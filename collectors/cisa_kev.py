import httpx
from datetime import datetime, timedelta, timezone
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ThreatEvent


# Keyword sets for sector detection in KEV entries (vendor/product/description)
SECTOR_KEYWORDS: dict[str, set] = {
    "banking": {
        "banking", "financial", "swift", "payment", "atm", "pos",
        # Infra heavily used in banking
        "f5", "citrix", "fortinet", "pulse secure", "ivanti",
    },
    "telecom": {
        "telecom", "telecommunication", "mobile", "carrier", "voip",
        "cisco ios", "juniper", "ericsson", "nokia", "5g", "ss7",
    },
    "government": {
        "government", "federal", "military", "defense", "scada", "ics",
        "industrial control", "critical infrastructure", "energy", "water",
        "microsoft exchange", "sharepoint", "citrix", "vmware",
    },
}

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVCollector(BaseCollector):
    name = "CISA KEV"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def _fetch(self, client: httpx.AsyncClient) -> dict:
        resp = await client.get(FEED_URL, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _cvss_to_severity(self, cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        return "low"

    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date()
        events: List[ThreatEvent] = []

        async with httpx.AsyncClient() as client:
            try:
                data = await self._fetch(client)
            except Exception as e:
                self._warn(f"Failed to fetch KEV feed: {e}")
                return []

        vulnerabilities = data.get("vulnerabilities", [])
        self._log(f"Total KEV entries: {len(vulnerabilities)}, filtering for last 24h")

        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded", "")
            try:
                added_date = datetime.strptime(date_added, "%Y-%m-%d").date()
            except ValueError:
                continue

            if added_date < cutoff:
                continue

            product = vuln.get("product", "")
            vendor = vuln.get("vendorProject", "")
            description = vuln.get("shortDescription", "")
            combined = f"{product} {vendor} {description}".lower()

            # Detect first matching sector (priority: banking → telecom → government)
            sector = None
            for s, keywords in SECTOR_KEYWORDS.items():
                if any(k in combined for k in keywords):
                    sector = s
                    break

            events.append(ThreatEvent(
                source_feed=self.name,
                source_event_id=vuln.get("cveID"),
                event_type="vulnerability",
                target_sector=sector,
                cve_id=vuln.get("cveID"),
                affected_product=f"{vendor} {product}".strip(),
                severity="high",  # all KEV entries are actively exploited = at minimum high
                attack_vector=vuln.get("requiredAction", ""),
                title=f"{vuln.get('cveID')} — {vendor} {product}",
                description=description[:500],
                reference_url=f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID')}",
                tags=["actively-exploited", "cisa-kev"],
            ))

        self._log(f"Collected {len(events)} new KEV entries")
        return events
