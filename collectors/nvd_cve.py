import asyncio
import httpx
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ThreatEvent
from config import settings


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Search terms grouped by sector.
# Each tuple is (search_term, sector_label).
# Shared infra terms (Fortinet, Cisco, etc.) tag as None since they span all sectors.
SECTOR_SEARCH_TERMS: list[tuple[str, str | None]] = [
    # Banking / Financial
    ("banking", "banking"),
    ("financial", "banking"),
    ("swift", "banking"),
    ("payment", "banking"),
    ("ATM", "banking"),
    # Telecom
    ("telecom", "telecom"),
    ("5G", "telecom"),
    ("VoIP", "telecom"),
    ("SS7", "telecom"),
    # Government / Critical infrastructure
    ("government", "government"),
    ("SCADA", "government"),
    ("industrial control", "government"),
    # Shared critical infra — relevant to all sectors
    ("Fortinet", None),
    ("Citrix", None),
    ("F5", None),
    ("Cisco", None),
    ("Palo Alto", None),
]


class NVDCollector(BaseCollector):
    name = "NVD CVE"

    def __init__(self) -> None:
        self._api_key = settings.nvd_api_key

    def _build_headers(self) -> dict:
        if self._api_key:
            return {"apiKey": self._api_key}
        return {}

    def _cvss_score(self, metrics: dict) -> Optional[float]:
        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(version, [])
            if entries:
                return entries[0].get("cvssData", {}).get("baseScore")
        return None

    def _severity_from_score(self, score: Optional[float]) -> str:
        if score is None:
            return "medium"
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        return "low"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=4, max=20))
    async def _fetch_cves(self, client: httpx.AsyncClient, keyword: str, start: str, end: str) -> list:
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start,
            "pubEndDate": end,
            "resultsPerPage": 20,
        }
        resp = await client.get(NVD_URL, params=params, headers=self._build_headers(), timeout=40)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])

    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        events: List[ThreatEvent] = []
        seen_cve_ids: set = set()

        # NVD rate limit: 5 req/30s without API key, 50 req/30s with key
        delay = 6.5 if not self._api_key else 0.6

        async with httpx.AsyncClient() as client:
            for i, (term, sector) in enumerate(SECTOR_SEARCH_TERMS):
                if i > 0:
                    await asyncio.sleep(delay)
                try:
                    vulns = await self._fetch_cves(client, term, start, end)
                except Exception as e:
                    self._warn(f"Failed for keyword '{term}': {e}")
                    continue

                for item in vulns:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")

                    if cve_id in seen_cve_ids:
                        continue
                    seen_cve_ids.add(cve_id)

                    descriptions = cve.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

                    metrics = cve.get("metrics", {})
                    score = self._cvss_score(metrics)
                    severity = self._severity_from_score(score)

                    # Extract affected products
                    configs = cve.get("configurations", [])
                    affected = []
                    for config in configs[:2]:
                        for node in config.get("nodes", []):
                            for match in node.get("cpeMatch", [])[:3]:
                                cpe = match.get("criteria", "")
                                parts = cpe.split(":")
                                if len(parts) > 4:
                                    affected.append(f"{parts[3]} {parts[4]}")

                    events.append(ThreatEvent(
                        source_feed=self.name,
                        source_event_id=cve_id,
                        event_type="vulnerability",
                        target_sector=sector,
                        cve_id=cve_id,
                        cvss_score=score,
                        affected_product=", ".join(affected[:3]) if affected else None,
                        severity=severity,
                        title=f"{cve_id} ({term})",
                        description=desc[:500],
                        reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        tags=["nvd", f"keyword:{term}"] + ([sector] if sector else []),
                    ))

        self._log(f"Collected {len(events)} CVEs")
        return events
