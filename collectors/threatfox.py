import httpx
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ThreatEvent


API_URL = "https://threatfox-api.abuse.ch/api/v1/"

IOC_TYPE_MAP = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash_md5",
    "sha256_hash": "hash_sha256",
}

BANKING_FAMILIES = {
    "emotet", "qakbot", "dridex", "trickbot", "ursnif", "ramnit",
    "bazarloader", "icedid", "zloader", "gozi", "retefe", "danabot",
}


class ThreatFoxCollector(BaseCollector):
    name = "ThreatFox"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def _fetch(self, client: httpx.AsyncClient, days: int) -> list:
        payload = {"query": "get_iocs", "days": min(days, 7)}  # API max is 7
        resp = await client.post(API_URL, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return []
        return data.get("data", []) or []

    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        events: List[ThreatEvent] = []

        async with httpx.AsyncClient() as client:
            try:
                iocs = await self._fetch(client, days)
            except Exception as e:
                self._warn(f"Failed to fetch: {e}")
                return []

        self._log(f"Fetched {len(iocs)} IOCs from API")

        for ioc in iocs:
            malware_raw = (ioc.get("malware") or "").lower()
            malware_name = ioc.get("malware_printable") or malware_raw

            is_banking = any(f in malware_raw for f in BANKING_FAMILIES)
            sector = "banking" if is_banking else None

            ioc_type_raw = ioc.get("ioc_type", "")
            ioc_type = IOC_TYPE_MAP.get(ioc_type_raw)
            if not ioc_type:
                continue

            ioc_value = ioc.get("ioc", "")
            # Strip port from ip:port format
            if ioc_type == "ip" and ":" in ioc_value:
                ioc_value = ioc_value.split(":")[0]

            confidence = ioc.get("confidence_level", 50)
            severity = "high" if confidence >= 75 else "medium"

            events.append(ThreatEvent(
                source_feed=self.name,
                source_event_id=str(ioc.get("id", "")),
                event_type="ioc",
                threat_family=malware_name if malware_name else None,
                target_sector=sector,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                severity=severity,
                title=f"IOC: {ioc_value} ({malware_name})",
                description=ioc.get("comment") or f"{malware_name} indicator",
                tags=ioc.get("tags") or [],
                reference_url=f"https://threatfox.abuse.ch/ioc/{ioc.get('id')}",
            ))

        self._log(f"Collected {len(events)} events")
        return events
