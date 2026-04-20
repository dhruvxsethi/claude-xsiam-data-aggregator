import httpx
from datetime import datetime, timedelta, timezone
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ThreatEvent


# Feodo Tracker tracks live C2 servers for banking trojans — no auth needed
FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# All malware families tracked are banking/financial sector trojans
BANKING_FAMILIES = {"Emotet", "QakBot", "Dridex", "TrickBot", "BazarLoader", "IcedID"}


class FeodoTrackerCollector(BaseCollector):
    name = "Feodo Tracker"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def _fetch(self, client: httpx.AsyncClient) -> list:
        resp = await client.get(FEED_URL, timeout=30)
        resp.raise_for_status()
        return resp.json()

    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        events: List[ThreatEvent] = []

        async with httpx.AsyncClient() as client:
            try:
                entries = await self._fetch(client)
            except Exception as e:
                self._warn(f"Failed to fetch: {e}")
                return []

        for entry in entries:
            try:
                first_seen = datetime.strptime(entry["first_seen"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except (ValueError, KeyError):
                continue

            if first_seen < cutoff:
                continue

            malware = entry.get("malware", "Unknown")
            events.append(ThreatEvent(
                source_feed=self.name,
                source_event_id=entry.get("ip_address"),
                event_type="ioc",
                threat_family=malware,
                target_sector="banking",
                ioc_type="ip",
                ioc_value=entry.get("ip_address"),
                geo_origin=entry.get("country_code"),
                severity="high",
                title=f"C2 IP: {entry.get('ip_address')} ({malware})",
                description=f"Active {malware} C2 server on port {entry.get('port', 'unknown')}. Status: {entry.get('status', 'unknown')}",
                tags=["c2", "botnet", malware.lower(), "banking-trojan"],
                reference_url=entry.get("abuse_ch_tracker"),
            ))

        self._log(f"Collected {len(events)} C2 IPs")
        return events
