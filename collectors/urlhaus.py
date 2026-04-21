import httpx
from datetime import datetime, timedelta, timezone
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ThreatEvent
from config import settings


API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/"

BANKING_TAGS = {
    "emotet", "qakbot", "dridex", "trickbot", "ursnif", "banking",
    "financial", "bazarloader", "icedid", "zloader",
}


class URLhausCollector(BaseCollector):
    name = "URLhaus"

    def __init__(self) -> None:
        self._api_key = settings.abusech_api_key

    def _headers(self) -> dict:
        return {"Auth-Key": self._api_key} if self._api_key else {}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def _fetch(self, client: httpx.AsyncClient) -> list:
        resp = await client.get(API_URL, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("urls", [])

    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        events: List[ThreatEvent] = []

        async with httpx.AsyncClient() as client:
            try:
                urls = await self._fetch(client)
            except Exception as e:
                self._warn(f"Failed to fetch: {e}")
                return []

        for entry in urls:
            try:
                date_added = datetime.strptime(entry["dateadded"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
            except (ValueError, KeyError):
                continue

            if date_added < cutoff:
                continue

            tags = [t.lower() for t in (entry.get("tags") or [])]
            is_banking = bool(set(tags) & BANKING_TAGS)

            events.append(ThreatEvent(
                source_feed=self.name,
                source_event_id=str(entry.get("id", "")),
                event_type="ioc",
                target_sector="banking" if is_banking else None,
                ioc_type="url",
                ioc_value=entry.get("url"),
                severity="high" if entry.get("url_status") == "online" else "medium",
                title=f"Malicious URL: {entry.get('url', '')[:80]}",
                description=f"Threat: {entry.get('threat', 'unknown')}. Status: {entry.get('url_status', 'unknown')}",
                tags=tags,
                reference_url=entry.get("urlhaus_reference"),
            ))

        self._log(f"Collected {len(events)} malicious URLs")
        return events
