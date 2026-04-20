import httpx
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ThreatEvent
from config import settings


# OTX pulse tags that indicate banking/financial sector threats
BANKING_TAGS = {
    "banking", "finance", "financial", "bank", "swift", "atm",
    "emotet", "qakbot", "dridex", "trickbot", "ursnif", "ramnit",
    "fin7", "fin8", "carbanak", "lazarus", "cobalt group",
}

SEVERITY_MAP = {
    1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"
}

INDICATOR_TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip",
    "domain": "domain", "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "email": "email",
    "CIDR": "cidr",
}


class AlienVaultOTXCollector(BaseCollector):
    name = "AlienVault OTX"
    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self) -> None:
        self._api_key = settings.otx_api_key
        self._target_sectors = set(settings.get_target_sectors())
        self._headers = {"X-OTX-API-KEY": self._api_key}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def _get_pulses(self, client: httpx.AsyncClient, modified_since: str) -> list:
        """Fetch pulses modified since a given ISO timestamp."""
        url = f"{self.BASE_URL}/pulses/subscribed"
        params = {"modified_since": modified_since, "limit": 100}
        resp = await client.get(url, params=params, headers=self._headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("results", [])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def _get_pulse_indicators(self, client: httpx.AsyncClient, pulse_id: str) -> list:
        url = f"{self.BASE_URL}/pulses/{pulse_id}/indicators"
        resp = await client.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("results", [])

    def _is_banking_related(self, pulse: dict) -> bool:
        pulse_tags = {t.lower() for t in pulse.get("tags", [])}
        pulse_name = pulse.get("name", "").lower()
        pulse_desc = pulse.get("description", "").lower()
        combined = pulse_tags | set(pulse_name.split()) | set(pulse_desc.split())
        return bool(combined & BANKING_TAGS)

    def _severity_from_tlp(self, tlp: str) -> str:
        return {"red": "critical", "amber": "high", "green": "medium", "white": "low"}.get(
            (tlp or "").lower(), "medium"
        )

    def _extract_mitre(self, pulse: dict) -> tuple[Optional[str], Optional[str]]:
        for ref in pulse.get("references", []):
            if "attack.mitre.org/techniques" in ref:
                technique = ref.rstrip("/").split("/")[-1]
                return None, technique
        return None, None

    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        if not self._api_key:
            self._warn("No API key — skipping. Set OTX_API_KEY in .env")
            return []

        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        events: List[ThreatEvent] = []

        async with httpx.AsyncClient() as client:
            try:
                pulses = await self._get_pulses(client, since)
            except Exception as e:
                self._warn(f"Failed to fetch pulses: {e}")
                return []

            self._log(f"Fetched {len(pulses)} pulses from last 24h")

            for pulse in pulses:
                is_banking = self._is_banking_related(pulse)
                sector = "banking" if is_banking else None
                tactic, technique = self._extract_mitre(pulse)
                severity = self._severity_from_tlp(pulse.get("tlp", "white"))

                # One campaign-level event per pulse
                events.append(ThreatEvent(
                    source_feed=self.name,
                    source_event_id=pulse.get("id"),
                    event_type="campaign",
                    threat_actor=pulse.get("author_name"),
                    campaign_name=pulse.get("name"),
                    target_sector=sector,
                    mitre_tactic=tactic,
                    mitre_technique=technique,
                    severity=severity,
                    title=pulse.get("name", "Unknown Pulse"),
                    description=pulse.get("description", "")[:500],
                    tags=pulse.get("tags", []),
                    reference_url=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                ))

                # IOC-level events for banking pulses
                if is_banking:
                    try:
                        indicators = await self._get_pulse_indicators(client, pulse["id"])
                        for ind in indicators[:50]:  # cap per pulse
                            ioc_type = INDICATOR_TYPE_MAP.get(ind.get("type", ""), None)
                            if not ioc_type:
                                continue
                            events.append(ThreatEvent(
                                source_feed=self.name,
                                source_event_id=str(ind.get("id")) if ind.get("id") is not None else None,
                                event_type="ioc",
                                campaign_name=pulse.get("name"),
                                target_sector="banking",
                                ioc_type=ioc_type,
                                ioc_value=ind.get("indicator"),
                                mitre_technique=technique,
                                severity=severity,
                                title=f"IOC: {ind.get('indicator', '')}",
                                description=ind.get("description", "") or pulse.get("name", ""),
                                tags=pulse.get("tags", []),
                            ))
                    except Exception as e:
                        self._warn(f"Could not fetch indicators for pulse {pulse.get('id')}: {e}")

        self._log(f"Collected {len(events)} events")
        return events
