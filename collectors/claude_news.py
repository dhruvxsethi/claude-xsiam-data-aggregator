"""
Claude AI News Collector — uses the Anthropic API with the built-in web_search tool
to surface live cyber threat intelligence across banking, telecom, and government sectors.

Each run queries Claude for the latest 24-48h threats per sector and converts the
structured response into normalised ThreatEvent objects.

Requirements:
  ANTHROPIC_API_KEY in .env
  pip install anthropic>=0.50.0
"""

import json
from typing import List

import anthropic

from collectors.base import BaseCollector
from normalizer.schema import ThreatEvent
from config import settings


# ── Per-sector search prompts ────────────────────────────────────────────────

SECTOR_QUERIES = {
    "banking": (
        "Search for the most recent cyber attacks, malware campaigns, and threat intelligence "
        "targeting banks, financial institutions, payment systems, or fintech companies "
        "in the last 24-48 hours. Include threat actor names, malware families, attack "
        "techniques, IOCs (IPs, domains, hashes), and affected organizations if reported."
    ),
    "telecom": (
        "Search for the most recent cyber attacks, espionage campaigns, and threat intelligence "
        "targeting telecom companies, mobile network operators, ISPs, or telecommunications "
        "infrastructure in the last 24-48 hours. Include APT groups (e.g. Salt Typhoon, Volt Typhoon), "
        "attack techniques (SS7 abuse, BGP hijacking, wiretapping), IOCs, and affected carriers."
    ),
    "government": (
        "Search for the most recent nation-state cyber attacks, espionage operations, and threat "
        "intelligence targeting government agencies, national security infrastructure, critical "
        "national infrastructure, or defense contractors in the last 24-48 hours. Include APT "
        "groups (e.g. APT28, APT29, Lazarus), attack techniques, IOCs, and targeted countries."
    ),
}

SYSTEM_PROMPT = """\
You are a cyber threat intelligence analyst. Use the web_search tool to find the \
latest threat news, then return your findings as a JSON array.

Each item in the array must have exactly these fields:
  title        – string, max 120 chars, concise threat headline
  description  – string, max 400 chars, 2-3 sentence summary
  severity     – one of: "critical" | "high" | "medium" | "low"
  threat_actor – string or null  (APT / threat group name)
  threat_family– string or null  (malware family, e.g. "Emotet")
  tags         – array of strings (e.g. ["ransomware", "phishing", "apt"])
  reference_url– string or null  (URL of the primary source article / advisory)
  ioc_type     – string or null  (only if a specific IOC is mentioned: "ip" | "domain" | "url" | "hash_md5" | "hash_sha256")
  ioc_value    – string or null  (the actual IOC value, paired with ioc_type)

Return ONLY a valid JSON array — no prose, no markdown fences. If you find no \
relevant recent threats, return []. Aim for 5-10 high-quality, recent entries."""


class ClaudeNewsCollector(BaseCollector):
    name = "Claude AI"

    def __init__(self) -> None:
        self._api_key = settings.anthropic_api_key
        self._sectors = settings.get_target_sectors()

    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        if not self._api_key:
            self._warn("No ANTHROPIC_API_KEY set — skipping. Add it to .env")
            return []

        import asyncio

        client = anthropic.Anthropic(api_key=self._api_key)
        all_events: List[ThreatEvent] = []

        for sector in self._sectors:
            query = SECTOR_QUERIES.get(sector.lower()) or (
                f"Search for the most recent cyber attacks and threat intelligence targeting "
                f"the {sector} sector in the last 24-48 hours. Include threat actors, "
                f"malware families, attack techniques, and any IOCs mentioned."
            )

            self._log(f"Querying Claude for '{sector}' threats…")
            try:
                events = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda s=sector, q=query: self._fetch_sector(client, s, q),
                )
                all_events.extend(events)
                self._log(f"  [{sector}] → {len(events)} events")
            except Exception as e:
                self._warn(f"Failed for sector '{sector}': {e}")

        self._log(f"Collected {len(all_events)} events across {len(self._sectors)} sectors")
        return all_events

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _fetch_sector(
        self, client: anthropic.Anthropic, sector: str, query: str
    ) -> List[ThreatEvent]:
        """Synchronous — runs in a thread executor from collect()."""

        messages: list = [{"role": "user", "content": query}]

        # Claude may do one or more web searches before giving the final JSON.
        # We loop until the model reaches end_turn (or we hit the iteration cap).
        MAX_ITERS = 5
        for _ in range(MAX_ITERS):
            response = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                tools=[{"type": "web_search_20250305", "name": "web_search"}],
                messages=messages,
            )

            if response.stop_reason == "end_turn":
                break

            # If the model used a tool, append its output and continue
            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        # web_search_20250305 is server-side: Anthropic executes it.
                        # We just need to pass back an empty tool_result so the loop
                        # continues — the search output is already baked into the
                        # assistant message.
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "",
                        })

                messages = messages + [
                    {"role": "assistant", "content": response.content},
                    {"role": "user", "content": tool_results},
                ]
            else:
                # Unexpected stop reason — bail out with whatever we have
                break

        # Extract final text block(s)
        text = "".join(
            block.text for block in response.content if hasattr(block, "text")
        )

        return self._parse_response(text, sector)

    def _parse_response(self, text: str, sector: str) -> List[ThreatEvent]:
        """Parse the JSON array Claude returned into ThreatEvent objects."""
        if not text.strip():
            return []

        # Find the outermost JSON array
        start = text.find("[")
        end = text.rfind("]") + 1
        if start == -1 or end == 0:
            self._warn(f"No JSON array in Claude response for sector '{sector}': {text[:200]}")
            return []

        try:
            items = json.loads(text[start:end])
        except json.JSONDecodeError as exc:
            self._warn(f"JSON parse error for sector '{sector}': {exc}")
            return []

        events: List[ThreatEvent] = []
        for item in items:
            if not isinstance(item, dict):
                continue

            has_ioc = bool(item.get("ioc_type") and item.get("ioc_value"))
            event_type = "ioc" if has_ioc else "intelligence"

            # Validate severity
            sev = item.get("severity", "medium").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "medium"

            events.append(ThreatEvent(
                source_feed=self.name,
                event_type=event_type,
                target_sector=sector,
                threat_actor=item.get("threat_actor") or None,
                threat_family=item.get("threat_family") or None,
                ioc_type=item.get("ioc_type") if has_ioc else None,
                ioc_value=item.get("ioc_value") if has_ioc else None,
                severity=sev,
                title=str(item.get("title", "Unnamed threat"))[:200],
                description=str(item.get("description", ""))[:500],
                tags=item.get("tags") or [],
                reference_url=item.get("reference_url") or None,
            ))

        return events
