"""
Core pipeline: collect → deduplicate → return events.

No XSIAM push logic here — that lives on the client (work laptop).

CLI usage (local testing):
  python pipeline.py                  collect + print summary
  python pipeline.py --show-events    print every event as a table
  python pipeline.py --days 3         look back 3 days
"""

import asyncio
import argparse
from collections import defaultdict
from typing import List
from loguru import logger

from collectors.alienvault_otx import AlienVaultOTXCollector
from collectors.cisa_kev import CISAKEVCollector
from collectors.nvd_cve import NVDCollector
from collectors.feodo_tracker import FeodoTrackerCollector
from collectors.threatfox import ThreatFoxCollector
from collectors.urlhaus import URLhausCollector
from collectors.claude_news import ClaudeNewsCollector
from normalizer.schema import ThreatEvent


def deduplicate(events: List[ThreatEvent]) -> List[ThreatEvent]:
    ioc_map: dict = {}
    result: List[ThreatEvent] = []

    for event in events:
        if event.event_type == "ioc" and event.ioc_value:
            key = f"{event.ioc_type}:{event.ioc_value}"
            if key in ioc_map:
                existing = ioc_map[key]
                if event.source_feed not in existing.seen_in:
                    existing.seen_in.append(event.source_feed)
                sev_order = ["info", "low", "medium", "high", "critical"]
                if sev_order.index(event.severity) > sev_order.index(existing.severity):
                    existing.severity = event.severity
            else:
                event.seen_in = [event.source_feed]
                ioc_map[key] = event
                result.append(event)
        else:
            result.append(event)

    dupes = len(events) - len(result)
    if dupes:
        logger.info(f"[Pipeline] Deduplication: {dupes} duplicates merged → {len(result)} unique events")

    return result


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


async def collect_events(days: int = 1, limit: int = 0) -> List[ThreatEvent]:
    """
    Collect from all sources in parallel, deduplicate, and return.
    limit=0 means no cap. When limit>0, returns the top events by severity.
    """
    collectors = [
        AlienVaultOTXCollector(),
        CISAKEVCollector(),
        # NVDCollector(),      # re-enable once NVD_API_KEY is set (free: nvd.nist.gov/developers/request-an-api-key)
        FeodoTrackerCollector(),
        ThreatFoxCollector(),
        URLhausCollector(),
        ClaudeNewsCollector(),
    ]

    async def _safe_collect(c):
        try:
            return await c.collect(days=days)
        except Exception as e:
            logger.error(f"[Pipeline] {c.name} crashed: {e}")
            return []

    # Run all collectors concurrently
    results = await asyncio.gather(*[_safe_collect(c) for c in collectors])
    all_events: List[ThreatEvent] = [e for batch in results for e in batch]
    all_events = deduplicate(all_events)

    if limit and len(all_events) > limit:
        all_events.sort(key=lambda e: SEV_ORDER.get(e.severity, 0), reverse=True)
        all_events = all_events[:limit]
        logger.info(f"[Pipeline] Capped to top {limit} events by severity")

    return all_events


# ── CLI helpers (local testing only) ─────────────────────────────────────────

def print_events_table(events: List[ThreatEvent]) -> None:
    SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}
    col = {"time": 20, "source": 16, "type": 13, "sector": 11, "sev": 6, "detail": 44}
    hr = "─" * (sum(col.values()) + len(col) * 3 + 1)

    print(f"\n{'─' * 18} COLLECTED EVENTS {'─' * 18}")
    print(
        f"{'TIMESTAMP':<{col['time']}}  "
        f"{'SOURCE':<{col['source']}}  "
        f"{'TYPE':<{col['type']}}  "
        f"{'SECTOR':<{col['sector']}}  "
        f"{'SEV':<{col['sev']}}  "
        f"{'TITLE / IOC / CVE':<{col['detail']}}"
    )
    print(hr)

    for e in events:
        ts = e.record_time[:19].replace("T", " ")
        if e.event_type == "ioc":
            detail = f"{e.ioc_type}: {e.ioc_value}"
            if e.threat_family:
                detail += f"  [{e.threat_family}]"
            if len(e.seen_in) > 1:
                detail += f"  ⚑ {len(e.seen_in)} feeds"
        elif e.event_type == "vulnerability":
            detail = f"{e.cve_id or ''} {e.affected_product or ''}"
        else:
            detail = e.title

        sev = SEV_LABEL.get(e.severity, e.severity[:4].upper())
        sector = (e.target_sector or "—")[:col["sector"]]
        print(
            f"{ts:<{col['time']}}  "
            f"{e.source_feed:<{col['source']}}  "
            f"{e.event_type:<{col['type']}}  "
            f"{sector:<{col['sector']}}  "
            f"{sev:<{col['sev']}}  "
            f"{detail[:col['detail']]:<{col['detail']}}"
        )

    print(hr)
    print(f"  Total: {len(events)} events  |  ⚑ = seen in multiple feeds\n")


def print_summary(events: List[ThreatEvent]) -> None:
    by_source: dict = defaultdict(int)
    by_type: dict = defaultdict(int)
    by_severity: dict = defaultdict(int)
    by_sector: dict = defaultdict(int)
    multi_source_iocs = 0

    for e in events:
        by_source[e.source_feed] += 1
        by_type[e.event_type] += 1
        by_severity[e.severity] += 1
        if e.target_sector:
            by_sector[e.target_sector] += 1
        if len(e.seen_in) > 1:
            multi_source_iocs += 1

    print("\n" + "=" * 50)
    print("  THREAT INTEL — COLLECTION SUMMARY")
    print("=" * 50)
    print(f"  Total events     : {len(events)}")
    print(f"  Multi-feed IOCs  : {multi_source_iocs}  ← high confidence")
    print()
    print("  By sector:")
    for s, c in sorted(by_sector.items(), key=lambda x: -x[1]):
        print(f"    {s:<26} {c}")
    print()
    print("  By source:")
    for s, c in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"    {s:<26} {c}")
    print()
    print("  By type:")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {t:<26} {c}")
    print()
    print("  By severity:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_severity:
            print(f"    {sev:<26} {by_severity[sev]}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect threat intel (local test)")
    parser.add_argument("--show-events", action="store_true", help="Print every event as a table")
    parser.add_argument("--days", type=int, default=1, help="Days to look back (default: 1)")
    parser.add_argument("--limit", type=int, default=0, help="Cap events to top N by severity (0 = no cap)")
    args = parser.parse_args()

    async def _main():
        events = await collect_events(days=args.days, limit=args.limit)
        if args.show_events:
            print_events_table(events)
        print_summary(events)

    asyncio.run(_main())
