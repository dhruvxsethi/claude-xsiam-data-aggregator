"""
Core pipeline: collect → deduplicate → push to XSIAM.

Flags:
  --dry-run       Collect only, skip XSIAM push
  --show-events   Print every collected event as a table (combine with --dry-run to preview what would be pushed)
  --days N        Look back N days instead of 24h (default: 1, max: 7)
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
from xsiam.ingestor import XSIAMIngestor


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


def print_events_table(events: List[ThreatEvent]) -> None:
    """Print every event as a readable table — exactly what gets pushed to XSIAM."""
    SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}
    col = {"time": 20, "source": 16, "type": 13, "sector": 11, "sev": 6, "detail": 44}
    hr = "─" * (sum(col.values()) + len(col) * 3 + 1)

    print(f"\n{'─' * 18} EVENTS THAT WOULD BE PUSHED TO XSIAM {'─' * 18}")
    header = (
        f"{'TIMESTAMP':<{col['time']}}  "
        f"{'SOURCE':<{col['source']}}  "
        f"{'TYPE':<{col['type']}}  "
        f"{'SECTOR':<{col['sector']}}  "
        f"{'SEV':<{col['sev']}}  "
        f"{'TITLE / IOC / CVE':<{col['detail']}}"
    )
    print(header)
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
    print(f"  Total: {len(events)} events  |  ⚑ = seen in multiple feeds (high confidence)\n")


def print_summary(events: List[ThreatEvent], pushed: int, dry_run: bool) -> None:
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

    print("\n" + "=" * 55)
    print("  THREAT INTEL PIPELINE — RUN SUMMARY")
    print("=" * 55)
    print(f"  Total events collected : {len(events)}")
    print(f"  IOCs seen in 2+ feeds  : {multi_source_iocs}  ← high confidence")
    print(f"  Pushed to XSIAM        : {pushed if not dry_run else 'skipped (dry-run)'}")
    print()
    print("  By sector:")
    for sector, count in sorted(by_sector.items(), key=lambda x: -x[1]):
        print(f"    {sector:<28} {count}")
    if not by_sector:
        print("    (none tagged — expand TARGET_SECTORS in .env)")
    print()
    print("  By source:")
    for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"    {src:<28} {count}")
    print()
    print("  By type:")
    for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {t:<28} {count}")
    print()
    print("  By severity:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_severity:
            print(f"    {sev:<28} {by_severity[sev]}")
    print("=" * 55 + "\n")


async def run_pipeline(dry_run: bool = False, days: int = 1, show_events: bool = False) -> dict:
    collectors = [
        AlienVaultOTXCollector(),
        CISAKEVCollector(),
        NVDCollector(),
        FeodoTrackerCollector(),
        ThreatFoxCollector(),
        URLhausCollector(),
        ClaudeNewsCollector(),   # live web search — requires ANTHROPIC_API_KEY
    ]

    all_events: List[ThreatEvent] = []

    for collector in collectors:
        try:
            events = await collector.collect(days=days)
            all_events.extend(events)
        except Exception as e:
            logger.error(f"[Pipeline] {collector.name} crashed: {e}")

    all_events = deduplicate(all_events)

    if show_events:
        print_events_table(all_events)

    pushed = 0
    if dry_run:
        logger.info("[Pipeline] Dry-run — skipping XSIAM push")
    else:
        ingestor = XSIAMIngestor()
        pushed = await ingestor.ingest(all_events)

    summary = {
        "total_collected": len(all_events),
        "total_pushed": pushed,
        "dry_run": dry_run,
        "by_source": {},
    }
    for event in all_events:
        summary["by_source"].setdefault(event.source_feed, 0)
        summary["by_source"][event.source_feed] += 1

    print_summary(all_events, pushed, dry_run)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat intel pipeline")
    parser.add_argument("--dry-run", action="store_true", help="Collect only, skip XSIAM push")
    parser.add_argument("--show-events", action="store_true", help="Print every event as a table")
    parser.add_argument("--days", type=int, default=1, help="How many days back to pull (default: 1)")
    args = parser.parse_args()
    asyncio.run(run_pipeline(dry_run=args.dry_run, days=args.days, show_events=args.show_events))
