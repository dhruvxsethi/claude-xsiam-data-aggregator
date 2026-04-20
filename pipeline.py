"""
Core pipeline: collect → deduplicate → push to XSIAM.

Flags:
  --dry-run     Collect only, skip XSIAM push (safe without credentials)
  --days N      Look back N days instead of 24h (default: 1, max: 7)
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
from normalizer.schema import ThreatEvent
from xsiam.ingestor import XSIAMIngestor


def deduplicate(events: List[ThreatEvent]) -> List[ThreatEvent]:
    """
    Merge duplicate IOCs seen across multiple feeds.
    Same ioc_value from different sources → one event with seen_in populated.
    """
    ioc_map: dict[str, ThreatEvent] = {}
    result: List[ThreatEvent] = []

    for event in events:
        if event.event_type == "ioc" and event.ioc_value:
            key = f"{event.ioc_type}:{event.ioc_value}"
            if key in ioc_map:
                existing = ioc_map[key]
                if event.source_feed not in existing.seen_in:
                    existing.seen_in.append(event.source_feed)
                # Escalate severity if a duplicate comes in higher
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
        logger.info(f"[Pipeline] Deduplication: {dupes} duplicate IOCs merged, {len(result)} unique events")

    return result


def print_summary(events: List[ThreatEvent], pushed: int, dry_run: bool) -> None:
    by_source: dict = defaultdict(int)
    by_type: dict = defaultdict(int)
    by_severity: dict = defaultdict(int)
    banking_count = 0
    multi_source_iocs = 0

    for e in events:
        by_source[e.source_feed] += 1
        by_type[e.event_type] += 1
        by_severity[e.severity] += 1
        if e.target_sector in ("banking", "finance"):
            banking_count += 1
        if len(e.seen_in) > 1:
            multi_source_iocs += 1

    print("\n" + "=" * 50)
    print("  THREAT INTEL PIPELINE — RUN SUMMARY")
    print("=" * 50)
    print(f"  Total events collected : {len(events)}")
    print(f"  Banking/finance related: {banking_count}")
    print(f"  IOCs seen in 2+ feeds  : {multi_source_iocs}  ← high confidence")
    print(f"  Pushed to XSIAM        : {pushed if not dry_run else 'skipped (dry-run)'}")
    print()
    print("  By source:")
    for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"    {src:<25} {count}")
    print()
    print("  By type:")
    for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {t:<25} {count}")
    print()
    print("  By severity:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_severity:
            print(f"    {sev:<25} {by_severity[sev]}")
    print("=" * 50 + "\n")


async def run_pipeline(dry_run: bool = False, days: int = 1) -> dict:
    collectors = [
        AlienVaultOTXCollector(),
        CISAKEVCollector(),
        NVDCollector(),
        FeodoTrackerCollector(),
        ThreatFoxCollector(),
        URLhausCollector(),
    ]

    all_events: List[ThreatEvent] = []

    for collector in collectors:
        try:
            events = await collector.collect(days=days)
            all_events.extend(events)
        except Exception as e:
            logger.error(f"[Pipeline] {collector.name} crashed: {e}")

    all_events = deduplicate(all_events)

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
    parser.add_argument("--days", type=int, default=1, help="How many days back to pull (default: 1)")
    args = parser.parse_args()
    asyncio.run(run_pipeline(dry_run=args.dry_run, days=args.days))
