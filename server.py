"""
FastAPI server — exposes the threat intel pipeline as an HTTP API.

Start:  python server.py          (runs on http://0.0.0.0:8000)
Expose: ngrok http 8000           (gives a public https://xxx.ngrok-free.app URL)

Endpoints:
  GET  /               Health check + last-run stats
  POST /run            Run the full pipeline (collects + pushes to XSIAM)
  POST /run?dry_run=1  Run without pushing to XSIAM
  GET  /events         Return events from the last run as JSON
  GET  /events/claude  Return only Claude AI-sourced events (the "live web search" ones)
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

from pipeline import run_pipeline
from normalizer.schema import ThreatEvent

# ── In-memory store for the most recent run ──────────────────────────────────
_last_run: dict[str, Any] = {}
_last_events: list[ThreatEvent] = []
_run_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n🛡️  Threat Intel API server ready")
    print("   POST /run          → run pipeline + push to XSIAM")
    print("   POST /run?dry_run=1 → collect only, no push")
    print("   GET  /events       → last collected events")
    print("   GET  /events/claude → Claude AI events only\n")
    yield


app = FastAPI(
    title="XSIAM Threat Intel Aggregator",
    description="Daily cyber threat intelligence across banking, telecom, and government sectors. Powered by Claude AI + OTX + CISA KEV + NVD.",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", summary="Health check")
async def health():
    """Returns server status and stats from the last pipeline run."""
    return {
        "status": "ok",
        "server_time": datetime.now(timezone.utc).isoformat(),
        "last_run": _last_run or None,
        "message": "POST /run to collect and push to XSIAM",
    }


@app.post("/run", summary="Run the threat intel pipeline")
async def run(
    dry_run: bool = Query(False, description="If true, collect only — skip XSIAM push"),
    days: int = Query(1, description="How many days back to pull (1–7)", ge=1, le=7),
):
    """
    Triggers the full pipeline:
    1. Collects from AlienVault OTX, CISA KEV, NVD, Feodo Tracker, ThreatFox, URLhaus
    2. **Claude AI** searches the live web for today's banking / telecom / government threats
    3. Deduplicates across all sources
    4. Pushes every event to Cortex XSIAM (unless dry_run=true)

    Returns a summary + every event collected, grouped by source.
    """
    global _last_run, _last_events

    if _run_lock.locked():
        raise HTTPException(status_code=409, detail="A pipeline run is already in progress. Try again in a moment.")

    async with _run_lock:
        started_at = datetime.now(timezone.utc).isoformat()

        # Run pipeline — capture events by monkey-patching the return
        # We call run_pipeline which prints to stdout and returns a summary dict.
        # To also get the raw events we use a wrapper.
        events: list[ThreatEvent] = []
        summary = await _run_pipeline_capture(events, dry_run=dry_run, days=days)

        _last_events = events
        _last_run = {
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": dry_run,
            "days": days,
            **summary,
        }

    # Build a rich response
    by_source: dict[str, list] = {}
    for e in events:
        by_source.setdefault(e.source_feed, []).append(_event_to_dict(e))

    return {
        "run": _last_run,
        "sources": {
            src: {
                "count": len(evts),
                "events": evts,
            }
            for src, evts in sorted(by_source.items(), key=lambda x: -len(x[1]))
        },
    }


@app.get("/events", summary="Events from the last run")
async def get_events(
    sector: Optional[str] = Query(None, description="Filter by sector: banking | telecom | government"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical | high | medium | low"),
    source: Optional[str] = Query(None, description="Filter by source feed name"),
    event_type: Optional[str] = Query(None, description="Filter by type: ioc | campaign | vulnerability | intelligence"),
    limit: int = Query(200, description="Max events to return", ge=1, le=1000),
):
    """Return events from the last pipeline run with optional filters."""
    if not _last_events:
        return {"message": "No run yet. POST /run first.", "events": []}

    filtered = _last_events
    if sector:
        filtered = [e for e in filtered if (e.target_sector or "").lower() == sector.lower()]
    if severity:
        filtered = [e for e in filtered if e.severity.lower() == severity.lower()]
    if source:
        filtered = [e for e in filtered if source.lower() in e.source_feed.lower()]
    if event_type:
        filtered = [e for e in filtered if e.event_type.lower() == event_type.lower()]

    return {
        "total": len(filtered),
        "run_at": _last_run.get("started_at"),
        "events": [_event_to_dict(e) for e in filtered[:limit]],
    }


@app.get("/events/claude", summary="Claude AI web-search events only")
async def get_claude_events():
    """
    Returns only the events sourced from Claude AI's live web search —
    these are the 'what happened today in cyber security' events, not
    just static feed IOCs.
    """
    if not _last_events:
        return {"message": "No run yet. POST /run first.", "events": []}

    claude_events = [e for e in _last_events if e.source_feed == "Claude AI"]

    # Group by sector for clarity
    by_sector: dict[str, list] = {}
    for e in claude_events:
        by_sector.setdefault(e.target_sector or "untagged", []).append(_event_to_dict(e))

    return {
        "source": "Claude AI (live web search)",
        "total": len(claude_events),
        "run_at": _last_run.get("started_at"),
        "by_sector": by_sector,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event_to_dict(e: ThreatEvent) -> dict:
    d = e.to_xsiam_dict()
    # Use record_time key (not the alias _time) for cleaner JSON responses
    if "_time" in d:
        d["timestamp"] = d.pop("_time")
    return d


async def _run_pipeline_capture(
    events_out: list,
    dry_run: bool,
    days: int,
) -> dict:
    """
    Runs the pipeline and also captures the raw ThreatEvent objects into events_out.
    We do this by importing the collectors directly so we get both the summary and events.
    """
    from collections import defaultdict
    from loguru import logger
    from collectors.alienvault_otx import AlienVaultOTXCollector
    from collectors.cisa_kev import CISAKEVCollector
    from collectors.nvd_cve import NVDCollector
    from collectors.feodo_tracker import FeodoTrackerCollector
    from collectors.threatfox import ThreatFoxCollector
    from collectors.urlhaus import URLhausCollector
    from collectors.claude_news import ClaudeNewsCollector
    from pipeline import deduplicate
    from xsiam.ingestor import XSIAMIngestor

    collectors = [
        AlienVaultOTXCollector(),
        CISAKEVCollector(),
        NVDCollector(),
        FeodoTrackerCollector(),
        ThreatFoxCollector(),
        URLhausCollector(),
        ClaudeNewsCollector(),
    ]

    all_events: list[ThreatEvent] = []
    for collector in collectors:
        try:
            evts = await collector.collect(days=days)
            all_events.extend(evts)
        except Exception as exc:
            logger.error(f"[Pipeline] {collector.name} crashed: {exc}")

    all_events = deduplicate(all_events)
    events_out.extend(all_events)

    pushed = 0
    if not dry_run:
        ingestor = XSIAMIngestor()
        pushed = await ingestor.ingest(all_events)

    by_source: dict = defaultdict(int)
    by_sector: dict = defaultdict(int)
    by_severity: dict = defaultdict(int)
    for e in all_events:
        by_source[e.source_feed] += 1
        if e.target_sector:
            by_sector[e.target_sector] += 1
        by_severity[e.severity] += 1

    return {
        "total_collected": len(all_events),
        "total_pushed": pushed,
        "by_source": dict(by_source),
        "by_sector": dict(by_sector),
        "by_severity": dict(by_severity),
    }


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
