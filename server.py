"""
Threat Intel Source Server — collects and serves threat intelligence as JSON.

This machine's only job: gather data from all feeds and return it.
XSIAM push logic lives on the client side (work laptop).

Start:   python server.py
Expose:  ngrok http 8000

Single endpoint:
  GET /events?days=1   →  run all collectors, return events as JSON array
  GET /               →  health check
"""

import asyncio
from datetime import datetime, timezone
from typing import Any
import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from normalizer.schema import ThreatEvent
from pipeline import collect_events

# ── Simple cache so rapid repeated calls don't re-run all collectors ─────────
_cache: dict[str, Any] = {}   # {"events": [...], "cached_at": "...", "days": 1}
CACHE_MINUTES = 30


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n🛡️  Threat Intel Source Server")
    print("   GET /events        →  collect & return all threat events")
    print("   GET /events?days=3 →  look back 3 days instead of 1")
    print("   GET /              →  health check\n")
    yield


app = FastAPI(
    title="Threat Intel Source API",
    description="Collects cyber threat intelligence across banking, telecom, and government sectors.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
async def health():
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "cached": bool(_cache),
        "cache_age_minutes": (
            round(
                (datetime.now(timezone.utc) - datetime.fromisoformat(_cache["cached_at"])).seconds / 60
            )
            if _cache else None
        ),
        "hint": "GET /events to collect threat intelligence",
    }


@app.get("/events")
async def get_events(
    days: int = Query(1, description="How many days back to pull (1–7)", ge=1, le=7),
    refresh: bool = Query(False, description="Force re-collect even if cache is fresh"),
):
    """
    Runs all threat intel collectors and returns the full event list as JSON.

    Cached for 30 minutes — call with ?refresh=true to force a fresh run.
    """
    global _cache

    # Return cache if fresh and same day range
    if _cache and not refresh and _cache.get("days") == days:
        age_minutes = (
            datetime.now(timezone.utc) - datetime.fromisoformat(_cache["cached_at"])
        ).seconds / 60
        if age_minutes < CACHE_MINUTES:
            return JSONResponse({
                "collected_at": _cache["cached_at"],
                "from_cache": True,
                "cache_age_minutes": round(age_minutes),
                "total": len(_cache["events"]),
                "events": _cache["events"],
            })

    # Fresh collection
    events = await collect_events(days=days)
    serialized = [_to_dict(e) for e in events]

    _cache = {
        "events": serialized,
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "days": days,
    }

    return JSONResponse({
        "collected_at": _cache["cached_at"],
        "from_cache": False,
        "total": len(serialized),
        "events": serialized,
    })


def _to_dict(e: ThreatEvent) -> dict:
    d = e.to_xsiam_dict()
    # Rename _time → timestamp for cleaner client-side JSON
    if "_time" in d:
        d["timestamp"] = d.pop("_time")
    return d


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
