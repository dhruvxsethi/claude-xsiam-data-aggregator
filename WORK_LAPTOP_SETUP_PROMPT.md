# Cursor Prompt — paste this into a new Cursor project on the work laptop

---

Build a Python project called `xsiam-threat-client`. This is the XSIAM push client for a two-machine threat intelligence pipeline.

## Context

A source server (running on another machine, exposed via ngrok) collects cyber threat intelligence from multiple feeds (AlienVault OTX, CISA KEV, NVD, Claude AI web search, etc.) and returns it as JSON from a single endpoint:

```
GET https://<SOURCE_URL>/events?days=1
```

Response shape:
```json
{
  "collected_at": "2026-04-24T06:00:00Z",
  "from_cache": false,
  "total": 115,
  "events": [
    {
      "timestamp": "2026-04-24T06:00:00Z",
      "source_feed": "Claude AI",
      "event_type": "intelligence",
      "target_sector": "banking",
      "severity": "high",
      "title": "...",
      "description": "...",
      "tags": ["ransomware", "phishing"],
      "threat_actor": "...",
      "threat_family": "...",
      "ioc_type": "domain",
      "ioc_value": "malicious.com",
      "reference_url": "https://..."
    }
  ]
}
```

This client's job:
1. Fetch events from the source server
2. Push them to Cortex XSIAM via its HTTP Log Collector
3. Expose 3 API endpoints + an automated daily schedule

---

## What to build

### File structure
```
xsiam-threat-client/
  server.py          ← FastAPI app (3 endpoints)
  ingestor.py        ← XSIAM push logic
  scheduler.py       ← APScheduler daily auto-run
  config.py          ← pydantic-settings, reads .env
  requirements.txt
  .env.example
  xql_queries.md     ← XQL queries for XSIAM
```

### config.py
Use `pydantic-settings` to read from `.env`:
```
SOURCE_API_URL=https://abc123.ngrok-free.app   # the source server ngrok URL
XSIAM_BASE_URL=https://api-YOUR-TENANT.xdr.us.paloaltonetworks.com/logs/v1/event
XSIAM_API_KEY=your_token_here
SCHEDULE_HOUR=6        # UTC hour for daily auto-run
SCHEDULE_MINUTE=0
LOOKBACK_DAYS=1
```

### ingestor.py
Push events to XSIAM HTTP Log Collector:
- `Authorization` header = raw API key (NO "Bearer" prefix)
- `Content-Type: text/plain`
- Body = one JSON object per line (newline-delimited, NOT a JSON array)
- Batch in groups of 500
- Retry up to 3 times with exponential backoff (use tenacity)
- Return count of successfully pushed events

### server.py — 3 endpoints

**1. GET /preview**
- Fetches events from SOURCE_API_URL
- Returns them as JSON — does NOT push to XSIAM
- Shows what would be pushed: total count, breakdown by sector, breakdown by source, list of events
- Accepts `?days=1` query param (passed through to source server)

**2. POST /push**
- Fetches events from SOURCE_API_URL
- Pushes all events to XSIAM
- Returns: `{ "fetched": 115, "pushed": 115, "failed": 0, "by_sector": {...}, "by_source": {...} }`
- Accepts `?days=1` query param

**3. GET /last-run**
- Returns summary of the most recent push (time, count pushed, by_sector, by_source)
- Returns `{ "message": "No run yet" }` if nothing has been pushed

### scheduler.py
- Use APScheduler AsyncIOScheduler
- Every day at SCHEDULE_HOUR:SCHEDULE_MINUTE UTC, call the same logic as POST /push
- Log results with loguru
- Start the scheduler when `server.py` starts (use FastAPI lifespan)

### xql_queries.md
Write XQL queries for Cortex XSIAM to query the ingested data. The dataset name is `custom_threatintelaggregator_raw`. Write queries for:
1. All events from the last 24 hours
2. High/critical severity events only
3. Events by sector (banking / telecom / government)
4. IOC events only (ioc_type + ioc_value present)
5. Events sourced from "Claude AI" (the live web search events)
6. Events by threat_actor
7. All unique domains/IPs collected today

### requirements.txt
```
httpx
fastapi
uvicorn
pydantic>=2.0
pydantic-settings
apscheduler
tenacity
loguru
python-dotenv
requests
```

---

## Key XSIAM push details (important — these are confirmed working)

- URL: the full URL from XSIAM → Settings → Data Sources → Custom HTTP Based Collector
- Auth: `Authorization: <token>` — the token goes directly, NO "Bearer " prefix
- Content-Type: `text/plain` (NOT application/json — this is critical)
- Body format: each event on its own line as a JSON object:
  ```
  {"timestamp": "...", "source_feed": "...", ...}
  {"timestamp": "...", "source_feed": "...", ...}
  ```
  NOT wrapped in an array. One object per line.
- The `timestamp` field in each event maps to `_time` in XSIAM

---

## How to run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# fill in SOURCE_API_URL, XSIAM_BASE_URL, XSIAM_API_KEY in .env
python server.py    # starts on port 8001
```

Then:
- `GET  http://localhost:8001/preview`  — see what would be pushed
- `POST http://localhost:8001/push`     — fetch + push to XSIAM
- `GET  http://localhost:8001/last-run` — last push summary
- Scheduler runs automatically daily at the configured UTC time
