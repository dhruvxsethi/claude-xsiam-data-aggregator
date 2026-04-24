# XSIAM Threat Intel Aggregator — Source Server

Collects cyber threat intelligence across **banking, telecom, and government** sectors from 6 free feeds + Claude AI live web search. Serves the data as a single JSON API. A separate client (work laptop) fetches from this API and pushes to Cortex XSIAM.

**Feeds:** AlienVault OTX · CISA KEV · NVD CVE · Feodo Tracker · ThreatFox · URLhaus · Claude AI (web search)

---

## Architecture

```
This machine (source server)          Work laptop (XSIAM client)
─────────────────────────────         ──────────────────────────
python server.py                      python server.py
      │                                     │
      ├─ collects from all feeds            ├─ GET /preview   → see events
      ├─ Claude AI searches live web        ├─ POST /push     → fetch + push to XSIAM
      └─ GET /events → returns JSON  ──────►└─ scheduler      → daily auto-push
```

This repo is **source server only** — no XSIAM credentials, no push logic here.

---

## Setup

```bash
git clone https://github.com/dhruvxsethi/claude-xsiam-data-aggregator
cd claude-xsiam-data-aggregator
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in keys
```

**Credentials needed (all free):**

| Variable | Where to get it |
|----------|----------------|
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) → API Integration |
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) → API Keys (add $5 USD credits) |
| `NVD_API_KEY` | Optional — [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| `ABUSECH_API_KEY` | Optional — [abuse.ch/account](https://abuse.ch/account) (covers ThreatFox + URLhaus) |

---

## Run

```bash
# Start the API server
python server.py

# Expose publicly (for work laptop access)
ngrok http 8000
```

**API:**

```
GET /events          collect all feeds + return JSON (cached 30 min)
GET /events?days=3   look back 3 days
GET /events?refresh=true   force fresh collection
GET /                health check
```

**Local test (no server):**

```bash
python pipeline.py                 # collect + summary
python pipeline.py --show-events   # collect + full events table
python pipeline.py --days 3
```

---

## Work laptop client

See `WORK_LAPTOP_SETUP_PROMPT.md` — paste it into Cursor to generate the XSIAM push client with 3 endpoints, daily scheduler, and XQL queries.
