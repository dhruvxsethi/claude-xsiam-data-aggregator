# XSIAM Threat Intel Aggregator

Pulls global cyber attack data daily from 6 free feeds, normalises it, deduplicates across sources, and pushes it into Cortex XSIAM for dashboards and detection rules. Built for banking sector threat monitoring.

**Feeds:** AlienVault OTX · CISA KEV · NVD CVE · Feodo Tracker · ThreatFox · URLhaus

---

## Getting Started (New User)

### Step 1 — Get the code

```bash
git clone https://github.com/dhruvxsethi/claude-xsiam-data-aggregator
cd claude-xsiam-data-aggregator
pip install -r requirements.txt
```

Or download the ZIP and unzip it.

### Step 2 — Get credentials

**AlienVault OTX (free)**
1. Create account at [otx.alienvault.com](https://otx.alienvault.com)
2. Profile icon → API Integration → copy the key

**Cortex XSIAM**
1. XSIAM → `Settings → Data Sources → Add Data Source`
2. Choose `Custom → HTTP Based Collector`
3. Set Log Format to `JSON`
4. Click **Save & Generate Token**
5. Copy the **endpoint URL** and **token**

### Step 3 — Configure

```bash
cp .env.example .env
```

Open `.env` and fill in:
```
OTX_API_KEY=your_otx_key
XSIAM_BASE_URL=https://api-YOUR-TENANT.xdr.us.paloaltonetworks.com/logs/v1/event
XSIAM_API_KEY=your_xsiam_token
```

### Step 4 — Test

```bash
# Collect from all feeds, print summary, skip XSIAM push
python pipeline.py --dry-run
```

You should see 100–500 events collected across all sources. If everything returns 0 with `ConnectError` — VPN or firewall is blocking outbound HTTP. Turn off VPN and retry.

### Step 5 — Push to XSIAM

```bash
python pipeline.py
```

### Step 6 — Verify in XSIAM

Go to **Investigation → XQL Search** and run:

```xql
dataset = global_threat_intel_raw
| limit 10
```

Rows = working. Empty = check terminal output for errors.

---

## Running Commands

| Command | What it does |
|---------|-------------|
| `python pipeline.py --dry-run` | Collect + print summary, no XSIAM push |
| `python pipeline.py` | Collect and push to XSIAM |
| `python pipeline.py --days 7` | Backfill last 7 days (good for first run) |
| `python main.py` | Local scheduler — runs daily at configured UTC time (terminal must stay open) |

---

## Automated Daily Schedule (Claude Code)

The recommended way to run this automatically is via the **Claude Code remote schedule** — no terminal needs to stay open.

**Schedule is already created:** [claude.ai/code/scheduled](https://claude.ai/code/scheduled)  
**Trigger name:** `xsiam-threat-intel-daily`  
**Fires:** Every day at 6:00 AM UTC

**One-time setup — add your credentials to the schedule:**
1. Go to [claude.ai/code/scheduled](https://claude.ai/code/scheduled)
2. Click on `xsiam-threat-intel-daily`
3. Edit the prompt and replace the 3 placeholder values:
   - `REPLACE_WITH_OTX_KEY` → your OTX API key
   - `REPLACE_WITH_XSIAM_URL` → your XSIAM endpoint URL
   - `REPLACE_WITH_XSIAM_TOKEN` → your XSIAM token
4. Save

From then on it runs every morning automatically, clones the repo fresh, runs the pipeline, and reports results.

**To run it immediately** (without waiting for 6 AM):
```
# In Claude Code terminal:
/schedule run xsiam-threat-intel-daily
```

---

## Using the Claude Code Skill

If you're using Claude Code, there's a built-in skill that handles the entire setup:

```
/setup-threat-intel
```

It will:
1. Check for missing credentials and ask you for each one
2. Run `--dry-run` to confirm feeds are working
3. Push to XSIAM
4. Walk you through verifying data in XQL

---

## XQL Queries (XSIAM → Investigation → XQL Search)

**All events today**
```xql
dataset = global_threat_intel_raw
| filter _time > now() - 1d
| fields _time, source_feed, event_type, severity, title, target_sector
| sort _time desc
```

**Banking threats only**
```xql
dataset = global_threat_intel_raw
| filter target_sector = "banking"
| filter _time > now() - 7d
| sort _time desc
```

**High-confidence IOCs (seen in 2+ feeds)**
```xql
dataset = global_threat_intel_raw
| filter event_type = "ioc"
| filter array_length(seen_in) > 1
| fields _time, ioc_value, ioc_type, seen_in, severity, threat_family
```

**Critical + high severity**
```xql
dataset = global_threat_intel_raw
| filter severity in ("critical", "high")
| filter _time > now() - 24h
| sort _time desc
```

**New exploited CVEs (CISA KEV)**
```xql
dataset = global_threat_intel_raw
| filter source_feed = "CISA KEV"
| filter _time > now() - 7d
| fields _time, cve_id, affected_product, severity, description
```

**Did a bad IP hit your environment?**
```xql
dataset = xdr_data
| filter _time > now() - 1d
| join type=inner (
    dataset = global_threat_intel_raw
    | filter event_type = "ioc" and ioc_type = "ip"
    | filter _time > now() - 24h
    | fields ioc_value
) as threat on threat.ioc_value = action_remote_ip
| fields _time, agent_hostname, action_remote_ip
```

---

## Detection Rules

**BIOC — endpoint contacted a known-bad IP**
`XSIAM → Correlation → BIOC Rules → New Rule` → paste the "bad IP" query above → Severity: High

**Analytics — critical CVE published**
`XSIAM → Correlation → Analytics Rules → New Rule`
```xql
dataset = global_threat_intel_raw
| filter source_feed = "CISA KEV" and severity = "critical"
| filter _time > now() - 1h
```
Severity: Critical

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OTX_API_KEY` | Yes | Free at otx.alienvault.com |
| `XSIAM_BASE_URL` | Yes | Endpoint URL from HTTP Based Collector |
| `XSIAM_API_KEY` | Yes | Token from HTTP Based Collector |
| `NVD_API_KEY` | No | Increases NVD rate limits (free at nvd.nist.gov) |
| `SCHEDULE_HOUR` | No | UTC hour for local scheduler (default: 6) |
| `SCHEDULE_MINUTE` | No | UTC minute (default: 0) |

---

## Project Structure

```
├── collectors/
│   ├── alienvault_otx.py   # OTX campaigns + banking IOCs
│   ├── cisa_kev.py         # Actively exploited CVEs
│   ├── nvd_cve.py          # New CVEs (last 24h)
│   ├── feodo_tracker.py    # Live C2 IPs for banking trojans
│   ├── threatfox.py        # IOCs by malware family
│   └── urlhaus.py          # Malicious URLs
├── normalizer/
│   └── schema.py           # ThreatEvent — unified schema for all sources
├── xsiam/
│   └── ingestor.py         # Batches + POSTs to XSIAM
├── pipeline.py             # Main runner (collect → deduplicate → push)
├── main.py                 # Local scheduler fallback
└── config.py               # Loads settings from .env
```
