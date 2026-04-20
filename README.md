# XSIAM Threat Intel Aggregator

Pulls global cyber attack data daily from 6 free feeds, normalises it, deduplicates across sources, and pushes it into Cortex XSIAM. Built for banking sector threat monitoring.

**Feeds:** AlienVault OTX · CISA KEV · NVD CVE · Feodo Tracker · ThreatFox · URLhaus

---

## How it runs (split architecture)

| Where | What it does | Credentials needed |
|-------|-------------|-------------------|
| **Claude Code schedule** (cloud, daily 6 AM UTC) | Collects from all 6 feeds, prints full events table | OTX key only |
| **Mac launchd** (local, daily 2 PM SGT) | Collects + pushes to XSIAM | OTX + XSIAM |

The cloud schedule gives you visibility into what's being collected every day. The local job does the actual XSIAM push. Both are independent — if one fails, the other still runs.

---

## Setup (New User)

### 1. Get the code

```bash
git clone https://github.com/dhruvxsethi/claude-xsiam-data-aggregator
cd claude-xsiam-data-aggregator
pip install -r requirements.txt
```

### 2. Get credentials

**AlienVault OTX (free)**
1. Create account at [otx.alienvault.com](https://otx.alienvault.com)
2. Profile icon (top right) → API Integration → copy the key

**Cortex XSIAM**
1. XSIAM → `Settings → Data Sources → Add Data Source`
2. Choose `Custom → HTTP Based Collector`
3. Name it `global_threat_intel`, set Log Format to `JSON`
4. Click **Save & Generate Token**
5. Copy the **endpoint URL** and **token** shown on screen — you only see these once

### 3. Configure credentials

```bash
cp .env.example .env
# open .env and fill in the 3 values
```

```
OTX_API_KEY=your_otx_key
XSIAM_BASE_URL=https://api-YOUR-TENANT.xdr.us.paloaltonetworks.com/logs/v1/event
XSIAM_API_KEY=your_xsiam_token
```

### 4. Test

```bash
# Collect from all feeds, preview full events table, skip XSIAM push
python pipeline.py --dry-run --show-events
```

You should see 100–500 events in a table. If everything returns 0 with `ConnectError` — turn off VPN and retry.

### 5. Push to XSIAM

```bash
python pipeline.py
```

### 6. Find your data in XSIAM

After the first successful push:

1. Go to **XSIAM → Investigation → XQL Search**
2. In the left panel, click **Datasets** — you should see `global_threat_intel_raw` appear after the first push
3. Run:
```xql
dataset = global_threat_intel_raw
| limit 10
```

> **Why `_raw`?** XSIAM automatically appends `_raw` to the dataset name. The dataset does not exist until the first event is pushed — so if you only ran `--dry-run` it won't be there yet.

---

## Automated Daily Schedule

### Cloud (Claude Code) — collection only

Already created. Runs every day at **6:00 AM UTC**.

**One-time step — add your OTX key:**
1. Go to [claude.ai/code/scheduled](https://claude.ai/code/scheduled)
2. Click `xsiam-threat-intel-daily` → edit the prompt
3. Replace `REPLACE_WITH_YOUR_OTX_KEY` with your real OTX key
4. Save

Every morning Claude Code clones the latest code from GitHub, collects from all feeds, and reports the full events table. CISA KEV, NVD, Feodo Tracker, ThreatFox, and URLhaus need no keys at all.

**To run it right now** (without waiting for 6 AM), in Claude Code terminal:
```
/schedule run xsiam-threat-intel-daily
```

### Local Mac (launchd) — full push to XSIAM

Runs at **2:00 PM Singapore time** daily (= 6 AM UTC). Reads your local `.env` so XSIAM credentials never leave your machine.

```bash
# Install the launchd job (one-time)
cp launchd/com.xsiam.threat-intel.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.xsiam.threat-intel.plist

# Check it's registered
launchctl list | grep xsiam

# Run it right now manually
launchctl start com.xsiam.threat-intel

# View logs
tail -f /tmp/xsiam-threat-intel.log

# Remove it
launchctl unload ~/Library/LaunchAgents/com.xsiam.threat-intel.plist
```

---

## Commands

| Command | What it does |
|---------|-------------|
| `python pipeline.py --dry-run` | Collect + summary, no XSIAM push |
| `python pipeline.py --dry-run --show-events` | Collect + full events table + summary |
| `python pipeline.py` | Collect and push to XSIAM |
| `python pipeline.py --days 7` | Backfill last 7 days (good for first run) |
| `python main.py` | Local scheduler fallback (terminal must stay open) |

---

## XQL Queries (Investigation → XQL Search)

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

**Did a bad IP hit your environment?** *(needs endpoints in XSIAM)*
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

## Using the Claude Code Skill

```
/setup-threat-intel
```
Guides you through credentials, runs the pipeline, and verifies data in XSIAM.

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
