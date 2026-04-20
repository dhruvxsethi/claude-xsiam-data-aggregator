# XSIAM Threat Intel Aggregator

Pulls global cyber attack data daily from 6 free feeds, normalises it, and pushes it into Cortex XSIAM. Built for banking sector threat monitoring.

## Sources

| Feed | What it tracks |
|------|---------------|
| AlienVault OTX | Threat campaigns + IOCs (banking-tagged) |
| CISA KEV | Actively exploited CVEs (US Gov) |
| NVD | New CVEs published in last 24h |
| Feodo Tracker | Live C2 IPs for Emotet, QakBot, Dridex, TrickBot |
| ThreatFox | IOCs by malware family |
| URLhaus | Malicious URLs actively distributing malware |

---

## Setup

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Get your free OTX key** — [otx.alienvault.com](https://otx.alienvault.com) → profile → API Integration

**3. Create HTTP Log Collector in XSIAM**
`Settings → Configurations → Data Sources → + Add Data Source → Custom → HTTP Based Collector`
Set Log Format: `JSON`. Save — copy the URL and token it gives you.

**4. Configure credentials**
```bash
cp .env.example .env
# Fill in OTX_API_KEY, XSIAM_BASE_URL, XSIAM_API_KEY
```

---

## Running

| Command | What it does |
|---------|-------------|
| `python pipeline.py --dry-run` | Collect + print summary, skip XSIAM push |
| `python pipeline.py` | Collect and push to XSIAM |
| `python pipeline.py --days 7` | Pull last 7 days instead of 24h |
| `python main.py` | Start daily scheduler (runs at 6 AM UTC, keep terminal open) |

---

## Verify in XSIAM

After `python pipeline.py`, go to **Investigation → XQL Search** and run:

```xql
dataset = global_threat_intel_raw
| limit 10
```

Rows = connected. Empty = check terminal for errors.

---

## Key XQL Queries

**Banking attacks only**
```xql
dataset = global_threat_intel_raw
| filter target_sector = "banking"
| filter _time > now() - 7d
| sort _time desc
```

**All IOCs (IPs, domains, URLs, hashes)**
```xql
dataset = global_threat_intel_raw
| filter event_type = "ioc"
| filter _time > now() - 7d
| fields _time, ioc_type, ioc_value, threat_family, severity, source_feed, seen_in
| sort _time desc
```

**High-confidence IOCs — seen in multiple feeds**
```xql
dataset = global_threat_intel_raw
| filter event_type = "ioc"
| filter array_length(seen_in) > 1
| fields _time, ioc_value, ioc_type, seen_in, severity
```

**Critical + high severity**
```xql
dataset = global_threat_intel_raw
| filter severity in ("critical", "high")
| filter _time > now() - 24h
| sort _time desc
```

**New exploited CVEs**
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

## Detection Rules in XSIAM

**BIOC — endpoint hit a known-bad IP:**
`Correlation → BIOC Rules → New Rule` → paste the IOC correlation query above → Severity: High

**Analytics — critical CVE published:**
`Correlation → Analytics Rules → New Rule` → filter `source_feed = "CISA KEV" and severity = "critical"` → Severity: Critical

---

## Claude Code Skill

If you're running this with Claude Code, use the built-in skill to get set up in one command:
```
/setup-threat-intel
```
Claude will check your credentials, run the pipeline, and walk you through verifying data in XSIAM.

---

## Environment Variables

| Variable | Required | Where to get it |
|----------|----------|----------------|
| `OTX_API_KEY` | Yes | otx.alienvault.com → profile → API Integration |
| `XSIAM_BASE_URL` | Yes | Full URL from HTTP Based Collector screen |
| `XSIAM_API_KEY` | Yes | Token from HTTP Based Collector screen |
| `NVD_API_KEY` | No | nvd.nist.gov/developers (increases rate limits) |
| `SCHEDULE_HOUR` | No | UTC hour for daily run (default: 6) |
| `SCHEDULE_MINUTE` | No | UTC minute (default: 0) |
