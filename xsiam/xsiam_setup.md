# XSIAM Setup Guide — Step by Step

## Step 1: Create the HTTP Log Collector (Data Source)

1. Log into Cortex XSIAM
2. Go to **Settings → Configurations → Data Sources**
3. Click **+ Add Data Source**
4. Choose **Custom** → **HTTP Log Collector**
5. Fill in:
   - Name: `Global Threat Intel`
   - Dataset name: `global_threat_intel`
   - Vendor: `Custom`
   - Product: `ThreatIntelAggregator`
6. Click **Create**
7. XSIAM gives you:
   - **Endpoint URL** → copy this into `.env` as `XSIAM_BASE_URL` (without the `/logs/v1/xsiam` suffix)
   - **API Key** → copy into `XSIAM_API_KEY`
   - **Auth ID** → copy into `XSIAM_AUTH_ID`

---

## Step 2: Verify Data is Flowing

After your first pipeline run (`python pipeline.py`):

1. Go to **Investigation → XQL Search**
2. Run:
```xql
dataset = global_threat_intel_raw
| limit 10
```
You should see events. If empty, check logs in the terminal.

---

## Step 3: Create a Dashboard

1. **Dashboards → New Dashboard** → Name it `Global Threat Intel`
2. Add widgets using the XQL queries from `xql_queries.md`:
   - **Bar chart**: Daily event volume by source (Query #3)
   - **Table**: Banking sector attacks (Query #2)
   - **Pie chart**: Severity distribution
   - **Table**: Top IOCs (Query #4)
   - **Table**: New CVEs (Query #6)
   - **Bar chart**: MITRE ATT&CK techniques (Query #7)

---

## Step 4: Create Detection Rules (Use Cases)

### Use Case 1 — Banking IOC Match Against Endpoints

**BIOC Rule** (Behavioral Indicator of Compromise):

1. Go to **Correlation → BIOC Rules → New BIOC Rule**
2. Rule type: **XQL**
3. Paste:
```xql
dataset = xdr_data
| filter _time > now() - 1h
| join type=inner (
    dataset = global_threat_intel_raw
    | filter event_type = "ioc" and target_sector = "banking"
    | filter _time > now() - 24h
    | fields ioc_value
) as threat on threat.ioc_value = action_remote_ip or threat.ioc_value = dns_query_name
```
4. Severity: **High**
5. Alert name: `Banking Threat IOC Detected on Endpoint`

---

### Use Case 2 — Critical CVE Published for Software You Run

1. **Correlation → Analytics Rules → New Rule**
2. XQL filter:
```xql
dataset = global_threat_intel_raw
| filter source_feed = "CISA KEV"
| filter severity = "critical"
| filter _time > now() - 1h
```
3. Alert: `Critical Actively-Exploited CVE Added to CISA KEV`
4. Severity: **Critical**
5. Action: Create incident + notify SOC

---

### Use Case 3 — Spike in Banking Sector Threats

1. **Correlation → Analytics Rules → Anomaly Detection**
2. Track: count of `target_sector = "banking"` events per hour
3. Alert when count > 2x the 7-day average
4. This fires when there's a sudden surge — e.g. a new campaign targeting banks

---

## Step 5: Configure Scheduled Run

### Option A — Run as a background service on a Linux VM / server
```bash
# Install dependencies
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
nano .env

# Run the scheduler (keeps running, fires daily at configured UTC time)
python main.py

# Or run once immediately:
python pipeline.py
```

### Option B — Cron job (simpler)
```cron
# Run every day at 6:00 AM UTC
0 6 * * * cd /path/to/project && python pipeline.py >> /var/log/threat_intel.log 2>&1
```

### Option C — Docker (recommended for production)
See Dockerfile below.

---

## What You'll See After Setup

| Where in XSIAM | What You See |
|---|---|
| Dashboard | Daily attack volume, banking threats, severity breakdown |
| XQL Search | Query any field — IOC, CVE, threat actor, sector, technique |
| BIOC Alerts | Real-time alert if your endpoint hits a known-bad IOC |
| Incidents | Auto-created when critical CVE or banking IOC match fires |
| Timeline | Full history of all threat intel ingested, searchable |

The most powerful view: run the **IOC Correlation query** (Query #8) — it will show you if any device in your environment communicated with a domain or IP that appeared in today's threat intel feed.
