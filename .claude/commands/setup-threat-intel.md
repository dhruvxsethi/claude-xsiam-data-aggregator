Set up and run the XSIAM Threat Intel pipeline end-to-end. Follow these steps in order:

## Step 1 — Credentials

Check if `.env` exists. If not, run: `cp .env.example .env`

Read `.env` and check for missing or placeholder values:
- `OTX_API_KEY` — free at https://otx.alienvault.com → profile icon → API Integration
- `XSIAM_BASE_URL` — full endpoint URL from the Custom HTTP Based Collector in XSIAM (Settings → Data Sources → your collector)
- `XSIAM_API_KEY` — token from the same screen (click "Save & Generate Token" if not yet generated)

For each missing value, tell the user exactly where to get it and ask them to paste it in. Write it to `.env` once provided.

## Step 2 — Test collectors

Run: `python pipeline.py --dry-run`

Show the summary output. If all sources return 0 events with ConnectError, tell the user it's a network issue (VPN or firewall blocking outbound HTTP) — the code is fine.

If some sources work, confirm which ones collected data.

## Step 3 — Push to XSIAM

Ask: "Ready to push to XSIAM?" — if yes, run: `python pipeline.py`

After a successful push, show this XQL query to verify data arrived:
```
dataset = custom_threatintelaggregator_raw
| limit 10
```
Tell them: XSIAM → Investigation → XQL Search → paste the query. Rows = working.

## Step 4 — Set up daily schedule in Claude Code

Ask the user: "Do you want to set up a daily automated schedule so this runs every morning without you doing anything?"

If yes, use the `schedule` skill or CronCreate to schedule a daily job that runs:
```bash
cd "/path/to/project" && python pipeline.py
```
Set it to run at 6:00 AM UTC daily. Confirm the schedule was created and tell the user they can check it with `/schedule list` or equivalent.

## Step 5 — Confirm everything

Summarise:
- Which credentials are configured
- Whether the pipeline ran successfully
- Whether the schedule is set up
- The XQL query to use in XSIAM daily
