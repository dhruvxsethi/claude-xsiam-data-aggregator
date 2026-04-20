# XSIAM XQL Queries — Threat Intel Dashboard

Once logs are flowing into XSIAM, paste these into XQL Search or save them as Widgets.

---

## 1. All Events from Last 24 Hours

```xql
dataset = global_threat_intel_raw
| filter _time > now() - 1d
| fields _time, source_feed, event_type, severity, title, target_sector
| sort _time desc
```

---

## 2. Banking Sector Attacks Only

```xql
dataset = global_threat_intel_raw
| filter target_sector = "banking" or target_sector = "finance"
| filter _time > now() - 7d
| fields _time, source_feed, event_type, severity, threat_actor, title, ioc_type, ioc_value
| sort _time desc
```

---

## 3. Daily Event Volume by Source (for a Bar Chart widget)

```xql
dataset = global_threat_intel_raw
| filter _time > now() - 30d
| comp count() as event_count by bin(_time, 1d), source_feed
| sort _time asc
```

---

## 4. Top IOCs — Domains and IPs (last 7 days)

```xql
dataset = global_threat_intel_raw
| filter event_type = "ioc"
| filter ioc_type in ("domain", "ip")
| filter _time > now() - 7d
| comp count() as sightings by ioc_value, ioc_type
| sort sightings desc
| limit 50
```

---

## 5. Critical + High Severity Events

```xql
dataset = global_threat_intel_raw
| filter severity in ("critical", "high")
| filter _time > now() - 24h
| fields _time, source_feed, cve_id, title, severity, affected_product, description
| sort severity asc, _time desc
```

---

## 6. New Actively-Exploited CVEs (CISA KEV)

```xql
dataset = global_threat_intel_raw
| filter source_feed = "CISA KEV"
| filter _time > now() - 7d
| fields _time, cve_id, affected_product, severity, description, reference_url
| sort _time desc
```

---

## 7. MITRE ATT&CK Techniques Distribution

```xql
dataset = global_threat_intel_raw
| filter mitre_technique != null
| filter _time > now() - 30d
| comp count() as count by mitre_technique, mitre_tactic
| sort count desc
```

---

## 8. IOC Correlation — Check if Any Known-Bad IOC Appeared in Your Environment
# Run this against your endpoint/network dataset to find matches

```xql
// Step 1: Get today's bad IOCs
dataset = global_threat_intel_raw
| filter event_type = "ioc"
| filter _time > now() - 1d
| fields ioc_value
| dedup ioc_value

// Step 2 (separate query): Join against XDR endpoint telemetry
dataset = xdr_data
| filter action_remote_ip != null or dns_query_name != null
| filter _time > now() - 1d
| join type=inner (
    dataset = global_threat_intel_raw
    | filter event_type = "ioc" and ioc_type = "ip"
    | fields ioc_value
) as threat on threat.ioc_value = action_remote_ip
| fields _time, agent_hostname, action_remote_ip, threat.ioc_value
```

---

## 9. Threat Actor Activity Tracker

```xql
dataset = global_threat_intel_raw
| filter threat_actor != null
| filter _time > now() - 30d
| comp count() as campaigns by threat_actor
| sort campaigns desc
| limit 20
```

---

## 10. Geography of Threats

```xql
dataset = global_threat_intel_raw
| filter geo_origin != null
| filter _time > now() - 7d
| comp count() as attacks by geo_origin
| sort attacks desc
```
