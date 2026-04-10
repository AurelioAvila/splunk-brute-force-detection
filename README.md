# SOC Lab — Brute Force Detection with Splunk

## Scenario
A Windows endpoint generated multiple failed authentication events
in a short timeframe. I ingested the logs into Splunk Cloud and
used SPL queries to identify a brute force attack against the
administrator account.

## Objective
Simulate a Tier 1 SOC analyst workflow using Splunk:
1. Ingest Windows Security event logs into Splunk Cloud
2. Query failed logon events (EventCode 4625) using SPL
3. Identify brute force patterns by counting failed attempts per IP
4. Produce an incident report with verdict and recommendations

## Tools Used
- Splunk Cloud (free trial)
- SPL (Search Processing Language)
- Windows Security Event Logs (simulated)

## Detection Logic

### Query 1 — Failed Logon Events
```spl
source="windows_security.log" EventCode=4625
| rex "Account Name=(?<account>[^,]+)"
| rex "IP Address=(?<ip>[^,]+)"
| rex "Failure Reason=(?<reason>[^\n]+)"
| table _time, account, ip, reason
| sort _time
```

### Query 2 — Brute Force Detection
```spl
source="windows_security.log" EventCode=4625
| rex "Account Name=(?<account>[^,]+)"
| rex "IP Address=(?<ip>[^,]+)"
| stats count by ip, account
| where count >= 3
| sort -count
| rename count as "Failed Attempts", ip as "Source IP", account as "Target Account"
```

## Results
- **Source IP:** 192.168.1.105
- **Target Account:** administrator
- **Failed Attempts:** 5 in 4 seconds
- **VERDICT: BRUTE FORCE DETECTED**

## Evidence
- `screenshot_splunk_query1.png` — Failed logon events timeline
- `screenshot_splunk_brute_force.png` — Brute force detection query

## What I Learned
- How to ingest and parse Windows Security logs in Splunk Cloud
- How to write SPL queries for threat detection
- How to identify brute force patterns using stats and aggregation
- How SPL compares to KQL (Microsoft Sentinel)