---
name: windows-eventlog-threat-hunting
description: Use when threat hunting over a database of Windows Security and Sysmon event logs to locate malicious activity with no prior indicators.
---

# Windows Event Log Threat Hunting Quick Reference

General methodology and field reference. Not specific to any one investigation
and contains no indicators for it.

## Querying

The events are in a SQLite table `events`. Start by understanding the shape of
the data before hunting:

```
sqlite3 /root/data/eventlogs.db ".schema events"
sqlite3 /root/data/eventlogs.db "SELECT event_code, COUNT(*) FROM events GROUP BY event_code ORDER BY 2 DESC;"
sqlite3 /root/data/eventlogs.db "SELECT DISTINCT image FROM events;"
```

## Hunting methodology

1. Baseline first: what processes, hosts, users, and destinations are normal and
   high-volume? Anomalies stand out against a baseline.
2. Form hypotheses around adversary objectives (execution, credential access,
   discovery, lateral movement, command-and-control, exfiltration) and query for
   each rather than reading events one by one.
3. Pivot on a strong signal. Once one event looks malicious, pivot on its
   `process_guid`, `host`, `user`, or network peer to pull the related activity —
   an intrusion is usually a connected set of events from the same actor/process.
4. Separate signal from noise. Verbose logging (script-block logs, routine system
   activity) dominates volume; the malicious events are a small, connected subset.

## Common Sysmon event codes

| Code | Meaning |
|---|---|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image/DLL loaded |
| 8 | CreateRemoteThread |
| 10 | Process access (one process opening a handle into another) |
| 11 | File created |
| 12/13/14 | Registry activity |
| 22 | DNS query |

## Common Windows Security event codes

| Code | Meaning |
|---|---|
| 4624 / 4625 | Logon success / failure |
| 4688 | Process creation |
| 4672 | Special privileges assigned |
| 5140 / 5145 | Network share access |

Map what you find to MITRE ATT&CK to reason about the stage of an intrusion, but
the grading is on the event ids you flag, not on technique labels.
