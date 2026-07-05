---
name: mitre-attack-reference
description: Use when mapping observed log events to MITRE ATT&CK technique IDs during threat hunting or detection engineering tasks.
---

# MITRE ATT&CK Quick Reference

A short lookup of common Enterprise ATT&CK techniques relevant to host/auth-log analysis. This is general reference material, not specific to any one investigation.

| Technique ID | Name | Typical log signature |
|---|---|---|
| T1110 | Brute Force | Repeated `Failed password` entries for the same account/source, followed by a success |
| T1078 | Valid Accounts | A legitimate-looking account used in an unexpected context (wrong time, wrong source) |
| T1021.004 | Remote Services: SSH | An `Accepted` SSH session opened from one internal host to another |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | A `sudo` invocation elevating to `root`, especially via `NOPASSWD` misconfiguration |
| T1005 | Data from Local System | A local file read/export/dump command against a sensitive data source |
| T1074 | Data Staged | Output written to an unusual or hidden location prior to exfiltration |
| T1136 | Create Account | Unexpected `useradd`/`adduser` activity |
| T1070 | Indicator Removal | Log clearing, history clearing, timestamp tampering |

General workflow for correlating a multi-host incident:
1. Establish a baseline of normal activity per host (regular users, regular hours, regular source IPs).
2. Look for an initial-access anomaly (a login that doesn't fit the baseline).
3. Trace the compromised identity/session forward in time across hosts.
4. Note any privilege change (user to root) and any data-handling command after that point.
5. Anchor each step to a timestamp and the most fitting technique ID above — a top-level technique ID (e.g. `T1021`) is acceptable even if the exact sub-technique is uncertain.
