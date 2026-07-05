You are a SOC analyst doing weekly threat hunting for a small infrastructure of three Linux hosts: `web01`, `app02`, and `db03`.

All logs are from the year **2026**. Note that standard syslog auth-log lines omit the year.

Inputs, all under `/root/data`:
- `logs/web01.log`, `logs/app02.log`, `logs/db03.log` — raw auth-log-style entries (SSH sessions, sudo invocations, cron) for the week of **2026-05-04 through 2026-05-10**.
- `asset_inventory.json` — known host IP addresses and known engineer workstation IP addresses. Anything not in this inventory is untrusted/external.

Somewhere in this week's logs, a real compromise occurred: an attacker got a foothold and moved across the environment. The rest of the week's traffic is ordinary business-as-usual noise — legitimate engineer logins, routine cron jobs, and an unrelated internet background-noise scanner that never actually succeeds at logging in.

Your job: find the actual compromise chain and write your findings to `/root/findings.json` as a JSON list, one object per event, in this shape:

```json
[
  {"host": "<hostname>", "timestamp": "<ISO 8601, e.g. 2026-05-06T02:14:41>", "mitre_technique": "<MITRE ATT&CK technique ID, e.g. T1110>"}
]
```

Requirements:
- Report only events that are actually part of the real compromise chain — not every failed login attempt, and not the background scanner. A precise, minimal list is what's being graded, not a broad sweep.
- Each event needs the correct host, the correct timestamp (to the second), and a MITRE ATT&CK technique ID that reasonably matches what happened at that step (sub-technique suffix is optional — the top-level technique family must be correct).
- Timestamps must reflect the year 2026.

You have shell access and Python 3 with the standard library available. There is no other tooling installed beyond what's already on the box — this is meant to be solved by directly reading and correlating the log files.
