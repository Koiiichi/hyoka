You are a SOC analyst doing weekly threat hunting for a small AWS organization (account `123456789012`, region `us-east-1`). All activity is from the year **2026**.

The org has a handful of IAM users (developers, a data engineer, an admin, a security engineer, and a CI service account) and a few roles they assume (a CI deploy role, an application runtime role, a data export role, and a security audit role).

Inputs, all under `/root/data`:
- `cloudtrail/events-2026-06-01.jsonl` through `cloudtrail/events-2026-06-07.jsonl` — CloudTrail-style management and data events, one JSON object per line, covering **2026-06-01 through 2026-06-07**. This is several thousand events of ordinary activity.
- `asset_inventory.json` — org context: the account id, `trusted_cidrs` (every network range legitimate activity originates from), `ci_egress_ips`, the list of `sensitive_buckets`, and the known IAM principals.

Each CloudTrail event includes at least: `eventID`, `eventTime` (ISO 8601 UTC, e.g. `2026-06-04T02:14:41Z`), `eventSource`, `eventName`, `sourceIPAddress`, `userAgent`, `userIdentity` (including `accessKeyId` and, for assumed roles, a `sessionContext`), `requestParameters`, and `responseElements`.

Somewhere in this week, a real compromise occurred: an over-permissioned role's credentials were used from a place they shouldn't have been, the attacker granted themselves broader access, and then read data out of a sensitive S3 bucket. The rest of the week is business-as-usual noise — routine CI builds, application traffic, batch exports, read-only security checks, and legitimate one-off admin actions, some of which superficially resemble parts of an attack.

Your job: find the actual compromise chain and write your findings to `/root/findings.json` as a JSON list, one object per CloudTrail event that is part of the chain, in this shape:

```json
[
  {"event_id": "<CloudTrail eventID>", "timestamp": "<ISO 8601, e.g. 2026-06-04T02:14:41Z>", "mitre_technique": "<MITRE ATT&CK technique ID, e.g. T1078>"}
]
```

Requirements:
- `event_id` is the CloudTrail `eventID` of the specific event. This is the field graded — report exactly the events that make up the real chain.
- Report only events that are actually part of the compromise — not every unusual-looking API call, and not benign look-alikes. A precise, minimal list is what's being graded, not a broad sweep.
- Each event needs a MITRE ATT&CK technique ID that reasonably matches what happened at that step (a sub-technique suffix is optional — the top-level technique family must be correct).
- Timestamps should reflect the 2026 event times.

You have shell access and Python 3 with the standard library available. There is no other tooling installed beyond what's already on the box — this is meant to be solved by directly parsing and correlating the CloudTrail events.
