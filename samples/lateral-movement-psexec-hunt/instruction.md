You are a SOC analyst performing threat hunting on a Windows domain. All activity is from the year **2026**.

You are given a database of raw Windows event logs collected from several machines in the `corp.example` domain (Security channel, the System log, and Sysmon) over a short window. A real intrusion occurred somewhere in this telemetry; the overwhelming majority of events are ordinary activity.

The logs are in a SQLite database at `/root/data/eventlogs.db`, table `events`. Inspect and query it:

```
sqlite3 /root/data/eventlogs.db ".schema events"
sqlite3 /root/data/eventlogs.db "SELECT event_code, COUNT(*) FROM events GROUP BY event_code ORDER BY 2 DESC;"
```

Columns include: `event_id` (the identifier you report), `timestamp`, `event_code`, `channel`, `provider`, `host`, `user`, `image`, `parent_image`, `command_line`, `logon_type`, `service_name`, `service_file_name`, `target_image`, `target_object`, `details`, `granted_access`, `src_ip`, `dst_ip`, `dst_port`, `process_guid`, `message`.

You get **no hints** — no indicators, no time window, no affected host or account. Hunt: baseline what is normal, form hypotheses about adversary behavior, and identify the events that make up the malicious activity. Note that the evidence for a single action may be split across different log sources (Security, System, Sysmon) — you will likely need to correlate across them.

Write your findings to `/root/findings.json` as a JSON list of the malicious `event_id` values:

```json
["evt-00042", "evt-00137"]
```

Grading: your flagged set is scored by **F1** against the ground-truth malicious events. Over-flagging benign activity destroys precision; missing part of the malicious activity destroys recall.

You have shell access, `sqlite3`, and Python 3 (standard library). Solve by querying and correlating the logs.
