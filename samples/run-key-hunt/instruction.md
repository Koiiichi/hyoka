You are a SOC analyst performing threat hunting on a Windows host fleet. All activity is from the year **2026**.

You are given a database of raw Windows event logs (Security channel and Sysmon) collected from several machines in the `corp.example` domain over a short window. A real intrusion occurred somewhere in this telemetry; almost everything else is ordinary activity.

The logs are in a SQLite database at `/root/data/eventlogs.db`, table `events`:

```
sqlite3 /root/data/eventlogs.db ".schema events"
sqlite3 /root/data/eventlogs.db "SELECT event_code, COUNT(*) FROM events GROUP BY event_code ORDER BY 2 DESC;"
```

Columns include: `event_id` (the identifier you report), `timestamp`, `event_code`, `channel`, `provider`, `host`, `user`, `target_user`, `image`, `parent_image`, `command_line`, `logon_type`, `service_name`, `service_file_name`, `target_image`, `target_object`, `details`, `granted_access`, `src_ip`, `dst_ip`, `dst_port`, `process_guid`, `message`.

You get **no hints** — no indicators, no time window, no affected host or account. Hunt: baseline what is normal, form hypotheses about adversary behavior, and identify all events that make up the malicious activity. A single actor's activity typically spans several event types and can be tied together through fields like `process_guid`.

Write your findings to `/root/findings.json` as a JSON list of the malicious `event_id` values:

```json
["evt-00042", "evt-00137"]
```

Grading: your flagged set is scored by **F1** against the ground-truth malicious events. Over-flagging benign activity destroys precision; catching only part of the malicious activity destroys recall — identify the malicious actor's full footprint, not just the single most obvious event.
