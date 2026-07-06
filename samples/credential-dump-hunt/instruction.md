A real intrusion is hidden in a database of raw Windows event logs (Security channel and Sysmon) collected from three machines (`DC01`, `WS-05`, `WS-06`) in the `corp.example` domain over a short window. The vast majority of the events are ordinary system and user activity.

The logs are in a SQLite database at `/root/data/eventlogs.db`, in a single table `events`. Each row has: `event_id` (a unique identifier you will report), `timestamp`, `event_code` (the Windows/Sysmon Event ID), `channel`, `provider`, `host`, `user`, `image`, `target_image`, `granted_access`, `src_ip`, `dst_ip`, `dst_port`, `process_guid`, and `message`.

You are given no indicators, no time range, and no affected host. Identify the events that make up the malicious activity.

Write your findings to `/root/findings.json` as a JSON list of the `event_id` values of the malicious events:

```json
["evt-00042", "evt-00137"]
```

Your flagged set is scored by **F1** against the ground-truth set of malicious events. Flagging benign events destroys precision; missing malicious events destroys recall. A precise, complete identification of the intrusion's malicious events is required.
