#!/bin/bash
set -e

python3 <<'PYTHON_SCRIPT'
"""
Oracle for persistence-run-key-hunt. Genuine detection: the process that wrote
a Run-key value (Sysmon 13, TargetObject under CurrentVersion\\Run) is
confirmed malicious; flag its persistence write and its C2 network connections
(Sysmon 3). Correlates registry persistence with network beaconing via the
process GUID.
"""
import json, os, sqlite3
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DB = TASK_ROOT / "data" / "eventlogs.db"
OUTPUT = TASK_ROOT / "findings.json"

conn = sqlite3.connect(str(DB))

guids = [r[0] for r in conn.execute(
    "SELECT DISTINCT process_guid FROM events "
    "WHERE event_code = 13 AND lower(target_object) LIKE '%currentversion\\run%' ESCAPE '\\' "
    "AND process_guid IS NOT NULL").fetchall()]
# Fallback if ESCAPE handling differs: broad match then filter.
if not guids:
    guids = [r[0] for r in conn.execute(
        "SELECT DISTINCT process_guid FROM events WHERE event_code=13 "
        "AND lower(target_object) LIKE '%currentversion%run%' AND process_guid IS NOT NULL").fetchall()]

ids = set()
if guids:
    ph = ",".join("?" for _ in guids)
    for (eid,) in conn.execute(
        f"""SELECT event_id FROM events WHERE process_guid IN ({ph})
            AND (event_code = 3 OR (event_code = 13 AND lower(target_object) LIKE '%currentversion%run%'))""",
        guids).fetchall():
        ids.add(eid)

conn.close()
OUTPUT.write_text(json.dumps(sorted(ids), indent=2), encoding="utf-8")
PYTHON_SCRIPT
