#!/bin/bash
set -e

python3 <<'PYTHON_SCRIPT'
"""
Oracle for threat-hunt-windows-eventlogs.

Genuine detection over the event database -- it does not hardcode the answer.
Pivot: a process that reads lsass.exe memory with a credential-theft access
mask is confirmed malicious; flag that process's high-signal events -- its
lsass memory reads (Sysmon EventID 10) and its C2 network connections (Sysmon
EventID 3). This recovers the intrusion's malicious events from raw telemetry.
"""
import json
import os
import sqlite3
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DB = TASK_ROOT / "data" / "eventlogs.db"
OUTPUT = TASK_ROOT / "findings.json"

MALICIOUS_LSASS_MASKS = ("0x1010", "0x1410", "0x143a", "0x1438", "0x1418", "0x1fffff")

conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row

# 1. Identify malicious process(es): those that read lsass memory with a
#    credential-dumping access mask.
placeholders = ",".join("?" for _ in MALICIOUS_LSASS_MASKS)
guids = [
    r["process_guid"]
    for r in conn.execute(
        f"""SELECT DISTINCT process_guid FROM events
            WHERE event_code = 10
              AND lower(target_image) LIKE '%lsass.exe'
              AND granted_access IN ({placeholders})
              AND process_guid IS NOT NULL""",
        MALICIOUS_LSASS_MASKS,
    ).fetchall()
]

# 2. Flag that process's high-signal events: credential access (10) and C2
#    network connections (3).
malicious = []
if guids:
    gph = ",".join("?" for _ in guids)
    malicious = [
        r["event_id"]
        for r in conn.execute(
            f"""SELECT event_id FROM events
                WHERE process_guid IN ({gph}) AND event_code IN (3, 10)""",
            guids,
        ).fetchall()
    ]

conn.close()
OUTPUT.write_text(json.dumps(sorted(set(malicious)), indent=2), encoding="utf-8")
PYTHON_SCRIPT
