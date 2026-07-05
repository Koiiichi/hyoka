#!/bin/bash
set -e

python3 <<'PYTHON_SCRIPT'
"""
Oracle for discovery-account-enum-hunt. Genuine account-discovery detection
across two sources: the reconnaissance commands (Sysmon 1, net.exe/net1.exe with
localgroup/user/group arguments) and the Windows Security membership-enumeration
audit events (4798/4799). Neither source alone holds the full set.
"""
import json, os, sqlite3
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DB = TASK_ROOT / "data" / "eventlogs.db"
OUTPUT = TASK_ROOT / "findings.json"

conn = sqlite3.connect(str(DB))
ids = set()

for (eid,) in conn.execute("SELECT event_id FROM events WHERE event_code IN (4798, 4799)"):
    ids.add(eid)

for (eid,) in conn.execute(
    """SELECT event_id FROM events
       WHERE event_code = 1
         AND (lower(image) LIKE '%\\net.exe' OR lower(image) LIKE '%\\net1.exe')
         AND (lower(command_line) LIKE '%localgroup%'
              OR lower(command_line) LIKE '%user%'
              OR lower(command_line) LIKE '%group%')"""):
    ids.add(eid)

conn.close()
OUTPUT.write_text(json.dumps(sorted(ids), indent=2), encoding="utf-8")
PYTHON_SCRIPT
