#!/bin/bash
set -e

python3 <<'PYTHON_SCRIPT'
"""
Oracle for lateral-movement-psexec-hunt. Genuine cross-source detection:
  - a service installed with an encoded-PowerShell ImagePath (Security 4697 and
    System 7045) -- a PsExec-style stager service,
  - the non-machine network logon (Security 4624 type 3) that authenticated it,
  - the service-spawned encoded-PowerShell process (Sysmon 1, parent services.exe).
No single log holds the whole chain.
"""
import json, os, sqlite3
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
DB = TASK_ROOT / "data" / "eventlogs.db"
OUTPUT = TASK_ROOT / "findings.json"

conn = sqlite3.connect(str(DB))
ids = set()

for (eid,) in conn.execute(
    """SELECT event_id FROM events
       WHERE event_code IN (4697, 7045)
         AND lower(service_file_name) LIKE '%powershell%'
         AND lower(service_file_name) LIKE '%enc%'"""):
    ids.add(eid)

for (eid,) in conn.execute(
    """SELECT event_id FROM events
       WHERE event_code = 4624 AND logon_type = '3'
         AND target_user NOT LIKE '%$' AND upper(target_user) != 'ANONYMOUS LOGON' AND target_user != ''"""):
    ids.add(eid)

for (eid,) in conn.execute(
    """SELECT event_id FROM events
       WHERE event_code = 1
         AND lower(parent_image) LIKE '%services.exe%'
         AND lower(command_line) LIKE '%-enc%'"""):
    ids.add(eid)

conn.close()
OUTPUT.write_text(json.dumps(sorted(ids), indent=2), encoding="utf-8")
PYTHON_SCRIPT
