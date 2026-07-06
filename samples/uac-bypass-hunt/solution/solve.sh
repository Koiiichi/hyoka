#!/bin/bash
set -e
python3 <<'PYTHON_SCRIPT'
"""
Oracle for privesc-uac-bypass-hunt. Cross-source UAC-bypass detection: the
ms-settings\\Shell\\Open\\command registry hijack (Sysmon 12/13), the
fodhelper.exe launch (Sysmon 1), and the elevated child fodhelper spawns.
"""
import json, os, sqlite3
from pathlib import Path
TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
conn = sqlite3.connect(str(TASK_ROOT / "data" / "eventlogs.db"))
ids = set()
for (eid,) in conn.execute(
    "SELECT event_id FROM events WHERE event_code IN (12,13) "
    "AND lower(target_object) LIKE '%ms-settings\\shell\\open\\command%' ESCAPE '\\'"):
    ids.add(eid)
if len(ids) == 0:
    for (eid,) in conn.execute(
        "SELECT event_id FROM events WHERE event_code IN (12,13) "
        "AND lower(target_object) LIKE '%ms-settings%shell%open%command%'"):
        ids.add(eid)
for (eid,) in conn.execute("SELECT event_id FROM events WHERE event_code=1 AND lower(image) LIKE '%\\fodhelper.exe' ESCAPE '\\'"):
    ids.add(eid)
for (eid,) in conn.execute("SELECT event_id FROM events WHERE event_code=1 AND lower(parent_image) LIKE '%\\fodhelper.exe' ESCAPE '\\'"):
    ids.add(eid)
conn.close()
(TASK_ROOT / "findings.json").write_text(json.dumps(sorted(ids), indent=2), encoding="utf-8")
PYTHON_SCRIPT
