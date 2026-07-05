#!/bin/bash
set -e
python3 <<'PYTHON_SCRIPT'
"""
Oracle for defense-evasion-injection-hunt. Detects the LOLBin + injection chain:
find the source of a CreateRemoteThread (Sysmon 8), then flag that process's
creation (Sysmon 1), its DLL loads from outside C:\\Windows (Sysmon 7), and the
CreateRemoteThread itself.
"""
import json, os, sqlite3
from pathlib import Path
TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
conn = sqlite3.connect(str(TASK_ROOT / "data" / "eventlogs.db"))

injectors = [r[0] for r in conn.execute(
    "SELECT DISTINCT process_guid FROM events WHERE event_code=8 AND process_guid IS NOT NULL").fetchall()]

ids = set()
if injectors:
    ph = ",".join("?" for _ in injectors)
    for (eid,) in conn.execute(
        f"""SELECT event_id FROM events WHERE process_guid IN ({ph})
            AND (event_code IN (1, 8)
                 OR (event_code = 7 AND lower(image_loaded) NOT LIKE 'c:\\windows%'))""",
        injectors).fetchall():
        ids.add(eid)
conn.close()
(TASK_ROOT / "findings.json").write_text(json.dumps(sorted(ids), indent=2), encoding="utf-8")
PYTHON_SCRIPT
