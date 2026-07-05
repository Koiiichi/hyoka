#!/bin/bash
set -e
python3 <<'PYTHON_SCRIPT'
"""
Oracle for execution-vbs-launcher-hunt. Detects the script-host execution chain:
find the wscript/cscript launcher, walk its process tree via parent_process_guid,
and flag the tree's process creations and network connections.
"""
import json, os, sqlite3
from pathlib import Path
TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
conn = sqlite3.connect(str(TASK_ROOT / "data" / "eventlogs.db"))

tree = {r[0] for r in conn.execute(
    "SELECT process_guid FROM events WHERE event_code=1 "
    "AND (lower(image) LIKE '%\\wscript.exe' OR lower(image) LIKE '%\\cscript.exe')"
    ).fetchall() if r[0]}
changed = True
while changed:
    changed = False
    for (g, pg) in conn.execute("SELECT process_guid, parent_process_guid FROM events WHERE event_code=1").fetchall():
        if pg in tree and g and g not in tree:
            tree.add(g); changed = True

ids = set()
if tree:
    ph = ",".join("?" for _ in tree)
    for (eid,) in conn.execute(
        f"SELECT event_id FROM events WHERE process_guid IN ({ph}) AND event_code IN (1,3)",
        list(tree)).fetchall():
        ids.add(eid)
conn.close()
(TASK_ROOT / "findings.json").write_text(json.dumps(sorted(ids), indent=2), encoding="utf-8")
PYTHON_SCRIPT
