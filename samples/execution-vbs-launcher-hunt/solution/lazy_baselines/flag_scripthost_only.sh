#!/bin/bash
# Lazy baseline: flag only wscript/cscript events. Misses the spawned PowerShell,
# its children, and the C2 network -> recall gap -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
q="SELECT event_id FROM events WHERE lower(image) LIKE '%wscript.exe' OR lower(image) LIKE '%cscript.exe'"
json.dump([r[0] for r in c.execute(q)], open(f"{sys.argv[1]}/findings.json","w"))
PY
