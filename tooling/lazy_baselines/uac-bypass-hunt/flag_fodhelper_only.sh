#!/bin/bash
# Lazy baseline: flag only fodhelper.exe process events. Misses the registry
# hijack that is the actual bypass mechanism (cross-source recall gap) -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE lower(image) LIKE '%fodhelper.exe' OR lower(parent_image) LIKE '%fodhelper.exe'")], open(f"{sys.argv[1]}/findings.json","w"))
PY
