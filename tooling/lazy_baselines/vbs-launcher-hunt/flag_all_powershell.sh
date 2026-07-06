#!/bin/bash
# Lazy baseline: flag all powershell activity. Over-broad and misses the launcher
# and network -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE lower(image) LIKE '%powershell%'")], open(f"{sys.argv[1]}/findings.json","w"))
PY
