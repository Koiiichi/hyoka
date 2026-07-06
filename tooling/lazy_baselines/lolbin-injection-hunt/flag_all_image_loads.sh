#!/bin/bash
# Lazy baseline: flag all image-load events (Sysmon 7). Drowns the single
# suspicious DLL load among ~180 benign loads and misses the process/thread
# events -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code=7")], open(f"{sys.argv[1]}/findings.json","w"))
PY
