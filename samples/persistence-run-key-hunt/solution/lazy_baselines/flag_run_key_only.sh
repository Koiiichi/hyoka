#!/bin/bash
# Lazy baseline: flag only the Run-key write(s). Catches the persistence IOC but
# misses the C2 beaconing of the same process -> recall gap -> fails the bar.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code=13 AND lower(target_object) LIKE '%currentversion%run%'")], open(f"{sys.argv[1]}/findings.json","w"))
PY
