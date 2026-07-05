#!/bin/bash
# Lazy baseline: flag all process-creation events (Sysmon 1 / 4688). Over-broad
# and misses the Security/System logon+service events -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code IN (1,4688)")], open(f"{sys.argv[1]}/findings.json","w"))
PY
