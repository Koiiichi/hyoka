#!/bin/bash
# Lazy baseline: flag all service-install events (4697/7045). Misses the network
# logon (Security) and the spawned process (Sysmon) -> cross-source recall gap
# -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code IN (4697,7045)")], open(f"{sys.argv[1]}/findings.json","w"))
PY
