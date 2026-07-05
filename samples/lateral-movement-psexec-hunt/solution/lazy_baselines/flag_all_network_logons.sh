#!/bin/bash
# Lazy baseline: flag all network logons (Security 4624 type 3). Over-includes
# benign machine-account logons and misses the service-install + Sysmon events
# in other logs -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code=4624 AND logon_type='3'")], open(f"{sys.argv[1]}/findings.json","w"))
PY
