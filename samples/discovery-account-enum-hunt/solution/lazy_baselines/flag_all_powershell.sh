#!/bin/bash
# Lazy baseline: flag all powershell-related events. Over-broad (Empire runs via
# powershell but so does benign activity) and misses the Security enumeration
# events -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE lower(image) LIKE '%powershell%'")], open(f"{sys.argv[1]}/findings.json","w"))
PY
