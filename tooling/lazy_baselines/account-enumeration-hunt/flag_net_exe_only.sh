#!/bin/bash
# Lazy baseline: flag only the net.exe recon commands (Sysmon). Misses the
# Windows Security 4798/4799 membership-enumeration events -> cross-source recall
# gap -> fails the bar.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
q="SELECT event_id FROM events WHERE event_code=1 AND (lower(image) LIKE '%\\net.exe' OR lower(image) LIKE '%\\net1.exe')"
json.dump([r[0] for r in c.execute(q)], open(f"{sys.argv[1]}/findings.json","w"))
PY
