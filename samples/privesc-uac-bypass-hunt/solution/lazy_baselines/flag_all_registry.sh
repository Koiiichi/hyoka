#!/bin/bash
# Lazy baseline: flag all registry activity (Sysmon 12/13). The ms-settings
# hijack is a needle among ~1000 registry events -> precision collapses -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3,sys,json
c=sqlite3.connect(f"{sys.argv[1]}/data/eventlogs.db")
json.dump([r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code IN (12,13)")], open(f"{sys.argv[1]}/findings.json","w"))
PY
