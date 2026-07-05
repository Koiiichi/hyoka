#!/bin/bash
# Lazy baseline: flag every network-connection event (Sysmon EventID 3). Grabs
# all benign network traffic too -> precision ~0.4, and misses the lsass reads
# -> F1 well below the bar -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3, sys, json
root = sys.argv[1]
c = sqlite3.connect(f"{root}/data/eventlogs.db")
ids = [r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code=3").fetchall()]
open(f"{root}/findings.json", "w").write(json.dumps(ids))
PY
