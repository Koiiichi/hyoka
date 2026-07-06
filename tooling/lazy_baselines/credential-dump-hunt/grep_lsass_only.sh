#!/bin/bash
# Lazy baseline: flag only lsass-access events (Sysmon EventID 10 to lsass).
# Catches the credential-theft reads but misses the 35 C2 beacon connections
# -> recall ~0.05 -> F1 far below the bar -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3, sys, json
root = sys.argv[1]
c = sqlite3.connect(f"{root}/data/eventlogs.db")
ids = [r[0] for r in c.execute("SELECT event_id FROM events WHERE event_code=10 AND lower(target_image) LIKE '%lsass.exe'").fetchall()]
open(f"{root}/findings.json", "w").write(json.dumps(ids))
PY
