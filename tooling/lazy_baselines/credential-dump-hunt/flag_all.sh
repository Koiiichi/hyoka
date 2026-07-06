#!/bin/bash
# Lazy baseline: flag every event. Recall 1, precision ~0.006 -> F1 ~0 -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3, sys, json
root = sys.argv[1]
c = sqlite3.connect(f"{root}/data/eventlogs.db")
ids = [r[0] for r in c.execute("SELECT event_id FROM events").fetchall()]
open(f"{root}/findings.json", "w").write(json.dumps(ids))
PY
