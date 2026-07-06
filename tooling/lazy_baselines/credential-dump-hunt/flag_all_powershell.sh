#!/bin/bash
# Lazy baseline: flag every event whose image is powershell. Empire runs heavily
# through powershell but so does benign activity, and most powershell events are
# not the C2/credential-theft events -> precision and recall both poor -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sqlite3, sys, json
root = sys.argv[1]
c = sqlite3.connect(f"{root}/data/eventlogs.db")
ids = [r[0] for r in c.execute("SELECT event_id FROM events WHERE lower(image) LIKE '%powershell%'").fetchall()]
open(f"{root}/findings.json", "w").write(json.dumps(ids))
PY
