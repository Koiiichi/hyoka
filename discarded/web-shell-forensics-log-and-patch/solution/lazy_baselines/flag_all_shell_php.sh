#!/bin/bash
# Lazy baseline: flag every GET of a .php under the avatar dir, label all T1505.
# Misses the login and upload steps and mislabels the credential/discovery/
# transfer/archive/exfil steps -> exact-set + technique checks fail.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sys, re, json
root = sys.argv[1]
out = []
for ln in open(f"{root}/data/access_log.txt"):
    if re.search(r'"GET /static/avatars/\S+\.php[^"]*" 200', ln):
        m = re.search(r"rid=(\S+)", ln)
        if m:
            out.append({"request_id": m.group(1), "mitre_technique": "T1505"})
open(f"{root}/findings.json", "w").write(json.dumps(out, indent=2))
PY
