#!/bin/bash
# Lazy baseline: flag everything with a c=/cmd= parameter, label all T1059. This
# grabs the benign /api/report?cmd=export feature (decoy), misses the login and
# upload steps, and mislabels every phase -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sys, re, json
root = sys.argv[1]
out = []
for ln in open(f"{root}/data/access_log.txt"):
    if re.search(r'\?(c|cmd)=', ln):
        m = re.search(r"rid=(\S+)", ln)
        if m:
            out.append({"request_id": m.group(1), "mitre_technique": "T1059"})
open(f"{root}/findings.json", "w").write(json.dumps(out, indent=2))
PY
