#!/bin/bash
# Lazy baseline: flag every request from the attacker IP (including the failed
# login attempts), all labelled T1059. Over-broad (>12 findings, includes the
# non-chain 401 probes) and mislabels every step -> fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sys, re, json
root = sys.argv[1]
out = []
for ln in open(f"{root}/data/access_log.txt"):
    if ln.startswith("203.0.113.66 "):
        m = re.search(r"rid=(\S+)", ln)
        if m:
            out.append({"request_id": m.group(1), "mitre_technique": "T1059"})
open(f"{root}/findings.json", "w").write(json.dumps(out, indent=2))
PY
