#!/bin/bash
# Lazy baseline: fix only the most obvious vulnerability (IDOR), miss the mass-
# assignment and SSTI issues. Models the incomplete audit -> security suite fails.
set -e
ROOT="${TASK_ROOT:-/root}"
python3 - "$ROOT" <<'PY'
import sys, re
p = f"{sys.argv[1]}/app/server.py"
src = open(p).read()
# Add an owner check to get_document only.
src = src.replace(
    '    if doc is None:\n        abort(404)\n    # Return the requested document.\n    return jsonify(doc)',
    '    if doc is None:\n        abort(404)\n    if doc["owner_id"] != user["id"]:\n        abort(403)\n    return jsonify(doc)'
)
open(p, "w").write(src)
PY
