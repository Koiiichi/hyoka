#!/bin/bash
# Lazy baseline: "fix" by disabling the endpoint entirely (always 403). This
# blocks traversal but breaks legitimate downloads, so the functional suite
# fails. Proves over-aggressive fixes do not pass.
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/app/server.py" <<'PYEOF'
import os

from flask import Flask, request, send_file, abort, jsonify

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/download")
def download():
    abort(403)


@app.route("/preview")
def preview():
    name = request.args.get("name", "")
    allowed = {"readme.txt", "notes.txt", "report.txt"}
    if name not in allowed:
        abort(403)
    return send_file(os.path.join(BASE_DIR, name))
PYEOF
