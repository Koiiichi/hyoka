#!/bin/bash
# Lazy baseline: naive blocklist that only rejects a literal '../'. It still
# leaks via the absolute-path vector (/etc/passwd) and URL-encoded traversal,
# so the security suite fails. The classic incomplete fix.
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
    name = request.args.get("name", "")
    if not name:
        abort(400)
    if "../" in name:
        abort(403)
    path = os.path.join(BASE_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.route("/preview")
def preview():
    name = request.args.get("name", "")
    allowed = {"readme.txt", "notes.txt", "report.txt"}
    if name not in allowed:
        abort(403)
    return send_file(os.path.join(BASE_DIR, name))
PYEOF
