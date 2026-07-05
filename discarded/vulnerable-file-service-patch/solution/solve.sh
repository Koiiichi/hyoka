#!/bin/bash
# Oracle: minimal correct fix. Confine /download to the content directory using
# werkzeug's safe_join, which returns None for any traversal or absolute path.
# Legitimate downloads keep working; every traversal vector is blocked.
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/app/server.py" <<'PYEOF'
"""
Internal file-distribution service.
"""
import os

from flask import Flask, request, send_file, abort, jsonify
from werkzeug.security import safe_join

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/download")
def download():
    """Download a document from the content directory by name."""
    name = request.args.get("name", "")
    if not name:
        abort(400)
    path = safe_join(BASE_DIR, name)
    if path is None:
        abort(403)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.route("/preview")
def preview():
    """Preview one of a small set of allow-listed documents."""
    name = request.args.get("name", "")
    allowed = {"readme.txt", "notes.txt", "report.txt"}
    if name not in allowed:
        abort(403)
    return send_file(os.path.join(BASE_DIR, name))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
PYEOF
