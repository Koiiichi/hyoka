#!/bin/bash
# Lazy baseline: "fix" by locking everything down -- documents always 403,
# profile updates ignored, greeting static. Blocks the exploits but breaks
# legitimate behavior -> functional suite fails.
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/app/server.py" <<'PYEOF'
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
USERS = {
    "alice": {"id": 1, "password": "alice-pw", "role": "user", "display_name": "Alice", "email": "alice@corp.example"},
    "bob": {"id": 2, "password": "bob-pw", "role": "user", "display_name": "Bob", "email": "bob@corp.example"},
    "carol": {"id": 3, "password": "carol-pw", "role": "admin", "display_name": "Carol", "email": "carol@corp.example"},
}
SESSIONS = {}


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    u = USERS.get(data.get("username", ""))
    if not u or u["password"] != data.get("password"):
        abort(401)
    SESSIONS[f"tok-{data['username']}"] = data["username"]
    return jsonify({"token": f"tok-{data['username']}"})


@app.route("/api/documents/<int:doc_id>")
def get_document(doc_id):
    abort(403)


@app.route("/api/profile", methods=["POST"])
def update_profile():
    return jsonify({"status": "updated"})


@app.route("/api/admin/users")
def admin_users():
    abort(403)


@app.route("/api/greeting")
def greeting():
    return "<p>Hello!</p>"
PYEOF
