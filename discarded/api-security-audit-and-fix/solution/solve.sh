#!/bin/bash
# Oracle: fix all three vulnerabilities minimally while preserving behavior.
#   V1 IDOR      -> enforce owner check on document access
#   V2 mass-assign-> whitelist updatable profile fields
#   V3 SSTI      -> pass user input as a template variable, not as template text
set -e
ROOT="${TASK_ROOT:-/root}"
cat > "${ROOT}/app/server.py" <<'PYEOF'
"""
Internal team API service.
"""
from flask import Flask, request, jsonify, abort, render_template_string

app = Flask(__name__)

USERS = {
    "alice": {"id": 1, "password": "alice-pw", "role": "user", "display_name": "Alice", "email": "alice@corp.example"},
    "bob": {"id": 2, "password": "bob-pw", "role": "user", "display_name": "Bob", "email": "bob@corp.example"},
    "carol": {"id": 3, "password": "carol-pw", "role": "admin", "display_name": "Carol", "email": "carol@corp.example"},
}

DOCUMENTS = {
    101: {"id": 101, "owner_id": 1, "title": "Alice roadmap", "body": "ALICE_PRIVATE_ROADMAP"},
    102: {"id": 102, "owner_id": 2, "title": "Bob salary review", "body": "BOB_PRIVATE_SALARY"},
    103: {"id": 103, "owner_id": 3, "title": "Admin runbook", "body": "ADMIN_RUNBOOK"},
}

SESSIONS = {}
ALLOWED_PROFILE_FIELDS = {"display_name", "email"}


def current_user():
    token = request.headers.get("X-Session", "")
    username = SESSIONS.get(token)
    if not username:
        abort(401)
    return USERS[username]


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    user = USERS.get(data.get("username", ""))
    if not user or user["password"] != data.get("password"):
        abort(401)
    token = f"tok-{data['username']}"
    SESSIONS[token] = data["username"]
    return jsonify({"token": token})


@app.route("/api/documents/<int:doc_id>")
def get_document(doc_id):
    user = current_user()
    doc = DOCUMENTS.get(doc_id)
    if doc is None:
        abort(404)
    if doc["owner_id"] != user["id"]:
        abort(403)
    return jsonify(doc)


@app.route("/api/profile", methods=["POST"])
def update_profile():
    user = current_user()
    updates = request.get_json(silent=True) or {}
    for field in ALLOWED_PROFILE_FIELDS:
        if field in updates:
            user[field] = updates[field]
    return jsonify({"status": "updated", "profile": user})


@app.route("/api/admin/users")
def admin_users():
    user = current_user()
    if user["role"] != "admin":
        abort(403)
    return jsonify({"users": [{"username": u, "role": USERS[u]["role"]} for u in USERS]})


@app.route("/api/greeting")
def greeting():
    name = request.args.get("name", "guest")
    return render_template_string("<p>Hello {{ name }}!</p>", name=name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
PYEOF
