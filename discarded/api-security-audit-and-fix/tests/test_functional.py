"""
Functional suite (executed). Legitimate behavior must be preserved -- a fix that
disables a feature to dodge a vulnerability does not pass.
"""
from conftest import login


def test_login_success_and_failure(client):
    token = login(client, "alice", "alice-pw")
    assert token
    bad = client.post("/login", json={"username": "alice", "password": "wrong"})
    assert bad.status_code == 401


def test_owner_can_read_own_document(client):
    token = login(client, "alice", "alice-pw")
    resp = client.get("/api/documents/101", headers={"X-Session": token})
    assert resp.status_code == 200
    assert "ALICE_PRIVATE_ROADMAP" in resp.get_data(as_text=True)


def test_profile_legitimate_update_works(client):
    token = login(client, "alice", "alice-pw")
    resp = client.post("/api/profile", headers={"X-Session": token},
                       json={"display_name": "Alicia", "email": "alicia@corp.example"})
    assert resp.status_code == 200
    profile = resp.get_json()["profile"]
    assert profile["display_name"] == "Alicia"
    assert profile["email"] == "alicia@corp.example"
    assert profile["role"] == "user"  # unchanged


def test_admin_can_list_users(client):
    token = login(client, "carol", "carol-pw")
    resp = client.get("/api/admin/users", headers={"X-Session": token})
    assert resp.status_code == 200
    assert len(resp.get_json()["users"]) == 3


def test_non_admin_cannot_list_users(client):
    token = login(client, "bob", "bob-pw")
    resp = client.get("/api/admin/users", headers={"X-Session": token})
    assert resp.status_code == 403


def test_greeting_still_greets(client):
    resp = client.get("/api/greeting", query_string={"name": "Alice"})
    assert resp.status_code == 200
    assert "Hello Alice" in resp.get_data(as_text=True)
