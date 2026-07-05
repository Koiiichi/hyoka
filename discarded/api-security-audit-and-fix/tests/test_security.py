"""
Security suite (executed). Three distinct vulnerabilities, each demonstrated by
an exploit that succeeds against the unpatched service and must be blocked after
the fix. Every one must be closed to pass.
"""
from conftest import login


def test_idor_cannot_read_other_users_document(client):
    """Broken object-level authorization: a user must not read another user's document."""
    token = login(client, "alice", "alice-pw")
    resp = client.get("/api/documents/102", headers={"X-Session": token})  # Bob's private doc
    body = resp.get_data(as_text=True)
    assert "BOB_PRIVATE_SALARY" not in body, (
        "Alice was able to read Bob's private document (IDOR / broken object-level "
        "authorization). Access must be restricted to the document's owner."
    )
    assert resp.status_code in (403, 404)


def test_mass_assignment_privilege_escalation(client):
    """Profile update must not let a user grant themselves a privileged role."""
    token = login(client, "alice", "alice-pw")
    client.post("/api/profile", headers={"X-Session": token}, json={"role": "admin"})
    resp = client.get("/api/admin/users", headers={"X-Session": token})
    assert resp.status_code == 403, (
        "Alice escalated to admin by setting 'role' via the profile endpoint "
        "(mass assignment). Only safe profile fields should be updatable."
    )


def test_ssti_in_greeting(client):
    """The greeting must not evaluate user input as a template (SSTI)."""
    resp = client.get("/api/greeting", query_string={"name": "{{7*7}}"})
    body = resp.get_data(as_text=True)
    assert "49" not in body, (
        "The greeting endpoint evaluated '{{7*7}}' to 49 -- server-side template "
        "injection. User input must not be rendered as a template."
    )
    resp2 = client.get("/api/greeting", query_string={"name": "{{ config }}"})
    assert "SECRET" not in resp2.get_data(as_text=True).upper()
