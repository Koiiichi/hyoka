"""
Security suite (executed): the /download endpoint must not expose any file
outside the content directory. Each vector is a distinct path-traversal
technique. On the vulnerable code at least one of these returns the sensitive
content; a correct fix blocks all of them. A naive single-pattern blocklist
(e.g. rejecting only literal '../') still fails the absolute-path and
encoded vectors.
"""
import pytest

SECRET_MARKER = "SENSITIVE_DO_NOT_SERVE_a17f0e21c4d5"

# (name query value, a substring that must NOT appear in the response body)
TRAVERSAL_VECTORS = [
    ("../secret.txt", SECRET_MARKER),
    ("..%2fsecret.txt", SECRET_MARKER),
    ("....//secret.txt", SECRET_MARKER),
    ("../../secret.txt", SECRET_MARKER),
    ("%2e%2e%2fsecret.txt", SECRET_MARKER),
    ("/etc/passwd", "root:"),
    ("../../../../../../etc/passwd", "root:"),
]


@pytest.mark.parametrize("name,forbidden", TRAVERSAL_VECTORS)
def test_download_blocks_traversal(client, name, forbidden):
    resp = client.get("/download", query_string={"name": name})
    body = resp.get_data(as_text=True)
    assert forbidden not in body, (
        f"Path traversal via name={name!r} exposed out-of-tree content "
        f"(found {forbidden!r} in the response). The /download endpoint must "
        "confine reads to the content directory."
    )
    assert resp.status_code in (400, 403, 404), (
        f"Traversal attempt name={name!r} should be rejected (400/403/404), "
        f"got {resp.status_code}."
    )
