"""
Functional suite (executed): legitimate behavior must be preserved. A fix that
simply disables downloads (e.g. always returning 403) breaks these and does not
pass.
"""


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json().get("status") == "ok"


def test_download_legit_file(client):
    resp = client.get("/download", query_string={"name": "readme.txt"})
    assert resp.status_code == 200, "Legitimate download of readme.txt must still work."
    assert "internal file-distribution service" in resp.get_data(as_text=True)


def test_download_second_legit_file(client):
    resp = client.get("/download", query_string={"name": "report.txt"})
    assert resp.status_code == 200, "Legitimate download of report.txt must still work."
    assert "Quarterly summary" in resp.get_data(as_text=True)


def test_download_missing_file_404(client):
    resp = client.get("/download", query_string={"name": "does_not_exist.txt"})
    assert resp.status_code == 404


def test_preview_allowlisted(client):
    resp = client.get("/preview", query_string={"name": "notes.txt"})
    assert resp.status_code == 200
    assert "Release notes" in resp.get_data(as_text=True)
