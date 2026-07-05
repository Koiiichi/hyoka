import importlib
import os
import sys

import pytest

APP_DIR = os.path.join(os.environ.get("TASK_ROOT", "/root"), "app")
sys.path.insert(0, APP_DIR)


@pytest.fixture
def client():
    """Fresh client with reset in-memory state for the (possibly patched) app."""
    import server
    importlib.reload(server)
    server.app.config.update(TESTING=True)
    return server.app.test_client()


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login for {username} should succeed"
    return resp.get_json()["token"]
