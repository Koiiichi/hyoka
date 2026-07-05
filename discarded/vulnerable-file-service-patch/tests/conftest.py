import importlib
import os
import sys

import pytest

APP_DIR = os.path.join(os.environ.get("TASK_ROOT", "/root"), "app")
sys.path.insert(0, APP_DIR)


@pytest.fixture
def client():
    """Return a fresh test client for the (possibly patched) service."""
    import server
    importlib.reload(server)
    server.app.config.update(TESTING=True)
    return server.app.test_client()
