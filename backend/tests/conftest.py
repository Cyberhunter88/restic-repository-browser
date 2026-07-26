from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select


TEST_ROOT = Path(tempfile.mkdtemp(prefix="rrb-tests-"))
os.environ["RRB_DATA_DIR"] = str(TEST_ROOT / "data")
os.environ["RRB_REPOSITORY_ROOT"] = str(TEST_ROOT / "repositories")
os.environ["RRB_INITIAL_ADMIN_PASSWORD"] = "Initial-password-123!"
os.environ["RRB_FRONTEND_DIR"] = str(TEST_ROOT / "missing-frontend")

from backend.app.main import app  # noqa: E402
from backend.app.db import SessionLocal  # noqa: E402
from backend.app.models import User  # noqa: E402


@pytest.fixture(scope="session")
def test_root() -> Path:
    return TEST_ROOT


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as value:
        yield value


@pytest.fixture()
def authenticated_client(client: TestClient):
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        assert user is not None
        user.must_change_password = False
        db.commit()
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Initial-password-123!"},
        headers={"X-RRB-Request": "1"},
    )
    assert response.status_code == 200
    return client
