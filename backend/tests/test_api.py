from __future__ import annotations

from unittest.mock import AsyncMock

from sqlalchemy import select

from backend.app import main
from backend.app.crypto import get_repository_secrets
from backend.app.db import SessionLocal
from backend.app.models import EncryptedSecret, Repository
from backend.app.repository_access import fingerprint_known_host


MUTATION_HEADERS = {"X-RRB-Request": "1"}


def test_login_requires_application_header(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Initial-password-123!"},
    )
    assert response.status_code == 403


def test_login_and_session(client):
    wrong = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong"},
        headers=MUTATION_HEADERS,
    )
    assert wrong.status_code == 401

    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Initial-password-123!"},
        headers=MUTATION_HEADERS,
    )
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
    assert client.get("/api/auth/me").status_code == 200


def test_create_and_delete_local_repository(authenticated_client, monkeypatch, test_root):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    payload = {
        "name": "Test Repository",
        "kind": "local",
        "repository_password": "secret-repository-password",
        "local_path": "local-test",
    }
    response = authenticated_client.post(
        "/api/repositories",
        json=payload,
        headers=MUTATION_HEADERS,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["location_display"].startswith((test_root / "repositories").as_posix())
    assert "secret-repository-password" not in response.text

    with SessionLocal() as db:
        repository = db.scalar(select(Repository).where(Repository.id == body["id"]))
        assert repository is not None
        assert get_repository_secrets(db, repository.id)["repository_password"] == "secret-repository-password"
        secret_row = db.scalar(
            select(EncryptedSecret).where(EncryptedSecret.repository_id == repository.id)
        )
        assert "secret-repository-password" not in secret_row.ciphertext

    deleted = authenticated_client.delete(
        f"/api/repositories/{body['id']}",
        headers=MUTATION_HEADERS,
    )
    assert deleted.status_code == 204
    with SessionLocal() as db:
        assert db.get(Repository, body["id"]) is None
        assert not db.scalars(
            select(EncryptedSecret).where(EncryptedSecret.repository_id == body["id"])
        ).all()


def test_create_sftp_repository_with_password(authenticated_client, monkeypatch):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    known_host = (
        "backup.example ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIEg5Q2p2cm93c2VyVGVzdEtleU1hdGVyaWFs"
    )
    payload = {
        "name": "SFTP Password Repository",
        "kind": "sftp",
        "repository_password": "secret-repository-password",
        "sftp_host": "backup.example",
        "sftp_port": 22,
        "sftp_username": "backup-user",
        "sftp_path": "/srv/restic/repo",
        "sftp_auth_method": "password",
        "sftp_password": "secret-sftp-password",
        "sftp_known_hosts": known_host,
        "sftp_fingerprint": fingerprint_known_host(known_host),
    }

    response = authenticated_client.post(
        "/api/repositories",
        json=payload,
        headers=MUTATION_HEADERS,
    )

    assert response.status_code == 201, response.text
    assert "secret-sftp-password" not in response.text
    repository_id = response.json()["id"]
    with SessionLocal() as db:
        repository = db.get(Repository, repository_id)
        assert repository is not None
        assert repository.location == "sftp://backup-user@backup.example:22//srv/restic/repo"
        secrets = get_repository_secrets(db, repository_id)
        assert secrets["sftp_password"] == "secret-sftp-password"
        assert "sftp_private_key" not in secrets
        encrypted_rows = db.scalars(
            select(EncryptedSecret).where(EncryptedSecret.repository_id == repository_id)
        ).all()
        assert all("secret-sftp-password" not in row.ciphertext for row in encrypted_rows)


def test_snapshot_path_validation():
    assert main.validate_snapshot_path("/home/user") == "/home/user"
    assert main.validate_snapshot_path("/") == "/"
    for value in ("relative", "/home/../etc", "/bad\\path", "/bad\x00path"):
        try:
            main.validate_snapshot_path(value)
        except Exception as exc:
            assert getattr(exc, "status_code", None) == 422
        else:
            raise AssertionError(f"{value!r} wurde nicht abgelehnt")
