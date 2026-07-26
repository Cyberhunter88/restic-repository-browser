from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from sqlalchemy import select

from backend.app import directory_cache, main
from backend.app.crypto import get_repository_secrets
from backend.app.db import SessionLocal
from backend.app.models import (
    AuditEvent,
    CachedEntry,
    DirectoryListing,
    EncryptedSecret,
    LoginAttempt,
    RefreshJob,
    Repository,
    SessionToken,
    Snapshot,
    User,
)
from backend.app.repository_access import fingerprint_known_host


MUTATION_HEADERS = {"X-RRB-Request": "1"}


async def test_repository_validation_uses_short_timeout(monkeypatch):
    runtime = object()
    list_snapshots = AsyncMock(return_value=[])
    monkeypatch.setattr(main, "list_snapshots", list_snapshots)

    assert await main.validate_runtime(runtime) == []
    list_snapshots.assert_awaited_once_with(
        runtime,
        timeout=30,
    )


async def test_audited_chunks_records_success_failure_and_cancellation():
    events: list[tuple[str, str]] = []

    async def successful():
        yield b"ok"

    assert b"".join(
        [chunk async for chunk in main.audited_chunks(successful(), lambda *value: events.append(value))]
    ) == b"ok"
    assert events.pop() == ("success", "")

    async def failing():
        if False:
            yield b""
        raise RuntimeError("stream failed")

    try:
        _ = [chunk async for chunk in main.audited_chunks(failing(), lambda *value: events.append(value))]
    except RuntimeError:
        pass
    else:
        raise AssertionError("Streamfehler wurde nicht weitergegeben")
    assert events.pop() == ("failed", "stream failed")

    async def cancellable():
        yield b"first"
        await main.asyncio.Event().wait()

    stream = main.audited_chunks(cancellable(), lambda *value: events.append(value))
    assert await anext(stream) == b"first"
    await stream.aclose()
    assert events.pop() == ("cancelled", "")


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


def test_snapshots_accept_sqlite_naive_refresh_timestamp(
    authenticated_client,
    monkeypatch,
):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    response = authenticated_client.post(
        "/api/repositories",
        json={
            "name": "SQLite Timestamp Repository",
            "kind": "local",
            "repository_password": "secret-repository-password",
            "local_path": "sqlite-timestamp-test",
        },
        headers=MUTATION_HEADERS,
    )
    assert response.status_code == 201, response.text

    repository_id = response.json()["id"]
    snapshots = authenticated_client.get(
        f"/api/repositories/{repository_id}/snapshots"
    )
    assert snapshots.status_code == 200
    assert snapshots.json() == []

    deleted = authenticated_client.delete(
        f"/api/repositories/{repository_id}",
        headers=MUTATION_HEADERS,
    )
    assert deleted.status_code == 204


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


def test_security_headers_request_id_and_status(authenticated_client):
    response = authenticated_client.get("/api/system/status")
    assert response.status_code == 200
    assert response.headers["x-request-id"]
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.json()["worker_running"] is True


def test_repository_state_blocks_live_operations(
    authenticated_client,
    monkeypatch,
):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    created = authenticated_client.post(
        "/api/repositories",
        json={
            "name": "Disabled Repository",
            "kind": "local",
            "repository_password": "repository-password",
            "local_path": "disabled-test",
        },
        headers=MUTATION_HEADERS,
    )
    repository_id = created.json()["id"]
    disabled = authenticated_client.patch(
        f"/api/repositories/{repository_id}/state",
        json={"enabled": False},
        headers=MUTATION_HEADERS,
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert authenticated_client.post(
        f"/api/repositories/{repository_id}/refresh",
        headers=MUTATION_HEADERS,
    ).status_code == 409
    assert authenticated_client.post(
        f"/api/repositories/{repository_id}/test",
        headers=MUTATION_HEADERS,
    ).status_code == 409
    assert authenticated_client.get(
        f"/api/repositories/{repository_id}/snapshots"
    ).status_code == 200


def test_repository_update_retains_password(
    authenticated_client,
    monkeypatch,
):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    created = authenticated_client.post(
        "/api/repositories",
        json={
            "name": "Retained Secret",
            "kind": "local",
            "repository_password": "kept-repository-password",
            "local_path": "retained-secret",
        },
        headers=MUTATION_HEADERS,
    )
    repository_id = created.json()["id"]
    updated = authenticated_client.put(
        f"/api/repositories/{repository_id}",
        json={
            "name": "Retained Secret Renamed",
            "kind": "local",
            "repository_password": "",
            "local_path": "retained-secret",
        },
        headers=MUTATION_HEADERS,
    )
    assert updated.status_code == 200, updated.text
    with SessionLocal() as db:
        assert (
            get_repository_secrets(db, repository_id)["repository_password"]
            == "kept-repository-password"
        )


def test_repository_update_can_clear_optional_secrets(
    authenticated_client,
    monkeypatch,
):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    created = authenticated_client.post(
        "/api/repositories",
        json={
            "name": "Optional Secrets",
            "kind": "rest",
            "repository_password": "repository-password",
            "rest_url": "https://backup.example/repository",
            "rest_username": "reader",
            "rest_password": "rest-password",
            "ca_certificate": "certificate",
        },
        headers=MUTATION_HEADERS,
    )
    repository_id = created.json()["id"]
    updated = authenticated_client.put(
        f"/api/repositories/{repository_id}",
        json={
            "name": "Optional Secrets",
            "kind": "rest",
            "repository_password": "",
            "rest_url": "https://backup.example/repository",
            "rest_username": "reader",
            "clear_secrets": ["rest_password", "ca_certificate"],
        },
        headers=MUTATION_HEADERS,
    )
    assert updated.status_code == 200, updated.text
    with SessionLocal() as db:
        secrets = get_repository_secrets(db, repository_id)
        assert secrets["repository_password"] == "repository-password"
        assert "rest_password" not in secrets
        assert "ca_certificate" not in secrets


def test_snapshot_and_entry_pages_are_stable(
    authenticated_client,
    monkeypatch,
):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    created = authenticated_client.post(
        "/api/repositories",
        json={
            "name": "Paged Repository",
            "kind": "local",
            "repository_password": "repository-password",
            "local_path": "paged-test",
        },
        headers=MUTATION_HEADERS,
    )
    repository_id = created.json()["id"]
    with SessionLocal() as db:
        repository = db.get(Repository, repository_id)
        main.cache_snapshots(
            db,
            repository,
            [
                {
                    "id": f"{number:064x}",
                    "short_id": f"{number:08x}",
                    "time": f"2026-07-{number:02d}T12:00:00Z",
                    "hostname": "host-a",
                    "paths": ["/data"],
                    "tags": ["daily"],
                }
                for number in range(1, 5)
            ],
        )
        db.commit()

    first = authenticated_client.get(
        f"/api/repositories/{repository_id}/snapshots/page?limit=2"
    )
    assert first.status_code == 200, first.text
    assert len(first.json()["items"]) == 2
    assert first.json()["next_cursor"]
    second = authenticated_client.get(
        f"/api/repositories/{repository_id}/snapshots/page",
        params={"limit": 2, "cursor": first.json()["next_cursor"]},
    )
    first_ids = {item["id"] for item in first.json()["items"]}
    second_ids = {item["id"] for item in second.json()["items"]}
    assert len(second_ids) == 2
    assert first_ids.isdisjoint(second_ids)
    assert authenticated_client.get(
        f"/api/repositories/{repository_id}/snapshots/page?cursor=invalid"
    ).status_code == 422
    assert len(
        authenticated_client.get(
            f"/api/repositories/{repository_id}/snapshots"
        ).json()
    ) == 4

    with SessionLocal() as db:
        snapshot = db.scalar(
            select(Snapshot).where(Snapshot.repository_id == repository_id)
        )
        listing = DirectoryListing(id="listing-page-test", snapshot_id=snapshot.id, path="/")
        db.add(listing)
        db.flush()
        db.add_all(
            [
                CachedEntry(
                    listing_id=listing.id,
                    path=f"/file-{number}.txt",
                    name=f"file-{number}.txt",
                    type="file",
                    size=number,
                )
                for number in range(260)
            ]
        )
        listing.entry_count = 260
        snapshot_row_id = snapshot.id
        db.commit()
    entries = authenticated_client.get(
        f"/api/snapshots/{snapshot_row_id}/entries/page?path=/&limit=250"
    )
    assert entries.status_code == 200, entries.text
    assert len(entries.json()["items"]) == 250
    next_entries = authenticated_client.get(
        f"/api/snapshots/{snapshot_row_id}/entries/page",
        params={"path": "/", "limit": 250, "cursor": entries.json()["next_cursor"]},
    )
    assert len(next_entries.json()["items"]) == 10
    assert {
        item["path"] for item in entries.json()["items"]
    }.isdisjoint({item["path"] for item in next_entries.json()["items"]})
    assert authenticated_client.delete(
        f"/api/repositories/{repository_id}",
        headers=MUTATION_HEADERS,
    ).status_code == 204
    with SessionLocal() as db:
        assert db.get(DirectoryListing, "listing-page-test") is None


def test_audit_api_records_repository_changes(authenticated_client):
    response = authenticated_client.get("/api/audit-events?limit=200")
    assert response.status_code == 200
    actions = {event["action"] for event in response.json()["items"]}
    assert "auth.login" in actions
    assert "repository.create" in actions


def test_directory_cache_is_reused_and_rolls_back(
    authenticated_client,
    monkeypatch,
):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    created = authenticated_client.post(
        "/api/repositories",
        json={
            "name": "Directory Cache Repository",
            "kind": "local",
            "repository_password": "repository-password",
            "local_path": "directory-cache",
        },
        headers=MUTATION_HEADERS,
    )
    repository_id = created.json()["id"]
    with SessionLocal() as db:
        repository = db.get(Repository, repository_id)
        main.cache_snapshots(
            db,
            repository,
            [{
                "id": "a" * 64,
                "time": "2026-07-26T12:00:00Z",
                "paths": ["/data"],
            }],
        )
        db.commit()
        snapshot = db.scalar(
            select(Snapshot).where(Snapshot.repository_id == repository_id)
        )
        snapshot_row_id = snapshot.id

    calls = 0

    async def entries(_runtime, _snapshot_id, path):
        nonlocal calls
        calls += 1
        yield {"struct_type": "node", "path": path, "type": "dir"}
        yield {
            "struct_type": "node",
            "path": f"{path}/file.txt",
            "type": "file",
            "size": 12,
        }

    monkeypatch.setattr(directory_cache, "iter_entries", entries)
    first = authenticated_client.get(
        f"/api/snapshots/{snapshot_row_id}/entries/page",
        params={"path": "/data"},
    )
    second = authenticated_client.get(
        f"/api/snapshots/{snapshot_row_id}/entries/page",
        params={"path": "/data"},
    )
    assert first.status_code == second.status_code == 200
    assert calls == 1

    async def failing_entries(_runtime, _snapshot_id, path):
        yield {"struct_type": "node", "path": f"{path}/partial", "type": "file"}
        raise RuntimeError("listing failed")

    monkeypatch.setattr(directory_cache, "iter_entries", failing_entries)
    failed = authenticated_client.get(
        f"/api/snapshots/{snapshot_row_id}/entries/page",
        params={"path": "/broken"},
    )
    assert failed.status_code == 502
    with SessionLocal() as db:
        assert db.scalar(
            select(DirectoryListing).where(
                DirectoryListing.snapshot_id == snapshot_row_id,
                DirectoryListing.path == "/broken",
            )
        ) is None


def test_download_success_is_audited(
    authenticated_client,
    monkeypatch,
):
    monkeypatch.setattr(main, "validate_runtime", AsyncMock(return_value=[]))
    created = authenticated_client.post(
        "/api/repositories",
        json={
            "name": "Download Audit Repository",
            "kind": "local",
            "repository_password": "repository-password",
            "local_path": "download-audit",
        },
        headers=MUTATION_HEADERS,
    )
    repository_id = created.json()["id"]
    with SessionLocal() as db:
        repository = db.get(Repository, repository_id)
        main.cache_snapshots(
            db,
            repository,
            [{"id": "b" * 64, "time": "2026-07-26T12:00:00Z", "paths": ["/data"]}],
        )
        db.commit()
        snapshot = db.scalar(
            select(Snapshot).where(Snapshot.repository_id == repository_id)
        )
        snapshot_row_id = snapshot.id

    monkeypatch.setattr(
        main,
        "list_entries",
        AsyncMock(return_value=[{"path": "/data/file.txt", "type": "file"}]),
    )

    async def dump(*_args, **_kwargs):
        yield b"download-content"

    monkeypatch.setattr(main, "stream_dump", dump)
    response = authenticated_client.get(
        f"/api/snapshots/{snapshot_row_id}/download",
        params={"path": "/data/file.txt"},
    )
    assert response.status_code == 200
    assert response.content == b"download-content"
    with SessionLocal() as db:
        event = db.scalar(
            select(main.AuditEvent)
            .where(
                main.AuditEvent.action == "snapshot.download",
                main.AuditEvent.repository_id == repository_id,
            )
            .order_by(main.AuditEvent.id.desc())
        )
        assert event.result == "success"
        assert event.path == "/data/file.txt"


def test_worker_recovers_aborted_jobs_and_cleanup_removes_old_rows(
    authenticated_client,
):
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        repository = db.scalar(select(Repository).limit(1))
        user = db.scalar(select(User).limit(1))
        job = RefreshJob(
            repository_id=repository.id,
            status="running",
            attempt_count=3,
            lease_expires_at=now + timedelta(hours=1),
        )
        db.add(job)
        db.add(
            LoginAttempt(
                source_address="old",
                username="old",
                success=False,
                created_at=now - timedelta(days=31),
            )
        )
        db.add(
            AuditEvent(
                action="old.event",
                result="success",
                created_at=now - timedelta(days=91),
            )
        )
        db.add(
            SessionToken(
                token_hash="f" * 64,
                user_id=user.id,
                expires_at=now - timedelta(seconds=1),
            )
        )
        db.commit()
        job_id = job.id

    main.recover_expired_jobs(force=True)
    main.run_cleanup()
    with SessionLocal() as db:
        recovered = db.get(RefreshJob, job_id)
        assert recovered.status == "failed"
        assert recovered.finished_at is not None
        assert not db.scalars(
            select(LoginAttempt).where(LoginAttempt.source_address == "old")
        ).all()
        assert not db.scalars(
            select(AuditEvent).where(AuditEvent.action == "old.event")
        ).all()
        assert db.get(SessionToken, "f" * 64) is None


def test_remote_repository_create_honors_allowlist(
    authenticated_client,
    monkeypatch,
):
    original = main.settings.allowed_remote_targets
    main.settings.allowed_remote_targets = "backup.example"
    monkeypatch.setattr(main, "list_snapshots", AsyncMock(return_value=[]))
    try:
        response = authenticated_client.post(
            "/api/repositories",
            json={
                "name": "Blocked Remote",
                "kind": "rest",
                "repository_password": "repository-password",
                "rest_url": "https://192.0.2.10/repository",
            },
            headers=MUTATION_HEADERS,
        )
        assert response.status_code == 422
        assert "RRB_ALLOWED_REMOTE_TARGETS" in response.text
    finally:
        main.settings.allowed_remote_targets = original
