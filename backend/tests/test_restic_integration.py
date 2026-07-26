from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from io import BytesIO

import pytest

from backend.app.repository_access import RuntimeRepository
from backend.app.restic import list_entries, list_snapshots, stream_dump


pytestmark = pytest.mark.skipif(
    os.name != "posix" or shutil.which("restic") is None,
    reason="Integrationstest benötigt Restic auf einem POSIX-System",
)


@pytest.mark.asyncio
async def test_real_repository_browse_and_download(tmp_path):
    repository_path = tmp_path / "repository"
    source_path = tmp_path / "source"
    nested = source_path / "nested"
    nested.mkdir(parents=True)
    expected = b"restore-test-content\n"
    (nested / "file.txt").write_bytes(expected)
    password_file = tmp_path / "password"
    password_file.write_text("integration-password", encoding="utf-8")
    env = {
        **os.environ,
        "RESTIC_REPOSITORY": str(repository_path),
        "RESTIC_PASSWORD_FILE": str(password_file),
    }
    subprocess.run(["restic", "init"], env=env, check=True, capture_output=True)
    subprocess.run(["restic", "backup", str(source_path)], env=env, check=True, capture_output=True)

    runtime = RuntimeRepository(
        id="integration",
        kind="local",
        location=str(repository_path),
        config={"path": str(repository_path)},
        secrets={"repository_password": "integration-password"},
    )
    snapshots = await list_snapshots(runtime)
    assert len(snapshots) == 1
    snapshot_id = snapshots[0]["id"]
    source_snapshot_path = source_path.as_posix()
    entries = await list_entries(runtime, snapshot_id, source_snapshot_path)
    assert any(item.get("path") == f"{source_snapshot_path}/nested" for item in entries)

    file_chunks = [
        chunk
        async for chunk in stream_dump(
            runtime,
            snapshot_id,
            f"{source_snapshot_path}/nested/file.txt",
        )
    ]
    assert b"".join(file_chunks) == expected

    zip_chunks = [
        chunk
        async for chunk in stream_dump(
            runtime,
            snapshot_id,
            f"{source_snapshot_path}/nested",
            archive="zip",
        )
    ]
    with zipfile.ZipFile(BytesIO(b"".join(zip_chunks))) as archive:
        assert archive.read("file.txt") == expected

