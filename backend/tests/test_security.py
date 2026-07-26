from __future__ import annotations

from pathlib import Path

from backend.app.crypto import decrypt_value, encrypt_value
from backend.app.repository_access import (
    RuntimeRepository,
    fingerprint_known_host,
    normalize_https,
    normalize_local_path,
    normalize_sftp,
)
from backend.app.restic import _materialize
from backend.app.security import hash_password, verify_password


def test_password_hashing_and_secret_encryption():
    password_hash = hash_password("very-long-password")
    assert "very-long-password" not in password_hash
    assert verify_password(password_hash, "very-long-password")
    assert not verify_password(password_hash, "wrong")

    ciphertext = encrypt_value("repo-secret", "repository:test:password")
    assert "repo-secret" not in ciphertext
    assert decrypt_value(ciphertext, "repository:test:password") == "repo-secret"


def test_endpoint_and_local_path_validation(test_root):
    assert normalize_https("https://EXAMPLE.test:443/repo//path", "URL") == "https://example.test/repo/path"
    assert normalize_local_path("server-a").startswith((test_root / "repositories").as_posix())

    for invalid in (
        "http://example.test/repo",
        "https://user:secret@example.test/repo",
        "https://example.test/repo?token=secret",
    ):
        try:
            normalize_https(invalid, "URL")
        except ValueError:
            pass
        else:
            raise AssertionError(f"{invalid} wurde nicht abgelehnt")

    try:
        normalize_local_path("../outside")
    except ValueError:
        pass
    else:
        raise AssertionError("Path-Traversal wurde nicht abgelehnt")


def test_ssh_fingerprint_is_sha256():
    line = "example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEg5Q2p2cm93c2VyVGVzdEtleU1hdGVyaWFs"
    fingerprint = fingerprint_known_host(line)
    assert fingerprint.startswith("SHA256:")
    assert "=" not in fingerprint


def test_sftp_location_uses_url_syntax_for_port_and_absolute_path():
    location, config = normalize_sftp(
        "BACKUP.EXAMPLE",
        2222,
        "backup-user",
        "/srv/restic repo",
    )

    assert location == "sftp://backup-user@backup.example:2222//srv/restic%20repo"
    assert config == {
        "host": "backup.example",
        "port": 2222,
        "username": "backup-user",
        "path": "/srv/restic repo",
    }


def test_sftp_password_is_materialized_without_command_line_secret(tmp_path):
    password = "secret-sftp-password"
    runtime = RuntimeRepository(
        id="sftp-password",
        kind="sftp",
        location="sftp://backup-user@backup.example:22//srv/restic/repo",
        config={
            "auth_method": "password",
            "host": "backup.example",
            "port": 2222,
            "username": "backup-user",
        },
        secrets={
            "repository_password": "repository-password",
            "sftp_password": password,
            "sftp_known_hosts": "backup.example ssh-ed25519 AAAA",
        },
    )

    env, options = _materialize(tmp_path, runtime)

    assert password not in repr(options)
    assert password not in repr(env)
    assert (tmp_path / "sftp-password").read_text(encoding="utf-8") == password
    assert not (tmp_path / "sftp-askpass").exists()
    assert env["SSH_ASKPASS"] == "/usr/local/bin/sftp-askpass.sh"
    assert "PubkeyAuthentication=no" in options[-1]
    assert "-o ConnectTimeout=10" in options[-1]
    assert "-o ConnectionAttempts=1" in options[-1]
    assert "-o ServerAliveInterval=10" in options[-1]
    assert "-o ServerAliveCountMax=1" in options[-1]
    assert options[-1].startswith("sftp.command=ssh ")
    assert "-p 2222 -l backup-user -s backup.example sftp" in options[-1]
    assert "," not in options[-1]


def test_entrypoint_does_not_recursively_chown_private_restic_cache():
    entrypoint = Path("scripts/entrypoint.sh").read_text(encoding="utf-8")

    assert "chown -R rrb:rrb /data\n" not in entrypoint
    assert "chown rrb:rrb /data /data/cache" in entrypoint
    assert "chown -R rrb:rrb /data/security" in entrypoint
