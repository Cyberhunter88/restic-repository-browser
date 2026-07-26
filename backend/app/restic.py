from __future__ import annotations

import asyncio
import json
import os
import shlex
import signal
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .config import get_settings
from .repository_access import RuntimeRepository


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def redact_text(value: str, secrets: dict[str, str]) -> str:
    redacted = value
    for secret in sorted({item for item in secrets.values() if item}, key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def minimal_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    allowed = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ")
    env = {name: os.environ[name] for name in allowed if name in os.environ}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env.setdefault("LC_ALL", "C.UTF-8")
    env["RESTIC_CACHE_DIR"] = str(get_settings().restic_cache_dir)
    if extra:
        env.update(extra)
    return env


def _materialize(
    directory: Path,
    repository: RuntimeRepository,
) -> tuple[dict[str, str], list[str]]:
    secrets = repository.secrets
    password_path = directory / "repository-password"
    password_path.write_text(secrets["repository_password"], encoding="utf-8")
    password_path.chmod(0o600)
    repository_path = directory / "repository"
    repository_path.write_text(repository.location, encoding="utf-8")
    repository_path.chmod(0o600)
    env = {
        "RESTIC_PASSWORD_FILE": str(password_path),
        "RESTIC_REPOSITORY_FILE": str(repository_path),
    }
    options: list[str] = []
    if repository.kind == "rest":
        if value := secrets.get("rest_username"):
            env["RESTIC_REST_USERNAME"] = value
        if value := secrets.get("rest_password"):
            env["RESTIC_REST_PASSWORD"] = value
        if value := secrets.get("ca_certificate"):
            ca_path = directory / "ca.crt"
            ca_path.write_text(value, encoding="utf-8")
            ca_path.chmod(0o600)
            env["RESTIC_CACERT"] = str(ca_path)
    elif repository.kind == "sftp":
        known_hosts_path = directory / "known_hosts"
        known_hosts_path.write_text(secrets["sftp_known_hosts"], encoding="utf-8")
        known_hosts_path.chmod(0o600)
        host_key_options = (
            f"-o UserKnownHostsFile={shlex.quote(str(known_hosts_path))} "
            "-o StrictHostKeyChecking=yes"
        )
        if repository.config.get("auth_method", "private_key") == "password":
            sftp_password_path = directory / "sftp-password"
            askpass_path = directory / "sftp-askpass"
            sftp_password_path.write_text(secrets["sftp_password"], encoding="utf-8")
            askpass_path.write_text(
                '#!/bin/sh\nexec cat -- "$RRB_SFTP_PASSWORD_FILE"\n',
                encoding="utf-8",
            )
            sftp_password_path.chmod(0o600)
            askpass_path.chmod(0o700)
            env.update(
                {
                    "RRB_SFTP_PASSWORD_FILE": str(sftp_password_path),
                    "SSH_ASKPASS": str(askpass_path),
                    "SSH_ASKPASS_REQUIRE": "force",
                    "DISPLAY": "rrb:0",
                }
            )
            ssh_command = (
                f"ssh {host_key_options} -o PubkeyAuthentication=no "
                "-o PreferredAuthentications=password,keyboard-interactive "
                "-o NumberOfPasswordPrompts=1"
            )
        else:
            key_path = directory / "sftp-key"
            key_path.write_text(secrets["sftp_private_key"], encoding="utf-8")
            key_path.chmod(0o600)
            ssh_command = (
                f"ssh -i {shlex.quote(str(key_path))} -o IdentitiesOnly=yes "
                f"{host_key_options} -o BatchMode=yes "
                "-o PreferredAuthentications=publickey"
            )
        options.extend(["-o", f"sftp.command={ssh_command}"])
    elif repository.kind == "s3":
        env["AWS_ACCESS_KEY_ID"] = secrets["s3_access_key_id"]
        env["AWS_SECRET_ACCESS_KEY"] = secrets["s3_secret_access_key"]
        if value := secrets.get("s3_session_token"):
            env["AWS_SESSION_TOKEN"] = value
        if value := repository.config.get("region"):
            env["AWS_DEFAULT_REGION"] = value
    return env, options


async def run_command(
    repository: RuntimeRepository,
    arguments: list[str],
    *,
    timeout: int = 300,
) -> CommandResult:
    with tempfile.TemporaryDirectory(prefix="rrb-restic-") as raw:
        directory = Path(raw)
        env_values, options = _materialize(directory, repository)
        process = await asyncio.create_subprocess_exec(
            "restic",
            *options,
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=minimal_environment(env_values),
            start_new_session=os.name == "posix",
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            await process.wait()
            raise RuntimeError("Restic-Aufruf hat das Zeitlimit überschritten")
        return CommandResult(
            process.returncode,
            stdout.decode(errors="replace"),
            redact_text(stderr.decode(errors="replace").strip(), repository.secrets),
        )


async def list_snapshots(repository: RuntimeRepository) -> list[dict]:
    result = await run_command(repository, ["snapshots", "--json", "--no-lock"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Snapshots konnten nicht gelesen werden")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Restic hat ungültige Snapshot-Daten geliefert") from exc
    if not isinstance(value, list):
        raise RuntimeError("Restic hat ungültige Snapshot-Daten geliefert")
    return value


async def list_entries(
    repository: RuntimeRepository,
    snapshot_id: str,
    path: str,
) -> list[dict]:
    result = await run_command(
        repository,
        ["ls", "--json", "--no-lock", snapshot_id, path],
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Snapshot konnte nicht gelesen werden")
    items: list[dict] = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("struct_type") == "node":
            items.append(item)
    return items


async def stream_dump(
    repository: RuntimeRepository,
    snapshot_id: str,
    path: str,
    *,
    archive: Literal["zip"] | None = None,
) -> AsyncIterator[bytes]:
    with tempfile.TemporaryDirectory(prefix="rrb-download-") as raw:
        directory = Path(raw)
        env_values, options = _materialize(directory, repository)
        arguments = ["dump", "--no-lock"]
        if archive == "zip":
            arguments.extend(["--archive", "zip", f"{snapshot_id}:{path}", "/"])
        else:
            arguments.extend([snapshot_id, path])
        process = await asyncio.create_subprocess_exec(
            "restic",
            *options,
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=minimal_environment(env_values),
            start_new_session=os.name == "posix",
        )

        async def read_stderr() -> str:
            data = await process.stderr.read(200_000)
            return redact_text(data.decode(errors="replace"), repository.secrets)

        error_task = asyncio.create_task(read_stderr())
        try:
            while chunk := await process.stdout.read(65536):
                yield chunk
            returncode = await process.wait()
            error = await error_task
            if returncode != 0:
                raise RuntimeError(error or "Download aus dem Snapshot ist fehlgeschlagen")
        except (asyncio.CancelledError, GeneratorExit):
            if process.returncode is None:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
                await process.wait()
            raise
        finally:
            if process.returncode is None:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
                await process.wait()
            if not error_task.done():
                error_task.cancel()
            await asyncio.gather(error_task, return_exceptions=True)
