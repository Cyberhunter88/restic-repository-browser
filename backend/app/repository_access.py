from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import socket
import asyncio
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

from .config import get_settings
from .schemas import RepositoryInput, RepositoryUpdateInput


@dataclass
class RuntimeRepository:
    id: str
    kind: str
    location: str
    config: dict
    secrets: dict[str, str]


def _secret(value) -> str | None:
    return value.get_secret_value() if value is not None else None


def _reject_controls(value: str, label: str) -> str:
    value = value.strip()
    if not value or any(ord(character) < 32 for character in value):
        raise ValueError(f"{label} ist ungültig")
    return value


def normalize_local_path(value: str) -> str:
    settings = get_settings()
    root = settings.repository_root.resolve()
    raw = Path(_reject_controls(value, "Repository-Pfad"))
    candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Lokale Repositories müssen innerhalb von /repositories liegen") from exc
    return resolved.as_posix()


def normalize_https(value: str, label: str) -> str:
    parsed = urlsplit(_reject_controls(value, label))
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"{label} muss HTTPS verwenden")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{label} darf keine Zugangsdaten, Query oder Fragment enthalten")
    host = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(host)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        pass
    port = parsed.port
    netloc = host if not port or port == 443 else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunsplit(("https", netloc, path, "", ""))


def _allowed_target_rules() -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    hosts: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in get_settings().allowed_remote_targets.split(","):
        value = raw.strip().lower()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            hosts.add(value.rstrip("."))
    return hosts, networks


async def ensure_remote_target_allowed(host: str) -> None:
    hosts, networks = _allowed_target_rules()
    if not hosts and not networks:
        return
    normalized = host.strip().lower().rstrip(".")
    if normalized in hosts:
        return
    try:
        addresses = {ipaddress.ip_address(normalized)}
    except ValueError:
        try:
            values = await asyncio.to_thread(socket.getaddrinfo, normalized, None)
        except socket.gaierror as exc:
            raise ValueError("Remote-Ziel konnte für die Allowlist nicht aufgelöst werden") from exc
        addresses = {ipaddress.ip_address(item[4][0]) for item in values}
    if not addresses or not all(any(address in network for network in networks) for address in addresses):
        raise ValueError("Remote-Ziel ist nicht durch RRB_ALLOWED_REMOTE_TARGETS erlaubt")


async def ensure_runtime_target_allowed(repository: RuntimeRepository) -> None:
    if repository.kind == "local":
        return
    if repository.kind == "sftp":
        host = str(repository.config.get("host") or "")
    else:
        key = "url" if repository.kind == "rest" else "endpoint"
        host = urlsplit(str(repository.config.get(key) or "")).hostname or ""
    await ensure_remote_target_allowed(host)


def normalize_sftp(host: str, port: int, username: str, path: str) -> tuple[str, dict]:
    host = _reject_controls(host, "SFTP-Host").lower()
    username = _reject_controls(username, "SFTP-Benutzer")
    path = _reject_controls(path, "SFTP-Pfad")
    if any(value in host for value in ("/", "@", ":", " ")):
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("SFTP-Host ist ungültig") from exc
    if any(value in username for value in ("/", "@", ":", " ")):
        raise ValueError("SFTP-Benutzer ist ungültig")
    if not path.startswith("/"):
        raise ValueError("SFTP-Pfad muss absolut sein")
    display_host = f"[{host}]" if ":" in host else host
    location = f"sftp://{username}@{display_host}:{port}/{quote(path, safe='/')}"
    return location, {"host": host, "port": port, "username": username, "path": path}


def fingerprint_known_host(line: str) -> str:
    fields = line.strip().split()
    if len(fields) < 3:
        raise ValueError("Ungültiger SSH-Hostschlüssel")
    try:
        key = base64.b64decode(fields[2], validate=True)
    except ValueError as exc:
        raise ValueError("Ungültiger SSH-Hostschlüssel") from exc
    digest = base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def runtime_from_input(data: RepositoryInput, repository_id: str) -> RuntimeRepository:
    password = data.repository_password.get_secret_value()
    if not password:
        raise ValueError("Repository-Passwort fehlt")
    secrets = {"repository_password": password}
    config: dict = {}

    if data.kind == "local":
        if not data.local_path:
            raise ValueError("Repository-Pfad fehlt")
        location = normalize_local_path(data.local_path)
        config = {"path": location}
    elif data.kind == "rest":
        if not data.rest_url:
            raise ValueError("REST-URL fehlt")
        endpoint = normalize_https(data.rest_url, "REST-URL")
        location = f"rest:{endpoint}"
        config = {"url": endpoint, "username": data.rest_username or ""}
        if data.rest_username:
            secrets["rest_username"] = data.rest_username
        if value := _secret(data.rest_password):
            secrets["rest_password"] = value
        if value := _secret(data.ca_certificate):
            secrets["ca_certificate"] = value
    elif data.kind == "sftp":
        required = {
            "Host": data.sftp_host,
            "Benutzer": data.sftp_username,
            "Pfad": data.sftp_path,
            "Hostschlüssel": _secret(data.sftp_known_hosts),
            "Fingerprint": data.sftp_fingerprint,
        }
        if data.sftp_auth_method == "private_key":
            required["Private Key"] = _secret(data.sftp_private_key)
        else:
            required["Passwort"] = _secret(data.sftp_password)
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"SFTP-Angaben fehlen: {', '.join(missing)}")
        location, config = normalize_sftp(
            data.sftp_host or "",
            data.sftp_port,
            data.sftp_username or "",
            data.sftp_path or "",
        )
        known_hosts = _secret(data.sftp_known_hosts) or ""
        actual = fingerprint_known_host(known_hosts.splitlines()[0])
        if actual != data.sftp_fingerprint:
            raise ValueError("Bestätigter SFTP-Fingerprint stimmt nicht mit dem Hostschlüssel überein")
        config["fingerprint"] = actual
        config["auth_method"] = data.sftp_auth_method
        if data.sftp_auth_method == "private_key":
            secrets["sftp_private_key"] = _secret(data.sftp_private_key) or ""
        else:
            secrets["sftp_password"] = _secret(data.sftp_password) or ""
        secrets["sftp_known_hosts"] = known_hosts
    else:
        required = {
            "Endpunkt": data.s3_endpoint,
            "Bucket": data.s3_bucket,
            "Access Key": _secret(data.s3_access_key_id),
            "Secret Key": _secret(data.s3_secret_access_key),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"S3-Angaben fehlen: {', '.join(missing)}")
        endpoint = normalize_https(data.s3_endpoint or "", "S3-Endpunkt").rstrip("/")
        bucket = _reject_controls(data.s3_bucket or "", "S3-Bucket").strip("/")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,62}", bucket):
            raise ValueError("S3-Bucket ist ungültig")
        prefix = (data.s3_prefix or "").strip("/")
        if any(part in {".", ".."} for part in prefix.split("/") if part):
            raise ValueError("S3-Präfix ist ungültig")
        suffix = f"/{prefix}" if prefix else ""
        location = f"s3:{endpoint}/{bucket}{suffix}"
        config = {
            "endpoint": endpoint,
            "bucket": bucket,
            "prefix": prefix,
            "region": data.s3_region or "",
        }
        secrets["s3_access_key_id"] = _secret(data.s3_access_key_id) or ""
        secrets["s3_secret_access_key"] = _secret(data.s3_secret_access_key) or ""
        if value := _secret(data.s3_session_token):
            secrets["s3_session_token"] = value

    return RuntimeRepository(
        id=repository_id,
        kind=data.kind,
        location=location,
        config=config,
        secrets=secrets,
    )


def runtime_from_update(
    data: RepositoryUpdateInput,
    repository,
    existing_secrets: dict[str, str],
) -> RuntimeRepository:
    payload = data.model_dump(exclude={"clear_secrets"})
    secret_fields = {
        "repository_password",
        "rest_password",
        "ca_certificate",
        "sftp_private_key",
        "sftp_password",
        "sftp_known_hosts",
        "s3_access_key_id",
        "s3_secret_access_key",
        "s3_session_token",
    }
    same_kind = data.kind == repository.kind
    retained = {"repository_password"}
    if same_kind:
        retained.update(
            {
                "rest_password",
                "ca_certificate",
                "sftp_private_key",
                "sftp_password",
                "sftp_known_hosts",
                "s3_access_key_id",
                "s3_secret_access_key",
                "s3_session_token",
            }
        )
    for field in secret_fields:
        value = payload.get(field)
        raw = value.get_secret_value() if value is not None else ""
        if raw:
            continue
        payload[field] = existing_secrets.get(field) if field in retained else None
    for field in data.clear_secrets:
        payload[field] = None

    old_config = json.loads(repository.config_json or "{}")
    if same_kind and data.kind == "sftp":
        host_unchanged = (
            str(data.sftp_host or "").lower() == str(old_config.get("host") or "").lower()
            and data.sftp_port == int(old_config.get("port") or 22)
        )
        if host_unchanged and not payload.get("sftp_known_hosts"):
            payload["sftp_known_hosts"] = existing_secrets.get("sftp_known_hosts")
        if host_unchanged and not data.sftp_fingerprint:
            payload["sftp_fingerprint"] = old_config.get("fingerprint")
        if not host_unchanged and not _secret(data.sftp_known_hosts):
            payload["sftp_known_hosts"] = None
            payload["sftp_fingerprint"] = data.sftp_fingerprint

    create_data = RepositoryInput.model_validate(payload)
    return runtime_from_input(create_data, repository.id)


def runtime_from_model(repository, secrets: dict[str, str]) -> RuntimeRepository:
    return RuntimeRepository(
        id=repository.id,
        kind=repository.kind,
        location=repository.location,
        config=json.loads(repository.config_json or "{}"),
        secrets=secrets,
    )


def display_location(kind: str, config: dict) -> str:
    if kind == "local":
        return config.get("path", "")
    if kind == "rest":
        return config.get("url", "")
    if kind == "sftp":
        return (
            f"{config.get('username', '')}@{config.get('host', '')}:"
            f"{config.get('port', 22)}{config.get('path', '')}"
        )
    endpoint = config.get("endpoint", "")
    suffix = f"/{config.get('prefix')}" if config.get("prefix") else ""
    return f"{endpoint}/{config.get('bucket', '')}{suffix}"
