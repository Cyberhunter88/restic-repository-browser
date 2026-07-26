from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, model_validator


RepositoryKind = Literal["local", "rest", "sftp", "s3"]
SftpAuthMethod = Literal["private_key", "password"]


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: SecretStr


class PasswordChange(BaseModel):
    current_password: SecretStr
    new_password: SecretStr

    @model_validator(mode="after")
    def validate_password(self):
        value = self.new_password.get_secret_value()
        if len(value) < 12:
            raise ValueError("Das neue Passwort muss mindestens 12 Zeichen lang sein")
        if value == self.current_password.get_secret_value():
            raise ValueError("Das neue Passwort muss sich vom bisherigen unterscheiden")
        return self


class UserOut(BaseModel):
    username: str
    must_change_password: bool


class SftpHostKeyRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)


class SftpHostKey(BaseModel):
    algorithm: str
    fingerprint: str
    known_hosts: str


class RepositoryInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: RepositoryKind
    repository_password: SecretStr

    local_path: str | None = Field(default=None, max_length=4096)

    rest_url: str | None = Field(default=None, max_length=4096)
    rest_username: str | None = Field(default=None, max_length=255)
    rest_password: SecretStr | None = None
    ca_certificate: SecretStr | None = None

    sftp_host: str | None = Field(default=None, max_length=255)
    sftp_port: int = Field(default=22, ge=1, le=65535)
    sftp_username: str | None = Field(default=None, max_length=255)
    sftp_path: str | None = Field(default=None, max_length=4096)
    sftp_auth_method: SftpAuthMethod = "private_key"
    sftp_private_key: SecretStr | None = None
    sftp_password: SecretStr | None = None
    sftp_known_hosts: SecretStr | None = None
    sftp_fingerprint: str | None = Field(default=None, max_length=200)

    s3_endpoint: str | None = Field(default=None, max_length=4096)
    s3_bucket: str | None = Field(default=None, max_length=255)
    s3_prefix: str | None = Field(default=None, max_length=2048)
    s3_region: str | None = Field(default=None, max_length=255)
    s3_access_key_id: SecretStr | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_session_token: SecretStr | None = None


class RepositorySummary(BaseModel):
    id: str
    name: str
    kind: RepositoryKind
    location_display: str
    enabled: bool
    last_check_at: datetime | None
    last_snapshot_refresh_at: datetime | None
    last_error: str
    snapshot_count: int = 0
    created_at: datetime
    config: dict


class SnapshotSummary(BaseModel):
    id: str
    repository_id: str
    snapshot_id: str
    short_id: str
    time: datetime
    hostname: str
    username: str
    paths: list[str]
    tags: list[str]
    summary: dict
    cached_at: datetime


class SnapshotEntry(BaseModel):
    path: str
    name: str
    type: str
    size: int = 0
    mode: int | str | None = None
    mtime: datetime | None = None
    uid: int | None = None
    gid: int | None = None
    linktarget: str | None = None


class RefreshJobOut(BaseModel):
    id: str
    repository_id: str
    status: Literal["queued", "running", "success", "failed"]
    error: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class MessageOut(BaseModel):
    message: str
