from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return secrets.token_hex(16)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SessionToken(Base):
    __tablename__ = "session_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    authenticated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_address: Mapped[str] = mapped_column(String(100), default="")
    user: Mapped[User] = relationship()


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_address: Mapped[str] = mapped_column(String(100), index=True)
    username: Mapped[str] = mapped_column(String(100), index=True)
    success: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(20))
    location: Mapped[str] = mapped_column(Text)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_snapshot_refresh_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class EncryptedSecret(Base):
    __tablename__ = "encrypted_secrets"
    __table_args__ = (
        UniqueConstraint("repository_id", "name", name="uq_repository_secret"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(80))
    ciphertext: Mapped[str] = mapped_column(Text)


class Snapshot(Base):
    __tablename__ = "snapshots"
    __table_args__ = (
        UniqueConstraint("repository_id", "snapshot_id", name="uq_repository_snapshot"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    snapshot_id: Mapped[str] = mapped_column(String(64))
    short_id: Mapped[str] = mapped_column(String(16))
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    username: Mapped[str] = mapped_column(String(255), default="")
    paths_json: Mapped[str] = mapped_column(Text, default="[]")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    repository: Mapped[Repository] = relationship()


class RefreshJob(Base):
    __tablename__ = "refresh_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    requested_by: Mapped[str] = mapped_column(String(100), default="system")
    active_key: Mapped[str | None] = mapped_column(
        String(32), nullable=True, unique=True
    )
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DirectoryListing(Base):
    __tablename__ = "directory_listings"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "path", name="uq_directory_listing"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("snapshots.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(Text)
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    entry_count: Mapped[int] = mapped_column(Integer, default=0)


class CachedEntry(Base):
    __tablename__ = "cached_entries"
    __table_args__ = (
        UniqueConstraint("listing_id", "path", name="uq_cached_entry"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    listing_id: Mapped[str] = mapped_column(
        ForeignKey("directory_listings.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(String(30), index=True)
    size: Mapped[int] = mapped_column(Integer, default=0)
    mode_json: Mapped[str] = mapped_column(Text, default="null")
    mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    uid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    linktarget: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(String(100), default="")
    action: Mapped[str] = mapped_column(String(80), index=True)
    result: Mapped[str] = mapped_column(String(20), index=True)
    repository_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
