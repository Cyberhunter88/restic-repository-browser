from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Cookie, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import LoginAttempt, SessionToken, User


password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def source_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def request_is_secure(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    settings = get_settings()
    remote = source_address(request)
    if settings.is_trusted_proxy(remote):
        proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
        return proto == "https"
    return False


def enforce_browser_request(request: Request) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if request.headers.get("x-rrb-request") != "1":
        raise HTTPException(403, "Fehlender Anwendungsheader")
    origin = request.headers.get("origin")
    if origin:
        forwarded_host = request.headers.get("host", "")
        scheme = "https" if request_is_secure(request) else request.url.scheme
        expected = f"{scheme}://{forwarded_host}".rstrip("/")
        if origin.rstrip("/") != expected:
            raise HTTPException(403, "Origin stimmt nicht überein")


def check_rate_limit(db: Session, address: str, username: str) -> None:
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    pair_failures = (
        db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.source_address == address,
                LoginAttempt.username == username,
                LoginAttempt.success.is_(False),
                LoginAttempt.created_at >= since,
            )
        )
        or 0
    )
    ip_failures = (
        db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.source_address == address,
                LoginAttempt.success.is_(False),
                LoginAttempt.created_at >= since,
            )
        )
        or 0
    )
    if pair_failures >= 5 or ip_failures >= 20:
        raise HTTPException(429, "Zu viele Anmeldeversuche. Bitte später erneut versuchen.")


def create_session(db: Session, user: User, request: Request) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(48)
    db.add(
        SessionToken(
            token_hash=hash_token(token),
            user_id=user.id,
            created_at=now,
            authenticated_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
            source_address=source_address(request),
        )
    )
    return token


def current_user(
    request: Request,
    session_cookie: str | None = Cookie(default=None, alias=get_settings().session_cookie_name),
    db: Session = Depends(get_db),
) -> User:
    if not session_cookie:
        raise HTTPException(401, "Anmeldung erforderlich")
    row = db.scalar(select(SessionToken).where(SessionToken.token_hash == hash_token(session_cookie)))
    now = datetime.now(timezone.utc)
    settings = get_settings()
    if (
        not row
        or as_utc(row.expires_at) <= now
        or as_utc(row.last_seen_at) <= now - timedelta(seconds=settings.session_idle_seconds)
    ):
        if row:
            db.delete(row)
            db.commit()
        raise HTTPException(401, "Sitzung abgelaufen")
    row.last_seen_at = now
    db.commit()
    request.state.user = row.user
    request.state.session = row
    if row.user.must_change_password and request.url.path not in {
        "/api/auth/me",
        "/api/auth/logout",
        "/api/auth/password",
    }:
        raise HTTPException(403, "Vor der weiteren Nutzung muss das Startpasswort geändert werden")
    return row.user
