from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import sys
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import add_audit_event
from .bootstrap import bootstrap
from .config import get_settings
from .crypto import (
    delete_repository_secrets,
    get_repository_secrets,
    set_repository_secret,
)
from .db import SessionLocal, get_db
from .directory_cache import ensure_directory_listing
from .models import (
    AuditEvent,
    CachedEntry,
    DirectoryListing,
    LoginAttempt,
    RefreshJob,
    Repository,
    SessionToken,
    Snapshot,
    User,
    new_id,
)
from .repository_access import (
    display_location,
    ensure_remote_target_allowed,
    ensure_runtime_target_allowed,
    fingerprint_known_host,
    runtime_from_input,
    runtime_from_model,
    runtime_from_update,
)
from .restic import list_entries, list_snapshots, run_command, stream_dump
from .schemas import (
    AuditEventOut,
    AuditPage,
    EntryPage,
    LoginInput,
    MessageOut,
    PasswordChange,
    RefreshJobOut,
    RepositoryInput,
    RepositoryStateInput,
    RepositorySummary,
    RepositoryUpdateInput,
    SftpHostKey,
    SftpHostKeyRequest,
    SnapshotPage,
    SnapshotEntry,
    SnapshotSummary,
    SystemStatusOut,
    UserOut,
)
from .security import (
    as_utc,
    check_rate_limit,
    create_session,
    current_user,
    enforce_browser_request,
    hash_password,
    hash_token,
    request_is_secure,
    source_address,
    verify_password,
)


REPOSITORY_VALIDATION_TIMEOUT_SECONDS = 30

settings = get_settings()
restic_semaphore = asyncio.Semaphore(settings.max_parallel_restic)
worker_wakeup = asyncio.Event()
worker_loop: asyncio.AbstractEventLoop | None = None
worker_running = False
last_cleanup_at: datetime | None = None
logger = logging.getLogger("rrb")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        value = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for name in ("request_id", "method", "path", "status_code", "duration_ms"):
            if hasattr(record, name):
                value[name] = getattr(record, name)
        return json.dumps(value, ensure_ascii=False)


def configure_logging() -> None:
    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global worker_loop, worker_running
    bootstrap()
    configure_logging()
    recover_expired_jobs(force=True)
    run_cleanup()
    worker_running = True
    worker_loop = asyncio.get_running_loop()
    task = asyncio.create_task(refresh_worker(), name="refresh-worker")
    try:
        yield
    finally:
        worker_running = False
        worker_loop = None
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


app = FastAPI(
    title="Restic Repository Browser API",
    version="0.2.0",
    lifespan=lifespan,
    dependencies=[Depends(enforce_browser_request)],
)


@app.middleware("http")
async def request_metadata(request: Request, call_next):
    request_id = uuid.uuid4().hex
    request.state.request_id = request_id
    started = asyncio.get_running_loop().time()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "request_failed",
            extra={"request_id": request_id, "method": request.method, "path": request.url.path},
        )
        raise
    duration_ms = round((asyncio.get_running_loop().time() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request_is_secure(request):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    logger.info(
        "request",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )
    return response


def parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def json_value(value: str, default):
    try:
        return json.loads(value or "")
    except json.JSONDecodeError:
        return default


def encode_cursor(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(value: str | None, expected: type) -> object | None:
    if not value:
        return None
    try:
        padding = "=" * (-len(value) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(value + padding))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(422, "Ungültiger Cursor") from exc
    if not isinstance(decoded, expected):
        raise HTTPException(422, "Ungültiger Cursor")
    return decoded


def cached_entry_out(row: CachedEntry) -> SnapshotEntry:
    return SnapshotEntry(
        path=row.path,
        name=row.name,
        type=row.type,
        size=row.size,
        mode=json_value(row.mode_json, None),
        mtime=row.mtime,
        uid=row.uid,
        gid=row.gid,
        linktarget=row.linktarget,
    )


async def audited_chunks(
    chunks: AsyncIterator[bytes],
    record: Callable[[str, str], None],
) -> AsyncIterator[bytes]:
    try:
        async for chunk in chunks:
            yield chunk
    except (asyncio.CancelledError, GeneratorExit):
        record("cancelled", "")
        raise
    except Exception as exc:
        record("failed", str(exc))
        raise
    else:
        record("success", "")


def repository_out(db: Session, row: Repository) -> RepositorySummary:
    config = json_value(row.config_json, {})
    count = db.scalar(
        select(func.count(Snapshot.id)).where(Snapshot.repository_id == row.id)
    ) or 0
    public_config = {
        key: value
        for key, value in config.items()
        if key
        in {
            "path",
            "url",
            "host",
            "port",
            "username",
            "fingerprint",
            "auth_method",
            "endpoint",
            "bucket",
            "prefix",
            "region",
        }
    }
    return RepositorySummary(
        id=row.id,
        name=row.name,
        kind=row.kind,
        location_display=display_location(row.kind, config),
        enabled=row.enabled,
        last_check_at=row.last_check_at,
        last_snapshot_refresh_at=row.last_snapshot_refresh_at,
        last_error=row.last_error,
        snapshot_count=count,
        created_at=row.created_at,
        config=public_config,
    )


def snapshot_out(row: Snapshot) -> SnapshotSummary:
    return SnapshotSummary(
        id=row.id,
        repository_id=row.repository_id,
        snapshot_id=row.snapshot_id,
        short_id=row.short_id,
        time=row.time,
        hostname=row.hostname,
        username=row.username,
        paths=json_value(row.paths_json, []),
        tags=json_value(row.tags_json, []),
        summary=json_value(row.summary_json, {}),
        cached_at=row.cached_at,
    )


def refresh_job_out(row: RefreshJob) -> RefreshJobOut:
    return RefreshJobOut(
        id=row.id,
        repository_id=row.repository_id,
        status=row.status,
        error=row.error,
        created_at=row.created_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
        attempt_count=row.attempt_count,
    )


def cache_snapshots(db: Session, repository: Repository, items: list[dict]) -> None:
    now = datetime.now(timezone.utc)
    seen: set[str] = set()
    for item in items:
        snapshot_id = str(item.get("id", ""))
        if not re.fullmatch(r"[a-fA-F0-9]{64}", snapshot_id):
            continue
        seen.add(snapshot_id)
        row = db.scalar(
            select(Snapshot).where(
                Snapshot.repository_id == repository.id,
                Snapshot.snapshot_id == snapshot_id,
            )
        )
        values = {
            "short_id": str(item.get("short_id") or snapshot_id[:8])[:16],
            "time": parse_time(item.get("time")),
            "hostname": str(item.get("hostname") or "")[:255],
            "username": str(item.get("username") or "")[:255],
            "paths_json": json.dumps(item.get("paths") or []),
            "tags_json": json.dumps(item.get("tags") or []),
            "summary_json": json.dumps(item.get("summary") or {}),
            "cached_at": now,
        }
        if row:
            for key, value in values.items():
                setattr(row, key, value)
        else:
            db.add(
                Snapshot(
                    repository_id=repository.id,
                    snapshot_id=snapshot_id,
                    **values,
                )
            )
    if seen:
        db.execute(
            delete(Snapshot).where(
                Snapshot.repository_id == repository.id,
                Snapshot.snapshot_id.not_in(seen),
            )
        )
    else:
        db.execute(delete(Snapshot).where(Snapshot.repository_id == repository.id))
    repository.last_snapshot_refresh_at = now
    repository.last_check_at = now
    repository.last_error = ""


def recover_expired_jobs(*, force: bool = False) -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        rows = db.scalars(
            select(RefreshJob).where(
                RefreshJob.status == "running",
            )
        ).all()
        for job in rows:
            expired = (
                force
                or not job.lease_expires_at
                or as_utc(job.lease_expires_at) <= now
            )
            if not expired:
                continue
            if job.attempt_count >= 3:
                job.status = "failed"
                job.active_key = None
                job.error = "Aktualisierung wurde nach wiederholten Prozessabbrüchen beendet"
                job.finished_at = now
            else:
                job.status = "queued"
                job.lease_expires_at = None
        db.commit()


def run_cleanup() -> None:
    global last_cleanup_at
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.execute(delete(SessionToken).where(SessionToken.expires_at <= now))
        db.execute(
            delete(LoginAttempt).where(
                LoginAttempt.created_at
                < now - timedelta(days=settings.login_retention_days)
            )
        )
        db.execute(
            delete(RefreshJob).where(
                RefreshJob.status.in_(("success", "failed")),
                RefreshJob.finished_at
                < now - timedelta(days=settings.job_retention_days),
            )
        )
        db.execute(
            delete(AuditEvent).where(
                AuditEvent.created_at
                < now - timedelta(days=settings.audit_retention_days)
            )
        )
        db.commit()
    last_cleanup_at = now


def claim_refresh_job() -> str | None:
    recover_expired_jobs()
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        candidate = db.scalar(
            select(RefreshJob)
            .where(RefreshJob.status == "queued")
            .order_by(RefreshJob.created_at, RefreshJob.id)
        )
        if not candidate:
            return None
        result = db.execute(
            update(RefreshJob)
            .where(RefreshJob.id == candidate.id, RefreshJob.status == "queued")
            .values(
                status="running",
                started_at=now,
                finished_at=None,
                error="",
                attempt_count=RefreshJob.attempt_count + 1,
                heartbeat_at=now,
                lease_expires_at=now
                + timedelta(seconds=settings.refresh_job_lease_seconds),
            )
        )
        db.commit()
        return candidate.id if result.rowcount == 1 else None


async def heartbeat_job(job_id: str) -> None:
    interval = max(5, settings.refresh_job_lease_seconds // 3)
    while True:
        await asyncio.sleep(interval)
        now = datetime.now(timezone.utc)
        with SessionLocal() as db:
            job = db.get(RefreshJob, job_id)
            if not job or job.status != "running":
                return
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(
                seconds=settings.refresh_job_lease_seconds
            )
            db.commit()


async def perform_refresh(job_id: str) -> None:
    with SessionLocal() as db:
        job = db.get(RefreshJob, job_id)
        if not job or job.status != "running":
            return
        repository = db.get(Repository, job.repository_id)
        if not repository:
            job.status = "failed"
            job.active_key = None
            job.error = "Repository nicht gefunden"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return
        if not repository.enabled:
            job.status = "failed"
            job.active_key = None
            job.error = "Repository ist deaktiviert"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return
        runtime = runtime_from_model(
            repository, get_repository_secrets(db, repository.id)
        )
        requested_by = job.requested_by
    heartbeat = asyncio.create_task(heartbeat_job(job_id))
    try:
        await ensure_runtime_target_allowed(runtime)
        async with restic_semaphore:
            items = await list_snapshots(runtime)
        with SessionLocal() as db:
            job = db.get(RefreshJob, job_id)
            repository = db.get(Repository, runtime.id)
            if not job or not repository:
                return
            cache_snapshots(db, repository, items)
            job.status = "success"
            job.active_key = None
            job.finished_at = datetime.now(timezone.utc)
            job.lease_expires_at = None
            add_audit_event(
                db,
                "repository.refresh",
                user=requested_by,
                repository_id=repository.id,
            )
            db.commit()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        with SessionLocal() as db:
            job = db.get(RefreshJob, job_id)
            repository = db.get(Repository, runtime.id)
            message = str(exc)[:2000]
            if job:
                job.status = "failed"
                job.active_key = None
                job.error = message
                job.finished_at = datetime.now(timezone.utc)
                job.lease_expires_at = None
            if repository:
                repository.last_error = message
                repository.last_check_at = datetime.now(timezone.utc)
            add_audit_event(
                db,
                "repository.refresh",
                result="failed",
                user=requested_by,
                repository_id=runtime.id,
                detail=message,
            )
            db.commit()
    finally:
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)


async def refresh_worker() -> None:
    next_cleanup = datetime.now(timezone.utc) + timedelta(days=1)
    while True:
        if datetime.now(timezone.utc) >= next_cleanup:
            run_cleanup()
            next_cleanup = datetime.now(timezone.utc) + timedelta(days=1)
        job_id = claim_refresh_job()
        if job_id:
            await perform_refresh(job_id)
            continue
        worker_wakeup.clear()
        try:
            await asyncio.wait_for(
                worker_wakeup.wait(), timeout=settings.worker_poll_seconds
            )
        except TimeoutError:
            pass


def queue_refresh(
    db: Session,
    repository_id: str,
    requested_by: str = "system",
) -> tuple[RefreshJob, bool]:
    existing = db.scalar(
        select(RefreshJob)
        .where(
            RefreshJob.repository_id == repository_id,
            RefreshJob.status.in_(("queued", "running")),
        )
        .order_by(RefreshJob.created_at.desc())
    )
    if existing:
        return existing, False
    job = RefreshJob(
        repository_id=repository_id,
        requested_by=requested_by,
        active_key=repository_id,
    )
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(RefreshJob).where(RefreshJob.active_key == repository_id)
        )
        if existing:
            return existing, False
        raise
    db.refresh(job)
    if worker_loop:
        worker_loop.call_soon_threadsafe(worker_wakeup.set)
    return job, True


@app.get("/api/health/live")
def health_live():
    return {"status": "ok"}


@app.get("/api/health/ready")
def health_ready(db: Session = Depends(get_db)):
    db.scalar(select(func.count(User.id)))
    return {"status": "ready"}


@app.post("/api/auth/login", response_model=UserOut)
def login(
    data: LoginInput,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    username = data.username.strip()
    address = source_address(request)
    check_rate_limit(db, address, username)
    user = db.scalar(select(User).where(User.username == username))
    success = bool(user and verify_password(user.password_hash, data.password.get_secret_value()))
    db.add(LoginAttempt(source_address=address, username=username, success=success))
    if not success:
        add_audit_event(
            db,
            "auth.login",
            result="failed",
            user=username,
            detail="Ungültige Anmeldedaten",
        )
        db.commit()
        raise HTTPException(401, "Benutzername oder Passwort ist falsch")
    token = create_session(db, user, request)
    add_audit_event(db, "auth.login", user=user)
    db.commit()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=request_is_secure(request),
        samesite="lax",
        max_age=settings.session_ttl_seconds,
        path="/",
    )
    return UserOut(username=user.username, must_change_password=user.must_change_password)


@app.post("/api/auth/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        row = db.get(SessionToken, hash_token(cookie))
        if row:
            db.delete(row)
    add_audit_event(db, "auth.logout", user=user)
    db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/")


@app.get("/api/auth/me", response_model=UserOut)
def auth_me(user: User = Depends(current_user)):
    return UserOut(username=user.username, must_change_password=user.must_change_password)


@app.post("/api/auth/password", response_model=MessageOut)
def change_password(
    data: PasswordChange,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if not verify_password(user.password_hash, data.current_password.get_secret_value()):
        raise HTTPException(422, "Das bisherige Passwort ist falsch")
    user.password_hash = hash_password(data.new_password.get_secret_value())
    user.must_change_password = False
    current_cookie = request.cookies.get(settings.session_cookie_name)
    current_hash = hash_token(current_cookie) if current_cookie else ""
    db.execute(
        delete(SessionToken).where(
            SessionToken.user_id == user.id,
            SessionToken.token_hash != current_hash,
        )
    )
    add_audit_event(db, "auth.password_change", user=user)
    db.commit()
    return MessageOut(message="Passwort wurde geändert")


@app.get("/api/repositories", response_model=list[RepositorySummary])
def repositories(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    return [
        repository_out(db, row)
        for row in db.scalars(select(Repository).order_by(Repository.name)).all()
    ]


async def validate_runtime(runtime) -> list[dict]:
    if hasattr(runtime, "kind"):
        await ensure_runtime_target_allowed(runtime)
    async with restic_semaphore:
        return await list_snapshots(
            runtime,
            timeout=REPOSITORY_VALIDATION_TIMEOUT_SECONDS,
        )


@app.post("/api/repositories", response_model=RepositorySummary, status_code=201)
async def create_repository(
    data: RepositoryInput,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    repository_id = new_id()
    try:
        runtime = runtime_from_input(data, repository_id)
        snapshots = await validate_runtime(runtime)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    row = Repository(
        id=repository_id,
        name=data.name.strip(),
        kind=data.kind,
        location=runtime.location,
        config_json=json.dumps(runtime.config),
        enabled=True,
        last_check_at=datetime.now(timezone.utc),
    )
    db.add(row)
    try:
        db.flush()
        for name, value in runtime.secrets.items():
            set_repository_secret(db, row.id, name, value)
        cache_snapshots(db, row, snapshots)
        add_audit_event(
            db, "repository.create", user=user, repository_id=row.id
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Ein Repository mit diesem Namen existiert bereits") from exc
    db.refresh(row)
    return repository_out(db, row)


@app.put("/api/repositories/{repository_id}", response_model=RepositorySummary)
async def update_repository(
    repository_id: str,
    data: RepositoryUpdateInput,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = db.get(Repository, repository_id)
    if not row:
        raise HTTPException(404, "Repository nicht gefunden")
    try:
        runtime = runtime_from_update(
            data, row, get_repository_secrets(db, row.id)
        )
        snapshots = await validate_runtime(runtime)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    row.name = data.name.strip()
    row.kind = data.kind
    row.location = runtime.location
    row.config_json = json.dumps(runtime.config)
    delete_repository_secrets(db, row.id)
    for name, value in runtime.secrets.items():
        set_repository_secret(db, row.id, name, value)
    cache_snapshots(db, row, snapshots)
    add_audit_event(
        db, "repository.update", user=user, repository_id=row.id
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Ein Repository mit diesem Namen existiert bereits") from exc
    return repository_out(db, row)


@app.patch("/api/repositories/{repository_id}/state", response_model=RepositorySummary)
def set_repository_state(
    repository_id: str,
    data: RepositoryStateInput,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = db.get(Repository, repository_id)
    if not row:
        raise HTTPException(404, "Repository nicht gefunden")
    row.enabled = data.enabled
    add_audit_event(
        db,
        "repository.enable" if data.enabled else "repository.disable",
        user=user,
        repository_id=row.id,
    )
    db.commit()
    return repository_out(db, row)


@app.post("/api/repositories/{repository_id}/test", response_model=MessageOut)
async def test_repository(
    repository_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = db.get(Repository, repository_id)
    if not row:
        raise HTTPException(404, "Repository nicht gefunden")
    if not row.enabled:
        raise HTTPException(409, "Repository ist deaktiviert")
    runtime = runtime_from_model(row, get_repository_secrets(db, row.id))
    try:
        await ensure_runtime_target_allowed(runtime)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    async with restic_semaphore:
        result = await run_command(runtime, ["snapshots", "--json", "--no-lock"])
    row.last_check_at = datetime.now(timezone.utc)
    if result.returncode != 0:
        row.last_error = result.stderr or "Verbindung ist fehlgeschlagen"
        add_audit_event(
            db,
            "repository.test",
            result="failed",
            user=user,
            repository_id=row.id,
            detail=row.last_error,
        )
        db.commit()
        raise HTTPException(502, row.last_error)
    row.last_error = ""
    add_audit_event(db, "repository.test", user=user, repository_id=row.id)
    db.commit()
    return MessageOut(message="Verbindung erfolgreich")


@app.delete("/api/repositories/{repository_id}", status_code=204)
def delete_repository(
    repository_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = db.get(Repository, repository_id)
    if not row:
        raise HTTPException(404, "Repository nicht gefunden")
    add_audit_event(db, "repository.delete", user=user, repository_id=row.id)
    delete_repository_secrets(db, row.id)
    db.delete(row)
    db.commit()


@app.post("/api/repositories/sftp/scan-host-key", response_model=list[SftpHostKey])
async def scan_sftp_host_key(
    data: SftpHostKeyRequest,
    _user: User = Depends(current_user),
):
    host = data.host.strip()
    if not re.fullmatch(r"(?:[A-Za-z0-9.-]+|[0-9A-Fa-f:]+)", host) or host.startswith("-"):
        raise HTTPException(422, "SFTP-Host ist ungültig")
    try:
        await ensure_remote_target_allowed(host)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            "ssh-keyscan",
            "-T",
            "10",
            "-p",
            str(data.port),
            host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=15)
    except FileNotFoundError as exc:
        raise HTTPException(503, "ssh-keyscan ist nicht installiert") from exc
    except TimeoutError as exc:
        if process and process.returncode is None:
            process.kill()
            await process.wait()
        raise HTTPException(504, "Zeitüberschreitung beim Abruf des Hostschlüssels") from exc
    except asyncio.CancelledError:
        if process and process.returncode is None:
            process.terminate()
            await process.wait()
        raise
    if process.returncode != 0 or not stdout:
        raise HTTPException(502, "SFTP-Hostschlüssel konnte nicht abgerufen werden")
    result: list[SftpHostKey] = []
    for line in stdout.decode(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            fingerprint = fingerprint_known_host(line)
        except ValueError:
            continue
        result.append(
            SftpHostKey(
                algorithm=fields[1],
                fingerprint=fingerprint,
                known_hosts=line,
            )
        )
    if not result:
        raise HTTPException(502, "SFTP-Host hat keinen verwendbaren Schlüssel geliefert")
    return result


@app.get(
    "/api/repositories/{repository_id}/snapshots",
    response_model=list[SnapshotSummary],
    deprecated=True,
)
def repository_snapshots(
    repository_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    repository = db.get(Repository, repository_id)
    if not repository:
        raise HTTPException(404, "Repository nicht gefunden")
    stale = (
        not repository.last_snapshot_refresh_at
        or as_utc(repository.last_snapshot_refresh_at)
        < datetime.now(timezone.utc) - timedelta(seconds=settings.snapshot_cache_seconds)
    )
    if stale and repository.enabled:
        queue_refresh(db, repository_id)
    rows = db.scalars(
        select(Snapshot)
        .where(Snapshot.repository_id == repository_id)
        .order_by(Snapshot.time.desc())
    ).all()
    return [snapshot_out(row) for row in rows]


@app.get(
    "/api/repositories/{repository_id}/snapshots/page",
    response_model=SnapshotPage,
)
def repository_snapshot_page(
    repository_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=1000),
    q: str = Query(default="", max_length=500),
    host: str = Query(default="", max_length=255),
    tag: str = Query(default="", max_length=255),
    date: str = Query(default="", max_length=10),
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    repository = db.get(Repository, repository_id)
    if not repository:
        raise HTTPException(404, "Repository nicht gefunden")
    stale = (
        not repository.last_snapshot_refresh_at
        or as_utc(repository.last_snapshot_refresh_at)
        < datetime.now(timezone.utc)
        - timedelta(seconds=settings.snapshot_cache_seconds)
    )
    if stale and repository.enabled:
        queue_refresh(db, repository_id)

    statement = select(Snapshot).where(Snapshot.repository_id == repository_id)
    decoded = decode_cursor(cursor, list)
    if decoded is not None:
        if len(decoded) != 2 or not all(isinstance(item, str) for item in decoded):
            raise HTTPException(422, "Ungültiger Cursor")
        try:
            cursor_time = datetime.fromisoformat(decoded[0])
        except ValueError as exc:
            raise HTTPException(422, "Ungültiger Cursor") from exc
        statement = statement.where(
            or_(
                Snapshot.time < cursor_time,
                and_(Snapshot.time == cursor_time, Snapshot.id < decoded[1]),
            )
        )
    if host:
        statement = statement.where(Snapshot.hostname == host)
    if date:
        try:
            start = datetime.fromisoformat(date).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise HTTPException(422, "Ungültiges Datum") from exc
        statement = statement.where(
            Snapshot.time >= start, Snapshot.time < start + timedelta(days=1)
        )
    statement = statement.order_by(Snapshot.time.desc(), Snapshot.id.desc())
    term = q.casefold()
    matches: list[Snapshot] = []
    for row in db.scalars(statement):
        tags = json_value(row.tags_json, [])
        if tag and tag not in tags:
            continue
        searchable = (
            f"{row.short_id} {row.hostname} {row.paths_json} {row.tags_json}"
        ).casefold()
        if term and term not in searchable:
            continue
        matches.append(row)
        if len(matches) > limit:
            break
    page_rows = matches[:limit]
    next_cursor = None
    if len(matches) > limit and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor([as_utc(last.time).isoformat(), last.id])
    return SnapshotPage(
        items=[snapshot_out(row) for row in page_rows],
        next_cursor=next_cursor,
    )


@app.post("/api/repositories/{repository_id}/refresh", response_model=RefreshJobOut, status_code=202)
def refresh_repository(
    repository_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    repository = db.get(Repository, repository_id)
    if not repository:
        raise HTTPException(404, "Repository nicht gefunden")
    if not repository.enabled:
        raise HTTPException(409, "Repository ist deaktiviert")
    job, _created = queue_refresh(db, repository_id, user.username)
    return refresh_job_out(job)


@app.get("/api/refresh-jobs/{job_id}", response_model=RefreshJobOut)
def refresh_job(
    job_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    row = db.get(RefreshJob, job_id)
    if not row:
        raise HTTPException(404, "Aktualisierung nicht gefunden")
    return refresh_job_out(row)


@app.get("/api/audit-events", response_model=AuditPage)
def audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=1000),
    action: str = Query(default="", max_length=80),
    result: str = Query(default="", max_length=20),
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    statement = select(AuditEvent)
    decoded = decode_cursor(cursor, dict)
    if decoded is not None:
        event_id = decoded.get("id", -1)
        if not isinstance(event_id, int) or event_id < 1:
            raise HTTPException(422, "Ungültiger Cursor")
        statement = statement.where(AuditEvent.id < event_id)
    if action:
        statement = statement.where(AuditEvent.action == action)
    if result:
        statement = statement.where(AuditEvent.result == result)
    rows = db.scalars(statement.order_by(AuditEvent.id.desc()).limit(limit + 1)).all()
    items = rows[:limit]
    return AuditPage(
        items=[
            AuditEventOut(
                id=row.id,
                user_name=row.user_name,
                action=row.action,
                result=row.result,
                repository_id=row.repository_id,
                snapshot_id=row.snapshot_id,
                path=row.path,
                detail=row.detail,
                created_at=row.created_at,
            )
            for row in items
        ],
        next_cursor=encode_cursor({"id": items[-1].id})
        if len(rows) > limit and items
        else None,
    )


@app.get("/api/system/status", response_model=SystemStatusOut)
def system_status(
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    return SystemStatusOut(
        worker_running=worker_running,
        queued_jobs=db.scalar(
            select(func.count(RefreshJob.id)).where(RefreshJob.status == "queued")
        )
        or 0,
        running_jobs=db.scalar(
            select(func.count(RefreshJob.id)).where(RefreshJob.status == "running")
        )
        or 0,
        failed_jobs=db.scalar(
            select(func.count(RefreshJob.id)).where(RefreshJob.status == "failed")
        )
        or 0,
        directory_listings=db.scalar(select(func.count(DirectoryListing.id))) or 0,
        cached_entries=db.scalar(select(func.count(CachedEntry.id))) or 0,
        restic_limit=settings.max_parallel_restic,
        last_cleanup_at=last_cleanup_at,
    )


def validate_snapshot_path(path: str) -> str:
    if (
        not path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(part in {".", ".."} for part in PurePosixPath(path).parts)
        or any(ord(character) < 32 for character in path)
    ):
        raise HTTPException(422, "Ungültiger Snapshot-Pfad")
    return path.rstrip("/") or "/"


@app.get(
    "/api/snapshots/{snapshot_row_id}/entries",
    response_model=list[SnapshotEntry],
    deprecated=True,
)
async def snapshot_entries(
    snapshot_row_id: str,
    path: str = Query(default="/", max_length=4096),
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    path = validate_snapshot_path(path)
    snapshot = db.get(Snapshot, snapshot_row_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot nicht gefunden")
    repository = db.get(Repository, snapshot.repository_id)
    if not repository.enabled:
        raise HTTPException(409, "Repository ist deaktiviert")
    runtime = runtime_from_model(repository, get_repository_secrets(db, repository.id))
    try:
        await ensure_runtime_target_allowed(runtime)
        listing_id = await ensure_directory_listing(
            snapshot, runtime, path, restic_semaphore
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    db.rollback()
    rows = db.scalars(
        select(CachedEntry)
        .where(CachedEntry.listing_id == listing_id)
        .order_by(CachedEntry.type != "dir", func.lower(CachedEntry.name), CachedEntry.path)
    ).all()
    return [cached_entry_out(row) for row in rows]


@app.get("/api/snapshots/{snapshot_row_id}/entries/page", response_model=EntryPage)
async def snapshot_entry_page(
    snapshot_row_id: str,
    path: str = Query(default="/", max_length=4096),
    limit: int = Query(default=100, ge=1, le=250),
    cursor: str | None = Query(default=None, max_length=1000),
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    path = validate_snapshot_path(path)
    snapshot = db.get(Snapshot, snapshot_row_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot nicht gefunden")
    repository = db.get(Repository, snapshot.repository_id)
    if not repository.enabled:
        raise HTTPException(409, "Repository ist deaktiviert")
    runtime = runtime_from_model(repository, get_repository_secrets(db, repository.id))
    try:
        await ensure_runtime_target_allowed(runtime)
        listing_id = await ensure_directory_listing(
            snapshot, runtime, path, restic_semaphore
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc

    offset = 0
    decoded = decode_cursor(cursor, dict)
    if decoded is not None:
        offset = decoded.get("offset", -1)
        if not isinstance(offset, int) or offset < 0:
            raise HTTPException(422, "Ungültiger Cursor")
    db.rollback()
    rows = db.scalars(
        select(CachedEntry)
        .where(CachedEntry.listing_id == listing_id)
        .order_by(CachedEntry.type != "dir", func.lower(CachedEntry.name), CachedEntry.path)
        .offset(offset)
        .limit(limit + 1)
    ).all()
    return EntryPage(
        items=[cached_entry_out(row) for row in rows[:limit]],
        next_cursor=encode_cursor({"offset": offset + limit})
        if len(rows) > limit
        else None,
    )


@app.get("/api/snapshots/{snapshot_row_id}/download")
async def snapshot_download(
    snapshot_row_id: str,
    path: str = Query(min_length=1, max_length=4096),
    archive: str | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    path = validate_snapshot_path(path)
    if archive not in {None, "zip"}:
        raise HTTPException(422, "Unbekanntes Archivformat")
    snapshot = db.get(Snapshot, snapshot_row_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot nicht gefunden")
    repository = db.get(Repository, snapshot.repository_id)
    if not repository.enabled:
        raise HTTPException(409, "Repository ist deaktiviert")
    runtime = runtime_from_model(repository, get_repository_secrets(db, repository.id))
    try:
        await ensure_runtime_target_allowed(runtime)
        async with restic_semaphore:
            items = await list_entries(runtime, snapshot.snapshot_id, path)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        add_audit_event(
            db,
            "snapshot.download",
            result="failed",
            user=user,
            repository_id=repository.id,
            snapshot_id=snapshot.snapshot_id,
            path=path,
            detail=str(exc),
        )
        db.commit()
        raise HTTPException(502, str(exc)) from exc
    exact = next((item for item in items if item.get("path") == path), None)
    expected = "dir" if archive == "zip" else "file"
    if not exact or exact.get("type") != expected:
        raise HTTPException(404, "Datei oder Ordner wurde im Snapshot nicht gefunden")
    filename = PurePosixPath(path).name or f"snapshot-{snapshot.short_id}"
    if archive == "zip":
        filename = f"{filename}-{snapshot.short_id}.zip"
    fallback = re.sub(r"[^A-Za-z0-9._-]", "_", filename) or "download"
    disposition = f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename)}"

    def audit_download(result: str, detail: str = "") -> None:
        with SessionLocal() as audit_db:
            add_audit_event(
                audit_db,
                "snapshot.download",
                result=result,
                user=user.username,
                repository_id=repository.id,
                snapshot_id=snapshot.snapshot_id,
                path=path,
                detail=detail,
            )
            audit_db.commit()

    async def download_chunks():
        async with restic_semaphore:
            async for chunk in stream_dump(
                runtime,
                snapshot.snapshot_id,
                path,
                archive="zip" if archive == "zip" else None,
            ):
                yield chunk

    return StreamingResponse(
        audited_chunks(download_chunks(), audit_download),
        media_type="application/zip" if archive == "zip" else "application/octet-stream",
        headers={
            "Content-Disposition": disposition,
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


frontend = settings.frontend_dir
if frontend.is_dir():
    app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
