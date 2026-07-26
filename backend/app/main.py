from __future__ import annotations

import asyncio
import json
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from urllib.parse import quote

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .bootstrap import bootstrap
from .config import get_settings
from .crypto import (
    delete_repository_secrets,
    get_repository_secrets,
    set_repository_secret,
)
from .db import SessionLocal, get_db
from .models import LoginAttempt, RefreshJob, Repository, SessionToken, Snapshot, User, new_id
from .repository_access import (
    display_location,
    fingerprint_known_host,
    runtime_from_input,
    runtime_from_model,
)
from .restic import list_entries, list_snapshots, run_command, stream_dump
from .schemas import (
    LoginInput,
    MessageOut,
    PasswordChange,
    RefreshJobOut,
    RepositoryInput,
    RepositorySummary,
    SftpHostKey,
    SftpHostKeyRequest,
    SnapshotEntry,
    SnapshotSummary,
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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap()
    yield


app = FastAPI(
    title="Restic Repository Browser API",
    version="0.1.0",
    lifespan=lifespan,
    dependencies=[Depends(enforce_browser_request)],
)


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


async def perform_refresh(job_id: str) -> None:
    with SessionLocal() as db:
        job = db.get(RefreshJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        repository = db.get(Repository, job.repository_id)
        if not repository:
            job.status = "failed"
            job.error = "Repository nicht gefunden"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return
        runtime = runtime_from_model(repository, get_repository_secrets(db, repository.id))
    try:
        async with restic_semaphore:
            items = await list_snapshots(runtime)
        with SessionLocal() as db:
            job = db.get(RefreshJob, job_id)
            repository = db.get(Repository, runtime.id)
            if not job or not repository:
                return
            cache_snapshots(db, repository, items)
            job.status = "success"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as exc:
        with SessionLocal() as db:
            job = db.get(RefreshJob, job_id)
            repository = db.get(Repository, runtime.id)
            message = str(exc)[:2000]
            if job:
                job.status = "failed"
                job.error = message
                job.finished_at = datetime.now(timezone.utc)
            if repository:
                repository.last_error = message
                repository.last_check_at = datetime.now(timezone.utc)
            db.commit()


def queue_refresh(db: Session, repository_id: str) -> tuple[RefreshJob, bool]:
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
    job = RefreshJob(repository_id=repository_id)
    db.add(job)
    db.commit()
    db.refresh(job)
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
        db.commit()
        raise HTTPException(401, "Benutzername oder Passwort ist falsch")
    token = create_session(db, user, request)
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
    _user: User = Depends(current_user),
):
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        row = db.get(SessionToken, hash_token(cookie))
        if row:
            db.delete(row)
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
    db.commit()
    return MessageOut(message="Passwort wurde geändert")


@app.get("/api/repositories", response_model=list[RepositorySummary])
def repositories(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    return [
        repository_out(db, row)
        for row in db.scalars(select(Repository).order_by(Repository.name)).all()
    ]


async def validate_runtime(runtime) -> list[dict]:
    async with restic_semaphore:
        return await list_snapshots(
            runtime,
            timeout=REPOSITORY_VALIDATION_TIMEOUT_SECONDS,
        )


@app.post("/api/repositories", response_model=RepositorySummary, status_code=201)
async def create_repository(
    data: RepositoryInput,
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
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
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Ein Repository mit diesem Namen existiert bereits") from exc
    db.refresh(row)
    return repository_out(db, row)


@app.put("/api/repositories/{repository_id}", response_model=RepositorySummary)
async def update_repository(
    repository_id: str,
    data: RepositoryInput,
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    row = db.get(Repository, repository_id)
    if not row:
        raise HTTPException(404, "Repository nicht gefunden")
    try:
        runtime = runtime_from_input(data, row.id)
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
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Ein Repository mit diesem Namen existiert bereits") from exc
    return repository_out(db, row)


@app.post("/api/repositories/{repository_id}/test", response_model=MessageOut)
async def test_repository(
    repository_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    row = db.get(Repository, repository_id)
    if not row:
        raise HTTPException(404, "Repository nicht gefunden")
    runtime = runtime_from_model(row, get_repository_secrets(db, row.id))
    result = await run_command(runtime, ["snapshots", "--json", "--no-lock"])
    row.last_check_at = datetime.now(timezone.utc)
    if result.returncode != 0:
        row.last_error = result.stderr or "Verbindung ist fehlgeschlagen"
        db.commit()
        raise HTTPException(502, row.last_error)
    row.last_error = ""
    db.commit()
    return MessageOut(message="Verbindung erfolgreich")


@app.delete("/api/repositories/{repository_id}", status_code=204)
def delete_repository(
    repository_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    row = db.get(Repository, repository_id)
    if not row:
        raise HTTPException(404, "Repository nicht gefunden")
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
        raise HTTPException(504, "Zeitüberschreitung beim Abruf des Hostschlüssels") from exc
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


@app.get("/api/repositories/{repository_id}/snapshots", response_model=list[SnapshotSummary])
def repository_snapshots(
    repository_id: str,
    background_tasks: BackgroundTasks,
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
    if stale:
        job, created = queue_refresh(db, repository_id)
        if created:
            background_tasks.add_task(perform_refresh, job.id)
    rows = db.scalars(
        select(Snapshot)
        .where(Snapshot.repository_id == repository_id)
        .order_by(Snapshot.time.desc())
    ).all()
    return [snapshot_out(row) for row in rows]


@app.post("/api/repositories/{repository_id}/refresh", response_model=RefreshJobOut, status_code=202)
def refresh_repository(
    repository_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    if not db.get(Repository, repository_id):
        raise HTTPException(404, "Repository nicht gefunden")
    job, created = queue_refresh(db, repository_id)
    if created:
        background_tasks.add_task(perform_refresh, job.id)
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


@app.get("/api/snapshots/{snapshot_row_id}/entries", response_model=list[SnapshotEntry])
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
    runtime = runtime_from_model(repository, get_repository_secrets(db, repository.id))
    try:
        async with restic_semaphore:
            items = await list_entries(runtime, snapshot.snapshot_id, path)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    entries: list[SnapshotEntry] = []
    for item in items:
        entry_path = str(item.get("path") or "")
        if entry_path == path:
            continue
        if PurePosixPath(entry_path).parent.as_posix() != path:
            continue
        entries.append(
            SnapshotEntry(
                path=entry_path,
                name=PurePosixPath(entry_path).name or "/",
                type=str(item.get("type") or "file"),
                size=int(item.get("size") or 0),
                mode=item.get("mode"),
                mtime=parse_time(item.get("mtime")) if item.get("mtime") else None,
                uid=item.get("uid"),
                gid=item.get("gid"),
                linktarget=item.get("linktarget"),
            )
        )
    return sorted(entries, key=lambda entry: (entry.type != "dir", entry.name.lower()))


@app.get("/api/snapshots/{snapshot_row_id}/download")
async def snapshot_download(
    snapshot_row_id: str,
    path: str = Query(min_length=1, max_length=4096),
    archive: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user: User = Depends(current_user),
):
    path = validate_snapshot_path(path)
    if archive not in {None, "zip"}:
        raise HTTPException(422, "Unbekanntes Archivformat")
    snapshot = db.get(Snapshot, snapshot_row_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot nicht gefunden")
    repository = db.get(Repository, snapshot.repository_id)
    runtime = runtime_from_model(repository, get_repository_secrets(db, repository.id))
    try:
        async with restic_semaphore:
            items = await list_entries(runtime, snapshot.snapshot_id, path)
    except RuntimeError as exc:
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
    async def limited_stream():
        async with restic_semaphore:
            async for chunk in stream_dump(
                runtime,
                snapshot.snapshot_id,
                path,
                archive="zip" if archive == "zip" else None,
            ):
                yield chunk

    return StreamingResponse(
        limited_stream(),
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
