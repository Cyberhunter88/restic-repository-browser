from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import PurePosixPath

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .db import SessionLocal
from .models import CachedEntry, DirectoryListing, Snapshot, new_id
from .repository_access import RuntimeRepository
from .restic import iter_entries


_listing_locks: dict[tuple[str, str], asyncio.Lock] = {}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def ensure_directory_listing(
    snapshot: Snapshot,
    runtime: RuntimeRepository,
    path: str,
    semaphore: asyncio.Semaphore,
) -> str:
    with SessionLocal() as db:
        existing = db.scalar(
            select(DirectoryListing).where(
                DirectoryListing.snapshot_id == snapshot.id,
                DirectoryListing.path == path,
            )
        )
        if existing:
            return existing.id

    key = (snapshot.id, path)
    lock = _listing_locks.setdefault(key, asyncio.Lock())
    async with lock:
        with SessionLocal() as db:
            existing = db.scalar(
                select(DirectoryListing).where(
                    DirectoryListing.snapshot_id == snapshot.id,
                    DirectoryListing.path == path,
                )
            )
            if existing:
                return existing.id

            listing = DirectoryListing(id=new_id(), snapshot_id=snapshot.id, path=path)
            db.add(listing)
            db.flush()
            count = 0
            try:
                async with semaphore:
                    async for item in iter_entries(runtime, snapshot.snapshot_id, path):
                        entry_path = str(item.get("path") or "")
                        if entry_path == path or PurePosixPath(entry_path).parent.as_posix() != path:
                            continue
                        db.add(
                            CachedEntry(
                                listing_id=listing.id,
                                path=entry_path,
                                name=PurePosixPath(entry_path).name or "/",
                                type=str(item.get("type") or "file"),
                                size=int(item.get("size") or 0),
                                mode_json=json.dumps(item.get("mode")),
                                mtime=_parse_time(item.get("mtime")),
                                uid=item.get("uid"),
                                gid=item.get("gid"),
                                linktarget=item.get("linktarget"),
                            )
                        )
                        count += 1
                        if count % 500 == 0:
                            db.flush()
                listing.entry_count = count
                db.commit()
                return listing.id
            except IntegrityError:
                db.rollback()
                existing = db.scalar(
                    select(DirectoryListing).where(
                        DirectoryListing.snapshot_id == snapshot.id,
                        DirectoryListing.path == path,
                    )
                )
                if existing:
                    return existing.id
                raise
            except BaseException:
                db.rollback()
                raise
            finally:
                _listing_locks.pop(key, None)
