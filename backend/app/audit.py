from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditEvent, User


def add_audit_event(
    db: Session,
    action: str,
    *,
    result: str = "success",
    user: User | str | None = None,
    repository_id: str | None = None,
    snapshot_id: str | None = None,
    path: str | None = None,
    detail: str = "",
) -> AuditEvent:
    row = AuditEvent(
        user_name=user.username if isinstance(user, User) else (user or ""),
        action=action[:80],
        result=result[:20],
        repository_id=repository_id,
        snapshot_id=snapshot_id,
        path=path,
        detail=detail[:500],
    )
    db.add(row)
    return row
