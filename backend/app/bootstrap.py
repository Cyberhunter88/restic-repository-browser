from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select

from .config import get_settings
from .crypto import ensure_master_key
from .db import SessionLocal
from .models import User
from .security import hash_password


def run_migrations() -> None:
    config_path = Path("alembic.ini")
    if not config_path.is_file():
        raise RuntimeError("alembic.ini wurde nicht gefunden")
    config = Config(str(config_path))
    config.set_main_option("sqlalchemy.url", get_settings().db_url)
    command.upgrade(config, "head")


def ensure_admin() -> None:
    settings = get_settings()
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)):
            return
        password = settings.initial_admin_password
        if len(password) < 12:
            raise RuntimeError(
                "RRB_INITIAL_ADMIN_PASSWORD muss beim Erststart gesetzt sein "
                "und mindestens 12 Zeichen haben"
            )
        db.add(
            User(
                username="admin",
                password_hash=hash_password(password),
                must_change_password=True,
            )
        )
        db.commit()


def bootstrap() -> None:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.repository_root.mkdir(parents=True, exist_ok=True)
    settings.restic_cache_dir.mkdir(parents=True, exist_ok=True)
    ensure_master_key()
    run_migrations()
    ensure_admin()


def main() -> None:
    bootstrap()


if __name__ == "__main__":
    main()

