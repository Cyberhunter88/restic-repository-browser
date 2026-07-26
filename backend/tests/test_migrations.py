from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import command
from alembic.config import Config


def test_sftp_url_migration_repairs_existing_repository(tmp_path):
    database_url = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0001_initial")

    engine = sa.create_engine(database_url)
    repositories = sa.Table("repositories", sa.MetaData(), autoload_with=engine)
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            repositories.insert(),
            {
                "id": "migration-sftp-repository",
                "name": "Existing SFTP Repository",
                "kind": "sftp",
                "location": "sftp:backup@nas.example:22//srv/restic",
                "config_json": "{}",
                "enabled": True,
                "last_check_at": None,
                "last_snapshot_refresh_at": None,
                "last_error": "",
                "created_at": now,
                "updated_at": now,
            },
        )

    command.upgrade(config, "head")

    with engine.connect() as connection:
        location = connection.scalar(
            sa.select(repositories.c.location).where(
                repositories.c.id == "migration-sftp-repository"
            )
        )
    assert location == "sftp://backup@nas.example:22//srv/restic"
    inspector = sa.inspect(engine)
    assert {"directory_listings", "cached_entries", "audit_events"}.issubset(
        set(inspector.get_table_names())
    )
    refresh_columns = {column["name"] for column in inspector.get_columns("refresh_jobs")}
    assert {
        "requested_by",
        "active_key",
        "attempt_count",
        "lease_expires_at",
        "heartbeat_at",
    }.issubset(refresh_columns)

    command.downgrade(config, "0002_fix_sftp_urls")
    assert "audit_events" not in sa.inspect(engine).get_table_names()
    command.upgrade(config, "head")
