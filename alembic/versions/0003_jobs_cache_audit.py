"""Add durable jobs, directory cache, and audit events.

Revision ID: 0003_jobs_cache_audit
Revises: 0002_fix_sftp_urls
Create Date: 2026-07-26
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_jobs_cache_audit"
down_revision = "0002_fix_sftp_urls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("refresh_jobs") as batch:
        batch.add_column(
            sa.Column("requested_by", sa.String(100), nullable=False, server_default="system")
        )
        batch.add_column(sa.Column("active_key", sa.String(32), nullable=True))
        batch.add_column(
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_unique_constraint("uq_refresh_jobs_active_key", ["active_key"])

    connection = op.get_bind()
    active_rows = connection.execute(
        sa.text(
            "SELECT id, repository_id FROM refresh_jobs "
            "WHERE status IN ('queued', 'running') ORDER BY created_at, id"
        )
    ).fetchall()
    seen: set[str] = set()
    for job_id, repository_id in active_rows:
        if repository_id not in seen:
            connection.execute(
                sa.text("UPDATE refresh_jobs SET active_key = :repository_id WHERE id = :job_id"),
                {"repository_id": repository_id, "job_id": job_id},
            )
            seen.add(repository_id)
        else:
            connection.execute(
                sa.text(
                    "UPDATE refresh_jobs SET status = 'failed', "
                    "error = 'Doppelter aktiver Job bei Migration beendet', "
                    "finished_at = CURRENT_TIMESTAMP WHERE id = :job_id"
                ),
                {"job_id": job_id},
            )

    op.create_table(
        "directory_listings",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.String(32),
            sa.ForeignKey("snapshots.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.UniqueConstraint("snapshot_id", "path", name="uq_directory_listing"),
    )
    op.create_index("ix_directory_listings_snapshot_id", "directory_listings", ["snapshot_id"])

    op.create_table(
        "cached_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "listing_id",
            sa.String(32),
            sa.ForeignKey("directory_listings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("type", sa.String(30), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("mode_json", sa.Text(), nullable=False),
        sa.Column("mtime", sa.DateTime(timezone=True), nullable=True),
        sa.Column("uid", sa.Integer(), nullable=True),
        sa.Column("gid", sa.Integer(), nullable=True),
        sa.Column("linktarget", sa.Text(), nullable=True),
        sa.UniqueConstraint("listing_id", "path", name="uq_cached_entry"),
    )
    op.create_index("ix_cached_entries_listing_id", "cached_entries", ["listing_id"])
    op.create_index("ix_cached_entries_type", "cached_entries", ["type"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_name", sa.String(100), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("repository_id", sa.String(32), nullable=True),
        sa.Column("snapshot_id", sa.String(64), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("detail", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_result", "audit_events", ["result"])
    op.create_index("ix_audit_events_repository_id", "audit_events", ["repository_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("cached_entries")
    op.drop_table("directory_listings")
    with op.batch_alter_table("refresh_jobs") as batch:
        batch.drop_constraint("uq_refresh_jobs_active_key", type_="unique")
        batch.drop_column("heartbeat_at")
        batch.drop_column("lease_expires_at")
        batch.drop_column("attempt_count")
        batch.drop_column("requested_by")
        batch.drop_column("active_key")
