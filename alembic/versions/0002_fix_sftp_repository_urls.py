"""Fix SFTP repository URLs that include an explicit port.

Revision ID: 0002_fix_sftp_urls
Revises: 0001_initial
Create Date: 2026-07-26
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_fix_sftp_urls"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


repositories = sa.table(
    "repositories",
    sa.column("id", sa.String(32)),
    sa.column("kind", sa.String(20)),
    sa.column("location", sa.Text()),
)


def _rewrite_prefix(old_prefix: str, new_prefix: str) -> None:
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(repositories.c.id, repositories.c.location).where(
            repositories.c.kind == "sftp"
        )
    ).all()
    for repository_id, location in rows:
        if not location.startswith(old_prefix):
            continue
        if old_prefix == "sftp:" and location.startswith("sftp://"):
            continue
        connection.execute(
            repositories.update()
            .where(repositories.c.id == repository_id)
            .values(location=f"{new_prefix}{location[len(old_prefix):]}")
        )


def upgrade() -> None:
    _rewrite_prefix("sftp:", "sftp://")


def downgrade() -> None:
    _rewrite_prefix("sftp://", "sftp:")
