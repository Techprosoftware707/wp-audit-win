"""add users.token_epoch for token revocation

Idempotent: the 0001 initial migration builds tables from the current model
metadata via create_all, so on a FRESH database the column already exists; this
revision only adds it where an EXISTING database predates the column.

Revision ID: 0002_token_epoch
Revises: 0001_initial
Create Date: 2026-10-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_token_epoch"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    cols = [c["name"] for c in sa.inspect(bind).get_columns("users")]
    if "token_epoch" not in cols:
        op.add_column(
            "users",
            sa.Column("token_epoch", sa.Integer(), nullable=False, server_default="0"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    cols = [c["name"] for c in sa.inspect(bind).get_columns("users")]
    if "token_epoch" in cols:
        op.drop_column("users", "token_epoch")
