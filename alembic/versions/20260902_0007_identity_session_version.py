"""Bind server-side sessions to the user's session invalidation version.

Revision ID: 20260902_0007
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260902_0007"
down_revision = "20260825_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "identity_sessions",
        sa.Column(
            "session_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )

    op.alter_column(
        "identity_sessions",
        "session_version",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_column("identity_sessions", "session_version")
