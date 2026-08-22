"""Widen audit sequence for nanosecond ordering.

Revision ID: 20260822_0003
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260822_0003"
down_revision = "20260822_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("audit_events", "sequence_no", existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=False)


def downgrade() -> None:
    op.alter_column("audit_events", "sequence_no", existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=False)
