"""Add shared rate-limit buckets for multi-instance API deployments.

Revision ID: 20260827_0008
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260827_0008"
down_revision = "20260827_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_buckets",
        sa.Column("bucket_key", sa.String(length=128), primary_key=True),
        sa.Column("window_start", sa.BigInteger(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
    )
    op.create_index("ix_rate_limit_buckets_window_start", "rate_limit_buckets", ["window_start"])


def downgrade() -> None:
    op.drop_index("ix_rate_limit_buckets_window_start", table_name="rate_limit_buckets")
    op.drop_table("rate_limit_buckets")
