"""Backfill integrity columns on databases created before Group 4.

Revision ID: 20260822_0002
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260822_0002"
down_revision = "20260822_0001"
branch_labels = None
depends_on = None

COLUMNS = {
    "detections": (
        ("correlation_id", sa.String(128), True),
        ("input_sha256", sa.String(64), True),
        ("rule_pack_sha256", sa.String(64), True),
        ("engine_version", sa.String(64), True),
        ("model_sha256", sa.String(64), True),
        ("config_sha256", sa.String(64), True),
    ),
    "case_events": (("correlation_id", sa.String(128), True),),
}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table, columns in COLUMNS.items():
        if table not in inspector.get_table_names():
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, column_type, nullable in columns:
            if name not in existing:
                op.add_column(table, sa.Column(name, column_type, nullable=nullable))
        for name, _, _ in columns:
            op.create_index(f"ix_{table}_{name}", table, [name], if_not_exists=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table, columns in reversed(tuple(COLUMNS.items())):
        if table not in inspector.get_table_names():
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, _, _ in reversed(columns):
            if name in existing:
                op.drop_index(f"ix_{table}_{name}", table_name=table, if_exists=True)
                op.drop_column(table, name)
