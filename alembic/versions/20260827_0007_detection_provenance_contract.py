"""Enforce complete detection provenance while explicitly marking legacy rows.

Revision ID: 20260827_0007
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260827_0007"
down_revision = "20260825_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    existing_columns = {column["name"] for column in sa.inspect(bind).get_columns("detections")}
    if "provenance_state" not in existing_columns:
        op.add_column(
            "detections",
            sa.Column("provenance_state", sa.String(length=32), nullable=False, server_default="complete"),
        )
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        UPDATE detections
        SET
          correlation_id = COALESCE(correlation_id, 'legacy-' || id::text),
          input_sha256 = COALESCE(input_sha256, encode(digest('legacy-input:' || id::text, 'sha256'), 'hex')),
          rule_pack_sha256 = COALESCE(rule_pack_sha256, encode(digest('legacy-rule-pack:' || id::text, 'sha256'), 'hex')),
          engine_version = COALESCE(engine_version, 'legacy-unverified'),
          config_sha256 = COALESCE(config_sha256, encode(digest('legacy-config:' || id::text, 'sha256'), 'hex')),
          provenance_state = CASE
            WHEN input_sha256 IS NULL
              OR rule_pack_sha256 IS NULL
              OR engine_version IS NULL
              OR config_sha256 IS NULL
              OR correlation_id IS NULL
            THEN 'legacy_unverified'
            ELSE 'complete'
          END
        """
    )
    op.alter_column("detections", "correlation_id", existing_type=sa.String(length=128), nullable=False)
    op.alter_column("detections", "input_sha256", existing_type=sa.String(length=64), nullable=False)
    op.alter_column("detections", "rule_pack_sha256", existing_type=sa.String(length=64), nullable=False)
    op.alter_column("detections", "engine_version", existing_type=sa.String(length=64), nullable=False)
    op.alter_column("detections", "config_sha256", existing_type=sa.String(length=64), nullable=False)


def downgrade() -> None:
    op.alter_column("detections", "config_sha256", existing_type=sa.String(length=64), nullable=True)
    op.alter_column("detections", "engine_version", existing_type=sa.String(length=64), nullable=True)
    op.alter_column("detections", "rule_pack_sha256", existing_type=sa.String(length=64), nullable=True)
    op.alter_column("detections", "input_sha256", existing_type=sa.String(length=64), nullable=True)
    op.alter_column("detections", "correlation_id", existing_type=sa.String(length=128), nullable=True)
    op.drop_column("detections", "provenance_state")
