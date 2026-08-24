"""Phase 3 SOC analyst workflow tables.

Revision ID: 20260824_0004
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260824_0004"
down_revision = "20260822_0003"
branch_labels = None
depends_on = None

TABLES = ("detection_workflow", "case_detection_links", "analyst_dispositions", "investigation_entities", "investigation_sessions")


def _tenant_index(table: str, name: str):
    op.create_index(name, table, ["tenant_id"])


def upgrade() -> None:
    op.create_table("detection_workflow", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.String(255), nullable=False), sa.Column("detection_id", sa.Integer(), nullable=False, unique=True), sa.Column("status", sa.String(32), nullable=False, server_default="new"), sa.Column("assignee", sa.String(255), nullable=True), sa.Column("priority", sa.Integer(), nullable=False, server_default="50"), sa.Column("updated_by", sa.String(255), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    _tenant_index("detection_workflow", "ix_detection_workflow_tenant"); op.create_index("ix_detection_workflow_detection", "detection_workflow", ["detection_id"])
    op.create_table("case_detection_links", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.String(255), nullable=False), sa.Column("case_id", sa.Integer(), nullable=False), sa.Column("detection_id", sa.Integer(), nullable=False), sa.Column("created_by", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    _tenant_index("case_detection_links", "ix_case_detection_links_tenant"); op.create_index("ix_case_detection_links_case", "case_detection_links", ["case_id"]); op.create_index("ix_case_detection_links_detection", "case_detection_links", ["detection_id"])
    op.create_table("analyst_dispositions", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.String(255), nullable=False), sa.Column("detection_id", sa.Integer(), nullable=False), sa.Column("case_id", sa.Integer(), nullable=True), sa.Column("analyst", sa.String(255), nullable=False), sa.Column("reason", sa.String(64), nullable=False), sa.Column("note", sa.Text(), nullable=False, server_default=""), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    _tenant_index("analyst_dispositions", "ix_analyst_dispositions_tenant"); op.create_index("ix_analyst_dispositions_detection", "analyst_dispositions", ["detection_id"]); op.create_index("ix_analyst_dispositions_case", "analyst_dispositions", ["case_id"])
    op.create_table("investigation_entities", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.String(255), nullable=False), sa.Column("correlation_id", sa.String(128), nullable=True), sa.Column("entity_type", sa.String(64), nullable=False), sa.Column("entity_key", sa.String(255), nullable=False), sa.Column("attributes_json", sa.Text(), nullable=False, server_default="{}"), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    _tenant_index("investigation_entities", "ix_investigation_entities_tenant"); op.create_index("ix_investigation_entities_correlation", "investigation_entities", ["correlation_id"])
    op.create_table("investigation_sessions", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.String(255), nullable=False), sa.Column("session_key", sa.String(255), nullable=False), sa.Column("correlation_id", sa.String(128), nullable=True), sa.Column("protocol", sa.String(32), nullable=True), sa.Column("started_at", sa.DateTime(timezone=True), nullable=True), sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True), sa.Column("attributes_json", sa.Text(), nullable=False, server_default="{}"))
    _tenant_index("investigation_sessions", "ix_investigation_sessions_tenant"); op.create_index("ix_investigation_sessions_key", "investigation_sessions", ["session_key"]); op.create_index("ix_investigation_sessions_correlation", "investigation_sessions", ["correlation_id"])
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
            op.execute(f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" USING (tenant_id = current_setting(\'threatfade.tenant_id\', true)) WITH CHECK (tenant_id = current_setting(\'threatfade.tenant_id\', true))')


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in reversed(TABLES):
            op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    for table in reversed(TABLES): op.drop_table(table)
