"""Enterprise integrity baseline.

Revision ID: 20260822_0001
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import inspect

from core.storage import Base

revision = "20260822_0001"
down_revision = None
branch_labels = None
depends_on = None

RLS_TABLES = (
    "detections", "cases", "detection_feedback", "case_comments", "case_events",
    "tenant_config", "audit_events", "evidence", "provenance", "investigation_timeline",
    "retention_policies", "legal_holds",
)


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    if bind.dialect.name != "postgresql":
        return
    for table in RLS_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
        op.execute(
            f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
            "USING (tenant_id = current_setting('threatfade.tenant_id', true)) "
            "WITH CHECK (tenant_id = current_setting('threatfade.tenant_id', true))"
        )
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_sequence ON audit_events (tenant_id, sequence_no)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_evidence_tenant_correlation ON evidence (tenant_id, correlation_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_provenance_tenant_correlation ON provenance (tenant_id, correlation_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_timeline_tenant_case ON investigation_timeline (tenant_id, case_id, created_at)")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in reversed(RLS_TABLES):
            op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    inspector = inspect(bind)
    for table in reversed(list(Base.metadata.tables)):
        if table in inspector.get_table_names():
            Base.metadata.tables[table].drop(bind=bind)
