"""Phase 5 persistent tenant-scoped environment profiles.
Revision ID: 20260825_0005
"""
from alembic import op
import sqlalchemy as sa

revision = "20260825_0005"
down_revision = "20260824_0004"
branch_labels = None
depends_on = None

TABLE = "environment_profiles"

def upgrade() -> None:
    op.create_table(TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("profile_id", sa.String(128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("profile_json", sa.Text(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "profile_id", "version", name="uq_environment_profiles_version"),
    )
    op.create_index("ix_environment_profiles_tenant", TABLE, ["tenant_id"])
    op.create_index("ix_environment_profiles_active", TABLE, ["tenant_id", "profile_id", "status"])
    op.create_table("environment_profile_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("profile_id", sa.String(128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("previous_version", sa.Integer(), nullable=True),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_environment_profile_audit_tenant", "environment_profile_audit", ["tenant_id"])
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in (TABLE, "environment_profile_audit"):
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" USING (tenant_id = current_setting(\'threatfade.tenant_id\', true)) WITH CHECK (tenant_id = current_setting(\'threatfade.tenant_id\', true))')

def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("environment_profile_audit", TABLE):
            op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    op.drop_table("environment_profile_audit")
    op.drop_table(TABLE)
