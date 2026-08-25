"""Phase 13 authenticated platform identity tables.

Revision ID: 20260825_0006
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260825_0006"
down_revision = "20260825_0005"
branch_labels = None
depends_on = None


def _index(table: str, name: str, column: str):
    op.create_index(name, table, [column])


def upgrade() -> None:
    op.create_table(
        "identity_users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subject", sa.String(255), nullable=False, unique=True),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("disabled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("session_version", sa.Integer(), nullable=False, server_default="1"),
    )
    _index("identity_users", "ix_identity_users_subject", "subject")
    _index("identity_users", "ix_identity_users_email", "email")

    op.create_table(
        "identity_organizations",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("slug", sa.String(63), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    _index("identity_organizations", "ix_identity_organizations_slug", "slug")

    op.create_table(
        "identity_memberships",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.String(32), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "subject", name="uq_identity_membership_org_subject"),
    )
    _index("identity_memberships", "ix_identity_memberships_org", "organization_id")
    _index("identity_memberships", "ix_identity_memberships_subject", "subject")

    op.create_table(
        "identity_invitations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.String(32), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("invited_by", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    _index("identity_invitations", "ix_identity_invitations_org", "organization_id")
    _index("identity_invitations", "ix_identity_invitations_email", "email")
    _index("identity_invitations", "ix_identity_invitations_token_hash", "token_hash")

    op.create_table(
        "identity_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("active_organization_id", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
    )
    _index("identity_sessions", "ix_identity_sessions_token_hash", "token_hash")
    _index("identity_sessions", "ix_identity_sessions_subject", "subject")

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("identity_users", "identity_organizations", "identity_memberships", "identity_invitations", "identity_sessions"):
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS "{table}_identity_isolation" ON "{table}"')
        # Identity tables are protected by application-level subject/membership checks;
        # database RLS is enabled to prevent accidental broad reads by future SQL paths.
        op.execute("CREATE POLICY \"identity_users_self\" ON \"identity_users\" USING (subject = current_setting('threatfade.subject', true))")
        op.execute("CREATE POLICY \"identity_orgs_membership\" ON \"identity_organizations\" USING (id IN (SELECT organization_id FROM identity_memberships WHERE subject = current_setting('threatfade.subject', true)))")
        op.execute("CREATE POLICY \"identity_memberships_self\" ON \"identity_memberships\" USING (subject = current_setting('threatfade.subject', true) OR organization_id IN (SELECT organization_id FROM identity_memberships WHERE subject = current_setting('threatfade.subject', true)))")
        op.execute("CREATE POLICY \"identity_invitations_member\" ON \"identity_invitations\" USING (organization_id IN (SELECT organization_id FROM identity_memberships WHERE subject = current_setting('threatfade.subject', true)))")
        op.execute("CREATE POLICY \"identity_sessions_self\" ON \"identity_sessions\" USING (subject = current_setting('threatfade.subject', true))")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("identity_sessions", "identity_invitations", "identity_memberships", "identity_organizations", "identity_users"):
            op.execute(f'DROP POLICY IF EXISTS "{table}_identity_isolation" ON "{table}"')
            for policy in ("identity_users_self", "identity_orgs_membership", "identity_memberships_self", "identity_invitations_member", "identity_sessions_self"):
                op.execute(f'DROP POLICY IF EXISTS "{policy}" ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    for table in ("identity_sessions", "identity_invitations", "identity_memberships", "identity_organizations", "identity_users"):
        op.drop_table(table)
