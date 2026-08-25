from __future__ import annotations
from datetime import datetime, timezone
import pytest
from core.identity import create_organization, ensure_user, invite_member, membership, accept_invitation, register_session, validate_session, revoke_session, change_member_role, list_members

def test_owner_admin_analyst_viewer_rbac_and_cross_tenant_isolation():
    owner = ensure_user("owner-phase13", "owner@example.test", "Owner")
    analyst = ensure_user("analyst-phase13", "analyst@example.test", "Analyst")
    other = ensure_user("other-phase13", "other@example.test", "Other")
    org_a = create_organization(owner.subject, "Alpha Security", "alpha-phase13")
    org_b = create_organization(other.subject, "Beta Security", "beta-phase13")
    token = invite_member(owner.subject, org_a.id, analyst.email, "analyst")
    assert accept_invitation(analyst.subject, token, analyst.email) == org_a.id
    assert membership(analyst.subject, org_a.id).role == "analyst"
    assert membership(analyst.subject, org_b.id) is None
    with pytest.raises(PermissionError): change_member_role(analyst.subject, org_b.id, other.subject, "viewer")
    assert {member["role"] for member in list_members(owner.subject, org_a.id)} == {"owner", "analyst"}

def test_admin_cannot_grant_or_invite_admin():
    owner = ensure_user("owner-admin-phase13", "owner-admin@example.test")
    admin = ensure_user("admin-phase13", "admin@example.test")
    target = ensure_user("target-admin-phase13", "target-admin@example.test")
    org = create_organization(owner.subject, "Admin Boundary", "admin-boundary-phase13")
    admin_invite = invite_member(owner.subject, org.id, admin.email, "admin")
    assert accept_invitation(admin.subject, admin_invite, admin.email) == org.id
    target_invite = invite_member(owner.subject, org.id, target.email, "viewer")
    assert accept_invitation(target.subject, target_invite, target.email) == org.id
    with pytest.raises(PermissionError): change_member_role(admin.subject, org.id, target.subject, "admin")
    with pytest.raises(PermissionError): invite_member(admin.subject, org.id, "another@example.test", "admin")

def test_invitation_is_single_use_and_email_bound():
    owner = ensure_user("invite-owner-phase13", "owner2@example.test")
    invited = ensure_user("invite-user-phase13", "user2@example.test")
    org = create_organization(owner.subject, "Invitation Security", "invitation-phase13")
    token = invite_member(owner.subject, org.id, invited.email, "viewer")
    assert accept_invitation(invited.subject, token, invited.email) == org.id
    with pytest.raises(ValueError): accept_invitation(invited.subject, token, invited.email)
    token2 = invite_member(owner.subject, org.id, "different@example.test", "viewer")
    with pytest.raises(PermissionError): accept_invitation(invited.subject, token2, invited.email)

def test_server_side_session_revocation():
    user = ensure_user("session-phase13", "session@example.test")
    session_token = register_session(user.subject, None, "pytest", "127.0.0.1")
    assert validate_session(session_token, user.subject) is not None
    revoke_session(user.subject, session_token)
    assert validate_session(session_token, user.subject) is None

def test_session_expiry_is_enforced():
    user = ensure_user("expiry-phase13", "expiry@example.test")
    session_token = register_session(user.subject, None, "pytest", "127.0.0.1")
    row = validate_session(session_token, user.subject)
    assert row is not None
    assert row.expires_at > datetime.now(timezone.utc)
