from __future__ import annotations
from datetime import datetime, timezone
import pytest
from fastapi import HTTPException
from core.enterprise import Principal, require_tenant
from core.identity import create_organization, ensure_user, invite_member, membership, accept_invitation, register_session, validate_session, revoke_session, revoke_all_sessions, change_member_role, list_members

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

def test_resource_tenant_authorization_denies_guessed_cross_tenant_id():
    user = ensure_user("resource-boundary-phase13", "resource@example.test")
    owner = ensure_user("resource-owner-phase13", "resource-owner@example.test")
    other = ensure_user("resource-other-phase13", "resource-other@example.test")
    org_a = create_organization(owner.subject, "Resource Alpha", "resource-alpha-phase13")
    org_b = create_organization(other.subject, "Resource Beta", "resource-beta-phase13")
    invitation = invite_member(owner.subject, org_a.id, user.email, "viewer")
    assert accept_invitation(user.subject, invitation, user.email) == org_a.id
    principal = Principal(user.subject, org_a.id, {"viewer"})
    assert require_tenant(principal, org_a.id) == org_a.id
    with pytest.raises(HTTPException) as exc: require_tenant(principal, org_b.id)
    assert exc.value.status_code == 403

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


def test_revoke_all_sessions_invalidates_existing_session_by_version():
    user = ensure_user("session-version-phase13", "session-version@example.test")
    session_token = register_session(user.subject, None, "pytest", "127.0.0.1")

    assert validate_session(session_token, user.subject) is not None

    revoke_all_sessions(user.subject)

    assert validate_session(session_token, user.subject) is None


def test_new_session_uses_current_session_version_after_global_revoke():
    user = ensure_user("session-version-new-phase13", "session-version-new@example.test")
    old_token = register_session(user.subject, None, "pytest", "127.0.0.1")

    revoke_all_sessions(user.subject)

    new_token = register_session(user.subject, None, "pytest", "127.0.0.1")

    assert old_token != new_token
    assert validate_session(old_token, user.subject) is None
    assert validate_session(new_token, user.subject) is not None


def test_invitation_acceptance_locks_invitation_row():
    owner = ensure_user("invite-lock-owner-phase13", "invite-lock-owner@example.test")
    invited = ensure_user("invite-lock-user-phase13", "invite-lock-user@example.test")
    org = create_organization(
        owner.subject,
        "Invitation Lock Security",
        "invitation-lock-phase13",
    )

    token = invite_member(owner.subject, org.id, invited.email, "viewer")

    assert accept_invitation(invited.subject, token, invited.email) == org.id

    with pytest.raises(ValueError):
        accept_invitation(invited.subject, token, invited.email)
