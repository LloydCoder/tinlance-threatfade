"""Authenticated identity, organization and RBAC API."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from core.api_security import enforce_rate_limit
from core.enterprise import AUDIT, authenticate, require_tenant
from core.identity import (
    accept_invitation,
    change_member_role,
    create_organization,
    ensure_user,
    invite_member,
    list_members,
    list_sessions,
    organizations_for,
    register_session,
    remove_member,
    revoke_all_sessions,
    revoke_invitation,
    revoke_session,
    switch_session_organization,
)

router = APIRouter(prefix="/enterprise/identity", tags=["identity"])


def _principal(request: Request):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    principal = authenticate(request)
    return principal


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    slug: Optional[str] = Field(default=None, max_length=63)


class InvitationCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    role: str = Field(default="analyst", pattern="^(admin|analyst|viewer)$")


class MemberRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst|viewer)$")


class SessionCreate(BaseModel):
    organization_id: Optional[str] = Field(default=None, max_length=32)


class SessionSwitch(BaseModel):
    organization_id: str = Field(..., min_length=32, max_length=32)


class InvitationAccept(BaseModel):
    token: str = Field(..., min_length=20, max_length=256)
    email: Optional[str] = Field(default=None, max_length=320)


@router.get("/me")
def me(request: Request):
    principal = _principal(request)
    user = ensure_user(principal.subject, principal.claims.get("email"), principal.claims.get("name") or principal.claims.get("preferred_username"))
    return {"subject": user.subject, "email": user.email, "name": user.name, "disabled": bool(user.disabled)}


@router.get("/organizations")
def organizations(request: Request):
    principal = _principal(request)
    return {"items": [{"id": org.id, "name": org.name, "slug": org.slug, "role": role, "created_at": org.created_at.isoformat()} for org, role in organizations_for(principal.subject)]}


@router.post("/organizations")
def organization_create(payload: OrganizationCreate, request: Request):
    principal = _principal(request)
    try:
        org = create_organization(principal.subject, payload.name, payload.slug)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    AUDIT.record("organization.created", principal, request, {"organization_id": org.id})
    return {"id": org.id, "name": org.name, "slug": org.slug, "role": "owner", "created_at": org.created_at.isoformat()}


@router.get("/organizations/{organization_id}/members")
def members(organization_id: str, request: Request):
    principal = _principal(request)
    try:
        return {"items": list_members(principal.subject, organization_id)}
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc


@router.post("/organizations/{organization_id}/invitations")
def invitation_create(organization_id: str, payload: InvitationCreate, request: Request):
    principal = _principal(request)
    try:
        token = invite_member(principal.subject, organization_id, payload.email, payload.role)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    AUDIT.record("organization.invitation.created", principal, request, {"organization_id": organization_id, "role": payload.role})
    return {"token": token, "expires_in": 604800}


@router.post("/invitations/accept")
def invitation_accept(payload: InvitationAccept, request: Request):
    principal = _principal(request)
    email = payload.email or principal.claims.get("email")
    try:
        organization_id = accept_invitation(principal.subject, payload.token, email)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    AUDIT.record("organization.invitation.accepted", principal, request, {"organization_id": organization_id})
    return {"organization_id": organization_id, "accepted": True}


@router.patch("/organizations/{organization_id}/members/{subject}")
def member_role(organization_id: str, subject: str, payload: MemberRoleUpdate, request: Request):
    principal = _principal(request)
    try:
        change_member_role(principal.subject, organization_id, subject, payload.role)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    AUDIT.record("organization.member.role_changed", principal, request, {"organization_id": organization_id, "subject": subject, "role": payload.role})
    return {"subject": subject, "role": payload.role}


@router.delete("/organizations/{organization_id}/members/{subject}")
def member_remove(organization_id: str, subject: str, request: Request):
    principal = _principal(request)
    try:
        remove_member(principal.subject, organization_id, subject)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    AUDIT.record("organization.member.removed", principal, request, {"organization_id": organization_id, "subject": subject})
    return {"removed": True}


@router.post("/organizations/{organization_id}/invitations/{invitation_id}/revoke")
def invitation_revoke(organization_id: str, invitation_id: int, request: Request):
    principal = _principal(request)
    try:
        revoke_invitation(principal.subject, organization_id, invitation_id)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"revoked": True}


@router.post("/sessions")
def session_create(payload: SessionCreate, request: Request):
    principal = _principal(request)
    if payload.organization_id:
        try:
            require_tenant(principal, payload.organization_id)
        except HTTPException:
            raise
    token = register_session(
        principal.subject,
        payload.organization_id,
        request.headers.get("user-agent"),
        request.client.host if request.client else None,
    )
    AUDIT.record("auth.session.created", principal, request, {"organization_id": payload.organization_id})
    return {"session_token": token, "expires_in": 28800}


@router.get("/sessions")
def sessions(request: Request):
    principal = _principal(request)
    return {"items": list_sessions(principal.subject)}


@router.post("/sessions/revoke")
def session_revoke(request: Request, x_threatfade_session: Optional[str] = Header(default=None)):
    principal = _principal(request)
    if not x_threatfade_session:
        raise HTTPException(400, "Session identifier required")
    revoke_session(principal.subject, x_threatfade_session)
    return {"revoked": True}


@router.post("/sessions/revoke-all")
def sessions_revoke_all(request: Request):
    principal = _principal(request)
    revoke_all_sessions(principal.subject)
    AUDIT.record("auth.session.revoke_all", principal, request)
    return {"revoked": True}


@router.post("/sessions/switch")
def session_switch(payload: SessionSwitch, request: Request, x_threatfade_session: Optional[str] = Header(default=None)):
    principal = _principal(request)
    if not x_threatfade_session:
        raise HTTPException(400, "Session identifier required")
    try:
        switch_session_organization(principal.subject, x_threatfade_session, payload.organization_id)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    return {"organization_id": payload.organization_id}
