"""Durable customer identity, organization membership, invitations and sessions."""
from __future__ import annotations
import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import DateTime, Integer, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column
from core.storage import Base, ENGINE
ORG_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ROLES = {"owner", "admin", "analyst", "viewer"}
ROLE_PERMISSIONS = {"owner": {"*"}, "admin": {"detection:read", "detection:run", "case:read", "case:write", "org:read", "org:write", "member:write", "session:read", "session:write"}, "analyst": {"detection:read", "detection:run", "case:read", "case:write", "session:read"}, "viewer": {"detection:read", "case:read", "session:read"}}
class UserRecord(Base):
    __tablename__ = "identity_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True); subject: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False); email: Mapped[str | None] = mapped_column(String(320), index=True, nullable=True); name: Mapped[str | None] = mapped_column(String(255), nullable=True); disabled: Mapped[int] = mapped_column(Integer, nullable=False, default=0); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False); last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False); session_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
class OrganizationRecord(Base):
    __tablename__ = "identity_organizations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True); slug: Mapped[str] = mapped_column(String(63), unique=True, index=True, nullable=False); name: Mapped[str] = mapped_column(String(120), nullable=False); created_by: Mapped[str] = mapped_column(String(255), nullable=False); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
class MembershipRecord(Base):
    __tablename__ = "identity_memberships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True); organization_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False); subject: Mapped[str] = mapped_column(String(255), index=True, nullable=False); role: Mapped[str] = mapped_column(String(16), nullable=False); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False); __table_args__ = (UniqueConstraint("organization_id", "subject", name="uq_identity_membership_org_subject"),)
class InvitationRecord(Base):
    __tablename__ = "identity_invitations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True); organization_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False); email: Mapped[str] = mapped_column(String(320), index=True, nullable=False); role: Mapped[str] = mapped_column(String(16), nullable=False); token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False); invited_by: Mapped[str] = mapped_column(String(255), nullable=False); expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False); accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True); revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
class AuthSessionRecord(Base):
    __tablename__ = "identity_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True); token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False); subject: Mapped[str] = mapped_column(String(255), index=True, nullable=False); active_organization_id: Mapped[str | None] = mapped_column(String(32), nullable=True); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False); last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False); expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False); revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True); user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True); source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
if ENGINE.dialect.name == "sqlite": Base.metadata.create_all(ENGINE)
def _now() -> datetime: return datetime.now(timezone.utc)
def _utc(value: datetime | None) -> datetime | None:
    if value is None: return None
    if value.tzinfo is None: return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
def _hash(value: str) -> str: return hashlib.sha256(value.encode("utf-8")).hexdigest()
def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not SLUG_RE.fullmatch(slug): raise ValueError("invalid organization slug")
    return slug
def ensure_user(subject: str, email: str | None = None, name: str | None = None) -> UserRecord:
    now = _now()
    with Session(ENGINE) as session:
        user = session.scalar(select(UserRecord).where(UserRecord.subject == subject))
        if user is None: user = UserRecord(subject=subject, email=email, name=name, created_at=now, last_seen_at=now); session.add(user)
        else:
            if email is not None: user.email = email
            if name is not None: user.name = name
            user.last_seen_at = now
        session.commit(); session.refresh(user); return user
def get_user(subject: str) -> UserRecord | None:
    with Session(ENGINE) as session: return session.scalar(select(UserRecord).where(UserRecord.subject == subject))
def create_organization(subject: str, name: str, slug: str | None = None) -> OrganizationRecord:
    name = name.strip()
    if not 2 <= len(name) <= 120: raise ValueError("organization name must be 2..120 characters")
    normalized = normalize_slug(slug or name)
    with Session(ENGINE) as session:
        if session.scalar(select(OrganizationRecord).where(OrganizationRecord.slug == normalized)): raise ValueError("organization slug is already in use")
        org = OrganizationRecord(id=uuid.uuid4().hex, slug=normalized, name=name, created_by=subject, created_at=_now()); session.add(org); session.add(MembershipRecord(organization_id=org.id, subject=subject, role="owner", created_at=_now())); session.commit(); session.refresh(org); return org
def organizations_for(subject: str) -> list[tuple[OrganizationRecord, str]]:
    with Session(ENGINE) as session: return list(session.execute(select(OrganizationRecord, MembershipRecord.role).join(MembershipRecord, MembershipRecord.organization_id == OrganizationRecord.id).where(MembershipRecord.subject == subject).order_by(OrganizationRecord.created_at.asc())))
def membership(subject: str, organization_id: str) -> MembershipRecord | None:
    if not ORG_ID_RE.fullmatch(organization_id): return None
    with Session(ENGINE) as session: return session.scalar(select(MembershipRecord).where(MembershipRecord.organization_id == organization_id, MembershipRecord.subject == subject))
def require_permission(subject: str, organization_id: str, permission: str) -> MembershipRecord:
    row = membership(subject, organization_id)
    if row is None or permission not in ROLE_PERMISSIONS.get(row.role, set()) and "*" not in ROLE_PERMISSIONS.get(row.role, set()): raise PermissionError("insufficient organization permissions")
    return row
def list_members(subject: str, organization_id: str) -> list[dict[str, object]]:
    require_permission(subject, organization_id, "org:read")
    with Session(ENGINE) as session:
        rows = session.execute(select(MembershipRecord, UserRecord).join(UserRecord, UserRecord.subject == MembershipRecord.subject).where(MembershipRecord.organization_id == organization_id).order_by(MembershipRecord.created_at.asc()))
        return [{"subject": member.subject, "email": user.email, "name": user.name, "role": member.role, "created_at": member.created_at.isoformat()} for member, user in rows]
def invite_member(subject: str, organization_id: str, email: str, role: str) -> str:
    actor = require_permission(subject, organization_id, "member:write")
    normalized_email = email.strip().lower()
    if "@" not in normalized_email or len(normalized_email) > 320: raise ValueError("invalid invitation email")
    if role not in {"admin", "analyst", "viewer"}: raise ValueError("invalid invitation role")
    if actor.role == "admin" and role == "admin": raise PermissionError("only the organization owner can invite an admin")
    token = secrets.token_urlsafe(32); now = _now()
    with Session(ENGINE) as session:
        existing = session.scalar(select(InvitationRecord).where(InvitationRecord.organization_id == organization_id, InvitationRecord.email == normalized_email, InvitationRecord.accepted_at.is_(None), InvitationRecord.revoked_at.is_(None)))
        if existing: existing.revoked_at = now
        session.add(InvitationRecord(organization_id=organization_id, email=normalized_email, role=role, token_hash=_hash(token), invited_by=subject, expires_at=now + timedelta(days=7), created_at=now)); session.commit()
    return token
def accept_invitation(subject: str, token: str, email: str | None) -> str:
    if not token or len(token) > 256: raise ValueError("invalid invitation")
    with Session(ENGINE) as session:
        invitation = session.scalar(select(InvitationRecord).where(InvitationRecord.token_hash == _hash(token))); now = _now(); expires_at = _utc(invitation.expires_at) if invitation is not None else None
        if invitation is None or invitation.accepted_at or invitation.revoked_at or expires_at is None or expires_at <= now: raise ValueError("invalid or expired invitation")
        if not email or email.strip().lower() != invitation.email: raise PermissionError("invitation email does not match authenticated account")
        existing = session.scalar(select(MembershipRecord).where(MembershipRecord.organization_id == invitation.organization_id, MembershipRecord.subject == subject))
        if existing: existing.role = invitation.role
        else: session.add(MembershipRecord(organization_id=invitation.organization_id, subject=subject, role=invitation.role, created_at=now))
        invitation.accepted_at = now; session.commit(); return invitation.organization_id
def revoke_invitation(subject: str, organization_id: str, invitation_id: int) -> None:
    require_permission(subject, organization_id, "member:write")
    with Session(ENGINE) as session:
        invitation = session.scalar(select(InvitationRecord).where(InvitationRecord.id == invitation_id, InvitationRecord.organization_id == organization_id))
        if invitation is None: raise ValueError("invitation not found")
        invitation.revoked_at = _now(); session.commit()
def change_member_role(actor: str, organization_id: str, target_subject: str, role: str) -> None:
    actor_member = require_permission(actor, organization_id, "member:write")
    if role not in ROLES - {"owner"}: raise ValueError("invalid member role")
    with Session(ENGINE) as session:
        target = session.scalar(select(MembershipRecord).where(MembershipRecord.organization_id == organization_id, MembershipRecord.subject == target_subject))
        if target is None: raise ValueError("member not found")
        if target.role == "owner": raise PermissionError("organization owner role cannot be reassigned")
        if actor_member.role == "admin" and target.role == "admin": raise PermissionError("only the organization owner can modify an admin")
        if actor_member.role == "admin" and role == "admin": raise PermissionError("only the organization owner can grant admin")
        target.role = role; session.commit()
def remove_member(actor: str, organization_id: str, target_subject: str) -> None:
    actor_member = require_permission(actor, organization_id, "member:write")
    with Session(ENGINE) as session:
        target = session.scalar(select(MembershipRecord).where(MembershipRecord.organization_id == organization_id, MembershipRecord.subject == target_subject))
        if target is None: raise ValueError("member not found")
        if target.role == "owner": raise PermissionError("organization owner cannot be removed")
        if actor_member.role == "admin" and target.role == "admin": raise PermissionError("only the organization owner can remove an admin")
        session.delete(target); session.commit()
def register_session(subject: str, active_organization_id: str | None, user_agent: str | None, source_ip: str | None, ttl_seconds: int = 28800) -> str:
    ttl_seconds = max(900, min(ttl_seconds, 43200)); user = ensure_user(subject)
    if user.disabled: raise PermissionError("account is disabled")
    if active_organization_id and membership(subject, active_organization_id) is None: raise PermissionError("organization access denied")
    token = secrets.token_urlsafe(32); now = _now()
    with Session(ENGINE) as session: session.add(AuthSessionRecord(token_hash=_hash(token), subject=subject, active_organization_id=active_organization_id, created_at=now, last_seen_at=now, expires_at=now + timedelta(seconds=ttl_seconds), user_agent=(user_agent or "")[:512] or None, source_ip=(source_ip or "")[:64] or None)); session.commit()
    return token
def validate_session(token: str, subject: str) -> AuthSessionRecord | None:
    if not token or len(token) > 256: return None
    with Session(ENGINE) as session:
        row = session.scalar(select(AuthSessionRecord).where(AuthSessionRecord.token_hash == _hash(token), AuthSessionRecord.subject == subject)); now = _now(); user = session.scalar(select(UserRecord).where(UserRecord.subject == subject)); expires_at = _utc(row.expires_at) if row is not None else None
        if row is None or row.revoked_at is not None or expires_at is None or expires_at <= now or user is None or user.disabled: return None
        row.last_seen_at = now; session.commit(); session.refresh(row); return row
def list_sessions(subject: str) -> list[dict[str, object]]:
    with Session(ENGINE) as session:
        now = _now(); rows = session.scalars(select(AuthSessionRecord).where(AuthSessionRecord.subject == subject, AuthSessionRecord.revoked_at.is_(None), AuthSessionRecord.expires_at > now).order_by(AuthSessionRecord.last_seen_at.desc()))
        return [{"id": row.id, "organization_id": row.active_organization_id, "created_at": row.created_at.isoformat(), "last_seen_at": row.last_seen_at.isoformat(), "expires_at": row.expires_at.isoformat(), "user_agent": row.user_agent, "source_ip": row.source_ip} for row in rows]
def revoke_session(subject: str, token: str) -> None:
    with Session(ENGINE) as session:
        row = session.scalar(select(AuthSessionRecord).where(AuthSessionRecord.token_hash == _hash(token), AuthSessionRecord.subject == subject))
        if row: row.revoked_at = _now(); session.commit()
def revoke_all_sessions(subject: str) -> None:
    with Session(ENGINE) as session:
        now = _now(); user = session.scalar(select(UserRecord).where(UserRecord.subject == subject))
        if user: user.session_version += 1
        for row in session.scalars(select(AuthSessionRecord).where(AuthSessionRecord.subject == subject, AuthSessionRecord.revoked_at.is_(None))): row.revoked_at = now
        session.commit()
def switch_session_organization(subject: str, token: str, organization_id: str) -> None:
    require_permission(subject, organization_id, "org:read")
    with Session(ENGINE) as session:
        row = session.scalar(select(AuthSessionRecord).where(AuthSessionRecord.token_hash == _hash(token), AuthSessionRecord.subject == subject)); expires_at = _utc(row.expires_at) if row is not None else None
        if row is None or row.revoked_at is not None or expires_at is None or expires_at <= _now(): raise PermissionError("invalid session")
        row.active_organization_id = organization_id; row.last_seen_at = _now(); session.commit()
