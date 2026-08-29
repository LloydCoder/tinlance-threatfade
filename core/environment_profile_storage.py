"""SQLAlchemy persistence for tenant-scoped environment profiles.

The domain model remains in :mod:`core.environment_profile`; this module owns
only the durable PostgreSQL representation and tenant-authorized persistence.
The table/constraint/index names intentionally mirror migration 20260825_0005.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from core.environment_profile import EnvironmentProfile, SensitivityThresholds, validate_profile
from core.storage import Base, ENGINE, set_tenant_context


class EnvironmentProfileRecord(Base):
    """Durable representation of a validated :class:`EnvironmentProfile`."""

    __tablename__ = "environment_profiles"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "profile_id",
            "version",
            name="uq_environment_profiles_version",
        ),
        Index("ix_environment_profiles_tenant", "tenant_id"),
        Index("ix_environment_profiles_active", "tenant_id", "profile_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    profile_json: Mapped[str] = mapped_column(Text, nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EnvironmentProfileAuditRecord(Base):
    """Append-only lifecycle audit record for environment profiles."""

    __tablename__ = "environment_profile_audit"
    __table_args__ = (
        Index("ix_environment_profile_audit_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


if ENGINE.dialect.name == "sqlite":
    # SQLite is the local developer/test store. Production PostgreSQL remains
    # migration-owned and therefore never receives ORM create_all DDL.
    Base.metadata.create_all(ENGINE)


def _authorize(tenant_id: str, actor_tenant: str) -> None:
    if not tenant_id or len(tenant_id) > 255:
        raise ValueError("invalid tenant_id")
    if actor_tenant != tenant_id:
        raise PermissionError("tenant mismatch")


def _record_to_domain(row: EnvironmentProfileRecord) -> EnvironmentProfile:
    payload = json.loads(row.profile_json)
    payload["created_at"] = datetime.fromisoformat(payload["created_at"])
    sensitivity = payload.get("sensitivity")
    if isinstance(sensitivity, dict):
        payload["sensitivity"] = SensitivityThresholds(**sensitivity)
    return EnvironmentProfile(**payload)


def put_profile(profile: EnvironmentProfile, *, actor_tenant: str) -> EnvironmentProfile:
    """Persist a new immutable profile version for its owning tenant."""
    _authorize(profile.tenant_id, actor_tenant)
    validate_profile(profile)
    with Session(ENGINE) as session:
        set_tenant_context(session, actor_tenant)
        existing = session.scalar(
            select(EnvironmentProfileRecord).where(
                EnvironmentProfileRecord.tenant_id == actor_tenant,
                EnvironmentProfileRecord.profile_id == profile.profile_id,
                EnvironmentProfileRecord.version == profile.version,
            )
        )
        if existing is not None:
            raise ValueError("profile version already exists")
        latest = session.scalar(
            select(EnvironmentProfileRecord.version)
            .where(
                EnvironmentProfileRecord.tenant_id == actor_tenant,
                EnvironmentProfileRecord.profile_id == profile.profile_id,
            )
            .order_by(EnvironmentProfileRecord.version.desc())
            .limit(1)
        )
        if profile.version != (latest or 0) + 1:
            raise ValueError("profile version must advance monotonically")
        if profile.status == "active":
            active = session.scalar(
                select(EnvironmentProfileRecord.id).where(
                    EnvironmentProfileRecord.tenant_id == actor_tenant,
                    EnvironmentProfileRecord.profile_id == profile.profile_id,
                    EnvironmentProfileRecord.status == "active",
                )
            )
            if active is not None:
                raise ValueError("active profile conflict; activate explicitly")
        row = EnvironmentProfileRecord(
            tenant_id=profile.tenant_id,
            profile_id=profile.profile_id,
            version=profile.version,
            schema_version=profile.schema_version,
            name=profile.name,
            status=profile.status,
            profile_json=json.dumps(profile.canonical_dict(), sort_keys=True, separators=(",", ":")),
            digest=profile.digest(),
            created_by=profile.created_by,
            created_at=profile.created_at.astimezone(timezone.utc),
        )
        session.add(row)
        session.add(
            EnvironmentProfileAuditRecord(
                tenant_id=profile.tenant_id,
                profile_id=profile.profile_id,
                version=profile.version,
                action="create",
                previous_version=None,
                digest=profile.digest(),
                actor=profile.created_by,
                created_at=datetime.now(timezone.utc),
            )
        )
        session.commit()
        return profile


def get_profile(tenant_id: str, profile_id: str, version: int, *, actor_tenant: str) -> EnvironmentProfile | None:
    _authorize(tenant_id, actor_tenant)
    with Session(ENGINE) as session:
        set_tenant_context(session, actor_tenant)
        row = session.scalar(
            select(EnvironmentProfileRecord).where(
                EnvironmentProfileRecord.tenant_id == actor_tenant,
                EnvironmentProfileRecord.profile_id == profile_id,
                EnvironmentProfileRecord.version == version,
            )
        )
        return _record_to_domain(row) if row is not None else None


def active_profile(tenant_id: str, profile_id: str, *, actor_tenant: str) -> EnvironmentProfile | None:
    _authorize(tenant_id, actor_tenant)
    with Session(ENGINE) as session:
        set_tenant_context(session, actor_tenant)
        row = session.scalar(
            select(EnvironmentProfileRecord).where(
                EnvironmentProfileRecord.tenant_id == actor_tenant,
                EnvironmentProfileRecord.profile_id == profile_id,
                EnvironmentProfileRecord.status == "active",
            )
        )
        return _record_to_domain(row) if row is not None else None


def _set_active(
    tenant_id: str,
    profile_id: str,
    version: int,
    *,
    actor_tenant: str,
    action: str,
) -> EnvironmentProfile:
    _authorize(tenant_id, actor_tenant)
    with Session(ENGINE) as session:
        set_tenant_context(session, actor_tenant)
        target = session.scalar(
            select(EnvironmentProfileRecord).where(
                EnvironmentProfileRecord.tenant_id == actor_tenant,
                EnvironmentProfileRecord.profile_id == profile_id,
                EnvironmentProfileRecord.version == version,
            )
        )
        if target is None:
            raise KeyError((tenant_id, profile_id, version))
        if target.status == "retired":
            raise ValueError("profile version cannot be activated")
        previous = session.scalar(
            select(EnvironmentProfileRecord)
            .where(
                EnvironmentProfileRecord.tenant_id == actor_tenant,
                EnvironmentProfileRecord.profile_id == profile_id,
                EnvironmentProfileRecord.status == "active",
            )
        )
        if previous is not None and previous.version == version:
            raise ValueError("profile version is already active")
        if previous is not None:
            previous.status = "draft"
        target.status = "active"
        session.add(
            EnvironmentProfileAuditRecord(
                tenant_id=actor_tenant,
                profile_id=profile_id,
                version=version,
                action=action,
                previous_version=previous.version if previous is not None else None,
                digest=target.digest,
                actor=actor_tenant,
                created_at=datetime.now(timezone.utc),
            )
        )
        session.commit()
        session.refresh(target)
        return _record_to_domain(target)


def activate_profile(tenant_id: str, profile_id: str, version: int, *, actor_tenant: str) -> EnvironmentProfile:
    return _set_active(tenant_id, profile_id, version, actor_tenant=actor_tenant, action="activate")


def rollback_profile(tenant_id: str, profile_id: str, version: int, *, actor_tenant: str) -> EnvironmentProfile:
    return _set_active(tenant_id, profile_id, version, actor_tenant=actor_tenant, action="rollback")


def audit_profiles(tenant_id: str, *, actor_tenant: str) -> list[EnvironmentProfileAuditRecord]:
    _authorize(tenant_id, actor_tenant)
    with Session(ENGINE) as session:
        set_tenant_context(session, actor_tenant)
        return list(
            session.scalars(
                select(EnvironmentProfileAuditRecord)
                .where(EnvironmentProfileAuditRecord.tenant_id == actor_tenant)
                .order_by(EnvironmentProfileAuditRecord.id.asc())
            )
        )
