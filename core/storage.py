"""Durable multi-tenant persistence for enterprise deployments.

PostgreSQL production deployments use Alembic migrations and database-enforced
row-level security. SQLite remains the intentionally permissive local developer
store. Tenant-aware application functions still filter explicitly even when RLS
is enabled.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import BigInteger, DateTime, Float, Integer, String, Text, create_engine, event, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

DATABASE_URL = os.getenv("THREATFADE_DATABASE_URL", "sqlite:///./threatfade.db")
_ENGINE_KWARGS = {"pool_pre_ping": True, "future": True}
if DATABASE_URL.startswith("postgresql"):
    _ENGINE_KWARGS.update(pool_recycle=1800, pool_size=int(os.getenv("THREATFADE_DB_POOL_SIZE", "10")), max_overflow=int(os.getenv("THREATFADE_DB_MAX_OVERFLOW", "20")))
else:
    _ENGINE_KWARGS["connect_args"] = {"check_same_thread": False}
ENGINE = create_engine(DATABASE_URL, **_ENGINE_KWARGS)


class Base(DeclarativeBase):
    pass


class DetectionRecord(Base):
    __tablename__ = "detections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    detected: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    mitre_ttp: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    input_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_pack_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    engine_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    config_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaseRecord(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class DetectionFeedbackRecord(Base):
    __tablename__ = "detection_feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    detection_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class CaseCommentRecord(Base):
    __tablename__ = "case_comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    case_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class CaseEventRecord(Base):
    __tablename__ = "case_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    case_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class TenantConfigRecord(Base):
    __tablename__ = "tenant_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    value_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class AuditEventRecord(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sequence_no: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    object_type: Mapped[str] = mapped_column(String(128), nullable=False)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    request_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    before_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    after_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceRecord(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    case_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    evidence_type: Mapped[str] = mapped_column(String(128), nullable=False)
    media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    source_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    custody_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ProvenanceRecord(Base):
    __tablename__ = "provenance"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    detection_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_pack_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    provenance_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TimelineEventRecord(Base):
    __tablename__ = "investigation_timeline"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    case_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RetentionPolicyRecord(Base):
    __tablename__ = "retention_policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LegalHoldRecord(Base):
    __tablename__ = "legal_holds"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    hold_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


if DATABASE_URL.startswith("sqlite"):
    Base.metadata.create_all(ENGINE)


def _validate_tenant_id(tenant_id: str) -> str:
    if not tenant_id or len(tenant_id) > 255:
        raise ValueError("invalid tenant_id")
    return tenant_id


def _apply_tenant_context(session: Session, connection) -> None:
    """Apply the session's tenant context to the current PostgreSQL transaction."""
    tenant_id = session.info.get("tenant_id")
    if not tenant_id or connection.dialect.name != "postgresql":
        return

    connection.execute(
        text("SELECT set_config('threatfade.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )


@event.listens_for(Session, "after_begin")
def _set_rls_tenant_context(session: Session, transaction, connection) -> None:
    """Set transaction-local RLS context whenever a tenant-bound transaction begins."""
    _apply_tenant_context(session, connection)


def set_tenant_context(session: Session, tenant_id: str) -> None:
    """Bind a SQLAlchemy session to a PostgreSQL transaction-local tenant context."""
    tenant_id = _validate_tenant_id(tenant_id)
    session.info["tenant_id"] = tenant_id

    # Establish the context immediately if this session already has a transaction.
    if session.in_transaction() and ENGINE.dialect.name == "postgresql":
        connection = session.connection()
        _apply_tenant_context(session, connection)


def tenant_session(tenant_id: str) -> Session:
    """Create a tenant-bound SQLAlchemy session."""
    tenant_id = _validate_tenant_id(tenant_id)
    session = Session(ENGINE, expire_on_commit=False)
    session.info["tenant_id"] = tenant_id
    return session


def save_detection(tenant_id: str, subject: str, source: str, result: Dict[str, Any], mitre_ttp: str, *, correlation_id: str | None = None, input_sha256: str | None = None, rule_pack_sha256: str | None = None, engine_version: str | None = None, model_sha256: str | None = None, config_sha256: str | None = None) -> int:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        record = DetectionRecord(
            tenant_id=tenant_id, subject=subject, source=source,
            detected=int(bool(result.get("detected"))), confidence=str(result.get("confidence", "info")), score=float(result.get("score", 0.0)), mitre_ttp=mitre_ttp,
            evidence_json=json.dumps(result.get("evidence", {}), sort_keys=True), correlation_id=correlation_id,
            input_sha256=input_sha256, rule_pack_sha256=rule_pack_sha256, engine_version=engine_version, model_sha256=model_sha256, config_sha256=config_sha256,
            created_at=datetime.now(timezone.utc),
        )
        session.add(record); session.commit(); session.refresh(record)
        return record.id


def list_detections(tenant_id: str, limit: int = 100) -> List[DetectionRecord]:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        return list(session.scalars(select(DetectionRecord).where(DetectionRecord.tenant_id == tenant_id).order_by(DetectionRecord.id.desc()).limit(limit)))
