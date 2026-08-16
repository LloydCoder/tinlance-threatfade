"""Durable multi-tenant persistence for enterprise deployments.

SQLite is suitable for single-node development. Production should use PostgreSQL
via THREATFADE_DATABASE_URL. Tenant IDs are part of every persisted record and
are checked before reads/writes.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import DateTime, Float, Integer, String, Text, create_engine, select
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class TenantConfigRecord(Base):
    __tablename__ = "tenant_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    value_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(ENGINE)


def save_detection(tenant_id: str, subject: str, source: str, result: Dict[str, Any], mitre_ttp: str) -> int:
    import json
    with Session(ENGINE) as session:
        record = DetectionRecord(
            tenant_id=tenant_id, subject=subject, source=source,
            detected=int(bool(result.get("detected"))), confidence=str(result.get("confidence", "info")),
            score=float(result.get("score", 0.0)), mitre_ttp=mitre_ttp,
            evidence_json=json.dumps(result.get("evidence", {}), sort_keys=True),
            created_at=datetime.now(timezone.utc),
        )
        session.add(record); session.commit(); session.refresh(record)
        return record.id


def list_detections(tenant_id: str, limit: int = 100) -> List[DetectionRecord]:
    with Session(ENGINE) as session:
        return list(session.scalars(select(DetectionRecord).where(DetectionRecord.tenant_id == tenant_id).order_by(DetectionRecord.id.desc()).limit(limit)))
