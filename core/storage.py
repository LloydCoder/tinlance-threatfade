"""Durable multi-tenant persistence for enterprise deployments.

SQLite is suitable for single-node development. Production should use PostgreSQL
via THREATFADE_DATABASE_URL. Tenant IDs are part of every persisted record and
are checked before reads/writes.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Float, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


DATABASE_URL = os.getenv("THREATFADE_DATABASE_URL", "sqlite:///./threatfade.db")
ENGINE = create_engine(DATABASE_URL, pool_pre_ping=True, future=True, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


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
