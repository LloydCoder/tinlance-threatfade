"""Tenant-scoped SOC analyst workflow primitives.

The analyst layer deliberately sits above the canonical detection/evidence data
plane. It owns workflow state (triage, assignment, disposition and case links)
and never changes detection evidence or tenant identity.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Integer, String, Text, DateTime, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from core.storage import Base, ENGINE, DetectionRecord, EvidenceRecord, CaseRecord, CaseEventRecord


class DetectionWorkflowRecord(Base):
    __tablename__ = "detection_workflow"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    detection_id: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="new")
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaseDetectionLinkRecord(Base):
    __tablename__ = "case_detection_links"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    case_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    detection_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AnalystDispositionRecord(Base):
    __tablename__ = "analyst_dispositions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    detection_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    case_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    analyst: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EntityRecord(Base):
    __tablename__ = "investigation_entities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_key: Mapped[str] = mapped_column(String(255), nullable=False)
    attributes_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SessionRecord(Base):
    __tablename__ = "investigation_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    session_key: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attributes_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


if ENGINE.dialect.name == "sqlite":
    Base.metadata.create_all(ENGINE)

WORKFLOW_STATUSES = {"new", "triaging", "investigating", "contained", "resolved", "closed"}
DISPOSITION_REASONS = {"true_positive", "false_positive", "benign", "duplicate", "insufficient_evidence", "needs_tuning"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def detection(tenant_id: str, detection_id: int) -> DetectionRecord | None:
    with Session(ENGINE) as s:
        return s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))


def inbox(tenant_id: str, *, limit: int = 100, status: str | None = None, assignee: str | None = None):
    limit = max(1, min(limit, 200))
    with Session(ENGINE) as s:
        q = select(DetectionRecord, DetectionWorkflowRecord).outerjoin(
            DetectionWorkflowRecord,
            (DetectionWorkflowRecord.detection_id == DetectionRecord.id) & (DetectionWorkflowRecord.tenant_id == tenant_id),
        ).where(DetectionRecord.tenant_id == tenant_id, DetectionRecord.detected == 1)
        if status:
            q = q.where(DetectionWorkflowRecord.status == status)
        if assignee:
            q = q.where(DetectionWorkflowRecord.assignee == assignee)
        return list(s.execute(q.order_by(DetectionRecord.created_at.desc()).limit(limit)))


def set_workflow(tenant_id: str, detection_id: int, actor: str, *, status: str | None = None, assignee: str | None = None, priority: int | None = None):
    if status is not None and status not in WORKFLOW_STATUSES:
        raise ValueError("invalid workflow status")
    if priority is not None and not 0 <= priority <= 100:
        raise ValueError("priority must be 0..100")
    with Session(ENGINE) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d:
            return None
        row = s.scalar(select(DetectionWorkflowRecord).where(DetectionWorkflowRecord.detection_id == detection_id, DetectionWorkflowRecord.tenant_id == tenant_id))
        if not row:
            row = DetectionWorkflowRecord(tenant_id=tenant_id, detection_id=detection_id, status="new", updated_by=actor, updated_at=_now())
            s.add(row)
        if status is not None: row.status = status
        if assignee is not None: row.assignee = assignee or None
        if priority is not None: row.priority = priority
        row.updated_by, row.updated_at = actor, _now()
        s.add(CaseEventRecord(tenant_id=tenant_id, case_id=None, event_type="detection.workflow", actor=actor, payload_json=json.dumps({"detection_id": detection_id, "status": row.status, "assignee": row.assignee, "priority": row.priority})))
        s.commit(); s.refresh(row)
        return row


def create_case_for_detection(tenant_id: str, detection_id: int, actor: str, title: str):
    with Session(ENGINE) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d:
            return None
        case = CaseRecord(tenant_id=tenant_id, owner=actor, title=title, status="investigating")
        s.add(case); s.flush()
        s.add(CaseDetectionLinkRecord(tenant_id=tenant_id, case_id=case.id, detection_id=detection_id, created_by=actor, created_at=_now()))
        s.add(CaseEventRecord(tenant_id=tenant_id, case_id=case.id, event_type="detection.linked", actor=actor, payload_json=json.dumps({"detection_id": detection_id})))
        s.commit(); s.refresh(case)
        return case


def dispose(tenant_id: str, detection_id: int, actor: str, reason: str, note: str = "", case_id: int | None = None):
    if reason not in DISPOSITION_REASONS:
        raise ValueError("invalid disposition reason")
    with Session(ENGINE) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d:
            return None
        if case_id is not None:
            case = s.scalar(select(CaseRecord).where(CaseRecord.id == case_id, CaseRecord.tenant_id == tenant_id))
            if not case: return None
        row = AnalystDispositionRecord(tenant_id=tenant_id, detection_id=detection_id, case_id=case_id, analyst=actor, reason=reason, note=note[:4000], created_at=_now())
        s.add(row)
        workflow = s.scalar(select(DetectionWorkflowRecord).where(DetectionWorkflowRecord.detection_id == detection_id, DetectionWorkflowRecord.tenant_id == tenant_id))
        if not workflow:
            workflow = DetectionWorkflowRecord(tenant_id=tenant_id, detection_id=detection_id, status="resolved", updated_by=actor, updated_at=_now()); s.add(workflow)
        workflow.status = "resolved" if reason != "needs_tuning" else "investigating"
        workflow.updated_by, workflow.updated_at = actor, _now()
        s.add(CaseEventRecord(tenant_id=tenant_id, case_id=case_id, event_type="detection.disposition", actor=actor, payload_json=json.dumps({"detection_id": detection_id, "reason": reason, "case_id": case_id})))
        s.commit(); s.refresh(row)
        return row


def timeline(tenant_id: str, detection_id: int, limit: int = 200):
    limit = max(1, min(limit, 500))
    with Session(ENGINE) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d: return None
        events = list(s.scalars(select(CaseEventRecord).where(CaseEventRecord.tenant_id == tenant_id).order_by(CaseEventRecord.created_at.asc()).limit(limit)))
        evidence = list(s.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id, EvidenceRecord.correlation_id == (d.correlation_id or "")).order_by(EvidenceRecord.collected_at.asc()).limit(limit))) if d.correlation_id else []
        linked = list(s.scalars(select(CaseDetectionLinkRecord).where(CaseDetectionLinkRecord.tenant_id == tenant_id, CaseDetectionLinkRecord.detection_id == detection_id)))
        case_ids = {x.case_id for x in linked}
        events = [e for e in events if e.case_id in case_ids or (e.case_id is None and str(detection_id) in e.payload_json)]
        items = [{"kind": "case_event", "event_type": e.event_type, "actor": e.actor, "payload": json.loads(e.payload_json), "timestamp": e.created_at.isoformat()} for e in events]
        items += [{"kind": "evidence", "evidence_type": e.evidence_type, "hash": e.content_sha256, "media_type": e.media_type, "timestamp": e.collected_at.isoformat()} for e in evidence]
        items.sort(key=lambda x: x["timestamp"])
        return items[-limit:]
