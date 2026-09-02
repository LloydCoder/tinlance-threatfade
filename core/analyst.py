"""Tenant-scoped SOC analyst workflow primitives.

The analyst layer deliberately sits above the canonical detection/evidence data
plane. It owns workflow state (triage, assignment, disposition and case links)
and never changes detection evidence or tenant identity.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Integer, String, Text, DateTime, select, func
from sqlalchemy.orm import Mapped, Session, mapped_column

from core.storage import (
    Base,
    ENGINE,
    DetectionRecord,
    EvidenceRecord,
    CaseRecord,
    CaseEventRecord,
    set_tenant_context,
)


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
SORT_FIELDS = {"created_at": DetectionRecord.created_at, "score": DetectionRecord.score, "id": DetectionRecord.id}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: str | None) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _session(tenant_id: str) -> Session:
    """Create a tenant-bound session with PostgreSQL RLS context."""
    session = Session(ENGINE, expire_on_commit=False)
    set_tenant_context(session, tenant_id)
    return session


def detection(tenant_id: str, detection_id: int) -> DetectionRecord | None:
    with _session(tenant_id) as s:
        return s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))


def inbox(tenant_id: str, *, limit: int = 100, offset: int = 0, status: str | None = None, assignee: str | None = None, sort: str = "created_at", order: str = "desc"):
    limit = max(1, min(limit, 200)); offset = max(0, min(offset, 100000))
    if status is not None and status not in WORKFLOW_STATUSES: raise ValueError("invalid workflow status")
    if sort not in SORT_FIELDS: raise ValueError("invalid sort field")
    if order.lower() not in {"asc", "desc"}: raise ValueError("invalid sort order")
    with _session(tenant_id) as s:
        q = select(DetectionRecord, DetectionWorkflowRecord).outerjoin(DetectionWorkflowRecord, (DetectionWorkflowRecord.detection_id == DetectionRecord.id) & (DetectionWorkflowRecord.tenant_id == tenant_id)).where(DetectionRecord.tenant_id == tenant_id, DetectionRecord.detected == 1)
        if status: q = q.where(DetectionWorkflowRecord.status == status)
        if assignee: q = q.where(DetectionWorkflowRecord.assignee == assignee)
        column = SORT_FIELDS[sort]
        q = q.order_by(column.asc() if order.lower() == "asc" else column.desc(), DetectionRecord.id.desc()).offset(offset).limit(limit)
        return list(s.execute(q))


def inbox_total(tenant_id: str, *, status: str | None = None, assignee: str | None = None) -> int:
    with _session(tenant_id) as s:
        q = select(func.count(DetectionRecord.id)).where(DetectionRecord.tenant_id == tenant_id, DetectionRecord.detected == 1)
        if status is not None or assignee is not None:
            q = q.join(DetectionWorkflowRecord, (DetectionWorkflowRecord.detection_id == DetectionRecord.id) & (DetectionWorkflowRecord.tenant_id == tenant_id))
            if status: q = q.where(DetectionWorkflowRecord.status == status)
            if assignee: q = q.where(DetectionWorkflowRecord.assignee == assignee)
        return int(s.execute(q).scalar_one())


def set_workflow(tenant_id: str, detection_id: int, actor: str, *, status: str | None = None, assignee: str | None = None, priority: int | None = None):
    if status is not None and status not in WORKFLOW_STATUSES: raise ValueError("invalid workflow status")
    if priority is not None and not 0 <= priority <= 100: raise ValueError("priority must be 0..100")
    if assignee is not None and len(assignee) > 255: raise ValueError("assignee too long")
    with _session(tenant_id) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d: return None
        row = s.scalar(select(DetectionWorkflowRecord).where(DetectionWorkflowRecord.detection_id == detection_id, DetectionWorkflowRecord.tenant_id == tenant_id))
        if not row:
            row = DetectionWorkflowRecord(tenant_id=tenant_id, detection_id=detection_id, status="new", updated_by=actor, updated_at=_now()); s.add(row)
        if status is not None: row.status = status
        if assignee is not None: row.assignee = assignee.strip() or None
        if priority is not None: row.priority = priority
        row.updated_by, row.updated_at = actor, _now()
        s.add(CaseEventRecord(tenant_id=tenant_id, case_id=None, event_type="detection.workflow", actor=actor, payload_json=json.dumps({"detection_id": detection_id, "status": row.status, "assignee": row.assignee, "priority": row.priority})))
        s.flush(); s.commit(); return row


def create_case_for_detection(tenant_id: str, detection_id: int, actor: str, title: str):
    if not title or len(title) > 500: raise ValueError("invalid case title")
    with _session(tenant_id) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d: return None
        case = CaseRecord(tenant_id=tenant_id, owner=actor, title=title.strip(), status="investigating")
        s.add(case); s.flush()
        s.add(CaseDetectionLinkRecord(tenant_id=tenant_id, case_id=case.id, detection_id=detection_id, created_by=actor, created_at=_now()))
        s.add(CaseEventRecord(tenant_id=tenant_id, case_id=case.id, event_type="detection.linked", actor=actor, payload_json=json.dumps({"detection_id": detection_id})))
        s.flush(); s.commit(); return case


def dispose(tenant_id: str, detection_id: int, actor: str, reason: str, note: str = "", case_id: int | None = None):
    if reason not in DISPOSITION_REASONS: raise ValueError("invalid disposition reason")
    if len(note) > 4000: raise ValueError("note too long")
    with _session(tenant_id) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d: return None
        if case_id is not None and not s.scalar(select(CaseRecord).where(CaseRecord.id == case_id, CaseRecord.tenant_id == tenant_id)): return None
        row = AnalystDispositionRecord(tenant_id=tenant_id, detection_id=detection_id, case_id=case_id, analyst=actor, reason=reason, note=note, created_at=_now()); s.add(row)
        workflow = s.scalar(select(DetectionWorkflowRecord).where(DetectionWorkflowRecord.detection_id == detection_id, DetectionWorkflowRecord.tenant_id == tenant_id))
        if not workflow:
            workflow = DetectionWorkflowRecord(tenant_id=tenant_id, detection_id=detection_id, status="resolved", updated_by=actor, updated_at=_now()); s.add(workflow)
        workflow.status = "resolved" if reason != "needs_tuning" else "investigating"; workflow.updated_by, workflow.updated_at = actor, _now()
        s.add(CaseEventRecord(tenant_id=tenant_id, case_id=case_id, event_type="detection.disposition", actor=actor, payload_json=json.dumps({"detection_id": detection_id, "reason": reason, "case_id": case_id})))
        s.flush(); s.commit(); return row


def investigation(tenant_id: str, detection_id: int) -> dict[str, Any] | None:
    with _session(tenant_id) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d: return None
        workflow = s.scalar(select(DetectionWorkflowRecord).where(DetectionWorkflowRecord.detection_id == detection_id, DetectionWorkflowRecord.tenant_id == tenant_id))
        evidence = list(s.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id, EvidenceRecord.correlation_id == (d.correlation_id or "")).order_by(EvidenceRecord.collected_at.asc()))) if d.correlation_id else []
        entities = list(s.scalars(select(EntityRecord).where(EntityRecord.tenant_id == tenant_id, EntityRecord.correlation_id == d.correlation_id).order_by(EntityRecord.created_at.asc()))) if d.correlation_id else []
        sessions = list(s.scalars(select(SessionRecord).where(SessionRecord.tenant_id == tenant_id, SessionRecord.correlation_id == d.correlation_id).order_by(SessionRecord.started_at.asc()))) if d.correlation_id else []
        dispositions = list(s.scalars(select(AnalystDispositionRecord).where(AnalystDispositionRecord.tenant_id == tenant_id, AnalystDispositionRecord.detection_id == detection_id).order_by(AnalystDispositionRecord.created_at.asc())))
        links = list(s.scalars(select(CaseDetectionLinkRecord).where(CaseDetectionLinkRecord.tenant_id == tenant_id, CaseDetectionLinkRecord.detection_id == detection_id)))
        case_ids = [link.case_id for link in links]
        cases = list(s.scalars(select(CaseRecord).where(CaseRecord.tenant_id == tenant_id, CaseRecord.id.in_(case_ids)))) if case_ids else []
        return {"detection": {"id": d.id, "subject": d.subject, "source": d.source, "confidence": d.confidence, "score": float(d.score), "mitre_ttp": d.mitre_ttp, "correlation_id": d.correlation_id, "created_at": d.created_at.isoformat(), "evidence": _json(d.evidence_json), "provenance": {"input_sha256": d.input_sha256, "rule_pack_sha256": d.rule_pack_sha256, "engine_version": d.engine_version, "model_sha256": d.model_sha256, "config_sha256": d.config_sha256}}, "workflow": {"status": workflow.status if workflow else "new", "assignee": workflow.assignee if workflow else None, "priority": workflow.priority if workflow else 50}, "evidence": [{"id": x.id, "type": x.evidence_type, "media_type": x.media_type, "hash": x.content_sha256, "size_bytes": x.size_bytes, "collected_at": x.collected_at.isoformat(), "source_uri": x.source_uri} for x in evidence], "entities": [{"id": x.id, "entity_type": x.entity_type, "entity_key": x.entity_key, "attributes": _json(x.attributes_json), "created_at": x.created_at.isoformat()} for x in entities], "sessions": [{"id": x.id, "session_key": x.session_key, "protocol": x.protocol, "started_at": x.started_at.isoformat() if x.started_at else None, "ended_at": x.ended_at.isoformat() if x.ended_at else None, "attributes": _json(x.attributes_json)} for x in sessions], "dispositions": [{"id": x.id, "reason": x.reason, "note": x.note, "analyst": x.analyst, "case_id": x.case_id, "created_at": x.created_at.isoformat()} for x in dispositions], "cases": [{"id": x.id, "title": x.title, "status": x.status, "owner": x.owner, "created_at": x.created_at.isoformat()} for x in cases]}


def timeline(tenant_id: str, detection_id: int, limit: int = 200):
    limit = max(1, min(limit, 500))
    with _session(tenant_id) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not d: return None
        events = list(s.scalars(select(CaseEventRecord).where(CaseEventRecord.tenant_id == tenant_id).order_by(CaseEventRecord.created_at.asc()).limit(limit)))
        evidence = list(s.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id, EvidenceRecord.correlation_id == (d.correlation_id or "")).order_by(EvidenceRecord.collected_at.asc()).limit(limit))) if d.correlation_id else []
        linked = list(s.scalars(select(CaseDetectionLinkRecord).where(CaseDetectionLinkRecord.tenant_id == tenant_id, CaseDetectionLinkRecord.detection_id == detection_id)))
        case_ids = {x.case_id for x in linked}
        events = [e for e in events if e.case_id in case_ids or (e.case_id is None and str(detection_id) in e.payload_json)]
        items = [{"kind": "case_event", "event_type": e.event_type, "actor": e.actor, "payload": _json(e.payload_json), "timestamp": e.created_at.isoformat()} for e in events]
        items += [{"kind": "evidence", "evidence_type": e.evidence_type, "hash": e.content_sha256, "media_type": e.media_type, "timestamp": e.collected_at.isoformat()} for e in evidence]
        items.sort(key=lambda x: x["timestamp"]); return items[-limit:]
