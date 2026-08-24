"""Secure tenant-scoped SOC analyst workflow API.

Browsers consume this boundary through the web application; privileged engine
internals are never exposed directly. Authentication, authorization and tenant
selection are delegated to the enterprise security boundary.
"""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.api_security import enforce_rate_limit
from core.enterprise import AUDIT, authenticate, authorize, require_tenant
from core.analyst import inbox, set_workflow, create_case_for_detection, dispose, timeline, DetectionWorkflowRecord, AnalystDispositionRecord, CaseDetectionLinkRecord, EntityRecord, SessionRecord
from core.storage import ENGINE, DetectionRecord, EvidenceRecord, CaseRecord

router = APIRouter(prefix="/enterprise/analyst", tags=["analyst"])


def _principal(request: Request, permission: str):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    principal = authenticate(request, request.headers.get("X-API-Key"))
    authorize(principal, permission)
    tenant = require_tenant(principal, request.headers.get("X-Tenant-ID"))
    return principal, tenant


class WorkflowUpdate(BaseModel):
    status: Optional[str] = Field(default=None, pattern="^(new|triaging|investigating|contained|resolved|closed)$")
    assignee: Optional[str] = Field(default=None, max_length=255)
    priority: Optional[int] = Field(default=None, ge=0, le=100)


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)


class DispositionRequest(BaseModel):
    reason: str = Field(..., pattern="^(true_positive|false_positive|benign|duplicate|insufficient_evidence|needs_tuning)$")
    note: str = Field(default="", max_length=4000)
    case_id: Optional[int] = Field(default=None, ge=1)


@router.get("/inbox")
def detection_inbox(request: Request, limit: int = 100, status: Optional[str] = None, assignee: Optional[str] = None):
    principal, tenant = _principal(request, "case:read")
    if status and status not in {"new", "triaging", "investigating", "contained", "resolved", "closed"}:
        raise HTTPException(400, "Invalid workflow status")
    rows = inbox(tenant, limit=limit, status=status, assignee=assignee)
    items = []
    for d, w in rows:
        items.append({"id": d.id, "subject": d.subject, "source": d.source, "severity": d.confidence, "confidence": d.score, "score": d.score, "mitre_ttp": d.mitre_ttp, "correlation_id": d.correlation_id, "created_at": d.created_at.isoformat(), "status": w.status if w else "new", "assignee": w.assignee if w else None, "priority": w.priority if w else 50})
    return {"tenant_id": tenant, "items": items, "count": len(items)}


@router.get("/detections/{detection_id}")
def get_detection(detection_id: int, request: Request):
    principal, tenant = _principal(request, "case:read")
    with Session(ENGINE) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant))
        if not d: raise HTTPException(404, "Detection not found")
        w = s.scalar(select(DetectionWorkflowRecord).where(DetectionWorkflowRecord.detection_id == detection_id, DetectionWorkflowRecord.tenant_id == tenant))
        evidence = list(s.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant, EvidenceRecord.correlation_id == (d.correlation_id or "")).order_by(EvidenceRecord.collected_at.asc()).limit(200))) if d.correlation_id else []
        dispositions = list(s.scalars(select(AnalystDispositionRecord).where(AnalystDispositionRecord.tenant_id == tenant, AnalystDispositionRecord.detection_id == detection_id).order_by(AnalystDispositionRecord.created_at.desc()).limit(20)))
    return {"tenant_id": tenant, "detection": {"id": d.id, "subject": d.subject, "source": d.source, "detected": bool(d.detected), "confidence": d.confidence, "score": d.score, "mitre_ttp": d.mitre_ttp, "correlation_id": d.correlation_id, "created_at": d.created_at.isoformat()}, "workflow": {"status": w.status, "assignee": w.assignee, "priority": w.priority} if w else {"status": "new", "assignee": None, "priority": 50}, "evidence": [{"id": e.id, "type": e.evidence_type, "media_type": e.media_type, "hash": e.content_sha256, "size_bytes": e.size_bytes, "provenance": e.metadata_json, "collected_at": e.collected_at.isoformat()} for e in evidence], "dispositions": [{"id": x.id, "reason": x.reason, "note": x.note, "analyst": x.analyst, "case_id": x.case_id, "created_at": x.created_at.isoformat()} for x in dispositions]}


@router.patch("/detections/{detection_id}/workflow")
def update_workflow(detection_id: int, req: WorkflowUpdate, request: Request):
    principal, tenant = _principal(request, "case:write")
    try: row = set_workflow(tenant, detection_id, principal.subject, status=req.status, assignee=req.assignee, priority=req.priority)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    if not row: raise HTTPException(404, "Detection not found")
    AUDIT.record("detection.workflow.updated", principal, request, {"detection_id": detection_id, "status": row.status, "assignee": row.assignee})
    return {"id": row.detection_id, "status": row.status, "assignee": row.assignee, "priority": row.priority, "updated_at": row.updated_at.isoformat()}


@router.get("/detections/{detection_id}/timeline")
def detection_timeline(detection_id: int, request: Request, limit: int = 200):
    principal, tenant = _principal(request, "case:read")
    result = timeline(tenant, detection_id, limit)
    if result is None: raise HTTPException(404, "Detection not found")
    return {"tenant_id": tenant, "detection_id": detection_id, "items": result}


@router.post("/detections/{detection_id}/cases")
def create_case(detection_id: int, req: CaseCreate, request: Request):
    principal, tenant = _principal(request, "case:write")
    case = create_case_for_detection(tenant, detection_id, principal.subject, req.title)
    if not case: raise HTTPException(404, "Detection not found")
    AUDIT.record("case.detection.linked", principal, request, {"case_id": case.id, "detection_id": detection_id})
    return {"id": case.id, "title": case.title, "owner": case.owner, "status": case.status, "detection_id": detection_id, "created_at": case.created_at.isoformat()}


@router.post("/detections/{detection_id}/disposition")
def set_disposition(detection_id: int, req: DispositionRequest, request: Request):
    principal, tenant = _principal(request, "case:write")
    try: row = dispose(tenant, detection_id, principal.subject, req.reason, req.note, req.case_id)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    if not row: raise HTTPException(404, "Detection or case not found")
    AUDIT.record("detection.disposition", principal, request, {"detection_id": detection_id, "reason": req.reason, "case_id": req.case_id})
    return {"id": row.id, "detection_id": row.detection_id, "reason": row.reason, "note": row.note, "analyst": row.analyst, "case_id": row.case_id, "created_at": row.created_at.isoformat()}


@router.get("/detections/{detection_id}/entities")
def entities(detection_id: int, request: Request, limit: int = 100):
    principal, tenant = _principal(request, "case:read")
    with Session(ENGINE) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant))
        if not d: raise HTTPException(404, "Detection not found")
        q = select(EntityRecord).where(EntityRecord.tenant_id == tenant)
        if d.correlation_id: q = q.where(EntityRecord.correlation_id == d.correlation_id)
        rows = list(s.scalars(q.order_by(EntityRecord.id.desc()).limit(max(1, min(limit, 200)))))
    return {"tenant_id": tenant, "items": [{"id": e.id, "type": e.entity_type, "key": e.entity_key, "attributes": e.attributes_json} for e in rows]}


@router.get("/detections/{detection_id}/sessions")
def sessions(detection_id: int, request: Request, limit: int = 100):
    principal, tenant = _principal(request, "case:read")
    with Session(ENGINE) as s:
        d = s.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant))
        if not d: raise HTTPException(404, "Detection not found")
        q = select(SessionRecord).where(SessionRecord.tenant_id == tenant)
        if d.correlation_id: q = q.where(SessionRecord.correlation_id == d.correlation_id)
        rows = list(s.scalars(q.order_by(SessionRecord.id.desc()).limit(max(1, min(limit, 200)))))
    return {"tenant_id": tenant, "items": [{"id": x.id, "session_key": x.session_key, "protocol": x.protocol, "correlation_id": x.correlation_id, "started_at": x.started_at.isoformat() if x.started_at else None, "ended_at": x.ended_at.isoformat() if x.ended_at else None, "attributes": x.attributes_json} for x in rows]}
