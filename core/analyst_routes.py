"""Secure tenant-scoped SOC analyst workflow API."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field

from core.api_security import enforce_rate_limit
from core.enterprise import AUDIT, authenticate, authorize, require_tenant
from core.analyst import DISPOSITION_REASONS, WORKFLOW_STATUSES, create_case_for_detection, dispose, inbox, inbox_total, investigation, set_workflow, timeline

router = APIRouter(prefix="/enterprise/analyst", tags=["analyst"])


def _principal(request: Request, permission: str):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    principal = authenticate(request, request.headers.get("X-API-Key"))
    tenant = require_tenant(principal, request.headers.get("X-Tenant-ID"))
    authorize(principal, permission)
    AUDIT.record("analyst.authorization", principal, request, {"permission": permission, "tenant_id": tenant})
    return principal, tenant


def _triage_severity(score: float, confidence: str) -> str:
    normalized = confidence.lower()
    if normalized in {"critical", "high"} or score >= 0.9:
        return "high"
    if normalized in {"medium", "moderate"} or score >= 0.6:
        return "medium"
    return "low"


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
def detection_inbox(request: Request, limit: int = Query(default=100, ge=1, le=200), offset: int = Query(default=0, ge=0, le=100000), status: Optional[str] = None, assignee: Optional[str] = Query(default=None, max_length=255), sort: str = Query(default="created_at"), order: str = Query(default="desc")):
    _, tenant = _principal(request, "case:read")
    if status and status not in WORKFLOW_STATUSES:
        raise HTTPException(400, "Invalid workflow status")
    if sort not in {"created_at", "score", "id"}:
        raise HTTPException(400, "Invalid sort field")
    if order.lower() not in {"asc", "desc"}:
        raise HTTPException(400, "Invalid sort order")
    rows = inbox(tenant, limit=limit, offset=offset, status=status, assignee=assignee, sort=sort, order=order)
    items = [{"id": d.id, "subject": d.subject, "source": d.source, "severity": _triage_severity(float(d.score), str(d.confidence)), "confidence": str(d.confidence), "score": float(d.score), "mitre_ttp": d.mitre_ttp, "correlation_id": d.correlation_id, "created_at": d.created_at.isoformat(), "status": w.status if w else "new", "assignee": w.assignee if w else None, "priority": w.priority if w else 50} for d, w in rows]
    total = inbox_total(tenant, status=status, assignee=assignee)
    return {"tenant_id": tenant, "items": items, "pagination": {"total": total, "limit": limit, "offset": offset, "has_more": offset + len(items) < total}}


@router.get("/detections/{detection_id}")
def get_detection(detection_id: int, request: Request):
    _, tenant = _principal(request, "case:read")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    result = investigation(tenant, detection_id)
    if result is None:
        raise HTTPException(404, "Detection not found")
    result["detection"]["triage_severity"] = _triage_severity(float(result["detection"]["score"]), str(result["detection"]["confidence"]))
    return {"tenant_id": tenant, **result}


@router.patch("/detections/{detection_id}/workflow")
def update_workflow(detection_id: int, req: WorkflowUpdate, request: Request):
    principal, tenant = _principal(request, "case:write")
    try:
        row = set_workflow(tenant, detection_id, principal.subject, status=req.status, assignee=req.assignee, priority=req.priority)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not row:
        raise HTTPException(404, "Detection not found")
    AUDIT.record("detection.workflow.updated", principal, request, {"detection_id": detection_id, "status": row.status, "assignee": row.assignee, "tenant_id": tenant})
    return {"id": row.detection_id, "status": row.status, "assignee": row.assignee, "priority": row.priority, "updated_at": row.updated_at.isoformat()}


@router.get("/detections/{detection_id}/timeline")
def detection_timeline(detection_id: int, request: Request, limit: int = Query(default=200, ge=1, le=500)):
    _, tenant = _principal(request, "case:read")
    result = timeline(tenant, detection_id, limit)
    if result is None:
        raise HTTPException(404, "Detection not found")
    return {"tenant_id": tenant, "detection_id": detection_id, "items": result}


@router.post("/detections/{detection_id}/cases")
def create_case(detection_id: int, req: CaseCreate, request: Request):
    principal, tenant = _principal(request, "case:write")
    try:
        case = create_case_for_detection(tenant, detection_id, principal.subject, req.title.strip())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not case:
        raise HTTPException(404, "Detection not found")
    AUDIT.record("case.detection.linked", principal, request, {"case_id": case.id, "detection_id": detection_id, "tenant_id": tenant})
    return {"id": case.id, "title": case.title, "owner": case.owner, "status": case.status, "detection_id": detection_id, "created_at": case.created_at.isoformat()}


@router.post("/detections/{detection_id}/disposition")
def set_disposition(detection_id: int, req: DispositionRequest, request: Request):
    principal, tenant = _principal(request, "case:write")
    if req.reason not in DISPOSITION_REASONS:
        raise HTTPException(400, "Invalid disposition reason")
    try:
        row = dispose(tenant, detection_id, principal.subject, req.reason, req.note, req.case_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not row:
        raise HTTPException(404, "Detection or case not found")
    AUDIT.record("detection.disposition", principal, request, {"detection_id": detection_id, "reason": req.reason, "case_id": req.case_id, "tenant_id": tenant})
    return {"id": row.id, "detection_id": row.detection_id, "reason": row.reason, "note": row.note, "analyst": row.analyst, "case_id": row.case_id, "created_at": row.created_at.isoformat()}


@router.get("/detections/{detection_id}/entities")
def entities(detection_id: int, request: Request):
    _, tenant = _principal(request, "case:read")
    result = investigation(tenant, detection_id)
    if result is None:
        raise HTTPException(404, "Detection not found")
    return {"tenant_id": tenant, "items": result["entities"]}


@router.get("/detections/{detection_id}/sessions")
def sessions(detection_id: int, request: Request):
    _, tenant = _principal(request, "case:read")
    result = investigation(tenant, detection_id)
    if result is None:
        raise HTTPException(404, "Detection not found")
    return {"tenant_id": tenant, "items": result["sessions"]}
