"""Authenticated SOC analyst API for the ThreatFade control plane."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.analyst import (
    DISPOSITION_REASONS,
    WORKFLOW_STATUSES,
    create_case_for_detection,
    dispose,
    inbox,
    inbox_total,
    investigation,
    set_workflow,
    timeline,
)
from core.api_security import enforce_rate_limit
from core.enterprise import AUDIT, authenticate, authorize, require_tenant

router = APIRouter(prefix="/enterprise/analyst", tags=["analyst"])


class WorkflowPatch(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = Field(default=None, max_length=255)
    priority: Optional[int] = Field(default=None, ge=0, le=100)


class DispositionRequest(BaseModel):
    reason: str
    note: str = Field(default="", max_length=4000)
    case_id: Optional[int] = Field(default=None, ge=1)


class CaseRequest(BaseModel):
    title: str = Field(min_length=1, max_length=500)


def _guard(request: Request, x_api_key: Optional[str], permission: str):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    principal = authenticate(request, x_api_key)
    authorize(principal, permission)
    tenant_id = require_tenant(principal, request.headers.get("X-Tenant-ID"))
    AUDIT.record("analyst.authorization", principal, request, {"permission": permission})
    return principal, tenant_id


def _triage_severity(score: float, confidence: str) -> str:
    """Presentation-only triage band; it is not a detection accuracy claim."""
    normalized = confidence.lower()
    if normalized in {"critical", "high"} or score >= 0.9:
        return "high"
    if normalized in {"medium", "moderate"} or score >= 0.6:
        return "medium"
    return "low"


@router.get("/inbox")
def analyst_inbox(
    request: Request,
    status: Optional[str] = Query(default=None),
    assignee: Optional[str] = Query(default=None, max_length=255),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100000),
    sort: str = Query(default="created_at"),
    order: str = Query(default="desc"),
    x_api_key: Optional[str] = Header(default=None),
):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    if status is not None and status not in WORKFLOW_STATUSES:
        raise HTTPException(400, "Invalid workflow status")
    if sort not in {"created_at", "score", "id"}:
        raise HTTPException(400, "Invalid sort field")
    if order.lower() not in {"asc", "desc"}:
        raise HTTPException(400, "Invalid sort order")
    if assignee is not None and not assignee.strip():
        raise HTTPException(400, "Invalid assignee")
    rows = inbox(tenant_id, limit=limit, offset=offset, status=status, assignee=assignee, sort=sort, order=order)
    items = []
    for detection, workflow in rows:
        items.append({
            "id": detection.id,
            "subject": detection.subject,
            "source": detection.source,
            "severity": _triage_severity(float(detection.score), str(detection.confidence)),
            "confidence": str(detection.confidence),
            "score": float(detection.score),
            "mitre_ttp": detection.mitre_ttp,
            "correlation_id": detection.correlation_id,
            "created_at": detection.created_at.isoformat(),
            "status": workflow.status if workflow else "new",
            "assignee": workflow.assignee if workflow else None,
            "priority": workflow.priority if workflow else 50,
        })
    return {"items": items, "pagination": {"total": inbox_total(tenant_id, status=status, assignee=assignee), "limit": limit, "offset": offset, "has_more": offset + len(items) < inbox_total(tenant_id, status=status, assignee=assignee)}}


@router.get("/detections/{detection_id}")
def analyst_detection(detection_id: int, request: Request, x_api_key: Optional[str] = Header(default=None)):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    data = investigation(tenant_id, detection_id)
    if data is None:
        raise HTTPException(404, "Detection not found")
    data["detection"]["triage_severity"] = _triage_severity(float(data["detection"]["score"]), str(data["detection"]["confidence"]))
    return data


@router.get("/detections/{detection_id}/timeline")
def analyst_timeline(detection_id: int, request: Request, x_api_key: Optional[str] = Header(default=None)):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    items = timeline(tenant_id, detection_id)
    if items is None:
        raise HTTPException(404, "Detection not found")
    return {"items": items}


@router.get("/detections/{detection_id}/entities")
def analyst_entities(detection_id: int, request: Request, x_api_key: Optional[str] = Header(default=None)):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    data = investigation(tenant_id, detection_id)
    if data is None:
        raise HTTPException(404, "Detection not found")
    return {"items": data["entities"]}


@router.get("/detections/{detection_id}/sessions")
def analyst_sessions(detection_id: int, request: Request, x_api_key: Optional[str] = Header(default=None)):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    data = investigation(tenant_id, detection_id)
    if data is None:
        raise HTTPException(404, "Detection not found")
    return {"items": data["sessions"]}


@router.patch("/detections/{detection_id}/workflow")
def analyst_workflow(detection_id: int, payload: WorkflowPatch, request: Request, x_api_key: Optional[str] = Header(default=None)):
    principal, tenant_id = _guard(request, x_api_key, "case:write")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    if payload.status is None and payload.assignee is None and payload.priority is None:
        raise HTTPException(400, "At least one workflow field is required")
    try:
        row = set_workflow(tenant_id, detection_id, principal.subject, status=payload.status, assignee=payload.assignee, priority=payload.priority)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if row is None:
        raise HTTPException(404, "Detection not found")
    AUDIT.record("analyst.workflow.updated", principal, request, {"detection_id": detection_id, "status": row.status})
    return {"status": row.status, "assignee": row.assignee, "priority": row.priority}


@router.post("/detections/{detection_id}/disposition")
def analyst_disposition(detection_id: int, payload: DispositionRequest, request: Request, x_api_key: Optional[str] = Header(default=None)):
    principal, tenant_id = _guard(request, x_api_key, "case:write")
    if detection_id < 1 or payload.reason not in DISPOSITION_REASONS:
        raise HTTPException(400, "Invalid disposition")
    row = dispose(tenant_id, detection_id, principal.subject, payload.reason, payload.note, payload.case_id)
    if row is None:
        raise HTTPException(404, "Detection or case not found")
    AUDIT.record("analyst.disposition.created", principal, request, {"detection_id": detection_id, "reason": payload.reason, "case_id": payload.case_id})
    return {"id": row.id, "reason": row.reason, "case_id": row.case_id}


@router.post("/detections/{detection_id}/cases")
def analyst_create_case(detection_id: int, payload: CaseRequest, request: Request, x_api_key: Optional[str] = Header(default=None)):
    principal, tenant_id = _guard(request, x_api_key, "case:write")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    try:
        case = create_case_for_detection(tenant_id, detection_id, principal.subject, payload.title.strip())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if case is None:
        raise HTTPException(404, "Detection not found")
    AUDIT.record("analyst.case.created", principal, request, {"detection_id": detection_id, "case_id": case.id})
    return {"id": case.id, "title": case.title, "status": case.status, "owner": case.owner, "created_at": case.created_at.isoformat()}
