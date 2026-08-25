"""Authenticated SOC analyst API for the ThreatFade control plane."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.api_security import enforce_rate_limit
from core.analyst_workflow import (
    DISPOSITION_REASONS,
    STATUSES,
    add_disposition,
    create_case,
    get_investigation,
    list_inbox,
    timeline,
    update_workflow,
)
from core.enterprise import AUDIT, authenticate, authorize, require_tenant

router = APIRouter(prefix="/enterprise/analyst", tags=["analyst"])


class WorkflowPatch(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = Field(default=None, max_length=255)
    priority: Optional[int] = Field(default=None, ge=0, le=100)


class DispositionRequest(BaseModel):
    reason: str
    note: str = Field(default="", max_length=4000)


class CaseRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=500)


def _guard(request: Request, x_api_key: Optional[str], permission: str):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    principal = authenticate(request, x_api_key)
    authorize(principal, permission)
    tenant_id = require_tenant(principal, request.headers.get("X-Tenant-ID"))
    AUDIT.record("analyst.authorization", principal, request, {"permission": permission})
    return principal, tenant_id


def _triage_severity(score: float, confidence: str) -> str:
    """Presentation-only triage band; it is not a detection accuracy claim."""
    if confidence.lower() in {"critical", "high"} or score >= 0.9:
        return "high"
    if confidence.lower() in {"medium", "moderate"} or score >= 0.6:
        return "medium"
    return "low"


@router.get("/inbox")
def analyst_inbox(
    request: Request,
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100000),
    sort: str = Query(default="created_at"),
    order: str = Query(default="desc"),
    x_api_key: Optional[str] = Header(default=None),
):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    if status is not None and status not in STATUSES:
        raise HTTPException(400, "Invalid workflow status")
    if sort not in {"created_at", "score", "priority", "id"}:
        raise HTTPException(400, "Invalid sort field")
    if order.lower() not in {"asc", "desc"}:
        raise HTTPException(400, "Invalid sort order")
    items, total = list_inbox(tenant_id, status=status, limit=limit, offset=offset, sort=sort, order=order)
    for item in items:
        item["severity"] = _triage_severity(float(item["score"]), str(item["confidence"]))
        item["confidence"] = str(item["confidence"])
        if hasattr(item["created_at"], "isoformat"):
            item["created_at"] = item["created_at"].isoformat()
    return {"items": items, "pagination": {"total": total, "limit": limit, "offset": offset, "has_more": offset + len(items) < total}}


@router.get("/detections/{detection_id}")
def analyst_detection(
    detection_id: int,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    data = get_investigation(tenant_id, detection_id)
    if data is None:
        raise HTTPException(404, "Detection not found")
    data["detection"]["triage_severity"] = _triage_severity(float(data["detection"]["score"]), str(data["detection"]["confidence"]))
    return data


@router.get("/detections/{detection_id}/timeline")
def analyst_timeline(
    detection_id: int,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    if get_investigation(tenant_id, detection_id) is None:
        raise HTTPException(404, "Detection not found")
    return {"items": timeline(tenant_id, detection_id)}


@router.get("/detections/{detection_id}/entities")
def analyst_entities(detection_id: int, request: Request, x_api_key: Optional[str] = Header(default=None)):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    data = get_investigation(tenant_id, detection_id)
    if data is None:
        raise HTTPException(404, "Detection not found")
    return {"items": data["entities"]}


@router.get("/detections/{detection_id}/sessions")
def analyst_sessions(detection_id: int, request: Request, x_api_key: Optional[str] = Header(default=None)):
    _, tenant_id = _guard(request, x_api_key, "detection:read")
    data = get_investigation(tenant_id, detection_id)
    if data is None:
        raise HTTPException(404, "Detection not found")
    return {"items": data["sessions"]}


@router.patch("/detections/{detection_id}/workflow")
def analyst_workflow(
    detection_id: int,
    payload: WorkflowPatch,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    principal, tenant_id = _guard(request, x_api_key, "case:write")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    if payload.status is None and payload.assignee is None and payload.priority is None:
        raise HTTPException(400, "At least one workflow field is required")
    try:
        update_workflow(tenant_id, detection_id, principal.subject, status=payload.status, assignee=payload.assignee, priority=payload.priority)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if get_investigation(tenant_id, detection_id) is None:
        raise HTTPException(404, "Detection not found")
    AUDIT.record("analyst.workflow.updated", principal, request, {"detection_id": detection_id, "status": payload.status})
    return get_investigation(tenant_id, detection_id)["workflow"]


@router.post("/detections/{detection_id}/disposition")
def analyst_disposition(
    detection_id: int,
    payload: DispositionRequest,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    principal, tenant_id = _guard(request, x_api_key, "case:write")
    if detection_id < 1 or payload.reason not in DISPOSITION_REASONS:
        raise HTTPException(400, "Invalid disposition")
    try:
        disposition_id = add_disposition(tenant_id, detection_id, principal.subject, payload.reason, payload.note)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if disposition_id == 0:
        raise HTTPException(404, "Detection not found")
    AUDIT.record("analyst.disposition.created", principal, request, {"detection_id": detection_id, "reason": payload.reason})
    return {"id": disposition_id, "reason": payload.reason}


@router.post("/detections/{detection_id}/cases")
def analyst_create_case(
    detection_id: int,
    payload: CaseRequest,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    principal, tenant_id = _guard(request, x_api_key, "case:write")
    if detection_id < 1:
        raise HTTPException(400, "Invalid detection id")
    try:
        case = create_case(tenant_id, principal.subject, detection_id, payload.title)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not case:
        raise HTTPException(404, "Detection not found")
    AUDIT.record("analyst.case.created", principal, request, {"detection_id": detection_id, "case_id": case["id"]})
    return case
