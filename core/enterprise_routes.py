"""Enterprise analyst workflow routes: feedback, cases, tenant configuration and feature flags.

Routes are deliberately tenant-scoped and use the same principal model as the main API.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select


from core.api_security import enforce_rate_limit
from core.enterprise import AUDIT, authenticate, authorize, require_tenant
from core.storage import (
    CaseCommentRecord,
    CaseEventRecord,
    CaseRecord,
    DetectionFeedbackRecord,
    TenantConfigRecord,
    tenant_session,
)

router = APIRouter(prefix="/enterprise", tags=["enterprise"])


def _principal(request: Request, permission: str):
    enforce_rate_limit(request.client.host if request.client else "unknown")
    api_key = request.headers.get("X-API-Key")
    principal = authenticate(request, api_key)
    authorize(principal, permission)
    tenant_id = require_tenant(principal, request.headers.get("X-Tenant-ID"))
    return principal, tenant_id


class FeedbackRequest(BaseModel):
    disposition: str = Field(..., pattern="^(true_positive|false_positive|needs_tuning)$")
    note: Optional[str] = Field(default=None, max_length=4000)


class CaseRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    owner: Optional[str] = Field(default=None, max_length=255)


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = Field(default=None, pattern="^(open|investigating|resolved|closed)$")
    owner: Optional[str] = Field(default=None, max_length=255)


class CommentRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=10000)


class ConfigRequest(BaseModel):
    value: Dict[str, Any]


class FeatureRequest(BaseModel):
    enabled: bool


@router.post("/detections/{detection_id}/feedback")
def submit_feedback(detection_id: int, req: FeedbackRequest, request: Request):
    principal, tenant_id = _principal(request, "case:write")
    with tenant_session(tenant_id) as session:
        from core.storage import DetectionRecord
        detection = session.scalar(select(DetectionRecord).where(DetectionRecord.id == detection_id, DetectionRecord.tenant_id == tenant_id))
        if not detection:
            raise HTTPException(404, "Detection not found")
        existing = session.scalar(select(DetectionFeedbackRecord).where(DetectionFeedbackRecord.detection_id == detection_id, DetectionFeedbackRecord.tenant_id == tenant_id))
        if existing:
            existing.disposition = req.disposition
            existing.note = req.note or ""
            existing.subject = principal.subject
        else:
            existing = DetectionFeedbackRecord(
                tenant_id=tenant_id, detection_id=detection_id, subject=principal.subject,
                disposition=req.disposition, note=req.note or "",
            )
            session.add(existing)
        session.add(CaseEventRecord(tenant_id=tenant_id, case_id=None, event_type="detection.feedback", actor=principal.subject, payload_json=json.dumps({"detection_id": detection_id, "disposition": req.disposition})))
        session.commit()
    AUDIT.record("detection.feedback", principal, request, {"detection_id": detection_id, "disposition": req.disposition})
    return {"status": "recorded", "detection_id": detection_id, "tenant_id": tenant_id, "disposition": req.disposition}


@router.get("/feedback")
def list_feedback(request: Request, limit: int = 100):
    principal, tenant_id = _principal(request, "case:read")
    limit = max(1, min(limit, 500))
    with tenant_session(tenant_id) as session:
        rows = list(session.scalars(select(DetectionFeedbackRecord).where(DetectionFeedbackRecord.tenant_id == tenant_id).order_by(DetectionFeedbackRecord.id.desc()).limit(limit)))
    return {"tenant_id": tenant_id, "items": [{"id": r.id, "detection_id": r.detection_id, "disposition": r.disposition, "note": r.note, "subject": r.subject, "created_at": r.created_at.isoformat()} for r in rows]}


@router.post("/cases")
def create_case(req: CaseRequest, request: Request):
    principal, tenant_id = _principal(request, "case:write")
    owner = req.owner or principal.subject
    with tenant_session(tenant_id) as session:
        case = CaseRecord(tenant_id=tenant_id, owner=owner, title=req.title, status="open")
        session.add(case)
        session.flush()
        session.add(CaseEventRecord(tenant_id=tenant_id, case_id=case.id, event_type="case.created", actor=principal.subject, payload_json=json.dumps({"title": req.title})))
        session.commit(); session.refresh(case)
    AUDIT.record("case.created", principal, request, {"case_id": case.id})
    return {"id": case.id, "tenant_id": tenant_id, "title": case.title, "owner": case.owner, "status": case.status, "created_at": case.created_at.isoformat()}


@router.get("/cases")
def get_cases(request: Request, limit: int = 100):
    principal, tenant_id = _principal(request, "case:read")
    limit = max(1, min(limit, 500))
    with tenant_session(tenant_id) as session:
        rows = list(session.scalars(select(CaseRecord).where(CaseRecord.tenant_id == tenant_id).order_by(CaseRecord.id.desc()).limit(limit)))
    return {"tenant_id": tenant_id, "items": [{"id": r.id, "title": r.title, "owner": r.owner, "status": r.status, "created_at": r.created_at.isoformat()} for r in rows]}


@router.patch("/cases/{case_id}")
def update_case(case_id: int, req: CaseUpdateRequest, request: Request):
    principal, tenant_id = _principal(request, "case:write")
    if req.status is None and req.owner is None:
        raise HTTPException(400, "At least one case field must be supplied")
    with tenant_session(tenant_id) as session:
        case = session.scalar(select(CaseRecord).where(CaseRecord.id == case_id, CaseRecord.tenant_id == tenant_id))
        if not case: raise HTTPException(404, "Case not found")
        if req.status is not None: case.status = req.status
        if req.owner is not None: case.owner = req.owner
        session.add(CaseEventRecord(tenant_id=tenant_id, case_id=case.id, event_type="case.updated", actor=principal.subject, payload_json=json.dumps(req.model_dump(exclude_none=True))))
        session.commit(); session.refresh(case)
    AUDIT.record("case.updated", principal, request, {"case_id": case_id})
    return {"id": case.id, "tenant_id": tenant_id, "title": case.title, "owner": case.owner, "status": case.status, "created_at": case.created_at.isoformat()}


@router.post("/cases/{case_id}/comments")
def add_comment(case_id: int, req: CommentRequest, request: Request):
    principal, tenant_id = _principal(request, "case:write")
    with tenant_session(tenant_id) as session:
        case = session.scalar(select(CaseRecord).where(CaseRecord.id == case_id, CaseRecord.tenant_id == tenant_id))
        if not case: raise HTTPException(404, "Case not found")
        comment = CaseCommentRecord(tenant_id=tenant_id, case_id=case_id, author=principal.subject, body=req.body)
        session.add(comment)
        session.flush()
        session.add(CaseEventRecord(tenant_id=tenant_id, case_id=case_id, event_type="case.comment", actor=principal.subject, payload_json=json.dumps({"comment_id": comment.id})))
        session.commit(); session.refresh(comment)
    AUDIT.record("case.comment", principal, request, {"case_id": case_id, "comment_id": comment.id})
    return {"id": comment.id, "case_id": case_id, "author": comment.author, "body": comment.body, "created_at": comment.created_at.isoformat()}


@router.get("/cases/{case_id}/timeline")
def case_timeline(case_id: int, request: Request, limit: int = 200):
    principal, tenant_id = _principal(request, "case:read")
    limit = max(1, min(limit, 1000))
    with tenant_session(tenant_id) as session:
        case = session.scalar(select(CaseRecord).where(CaseRecord.id == case_id, CaseRecord.tenant_id == tenant_id))
        if not case: raise HTTPException(404, "Case not found")
        events = list(session.scalars(select(CaseEventRecord).where(CaseEventRecord.case_id == case_id, CaseEventRecord.tenant_id == tenant_id).order_by(CaseEventRecord.id.asc()).limit(limit)))
        comments = list(session.scalars(select(CaseCommentRecord).where(CaseCommentRecord.case_id == case_id, CaseCommentRecord.tenant_id == tenant_id).order_by(CaseCommentRecord.id.asc()).limit(limit)))
    timeline = [{"type": "event", "id": e.id, "event_type": e.event_type, "actor": e.actor, "payload": json.loads(e.payload_json), "created_at": e.created_at.isoformat()} for e in events]
    timeline += [{"type": "comment", "id": c.id, "author": c.author, "body": c.body, "created_at": c.created_at.isoformat()} for c in comments]
    timeline.sort(key=lambda item: item["created_at"])
    return {"tenant_id": tenant_id, "case_id": case_id, "items": timeline[-limit:]}


@router.get("/config/{name}")
def get_config(name: str, request: Request):
    principal, tenant_id = _principal(request, "case:read")
    with tenant_session(tenant_id) as session:
        row = session.scalar(select(TenantConfigRecord).where(TenantConfigRecord.tenant_id == tenant_id, TenantConfigRecord.name == name))
    if not row:
        raise HTTPException(404, "Configuration not found")
    return {"tenant_id": tenant_id, "name": row.name, "value": json.loads(row.value_json), "updated_at": row.updated_at.isoformat()}


@router.put("/config/{name}")
def put_config(name: str, req: ConfigRequest, request: Request):
    principal, tenant_id = _principal(request, "case:write")
    if len(name) > 100 or not name.replace("_", "").replace("-", "").isalnum(): raise HTTPException(400, "Invalid configuration name")
    with tenant_session(tenant_id) as session:
        row = session.scalar(select(TenantConfigRecord).where(TenantConfigRecord.tenant_id == tenant_id, TenantConfigRecord.name == name))
        if row: row.value_json = json.dumps(req.value, sort_keys=True)
        else:
            row = TenantConfigRecord(tenant_id=tenant_id, name=name, value_json=json.dumps(req.value, sort_keys=True)); session.add(row)
        session.commit(); session.refresh(row)
    AUDIT.record("tenant.config.updated", principal, request, {"name": name})
    return {"tenant_id": tenant_id, "name": row.name, "value": req.value, "updated_at": row.updated_at.isoformat()}


@router.get("/features/{name}")
def get_feature(name: str, request: Request):
    principal, tenant_id = _principal(request, "case:read")
    with tenant_session(tenant_id) as session:
        row = session.scalar(select(TenantConfigRecord).where(TenantConfigRecord.tenant_id == tenant_id, TenantConfigRecord.name == f"feature:{name}"))
    return {"tenant_id": tenant_id, "name": name, "enabled": bool(json.loads(row.value_json).get("enabled", False)) if row else False}


@router.put("/features/{name}")
def put_feature(name: str, req: FeatureRequest, request: Request):
    principal, tenant_id = _principal(request, "case:write")
    if len(name) > 100 or not name.replace("_", "").replace("-", "").isalnum(): raise HTTPException(400, "Invalid feature name")
    with tenant_session(tenant_id) as session:
        key = f"feature:{name}"
        row = session.scalar(select(TenantConfigRecord).where(TenantConfigRecord.tenant_id == tenant_id, TenantConfigRecord.name == key))
        payload = json.dumps({"enabled": req.enabled})
        if row: row.value_json = payload
        else: session.add(TenantConfigRecord(tenant_id=tenant_id, name=key, value_json=payload))
        session.commit()
    AUDIT.record("feature.updated", principal, request, {"name": name, "enabled": req.enabled})
    return {"tenant_id": tenant_id, "name": name, "enabled": req.enabled}
