"""Tenant-scoped investigation case operations."""
from sqlalchemy import select
from sqlalchemy.orm import Session
from core.storage import ENGINE, CaseRecord
from datetime import datetime, timezone

def create_case(tenant_id: str, owner: str, title: str) -> CaseRecord:
    with Session(ENGINE) as s:
        c=CaseRecord(tenant_id=tenant_id,owner=owner,title=title,status="open",created_at=datetime.now(timezone.utc)); s.add(c); s.commit(); s.refresh(c); return c

def list_cases(tenant_id: str, limit: int=100):
    with Session(ENGINE) as s:
        return list(s.scalars(select(CaseRecord).where(CaseRecord.tenant_id==tenant_id).order_by(CaseRecord.id.desc()).limit(limit)))

def close_case(tenant_id: str, case_id: int):
    with Session(ENGINE) as s:
        c=s.scalar(select(CaseRecord).where(CaseRecord.id==case_id,CaseRecord.tenant_id==tenant_id))
        if not c:return None
        c.status="closed"; s.commit(); s.refresh(c); return c
