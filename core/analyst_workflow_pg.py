"""PostgreSQL-safe overrides for analyst workflow writes.

The shared analyst workflow module owns validation and read paths. These write
helpers use INSERT ... RETURNING so PostgreSQL and SQLite behave consistently.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.analyst_workflow import (
    DISPOSITION_REASONS,
    STATUSES,
    add_disposition as _unused_add_disposition,
    create_case as _unused_create_case,
    get_investigation,
    list_inbox,
    timeline,
    update_workflow,
)
from core.storage import ENGINE, set_tenant_context


def add_disposition(tenant_id: str, detection_id: int, analyst: str, reason: str, note: str) -> int:
    if reason not in DISPOSITION_REASONS:
        raise ValueError("invalid disposition reason")
    if len(note) > 4000:
        raise ValueError("note too long")
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        exists = session.execute(
            text("SELECT 1 FROM detections WHERE id=:detection_id AND tenant_id=:tenant_id"),
            {"detection_id": detection_id, "tenant_id": tenant_id},
        ).first()
        if exists is None:
            return 0
        case = session.execute(
            text("SELECT case_id FROM case_detection_links WHERE tenant_id=:tenant_id AND detection_id=:detection_id ORDER BY created_at DESC LIMIT 1"),
            {"tenant_id": tenant_id, "detection_id": detection_id},
        ).first()
        row = session.execute(
            text(
                "INSERT INTO analyst_dispositions (tenant_id,detection_id,case_id,analyst,reason,note,created_at) "
                "VALUES (:tenant_id,:detection_id,:case_id,:analyst,:reason,:note,:created_at) RETURNING id"
            ),
            {"tenant_id": tenant_id, "detection_id": detection_id, "case_id": case[0] if case else None, "analyst": analyst, "reason": reason, "note": note, "created_at": datetime.now(timezone.utc)},
        ).scalar_one()
        session.commit()
        return int(row)


def create_case(tenant_id: str, owner: str, detection_id: int, title: str | None) -> dict[str, Any]:
    if len(owner) > 255 or not owner:
        raise ValueError("invalid owner")
    if title is not None and len(title) > 500:
        raise ValueError("title too long")
    now = datetime.now(timezone.utc)
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        detection = session.execute(
            text("SELECT subject FROM detections WHERE id=:detection_id AND tenant_id=:tenant_id"),
            {"detection_id": detection_id, "tenant_id": tenant_id},
        ).first()
        if detection is None:
            return {}
        case_title = title.strip() if title and title.strip() else f"Investigation: {detection[0]}"
        case_row = session.execute(
            text("INSERT INTO cases (tenant_id,title,status,owner,created_at) VALUES (:tenant_id,:title,'open',:owner,:created_at) RETURNING id"),
            {"tenant_id": tenant_id, "title": case_title, "owner": owner, "created_at": now},
        ).scalar_one()
        case_id = int(case_row)
        session.execute(
            text("INSERT INTO case_detection_links (tenant_id,case_id,detection_id,created_by,created_at) VALUES (:tenant_id,:case_id,:detection_id,:owner,:created_at)"),
            {"tenant_id": tenant_id, "case_id": case_id, "detection_id": detection_id, "owner": owner, "created_at": now},
        )
        session.commit()
    return {"id": case_id, "title": case_title, "status": "open", "owner": owner, "created_at": now.isoformat()}
