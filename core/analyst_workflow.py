"""Tenant-scoped persistence helpers for the SOC analyst workflow.

The Alembic migration is authoritative for production PostgreSQL. SQLite local
runs create the same workflow tables lazily so the analyst API remains usable
in the repository's development mode.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.storage import ENGINE, DetectionRecord, set_tenant_context

STATUSES = {"new", "triaging", "investigating", "contained", "resolved"}
DISPOSITION_REASONS = {
    "true_positive",
    "false_positive",
    "benign",
    "duplicate",
    "insufficient_evidence",
    "needs_tuning",
}
SORT_COLUMNS = {
    "created_at": "d.created_at",
    "score": "d.score",
    "priority": "COALESCE(w.priority, 50)",
    "id": "d.id",
}


def _ensure_sqlite_tables() -> None:
    if ENGINE.dialect.name != "sqlite":
        return
    ddl = (
        "CREATE TABLE IF NOT EXISTS detection_workflow ("
        "id INTEGER PRIMARY KEY, tenant_id VARCHAR(255) NOT NULL, detection_id INTEGER NOT NULL UNIQUE, "
        "status VARCHAR(32) NOT NULL DEFAULT 'new', assignee VARCHAR(255), priority INTEGER NOT NULL DEFAULT 50, "
        "updated_by VARCHAR(255) NOT NULL, updated_at DATETIME NOT NULL)",
        "CREATE INDEX IF NOT EXISTS ix_detection_workflow_tenant ON detection_workflow (tenant_id)",
        "CREATE INDEX IF NOT EXISTS ix_detection_workflow_detection ON detection_workflow (detection_id)",
        "CREATE TABLE IF NOT EXISTS case_detection_links ("
        "id INTEGER PRIMARY KEY, tenant_id VARCHAR(255) NOT NULL, case_id INTEGER NOT NULL, detection_id INTEGER NOT NULL, "
        "created_by VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL)",
        "CREATE INDEX IF NOT EXISTS ix_case_detection_links_tenant ON case_detection_links (tenant_id)",
        "CREATE INDEX IF NOT EXISTS ix_case_detection_links_case ON case_detection_links (case_id)",
        "CREATE INDEX IF NOT EXISTS ix_case_detection_links_detection ON case_detection_links (detection_id)",
        "CREATE TABLE IF NOT EXISTS analyst_dispositions ("
        "id INTEGER PRIMARY KEY, tenant_id VARCHAR(255) NOT NULL, detection_id INTEGER NOT NULL, case_id INTEGER, "
        "analyst VARCHAR(255) NOT NULL, reason VARCHAR(64) NOT NULL, note TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL)",
        "CREATE INDEX IF NOT EXISTS ix_analyst_dispositions_tenant ON analyst_dispositions (tenant_id)",
        "CREATE INDEX IF NOT EXISTS ix_analyst_dispositions_detection ON analyst_dispositions (detection_id)",
        "CREATE TABLE IF NOT EXISTS investigation_entities ("
        "id INTEGER PRIMARY KEY, tenant_id VARCHAR(255) NOT NULL, correlation_id VARCHAR(128), entity_type VARCHAR(64) NOT NULL, "
        "entity_key VARCHAR(255) NOT NULL, attributes_json TEXT NOT NULL DEFAULT '{}', created_at DATETIME NOT NULL)",
        "CREATE INDEX IF NOT EXISTS ix_investigation_entities_tenant ON investigation_entities (tenant_id)",
        "CREATE INDEX IF NOT EXISTS ix_investigation_entities_correlation ON investigation_entities (correlation_id)",
        "CREATE TABLE IF NOT EXISTS investigation_sessions ("
        "id INTEGER PRIMARY KEY, tenant_id VARCHAR(255) NOT NULL, session_key VARCHAR(255) NOT NULL, correlation_id VARCHAR(128), "
        "protocol VARCHAR(32), started_at DATETIME, ended_at DATETIME, attributes_json TEXT NOT NULL DEFAULT '{}')",
        "CREATE INDEX IF NOT EXISTS ix_investigation_sessions_tenant ON investigation_sessions (tenant_id)",
        "CREATE INDEX IF NOT EXISTS ix_investigation_sessions_correlation ON investigation_sessions (correlation_id)",
    )
    with ENGINE.begin() as connection:
        for statement in ddl:
            connection.execute(text(statement))


_ensure_sqlite_tables()


def _row_dict(row: Any) -> dict[str, Any]:
    return dict(row._mapping)


def list_inbox(
    tenant_id: str,
    *,
    status: str | None,
    limit: int,
    offset: int,
    sort: str,
    order: str,
) -> tuple[list[dict[str, Any]], int]:
    if status is not None and status not in STATUSES:
        raise ValueError("invalid workflow status")
    sort_sql = SORT_COLUMNS.get(sort, SORT_COLUMNS["created_at"])
    direction = "ASC" if order.lower() == "asc" else "DESC"
    where = "WHERE d.tenant_id = :tenant_id"
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit, "offset": offset}
    if status:
        where += " AND COALESCE(w.status, 'new') = :status"
        params["status"] = status
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        total = session.execute(
            text(
                "SELECT COUNT(*) FROM detections d "
                "LEFT JOIN detection_workflow w ON w.detection_id = d.id AND w.tenant_id = d.tenant_id "
                f"{where}"
            ),
            params,
        ).scalar_one()
        rows = session.execute(
            text(
                "SELECT d.id, d.subject, d.source, d.confidence, d.score, d.mitre_ttp, d.correlation_id, d.created_at, "
                "COALESCE(w.status, 'new') AS status, w.assignee, COALESCE(w.priority, 50) AS priority "
                "FROM detections d LEFT JOIN detection_workflow w "
                "ON w.detection_id = d.id AND w.tenant_id = d.tenant_id "
                f"{where} ORDER BY {sort_sql} {direction}, d.id DESC LIMIT :limit OFFSET :offset"
            ),
            params,
        ).mappings().all()
    return [_row_dict(row) for row in rows], int(total)


def get_investigation(tenant_id: str, detection_id: int) -> dict[str, Any] | None:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        detection = session.scalars(
            text("SELECT id FROM detections WHERE id=:detection_id AND tenant_id=:tenant_id"),
            {"detection_id": detection_id, "tenant_id": tenant_id},
        ).first()
        if detection is None:
            return None
        row = session.execute(
            text(
                "SELECT d.id, d.subject, d.source, d.confidence, d.score, d.mitre_ttp, d.correlation_id, d.created_at, "
                "d.evidence_json, d.input_sha256, d.rule_pack_sha256, d.engine_version, d.model_sha256, d.config_sha256, "
                "COALESCE(w.status, 'new') AS status, w.assignee, COALESCE(w.priority, 50) AS priority "
                "FROM detections d LEFT JOIN detection_workflow w "
                "ON w.detection_id=d.id AND w.tenant_id=d.tenant_id "
                "WHERE d.id=:detection_id AND d.tenant_id=:tenant_id"
            ),
            {"detection_id": detection_id, "tenant_id": tenant_id},
        ).mappings().one()
        correlation_id = row["correlation_id"]
        evidence = []
        entities = []
        sessions = []
        if correlation_id:
            evidence = [
                _row_dict(item)
                for item in session.execute(
                    text(
                        "SELECT id, evidence_type AS type, media_type, content_sha256 AS hash, size_bytes, collected_at, "
                        "source_uri FROM evidence WHERE tenant_id=:tenant_id AND correlation_id=:correlation_id ORDER BY collected_at ASC"
                    ),
                    {"tenant_id": tenant_id, "correlation_id": correlation_id},
                ).mappings().all()
            ]
            entities = [
                _row_dict(item)
                for item in session.execute(
                    text(
                        "SELECT id, entity_type, entity_key, attributes_json, created_at FROM investigation_entities "
                        "WHERE tenant_id=:tenant_id AND correlation_id=:correlation_id ORDER BY created_at ASC"
                    ),
                    {"tenant_id": tenant_id, "correlation_id": correlation_id},
                ).mappings().all()
            ]
            sessions = [
                _row_dict(item)
                for item in session.execute(
                    text(
                        "SELECT id, session_key, protocol, started_at, ended_at, attributes_json FROM investigation_sessions "
                        "WHERE tenant_id=:tenant_id AND correlation_id=:correlation_id ORDER BY started_at ASC"
                    ),
                    {"tenant_id": tenant_id, "correlation_id": correlation_id},
                ).mappings().all()
            ]
        dispositions = [
            _row_dict(item)
            for item in session.execute(
                text(
                    "SELECT id, reason, note, analyst, case_id, created_at FROM analyst_dispositions "
                    "WHERE tenant_id=:tenant_id AND detection_id=:detection_id ORDER BY created_at ASC"
                ),
                {"tenant_id": tenant_id, "detection_id": detection_id},
            ).mappings().all()
        ]
        cases = [
            _row_dict(item)
            for item in session.execute(
                text(
                    "SELECT c.id, c.title, c.status, c.owner, c.created_at FROM cases c "
                    "JOIN case_detection_links l ON l.case_id=c.id AND l.tenant_id=c.tenant_id "
                    "WHERE l.tenant_id=:tenant_id AND l.detection_id=:detection_id ORDER BY c.created_at DESC"
                ),
                {"tenant_id": tenant_id, "detection_id": detection_id},
            ).mappings().all()
        ]
    return {
        "detection": {
            "id": row["id"],
            "subject": row["subject"],
            "source": row["source"],
            "confidence": row["confidence"],
            "score": float(row["score"]),
            "mitre_ttp": row["mitre_ttp"],
            "correlation_id": row["correlation_id"],
            "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
            "evidence": json.loads(row["evidence_json"] or "{}"),
            "provenance": {
                "input_sha256": row["input_sha256"],
                "rule_pack_sha256": row["rule_pack_sha256"],
                "engine_version": row["engine_version"],
                "model_sha256": row["model_sha256"],
                "config_sha256": row["config_sha256"],
            },
        },
        "workflow": {"status": row["status"], "assignee": row["assignee"], "priority": int(row["priority"])},
        "evidence": evidence,
        "entities": [
            {**item, "attributes": json.loads(item.pop("attributes_json") or "{}")}
            for item in entities
        ],
        "sessions": [
            {**item, "attributes": json.loads(item.pop("attributes_json") or "{}")}
            for item in sessions
        ],
        "dispositions": dispositions,
        "cases": cases,
    }


def update_workflow(tenant_id: str, detection_id: int, actor: str, *, status: str | None, assignee: str | None, priority: int | None) -> None:
    if status is not None and status not in STATUSES:
        raise ValueError("invalid workflow status")
    if assignee is not None and (len(assignee) > 255 or not assignee.strip()):
        raise ValueError("invalid assignee")
    if priority is not None and not 0 <= priority <= 100:
        raise ValueError("invalid priority")
    now = datetime.now(timezone.utc)
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        exists = session.execute(
            text("SELECT 1 FROM detections WHERE id=:detection_id AND tenant_id=:tenant_id"),
            {"detection_id": detection_id, "tenant_id": tenant_id},
        ).first()
        if exists is None:
            return
        current = session.execute(
            text("SELECT status, assignee, priority FROM detection_workflow WHERE detection_id=:detection_id AND tenant_id=:tenant_id"),
            {"detection_id": detection_id, "tenant_id": tenant_id},
        ).mappings().first()
        if current is None:
            session.execute(
                text(
                    "INSERT INTO detection_workflow (tenant_id,detection_id,status,assignee,priority,updated_by,updated_at) "
                    "VALUES (:tenant_id,:detection_id,:status,:assignee,:priority,:actor,:updated_at)"
                ),
                {"tenant_id": tenant_id, "detection_id": detection_id, "status": status or "new", "assignee": assignee, "priority": priority if priority is not None else 50, "actor": actor, "updated_at": now},
            )
        else:
            session.execute(
                text(
                    "UPDATE detection_workflow SET status=:status, assignee=:assignee, priority=:priority, updated_by=:actor, updated_at=:updated_at "
                    "WHERE detection_id=:detection_id AND tenant_id=:tenant_id"
                ),
                {"tenant_id": tenant_id, "detection_id": detection_id, "status": status or current["status"], "assignee": assignee if assignee is not None else current["assignee"], "priority": priority if priority is not None else current["priority"], "actor": actor, "updated_at": now},
            )
        session.commit()


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
        result = session.execute(
            text(
                "INSERT INTO analyst_dispositions (tenant_id,detection_id,case_id,analyst,reason,note,created_at) "
                "VALUES (:tenant_id,:detection_id,:case_id,:analyst,:reason,:note,:created_at)"
            ),
            {"tenant_id": tenant_id, "detection_id": detection_id, "case_id": case[0] if case else None, "analyst": analyst, "reason": reason, "note": note, "created_at": datetime.now(timezone.utc)},
        )
        session.commit()
        return int(result.lastrowid)


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
        result = session.execute(
            text("INSERT INTO cases (tenant_id,title,status,owner,created_at) VALUES (:tenant_id,:title,'open',:owner,:created_at)"),
            {"tenant_id": tenant_id, "title": case_title, "owner": owner, "created_at": now},
        )
        case_id = int(result.lastrowid)
        session.execute(
            text("INSERT INTO case_detection_links (tenant_id,case_id,detection_id,created_by,created_at) VALUES (:tenant_id,:case_id,:detection_id,:owner,:created_at)"),
            {"tenant_id": tenant_id, "case_id": case_id, "detection_id": detection_id, "owner": owner, "created_at": now},
        )
        session.commit()
    return {"id": case_id, "title": case_title, "status": "open", "owner": owner, "created_at": now.isoformat()}


def timeline(tenant_id: str, detection_id: int) -> list[dict[str, Any]]:
    investigation = get_investigation(tenant_id, detection_id)
    if investigation is None:
        return []
    items: list[dict[str, Any]] = []
    for item in investigation["evidence"]:
        items.append({"timestamp": item["collected_at"].isoformat() if hasattr(item["collected_at"], "isoformat") else item["collected_at"], "kind": "evidence", "evidence_type": item["type"], "hash": item["hash"]})
    for item in investigation["dispositions"]:
        items.append({"timestamp": item["created_at"].isoformat() if hasattr(item["created_at"], "isoformat") else item["created_at"], "kind": "case_event", "event_type": "analyst_disposition", "payload": {"reason": item["reason"], "analyst": item["analyst"], "note": item["note"]}})
    items.sort(key=lambda item: item["timestamp"])
    return items
