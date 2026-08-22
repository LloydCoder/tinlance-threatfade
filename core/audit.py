"""Append-only, hash-chained audit service."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .integrity import GENESIS_HASH, audit_event_hash, verify_hash_chain
from .storage import AuditEventRecord, ENGINE, set_tenant_context


def append_event(*, tenant_id: str, actor: str, action: str, object_type: str, object_id: str, outcome: str, reason: str = "", request_id: str | None = None, correlation_id: str | None = None, source_ip: str | None = None, auth_method: str | None = None, auth_decision: str | None = None, before: Any = None, after: Any = None) -> AuditEventRecord:
    now = datetime.now(timezone.utc)
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        previous = session.scalar(select(AuditEventRecord).where(AuditEventRecord.tenant_id == tenant_id).order_by(AuditEventRecord.sequence_no.desc()).limit(1))
        sequence = time.time_ns()
        while previous is not None and sequence <= previous.sequence_no:
            sequence += 1
        prev_hash = GENESIS_HASH if previous is None else previous.event_hash
        created_at = now.isoformat()
        event_hash = audit_event_hash(
            prev_hash=prev_hash, sequence_no=sequence, tenant_id=tenant_id, actor=actor,
            action=action, object_type=object_type, object_id=object_id, outcome=outcome,
            reason=reason, request_id=request_id, correlation_id=correlation_id,
            before=before, after=after, created_at=created_at,
        )
        event = AuditEventRecord(
            sequence_no=sequence, tenant_id=tenant_id, actor=actor, action=action,
            object_type=object_type, object_id=object_id, outcome=outcome, reason=reason,
            request_id=request_id, correlation_id=correlation_id, source_ip=source_ip,
            auth_method=auth_method, auth_decision=auth_decision,
            before_json=json.dumps(before, sort_keys=True) if before is not None else None,
            after_json=json.dumps(after, sort_keys=True) if after is not None else None,
            prev_hash=prev_hash, event_hash=event_hash, created_at=now,
        )
        session.add(event)
        session.commit()
        session.refresh(event)
        return event


def list_events(tenant_id: str, limit: int = 1000) -> list[AuditEventRecord]:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        return list(session.scalars(select(AuditEventRecord).where(AuditEventRecord.tenant_id == tenant_id).order_by(AuditEventRecord.sequence_no.asc()).limit(limit)))


def verify_events(events: list[AuditEventRecord]) -> bool:
    rows = [{"prev_hash": event.prev_hash, "event_hash": event.event_hash} for event in events]
    return verify_hash_chain(rows, hash_field="event_hash", previous_field="prev_hash")


def export_jsonl(tenant_id: str, limit: int = 10000) -> str:
    events = list_events(tenant_id, limit)
    lines = []
    for event in events:
        lines.append(json.dumps({
            "sequence_no": event.sequence_no, "tenant_id": event.tenant_id, "actor": event.actor,
            "action": event.action, "object_type": event.object_type, "object_id": event.object_id,
            "outcome": event.outcome, "reason": event.reason, "request_id": event.request_id,
            "correlation_id": event.correlation_id, "source_ip": event.source_ip,
            "auth_method": event.auth_method, "auth_decision": event.auth_decision,
            "before": json.loads(event.before_json) if event.before_json else None,
            "after": json.loads(event.after_json) if event.after_json else None,
            "prev_hash": event.prev_hash, "event_hash": event.event_hash,
            "created_at": event.created_at.isoformat(),
        }, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")
