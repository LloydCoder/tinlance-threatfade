"""Evidence integrity, provenance, investigation timeline and retention primitives."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from uuid import uuid4
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .integrity import GENESIS_HASH, evidence_custody_hash, sha256_json, verify_content
from .storage import (
    ENGINE, EvidenceRecord, LegalHoldRecord, ProvenanceRecord, RetentionPolicyRecord,
    TimelineEventRecord, set_tenant_context,
)


def register_evidence(*, tenant_id: str, correlation_id: str, evidence_type: str, media_type: str, content: bytes, source_uri: str | None = None, case_id: int | None = None, metadata: dict[str, Any] | None = None, collected_at: datetime | None = None) -> EvidenceRecord:
    collected = collected_at or datetime.now(timezone.utc)
    content_sha256 = sha256(content).hexdigest()
    metadata = metadata or {}
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        previous = session.scalar(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.id.desc()).limit(1))
        previous_hash = GENESIS_HASH if previous is None else previous.custody_hash
        custody_hash = evidence_custody_hash(
            previous_hash=previous_hash, tenant_id=tenant_id, correlation_id=correlation_id,
            evidence_type=evidence_type, content_sha256=content_sha256, size_bytes=len(content),
            source_uri=source_uri, collected_at=collected.isoformat(),
        )
        record = EvidenceRecord(
            tenant_id=tenant_id, correlation_id=correlation_id, case_id=case_id,
            evidence_type=evidence_type, media_type=media_type, source_uri=source_uri,
            content_sha256=content_sha256, size_bytes=len(content), metadata_json=json.dumps(metadata, sort_keys=True),
            previous_hash=previous_hash, custody_hash=custody_hash, collected_at=collected,
            created_at=datetime.now(timezone.utc),
        )
        session.add(record); session.commit(); session.refresh(record)
        return record


def verify_evidence(content: bytes, evidence: EvidenceRecord) -> bool:
    return verify_content(content, evidence.content_sha256)


def evidence_manifest(tenant_id: str, correlation_id: str | None = None) -> dict[str, Any]:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        query = select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.id.asc())
        if correlation_id:
            query = query.where(EvidenceRecord.correlation_id == correlation_id)
        rows = list(session.scalars(query))
    items = [{"id": row.id, "type": row.evidence_type, "sha256": row.content_sha256, "size": row.size_bytes, "custody_hash": row.custody_hash, "previous_hash": row.previous_hash} for row in rows]
    return {"tenant_id": tenant_id, "correlation_id": correlation_id, "items": items, "manifest_sha256": sha256_json({"items": items})}


def record_provenance(*, tenant_id: str, correlation_id: str, input_sha256: str, rule_pack_sha256: str, engine_version: str, config_sha256: str, model_sha256: str | None = None, detection_id: int | None = None, provenance: dict[str, Any] | None = None) -> ProvenanceRecord:
    payload = provenance or {
        "input_sha256": input_sha256, "rule_pack_sha256": rule_pack_sha256,
        "engine_version": engine_version, "model_sha256": model_sha256, "config_sha256": config_sha256,
    }
    provenance_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    provenance_sha256 = sha256(provenance_json.encode("utf-8")).hexdigest()
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        record = ProvenanceRecord(
            tenant_id=tenant_id, correlation_id=correlation_id, detection_id=detection_id,
            input_sha256=input_sha256, rule_pack_sha256=rule_pack_sha256, engine_version=engine_version,
            model_sha256=model_sha256, config_sha256=config_sha256, provenance_sha256=provenance_sha256,
            provenance_json=provenance_json, created_at=datetime.now(timezone.utc),
        )
        session.add(record); session.commit(); session.refresh(record)
        return record


def add_timeline_event(*, tenant_id: str, case_id: int, actor: str, event_type: str, summary: str, correlation_id: str, payload: dict[str, Any] | None = None) -> TimelineEventRecord:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        record = TimelineEventRecord(
            tenant_id=tenant_id, case_id=case_id, correlation_id=correlation_id, actor=actor,
            event_type=event_type, summary=summary, payload_json=json.dumps(payload or {}, sort_keys=True),
            created_at=datetime.now(timezone.utc),
        )
        session.add(record); session.commit(); session.refresh(record)
        return record


def set_retention_policy(*, tenant_id: str, retention_days: int, evidence_retention_days: int, updated_by: str) -> RetentionPolicyRecord:
    if retention_days < 1 or evidence_retention_days < 1:
        raise ValueError("retention periods must be positive")
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        record = session.scalar(select(RetentionPolicyRecord).where(RetentionPolicyRecord.tenant_id == tenant_id))
        now = datetime.now(timezone.utc)
        if record is None:
            record = RetentionPolicyRecord(tenant_id=tenant_id, retention_days=retention_days, evidence_retention_days=evidence_retention_days, updated_by=updated_by, updated_at=now)
            session.add(record)
        else:
            record.retention_days = retention_days; record.evidence_retention_days = evidence_retention_days; record.updated_by = updated_by; record.updated_at = now
        session.commit(); session.refresh(record)
        return record


def create_legal_hold(*, tenant_id: str, reason: str, created_by: str) -> LegalHoldRecord:
    if not reason.strip():
        raise ValueError("legal hold reason is required")
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        record = LegalHoldRecord(tenant_id=tenant_id, hold_id=str(uuid4()), reason=reason, active=1, created_by=created_by, created_at=datetime.now(timezone.utc))
        session.add(record); session.commit(); session.refresh(record)
        return record


def release_legal_hold(tenant_id: str, hold_id: str) -> LegalHoldRecord:
    with Session(ENGINE) as session:
        set_tenant_context(session, tenant_id)
        record = session.scalar(select(LegalHoldRecord).where(LegalHoldRecord.tenant_id == tenant_id, LegalHoldRecord.hold_id == hold_id))
        if record is None:
            raise ValueError("legal hold not found")
        record.active = 0; record.released_at = datetime.now(timezone.utc)
        session.commit(); session.refresh(record)
        return record
