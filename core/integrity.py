"""Cryptographic integrity primitives for audit and evidence chains."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Mapping

GENESIS_HASH = "0" * 64


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(value: Mapping[str, Any]) -> str:
    return sha256(canonical_json(value)).hexdigest()


def audit_event_hash(*, prev_hash: str, sequence_no: int, tenant_id: str, actor: str, action: str, object_type: str, object_id: str, outcome: str, reason: str, request_id: str | None, correlation_id: str | None, before: Any, after: Any, created_at: str) -> str:
    payload = {
        "prev_hash": prev_hash, "sequence_no": sequence_no, "tenant_id": tenant_id,
        "actor": actor, "action": action, "object_type": object_type, "object_id": object_id,
        "outcome": outcome, "reason": reason, "request_id": request_id,
        "correlation_id": correlation_id, "before": before, "after": after, "created_at": created_at,
    }
    return sha256_json(payload)


def evidence_custody_hash(*, previous_hash: str, tenant_id: str, correlation_id: str, evidence_type: str, content_sha256: str, size_bytes: int, source_uri: str | None, collected_at: str) -> str:
    payload = {
        "previous_hash": previous_hash, "tenant_id": tenant_id, "correlation_id": correlation_id,
        "evidence_type": evidence_type, "content_sha256": content_sha256, "size_bytes": size_bytes,
        "source_uri": source_uri, "collected_at": collected_at,
    }
    return sha256_json(payload)


def verify_hash_chain(events: list[Mapping[str, Any]], *, hash_field: str, previous_field: str, genesis: str = GENESIS_HASH) -> bool:
    previous = genesis
    for event in events:
        if event.get(previous_field) != previous:
            return False
        previous = str(event.get(hash_field, ""))
        if len(previous) != 64:
            return False
    return True


def verify_content(content: bytes, expected_sha256: str) -> bool:
    return sha256(content).hexdigest() == expected_sha256
