from datetime import datetime, timezone

from core.integrity import GENESIS_HASH, audit_event_hash, evidence_custody_hash, verify_hash_chain


def test_audit_chain_is_tamper_evident():
    first = audit_event_hash(prev_hash=GENESIS_HASH, sequence_no=1, tenant_id="t", actor="a", action="create", object_type="x", object_id="1", outcome="success", reason="", request_id=None, correlation_id="c", before=None, after={"state": "open"}, created_at=datetime.now(timezone.utc).isoformat())
    second = audit_event_hash(prev_hash=first, sequence_no=2, tenant_id="t", actor="a", action="update", object_type="x", object_id="1", outcome="success", reason="", request_id=None, correlation_id="c", before={"state": "open"}, after={"state": "closed"}, created_at=datetime.now(timezone.utc).isoformat())
    assert verify_hash_chain([{"prev": GENESIS_HASH, "hash": first}, {"prev": first, "hash": second}], hash_field="hash", previous_field="prev")
    assert not verify_hash_chain([{"prev": GENESIS_HASH, "hash": first}, {"prev": "f" * 64, "hash": second}], hash_field="hash", previous_field="prev")


def test_evidence_custody_hash_changes_when_content_changes():
    kwargs = dict(previous_hash=GENESIS_HASH, tenant_id="t", correlation_id="c", evidence_type="pcap", size_bytes=4, source_uri="ci://fixture", collected_at=datetime.now(timezone.utc).isoformat())
    first = evidence_custody_hash(content_sha256="a" * 64, **kwargs)
    second = evidence_custody_hash(content_sha256="b" * 64, **kwargs)
    assert first != second
    assert len(first) == 64
