from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.data_plane import SignalEvent
from core.offline_transport import BandwidthAwareTransmitter, BandwidthPolicy, DurableEventQueue, EvidenceSigner, QueuePolicy, ReplayProtector, SigningKey, build_evidence_package, batch_payload, verify_evidence_package, verify_signature


def event(*, tenant: str = "tenant-a", sensor: str = "sensor-a", event_id: str = "event-1", at: datetime | None = None) -> SignalEvent:
    return SignalEvent(event_id=event_id, sensor_id=sensor, tenant_id=tenant, kind="signal", observed_at=at or datetime(2026, 8, 24, tzinfo=timezone.utc), metadata={"quality": 0.9})


def test_queue_is_durable_bounded_and_idempotent(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    q = DurableEventQueue(db, policy=QueuePolicy(max_bytes=2048, max_events=3, retention_seconds=3600))
    assert q.enqueue(event(event_id="a"), priority=90) == 1
    assert q.enqueue(event(event_id="a")) == 1
    assert q.count() == 1
    q.close(); q2 = DurableEventQueue(db, policy=QueuePolicy(max_bytes=2048, max_events=3, retention_seconds=3600))
    assert q2.count() == 1 and q2.peek()[0]["sequence_no"] == 1


def test_queue_sequences_are_scoped_per_sensor_and_tenant(tmp_path: Path):
    q = DurableEventQueue(tmp_path / "q.db", policy=QueuePolicy(max_bytes=4096))
    assert q.enqueue(event(event_id="a", sensor="s1")) == 1
    assert q.enqueue(event(event_id="b", sensor="s1")) == 2
    assert q.enqueue(event(event_id="c", sensor="s2")) == 1
    assert [r["sequence_no"] for r in q.peek(tenant_id="tenant-a", sensor_id="s1")] == [1, 2]
    assert [r["sequence_no"] for r in q.peek(tenant_id="tenant-a", sensor_id="s2")] == [1]


def test_queue_eviction_is_low_priority_first(tmp_path: Path):
    q = DurableEventQueue(tmp_path / "q.db", policy=QueuePolicy(max_bytes=900, max_events=10, retention_seconds=3600))
    q.enqueue(event(event_id="low"), priority=1); q.enqueue(event(event_id="high"), priority=100); q.enqueue(event(event_id="new"), priority=50)
    payloads = {r["payload"] for r in q.peek()}
    assert len(payloads) <= 2 and any(b'"event_id":"high"' in payload for payload in payloads)


def test_queue_expiry_does_not_evict_critical(tmp_path: Path):
    q = DurableEventQueue(tmp_path / "q.db", policy=QueuePolicy(retention_seconds=1))
    q.enqueue(event(event_id="critical"), priority=100); q.enqueue(event(event_id="normal"), priority=50); q._db.execute("UPDATE events SET inserted_at=?", (0,))
    assert q.expire(now=10) == 1 and q.count() == 1 and b'"event_id":"critical"' in q.peek()[0]["payload"]


def test_queue_fails_explicitly_when_disk_headroom_is_unavailable(tmp_path: Path, monkeypatch):
    import core.offline_transport as transport
    class Usage: free = 0
    monkeypatch.setattr(transport.shutil, "disk_usage", lambda _: Usage())
    q = DurableEventQueue(tmp_path / "q.db", policy=QueuePolicy(max_bytes=4096, min_free_bytes=1))
    with pytest.raises(OSError, match="free-space"): q.enqueue(event())


def test_bandwidth_planner_never_exceeds_batch_budget():
    tx = BandwidthAwareTransmitter(BandwidthPolicy(bytes_per_second=1000, burst_bytes=1000, max_batch_bytes=500))
    records = [{"payload": b"x" * 200}, {"payload": b"y" * 200}, {"payload": b"z" * 200}]
    assert sum(len(r["payload"]) for r in tx.select(records)) <= 500


def test_replay_protector_handles_duplicate_replay_and_gap():
    p = ReplayProtector()
    assert p.accept(batch_id="b1", tenant_id="t", sensor_id="s", first_sequence=1, last_sequence=2) == "accepted"
    assert p.accept(batch_id="b1", tenant_id="t", sensor_id="s", first_sequence=1, last_sequence=2) == "duplicate"
    assert p.accept(batch_id="b0", tenant_id="t", sensor_id="s", first_sequence=1, last_sequence=1) == "replay"
    assert p.accept(batch_id="b3", tenant_id="t", sensor_id="s", first_sequence=4, last_sequence=4) == "gap"


def test_batch_rejects_reordered_sequences():
    records = [{"sequence_no": 2, "tenant_id": "t", "sensor_id": "s", "payload": b"{}"}, {"sequence_no": 1, "tenant_id": "t", "sensor_id": "s", "payload": b"{}"}]
    with pytest.raises(ValueError): batch_payload(records, tenant_id="t", sensor_id="s", batch_id="b")


def test_signed_package_is_deterministically_verifiable_offline():
    signer = EvidenceSigner(); package = build_evidence_package(tenant_id="t", sensor_id="s", events=[event(tenant="t", sensor="s")], evidence=[{"sha": "abc", "kind": "pcap"}], provenance={"source": "air-gap"}, signer=signer)
    assert verify_evidence_package(package, {signer.key_id: signer.metadata}, tenant_id="t")["verified"]


def test_tampered_package_fails():
    signer = EvidenceSigner(); package = bytearray(build_evidence_package(tenant_id="t", sensor_id="s", events=[event(tenant="t", sensor="s")], signer=signer)); package[-20] ^= 0x01
    with pytest.raises(Exception): verify_evidence_package(bytes(package), {signer.key_id: signer.metadata})


def test_tenant_mismatch_fails_closed():
    signer = EvidenceSigner(); package = build_evidence_package(tenant_id="t-a", sensor_id="s", events=[event(tenant="t-a", sensor="s")], signer=signer)
    with pytest.raises(ValueError, match="tenant mismatch"): verify_evidence_package(package, {signer.key_id: signer.metadata}, tenant_id="t-b")


def test_revoked_and_expired_keys_fail():
    signer = EvidenceSigner(); payload = b"evidence"; signature = signer.sign(payload)
    revoked = SigningKey(**{**signer.metadata.__dict__, "revoked_at": datetime.now(timezone.utc).isoformat()}); expired = SigningKey(**{**signer.metadata.__dict__, "not_after": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()})
    assert not verify_signature(payload, signature, revoked) and not verify_signature(payload, signature, expired)


def test_package_rejects_modified_event_content():
    signer = EvidenceSigner(); package = build_evidence_package(tenant_id="t", sensor_id="s", events=[event(tenant="t", sensor="s")], signer=signer)
    import io, json, zipfile
    source = zipfile.ZipFile(io.BytesIO(package), "r"); out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in source.namelist():
            content = source.read(name)
            if name == "events.json":
                data = json.loads(content); data[0]["event_id"] = "attacker"; content = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
            z.writestr(name, content)
    with pytest.raises(ValueError, match="event content digest"): verify_evidence_package(out.getvalue(), {signer.key_id: signer.metadata})
