"""Phase 2 validation gate: offline transport, signing and replay invariants."""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.data_plane import SignalEvent
from core.offline_transport import EvidenceSigner, DurableEventQueue, QueuePolicy, build_evidence_package, verify_evidence_package
from core.transport_batch import sign_batch, verify_and_accept_batch
from core.transport_protocol import DurableReplayLedger, SigningTrustStore


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        event = SignalEvent(event_id="phase2-validation", sensor_id="sensor-validation", tenant_id="tenant-validation", kind="signal", observed_at=datetime(2026, 8, 24, tzinfo=timezone.utc))
        queue = DurableEventQueue(root / "queue.db", policy=QueuePolicy(max_bytes=4 * 1024 * 1024, max_events=100))
        assert queue.enqueue(event, priority=100) == 1
        queue.close()
        queue = DurableEventQueue(root / "queue.db", policy=QueuePolicy(max_bytes=4 * 1024 * 1024, max_events=100))
        records = queue.peek()
        signer = EvidenceSigner()
        batch = sign_batch(records, tenant_id="tenant-validation", sensor_id="sensor-validation", batch_id="phase2-batch", signer=signer)
        ledger = DurableReplayLedger(root / "replay.db")
        assert verify_and_accept_batch(batch, trusted_key=signer.metadata, replay_ledger=ledger, expected_tenant="tenant-validation", expected_sensor="sensor-validation") == "accepted"
        assert verify_and_accept_batch(batch, trusted_key=signer.metadata, replay_ledger=ledger, expected_tenant="tenant-validation", expected_sensor="sensor-validation") == "duplicate"
        package = build_evidence_package(tenant_id=event.tenant_id, sensor_id=event.sensor_id, events=[event], evidence=[{"type": "signal", "digest": event.digest()}], provenance={"validator": "phase2"}, signer=signer)
        assert verify_evidence_package(package, {signer.key_id: signer.metadata}, tenant_id=event.tenant_id)["verified"]
        trust = SigningTrustStore(root / "trust.db")
        trust.add(signer.metadata)
        trust.revoke(signer.key_id)
        assert trust.get(signer.key_id).revoked_at is not None
        print("Phase 2 offline evidence validation: GREEN")


if __name__ == "__main__":
    main()
