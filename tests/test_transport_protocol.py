from __future__ import annotations

from pathlib import Path

import pytest

from core.data_plane import SignalEvent
from core.offline_transport import EvidenceSigner
from core.transport_batch import sign_batch, verify_and_accept_batch
from core.transport_protocol import DurableReplayLedger, SigningTrustStore


def make_event(seq_id: str) -> SignalEvent:
    from datetime import datetime, timezone
    return SignalEvent(event_id=seq_id, sensor_id="s", tenant_id="t", kind="signal", observed_at=datetime(2026, 8, 24, tzinfo=timezone.utc))


def record(seq: int, event_id: str) -> dict:
    return {"sequence_no": seq, "tenant_id": "t", "sensor_id": "s", "payload": make_event(event_id).canonical_bytes()}


def test_durable_replay_ledger_survives_restart(tmp_path: Path):
    db = tmp_path / "replay.db"; ledger = DurableReplayLedger(db)
    assert ledger.accept(batch_id="b1", tenant_id="t", sensor_id="s", first_sequence=1, last_sequence=2) == "accepted"
    ledger.close(); ledger = DurableReplayLedger(db)
    assert ledger.accept(batch_id="b1", tenant_id="t", sensor_id="s", first_sequence=1, last_sequence=2) == "duplicate"
    assert ledger.accept(batch_id="b0", tenant_id="t", sensor_id="s", first_sequence=1, last_sequence=1) == "replay"
    assert ledger.accept(batch_id="b3", tenant_id="t", sensor_id="s", first_sequence=4, last_sequence=4) == "gap"


def test_signed_batch_is_verified_before_replay_acceptance(tmp_path: Path):
    signer = EvidenceSigner(); ledger = DurableReplayLedger(tmp_path / "replay.db")
    batch = sign_batch([record(1, "e1"), record(2, "e2")], tenant_id="t", sensor_id="s", batch_id="b1", signer=signer)
    assert verify_and_accept_batch(batch, trusted_key=signer.metadata, replay_ledger=ledger, expected_tenant="t", expected_sensor="s") == "accepted"
    assert verify_and_accept_batch(batch, trusted_key=signer.metadata, replay_ledger=ledger, expected_tenant="t", expected_sensor="s") == "duplicate"


def test_signed_batch_tenant_and_signature_fail_closed(tmp_path: Path):
    signer = EvidenceSigner(); ledger = DurableReplayLedger(tmp_path / "replay.db")
    batch = sign_batch([record(1, "e1")], tenant_id="t", sensor_id="s", batch_id="b1", signer=signer)
    with pytest.raises(ValueError, match="tenant or sensor mismatch"):
        verify_and_accept_batch(batch, trusted_key=signer.metadata, replay_ledger=ledger, expected_tenant="other", expected_sensor="s")
    from dataclasses import replace
    with pytest.raises(ValueError):
        verify_and_accept_batch(replace(batch, first_sequence=99), trusted_key=signer.metadata, replay_ledger=ledger, expected_tenant="t", expected_sensor="s")


def test_trust_store_rotation_and_revocation(tmp_path: Path):
    store = SigningTrustStore(tmp_path / "keys.db"); first = EvidenceSigner().metadata; second = EvidenceSigner().metadata
    store.add(first); store.add(second); assert store.get(first.key_id) is not None
    store.revoke(first.key_id); assert store.get(first.key_id).revoked_at is not None
    assert second.key_id in {key.key_id for key in store.active_keys()}; assert first.key_id not in {key.key_id for key in store.active_keys()}


def test_trust_store_rejects_revoked_key(tmp_path: Path):
    store = SigningTrustStore(tmp_path / "keys.db"); signer = EvidenceSigner()
    revoked = signer.metadata.__class__(**{**signer.metadata.__dict__, "revoked_at": "2026-08-24T00:00:00+00:00"})
    with pytest.raises(ValueError): store.add(revoked)
