"""Signed transport envelopes for store-and-forward ingestion."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .offline_transport import EvidenceSigner, SigningKey, _canonical, batch_payload, verify_signature
from .transport_protocol import DurableReplayLedger


@dataclass(frozen=True)
class SignedBatch:
    batch_id: str
    tenant_id: str
    sensor_id: str
    first_sequence: int
    last_sequence: int
    payload_b64: str
    signature_b64: str
    signing_key_id: str

    def canonical(self) -> bytes:
        return _canonical(self.__dict__)


def sign_batch(records: Sequence[Mapping[str, Any]], *, tenant_id: str, sensor_id: str, batch_id: str, signer: EvidenceSigner) -> SignedBatch:
    payload = batch_payload(records, tenant_id=tenant_id, sensor_id=sensor_id, batch_id=batch_id)
    decoded = json.loads(payload)
    signature = signer.sign(payload)
    return SignedBatch(batch_id=batch_id, tenant_id=tenant_id, sensor_id=sensor_id, first_sequence=decoded["first_sequence"], last_sequence=decoded["last_sequence"], payload_b64=base64.b64encode(payload).decode(), signature_b64=signature, signing_key_id=signer.key_id)


def verify_and_accept_batch(batch: SignedBatch, *, trusted_key: SigningKey, replay_ledger: DurableReplayLedger, expected_tenant: str, expected_sensor: str) -> str:
    if batch.tenant_id != expected_tenant or batch.sensor_id != expected_sensor:
        raise ValueError("tenant or sensor mismatch")
    if batch.signing_key_id != trusted_key.key_id:
        raise ValueError("signing key mismatch")
    payload = base64.b64decode(batch.payload_b64, validate=True)
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid batch payload") from exc
    if decoded.get("batch_id") != batch.batch_id or decoded.get("tenant_id") != batch.tenant_id or decoded.get("sensor_id") != batch.sensor_id:
        raise ValueError("batch envelope mismatch")
    if decoded.get("first_sequence") != batch.first_sequence or decoded.get("last_sequence") != batch.last_sequence:
        raise ValueError("batch sequence metadata mismatch")
    if not verify_signature(payload, batch.signature_b64, trusted_key):
        raise ValueError("batch signature verification failed")
    return replay_ledger.accept(batch_id=batch.batch_id, tenant_id=batch.tenant_id, sensor_id=batch.sensor_id, first_sequence=batch.first_sequence, last_sequence=batch.last_sequence)
