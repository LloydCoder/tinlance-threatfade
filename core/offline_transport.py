"""ThreatFade Phase 2 bounded offline transport and portable evidence."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .data_plane import SignalEvent

PROTOCOL_VERSION = "1.0"
PACKAGE_MEDIA_TYPE = "application/vnd.threatfade.evidence+zip"
DEFAULT_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_RETENTION_SECONDS = 7 * 24 * 3600
DEFAULT_BATCH_EVENTS = 256
MAX_EVENT_BYTES = 256 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now() -> float:
    return time.time()


def _event_digest(record: Mapping[str, Any]) -> str:
    event = {k: v for k, v in record.items() if k not in {"sequence_no", "event_digest"}}
    return _sha256(_canonical(event))


def _event_record(event: SignalEvent, sequence_no: int) -> dict[str, Any]:
    payload = event.canonical_dict()
    payload["sequence_no"] = sequence_no
    payload["event_digest"] = event.digest()
    return payload


@dataclass(frozen=True)
class QueuePolicy:
    max_bytes: int = DEFAULT_MAX_BYTES
    retention_seconds: int = DEFAULT_RETENTION_SECONDS
    max_events: int = 100_000
    min_free_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if not 1 <= self.max_bytes <= 8 * 1024 * 1024 * 1024:
            raise ValueError("max_bytes out of bounds")
        if not 1 <= self.retention_seconds <= 365 * 24 * 3600:
            raise ValueError("retention_seconds out of bounds")
        if not 1 <= self.max_events <= 10_000_000:
            raise ValueError("max_events out of bounds")
        if not 0 <= self.min_free_bytes <= self.max_bytes:
            raise ValueError("min_free_bytes out of bounds")


class DurableEventQueue:
    """Durable bounded queue with per-tenant/sensor monotonic sequencing."""

    def __init__(self, path: str | os.PathLike[str], *, policy: QueuePolicy | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.policy = policy or QueuePolicy()
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS queue_meta (tenant_id TEXT NOT NULL, sensor_id TEXT NOT NULL, next_sequence INTEGER NOT NULL, PRIMARY KEY(tenant_id,sensor_id));
        CREATE TABLE IF NOT EXISTS events (
            event_digest TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, sensor_id TEXT NOT NULL,
            sequence_no INTEGER NOT NULL, priority INTEGER NOT NULL, observed_at REAL NOT NULL,
            inserted_at REAL NOT NULL, payload BLOB NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
            UNIQUE(tenant_id,sensor_id,sequence_no)
        );
        CREATE INDEX IF NOT EXISTS idx_events_order ON events(priority DESC, inserted_at ASC);
        CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id, sensor_id, sequence_no);
        """)

    def close(self) -> None:
        self._db.close()

    def _size(self) -> int:
        return int(self._db.execute("SELECT COALESCE(SUM(length(payload)),0) FROM events").fetchone()[0])

    def _evict(self, required: int) -> None:
        while self._size() + required > self.policy.max_bytes or self.count() >= self.policy.max_events:
            row = self._db.execute("SELECT event_digest FROM events ORDER BY priority ASC, inserted_at ASC LIMIT 1").fetchone()
            if row is None:
                raise OSError("offline queue capacity exhausted")
            self._db.execute("DELETE FROM events WHERE event_digest=?", (row[0],))

    def _ensure_disk_headroom(self, required: int) -> None:
        usage = shutil.disk_usage(self.path.parent)
        if usage.free < self.policy.min_free_bytes + required:
            raise OSError("offline queue minimum free-space limit reached")

    def enqueue(self, event: SignalEvent, *, priority: int = 50) -> int:
        if not isinstance(event, SignalEvent):
            raise TypeError("event must be SignalEvent")
        if not 0 <= priority <= 100:
            raise ValueError("priority must be between 0 and 100")
        payload = _canonical(event.canonical_dict())
        if len(payload) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds maximum size")
        digest = event.digest()
        self._db.execute("BEGIN IMMEDIATE")
        try:
            existing = self._db.execute("SELECT sequence_no FROM events WHERE event_digest=?", (digest,)).fetchone()
            if existing:
                self._db.execute("COMMIT")
                return int(existing[0])
            self._ensure_disk_headroom(len(payload))
            self._evict(len(payload))
            row = self._db.execute("SELECT next_sequence FROM queue_meta WHERE tenant_id=? AND sensor_id=?", (event.tenant_id, event.sensor_id)).fetchone()
            sequence = int(row[0]) if row else 1
            self._db.execute("INSERT OR REPLACE INTO queue_meta VALUES(?,?,?)", (event.tenant_id, event.sensor_id, sequence + 1))
            self._db.execute("INSERT INTO events(event_digest,tenant_id,sensor_id,sequence_no,priority,observed_at,inserted_at,payload) VALUES(?,?,?,?,?,?,?,?)", (digest, event.tenant_id, event.sensor_id, sequence, priority, event.observed_at.timestamp(), _now(), payload))
            self._db.execute("COMMIT")
            return sequence
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def bytes_used(self) -> int:
        return self._size()

    def expire(self, *, now: float | None = None) -> int:
        cutoff = (now if now is not None else _now()) - self.policy.retention_seconds
        return self._db.execute("DELETE FROM events WHERE inserted_at < ? AND priority < 100", (cutoff,)).rowcount

    def peek(self, *, limit: int = DEFAULT_BATCH_EVENTS, tenant_id: str | None = None, sensor_id: str | None = None) -> list[dict[str, Any]]:
        if not 1 <= limit <= 4096:
            raise ValueError("invalid batch limit")
        if tenant_id and sensor_id:
            rows = self._db.execute("SELECT event_digest,tenant_id,sensor_id,sequence_no,priority,payload FROM events WHERE tenant_id=? AND sensor_id=? ORDER BY sequence_no ASC LIMIT ?", (tenant_id, sensor_id, limit)).fetchall()
        elif tenant_id:
            rows = self._db.execute("SELECT event_digest,tenant_id,sensor_id,sequence_no,priority,payload FROM events WHERE tenant_id=? ORDER BY sequence_no ASC LIMIT ?", (tenant_id, limit)).fetchall()
        else:
            rows = self._db.execute("SELECT event_digest,tenant_id,sensor_id,sequence_no,priority,payload FROM events ORDER BY priority DESC, inserted_at ASC LIMIT ?", (limit,)).fetchall()
        return [{"event_digest": r[0], "tenant_id": r[1], "sensor_id": r[2], "sequence_no": r[3], "priority": r[4], "payload": bytes(r[5])} for r in rows]

    def acknowledge(self, digests: Iterable[str]) -> int:
        removed = 0
        for digest in dict.fromkeys(digests):
            removed += self._db.execute("DELETE FROM events WHERE event_digest=?", (digest,)).rowcount
        return removed

    def metrics(self) -> dict[str, int]:
        return {"events": self.count(), "bytes": self.bytes_used(), "max_bytes": self.policy.max_bytes, "max_events": self.policy.max_events}


@dataclass(frozen=True)
class BandwidthPolicy:
    bytes_per_second: int = 256 * 1024
    burst_bytes: int = 1024 * 1024
    max_batch_bytes: int = 512 * 1024

    def allowance(self, elapsed_seconds: float, tokens: int) -> int:
        if elapsed_seconds < 0:
            raise ValueError("elapsed_seconds cannot be negative")
        return min(self.burst_bytes, tokens + int(elapsed_seconds * self.bytes_per_second))


class BandwidthAwareTransmitter:
    """Bounded token-bucket batch planner; transport acknowledgement is external."""
    def __init__(self, policy: BandwidthPolicy | None = None):
        self.policy = policy or BandwidthPolicy()
        self._tokens = self.policy.burst_bytes
        self._last = _now()

    def select(self, records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        now = _now(); self._tokens = self.policy.allowance(now - self._last, self._tokens); self._last = now
        selected: list[Mapping[str, Any]] = []; used = 0
        for record in records:
            size = len(record["payload"])
            if size > self.policy.max_batch_bytes or size > self._tokens:
                if not selected: continue
                break
            if used + size > self.policy.max_batch_bytes or used + size > self._tokens: break
            selected.append(record); used += size
        self._tokens -= used
        return selected


def batch_payload(records: Sequence[Mapping[str, Any]], *, tenant_id: str, sensor_id: str, batch_id: str) -> bytes:
    if not records: raise ValueError("batch cannot be empty")
    sequence = [int(r["sequence_no"]) for r in records]
    if sequence != sorted(sequence) or len(sequence) != len(set(sequence)): raise ValueError("batch sequence numbers must be strictly ordered")
    if any(r["tenant_id"] != tenant_id or r["sensor_id"] != sensor_id for r in records): raise ValueError("batch tenant or sensor mismatch")
    return _canonical({"protocol_version": PROTOCOL_VERSION, "batch_id": batch_id, "tenant_id": tenant_id, "sensor_id": sensor_id, "first_sequence": sequence[0], "last_sequence": sequence[-1], "event_count": len(records), "events": [json.loads(bytes(r["payload"]).decode()) for r in records]})


class ReplayProtector:
    def __init__(self): self._batches: set[str] = set(); self._last: dict[tuple[str, str], int] = {}
    def accept(self, *, batch_id: str, tenant_id: str, sensor_id: str, first_sequence: int, last_sequence: int) -> str:
        key = (tenant_id, sensor_id)
        if batch_id in self._batches: return "duplicate"
        if first_sequence < 1 or last_sequence < first_sequence: raise ValueError("invalid sequence range")
        previous = self._last.get(key, 0)
        if last_sequence <= previous: return "replay"
        if previous and first_sequence > previous + 1: return "gap"
        self._batches.add(batch_id); self._last[key] = last_sequence; return "accepted"


@dataclass(frozen=True)
class SigningKey:
    key_id: str; algorithm: str; public_key_b64: str; created_at: str; not_before: str; not_after: str; revoked_at: str | None = None


class EvidenceSigner:
    algorithm = "Ed25519"
    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._private = private_key or Ed25519PrivateKey.generate()
        public = self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = _sha256(public)[:32]; now = datetime.now(timezone.utc).isoformat()
        self.metadata = SigningKey(self.key_id, self.algorithm, base64.b64encode(public).decode(), now, now, "9999-12-31T23:59:59+00:00")
    def sign(self, payload: bytes) -> str: return base64.b64encode(self._private.sign(payload)).decode()
    def export_private(self) -> bytes: return self._private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    @classmethod
    def from_private_bytes(cls, data: bytes) -> "EvidenceSigner": return cls(Ed25519PrivateKey.from_private_bytes(data))


def verify_signature(payload: bytes, signature_b64: str, key: SigningKey, *, at: datetime | None = None) -> bool:
    moment = at or datetime.now(timezone.utc)
    if key.algorithm != "Ed25519" or key.revoked_at is not None: return False
    if moment < datetime.fromisoformat(key.not_before) or moment > datetime.fromisoformat(key.not_after): return False
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key.public_key_b64, validate=True)); public.verify(base64.b64decode(signature_b64, validate=True), payload); return True
    except (ValueError, InvalidSignature): return False


def build_evidence_package(*, tenant_id: str, sensor_id: str, events: Sequence[SignalEvent], evidence: Sequence[Mapping[str, Any]] = (), provenance: Mapping[str, Any] | None = None, signer: EvidenceSigner) -> bytes:
    if not tenant_id or not sensor_id or not events: raise ValueError("tenant, sensor and events are required")
    if any(e.tenant_id != tenant_id or e.sensor_id != sensor_id for e in events): raise ValueError("tenant or sensor mismatch")
    records = [_event_record(e, i + 1) for i, e in enumerate(sorted(events, key=lambda e: (e.observed_at, e.event_id)))]
    manifest = {"media_type": PACKAGE_MEDIA_TYPE, "protocol_version": PROTOCOL_VERSION, "schema_version": records[0]["schema_version"], "tenant_id": tenant_id, "sensor_id": sensor_id, "event_count": len(records), "event_hashes": [r["event_digest"] for r in records], "evidence_hashes": [_sha256(_canonical(dict(x))) for x in evidence], "provenance": dict(provenance or {}), "created_at": datetime.now(timezone.utc).isoformat(), "signing_key_id": signer.key_id, "signature_algorithm": signer.algorithm}
    signed = _canonical(manifest); manifest["signature"] = signer.sign(signed); manifest["manifest_sha256"] = _sha256(signed)
    out = BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in (("manifest.json", _canonical(manifest)), ("events.json", _canonical(records)), ("evidence.json", _canonical(list(evidence))), ("provenance.json", _canonical(dict(provenance or {}))), ("signing-key.json", _canonical(signer.metadata.__dict__))):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED; archive.writestr(info, content)
    return out.getvalue()


def verify_evidence_package(package: bytes, trusted_keys: Mapping[str, SigningKey], *, tenant_id: str | None = None, at: datetime | None = None) -> dict[str, Any]:
    with zipfile.ZipFile(BytesIO(package), "r") as archive:
        required = {"manifest.json", "events.json", "evidence.json", "provenance.json", "signing-key.json"}
        if set(archive.namelist()) != required: raise ValueError("invalid evidence package contents")
        manifest = json.loads(archive.read("manifest.json")); events = json.loads(archive.read("events.json")); evidence = json.loads(archive.read("evidence.json"))
    if tenant_id is not None and manifest.get("tenant_id") != tenant_id: raise ValueError("tenant mismatch")
    key = trusted_keys.get(manifest.get("signing_key_id"))
    if key is None: raise ValueError("untrusted signing key")
    signature = manifest.pop("signature", None); manifest_hash = manifest.pop("manifest_sha256", None)
    if not signature or not manifest_hash: raise ValueError("missing signature metadata")
    signed = _canonical(manifest)
    if _sha256(signed) != manifest_hash or not verify_signature(signed, signature, key, at=at): raise ValueError("signature verification failed")
    if manifest["event_count"] != len(events) or manifest["event_hashes"] != [e.get("event_digest") for e in events]: raise ValueError("event manifest mismatch")
    for record in events:
        if _event_digest(record) != record.get("event_digest"): raise ValueError("event content digest mismatch")
    if [_sha256(_canonical(dict(x))) for x in evidence] != manifest["evidence_hashes"]: raise ValueError("evidence manifest mismatch")
    return {"verified": True, "tenant_id": manifest["tenant_id"], "sensor_id": manifest["sensor_id"], "event_count": len(events), "signing_key_id": manifest["signing_key_id"]}
