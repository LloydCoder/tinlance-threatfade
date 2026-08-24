"""ThreatFade Phase 2 offline transport and portable evidence primitives.

The module keeps the Group 11 SignalEvent contract intact and adds a durable,
bounded hand-off layer after canonical event creation. It deliberately does
not capture traffic or own the control-plane transport.

Protocol order:
    SignalEvent -> DurableEventQueue -> signed batch -> receiver verification
    -> idempotent acceptance

The evidence package is deterministic and independently verifiable so that an
air-gapped verifier needs only the package and trusted public keys.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
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
        if not (1 <= self.max_bytes <= 8 * 1024 * 1024 * 1024):
            raise ValueError("max_bytes out of bounds")
        if not (1 <= self.retention_seconds <= 365 * 24 * 3600):
            raise ValueError("retention_seconds out of bounds")
        if not (1 <= self.max_events <= 10_000_000):
            raise ValueError("max_events out of bounds")
        if not (0 <= self.min_free_bytes <= self.max_bytes):
            raise ValueError("min_free_bytes out of bounds")


class DurableEventQueue:
    """SQLite-backed, bounded, tenant/sensor-scoped store-and-forward queue.

    Eviction is oldest-lowest-priority first. Priority 100 is reserved for
    critical evidence; normal events use lower values. The queue never grows
    beyond policy limits and never silently mutates an accepted event.
    """

    def __init__(self, path: str | os.PathLike[str], *, policy: QueuePolicy | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.policy = policy or QueuePolicy()
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS queue_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
            event_digest TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            sensor_id TEXT NOT NULL,
            sequence_no INTEGER NOT NULL,
            priority INTEGER NOT NULL,
            observed_at REAL NOT NULL,
            inserted_at REAL NOT NULL,
            payload BLOB NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE INDEX IF NOT EXISTS idx_events_order ON events(priority DESC, sequence_no ASC);
        CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id, sequence_no);
        """)
        if self._db.execute("SELECT 1 FROM queue_meta WHERE k='next_sequence'").fetchone() is None:
            self._db.execute("INSERT INTO queue_meta(k,v) VALUES('next_sequence','1')")

    def close(self) -> None:
        self._db.close()

    def _next_sequence(self) -> int:
        row = self._db.execute("SELECT v FROM queue_meta WHERE k='next_sequence'").fetchone()
        value = int(row[0])
        self._db.execute("UPDATE queue_meta SET v=? WHERE k='next_sequence'", (str(value + 1),))
        return value

    def _size(self) -> int:
        row = self._db.execute("SELECT COALESCE(SUM(length(payload)),0) FROM events").fetchone()
        return int(row[0])

    def _evict(self, required_bytes: int) -> None:
        while self._size() + required_bytes > self.policy.max_bytes or self.count() >= self.policy.max_events:
            row = self._db.execute(
                "SELECT event_digest FROM events ORDER BY priority ASC, inserted_at ASC LIMIT 1"
            ).fetchone()
            if row is None:
                raise OSError("offline queue capacity exhausted")
            self._db.execute("DELETE FROM events WHERE event_digest=?", (row[0],))

    def enqueue(self, event: SignalEvent, *, priority: int = 50) -> int:
        if not isinstance(event, SignalEvent):
            raise TypeError("event must be SignalEvent")
        if not 0 <= priority <= 100:
            raise ValueError("priority must be between 0 and 100")
        payload = _canonical(event.canonical_dict())
        if len(payload) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds maximum size")
        digest = event.digest()
        if self._db.execute("SELECT 1 FROM events WHERE event_digest=?", (digest,)).fetchone():
            return int(self._db.execute("SELECT sequence_no FROM events WHERE event_digest=?", (digest,)).fetchone()[0])
        sequence = self._next_sequence()
        self._evict(len(payload))
        self._db.execute(
            "INSERT INTO events(event_digest,tenant_id,sensor_id,sequence_no,priority,observed_at,inserted_at,payload) VALUES(?,?,?,?,?,?,?,?)",
            (digest, event.tenant_id, event.sensor_id, sequence, priority, event.observed_at.timestamp(), _now(), payload),
        )
        return sequence

    def count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def bytes_used(self) -> int:
        return self._size()

    def expire(self, *, now: float | None = None) -> int:
        cutoff = (now if now is not None else _now()) - self.policy.retention_seconds
        cur = self._db.execute("DELETE FROM events WHERE inserted_at < ? AND priority < 100", (cutoff,))
        return cur.rowcount

    def peek(self, *, limit: int = DEFAULT_BATCH_EVENTS, tenant_id: str | None = None) -> list[dict[str, Any]]:
        if not 1 <= limit <= 4096:
            raise ValueError("invalid batch limit")
        if tenant_id:
            rows = self._db.execute(
                "SELECT event_digest,tenant_id,sensor_id,sequence_no,priority,payload FROM events WHERE tenant_id=? ORDER BY sequence_no ASC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT event_digest,tenant_id,sensor_id,sequence_no,priority,payload FROM events ORDER BY priority DESC, sequence_no ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"event_digest": r[0], "tenant_id": r[1], "sensor_id": r[2], "sequence_no": r[3], "priority": r[4], "payload": bytes(r[5])} for r in rows]

    def acknowledge(self, digests: Iterable[str]) -> int:
        values = list(dict.fromkeys(digests))
        if not values:
            return 0
        removed = 0
        for digest in values:
            cur = self._db.execute("DELETE FROM events WHERE event_digest=?", (digest,))
            removed += cur.rowcount
        return removed

    def metrics(self) -> dict[str, int]:
        return {"events": self.count(), "bytes": self.bytes_used(), "max_bytes": self.policy.max_bytes, "max_events": self.policy.max_events}


@dataclass(frozen=True)
class BandwidthPolicy:
    bytes_per_second: int = 256 * 1024
    burst_bytes: int = 1024 * 1024
    max_batch_bytes: int = 512 * 1024

    def __post_init__(self) -> None:
        if self.bytes_per_second <= 0 or self.burst_bytes <= 0 or self.max_batch_bytes <= 0:
            raise ValueError("bandwidth limits must be positive")

    def allowance(self, elapsed_seconds: float, tokens: int) -> int:
        if elapsed_seconds < 0:
            raise ValueError("elapsed_seconds cannot be negative")
        return min(self.burst_bytes, tokens + int(elapsed_seconds * self.bytes_per_second))


class BandwidthAwareTransmitter:
    """Pure planner; transport errors leave queue state untouched."""

    def __init__(self, policy: BandwidthPolicy | None = None):
        self.policy = policy or BandwidthPolicy()
        self._tokens = self.policy.burst_bytes
        self._last = _now()

    def select(self, records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        now = _now()
        self._tokens = self.policy.allowance(now - self._last, self._tokens)
        self._last = now
        selected: list[Mapping[str, Any]] = []
        used = 0
        for record in records:
            size = len(record["payload"])
            if selected and (used + size > self._tokens or used + size > self.policy.max_batch_bytes):
                break
            if size > self._tokens or size > self.policy.max_batch_bytes:
                continue
            selected.append(record)
            used += size
        self._tokens -= used
        return selected


def batch_payload(records: Sequence[Mapping[str, Any]], *, tenant_id: str, sensor_id: str, batch_id: str) -> bytes:
    if not records:
        raise ValueError("batch cannot be empty")
    sequence = [int(r["sequence_no"]) for r in records]
    if sequence != sorted(sequence) or len(sequence) != len(set(sequence)):
        raise ValueError("batch sequence numbers must be strictly ordered")
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "batch_id": batch_id,
        "tenant_id": tenant_id,
        "sensor_id": sensor_id,
        "first_sequence": sequence[0],
        "last_sequence": sequence[-1],
        "event_count": len(records),
        "events": [json.loads(bytes(r["payload"]).decode("utf-8")) for r in records],
    }
    return _canonical(payload)


class ReplayProtector:
    """Monotonic per-sensor sequence acceptance with idempotent batch IDs."""

    def __init__(self):
        self._batches: set[str] = set()
        self._last: dict[tuple[str, str], int] = {}

    def accept(self, *, batch_id: str, tenant_id: str, sensor_id: str, first_sequence: int, last_sequence: int) -> str:
        key = (tenant_id, sensor_id)
        if batch_id in self._batches:
            return "duplicate"
        if first_sequence < 1 or last_sequence < first_sequence:
            raise ValueError("invalid sequence range")
        previous = self._last.get(key, 0)
        if last_sequence <= previous:
            return "replay"
        if first_sequence > previous + 1 and previous != 0:
            return "gap"
        self._batches.add(batch_id)
        self._last[key] = last_sequence
        return "accepted"


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    algorithm: str
    public_key_b64: str
    created_at: str
    not_before: str
    not_after: str
    revoked_at: str | None = None


class EvidenceSigner:
    """Ed25519 signer with explicit validity and revocation metadata."""

    algorithm = "Ed25519"

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._private = private_key or Ed25519PrivateKey.generate()
        public = self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = _sha256(public)[:32]
        now = datetime.now(timezone.utc).isoformat()
        self.metadata = SigningKey(self.key_id, self.algorithm, base64.b64encode(public).decode(), now, now, "9999-12-31T23:59:59+00:00")

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._private.sign(payload)).decode("ascii")

    def export_private(self) -> bytes:
        return self._private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "EvidenceSigner":
        return cls(Ed25519PrivateKey.from_private_bytes(data))


def verify_signature(payload: bytes, signature_b64: str, key: SigningKey, *, at: datetime | None = None) -> bool:
    moment = at or datetime.now(timezone.utc)
    if key.algorithm != "Ed25519" or key.revoked_at is not None:
        return False
    if moment < datetime.fromisoformat(key.not_before) or moment > datetime.fromisoformat(key.not_after):
        return False
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key.public_key_b64, validate=True))
        public.verify(base64.b64decode(signature_b64, validate=True), payload)
        return True
    except (ValueError, InvalidSignature):
        return False


def build_evidence_package(*, tenant_id: str, sensor_id: str, events: Sequence[SignalEvent], evidence: Sequence[Mapping[str, Any]] = (), provenance: Mapping[str, Any] | None = None, signer: EvidenceSigner) -> bytes:
    if not tenant_id or not sensor_id or not events:
        raise ValueError("tenant, sensor and events are required")
    if any(event.tenant_id != tenant_id or event.sensor_id != sensor_id for event in events):
        raise ValueError("tenant or sensor mismatch")
    records = [_event_record(event, i + 1) for i, event in enumerate(sorted(events, key=lambda e: (e.observed_at, e.event_id)))]
    event_hashes = [r["event_digest"] for r in records]
    manifest = {
        "media_type": PACKAGE_MEDIA_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": records[0]["schema_version"],
        "tenant_id": tenant_id,
        "sensor_id": sensor_id,
        "event_count": len(records),
        "event_hashes": event_hashes,
        "evidence_hashes": [_sha256(_canonical(dict(item))) for item in evidence],
        "provenance": dict(provenance or {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "signing_key_id": signer.key_id,
    }
    signed_payload = _canonical(manifest)
    signature = signer.sign(signed_payload)
    manifest["signature_algorithm"] = signer.algorithm
    manifest["signature"] = signature
    manifest["manifest_sha256"] = _sha256(signed_payload)

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in (("manifest.json", _canonical(manifest)), ("events.json", _canonical(records)), ("evidence.json", _canonical(list(evidence))), ("provenance.json", _canonical(dict(provenance or {}))), ("signing-key.json", _canonical(signer.metadata.__dict__))):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    return buffer.getvalue()


def verify_evidence_package(package: bytes, trusted_keys: Mapping[str, SigningKey], *, tenant_id: str | None = None, at: datetime | None = None) -> dict[str, Any]:
    with zipfile.ZipFile(BytesIO(package), "r") as archive:
        required = {"manifest.json", "events.json", "evidence.json", "provenance.json", "signing-key.json"}
        if set(archive.namelist()) != required:
            raise ValueError("invalid evidence package contents")
        manifest = json.loads(archive.read("manifest.json"))
        events = json.loads(archive.read("events.json"))
        evidence = json.loads(archive.read("evidence.json"))
    if tenant_id is not None and manifest.get("tenant_id") != tenant_id:
        raise ValueError("tenant mismatch")
    key_id = manifest.get("signing_key_id")
    key = trusted_keys.get(key_id)
    if key is None:
        raise ValueError("untrusted signing key")
    signature = manifest.pop("signature", None)
    manifest_hash = manifest.pop("manifest_sha256", None)
    if not signature or not manifest_hash:
        raise ValueError("missing signature metadata")
    signed = _canonical(manifest)
    if _sha256(signed) != manifest_hash:
        raise ValueError("manifest digest mismatch")
    if not verify_signature(signed, signature, key, at=at):
        raise ValueError("signature verification failed")
    if manifest["event_count"] != len(events) or manifest["event_hashes"] != [e["event_digest"] for e in events]:
        raise ValueError("event manifest mismatch")
    evidence_hashes = [_sha256(_canonical(dict(item))) for item in evidence]
    if evidence_hashes != manifest["evidence_hashes"]:
        raise ValueError("evidence manifest mismatch")
    return {"verified": True, "tenant_id": manifest["tenant_id"], "sensor_id": manifest["sensor_id"], "event_count": len(events), "signing_key_id": key_id}
