"""Canonical ThreatFade detection data-plane primitives.

The data plane is intentionally transport-agnostic. Sensors emit immutable,
validated events; ingestion normalizes and bounds them; downstream detection
receives the same schema regardless of whether the source is PCAP, a live
capture adapter, or an endpoint/edge sensor.

This module does not open sockets or capture packets itself. Platform-specific
capture belongs in adapters so the security-critical normalization and
backpressure contract remains deterministic and testable.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from queue import Full, Queue
from threading import Lock
from typing import Any, Dict, Iterable, Mapping, Optional

SCHEMA_VERSION = "1.0"
MAX_EVENT_BYTES = 256 * 1024
MAX_METADATA_KEYS = 64
MAX_METADATA_VALUE = 4096
ALLOWED_KINDS = {"packet", "flow", "session", "signal"}
ALLOWED_PROTOCOLS = {"unknown", "tcp", "udp", "tls", "quic", "dns", "http", "https", "ssh", "rdp"}


def _utc(value: Optional[datetime]) -> datetime:
    return value or datetime.now(timezone.utc)


def _clean_text(value: Any, *, name: str, limit: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f"invalid {name}")
    return value


def _clean_metadata(metadata: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(metadata, Mapping) or len(metadata) > MAX_METADATA_KEYS:
        raise ValueError("invalid metadata")
    result: Dict[str, Any] = {}
    for key, value in metadata.items():
        key = _clean_text(key, name="metadata key", limit=128)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        if len(encoded) > MAX_METADATA_VALUE:
            raise ValueError("metadata value too large")
        result[key] = value
    return result


@dataclass(frozen=True)
class SignalEvent:
    event_id: str
    sensor_id: str
    tenant_id: str
    kind: str
    observed_at: datetime
    protocol: str = "unknown"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    bytes_in: int = 0
    bytes_out: int = 0
    packets: int = 0
    duration_ms: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _clean_text(self.event_id, name="event_id", limit=64)
        _clean_text(self.sensor_id, name="sensor_id", limit=128)
        _clean_text(self.tenant_id, name="tenant_id", limit=255)
        if self.kind not in ALLOWED_KINDS:
            raise ValueError("unsupported event kind")
        if self.protocol not in ALLOWED_PROTOCOLS:
            raise ValueError("unsupported protocol")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        for name, value in (("bytes_in", self.bytes_in), ("bytes_out", self.bytes_out), ("packets", self.packets), ("duration_ms", self.duration_ms)):
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"invalid {name}")
        for name, value in (("src_port", self.src_port), ("dst_port", self.dst_port)):
            if value is not None and (not isinstance(value, int) or not 0 <= value <= 65535):
                raise ValueError(f"invalid {name}")
        _clean_metadata(self.metadata)

    def canonical_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["observed_at"] = self.observed_at.astimezone(timezone.utc).isoformat()
        payload["metadata"] = _clean_metadata(self.metadata)
        return payload

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class BoundedEventQueue:
    """Bounded in-memory buffer with explicit backpressure semantics."""

    def __init__(self, maxsize: int = 4096):
        if not isinstance(maxsize, int) or not 1 <= maxsize <= 1_000_000:
            raise ValueError("invalid queue size")
        self._queue: Queue[SignalEvent] = Queue(maxsize=maxsize)
        self._accepted = 0
        self._dropped = 0
        self._lock = Lock()

    def put(self, event: SignalEvent, *, block: bool = False, timeout: float = 0.0) -> bool:
        if not isinstance(event, SignalEvent):
            raise TypeError("queue accepts SignalEvent only")
        if len(event.canonical_bytes()) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds maximum size")
        try:
            self._queue.put(event, block=block, timeout=timeout if block else 0)
        except Full:
            with self._lock:
                self._dropped += 1
            return False
        with self._lock:
            self._accepted += 1
        return True

    def get(self, timeout: Optional[float] = None) -> SignalEvent:
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        self._queue.task_done()

    def join(self) -> None:
        self._queue.join()

    def metrics(self) -> Dict[str, int]:
        with self._lock:
            return {"accepted": self._accepted, "dropped": self._dropped, "depth": self._queue.qsize()}


class SensorRegistry:
    """Thread-safe sensor lifecycle registry with fail-closed identity state."""

    VALID_STATES = {"pending", "active", "draining", "revoked"}

    def __init__(self):
        self._sensors: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()

    def register(self, sensor_id: str, tenant_id: str, *, version: str, fingerprint: str) -> Dict[str, Any]:
        _clean_text(sensor_id, name="sensor_id", limit=128)
        _clean_text(tenant_id, name="tenant_id", limit=255)
        _clean_text(version, name="version", limit=64)
        if not isinstance(fingerprint, str) or len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint.lower()):
            raise ValueError("sensor fingerprint must be SHA-256 hex")
        with self._lock:
            current = self._sensors.get(sensor_id)
            if current and current["tenant_id"] != tenant_id:
                raise ValueError("sensor identity is already bound to another tenant")
            record = {"sensor_id": sensor_id, "tenant_id": tenant_id, "version": version, "fingerprint": fingerprint.lower(), "state": "pending", "registered_at": time.time()}
            self._sensors[sensor_id] = record
            return dict(record)

    def activate(self, sensor_id: str) -> Dict[str, Any]:
        with self._lock:
            record = self._sensors.get(sensor_id)
            if not record or record["state"] in {"revoked", "draining"}:
                raise ValueError("sensor cannot be activated")
            record["state"] = "active"
            record["activated_at"] = time.time()
            return dict(record)

    def transition(self, sensor_id: str, state: str) -> Dict[str, Any]:
        if state not in self.VALID_STATES:
            raise ValueError("invalid sensor state")
        with self._lock:
            record = self._sensors.get(sensor_id)
            if not record:
                raise KeyError(sensor_id)
            record["state"] = state
            record["updated_at"] = time.time()
            return dict(record)

    def get(self, sensor_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._sensors.get(sensor_id)
            return dict(record) if record else None

    def can_ingest(self, sensor_id: str, tenant_id: str) -> bool:
        with self._lock:
            record = self._sensors.get(sensor_id)
            return bool(record and record["tenant_id"] == tenant_id and record["state"] == "active")


def new_event(sensor_id: str, tenant_id: str, kind: str, **kwargs: Any) -> SignalEvent:
    return SignalEvent(event_id=uuid.uuid4().hex, sensor_id=sensor_id, tenant_id=tenant_id, kind=kind, observed_at=_utc(kwargs.pop("observed_at", None)), **kwargs)
