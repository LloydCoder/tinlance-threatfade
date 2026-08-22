from datetime import datetime, timezone

import pytest

from agents.sensor import SensorAdapter
from core.data_plane import BoundedEventQueue, SensorRegistry, SignalEvent, new_event


def fingerprint(seed="sensor"):
    import hashlib
    return hashlib.sha256(seed.encode()).hexdigest()


def active_sensor():
    registry = SensorRegistry()
    registry.register("sensor-a", "tenant-a", version="1.0.0", fingerprint=fingerprint())
    registry.activate("sensor-a")
    return registry


def test_canonical_event_is_deterministic_and_hashed():
    event = SignalEvent(
        event_id="evt-1", sensor_id="sensor-a", tenant_id="tenant-a", kind="flow",
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc), protocol="quic",
        src_ip="10.0.0.1", dst_ip="203.0.113.10", src_port=4433, dst_port=443,
        bytes_in=10, bytes_out=20, packets=3, metadata={"ja3": "example"},
    )
    assert len(event.digest()) == 64
    assert event.canonical_bytes() == event.canonical_bytes()


def test_event_rejects_naive_timestamp_and_invalid_ports():
    with pytest.raises(ValueError):
        SignalEvent("e", "s", "t", "flow", datetime.now())
    with pytest.raises(ValueError):
        SignalEvent("e", "s", "t", "flow", datetime.now(timezone.utc), src_port=70000)


def test_bounded_queue_drops_without_blocking():
    queue = BoundedEventQueue(maxsize=1)
    event = new_event("s", "t", "signal")
    assert queue.put(event)
    assert not queue.put(new_event("s", "t", "signal"))
    assert queue.metrics() == {"accepted": 1, "dropped": 1, "depth": 1}


def test_sensor_cannot_cross_tenant_or_ingest_before_activation():
    registry = SensorRegistry()
    registry.register("sensor-a", "tenant-a", version="1.0.0", fingerprint=fingerprint())
    queue = BoundedEventQueue()
    with pytest.raises(PermissionError):
        SensorAdapter("sensor-a", "tenant-a", registry, queue)
    registry.activate("sensor-a")
    with pytest.raises(PermissionError):
        SensorAdapter("sensor-a", "tenant-b", registry, queue)


def test_sensor_emits_only_after_active_binding():
    registry = active_sensor()
    queue = BoundedEventQueue()
    adapter = SensorAdapter("sensor-a", "tenant-a", registry, queue)
    event = adapter.emit("session", protocol="tls", packets=2)
    assert event.tenant_id == "tenant-a"
    assert queue.get().event_id == event.event_id


def test_sensor_fingerprint_is_sha256_and_identity_is_immutable():
    registry = SensorRegistry()
    registry.register("sensor-a", "tenant-a", version="1", fingerprint=fingerprint())
    with pytest.raises(ValueError):
        registry.register("sensor-a", "tenant-b", version="1", fingerprint=fingerprint())
    with pytest.raises(ValueError):
        registry.register("sensor-b", "tenant-a", version="1", fingerprint="not-a-digest")


def test_revoked_sensor_cannot_ingest():
    registry = active_sensor()
    registry.transition("sensor-a", "revoked")
    assert not registry.can_ingest("sensor-a", "tenant-a")
