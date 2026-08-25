from datetime import datetime, timezone
from pathlib import Path

import pytest

from agents.durable_queue import DurableSensorQueue
from agents.edge_runtime import EdgeSensorRuntime
from agents.fleet import SensorFleet
from agents.live_capture import LiveCaptureAdapter
from core.data_plane import SensorRegistry, SignalEvent


def fp(seed="sensor"):
    import hashlib
    return hashlib.sha256(seed.encode()).hexdigest()


def registry():
    r = SensorRegistry()
    r.register("sensor-a", "tenant-a", version="1.0.0", fingerprint=fp())
    r.activate("sensor-a")
    return r


def event(i="1"):
    return SignalEvent(event_id=i, sensor_id="sensor-a", tenant_id="tenant-a", kind="packet",
                       observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc), protocol="udp", packets=1, bytes_in=128)


def test_durable_queue_fifo_and_duplicate_idempotency(tmp_path: Path):
    q = DurableSensorQueue(str(tmp_path / "queue.db"), max_bytes=1 << 20, max_events=1000, retention_seconds=3600)
    assert q.enqueue(event("a"))
    assert q.enqueue(event("a"))
    assert q.enqueue(event("b"))
    batch = q.peek(10)
    assert [p for _, p in batch] == [event("a").canonical_bytes(), event("b").canonical_bytes()]
    assert q.acknowledge(batch[0][0]) == 1
    assert len(q.peek()) == 1


def test_durable_queue_is_bounded(tmp_path: Path):
    q = DurableSensorQueue(str(tmp_path / "queue.db"), max_bytes=1 << 20, max_events=1, retention_seconds=3600)
    assert q.enqueue(event("a"))
    assert not q.enqueue(event("b"))
    assert q.metrics()["events"] == 1


def test_runtime_offline_then_replay(tmp_path: Path):
    r = registry()
    q = DurableSensorQueue(str(tmp_path / "queue.db"), max_bytes=1 << 20, max_events=1000, retention_seconds=3600)
    calls = []
    def sender(batch):
        calls.append(batch)
        return batch[-1][0]
    runtime = EdgeSensorRuntime(sensor_id="sensor-a", tenant_id="tenant-a", registry=r, queue=q, sender=sender)
    assert runtime.ingest(event("a"))
    assert q.metrics()["events"] == 1
    assert q.replay(sender) == 1
    assert calls and not q.peek()


def test_runtime_rejects_cross_tenant_event(tmp_path: Path):
    r = registry()
    q = DurableSensorQueue(str(tmp_path / "queue.db"), max_bytes=1 << 20, max_events=1000, retention_seconds=3600)
    runtime = EdgeSensorRuntime(sensor_id="sensor-a", tenant_id="tenant-a", registry=r, queue=q)
    bad = SignalEvent(event_id="bad", sensor_id="sensor-a", tenant_id="tenant-b", kind="packet",
                      observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(PermissionError):
        runtime.ingest(bad)


def test_fleet_lifecycle():
    r = SensorRegistry()
    fleet = SensorFleet(r)
    enrolled = fleet.enroll("sensor-a", "tenant-a", "1.0.0", fp())
    assert enrolled["state"] == "pending"
    fleet.activate("sensor-a")
    assert fleet.health("sensor-a")["state"] == "active"
    fleet.drain("sensor-a")
    assert fleet.health("sensor-a")["state"] == "draining"
    fleet.revoke("sensor-a")
    assert fleet.health("sensor-a")["state"] == "revoked"


def test_capture_adapter_bounds_configuration():
    with pytest.raises(ValueError):
        LiveCaptureAdapter(sensor_id="s", tenant_id="t", interface="", emit=lambda e: True)
    with pytest.raises(ValueError):
        LiveCaptureAdapter(sensor_id="s", tenant_id="t", interface="eth0", emit=lambda e: True, snaplen=1)
