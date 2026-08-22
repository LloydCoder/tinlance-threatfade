"""Fail-closed Group 11 architecture gate.

The gate verifies that the canonical data-plane contract remains present and
that sensor ingestion cannot bypass tenant/state checks or bounded buffering.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = (ROOT / "core/data_plane.py").read_text(encoding="utf-8")
SENSOR = (ROOT / "agents/sensor.py").read_text(encoding="utf-8")
TESTS = (ROOT / "tests/test_data_plane.py").read_text(encoding="utf-8")

required_data = [
    "class SignalEvent",
    "SCHEMA_VERSION",
    "MAX_EVENT_BYTES",
    "class BoundedEventQueue",
    "class SensorRegistry",
    "def digest",
]
required_sensor = [
    "registry.can_ingest",
    "class SensorAdapter",
    "self.queue.put",
]
required_tests = [
    "test_canonical_event_is_deterministic_and_hashed",
    "test_bounded_queue_drops_without_blocking",
    "test_sensor_cannot_cross_tenant_or_ingest_before_activation",
    "test_revoked_sensor_cannot_ingest",
]

for needle in required_data:
    assert needle in DATA, f"missing data-plane control: {needle}"
for needle in required_sensor:
    assert needle in SENSOR, f"missing sensor control: {needle}"
for needle in required_tests:
    assert needle in TESTS, f"missing regression test: {needle}"

assert "PermissionError" in SENSOR
assert "MAX_EVENT_BYTES" in DATA
assert "state\"] == \"active\"" in DATA
print("data-plane architecture: OK")
