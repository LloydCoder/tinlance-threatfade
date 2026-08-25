from datetime import datetime, timedelta, timezone

from agents.detection_pipeline import SensorDetectionPipeline
from core.data_plane import SignalEvent


def event(i, value):
    return SignalEvent(event_id=str(i), sensor_id="s", tenant_id="t", kind="packet",
                       observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
                       protocol="udp", src_ip="10.0.0.1", src_port=1234, dst_ip="203.0.113.1", dst_port=443,
                       packets=1, bytes_in=value)


def test_pipeline_is_bounded_and_uses_existing_detector():
    p = SensorDetectionPipeline(window_size=12)
    for i in range(12):
        p.ingest(event(i, 100))
    assert p.metrics()["active_sessions"] == 1
    assert p.metrics()["buffered_events"] == 12
    p.ingest(event(12, 100))
    assert p.metrics()["buffered_events"] == 12


def test_pipeline_rejects_non_event():
    p = SensorDetectionPipeline()
    try:
        p.ingest(object())
    except TypeError:
        pass
    else:
        raise AssertionError("non-SignalEvent must be rejected")
