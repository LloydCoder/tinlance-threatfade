"""Streaming adapter from canonical SignalEvent batches to the existing fade engine."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from typing import Callable

from core.data_plane import SignalEvent
from core.fade_engine import detect_fade


class SensorDetectionPipeline:
    """Deterministic bounded session window feeding the existing detector.

    The pipeline does not invent a second detector. It converts canonical packet
    events into the activity series expected by ``core.fade_engine.detect_fade``
    and bounds each session window to prevent untrusted traffic from exhausting
    memory.
    """

    def __init__(self, *, window_size: int = 256, on_detection: Callable[[SignalEvent, dict], None] | None = None):
        if not 12 <= window_size <= 4096:
            raise ValueError("window_size out of bounds")
        self.window_size = window_size
        self.on_detection = on_detection
        self._windows: dict[tuple[str, str, str], deque[float]] = defaultdict(lambda: deque(maxlen=window_size))
        self._timestamps: dict[tuple[str, str, str], deque[datetime]] = defaultdict(lambda: deque(maxlen=window_size))

    @staticmethod
    def _key(event: SignalEvent) -> tuple[str, str, str]:
        return event.tenant_id, event.sensor_id, f"{event.src_ip or ''}:{event.src_port or ''}->{event.dst_ip or ''}:{event.dst_port or ''}"

    def ingest(self, event: SignalEvent) -> dict | None:
        if not isinstance(event, SignalEvent):
            raise TypeError("SignalEvent required")
        key = self._key(event)
        activity = float(event.bytes_in + event.bytes_out)
        self._windows[key].append(activity)
        self._timestamps[key].append(event.observed_at)
        values = list(self._windows[key])
        timestamps = list(self._timestamps[key])
        if len(values) < 12:
            return None
        result = detect_fade(timestamps, values)
        if result["detected"] and self.on_detection is not None:
            self.on_detection(event, result)
        return result

    def metrics(self) -> dict[str, int]:
        return {"active_sessions": len(self._windows), "buffered_events": sum(len(v) for v in self._windows.values())}
