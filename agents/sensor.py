"""Reference sensor adapter for the ThreatFade data plane.

The adapter intentionally accepts already-extracted flow/session metadata. It
never shells out, opens raw sockets, or executes untrusted input. Platform
capture implementations can feed the same ``emit`` contract.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from core.data_plane import BoundedEventQueue, SensorRegistry, SignalEvent, new_event


class SensorAdapter:
    def __init__(self, sensor_id: str, tenant_id: str, registry: SensorRegistry, queue: BoundedEventQueue):
        if not registry.can_ingest(sensor_id, tenant_id):
            raise PermissionError("sensor is not active for this tenant")
        self.sensor_id = sensor_id
        self.tenant_id = tenant_id
        self.registry = registry
        self.queue = queue

    def emit(self, kind: str, **fields: Any) -> SignalEvent:
        event = new_event(self.sensor_id, self.tenant_id, kind, **fields)
        if not self.queue.put(event):
            raise BufferError("sensor queue is full; event was not accepted")
        return event

    def health(self) -> Dict[str, Any]:
        state = self.registry.get(self.sensor_id)
        return {"sensor_id": self.sensor_id, "tenant_id": self.tenant_id, "state": state["state"] if state else "unknown", "queue": self.queue.metrics()}
