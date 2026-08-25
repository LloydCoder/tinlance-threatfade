"""Platform-neutral sensor runtime orchestrator.

Capture adapters feed canonical events into the durable queue. The runtime
continues collecting while the sender/control plane is unavailable and shuts
down gracefully on request.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from core.data_plane import SignalEvent, SensorRegistry
from .durable_queue import DurableSensorQueue


@dataclass(frozen=True)
class RuntimeLimits:
    max_queue_bytes: int = 256 * 1024 * 1024
    max_queue_events: int = 100_000
    batch_size: int = 100
    send_interval_seconds: float = 1.0


class EdgeSensorRuntime:
    def __init__(self, *, sensor_id: str, tenant_id: str, registry: SensorRegistry,
                 queue: DurableSensorQueue, sender: Optional[Callable[[list[tuple[int, bytes]]], int]] = None,
                 limits: RuntimeLimits = RuntimeLimits()):
        if not registry.can_ingest(sensor_id, tenant_id):
            raise PermissionError("sensor is not active for tenant")
        self.sensor_id = sensor_id
        self.tenant_id = tenant_id
        self.registry = registry
        self.queue = queue
        self.sender = sender
        self.limits = limits
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._accepted = 0
        self._rejected = 0

    def ingest(self, event: SignalEvent) -> bool:
        if event.sensor_id != self.sensor_id or event.tenant_id != self.tenant_id:
            raise PermissionError("event identity does not match sensor binding")
        accepted = self.queue.enqueue(event)
        if accepted:
            self._accepted += 1
        else:
            self._rejected += 1
        return accepted

    def _run(self) -> None:
        while not self._stop.wait(self.limits.send_interval_seconds):
            if self.sender is None:
                continue
            try:
                self.queue.replay(self.sender, batch_size=self.limits.batch_size)
            except (OSError, TimeoutError, ConnectionError):
                # Offline mode is expected; local durable queue remains source of truth.
                continue
            except Exception:
                # Sender failures must not stop capture. The next cycle retries.
                continue

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"threatfade-sensor-{self.sensor_id}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def health(self) -> dict:
        return {"sensor_id": self.sensor_id, "tenant_id": self.tenant_id,
                "state": (self.registry.get(self.sensor_id) or {}).get("state", "unknown"),
                "queue": self.queue.metrics(), "accepted": self._accepted, "rejected": self._rejected,
                "sender_configured": self.sender is not None, "running": bool(self._thread and self._thread.is_alive())}
