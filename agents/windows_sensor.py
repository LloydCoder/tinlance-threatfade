"""Windows sensor architecture boundary.

Windows capture is delegated to Npcap rather than inventing a kernel driver.
The service host remains a normal user-space process and receives the same
canonical SignalEvent objects as Linux.
"""
from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Callable

from core.data_plane import SignalEvent
from .live_capture import LiveCaptureAdapter


@dataclass(frozen=True)
class WindowsSensorConfig:
    interface: str
    service_name: str = "ThreatFadeSensor"
    require_npcap: bool = True


class WindowsSensor:
    """Npcap-backed Windows capture facade; service installation is external."""

    def __init__(self, *, sensor_id: str, tenant_id: str, config: WindowsSensorConfig,
                 emit: Callable[[SignalEvent], bool]):
        if platform.system() != "Windows":
            raise OSError("WindowsSensor can only run on Windows")
        self.config = config
        self.capture = LiveCaptureAdapter(sensor_id=sensor_id, tenant_id=tenant_id,
                                          interface=config.interface, emit=emit)

    def run(self, stop_event=None) -> None:
        self.capture.run(stop_event=stop_event)

    def health(self) -> dict:
        return {"platform": "windows", "capture_backend": "npcap", "service_name": self.config.service_name,
                "capture": self.capture.metrics()}
