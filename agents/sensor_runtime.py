"""CLI entry point for the Linux/edge sensor runtime.

Enrollment is explicit: sensor identity and tenant binding are supplied by the
operator/bootstrap system. This process never derives tenant identity from
network input and never enables capture implicitly without an interface.
"""
from __future__ import annotations

import argparse
import signal
import threading

from core.data_plane import SensorRegistry
from .detection_pipeline import SensorDetectionPipeline
from .durable_queue import DurableSensorQueue
from .edge_runtime import EdgeSensorRuntime
from .live_capture import LiveCaptureAdapter


def main() -> int:
    p = argparse.ArgumentParser(description="ThreatFade sensor runtime")
    p.add_argument("--sensor-id", required=True)
    p.add_argument("--tenant-id", required=True)
    p.add_argument("--fingerprint", required=True, help="SHA-256 sensor identity fingerprint")
    p.add_argument("--interface", required=True)
    p.add_argument("--queue", default="/var/lib/threatfade/events.db")
    args = p.parse_args()
    if len(args.fingerprint) != 64 or any(c not in "0123456789abcdefABCDEF" for c in args.fingerprint):
        raise SystemExit("fingerprint must be SHA-256 hex")

    registry = SensorRegistry()
    registry.register(args.sensor_id, args.tenant_id, version="0.8.0", fingerprint=args.fingerprint.lower())
    registry.activate(args.sensor_id)
    queue = DurableSensorQueue(args.queue)
    pipeline = SensorDetectionPipeline()
    runtime = EdgeSensorRuntime(sensor_id=args.sensor_id, tenant_id=args.tenant_id,
                                registry=registry, queue=queue, detection_pipeline=pipeline)
    capture = LiveCaptureAdapter(sensor_id=args.sensor_id, tenant_id=args.tenant_id,
                                 interface=args.interface, emit=runtime.ingest)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    runtime.start()
    try:
        capture.run(stop_event=stop)
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
