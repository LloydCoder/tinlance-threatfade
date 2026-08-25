"""Reproducible sensor-path benchmark.

This benchmark measures canonical event construction + bounded durable enqueue.
It is deliberately not presented as a line-rate NIC benchmark. Run on the
specified host and record packets/sec, CPU, RAM, queue depth and duration.
"""
from __future__ import annotations

import argparse
import os
import platform
import tempfile
import time
from datetime import datetime, timezone

from agents.durable_queue import DurableSensorQueue
from core.data_plane import SignalEvent


def run(count: int, duration: float) -> dict:
    with tempfile.TemporaryDirectory() as td:
        queue = DurableSensorQueue(os.path.join(td, "events.db"), max_bytes=512 * 1024 * 1024, max_events=max(count + 100, 1000))
        start = time.perf_counter()
        accepted = 0
        for i in range(count):
            event = SignalEvent(event_id=f"bench-{i}", sensor_id="bench-sensor", tenant_id="bench-tenant",
                                kind="packet", observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                                protocol="udp", packets=1, bytes_in=128)
            accepted += queue.enqueue(event)
        elapsed = max(time.perf_counter() - start, 1e-9)
        return {"events": count, "accepted": accepted, "events_per_sec": round(accepted / elapsed, 2),
                "elapsed_sec": round(elapsed, 4), "queue": queue.metrics(), "duration_target_sec": duration,
                "python": platform.python_version(), "os": platform.platform(), "cpu_count": os.cpu_count()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--duration", type=float, default=10.0)
    args = parser.parse_args()
    print(run(args.events, args.duration))
