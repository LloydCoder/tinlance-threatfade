#!/usr/bin/env python3
"""Reproducible Phase 7 data-plane benchmark.

The benchmark deliberately measures the existing canonical event and detection
pipeline without claiming packet-capture throughput. Capture must be benchmarked
with the platform adapter on the target host. Synthetic events isolate the
software data-plane stages and make CI results reproducible.
"""
from __future__ import annotations

import argparse
import gc
import json
import os
import platform
import resource
import statistics
import time
from datetime import datetime, timedelta, timezone

from agents.detection_pipeline import SensorDetectionPipeline
from core.data_plane import SignalEvent


def make_event(i: int) -> SignalEvent:
    return SignalEvent(
        event_id=f"bench-{i:012d}", sensor_id="bench-sensor", tenant_id="bench-tenant",
        kind="packet", observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=i),
        protocol="tcp", src_ip="10.0.0.10", dst_ip="10.0.0.20", src_port=40000 + (i % 1000),
        dst_port=443, bytes_in=128 + (i % 32), bytes_out=256 + (i % 64), packets=1,
    )


def rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value * (1024 if platform.system() != "Darwin" else 1)


def run(target: int, duration: float) -> dict:
    gc.collect()
    gc.disable()
    pipeline = SensorDetectionPipeline(window_size=256)
    produced = 0
    accepted = 0
    latencies_ns: list[int] = []
    start = time.perf_counter_ns()
    deadline = time.perf_counter() + duration
    while time.perf_counter() < deadline:
        event = make_event(produced)
        produced += 1
        t0 = time.perf_counter_ns()
        event.canonical_bytes()
        pipeline.ingest(event)
        latencies_ns.append(time.perf_counter_ns() - t0)
        accepted += 1
        if target and accepted >= target:
            break
    elapsed = (time.perf_counter_ns() - start) / 1e9
    gc.enable()
    latencies_ns.sort()
    return {
        "target_events": target,
        "events": accepted,
        "elapsed_seconds": round(elapsed, 6),
        "throughput_events_per_second": round(accepted / elapsed, 2) if elapsed else 0,
        "latency_us_p50": round(statistics.median(latencies_ns) / 1000, 3) if latencies_ns else 0,
        "latency_us_p95": round(latencies_ns[int(len(latencies_ns) * 0.95)] / 1000, 3) if latencies_ns else 0,
        "latency_us_p99": round(latencies_ns[int(len(latencies_ns) * 0.99)] / 1000, 3) if latencies_ns else 0,
        "max_rss_bytes": rss_bytes(),
        "pipeline_metrics": pipeline.metrics(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=100_000)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--output", default="phase7-benchmark.json")
    args = parser.parse_args()
    if args.events < 1 or args.events > 10_000_000 or args.duration <= 0 or args.duration > 600:
        raise SystemExit("invalid benchmark bounds")
    result = run(args.events, args.duration)
    result.update({
        "benchmark": "phase7-data-plane",
        "schema_version": 1,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "cpu": platform.processor(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
