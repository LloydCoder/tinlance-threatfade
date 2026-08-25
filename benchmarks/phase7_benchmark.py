#!/usr/bin/env python3
"""Reproducible Phase 7 sustained software-data-plane benchmark."""
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


def run(target_pps: int, duration: float) -> dict:
    gc.collect()
    gc.disable()
    pipeline = SensorDetectionPipeline(window_size=256)
    produced = 0
    accepted = 0
    latencies_ns: list[int] = []
    start = time.perf_counter()
    deadline = start + duration
    next_slot = start
    while time.perf_counter() < deadline:
        now = time.perf_counter()
        if now < next_slot:
            time.sleep(min(next_slot - now, 0.001))
            continue
        event = make_event(produced)
        produced += 1
        t0 = time.perf_counter_ns()
        event.canonical_bytes()
        pipeline.ingest(event)
        latencies_ns.append(time.perf_counter_ns() - t0)
        accepted += 1
        next_slot += 1.0 / target_pps
        if next_slot < time.perf_counter() - 1.0:
            next_slot = time.perf_counter()
    elapsed = time.perf_counter() - start
    gc.enable()
    latencies_ns.sort()
    return {
        "target_pps": target_pps,
        "events": accepted,
        "elapsed_seconds": round(elapsed, 6),
        "throughput_events_per_second": round(accepted / elapsed, 2) if elapsed else 0,
        "target_achievement_ratio": round((accepted / elapsed) / target_pps, 4) if elapsed else 0,
        "latency_us_p50": round(statistics.median(latencies_ns) / 1000, 3) if latencies_ns else 0,
        "latency_us_p95": round(latencies_ns[int(len(latencies_ns) * 0.95)] / 1000, 3) if latencies_ns else 0,
        "latency_us_p99": round(latencies_ns[int(len(latencies_ns) * 0.99)] / 1000, 3) if latencies_ns else 0,
        "max_rss_bytes": rss_bytes(),
        "pipeline_metrics": pipeline.metrics(),
        "packet_loss": None,
        "note": "Software data-plane benchmark only; NIC capture loss is measured by the platform sensor benchmark.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-pps", type=int, default=10_000)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--output", default="phase7-benchmark.json")
    args = parser.parse_args()
    if args.target_pps < 100 or args.target_pps > 1_000_000 or args.duration <= 0 or args.duration > 600:
        raise SystemExit("invalid benchmark bounds")
    result = run(args.target_pps, args.duration)
    result.update({
        "benchmark": "phase7-data-plane-sustained",
        "schema_version": 2,
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
