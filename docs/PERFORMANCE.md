# ThreatFade Performance Engineering

## Phase 7 policy

ThreatFade does not claim a target throughput until it is measured on a named hardware/software configuration. The historical 1M packets/sec roadmap target is therefore **not a current product claim**.

The first reproducible benchmark measures canonical event construction, serialization and bounded in-memory queue ingestion. It is a data-plane microbenchmark, not a live NIC capture benchmark and not an end-to-end detection benchmark.

## Reproduction

```bash
python benchmarks/phase7_data_plane_benchmark.py --rate 10000 --duration 10
python benchmarks/phase7_data_plane_benchmark.py --rate 100000 --duration 10
python benchmarks/phase7_data_plane_benchmark.py --rate 500000 --duration 10
python benchmarks/phase7_data_plane_benchmark.py --rate 1000000 --duration 10
```

Run these workloads separately and retain the JSON output with hardware, OS and Python version. Do not compare results across machines as though they were equivalent.

## Metrics

The harness records requested events, elapsed time, throughput, accepted/dropped events, drop rate, queue depth, p50/p99 enqueue latency, Python version, platform and CPU count.

The next performance gate must add live-capture packet-loss measurement, CPU/RAM, disk/network I/O, sustained-duration behavior and end-to-end detection latency on controlled hardware before making a packet-per-second product claim.

## Optimization policy

Profile first. Prefer algorithmic improvements and vectorization where they materially reduce measured CPU cost. Use multiprocessing/native extensions/Rust/eBPF/GPU only when a reproducible profile demonstrates that the technique is justified and the resulting operational/security complexity is acceptable.

## Acceptance boundary

A CI benchmark proves that the harness runs reproducibly and that its internal invariants hold. It does **not** prove 10K/100K/500K/1M live packet processing. Field or lab capture benchmarks are required for those claims.
