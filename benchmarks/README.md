# Phase 7 Performance Benchmarking

Phase 7 measures the existing ThreatFade software data plane before any native rewrite.

## Stages

1. capture adapter (platform-specific; benchmarked separately on deployment hosts)
2. canonical `SignalEvent` construction/validation
3. canonical serialization/digest
4. bounded queueing
5. session-window reconstruction
6. entropy/statistical/ML stages where enabled
7. evidence/persistence/API stages in their dedicated integration benchmarks

`phase7_benchmark.py` isolates stages 2–5 using deterministic synthetic `SignalEvent` input. It is not a packet-capture benchmark and must not be used to claim packets/sec at the NIC.

## Reproducibility

```bash
python benchmarks/phase7_benchmark.py --events 100000 --duration 10 --output phase7-benchmark.json
```

Record Python version, OS, CPU, event count, duration, throughput, p50/p95/p99 latency, RSS and pipeline depth. Repeat at least three times and report median plus run variance.

## Scale points

The validation matrix is 10K, 100K, 500K and, only where the target host sustains it, 1M events/sec. A target is never considered achieved merely because a short synthetic burst reaches it. Sustained capture benchmarks must additionally record packet loss, CPU, RAM, queue depth, disk I/O and network I/O.

## Engineering rule

No Rust/native/GPU rewrite is justified by the roadmap alone. A rewrite requires a measured hotspot, a baseline benchmark, an equivalent implementation, and a regression benchmark showing a material improvement without weakening correctness or security.
