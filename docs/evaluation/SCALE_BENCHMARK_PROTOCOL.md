# ThreatFade Independent Scale Benchmark Protocol

## Purpose

Define reproducible performance testing for throughput, latency, resource usage, concurrency and failure recovery. This document defines the protocol only; it contains no fabricated performance result.

## Required environment record

- ThreatFade release commit/tag
- detector and detection-pack versions
- CPU model and core count
- memory
- storage type and capacity
- operating system/container image digest
- Python/runtime versions
- configuration and feature flags
- dataset/scenario manifest digest
- concurrency level
- measurement tooling versions

## Measurements

### Throughput

Report records, flows or bytes processed per second using a precisely defined unit.

### Latency

Report at minimum median and tail latency when the workload permits. State the measurement boundary, warm-up policy and sample count.

### Resource usage

Measure CPU, resident memory, storage growth and queue depth where relevant.

### Concurrency

Evaluate defined concurrent workloads and identify saturation points rather than selecting a single flattering operating point.

### Failure recovery

Measure recovery behavior after controlled dependency/process interruption, including time to resume, lost work and duplicate processing.

## Statistical requirements

Use repeated runs and report sample size, variance/uncertainty and environmental conditions. Do not publish a single-run number as a general performance claim.

NIST SP 800-55 Volumes 1 and 2 are the measurement-program reference for selecting, documenting and interpreting security/performance measures.

## Regression policy

Regression thresholds must be justified by historical measurements and workload characteristics. A threshold is a guardrail, not a guarantee of production performance.

## External validation gate

A scale result is **independently validated** only when the measurement is reproduced by an independent evaluator using a frozen methodology and artefact set. Internal benchmark results remain internal evidence.
