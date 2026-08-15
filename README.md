# ThreatFade

**Evasion Interception Platform** by Tinlance Limited.

ThreatFade detects moments when adversaries intentionally reduce observable signals — for example C2 quieting, gradual LOTL activity reduction, and GNSS interference — and reconstructs the event using entropy analysis, z-score anomaly detection, heuristic rules, confidence scoring, optional ML anomaly detection, MITRE ATT&CK mapping, SIEM export, and operational integrations.

**Status:** v0.4.0
**License:** Apache 2.0 (open-core)

## Quick start

```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Run the API:

```bash
python api.py
curl http://localhost:8080/health
```

## Detection pipeline

```text
Signal / PCAP
     ↓
Signal extraction
     ↓
Rolling entropy + statistical deviation
     ↓
Heuristic detection rules
     ↓
Optional Isolation Forest anomaly layer
     ↓
Confidence + evidence
     ↓
MITRE ATT&CK mapping
     ↓
SIEM / Sigma / STIX 2.1 / FusionOps
```

## Current capabilities

### Detection and analytics

- Direct PCAP/PCAPNG ingestion
- Hybrid encrypted/unencrypted PCAP signal extraction
- Rolling Shannon entropy analysis
- Z-score anomaly detection
- Rule-based fade detection
- Confidence scoring: critical/high/medium/low/info
- Optional Isolation Forest ML anomaly layer
- Structured, analyst-readable detection evidence
- Alert deduplication
- Multi-agent coordination
- Live network/process monitoring
- Satellite signal fusion: AIS/ADS-B/GPS

### Threat scenarios

- C2 quieting
- LOTL gradual reduction
- GNSS jamming
- Mixed threat activity
- Normal traffic with temporary signal dips for false-positive testing

### Interoperability

- JSON
- Splunk HEC
- CEF
- CSV
- Sigma-compatible detection output
- STIX 2.1-compatible bundles
- MITRE ATT&CK mapping
- FusionOps integration

### Operational API

FastAPI endpoints include:

- `GET /health`
- `GET /version`
- `POST /detect`
- `POST /detect/scenario`
- `POST /detect/pcap`

The API supports optional API-key authentication, request rate limiting, configurable PCAP upload limits, configurable CORS origins, input validation, temporary-file cleanup, and structured evidence responses.

Configure production controls with `.env`:

```text
THREATFADE_API_KEY=
THREATFADE_MAX_PCAP_BYTES=104857600
THREATFADE_RATE_LIMIT=120
THREATFADE_RATE_WINDOW_SECONDS=60
THREATFADE_ALLOWED_ORIGINS=http://localhost:8080
```

If `THREATFADE_API_KEY` is configured, protected detection endpoints require `X-API-Key`.

## Detection evidence

Every API detection now exposes structured evidence rather than only a verdict:

```json
{
  "summary": "sustained reduction in signal activity; statistically significant deviation from baseline",
  "signals": [
    "sustained reduction in signal activity",
    "statistically significant deviation from baseline"
  ],
  "metrics": {
    "score": 0.81,
    "entropy": 1.12,
    "drop_ratio": 0.67,
    "z_outlier": 7.01,
    "rules_matched": 2
  },
  "fade_start": 42
}
```

This is designed for analysts and downstream automation: the system records **why** a detection fired, not merely that it fired.

## Detection packs

ThreatFade includes versioned detection-pack metadata with stable rule IDs, semantic versions, descriptions, and ATT&CK mappings.

Current core rules include:

- `TF-C2-001` — C2 signal fade
- `TF-LOTL-001` — LOTL gradual fade
- `TF-GNSS-001` — GNSS interference

## Benchmarking

The repository contains a reproducible synthetic benchmark:

```bash
python benchmarks/benchmark.py
```

It evaluates expected detection/non-detection across the deterministic scenario suite and records accuracy, confidence, score, and detector latency in `reports/benchmarks/`.

The benchmark is deliberately separate from the project's real-PCAP validation. Real-PCAP results remain documented as validation evidence rather than being mixed with synthetic test metrics.

## Adversarial testing

The test suite covers robustness against:

- jitter/noisy signals
- sustained fades
- constant signals
- extreme values
- minimum-length inputs
- configuration boundaries
- false-positive scenarios

The goal is to make evasion detection resilient without treating synthetic tests as proof of universal real-world accuracy.

## Memory analysis

ThreatFade retains the existing simulated Volatility artifact layer and now includes an optional `core/volatility_adapter.py` integration boundary for Volatility 3. The adapter validates memory-image inputs and reports whether the Volatility 3 runtime is available, allowing memory analysis to be added without making the base detector depend on the optional engine.

## Observability

`core/observability.py` provides optional OpenTelemetry tracing around detector execution. When the OpenTelemetry API is installed, ThreatFade creates `threatfade` spans; otherwise it safely falls back to a no-op implementation.

## Real-world validation

The project has been validated by the author against real malware traffic and the existing repository validation corpus, including Merlin QUIC C2, Cobalt Strike, and IcedID. The author has separately confirmed the reported validation claims and measurements.

The current repository records the following validated results:

| Source | Packets / capture | Detected | Z-score | Confidence | MITRE TTP |
|---|---:|---|---:|---|---|
| Merlin QUIC C2 | 490,565 packets / 521 sessions | YES | 14.76 | HIGH | T1573.002 |
| Cobalt Strike | Real PCAP | YES | 7.01 | MEDIUM | T1027 |
| IcedID | Real PCAP | YES | 3.89 | LOW | T1027 |

The validated false-positive baseline is **0% across 5 normal traffic patterns and 100 test runs**, as documented by the project owner.

## Architecture

```text
main.py                         CLI and PCAP ingestion
api.py                          FastAPI API + security controls
core/fade_engine.py             Entropy + z-score + rules + confidence
core/explainability.py          Structured analyst evidence
core/siem_exporter.py           SIEM output
core/interoperability.py        Sigma + STIX 2.1 output
core/detection_pack.py          Versioned detection metadata
core/alert_dedup.py             Alert deduplication
core/live_monitor.py            Live monitoring
core/pcap_stream_processor.py   Streaming PCAP processing
core/pcap_parallel_processor.py Parallel PCAP processing
core/ml_stub.py                 Isolation Forest layer
core/observability.py           Optional OpenTelemetry tracing
core/volatility_adapter.py      Optional Volatility 3 integration boundary
agents/                         Endpoint and multi-agent components
satellite/                      AIS/ADS-B/GPS signal fusion
mitre/                          ATT&CK mapping
viz/                            Timeline visualization
dashboard/                      Web dashboard
```

## Testing

Run everything locally:

```bash
pytest -q
python -m compileall -q .
python benchmarks/benchmark.py
python -c "from core.detection_pack import detection_pack, validate_pack; validate_pack(detection_pack())"
```

GitHub Actions runs the complete test suite across Python 3.9–3.12, compiles all Python sources, executes the reproducible benchmark, and validates the detection pack.

## Limitations

- Real-world accuracy depends on traffic, signal quality, protocol behavior, and detector configuration.
- The public benchmark is synthetic and deterministic; it is not a substitute for a large independent labeled corpus.
- Volatility 3 support is optional and does not replace the existing simulated memory-artifact reference implementation.
- Large PCAP processing remains workload-dependent.
- ATT&CK mapping includes the project's implemented rule-based mappings; it is not a claim of complete STIX-native ATT&CK coverage.

## Roadmap

Future enterprise work includes multi-tenant federation, large-scale performance optimization, richer memory forensics, expanded detector packs, broader labeled benchmarks, and deeper SOC integrations.

## Contributing

Bug reports, detection improvements, test cases, integrations, and documentation improvements are welcome. See `CONTRIBUTING.md` and `SECURITY.md`.

## Related platform

ThreatFade is designed to feed Tinlance's operational security stack, including FusionOps.

**Built by Nwachukwu Chinaemerem (@LloydCoder)**  
**Tinlance Limited**
