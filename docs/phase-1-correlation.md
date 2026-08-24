# Phase 1 — Multi-Domain Fade Correlation

## Status

**Implemented — not yet production validated.**

Builds 83–90 establish the first reusable multi-domain temporal correlation capability. Repository tests and deterministic synthetic validation prove the implementation contract; they do not establish field accuracy or causality.

## Architecture

```text
GNSS / network / endpoint / RF / timing / sensor-health observations
                         │
                         ▼
                 canonical SignalEvent
                         │
                         ▼
             CorrelationObservation
                         │
                         ▼
              TemporalCorrelationEngine
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
      time window    sensor confidence   uncertainty
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                multi-domain confidence
                         │
                         ▼
                 CorrelatedDetection
                         │
                         ▼
               evidence custody record
                         │
                         ▼
             analyst / dashboard view
```

## Builds

- **83 — Correlation event model:** `CorrelationObservation` normalizes domain, signal type, score, sensor confidence, uncertainty, timestamp and source-event digest.
- **84 — Temporal correlation engine:** deterministic time-window matching with tenant isolation, duplicate suppression, out-of-order normalization and explicit policy bounds.
- **85 — GNSS/network detection pack:** `TF-GNSS-CORR-001` is the first concrete deployment of the generic correlation model. The generic `TF-CORR-001` rule remains reusable for future domains.
- **86 — Evidence/confidence integration:** confidence combines temporal proximity, signal strength, sensor confidence/uncertainty and corroboration strength. Evidence is SHA-256 bound to source event digests and can be placed into the existing evidence custody chain.
- **87 — Validation corpus:** `validation/correlation_corpus.json` contains synthetic metadata-only scenarios with governed limitations.
- **88 — Robustness validation:** tests cover temporal separation, missing domains, weak signals, tenant isolation, duplicate events, out-of-order events, uncertainty and policy validation.
- **89 — Dashboard visualization:** `dashboard/correlation.html` and the public web correlation evidence view provide analyst-facing visualization without inventing live telemetry.
- **90 — Documentation/claims:** this document records the evidence boundary and explicitly separates observed correlation from causal attribution.

## Correlation policy

The initial GNSS/network pack uses:

- 30 second maximum correlation window.
- 5 second explicit clock-skew tolerance.
- 0.50 minimum signal score per participating observation.
- 0.65 minimum fused confidence for emission of a correlation result.
- At least two independent domains.
- Same-tenant observations only.
- Duplicate event IDs excluded from scoring.
- Out-of-order input normalized by timestamp and recorded as provenance.
- Missing required domains fail closed and do not emit a correlated detection.

These values are **engineering defaults**, not universal detection thresholds. They must be calibrated against representative labeled field data before any production-accuracy claim.

## Evidence boundary

ThreatFade emits:

> **OBSERVED CORRELATION** — independent signal domains overlapped within the configured temporal and confidence constraints.

ThreatFade does **not** emit:

> GNSS interference caused the network fade.

Nor does it infer that GNSS disruption was intentional, malicious, jamming or spoofing solely from temporal correlation. GNSS outages/interference have benign, accidental and adversarial causes. Independent timing and sensor sources are relevant to stronger GNSS integrity conclusions.

## Research basis

NIST work on GNSS spoofing and resilient timing supports multi-source corroboration and explicit treatment of timing uncertainty rather than relying on a single GNSS signal. NIST's timing guidance also distinguishes jamming from spoofing and recommends independent timing references for resilience. MITRE ATT&CK documents signal jamming as a possible network-impact technique, but the presence of a GNSS disruption alone does not establish adversarial activity.

## Validation boundary

The current validation corpus is synthetic metadata only. It demonstrates deterministic software behavior and adversarial edge handling. It does **not** establish:

- field false-positive rate;
- field recall;
- GNSS jamming/spoofing classification accuracy;
- causality between GNSS and network events;
- performance under real sensor clock drift;
- customer-scale multi-sensor throughput;
- independent third-party assurance.

Production validation requires representative multi-sensor datasets, independently labeled scenarios, clock-quality characterization, environmental controls and external/purple-team validation.
