# ThreatFade Purple-Team Validation Protocol

## Purpose

Define a controlled adversarial evaluation that tests ThreatFade against realistic behavioral changes without claiming an independent result before an external evaluator executes the protocol.

## Design principles

- behavior-focused rather than IOC-only
- reproducible and versioned
- separate attack generation from detector tuning
- freeze scenarios and thresholds before blind execution
- preserve benign controls and negative cases
- record deviations and environmental changes

MITRE ATT&CK adversary-emulation material is used as the behavioral planning reference. The protocol should map each scenario to the relevant ATT&CK behavior where a meaningful mapping exists, while avoiding claims that ThreatFade detects an entire ATT&CK technique from one scenario.

## Scenario families

1. C2 beaconing with controlled quieting/fade
2. periodicity degradation
3. encrypted-traffic distribution change
4. benign service degradation
5. application update/configuration change
6. sensor loss and partial capture
7. protocol/configuration migration
8. temporal/environmental drift
9. adversarial feature perturbation
10. recovery after the behavioral signal returns

## Execution phases

### Phase A — calibration

Run only on development/calibration data. Thresholds may be tuned here.

### Phase B — freeze

Freeze:

- detector version
- detection-pack version
- configuration
- thresholds
- scenario definitions
- corpus membership
- evaluator tooling

Record SHA-256 digests.

### Phase C — blind execution

An evaluator or separate validation operator controls the labels and executes the frozen protocol without changing detector thresholds or scenario membership.

### Phase D — analysis

Report per-scenario confusion matrices, precision, recall, FPR/FNR, latency and evidence completeness where measurable. Include denominators and uncertainty intervals for headline rates.

## Safety

Only authorised lab environments and benign/synthetic or legally controlled traffic should be used. No protocol step requires uncontrolled malware deployment or access to third-party systems.

## Independence gate

Internal purple-team execution is **internal validation**. It becomes **independent validation** only when an appropriately independent evaluator controls the blind evaluation and produces a signed report.
