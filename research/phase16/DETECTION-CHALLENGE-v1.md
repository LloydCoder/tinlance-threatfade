# ThreatFade Detection Challenge v1

## Purpose

Evaluate reproducible approaches to behavioral fade detection against a versioned synthetic challenge set without exposing customer data or treating the challenge as a production accuracy claim.

## Challenge tracks

### Track A — Rule-based reproduction

Participants reproduce or extend the documented behavioral-fade approach using the public synthetic fixture.

### Track B — Independent detector

Participants implement an independent detector against the same feature/event contract. The submission must disclose feature provenance and whether any ThreatFade implementation was reused.

### Track C — Robustness research

Participants evaluate controlled perturbations such as timing jitter, signal sparsity and benign transient fades. Results must include the perturbation protocol and limitations.

## Submission contract

A submission consists of:

- detector name and version;
- source repository or reproducible package;
- exact dataset manifest/digest;
- execution command;
- prediction/output file;
- runtime and dependency versions;
- resource limits;
- methodology statement;
- known limitations.

No packet capture, customer telemetry, secrets or credentials should be submitted.

## Evaluation

The evaluator computes metrics from raw predictions and the challenge labels. The public leaderboard remains **unpublished/empty** until a submission is actually evaluated.

Required metrics depend on the track, but should include confusion-matrix counts and precision/recall/F1 where labels support them. Robustness tracks must report results per perturbation rather than only an aggregate score.

## Anti-leakage rules

- Do not train on hidden evaluation data.
- Do not modify challenge labels.
- Do not use future/held-out labels during detector fitting.
- Disclose external datasets and pretrained models.
- Do not submit executable code that requires unrestricted network access to evaluate.

## Evidence boundary

Challenge performance is benchmark evidence for the specified dataset and protocol. It is not independent validation, a universal detection guarantee, or a customer performance SLA.
