# ThreatFade documentation

This index is the entry point for maintainers, operators, contributors and technical evaluators. The repository contains both current operational guidance and historical engineering/phase records. When documents disagree, prefer current executable behavior, tests, workflow definitions, `docs/public-truth.json`, and the current reference pages.

## Tutorials

A tutorial is a guided learning path that produces a working result.

- [Repository quick start](../README.md#quick-start)
- [Run a local scenario](../README.md#usage)
- [Performance benchmark walkthrough](../benchmarks/README.md)

## How-to guides

Task-oriented operational instructions:

- [Secure deployment](SECURE_DEPLOYMENT.md)
- [Configuration reference](reference/configuration.md)
- [Sensor runtime](SENSOR_RUNTIME.md)
- [Enterprise integrations](ENTERPRISE_INTEGRATIONS.md)
- [Alerting](alerting.md)
- [Disaster recovery](DISASTER_RECOVERY.md)

## Explanation

Concepts, design rationale and system behavior:

- [Security architecture](SECURITY_ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Enterprise readiness and evidence boundaries](ENTERPRISE_READINESS.md)
- [Detection science](GROUP_9_DETECTION_SCIENCE.md)
- [Detection data plane](GROUP_11_DATA_PLANE.md)
- [Multi-domain correlation](GROUP_12_SOC_PRODUCTIZATION.md)
- [Identity architecture](GROUP_8_IDENTITY.md)
- [Architecture decision records](adr/)

## Reference

- [ASVS 5.0 control matrix](ASVS_5.0_MATRIX.md)
- [Detection evaluation methodology](DETECTION_EVALUATION.md)
- [Ground-truth dataset standard](GROUND_TRUTH_DATASET_STANDARD.md)
- [Environment profiles](ENVIRONMENT_PROFILES.md)
- [Enterprise integration contracts](ENTERPRISE_INTEGRATIONS.md)
- [GitHub About, social preview and branch-protection guidance](REPOSITORY_SETTINGS.md)
- [Public capability/evidence manifest](public-truth.json)
- [Build status](BUILD_STATUS.md)
- [Independent assurance package](evaluation/INDEPENDENT_VALIDATION_PACKAGE.md)
- [Penetration-test scope](evaluation/PENTEST_SCOPE.md)
- [Scale benchmark protocol](evaluation/SCALE_BENCHMARK_PROTOCOL.md)
- [Purple-team protocol](evaluation/PURPLE_TEAM_PROTOCOL.md)

## Historical phase records

Documents named `PHASE_*` or `GROUP_*` preserve implementation history and acceptance evidence. They are not a substitute for the current README, configuration reference or deployment guide. Check their stated version, phase and evidence boundary before using them operationally.

## Contribution and policy

- [Contributing](../CONTRIBUTING.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Security policy](../SECURITY.md)
- [Support](../SUPPORT.md)
- [Changelog](../CHANGELOG.md)
- [License](../LICENSE)

## Documentation principles

ThreatFade documentation follows the Diátaxis distinction between tutorials, how-to guides, explanation and reference. Prefer relative links for files in this repository. Keep examples reproducible, label synthetic and experimental evidence, and never promote a repository test into a customer or independent-assurance claim.
