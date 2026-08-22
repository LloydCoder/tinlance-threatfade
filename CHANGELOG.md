# Changelog

All notable changes to ThreatFade will be documented in this file.

## [0.6.0] – 2026-08-22

### Disaster Recovery, Backup & Operational Continuity

#### Added
- Portable PostgreSQL custom-format backup generator with SHA-256 integrity manifest.
- Credential-safe PostgreSQL command construction using `PGPASSWORD` rather than putting database credentials in command-line arguments.
- Backup catalog verification using `pg_restore --list`.
- Isolated restore drill that verifies Alembic migration state, required enterprise tables and forced PostgreSQL RLS.
- Disaster-recovery architecture acceptance gate.
- CI-integrated backup creation, artifact verification and isolated restore verification against PostgreSQL 16.
- Recovery runbook defining RPO/RTO targets, backup tiers, restore procedure, integrity checks and production/infrastructure boundaries.

#### Operational notes
- Production low-RPO recovery is expected to use provider-native PostgreSQL PITR/WAL archiving; the repository's logical dump is a complementary portable recovery mechanism.
- CI recovery artifacts are ephemeral and are never committed to the repository.
- RPO/RTO values are engineering targets, not contractual guarantees.

## [0.5.0] – 2026-08-22

### Reliability, Observability & Resilience

#### Added
- Prometheus-compatible request counters, latency histograms, in-flight gauges, detection counters and build metadata.
- Low-cardinality HTTP telemetry with optional OpenTelemetry tracing spans.
- Dependency-aware readiness checks with real database connectivity validation.
- Explicit liveness, readiness and startup operational endpoints.
- FastAPI lifespan lifecycle state for controlled startup and shutdown.
- Bounded exponential retry policy with jitter and transient-error filtering.
- Thread-safe circuit breaker with closed/open/half-open recovery.
- Synchronous and asynchronous bulkhead primitives for bounded concurrency.
- Reliability acceptance script and regression tests.
- Kubernetes startup/readiness/liveness probes, safe rolling updates, topology spread and PodDisruptionBudget.
- Container healthcheck now tests liveness independently of backend readiness.

#### Operational notes
- Readiness returns `503` when required storage is unavailable or the application is draining.
- Resilience controls fail closed rather than silently discarding detection work.
- Metrics intentionally avoid tenant/user identifiers as labels to prevent high-cardinality telemetry.

## [1.0.0-beta] – 2026-03-09

### Initial Release

**Early Research MVP – Simulated data only**

#### Added
- Core fade detection engine (entropy + z-score + rule-based)
- Multi-scenario signal simulation
- JSON report export
- Comprehensive pytest test suite
- YAML configuration management
- Environment variable support for secrets
- GitHub Actions CI/CD pipeline
- Apache 2.0 open-core licensing

#### Known Limitations
- Detection trained on simulated data only
- False positive rate unknown on real traffic
- MITRE/Volatility implementations are stubs
- Telegram-only alerts
- No endpoint agents yet

---

## Versioning

This project follows Semantic Versioning.

## Contributing

Found a bug or want to contribute? See [CONTRIBUTING.md](CONTRIBUTING.md)

---

© 2026 Tinlance Limited
