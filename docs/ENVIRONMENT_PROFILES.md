# ThreatFade Environment Profiles

## Purpose

Environment profiles are tenant-scoped, versioned configuration describing expected operating context and adaptive detection baselines. They are context, not verdicts.

ThreatFade deliberately separates:

- **Observed behavior:** telemetry actually measured by sensors and the detection data plane.
- **Authorized behavior:** behavior an operator has declared expected or permitted through a versioned profile.

A mismatch is contextual evidence only. It is never sufficient by itself to label behavior malicious. Independent detection/evidence remains required.

## Profile schema v1.1

A profile contains:

- `profile_id`, `tenant_id`, `version`, `schema_version`
- expected protocols and ports
- baseline entropy and periodicity by protocol/context
- expected destinations
- sensitivity thresholds
- allowed integrations
- retention policy
- deployment constraints
- lifecycle status and creation provenance

Versions are immutable. Updates create the next monotonically increasing version.

## Persistence and lifecycle

Profiles are persisted through the `environment_profiles` schema. PostgreSQL deployments enforce tenant isolation with RLS. `environment_profile_audit` records create, activation and rollback operations with profile digest and actor.

Lifecycle is `draft → active → retired`. Only one version may be active for a profile identity. An explicit activation is required when replacing an active version; conflicting active writes are rejected. Rollback selects an existing validated version and is audited.

## Observation assessment

`ObservationContext` represents measured telemetry. `AuthorizationAssessment` compares that observation with the active profile and returns deviations such as `protocol`, `port`, `destination`, `entropy` or `periodicity`.

The assessment contains no maliciousness verdict. A deviation means **evidence is required**, not that the observation is malicious.

## Security requirements

- Tenant identity is server-side context; callers cannot write for another tenant.
- Database RLS prevents cross-tenant persistence access.
- Profile versions cannot be overwritten or skipped.
- Structural bounds, schema version and duplicate values are validated.
- Active-profile conflicts fail closed.
- Rollback targets an existing version only.
- Deterministic SHA-256 digests provide integrity references.
- Raw observations are never suppressed because of profile mismatch.

## Staleness and operational accuracy

Structural validation does not prove that a profile accurately represents a real environment. Consumers must apply deployment-specific freshness/validity rules and must not allow stale configuration to suppress telemetry or independently supported detections.

## Evidence boundary

Repository validation establishes deterministic profile behavior, tenant isolation, lifecycle controls and hostile-condition handling. It does not establish operational accuracy of tenant-authored profiles.

Phase 5 does not implement EMCON, military classification, clearance levels, or policy-as-verdict logic.
