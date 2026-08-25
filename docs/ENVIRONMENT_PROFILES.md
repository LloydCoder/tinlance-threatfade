# ThreatFade Environment Profiles

## Purpose

Environment profiles provide tenant-scoped, versioned configuration for expected operating conditions and adaptive detection baselines. They are configuration and context, not verdicts.

ThreatFade deliberately separates:

- **Observed behavior:** telemetry actually measured by sensors and the detection data plane.
- **Authorized behavior:** behavior an operator has declared expected or permitted through a versioned profile.

A mismatch between observed and authorized behavior is a contextual signal only. It is never sufficient by itself to label behavior malicious. A detection requires independent evidence from the detection engine and its evidence model.

## Profile schema v1

A profile contains:

- `profile_id`, `tenant_id`, `version`, `schema_version`
- expected protocols
- expected ports
- baseline entropy by protocol/context
- baseline periodicity by protocol/context
- expected destinations
- sensitivity thresholds
- allowed integrations
- retention policy
- deployment constraints
- lifecycle status and creation provenance

Profiles are immutable by version. Updates create the next monotonically increasing version.

## Lifecycle

`draft → active → retired` is the normal lifecycle. A previously validated version may be selected again through an audited rollback operation. Only one version of a profile identity can be active for a tenant at a time.

Every create, activation and rollback operation records tenant, profile identity, version and digest in the audit trail.

## Security requirements

- Tenant identity is server-side context; callers cannot write a profile for another tenant.
- Cross-tenant reads and lifecycle changes fail closed.
- Schema and field bounds are validated before persistence.
- Profile versions cannot be overwritten or skipped.
- Malformed profiles are rejected.
- Rollback targets an existing validated version only.
- Profile digests provide deterministic integrity references.
- No profile field is interpreted as a maliciousness verdict.

## Staleness and deployment

Consumers should treat profiles as stale when their configured operational validity window expires or when the tenant retires/revokes the profile. Stale-profile policy belongs to the deployment consumer and must fail closed for configuration writes; it must not suppress raw observations.

## Evidence boundary

The environment-profile implementation is **repository validated** when the Phase 5 CI gates pass. It does not establish that a profile accurately represents a real environment. Profile accuracy remains an operational validation responsibility.

Environment profiles do not implement EMCON, military classification, clearance levels, or policy-as-verdict logic.
