# ThreatFade Phase 3 — Production SOC / Analyst Platform

## Scope

Builds 98–107 add an investigation workflow above the existing detection, evidence, audit, identity and multi-domain correlation layers. The dashboard is evolved rather than replaced.

## Workflow

```text
Detection
  → triage
  → investigation
  → evidence review
  → entity/session correlation
  → disposition
  → case
  → SIEM / FusionOps handoff
```

## Security boundary

The engine remains the system of record for detection, evidence, tenant identity and authorization. The web application uses a server-side proxy for analyst operations. Engine credentials are server-only. The browser cannot choose a tenant or elevate privileges. Engine endpoints continue to enforce OIDC/API authentication, role authorization, tenant binding, rate limits and object-level lookups.

The web proxy rejects cross-origin mutating requests when an `Origin` header is supplied, bounds request/response bodies, disables redirects and only forwards an explicit analyst route allowlist.

## Core workflow objects

- **Detection** — existing immutable detection record.
- **Evidence** — existing hashed evidence/provenance record.
- **Session** — correlation-scoped investigation session record.
- **Asset / entity** — correlation-scoped investigation entity record; platform-specific asset identity remains a future sensor concern.
- **Sensor** — existing Group 11 identity/data-plane boundary.
- **Case** — existing tenant-scoped case record, now linkable to detections.
- **Disposition** — durable analyst decision with reason, note, actor and timestamp.
- **Analyst** — authenticated enterprise principal.
- **AuditEvent** — existing append-only audit chain plus workflow events.

## State model

Detection workflow states are bounded to:

`new → triaging → investigating → contained → resolved → closed`

The workflow state is separate from the detection evidence and does not mutate evidence hashes.

Disposition reasons are bounded to:

`true_positive`, `false_positive`, `benign`, `duplicate`, `insufficient_evidence`, `needs_tuning`.

## Evidence and confidence

The UI explicitly distinguishes evidence from confidence/score. Evidence records are displayed with content hash, media type, size, collection timestamp and provenance metadata. A confidence score is an analytical assessment and is not treated as proof.

## Multi-tenancy

All workflow tables contain `tenant_id`. PostgreSQL migrations enable and force RLS policies using the transaction-local ThreatFade tenant context. Application queries also include explicit tenant predicates. Cross-tenant object IDs therefore return not-found rather than leaking existence.

## Validation boundary

Repository tests establish deterministic workflow behavior, tenant isolation and input validation. They do not establish customer-scale SOC usability, production identity-provider configuration, production FusionOps connectivity or independent security assurance.
