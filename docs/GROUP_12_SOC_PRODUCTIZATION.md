# Group 12 — SOC Productization

## Status

**GREEN for the engine-side Phase 12 implementation.**

The canonical analyst platform remains in the ThreatFade engine. The web repository consumes this contract; it does not create a parallel SOC persistence layer.

## Engine-backed analyst contract

Authenticated routes:

- `GET /enterprise/analyst/inbox`
- `GET /enterprise/analyst/detections/{id}`
- `GET /enterprise/analyst/detections/{id}/timeline`
- `GET /enterprise/analyst/detections/{id}/entities`
- `GET /enterprise/analyst/detections/{id}/sessions`
- `PATCH /enterprise/analyst/detections/{id}/workflow`
- `POST /enterprise/analyst/detections/{id}/disposition`
- `POST /enterprise/analyst/detections/{id}/cases`

## Capability boundary

The engine provides the authoritative detection, investigation, evidence, entity, session, case, workflow and disposition data used by the SOC web workspace.

Inbox queries support bounded pagination, workflow status/assignee filtering and deterministic sorting. Detection assessment preserves the distinction between engine score/confidence and presentation-only triage severity.

Investigation responses include provenance, structured detection evidence, linked evidence records, entities, sessions, analyst disposition history and linked cases.

Workflow, assignment, case-title and analyst-note inputs are bounded and validated. Mutations preserve canonical tenant scoping and audit events.

## Authorization

Every analyst operation is authenticated and tenant-scoped. Object access is never inferred from a resource identifier alone. Existing role/permission controls remain authoritative for analyst reads and mutations.

## Security boundary

The engine remains the source of truth for authorization and persistence. The web application must forward authenticated identity to these routes through its server-side boundary and must not accept browser-controlled tenant identifiers as authorization decisions.

## Validation evidence

Phase 12 engine PR checks completed successfully before merge, including analyst validation, general validation, data-plane checks, integrations, CodeQL, secret scanning, dependency audit and build scanning.

Independent customer-scale validation, independent penetration testing, purple-team validation and production identity-provider configuration are separate assurance activities and are not implied by this implementation record.
