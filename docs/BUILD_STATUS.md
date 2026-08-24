# ThreatFade Enterprise Build Status

**Program:** Enterprise Hardening  
**Current release baseline:** v0.7.0  
**Current group:** Group 14 — Analyst Investigation & Operational Workflow  
**Current build:** Builds 98–107  
**Status:** GROUP 14 IMPLEMENTED — repository validation pending

## Completed groups

- Group 1 — Security Architecture & Threat Model: ✅ Builds 15–17
- Group 2 — Detection Science & Validation: ✅ Builds 18–23
- Group 3 — Detection Pack Platform: ✅ Builds 24–27
- Group 4 — Data Integrity, Evidence & Audit: ✅ Builds 28–33
- Group 5 — Reliability, Observability & Resilience: ✅ Builds 34–37
- Group 6 — Disaster Recovery, Backup & Operational Continuity: ✅ Builds 38–41
- Group 7 — Secure Deployment, Supply Chain & Production Operations: ✅ Builds 42–46
- Group 8 — Identity, Access Control & Enterprise Multi-Tenancy: ✅ Builds 47–52
- Group 9 — ThreatFade Detection Science 2.0: ✅ Builds 53–62
- Group 10 — Real-World Evidence & Validation Framework: ✅ Builds 63–70
- Group 11 — Detection Data Plane & Sensor Architecture: ✅ Builds 71–78
- Group 12 — Multi-Domain Fade Correlation: ✅ Builds 83–90
- Group 13 — Resilient Offline Evidence: ✅ Builds 91–97
- Group 14 — Analyst Investigation & Operational Workflow: 🟡 Builds 98–107 — validation pending

## Group 14 — Analyst Investigation & Operational Workflow

| Build | Deliverable | Status |
|---|---|---|
| 98 | Detection inbox | 🟢 |
| 99 | Fade investigation workspace | 🟢 |
| 100 | Evidence timeline | 🟢 |
| 101 | Entity correlation | 🟢 |
| 102 | Network/session explorer | 🟢 |
| 103 | Case management integration | 🟢 |
| 104 | Analyst disposition | 🟢 |
| 105 | Analyst feedback/workflow history | 🟢 |
| 106 | Secure engine/web boundary for analyst operations | 🟢 |
| 107 | End-to-end detection-to-disposition workflow | 🟢 implementation; validation pending |

## Group 14 implementation evidence

- `core/analyst.py`
- `core/analyst_routes.py`
- `enterprise_app.py`
- `alembic/versions/20260824_0004_analyst_workflow.py`
- `tests/test_analyst_workflow.py`
- `app/soc/page.tsx`
- `app/soc/[id]/page.tsx`
- `app/soc/[id]/timeline/page.tsx`
- `app/api/analyst/[...path]/route.ts`

## Acceptance boundary

- Detection inbox is tenant-scoped and bounded.
- Workflow state is separate from immutable detection/evidence records.
- Server-side engine authorization remains authoritative; the browser never supplies tenant identity or privileged engine credentials.
- Mutating web proxy requests require a same-origin request when an Origin header is present.
- Evidence is displayed with provenance hashes and explicitly separated from confidence/score.
- Investigation supports triage, investigation, evidence review, timeline, case linking, disposition and feedback history.
- Object-level detection/case access is tenant constrained.
- Repository validation must cover tenant isolation, invalid workflow/disposition inputs, route security, lint/typecheck/build and end-to-end navigation before this group is marked green.

## Capability truth

| Capability | Repository status | Production-validation status |
|---|---|---|
| Detection inbox | Implemented | Repository validation pending |
| Investigation workspace | Implemented | Repository validation pending |
| Evidence timeline | Implemented | Repository validation pending |
| Entity/session explorer | Implemented as correlation-scoped investigation records | Production sensor/entity fleet validation remains external |
| Case management | Implemented | Repository validation pending |
| Analyst disposition | Implemented | Repository validation pending |
| Analyst feedback | Implemented through workflow/disposition audit history | Model-training impact is not claimed |
| Secure web/engine boundary | Implemented | Deployment identity-provider validation remains external |
| FusionOps handoff | Existing integration boundary preserved; no contract-breaking changes | External FusionOps end-to-end validation remains deployment work |

## Verification boundary

Group 14 provides an investigation workflow over existing ThreatFade detections and evidence. It does not convert confidence into truth, does not establish causal attribution, and does not claim that synthetic repository workflows equal customer-scale SOC validation. The browser is intentionally prevented from choosing a tenant or supplying privileged engine credentials.

## Next planned group

**Group 15 — Production Sensor / Edge Runtime.**

Focus: production-grade live sensor ingestion, secure enrollment, edge runtime, bounded local processing and platform-specific deployment validation.
