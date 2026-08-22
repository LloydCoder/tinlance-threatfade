# ThreatFade OWASP ASVS 5.0 Verification Matrix

**Standard:** OWASP Application Security Verification Standard 5.0.0  
**Target:** Level 2 baseline; selected Level 3 controls for high-impact boundaries  
**Status:** Group 1 architecture baseline; requirement verification continues in later enterprise-hardening groups

OWASP ASVS 5.0.0 is the current stable ASVS release and is intended to provide measurable requirements for application security verification. OWASP describes Level 2 as the standard target for applications handling sensitive data, with Level 3 reserved for the highest-assurance applications. urlOWASP ASVS 5.0.0https://owasp.org/www-project-application-security-verification-standard/

The authoritative machine-readable source is the OWASP ASVS 5.0.0 release JSON. urlOWASP ASVS 5.0.0 JSONhttps://github.com/OWASP/ASVS/blob/master/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json

## Status vocabulary

- **Implemented:** repository evidence exists and the control is materially implemented; later builds may strengthen it.
- **Partial:** a meaningful control exists, but the ASVS outcome is not yet fully verified.
- **Planned:** identified as a required future implementation.
- **External:** depends on deployment/organizational controls and cannot be proven by repository code alone.
- **N/A:** genuinely outside ThreatFade's feature scope; the rationale is documented.

A status of **Implemented** is not a certification claim. Verification requires code evidence, tests, deployment evidence, or independent assessment as appropriate.

## Chapter-level applicability matrix

| Chapter | Domain | ThreatFade applicability | Baseline status | Primary evidence / next action |
|---|---|---|---|---|
| V1 | Encoding and Sanitization | High | Partial | API/dashboard output handling; add security regression tests |
| V2 | Validation and Business Logic | High | Partial | Pydantic validation and bounds; formalize business invariants |
| V3 | Web Frontend Security | Medium | Partial | CSP/security headers; browser security regression coverage |
| V4 | API and Web Service | Critical | Partial | FastAPI boundary; expand API security tests |
| V5 | File Handling | Critical | Partial | PCAP upload validation; parser sandbox is required |
| V6 | Authentication | Critical | Partial | OIDC validation; strengthen token/authentication assurance |
| V7 | Session Management | Medium | Partial | Primarily delegated to external IdP/gateway; document session boundary |
| V8 | Authorization | Critical | Partial | RBAC/tenant checks; PostgreSQL RLS and comprehensive authorization tests required |
| V9 | Self-contained Tokens | Critical | Partial | JWT validation exists; claim/algorithm/lifecycle tests required |
| V10 | OAuth and OIDC | Critical | Partial | OIDC validator exists; harden discovery/JWKS and deployment configuration |
| V11 | Cryptography | High | Partial | TLS/signing delegated to edge/release; crypto inventory required |
| V12 | Secure Communication | Critical | External + partial | TLS is deployment boundary; document and test deployment requirements |
| V13 | Configuration | Critical | Partial | env/config baseline exists; secrets/configuration hardening required |
| V14 | Data Protection | Critical | Partial | tenant-scoped storage; encryption/retention/residency need operational evidence |
| V15 | Secure Coding and Architecture | Critical | Partial | CI/SCA/SBOM/provenance strong; action pinning and secure-design tests remain |
| V16 | Security Logging and Error Handling | Critical | Partial | structured audit exists; tamper evidence/durable retention required |
| V17 | WebRTC | N/A currently | N/A | No WebRTC feature in current ThreatFade scope; re-open if added |

## High-priority requirement verification baseline

The following requirements are the architecture/security baseline for ThreatFade. Requirement text is intentionally not reproduced; use the authoritative OWASP source for the normative wording.

| ASVS ID | Level | ThreatFade relevance | Current status | Repository evidence / required follow-up |
|---|---:|---|---|---|
| V1.1.1 | 2 | Canonical input processing | Partial | Document parsing/normalization rules and regression tests |
| V1.1.2 | 2 | Safe output encoding | Partial | Dashboard/API output review and browser tests |
| V1.2.4 | 1 | Database injection | Implemented/verify | SQLAlchemy ORM; add integration security tests |
| V1.2.5 | 1 | OS command injection | Implemented/verify | No direct shell boundary in primary API; add static/security regression check |
| V1.3.2 | 1 | Dynamic code execution | Implemented/verify | No intended eval path; enforce in secure coding checks |
| V1.3.6 | 2 | SSRF | Partial | Integration architecture requires explicit egress allowlists |
| V1.5.2 | 2 | Unsafe deserialization | Partial | JSON/YAML boundaries require parser review and tests |
| V2.1.1 | 1 | Validation documentation | Partial | Formal validation rules are being centralized in security architecture |
| V2.1.3 | 2 | Business/resource limits | Partial | API bounds exist; worker/global quotas remain |
| V4.1.1 | 1 | Correct HTTP response content types | Implemented/verify | FastAPI response handling; add API regression assertions |
| V4.1.3 | 2 | Trusted intermediary headers | Partial | Request-ID/proxy deployment boundary requires documented trusted-proxy policy |
| V5.1.1 | 2 | Upload requirements | Partial | PCAP limits/validation documented; parser sandbox still required |
| V5.2.1 | 1 | File size/DoS bounds | Partial | bounded uploads; CPU/memory/time isolation is next |
| V5.2.2 | 2 | File type/content validation | Partial | extension/content validation exists; strengthen magic/content validation |
| V6.1.1 | 1 | Authentication attack defenses | Partial | rate limiting exists; external IdP provides primary credential controls |
| V8.1.1 | 1 | Access-control architecture | Partial | RBAC/tenant authorization exists; formal matrix/tests required |
| V8.2.1 | 1 | IDOR/access-control bypass | Partial | tenant checks exist; comprehensive object-level authorization tests required |
| V9.1.1 | 1 | JWT validation | Partial | issuer/audience/exp/iat/sub and signature validation exist; strengthen claim policy |
| V10.1.1 | 1 | OAuth/OIDC flow security | Partial | OIDC validator exists; deployment/auth-flow requirements need formalization |
| V10.2.1 | 2 | OIDC security configuration | Partial | issuer/audience/JWKS configuration exists; discovery and rotation hardening required |
| V11.1.1 | 1 | Cryptographic inventory | Planned | create crypto inventory and approved-algorithm policy |
| V12.1.1 | 1 | TLS baseline | External | TLS terminates at deployment edge; test production configuration |
| V13.1.1 | 1 | Secure configuration | Partial | production fail-closed settings and env configuration exist |
| V13.2.1 | 2 | Secret management | Partial | secret-manager requirement documented; add automated secret/config checks |
| V14.1.1 | 1 | Data classification | Implemented baseline | C0–C3 classification established in security architecture |
| V14.2.1 | 2 | Sensitive-data protection | Partial | tenant controls exist; encryption/retention/residency evidence required |
| V15.1.1 | 1 | Dependency vulnerability response | Implemented baseline | Dependabot/pip-audit/security workflow |
| V15.1.2 | 2 | SBOM | Implemented baseline | release workflow generates SBOM |
| V15.2.1 | 2 | Secure dependency sources | Partial | dependency policy exists; pinning/verification to be strengthened |
| V15.3.1 | 2 | Secure architecture | Implemented baseline | security architecture + threat model + ADR process |
| V16.1.1 | 1 | Security logging documentation | Partial | audit architecture documented; event catalogue to be expanded |
| V16.3.1 | 2 | Security event coverage | Partial | auth/authorization/detection events exist; admin/config events need expansion |
| V16.4.1 | 2 | Log protection | Planned | tamper-evident durable audit ledger |
| V16.5.1 | 1 | Safe error handling | Partial | generic HTTP errors exist; expand leak regression tests |

## NIST CSF 2.0 alignment

NIST CSF 2.0 is an outcome-based framework organized around **Govern, Identify, Protect, Detect, Respond, Recover**. citeturn0search1turn0search7

| CSF Function | ThreatFade architecture contribution |
|---|---|
| Govern | security architecture, threat model, control matrix, assurance boundary |
| Identify | asset inventory, data classification, trust boundaries, risk register |
| Protect | auth/RBAC, input bounds, secrets, container hardening, supply-chain controls |
| Detect | fade detection engine, detection packs, evidence, ATT&CK mapping |
| Respond | cases, alerting, SIEM/FusionOps interoperability |
| Recover | backups/restore targets, release rollback, operational recovery requirements |

## Verification rules

1. A control cannot be marked **Implemented** solely because documentation claims it exists.
2. Security-critical requirements must have executable tests or independently verifiable deployment evidence whenever technically feasible.
3. Deployment-only controls must be explicitly marked **External** and have an operator verification procedure.
4. Any new external endpoint, identity flow, parser, integration, persistence boundary, or release mechanism must update this matrix.
5. Later enterprise groups may promote a control from Partial to Implemented only when evidence exists.

## Target state

ThreatFade's target is **ASVS 5.0 Level 2 across all applicable chapters**, with selected Level 3 controls for:

- multi-tenant authorization and isolation;
- hostile file/PCAP processing;
- evidence/audit integrity;
- cryptographic key and artifact protection;
- secure supply chain and release provenance;
- security logging and monitoring;
- high-impact administrative actions.

This matrix is a living engineering artifact and is not a claim of ASVS certification.
