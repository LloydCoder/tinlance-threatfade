# Security Policy

ThreatFade is a security-sensitive detection and investigation platform. We welcome responsible reports that help protect users, operators and the integrity of detection evidence.

## Supported versions

Security fixes are developed against the latest maintained `main` branch and the latest published release, where one exists. The current repository development baseline may be newer than the latest published release. Users should upgrade to the latest supported release before reporting an issue already fixed upstream.

## Private vulnerability reporting

Report suspected vulnerabilities privately to **security@tinlance.com**.

Do not publish exploit details, proof-of-concept payloads, credentials, customer data, packet captures or other sensitive evidence in public GitHub issues or pull requests.

Include, where possible:

- Affected release, commit, component, route or deployment configuration.
- A concise description of security impact and affected trust boundary.
- Reproduction steps and a minimal proof of concept that does not expose real customer data.
- Preconditions, required privileges and remote exploitability.
- Relevant logs or artifacts with secrets and personal data removed.
- Suggested mitigation, if known.

Do not send live credentials, private keys or unredacted customer evidence. Coordinate with the maintainer before sending sensitive attachments.

## Acknowledgement and response targets

The project aims to:

| Activity | Target |
|---|---|
| Initial acknowledgement | Within 24 hours |
| Initial triage and severity assessment | Within 3 business days |
| Progress updates | At meaningful triage/remediation milestones |
| Coordinated disclosure | Agreed with the reporter after a fix or mitigation is available |

These are best-effort targets, not contractual SLAs or guaranteed resolution times. Complexity, severity, maintainer availability and third-party dependencies may affect remediation.

## Coordinated disclosure

The maintainer will work with the reporter to validate the issue, determine affected versions, assess severity, prepare a fix or mitigation and agree on an appropriate disclosure date. Please allow reasonable time for remediation before public disclosure.

The project will not ask a reporter to access, retain or disclose data beyond what is necessary to demonstrate the issue safely. Credit will be provided when the reporter consents.

## Scope

Reports are especially useful for:

- Authentication, OIDC/JWT validation, session lifecycle and account disablement.
- Authorization, role enforcement, tenant isolation and cross-tenant access.
- Detection, evidence, provenance, audit-log integrity and offline package verification.
- PCAP and hostile-input parsing, resource exhaustion and unsafe file handling.
- API abuse, rate limiting, request validation, SSRF, injection and integration delivery.
- Secrets handling, cryptographic key lifecycle, container hardening, CI/CD, dependencies and release provenance.

Do not test against systems, tenants, accounts or data you do not own or have explicit permission to assess. Avoid destructive testing and denial-of-service activity.

## Security assurance boundary

Automated tests, static analysis, dependency scanning, SBOMs, signatures and repository controls provide engineering evidence. They do not by themselves establish independent penetration-test coverage, certification, regulatory compliance or a guarantee that the platform is vulnerability-free. External assurance must be described separately and supported by its own evidence.

## Public issues

Use GitHub issues for non-sensitive bugs and feature requests only. If a public issue accidentally contains sensitive security details, remove the exploit material where possible and continue through the private reporting channel.

---

ThreatFade is developed by Tinlance Limited.
