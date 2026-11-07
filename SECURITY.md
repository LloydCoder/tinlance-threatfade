# Security Policy

ThreatFade is a security-sensitive detection and investigation platform. We welcome responsible reports that help protect users, operators, and the integrity of detection evidence.

## Supported release

Security fixes are developed against the latest maintained `main` branch and the latest published release, where one exists. Users should upgrade to the latest supported release before requesting assistance with an issue that is already fixed.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **security@tinlance.com**.

Do not publish exploit details, proof-of-concept payloads, credentials, customer data, packet captures, or other sensitive evidence in public GitHub issues or pull requests.

Include, where possible:

- Affected version, commit, component, route, or deployment configuration.
- A concise description of the security impact and relevant trust boundary.
- Reproduction steps and a minimal proof of concept that does not expose real customer data.
- Preconditions, required privileges, and whether the issue is remotely exploitable.
- Relevant logs or artifacts with secrets and personal data removed.
- A suggested mitigation, if known.

If a report contains sensitive material, coordinate with the maintainer before sending attachments. Do not send live credentials, private keys, or unredacted customer evidence.

## Response and coordinated disclosure

The project aims to acknowledge reports within 24 hours and provide progress updates as triage and remediation proceed. These are response targets, not contractual service levels or guaranteed resolution times.

We will work with the reporter to validate the issue, assess severity and affected versions, prepare a fix or mitigation, and coordinate an appropriate disclosure date. Please allow reasonable time for remediation before public disclosure. We will not ask a reporter to access, retain, or disclose data beyond what is necessary to demonstrate the issue safely.

## Scope and security boundaries

Reports are especially useful for issues involving:

- Authentication, OIDC/JWT validation, session lifecycle, or account disablement.
- Authorization, role enforcement, tenant isolation, or cross-tenant data access.
- Detection, evidence, provenance, audit-log integrity, or offline package verification.
- PCAP and other hostile-input parsing, resource exhaustion, or unsafe file handling.
- API abuse, rate limiting, request validation, SSRF, injection, or unsafe integration delivery.
- Secrets handling, cryptographic key lifecycle, container hardening, CI/CD, dependencies, and release provenance.

Do not test against systems, tenants, accounts, or data that you do not own or have explicit permission to assess. Avoid destructive testing and denial-of-service activity.

## Security assurance boundary

Automated tests, static analysis, dependency scanning, SBOMs, signatures, and repository controls provide engineering evidence; they do not by themselves establish independent penetration-test coverage, a certification, or a guarantee that the platform is vulnerability-free. Any external assurance must be described separately and supported by its own evidence.

## Public issues

Use GitHub issues for non-sensitive bugs and feature requests only. If an issue turns out to contain sensitive security details, remove the public exploit material and continue through the private reporting channel.

---

ThreatFade is developed by Tinlance Limited.
