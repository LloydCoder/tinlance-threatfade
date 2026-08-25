# ThreatFade Enterprise Integrations

## Status

Phase 6 / Group 17 introduces a normalized integration model and one delivery engine for enterprise destinations. The framework is implemented and repository-tested. It is not a claim of live production certification or field validation against every customer deployment.

## Architecture

```text
Detection / Evidence
        |
        v
IntegrationEvent (canonical)
        |
        +--> normalized idempotency key
        |
        v
IntegrationTransport
  |  auth / TLS / timeout
  |  retry / backoff / rate-aware handling
  |  audit / delivery status
  |  dead-letter sink
  v
Destination adapter
  |-- Elastic (ECS-shaped JSON)
  |-- Microsoft Sentinel (Logs Ingestion-shaped records)
  |-- IBM QRadar (CEF payload)
  |-- Graylog (GELF-shaped JSON)
  |-- Wazuh (alert-shaped JSON)
  |-- MISP (event/attribute payload)
  |-- OpenCTI (GraphQL request envelope)
  |-- TheHive (case/task payload)
  `-- SOAR (vendor-neutral webhook envelope)
```

The adapter layer is deliberately thin. Retry, authentication, TLS, idempotency, delivery auditing and dead-letter behavior are not duplicated per destination.

## Security contract

- Tenant identity is carried in the canonical event and destination payload; callers must obtain it from the authenticated engine context rather than a browser-controlled header.
- Credentials are supplied through a `CredentialProvider`; the transport does not persist secrets.
- Supported credential schemes are bearer, API key, basic authentication, HMAC-SHA256 request signing and client certificates.
- HTTPS verification is enabled by default and cannot be disabled for an HTTPS endpoint through this configuration.
- Redirects are disabled so a credential-bearing request cannot silently follow an attacker-controlled redirect.
- Timeouts are bounded to 120 seconds.
- Retry attempts are finite and use exponential backoff with support for `Retry-After`.
- Idempotency uses a tenant + event identifier digest and an `Idempotency-Key` header.
- Duplicate destination acknowledgement (`409`) is treated as successful duplicate delivery.
- Non-retryable and exhausted failures enter a dead-letter sink and produce an audit record.
- Audit records contain delivery metadata, never credential material.

## Credential rotation

Production deployments should implement `CredentialProvider` against the deployment secret manager. The provider is queried when a delivery starts, so rotating the current secret does not require rebuilding the integration transport. Revocation is implemented operationally by removing/invalidating the credential in that provider and destination.

`StaticCredentialProvider` exists for tests and local development only.

## Destination notes

### Elastic

Payloads follow an ECS-oriented structure and retain ThreatFade-specific evidence under a namespaced `threatfade` object.

### Microsoft Sentinel

The adapter emits records suitable for the Azure Monitor Logs Ingestion path. Deployments must configure the current Data Collection Endpoint/Data Collection Rule and the appropriate Azure authentication boundary. ThreatFade does not depend on the deprecated HTTP Data Collector API.

### IBM QRadar

The adapter emits CEF, allowing QRadar DSM/syslog ingestion. A customer deployment chooses the transport/log source appropriate to its QRadar version; the normalized ThreatFade transport remains independent of that receiver configuration.

### Graylog

The payload follows GELF 1.1 fields and is intended for a configured Graylog HTTP input or equivalent GELF receiver.

### Wazuh

The adapter emits an alert-shaped JSON envelope. Production deployments must connect it through a supported Wazuh ingestion/integration boundary rather than granting ThreatFade direct privileged access to the manager host.

### MISP

The adapter creates an event-oriented payload with ThreatFade ATT&CK tags and a serialized evidence attribute. Distribution remains local (`0`) by default.

### OpenCTI

The adapter produces a GraphQL request envelope. The exact GraphQL schema/mutation must be validated against the target OpenCTI release; ThreatFade does not claim a custom `ThreatFadeAlert` schema exists in an unmodified OpenCTI deployment.

### TheHive

The adapter produces a case/task-compatible payload with deterministic `sourceRef` and ThreatFade custom fields. Exact route/version mapping is deployment-specific.

### SOAR

The vendor-neutral adapter provides a stable webhook envelope so Splunk SOAR, Palo Alto Cortex XSOAR, IBM SOAR or another orchestration platform can be connected without changing the ThreatFade event model.

## Validation

The Phase 6 test suite covers:

- all nine adapters registered through one normalized registry;
- deterministic idempotency;
- duplicate suppression;
- retry and backoff;
- `Retry-After` handling;
- dead-letter behavior;
- network failure handling;
- tenant propagation;
- TLS verification requirements;
- endpoint validation;
- bearer/HMAC credential handling;
- secret non-disclosure in audit output.

Repository validation is evidence of implementation correctness. It is not evidence of production connectivity to every third-party platform.

## FusionOps

FusionOps remains an external integration boundary. The enterprise integration layer does not replace, fork or weaken the existing FusionOps contract. A FusionOps destination can use the same normalized event and delivery controls, while its existing API/event schema remains authoritative.
