# ADR-0001: Enterprise security and deployment boundaries

## Status
Accepted

## Context

ThreatFade needs to serve both a community/research workflow and production SOC deployments without pretending that application code alone provides enterprise identity, HA, tenancy, or compliance.

## Decision

Keep the detection engine portable and stateless where possible. Put enterprise identity, tenant policy, durable storage, queueing, HA, and regional controls behind explicit deployment boundaries. The application provides secure primitives and reference contracts; production operators select their identity provider, database, object store, queue, and orchestration platform.

## Consequences

- Community deployments remain easy to run.
- Enterprise deployments can use managed infrastructure and SSO without forking detector logic.
- Claims about compliance and availability remain evidence-based.
- Integrations must be tested against the deployment profile in which they are enabled.
