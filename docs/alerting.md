# ThreatFade Enterprise Alerting

ThreatFade supports tenant-scoped, severity-aware notification routing through a provider-neutral dispatcher.

## Providers

| Provider | Use | Configuration |
|---|---|---|
| Telegram | Existing lightweight notification | Existing Telegram adapter |
| Slack | SOC/chat operations | `THREATFADE_SLACK_WEBHOOK_URL` |
| Microsoft Teams | Microsoft 365 security operations | `THREATFADE_TEAMS_WEBHOOK_URL` |
| Generic webhook | SIEM/SOAR/custom automation | `THREATFADE_WEBHOOK_URL`, optional HMAC secret |
| Email | SMTP notification | `THREATFADE_SMTP_*` |
| PagerDuty | High/critical on-call | `THREATFADE_PAGERDUTY_ROUTING_KEY` |
| Opsgenie | High/critical on-call | `THREATFADE_OPSGENIE_API_KEY`, optional EU region |

## Severity routing

Policies are intentionally independent from provider credentials. A deployment can define a tenant's routing policy as:

```json
{
  "critical": ["slack", "teams", "pagerduty"],
  "high": ["slack", "teams", "webhook"],
  "medium": ["slack", "webhook"],
  "low": ["webhook"],
  "default": ["slack"]
}
```

Credentials belong in the deployment secret manager, never in tenant event payloads or source control.

## Webhook security

ThreatFade treats outbound notification URLs as an SSRF boundary:

- HTTPS only.
- Private, loopback, link-local and reserved literal IP destinations are rejected.
- Production deployments require `THREATFADE_WEBHOOK_ALLOWLIST`.
- Generic webhook payloads can be signed with `X-ThreatFade-Signature: sha256=<HMAC-SHA256>`.
- Provider credentials are read from environment/secret injection only.
- Notification payloads contain detection evidence but not provider credentials.

For production, the network egress layer should additionally enforce DNS/IP policy, proxy controls and destination allowlists.

## Microsoft Teams

Use the current **Workflows webhook trigger / Adaptive Card** approach rather than provisioning legacy Microsoft 365 Connectors. Microsoft documents the connector retirement path and recommends the Workflows webhook trigger for new webhook-driven Teams messages.

## On-call

PagerDuty is used for critical/high urgency escalation. Opsgenie is supported for customers that still operate an Opsgenie integration; its API integration accepts HTTPS/JSON and supports alert lifecycle automation.

## Reliability requirements

Enterprise deployments should treat notification delivery as asynchronous work rather than making detection latency depend on a third-party provider. Recommended production implementation:

1. Persist the detection and audit event first.
2. Enqueue notification jobs.
3. Retry transient 429/5xx failures with exponential backoff and jitter.
4. Use idempotency/deduplication keys.
5. Apply provider-specific rate limits.
6. Dead-letter permanently failed deliveries.
7. Expose delivery latency, success rate and backlog metrics.
8. Keep a provider outage from blocking detection.

The current provider adapters are intentionally synchronous building blocks; a production queue/worker should wrap them when external delivery volume requires it.

## References

- Slack Incoming Webhooks: https://api.slack.com/messaging/webhooks
- Microsoft Teams Workflows webhooks: https://learn.microsoft.com/en-us/microsoftteams/m365-custom-connectors
- PagerDuty Events API v2: https://developer.pagerduty.com/docs/events-api-v2/overview/
- Opsgenie API integrations: https://support.atlassian.com/opsgenie/docs/create-a-default-api-integration/
