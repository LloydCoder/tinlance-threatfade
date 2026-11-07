# ThreatFade configuration reference

This page describes settings verified in the current repository source, `api.py`, `docker-compose.yml` and `.env.example`. Optional integration variables may be documented in their respective guides. A blank value in `.env.example` is a placeholder and must not be treated as a valid secret.

## Application defaults

| Setting | Default | Notes |
|---|---|---|
| `THREATFADE_ENV` | `development` | Production mode enables stricter security behavior and expects a real identity boundary. |
| `THREATFADE_ALLOWED_ORIGINS` | `http://localhost:8080` | Comma-separated origins. Wildcard CORS is rejected in production. |
| `THREATFADE_MAX_BODY_BYTES` | `2097152` | API request body limit in bytes. |
| `THREATFADE_MAX_PCAP_BYTES` | `104857600` in `.env.example` | Maximum uploaded PCAP size. |
| `THREATFADE_MAX_PCAP_PACKETS` | `1000000` in `.env.example` | Maximum packet count. |
| `THREATFADE_PCAP_TIMEOUT_SECONDS` | `30` in `.env.example` | PCAP processing time bound. |
| `THREATFADE_PCAP_MAX_MEMORY_MB` | `512` in `.env.example` | PCAP processing memory bound. |
| `THREATFADE_RATE_LIMIT` | `120` in `.env.example` | Rate-limit request count. |
| `THREATFADE_RATE_WINDOW_SECONDS` | `60` in `.env.example` | Rate-limit window in seconds. |

## Identity provider

Production Compose requires:

| Variable | Requirement |
|---|---|
| `THREATFADE_OIDC_ISSUER` | Required |
| `THREATFADE_OIDC_AUDIENCE` | Required |
| `THREATFADE_OIDC_JWKS_URL` | Optional in Compose; configure according to the identity provider and application validation contract |
| `THREATFADE_OIDC_CLOCK_SKEW_SECONDS` | `30` in `.env.example` |

Use a trusted HTTPS issuer/JWKS endpoint, keep clocks synchronized, and validate issuer, audience, signature algorithm, key identity and token time claims. Do not disable production authentication to work around configuration errors.

## Database and Compose requirements

The production Compose file requires these values:

- `POSTGRES_PASSWORD`
- `THREATFADE_APP_DB_USER`
- `THREATFADE_APP_DB_PASSWORD`
- `THREATFADE_OIDC_ISSUER`
- `THREATFADE_OIDC_AUDIENCE`
- `THREATFADE_ALLOWED_ORIGINS`

It also accepts `POSTGRES_DB`, `POSTGRES_USER`, `THREATFADE_OIDC_JWKS_URL`, PCAP limits and rate-limit overrides. The Compose deployment expects an external Docker network named `threatfade_proxy`. Review `docker-compose.yml` before deployment; do not assume `docker compose up` is a complete standalone production installation.

Set `THREATFADE_DATABASE_URL` to the SQLAlchemy URL for the application database. The Compose file constructs this value from the application database credentials and PostgreSQL service.

## Detection configuration

The checked-in `config.yaml` currently defines:

| Key | Default |
|---|---:|
| `fade_detection.entropy_window` | `8` |
| `fade_detection.min_points` | `12` |
| `fade_detection.threshold` | `0.20` |
| `fade_detection.drop_weight` | `0.50` |
| `fade_detection.entropy_weight` | `0.30` |
| `fade_detection.zscore_weight` | `0.20` |
| `fade_detection.rule_threshold` | `2` |

Change detection thresholds only with an evaluation plan and representative data. Preserve a held-out evaluation set and document the configuration used to generate any reported metric.

## Secrets

- Keep populated local environment files out of Git.
- Inject production secrets through an approved secret manager or deployment secret mechanism.
- Never place API keys, OIDC client secrets, webhook tokens, database passwords or private signing keys in `config.yaml`, issue reports, screenshots or logs.
- Rotate any credential suspected of exposure; removing a value from the latest commit does not remove it from Git history.

See [SECURITY.md](../../SECURITY.md), [secure deployment](../SECURE_DEPLOYMENT.md) and [alerting](../alerting.md).
