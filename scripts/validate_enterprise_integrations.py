"""Static architecture gate for Group 17 enterprise integrations."""
from core.integrations import ADAPTERS, Credential, IntegrationConfig, StaticCredentialProvider

EXPECTED = {"elastic", "sentinel", "qradar", "graylog", "wazuh", "misp", "opencti", "thehive", "soar"}


def main() -> None:
    assert set(ADAPTERS) == EXPECTED
    provider = StaticCredentialProvider(Credential("bearer", "validation-only"))
    for name in sorted(EXPECTED):
        cfg = IntegrationConfig(name=name, endpoint="https://example.invalid/ingest", credential_provider=provider)
        assert cfg.verify_tls is True
        assert cfg.timeout_seconds <= 120
        assert cfg.retry_policy.max_attempts <= 10
    print("enterprise integrations: OK")


if __name__ == "__main__":
    main()
