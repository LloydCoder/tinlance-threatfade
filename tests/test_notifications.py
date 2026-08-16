import os

import pytest

from alerts.notification_dispatcher import NotificationError, dispatch


def test_production_requires_webhook_allowlist(monkeypatch):
    monkeypatch.setenv("THREATFADE_ENV", "production")
    monkeypatch.delenv("THREATFADE_WEBHOOK_ALLOWLIST", raising=False)
    from alerts.notification_dispatcher import _safe_url
    with pytest.raises(NotificationError):
        _safe_url("https://example.com/hook")


def test_private_destination_is_rejected(monkeypatch):
    monkeypatch.setenv("THREATFADE_ENV", "development")
    monkeypatch.setenv("THREATFADE_WEBHOOK_ALLOWLIST", "127.0.0.1")
    from alerts.notification_dispatcher import _safe_url
    with pytest.raises(NotificationError):
        _safe_url("https://127.0.0.1/hook")


def test_policy_selects_severity_providers(monkeypatch):
    calls = []
    monkeypatch.setenv("THREATFADE_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setenv("THREATFADE_WEBHOOK_ALLOWLIST", "hooks.slack.com")
    monkeypatch.setattr("alerts.notification_dispatcher.send_slack", lambda event, url: calls.append(("slack", url)) or type("R", (), {"provider": "slack", "delivered": True})())
    result = dispatch({"severity": "critical", "title": "test"}, {"critical": ["slack"]})
    assert result[0].provider == "slack"
    assert calls == [("slack", "https://hooks.slack.com/services/T/B/X")]


def test_unknown_provider_fails_closed():
    with pytest.raises(NotificationError, match="Unsupported"):
        dispatch({"severity": "high"}, {"high": ["unknown"]})
