"""Enterprise alert notification adapters.

The dispatcher deliberately keeps provider credentials out of source/config files.
Production secrets must be injected by the deployment secret manager. Provider
selection and severity routing are tenant-scoped policy data.

Supported providers:
- telegram (existing adapter can be called separately)
- slack (Incoming Webhook)
- teams (Workflows webhook / Adaptive Card payload)
- webhook (signed JSON webhook)
- email (SMTP)
- pagerduty (Events API v2)
- opsgenie (Alerts API)

All HTTP destinations are HTTPS-only in production and may be constrained with
THREATFADE_WEBHOOK_ALLOWLIST. This is an outbound SSRF boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import smtplib
import socket
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Dict, Iterable, Mapping, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class NotificationError(RuntimeError):
    """Raised when an outbound notification cannot be delivered."""


@dataclass(frozen=True)
class NotificationResult:
    provider: str
    delivered: bool
    status: int = 200
    detail: str = "ok"


def _production() -> bool:
    return os.getenv("THREATFADE_ENV", "development").lower() == "production"


def _allowlisted(host: str) -> bool:
    raw = os.getenv("THREATFADE_WEBHOOK_ALLOWLIST", "").strip()
    if not raw:
        return not _production()
    allowed = {x.strip().lower() for x in raw.split(",") if x.strip()}
    return host.lower() in allowed


def _safe_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise NotificationError("Notification endpoints must use HTTPS")
    host = parsed.hostname
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise NotificationError("Private/link-local notification destinations are forbidden")
    except ValueError:
        pass
    if not _allowlisted(host):
        raise NotificationError("Notification destination is not allowlisted")
    return url


def _post_json(url: str, payload: Mapping[str, Any], headers: Optional[Mapping[str, str]] = None, timeout: float = 10.0) -> int:
    url = _safe_url(url)
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    req = Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "ThreatFade-Notifier/1.0", **(dict(headers or {}))}, method="POST")
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            status = int(response.status)
            if status < 200 or status >= 300:
                raise NotificationError(f"notification provider returned HTTP {status}")
            return status
    except NotificationError:
        raise
    except Exception as exc:
        raise NotificationError(f"notification delivery failed: {exc}") from exc


def _text(event: Mapping[str, Any]) -> str:
    return (
        f"ThreatFade {str(event.get('severity', 'info')).upper()}: "
        f"{event.get('title', 'Detection')} — {event.get('summary', 'Detection requires review')} "
        f"[confidence={event.get('confidence', 'unknown')}]"
    )


def send_slack(event: Mapping[str, Any], webhook_url: str) -> NotificationResult:
    status = _post_json(webhook_url, {"text": _text(event)})
    return NotificationResult("slack", True, status)


def send_teams(event: Mapping[str, Any], webhook_url: str) -> NotificationResult:
    # Microsoft Teams Workflows webhook trigger accepts Adaptive Cards. This avoids
    # the legacy Microsoft 365 Connector path that is being retired.
    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": "ThreatFade Detection", "weight": "Bolder", "size": "Medium"},
                    {"type": "TextBlock", "text": _text(event), "wrap": True},
                ],
            },
        }],
    }
    status = _post_json(webhook_url, card)
    return NotificationResult("teams", True, status)


def send_webhook(event: Mapping[str, Any], webhook_url: str, secret: Optional[str] = None) -> NotificationResult:
    payload = dict(event)
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest() if secret else None
    headers = {"X-ThreatFade-Event": "detection", "X-ThreatFade-Signature": f"sha256={signature}" if signature else ""}
    status = _post_json(webhook_url, payload, headers=headers)
    return NotificationResult("webhook", True, status)


def send_email(event: Mapping[str, Any], *, host: str, port: int, username: str, password: str, sender: str, recipients: Iterable[str], starttls: bool = True) -> NotificationResult:
    msg = EmailMessage()
    msg["Subject"] = f"[ThreatFade] {str(event.get('severity', 'info')).upper()} — {event.get('title', 'Detection')}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(_text(event) + "\n\n" + json.dumps(dict(event), indent=2, ensure_ascii=False))
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if starttls:
            smtp.starttls(context=context)
        if username:
            smtp.login(username, password)
        smtp.send_message(msg)
    return NotificationResult("email", True)


def send_pagerduty(event: Mapping[str, Any], routing_key: str) -> NotificationResult:
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": _text(event),
            "source": str(event.get("source", "ThreatFade")),
            "severity": str(event.get("severity", "info")).lower(),
            "custom_details": dict(event),
        },
    }
    status = _post_json("https://events.pagerduty.com/v2/enqueue", payload)
    return NotificationResult("pagerduty", True, status)


def send_opsgenie(event: Mapping[str, Any], api_key: str, region: str = "us") -> NotificationResult:
    host = "api.eu.opsgenie.com" if region.lower() == "eu" else "api.opsgenie.com"
    payload = {
        "message": _text(event)[:130],
        "alias": str(event.get("dedup_key") or event.get("detection_id") or hashlib.sha256(_text(event).encode()).hexdigest()[:24]),
        "description": json.dumps(dict(event), ensure_ascii=False),
        "priority": "P1" if str(event.get("severity", "info")).lower() == "critical" else "P2",
        "source": "ThreatFade",
        "tags": ["threatfade", str(event.get("severity", "info")).lower()],
    }
    status = _post_json(f"https://{host}/v2/alerts", payload, headers={"Authorization": api_key})
    return NotificationResult("opsgenie", True, status)


def dispatch(event: Mapping[str, Any], policy: Mapping[str, Any]) -> list[NotificationResult]:
    """Dispatch an event using a tenant-scoped, severity-aware policy.

    Policy shape::

        {"critical": ["slack", "pagerduty"], "high": ["slack", "teams"], "default": ["webhook"]}

    Credentials/URLs are supplied by environment variables, never by event data.
    """
    severity = str(event.get("severity", "info")).lower()
    providers = policy.get(severity, policy.get("default", []))
    results: list[NotificationResult] = []
    for provider in providers:
        name = str(provider).lower()
        if name == "slack": results.append(send_slack(event, os.environ["THREATFADE_SLACK_WEBHOOK_URL"]))
        elif name == "teams": results.append(send_teams(event, os.environ["THREATFADE_TEAMS_WEBHOOK_URL"]))
        elif name == "webhook": results.append(send_webhook(event, os.environ["THREATFADE_WEBHOOK_URL"], os.getenv("THREATFADE_WEBHOOK_SECRET")))
        elif name == "pagerduty": results.append(send_pagerduty(event, os.environ["THREATFADE_PAGERDUTY_ROUTING_KEY"]))
        elif name == "opsgenie": results.append(send_opsgenie(event, os.environ["THREATFADE_OPSGENIE_API_KEY"], os.getenv("THREATFADE_OPSGENIE_REGION", "us")))
        elif name == "email":
            results.append(send_email(event, host=os.environ["THREATFADE_SMTP_HOST"], port=int(os.getenv("THREATFADE_SMTP_PORT", "587")), username=os.getenv("THREATFADE_SMTP_USERNAME", ""), password=os.getenv("THREATFADE_SMTP_PASSWORD", ""), sender=os.environ["THREATFADE_SMTP_FROM"], recipients=[x.strip() for x in os.environ["THREATFADE_SMTP_TO"].split(",") if x.strip()]))
        elif name == "telegram":
            # Existing Telegram adapter remains available to the application.
            continue
        else:
            raise NotificationError(f"Unsupported notification provider: {provider}")
    return results
