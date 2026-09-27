"""Defensive egress validation for third-party integration endpoints."""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


def validate_integration_endpoint(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" and os.getenv("THREATFADE_ENV", "development").lower() == "production":
        raise ValueError("production integrations require HTTPS")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("integration endpoint must be an explicit HTTP(S) URL")
    host = parsed.hostname.rstrip(".").lower()
    allowed_hosts = {
        item.strip().lower().rstrip(".")
        for item in os.getenv("THREATFADE_INTEGRATION_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }
    if allowed_hosts and host not in allowed_hosts:
        raise ValueError("integration endpoint host is not allowlisted")
    environment = os.getenv("THREATFADE_ENV", "development").lower()
    if host in {"localhost", "localhost.localdomain"}:
        if environment == "production" and os.getenv("THREATFADE_INTEGRATION_ALLOW_LOOPBACK") != "true":
            raise ValueError("localhost integration endpoints are forbidden in production")
        return
    if host.endswith(".invalid"):
        return
    allowed_networks = []
    for raw in os.getenv("THREATFADE_INTEGRATION_ALLOWED_CIDRS", "").split(","):
        raw = raw.strip()
        if raw:
            allowed_networks.append(ipaddress.ip_network(raw, strict=False))
    try:
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        }
    except OSError as exc:
        raise ValueError("integration endpoint DNS resolution failed") from exc
    for raw_address in addresses:
        address = ipaddress.ip_address(raw_address)
        if any(address in network for network in allowed_networks):
            continue
        if environment != "production":
            continue
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ValueError("integration endpoint resolves to a non-public address")
