"""Sensor fleet lifecycle operations over the existing SensorRegistry contract."""
from __future__ import annotations

import secrets
import time
from typing import Any

from core.data_plane import SensorRegistry


class SensorFleet:
    def __init__(self, registry: SensorRegistry):
        self.registry = registry

    def enroll(self, sensor_id: str, tenant_id: str, version: str, fingerprint: str) -> dict[str, Any]:
        record = self.registry.register(sensor_id, tenant_id, version=version, fingerprint=fingerprint)
        return {**record, "enrollment_token": secrets.token_urlsafe(32)}

    def activate(self, sensor_id: str) -> dict[str, Any]:
        return self.registry.activate(sensor_id)

    def drain(self, sensor_id: str) -> dict[str, Any]:
        return self.registry.transition(sensor_id, "draining")

    def revoke(self, sensor_id: str) -> dict[str, Any]:
        return self.registry.transition(sensor_id, "revoked")

    def health(self, sensor_id: str) -> dict[str, Any]:
        record = self.registry.get(sensor_id)
        if record is None:
            raise KeyError(sensor_id)
        return {"sensor_id": sensor_id, "state": record["state"], "tenant_id": record["tenant_id"],
                "version": record["version"], "updated_at": record.get("updated_at", record.get("registered_at"))}
