"""Offline ML governance primitives for ThreatFade.

These helpers make model provenance and drift checks explicit without making
model inference a mandatory runtime dependency.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Sequence

import numpy as np


FEATURE_SCHEMA_VERSION = "threatfade-signal-features-v2"
MODEL_MANIFEST_VERSION = 1


@dataclass(frozen=True)
class ModelManifest:
    model_id: str
    model_version: str
    feature_schema: str
    algorithm: str
    training_support: int
    random_state: int
    artifact_sha256: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "manifest_version": MODEL_MANIFEST_VERSION,
            **self.__dict__,
        }


def artifact_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_digest(manifest: ModelManifest) -> str:
    canonical = json.dumps(manifest.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def population_stability_index(expected: Sequence[float], actual: Sequence[float], bins: int = 10) -> float:
    """Calculate PSI for bounded feature distributions.

    PSI is a drift indicator, not a detector-quality metric. Zero means the
    binned distributions match. Small epsilon masses prevent log(0).
    """
    if bins < 2:
        raise ValueError("bins must be at least 2")
    reference = np.asarray(list(expected), dtype=np.float64)
    current = np.asarray(list(actual), dtype=np.float64)
    if reference.size < 2 or current.size < 2:
        raise ValueError("PSI requires at least two observations per population")
    if not np.all(np.isfinite(reference)) or not np.all(np.isfinite(current)):
        raise ValueError("PSI populations must be finite")
    lo = float(min(reference.min(), current.min()))
    hi = float(max(reference.max(), current.max()))
    if hi <= lo:
        return 0.0
    edges = np.linspace(lo, hi, bins + 1)
    ref_counts, _ = np.histogram(reference, bins=edges)
    cur_counts, _ = np.histogram(current, bins=edges)
    ref = np.maximum(ref_counts / reference.size, 1e-6)
    cur = np.maximum(cur_counts / current.size, 1e-6)
    return float(np.sum((cur - ref) * np.log(cur / ref)))


def drift_state(psi: float, *, warning: float = 0.10, critical: float = 0.25) -> str:
    if not np.isfinite(psi) or psi < 0:
        raise ValueError("psi must be a finite non-negative value")
    if not 0.0 <= warning < critical:
        raise ValueError("thresholds must satisfy 0 <= warning < critical")
    if psi >= critical:
        return "critical"
    if psi >= warning:
        return "warning"
    return "stable"
