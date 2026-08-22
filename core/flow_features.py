"""Canonical network-flow and session feature primitives.

The module accepts normalized packet observations so packet capture adapters can
remain separate from detection science. It intentionally uses metadata only;
it never requires payload decryption.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np


@dataclass(frozen=True)
class PacketObservation:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_bytes: int
    payload_bytes: int = 0

    def __post_init__(self) -> None:
        if not np.isfinite(float(self.timestamp)):
            raise ValueError("packet timestamp must be finite")
        if self.packet_bytes < 0 or self.payload_bytes < 0:
            raise ValueError("packet sizes cannot be negative")
        if self.payload_bytes > self.packet_bytes:
            raise ValueError("payload cannot exceed packet size")

    @property
    def flow_key(self) -> tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, int(self.src_port), int(self.dst_port), self.protocol.upper())

    @property
    def bidirectional_key(self) -> tuple[tuple[str, int], tuple[str, int], str]:
        left = (self.src_ip, int(self.src_port))
        right = (self.dst_ip, int(self.dst_port))
        return (left, right, self.protocol.upper()) if left <= right else (right, left, self.protocol.upper())


@dataclass(frozen=True)
class FlowFeatures:
    flow_key: tuple
    packet_count: int
    total_bytes: int
    payload_bytes: int
    duration_seconds: float
    mean_interarrival_seconds: float
    interarrival_cv: float
    packets_per_second: float
    bytes_per_second: float
    upstream_ratio: float

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def sessionize_observations(
    observations: Iterable[PacketObservation],
    *,
    inactivity_gap_seconds: float = 30.0,
) -> list[list[PacketObservation]]:
    """Group observations by bidirectional flow and inactivity gap."""
    if inactivity_gap_seconds <= 0:
        raise ValueError("inactivity_gap_seconds must be positive")
    groups: dict[tuple, list[PacketObservation]] = {}
    for observation in observations:
        groups.setdefault(observation.bidirectional_key, []).append(observation)
    sessions: list[list[PacketObservation]] = []
    for items in groups.values():
        ordered = sorted(items, key=lambda item: item.timestamp)
        current: list[PacketObservation] = []
        previous = None
        for item in ordered:
            if previous is not None and item.timestamp - previous > inactivity_gap_seconds:
                if current:
                    sessions.append(current)
                current = []
            current.append(item)
            previous = item.timestamp
        if current:
            sessions.append(current)
    return sessions


def extract_flow_features(observations: Sequence[PacketObservation]) -> FlowFeatures:
    if not observations:
        raise ValueError("at least one packet observation is required")
    ordered = sorted(observations, key=lambda item: item.timestamp)
    key = ordered[0].bidirectional_key
    timestamps = np.asarray([item.timestamp for item in ordered], dtype=np.float64)
    intervals = np.diff(timestamps)
    duration = float(max(0.0, timestamps[-1] - timestamps[0]))
    mean_iat = float(np.mean(intervals)) if intervals.size else 0.0
    iat_cv = float(np.std(intervals) / max(mean_iat, 1e-12)) if intervals.size else 0.0
    packet_count = len(ordered)
    total_bytes = int(sum(item.packet_bytes for item in ordered))
    payload_bytes = int(sum(item.payload_bytes for item in ordered))
    pps = float(packet_count / duration) if duration > 0 else float(packet_count)
    bps = float(total_bytes / duration) if duration > 0 else float(total_bytes)
    # Directionality is metadata only and remains bounded for evidence fusion.
    first_src = ordered[0].src_ip
    upstream = sum(1 for item in ordered if item.src_ip == first_src)
    upstream_ratio = float(upstream / packet_count)
    return FlowFeatures(key, packet_count, total_bytes, payload_bytes, duration, mean_iat, iat_cv, pps, bps, upstream_ratio)


def activity_series(
    observations: Sequence[PacketObservation],
    *,
    interval_seconds: float = 1.0,
    use_bytes: bool = True,
) -> tuple[list[float], list[float]]:
    """Create a dense activity time series for fade detection."""
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    if not observations:
        return [], []
    ordered = sorted(observations, key=lambda item: item.timestamp)
    start = ordered[0].timestamp
    end = ordered[-1].timestamp
    count = max(1, int(np.floor((end - start) / interval_seconds)) + 1)
    buckets = np.zeros(count, dtype=np.float64)
    for item in ordered:
        index = min(count - 1, int((item.timestamp - start) // interval_seconds))
        buckets[index] += item.packet_bytes if use_bytes else 1.0
    maximum = float(buckets.max())
    normalized = (buckets / maximum).tolist() if maximum > 0 else buckets.tolist()
    timestamps = [float(start + i * interval_seconds) for i in range(count)]
    return timestamps, normalized
