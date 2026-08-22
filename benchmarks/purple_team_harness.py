"""Safe purple-team test-case generator for ThreatFade.

This produces abstract network-signal transformations only. It does not execute
malware, generate C2 payloads, or provide operational intrusion instructions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Transformation:
    name: str
    expected_effect: str
    preserves_semantics: bool = True


TRANSFORMATIONS = (
    Transformation("timing_jitter", "periodicity becomes less regular"),
    Transformation("silence_extension", "fade window becomes longer"),
    Transformation("burst_split", "traffic bursts become fragmented"),
    Transformation("packet_loss", "partial observation"),
    Transformation("padding_variation", "payload-size distribution changes"),
    Transformation("capture_truncation", "session evidence becomes incomplete"),
)


def generate_matrix() -> list[dict]:
    return [
        {"id": f"PT-{i+1:03d}", "transformation": item.name, "expected_effect": item.expected_effect,
         "preserves_semantics": item.preserves_semantics}
        for i, item in enumerate(TRANSFORMATIONS)
    ]


def validate_matrix(rows: Iterable[dict]) -> None:
    rows = list(rows)
    if len(rows) != len(TRANSFORMATIONS):
        raise ValueError("purple-team matrix is incomplete")
    names = {row["transformation"] for row in rows}
    expected = {item.name for item in TRANSFORMATIONS}
    if names != expected:
        raise ValueError("purple-team matrix contains missing or unknown transformations")


if __name__ == "__main__":
    matrix = generate_matrix()
    validate_matrix(matrix)
    print("Purple-team robustness matrix: OK")
