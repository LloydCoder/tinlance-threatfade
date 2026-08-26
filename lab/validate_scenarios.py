#!/usr/bin/env python3
"""Validate the deterministic ThreatFade PCAP fixtures and their ground truth."""

from __future__ import annotations

import json
from pathlib import Path

from scapy.all import rdpcap

ROOT = Path(__file__).resolve().parent
PCAPS = ROOT / "pcaps"
TRUTH = ROOT / "ground-truth"
EXPECTED = {"normal-web": "benign", "dns-burst": "benign", "beacon": "beacon", "fade": "fade"}


def main() -> None:
    failures: list[str] = []
    for scenario, label in EXPECTED.items():
        pcap = PCAPS / f"{scenario}.pcap"
        truth = TRUTH / f"{scenario}.json"
        if not pcap.exists() or not truth.exists():
            failures.append(f"missing fixture: {scenario}")
            continue

        packets = rdpcap(str(pcap))
        data = json.loads(truth.read_text(encoding="utf-8"))
        if data["label"] != label:
            failures.append(f"{scenario}: label mismatch")
        if data["packet_count"] != len(packets):
            failures.append(f"{scenario}: packet count mismatch")
        if data["expected_fade"] != (label == "fade"):
            failures.append(f"{scenario}: expected_fade mismatch")
        if len(packets) == 0:
            failures.append(f"{scenario}: empty PCAP")

    if failures:
        raise SystemExit("\n".join(failures))
    print(f"PASS: {len(EXPECTED)} deterministic ThreatFade scenarios validated")


if __name__ == "__main__":
    main()
