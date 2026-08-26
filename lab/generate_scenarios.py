#!/usr/bin/env python3
"""Generate deterministic, benign network-traffic PCAP fixtures for ThreatFade.

This lab intentionally does not execute malware or contact external C2. It creates
synthetic packet sequences whose timing and payload characteristics can be used to
exercise ThreatFade's behavioral/fade detection logic.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "pcaps"
META = ROOT / "ground-truth"

BASE_TIME = 1_756_000_000.0
SRC = "10.10.0.10"
DST = "10.10.0.20"


def tcp_packet(ts: float, payload: bytes, sport: int = 41000, dport: int = 443):
    pkt = Ether() / IP(src=SRC, dst=DST) / TCP(sport=sport, dport=dport, flags="PA", seq=1) / Raw(payload)
    pkt.time = ts
    return pkt


def udp_packet(ts: float, payload: bytes, sport: int = 53000, dport: int = 53):
    pkt = Ether() / IP(src=SRC, dst=DST) / UDP(sport=sport, dport=dport) / Raw(payload)
    pkt.time = ts
    return pkt


def periodic_beacon(fade: bool = False) -> list:
    intervals = [10.0] * 8
    if fade:
        intervals = [10.0, 10.0, 11.0, 14.0, 22.0, 35.0, 55.0, 80.0]

    packets = []
    ts = BASE_TIME
    for i, interval in enumerate(intervals):
        payload = (b"THREATFADE-BENIGN-BEACON-%02d" % i) + (b"A" * (32 if not fade else 20 + i * 7))
        packets.append(tcp_packet(ts, payload))
        ts += interval
    return packets


def normal_web() -> list:
    packets = []
    ts = BASE_TIME
    for i in range(12):
        packets.append(tcp_packet(ts, b"GET /health HTTP/1.1\r\nHost: lab.local\r\n\r\n", sport=42000 + i))
        packets.append(tcp_packet(ts + 0.15, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", sport=443, dport=42000 + i))
        ts += 3.0 + (i % 3) * 0.7
    return packets


def dns_burst() -> list:
    packets = []
    ts = BASE_TIME
    for i in range(20):
        packets.append(udp_packet(ts, f"query-{i:02d}.lab.local".encode()))
        ts += 0.5
    return packets


def write_scenario(name: str, packets: Iterable, label: str, description: str) -> None:
    packets = list(packets)
    OUT.mkdir(parents=True, exist_ok=True)
    META.mkdir(parents=True, exist_ok=True)

    pcap_path = OUT / f"{name}.pcap"
    truth_path = META / f"{name}.json"
    wrpcap(str(pcap_path), packets)

    truth = {
        "scenario_id": name,
        "generator": "ThreatFade deterministic synthetic traffic lab v1",
        "safety": "benign synthetic packets; no malware execution; no external network destinations",
        "label": label,
        "expected_fade": label == "fade",
        "description": description,
        "packet_count": len(packets),
        "capture_start": BASE_TIME,
        "capture_end": max(float(p.time) for p in packets),
    }
    truth_path.write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    print(f"generated {pcap_path} ({len(packets)} packets)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["all", "normal-web", "dns-burst", "beacon", "fade"], default="all")
    args = parser.parse_args()

    scenarios = {
        "normal-web": (normal_web(), "benign", "Repeated short-lived web-style requests with stable cadence."),
        "dns-burst": (dns_burst(), "benign", "Short deterministic DNS-like UDP burst."),
        "beacon": (periodic_beacon(False), "beacon", "Stable periodic TCP beacon-like sequence."),
        "fade": (periodic_beacon(True), "fade", "Beacon sequence whose timing and payload profile progressively degrades."),
    }

    selected = scenarios if args.scenario == "all" else {args.scenario: scenarios[args.scenario]}
    for name, (packets, label, description) in selected.items():
        write_scenario(name, packets, label, description)


if __name__ == "__main__":
    main()
