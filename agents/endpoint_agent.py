#!/usr/bin/env python3
"""
ThreatFade Endpoint Agent (Stub)
Monitors local network connections and detects fade patterns.
Supports Linux and Windows.

Usage:
    python agents/endpoint_agent.py --duration 60 --interval 5 --export json
    python agents/endpoint_agent.py --mode process --duration 30
"""

import argparse
import json
import os
import sys
import time
import platform
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.fade_engine import detect_fade
from core.siem_exporter import SIEMExporter
from mitre.rule_parser import match_mitre_ttp


def collect_network_signals(duration_sec, interval_sec):
    """Collect network connection counts at regular intervals."""
    print(f"[*] Monitoring network connections for {duration_sec}s (every {interval_sec}s)")
    signals = []
    timestamps = []
    start = time.time()

    while (time.time() - start) < duration_sec:
        count = _count_connections()
        signals.append(float(count))
        timestamps.append(time.time() - start)
        time.sleep(interval_sec)

    print(f"[+] Collected {len(signals)} samples")
    return timestamps, signals


def collect_process_signals(duration_sec, interval_sec):
    """Collect running process counts at regular intervals."""
    print(f"[*] Monitoring process activity for {duration_sec}s (every {interval_sec}s)")
    signals = []
    timestamps = []
    start = time.time()

    while (time.time() - start) < duration_sec:
        count = _count_processes()
        signals.append(float(count))
        timestamps.append(time.time() - start)
        time.sleep(interval_sec)

    print(f"[+] Collected {len(signals)} samples")
    return timestamps, signals


def _count_connections():
    """Count active network connections (cross-platform)."""
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()
            return max(1, len(lines) - 1)
        elif system == "Windows":
            import subprocess
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True, text=True, timeout=5
            )
            established = [l for l in result.stdout.split("\n") if "ESTABLISHED" in l]
            return max(1, len(established))
        elif system == "Darwin":
            import subprocess
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True, text=True, timeout=5
            )
            established = [l for l in result.stdout.split("\n") if "ESTABLISHED" in l]
            return max(1, len(established))
        else:
            return 1
    except Exception:
        return 1


def _count_processes():
    """Count running processes (cross-platform)."""
    system = platform.system()
    try:
        if system == "Linux":
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
            return len(pids)
        elif system == "Windows":
            import subprocess
            result = subprocess.run(
                ["tasklist"],
                capture_output=True, text=True, timeout=5
            )
            return max(1, len(result.stdout.strip().split("\n")) - 3)
        elif system == "Darwin":
            import subprocess
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=5
            )
            return max(1, len(result.stdout.strip().split("\n")) - 1)
        else:
            return 1
    except Exception:
        return 1


def normalize_signals(signals):
    """Normalize signal values to 0-1 range for fade detection."""
    if not signals or max(signals) == 0:
        return [0.5] * len(signals)
    max_val = max(signals)
    min_val = min(signals)
    if max_val == min_val:
        return [0.5] * len(signals)
    return [(v - min_val) / (max_val - min_val) for v in signals]


def print_agent_banner():
    system = platform.system()
    hostname = platform.node()
    print(f"\n{'=' * 56}")
    print(f"  ThreatFade Endpoint Agent (Stub)")
    print(f"  Host: {hostname}")
    print(f"  OS: {system} {platform.release()}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'=' * 56}\n")


def main():
    parser = argparse.ArgumentParser(description="ThreatFade Endpoint Agent")
    parser.add_argument("--mode", choices=["network", "process"], default="network",
                        help="Monitoring mode (default: network)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Monitoring duration in seconds (default: 60)")
    parser.add_argument("--interval", type=int, default=5,
                        help="Sample interval in seconds (default: 5)")
    parser.add_argument("--export", choices=["json", "splunk", "cef", "csv", "none"],
                        default="none", help="SIEM export format")
    args = parser.parse_args()

    print_agent_banner()

    if args.mode == "network":
        timestamps, signals = collect_network_signals(args.duration, args.interval)
    else:
        timestamps, signals = collect_process_signals(args.duration, args.interval)

    if len(signals) < 12:
        print(f"[!] Only {len(signals)} samples collected (minimum 12 needed).")
        print(f"[!] Increase --duration or decrease --interval.")
        return

    normalized = normalize_signals(signals)

    print(f"\n[*] Running fade detection on {len(normalized)} samples ...")
    result = detect_fade(timestamps, normalized)
    mitre_ttp = match_mitre_ttp(result) if result["detected"] else "None"

    print(f"\n{'_' * 56}")
    print(f"  Endpoint Agent Detection Report")
    print(f"{'_' * 56}")
    detected = result["detected"]
    print(f"  Mode           : {args.mode}")
    print(f"  Samples        : {len(signals)}")
    print(f"  Duration       : {args.duration}s")
    print(f"  Fade detected  : {'YES' if detected else 'NO'}")
    if detected:
        print(f"  Confidence     : {result['confidence'].upper()}")
        print(f"  Score          : {result['score']:.4f}")
        print(f"  Z-score        : {result['z_outlier']:.2f}")
        print(f"  MITRE TTP      : {mitre_ttp}")
    print(f"{'_' * 56}\n")

    if args.export != "none" and detected:
        source = f"endpoint_{args.mode}_{platform.node()}"
        exporter = SIEMExporter()
        path = exporter.export([result], format_type=args.export)
        print(f"[+] SIEM export saved: {path}")

    print("[+] Agent scan complete.\n")


if __name__ == "__main__":
    main()
