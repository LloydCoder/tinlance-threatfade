#!/usr/bin/env python3
"""
ThreatFade™ - Evasion Interception Platform
Main CLI with SIEM Export (Q2 Deliverable)

© Tinlance Limited 2026 - Apache 2.0
"""

import argparse
import sys
from pathlib import Path

from core.fade_engine import detect_fade
from core.siem_exporter import SIEMExporter
from agents.signal_generator import generate_signals

def main():
    parser = argparse.ArgumentParser(description="ThreatFade™ v0.2.0-beta - Threat Fade / Evasion Detection")
    parser.add_argument("--scenario", type=str, default="c2_quieting",
                        choices=["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"],
                        help="Simulation scenario")
    parser.add_argument("--pcap", type=str, help="Path to .pcap/.pcapng file")
    parser.add_argument("--data", type=str, help="Path to pre-processed JSON signal file")
    parser.add_argument("--export", type=str, choices=["none", "json", "cef", "syslog"], default="none",
                        help="SIEM export format")
    args = parser.parse_args()

    print("🚀 ThreatFade™ v0.2.0-beta")
    print("=" * 70)

    # Get signals
    if args.pcap:
        print(f"📁 Analyzing PCAP: {args.pcap}")
        try:
            from pcap_to_threatfade import pcap_to_signals
            # Suppress the "Now run --data" message by redirecting stdout temporarily if possible
            import contextlib
            with contextlib.redirect_stdout(sys.stdout):
                timestamps, entropy_values = pcap_to_signals(args.pcap)
            source_name = Path(args.pcap).stem
        except Exception as e:
            print(f"[!] PCAP processing error: {e}")
            return
    elif args.data:
        print(f"📄 Loading signals from: {args.data}")
        import json
        with open(args.data) as f:
            data = json.load(f)
        timestamps = list(range(len(data.get("values", []))))
        entropy_values = data.get("values", [])
        source_name = Path(args.data).stem
    else:
        print(f"🔬 Simulating scenario: {args.scenario}")
        timestamps, entropy_values = generate_signals(args.scenario)
        source_name = args.scenario

    # Run detection
    result = detect_fade(timestamps, entropy_values)

    print("\n📊 Detection Results:")
    print(f"   Detected      : {result.get('detected', False)}")
    print(f"   Confidence    : {result.get('confidence', 'MEDIUM')}")
    print(f"   Z-Score       : {result.get('z_score', result.get('z_outlier', 0)):.2f}")
    print(f"   MITRE TTP     : {result.get('mitre_ttp', 'N/A')}")

    if result.get('z_score', 0) > 10 or result.get('z_outlier', 0) > 10:
        print(f"   🔥 Strong signal detected (Z-Score > 10)")

    # SIEM Export
    if args.export != "none":
        exporter = SIEMExporter()
        msg = exporter.export(
            result=result,
            source_name=source_name,
            format_type=args.export
        )
        print(f"\n{msg}")
    else:
        print("\n💡 Tip: Add --export json | cef | syslog")

    print("\n✅ Analysis complete. Q2 SIEM Export is live.")

if __name__ == "__main__":
    main()
