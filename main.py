#!/usr/bin/env python3
"""
ThreatFade - Evasion Interception Platform
Owned and copyrighted by Tinlance Limited
Open-core portion licensed under Apache 2.0
v0.2.0-beta
"""

from colorama import init, Fore, Style
init(autoreset=True)

from datetime import datetime
import argparse
import yaml
import os
import json
import math
from collections import defaultdict

from agents.signal_generator import generate_signals
from core.fade_engine import detect_fade
from viz.timeline_plot import save_plot
from mitre.rule_parser import match_mitre_ttp
from volatility.memory_sim import simulate_volatility_dump
from alerts.telegram_alert import send_telegram_alert

with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

VERSION = CONFIG["branding"]["version"]
COMPANY = CONFIG["branding"]["company"]


def pcap_to_signals(pcap_path, interval_sec=60):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, Raw
    except ImportError:
        print(f"{Fore.RED}[!] scapy required. Run: pip install scapy{Style.RESET_ALL}")
        raise SystemExit(1)
    print(f"{Fore.CYAN}[*] Reading PCAP: {pcap_path}{Style.RESET_ALL}")
    packets = rdpcap(pcap_path)
    print(f"{Fore.GREEN}[+] Loaded {len(packets)} packets{Style.RESET_ALL}")
    sessions = defaultdict(list)
    for pkt in packets:
        if IP in pkt and Raw in pkt and (TCP in pkt or UDP in pkt):
            payload = pkt[Raw].load
            sessions[float(pkt.time)].append(payload)
    if not sessions:
        print(f"{Fore.YELLOW}[!] No payload-bearing packets found.{Style.RESET_ALL}")
        return list(range(20)), [0.5] * 20
    all_times = sorted(sessions.keys())
    start_t = int(all_times[0])
    end_t = int(all_times[-1])
    timestamps = []
    entropy_values = []
    current = start_t
    while current < end_t:
        window_payloads = []
        for t in all_times:
            if current <= t < current + interval_sec:
                window_payloads.extend(sessions[t])
        if window_payloads:
            combined = b"".join(window_payloads)
            ent = _byte_entropy(combined)
        else:
            ent = 0.0
        timestamps.append(current - start_t)
        entropy_values.append(ent)
        current += interval_sec
    print(f"{Fore.GREEN}[+] Extracted {len(entropy_values)} time-series points{Style.RESET_ALL}")
    return timestamps, entropy_values


def _byte_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent


def print_banner():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 56}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  ThreatFade  v{VERSION}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {COMPANY}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Evasion Interception Platform{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 56}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Early Research MVP - Use at your own risk{Style.RESET_ALL}\n")


def print_report(result, mitre_ttp, vol_artifacts):
    print(f"{Fore.YELLOW}{'_' * 56}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Detection Report{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'_' * 56}{Style.RESET_ALL}")
    detected = result["detected"]
    tag = f"{Fore.RED}YES" if detected else f"{Fore.GREEN}NO"
    print(f"  Fade detected    : {tag}{Style.RESET_ALL}")
    if detected:
        conf = result["confidence"]
        conf_colors = {"critical": Fore.RED, "high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.CYAN, "info": Fore.WHITE}
        cc = conf_colors.get(conf, Fore.WHITE)
        print(f"  Confidence       : {cc}{conf.upper()}{Style.RESET_ALL}")
        print(f"  Score            : {result['score']:.4f}")
        print(f"  Entropy          : {result['entropy']:.4f}")
        print(f"  Drop ratio       : {result['drop_ratio']:.4f}")
        print(f"  Z-score outlier  : {result['z_outlier']:.2f}")
        print(f"  Rules matched    : {result['rules_matched']}")
        print(f"  Fade started at  : sample {result['fade_start']}")
        print(f"  MITRE TTP        : {Fore.MAGENTA}{mitre_ttp}{Style.RESET_ALL}")
        print(f"  Volatility       : {vol_artifacts}")
    print(f"{Fore.YELLOW}{'_' * 56}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="ThreatFade - Evasion Interception Platform")
    parser.add_argument("--scenario", choices=["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"], default="mixed", help="Threat scenario to simulate")
    parser.add_argument("--pcap", help="Path to a .pcap or .pcapng file for direct analysis")
    parser.add_argument("--data", help="Path to a JSON file with timestamps/values arrays")
    parser.add_argument("--export", action="store_true", help="Save JSON report + PNG to reports/")
    args = parser.parse_args()
    print_banner()
    if args.pcap:
        source_name = os.path.basename(args.pcap).replace(" ", "_")
        timestamps, values = pcap_to_signals(args.pcap)
    elif args.data:
        source_name = os.path.basename(args.data).replace(" ", "_")
        print(f"{Fore.CYAN}[*] Loading signals from {args.data}{Style.RESET_ALL}")
        with open(args.data, "r") as f:
            data = json.load(f)
        timestamps = list(range(len(data["values"])))
        values = data["values"]
    else:
        source_name = args.scenario
        print(f"{Fore.CYAN}[*] Simulating scenario: {args.scenario}{Style.RESET_ALL}")
        timestamps, values = generate_signals(args.scenario)
    print(f"{Fore.GREEN}[+] {len(values)} signal points ready{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}[*] Running fade detection engine ...{Style.RESET_ALL}\n")
    result = detect_fade(timestamps, values)
    mitre_ttp = match_mitre_ttp(result) if result["detected"] else "None"
    vol_artifacts = simulate_volatility_dump(result) if result["detected"] else "None"
    print_report(result, mitre_ttp, vol_artifacts)
    os.makedirs("reports", exist_ok=True)
    plot_path = save_plot(timestamps, values, result, source_name)
    print(f"{Fore.GREEN}[+] Visualization saved: {plot_path}{Style.RESET_ALL}")
    if args.export:
        report_data = {
            "timestamp": datetime.now().isoformat(), "source": source_name,
            "detected": result["detected"], "confidence": result["confidence"],
            "score": result["score"], "entropy": result["entropy"],
            "drop_ratio": result["drop_ratio"], "z_outlier": result["z_outlier"],
            "fade_start": result["fade_start"], "rules_matched": result["rules_matched"],
            "mitre_ttp": mitre_ttp, "volatility_artifacts": vol_artifacts,
        }
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"reports/report_{source_name}_{ts}.json"
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"{Fore.GREEN}[+] JSON report saved: {report_path}{Style.RESET_ALL}")
    token = os.getenv("TELEGRAM_BOT_TOKEN", CONFIG["telegram"]["bot_token"])
    chat_id = os.getenv("TELEGRAM_CHAT_ID", CONFIG["telegram"]["chat_id"])
    if result["detected"] and token != "YOUR_BOT_TOKEN_HERE":
        print(f"{Fore.CYAN}[*] Sending Telegram alert ...{Style.RESET_ALL}")
        try:
            send_telegram_alert(result, mitre_ttp, vol_artifacts, plot_path, token, chat_id)
            print(f"{Fore.GREEN}[+] Telegram alert sent{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Telegram alert failed: {e}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}{'=' * 56}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Done. Early research prototype.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 56}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
