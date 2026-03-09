#!/usr/bin/env python3
"""
ThreatFade™ – Evasion Interception Platform
Owned and copyrighted by Tinlance Limited
Open-core portion licensed under Apache 2.0
Proprietary extensions reserved

Early Research MVP – v1.0.0-beta
"""

from colorama import init, Fore, Style
init(autoreset=True)

from datetime import datetime
import argparse
import yaml
import os
import json

from agents.signal_generator import generate_signals
from core.fade_engine import detect_fade
from viz.timeline_plot import save_plot
from mitre.rule_parser import match_mitre_ttp
from volatility.memory_sim import simulate_volatility_dump
from alerts.telegram_alert import send_telegram_alert

# Load config
with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

# CLI arguments
parser = argparse.ArgumentParser(
    description="ThreatFade™ MVP – Tinlance Limited – Evasion Interception Platform"
)
parser.add_argument(
    "--scenario",
    choices=["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"],
    default="mixed",
    help="Threat scenario to simulate"
)
parser.add_argument(
    "--export",
    action="store_true",
    help="Export JSON + PNG reports to reports/ folder"
)

args = parser.parse_args()

# Banner
print(f"{Fore.CYAN}{Style.BRIGHT}╔══════════════════════════════════════════════╗{Style.RESET_ALL}")
print(f"{Fore.CYAN}{Style.BRIGHT}║  ThreatFade™ v{CONFIG['branding']['version']}                          ║{Style.RESET_ALL}")
print(f"{Fore.CYAN}{Style.BRIGHT}║  {CONFIG['branding']['company']}                   ║{Style.RESET_ALL}")
print(f"{Fore.CYAN}{Style.BRIGHT}║  Evasion Interception Platform                ║{Style.RESET_ALL}")
print(f"{Fore.CYAN}{Style.BRIGHT}╚══════════════════════════════════════════════╝{Style.RESET_ALL}\n")
print(f"{Fore.YELLOW}Early Research MVP – Simulated Data Only{Style.RESET_ALL}\n")

# Generate signals
print(f"{Fore.CYAN}[*] Generating {args.scenario} scenario...{Style.RESET_ALL}")
timestamps, values = generate_signals(args.scenario)
print(f"{Fore.GREEN}[✓] Generated {len(values)} signal points{Style.RESET_ALL}\n")

# Detect fade
print(f"{Fore.CYAN}[*] Running fade detection engine...{Style.RESET_ALL}")
result = detect_fade(timestamps, values)

# MITRE TTP matching
mitre_ttp = match_mitre_ttp(result) if result["detected"] else "No match"

# Volatility simulation
vol_artifacts = simulate_volatility_dump(result) if result["detected"] else "No artifacts"

# Report
print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
print(f"{Fore.YELLOW}Detection Report:{Style.RESET_ALL}")
print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
print(f"  Detected fade     : {Fore.GREEN if result['detected'] else Fore.RED}{'YES' if result['detected'] else 'NO'}{Style.RESET_ALL}")

if result["detected"]:
    print(f"  Score             : {Fore.GREEN}{result['score']:.2f}{Style.RESET_ALL}")
    print(f"  Entropy           : {result['entropy']:.4f}")
    print(f"  Drop ratio        : {result['drop_ratio']:.4f}")
    print(f"  Z-score outlier   : {result['z_outlier']:.2f}")
    print(f"  Fade started at   : {result['fade_start']}")
    print(f"  MITRE TTP         : {Fore.MAGENTA}{mitre_ttp}{Style.RESET_ALL}")
    print(f"  Volatility        : {vol_artifacts}")

print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}\n")

# Save visualization
print(f"{Fore.CYAN}[*] Generating visualization...{Style.RESET_ALL}")
plot_path = save_plot(timestamps, values, result, args.scenario)
print(f"{Fore.GREEN}[✓] Visualization saved: {plot_path}{Style.RESET_ALL}\n")

# Save JSON report
if args.export:
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "scenario": args.scenario,
        "detected": bool(result["detected"]),
        "score": result["score"],
        "entropy": result["entropy"],
        "drop_ratio": result["drop_ratio"],
        "z_outlier": result["z_outlier"],
        "fade_start": result["fade_start"],
        "mitre_ttp": mitre_ttp,
        "volatility_artifacts": vol_artifacts
    }
    
    report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2)
    
    print(f"{Fore.GREEN}[✓] JSON report saved: {report_path}{Style.RESET_ALL}\n")

# Send Telegram alert if enabled
telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", CONFIG["telegram"]["bot_token"])
telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", CONFIG["telegram"]["chat_id"])

if result["detected"] and telegram_token != "YOUR_BOT_TOKEN_HERE":
    print(f"{Fore.CYAN}[*] Sending Telegram alert...{Style.RESET_ALL}")
    try:
        send_telegram_alert(
            result, mitre_ttp, vol_artifacts, plot_path,
            telegram_token,
            telegram_chat_id
        )
        print(f"{Fore.GREEN}[✓] Telegram alert sent{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}[!] Telegram alert failed: {e}{Style.RESET_ALL}\n")

# Final message
print(f"{Fore.GREEN}{'='*50}{Style.RESET_ALL}")
print(f"{Fore.GREEN}{Style.BRIGHT}ThreatFade MVP run complete.{Style.RESET_ALL}")
print(f"{Fore.GREEN}{Style.BRIGHT}Early research prototype – Data simulated only{Style.RESET_ALL}")
print(f"{Fore.GREEN}{'='*50}{Style.RESET_ALL}\n")
print(f"{Fore.CYAN}Questions? Open an issue on GitHub.{Style.RESET_ALL}")
print(f"{Fore.CYAN}Nigeria-1. World-0. 💚{Style.RESET_ALL}\n")
