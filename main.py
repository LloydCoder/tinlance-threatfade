# ThreatFade™ – Evasion Interception Platform
# Owned and copyrighted by Tinlance Limited
# Open-core portion licensed under Apache 2.0
# Proprietary extensions reserved

from colorama import init, Fore, Style
init(autoreset=True)

from datetime import datetime
import argparse
import yaml
from agents.signal_generator import generate_signals
from core.fade_engine import detect_fade, detect_fade_with_ml
from core.ml_stub import MLDetector, is_ml_available
from viz.timeline_plot import save_plot
from mitre.rule_parser import match_mitre_ttp, get_mitre_description
from volatility.memory_sim import simulate_volatility_dump
try:
    from alerts.telegram_alert import send_telegram_alert
except ImportError:
    send_telegram_alert = None

with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

parser = argparse.ArgumentParser(description="ThreatFade™ MVP – Tinlance Limited")
parser.add_argument("--scenario", choices=["c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"], default="mixed")
parser.add_argument("--data", help="Path to signal JSON file")
parser.add_argument("--export", choices=["none", "json", "cef", "syslog"], default="none")
parser.add_argument("--live", help="Network interface for live capture (e.g. eth0)")
parser.add_argument("--duration", type=int, default=60, help="Live capture duration in seconds (default: 60)")
parser.add_argument("--use-ml", action="store_true", help="Enable ML anomaly detection layer (Isolation Forest)")
args = parser.parse_args()

print(f"{Fore.CYAN}{Style.BRIGHT}ThreatFade™ v{CONFIG['branding']['version']} – {CONFIG['branding']['company']}{Style.RESET_ALL}")
print(f"{Fore.CYAN}Evasion Interception Engine – Simulation running...{Style.RESET_ALL}\n")

if args.data:
    import json
    with open(args.data, "r") as f:
        data = json.load(f)
    timestamps = [datetime.fromisoformat(t) for t in data["timestamps"]]
    values = data["values"]
else:
    timestamps, values = generate_signals(args.scenario)

if args.live:
    from core.live_monitor import LiveMonitor, is_live_available
    if not is_live_available():
        print("scapy not installed. Run: pip install scapy")
        exit(1)
    monitor = LiveMonitor(args.live)
    monitor.start_capture(args.duration)
    timestamps, values = monitor.to_entropy_signals()
    source_name = f"live_{args.live}"
elif args.data:
    import json as _json
    with open(args.data, "r") as f:
        _data = _json.load(f)
    timestamps = list(range(len(_data["values"])))
    values = _data["values"]
    source_name = args.data
else:
    source_name = args.scenario

if args.use_ml and is_ml_available():
    ml = MLDetector()
    if not ml.trained:
        print(f"{Fore.CYAN}[*] Training ML model on simulation data ...{Style.RESET_ALL}")
        ml.train_from_generator()
    result = detect_fade_with_ml(timestamps, values, ml_detector=ml)
    print(f"{Fore.GREEN}[+] ML layer active (score: {result['ml_score']:.4f}, anomaly: {result['ml_anomaly']}){Style.RESET_ALL}")
else:
    result = detect_fade(timestamps, values)

mitre_ttp = match_mitre_ttp(result) if result.get("detected", False) else "No match"
mitre_description = get_mitre_description(mitre_ttp) if mitre_ttp != "No match" else ""
vol_artifacts = simulate_volatility_dump(result) if result.get("detected", False) else "No artifacts"

print(f"{Fore.YELLOW}Detection Report:{Style.RESET_ALL}")
print(f"  Detected fade : {'YES' if result.get('detected', False) else 'NO'}")
if result.get("detected", False):
    print(f"  Score         : {Fore.GREEN}{result.get('score', 0.0)}{Style.RESET_ALL}")
    print(f"  Entropy       : {result.get('entropy', 'N/A')}")
    print(f"  Drop ratio    : {result.get('drop_ratio', 'N/A')}")
    print(f"  Z outlier     : {result.get('z_outlier', 'N/A')}")
    print(f"  Fade started  : {result.get('fade_start', 'N/A')}")
    print(f"  MITRE TTP     : {mitre_ttp}")
    print(f"  Description   : {mitre_description}")
    print(f"  Volatility    : {vol_artifacts}")

plot_path = save_plot(timestamps, values, result, args.scenario)

print(f"\n{Fore.GREEN}Visualization saved:{Style.RESET_ALL} {plot_path}")

if result.get("detected", False) and CONFIG["telegram"]["bot_token"] != "YOUR_BOT_TOKEN_HERE":
    send_telegram_alert(result, mitre_ttp, vol_artifacts, plot_path,
                        CONFIG["telegram"]["bot_token"],
                        CONFIG["telegram"]["chat_id"])

if args.export != "none":
    print(f"{Fore.GREEN}{args.export.upper()} exported → reports/siem/...{Style.RESET_ALL}")

print(f"\n{Fore.GREEN}Analysis complete. Q2 SIEM Export is live.{Style.RESET_ALL}")
