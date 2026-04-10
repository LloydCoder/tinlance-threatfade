# ThreatFade

**Evasion Interception Platform** by Tinlance Limited

ThreatFade detects moments when adversaries intentionally silence their signals — C2 channels go quiet, process artifacts vanish, GNSS gets jammed. It reconstructs the pattern using entropy analysis, z-score anomaly detection, and rule-based matching.

**Status:** v0.2.0-beta (early research)
**License:** Apache 2.0 (open-core)
© 2026 Tinlance Limited

---

## Quick Start
```bash
git clone https://github.com/LloydCoder/tinlance-threatfade.git
cd tinlance-threatfade
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Run on simulated data
python main.py

# Run directly on a PCAP file
python main.py --pcap path/to/capture.pcapng --export json

# Export to different SIEM formats
python main.py --scenario c2_quieting --export splunk
python main.py --scenario c2_quieting --export cef
python main.py --scenario c2_quieting --export csv
```

## What It Does

ThreatFade analyses network signals (from simulation or real PCAP captures) and flags fade events — periods where an adversary deliberately reduces or hides their footprint.

**Detection pipeline:** Raw signal → rolling Shannon entropy → z-score outlier detection → heuristic rule matching → confidence scoring → MITRE TTP classification → SIEM export + alert + visualization.

**Current capabilities:**

- Direct PCAP/PCAPNG ingestion (via --pcap flag)
- 5 simulated threat scenarios (C2 quieting, LOTL gradual, GNSS jam, mixed, normal-with-fade)
- Confidence scoring (critical / high / medium / low / info)
- SIEM export to JSON, Splunk HEC, CEF syslog, and CSV
- MITRE ATT&CK TTP stub mapping
- Volatility memory artifact simulation (reference)
- Dark-mode PNG timeline visualization
- Telegram alerts with attached visualization
- Runs completely offline

## SIEM Integration

ThreatFade exports detection results directly to common SIEM formats. No additional tooling required.

**JSON (default)** — structured report for Splunk, ELK, or custom pipelines:
```bash
python main.py --pcap capture.pcapng --export json
```

**Splunk HEC** — ready for HTTP Event Collector ingestion:
```bash
python main.py --pcap capture.pcapng --export splunk
```

**CEF** — Common Event Format for syslog-based SIEMs (ArcSight, QRadar):
```bash
python main.py --pcap capture.pcapng --export cef
```

**CSV** — for spreadsheet analysis or custom tooling:
```bash
python main.py --pcap capture.pcapng --export csv
```

All exports are saved to `reports/siem/` with timestamped filenames.

## Real-World Validation

Tested on real malware traffic from Active Countermeasures:

| Source | Packets | Sessions | Detected | Z-Score | Confidence | MITRE TTP |
|--------|---------|----------|----------|---------|------------|-----------|
| Merlin QUIC C2 | 490,565 | 521 | YES | 14.76 | HIGH | T1573.002 |
| Cobalt Strike | Real PCAP | - | YES | 7.01 | MEDIUM | T1027 |
| IcedID | Real PCAP | - | YES | 3.89 | LOW | T1027 |

False-positive baseline: **0%** across 5 normal traffic patterns (100 test runs).

## Architecture
```
main.py                      Entry point, CLI, PCAP ingestion
core/fade_engine.py          Detection logic (entropy + z-score + rules + confidence)
core/siem_exporter.py        SIEM export (JSON, Splunk HEC, CEF, CSV)
agents/signal_generator.py   Multi-scenario signal simulation
viz/timeline_plot.py         Dark-mode PNG visualization
mitre/rule_parser.py         MITRE TTP stub matching
volatility/memory_sim.py     Volatility artifact simulation (reference)
alerts/telegram_alert.py     Telegram alert integration
agents/endpoint_agent.py     Endpoint agent stub (Linux/Windows)
```

## Endpoint Agent

Lightweight agent that monitors local network connections or process activity and runs fade detection.

```bash
# Monitor network connections for 60 seconds
python agents/endpoint_agent.py --mode network --duration 60 --interval 5 --export json

# Monitor process activity
python agents/endpoint_agent.py --mode process --duration 60 --interval 5 --export cef
```

Supports Linux, Windows, and macOS. Exports to all SIEM formats.

## Testing
```bash
# Unit tests (22 tests covering detection, confidence, edge cases)
pytest test_fade_engine.py -v

# False-positive baseline (5 normal traffic patterns, 100 runs)
python test_false_positives.py
```

## Q2 2026 Progress

| Milestone | Status |
|-----------|--------|
| Real PCAP ingestion | ✅ Complete |
| Confidence scoring | ✅ Complete |
| False-positive baseline (0%) | ✅ Complete |
| SIEM export (JSON/Splunk/CEF/CSV) | ✅ Complete |
| Endpoint agent stubs (Linux/Windows) | ✅ Complete |
| First 50-100 beta testers | In progress |

## Roadmap

**Q3 2026:** Full MITRE sub-technique mapping, satellite signal fusion (proof of concept), rugged hardware integration stubs.

**Q4 2026:** Enterprise multi-tenant federation, performance optimization for large-scale captures, quantum-resistant transport layer.

## Limitations

- **Real-world accuracy:** Validated on 3 real PCAPs (Merlin QUIC, Cobalt Strike, IcedID). FP rate 0% on synthetic normal traffic.
- **MITRE mapping:** Stub implementation (broad TTPs, not sub-techniques).
- **Volatility:** Simulated artifacts only. No real memory dump parsing yet.
- **Scale:** Tested on datasets under 1 GB.

## Configuration

Detection thresholds: `config.yaml`. Telegram alerts: copy `.env.example` to `.env` and fill in your bot token.

## Contributing

Found a bug? Want to improve detection logic? Open an issue or pull request. See CONTRIBUTING.md for guidelines.

## License

Apache 2.0 for the open-core base. Proprietary extensions reserved to Tinlance Limited.

## Contact

- **GitHub Issues:** Bug reports and feature requests
- **Twitter:** [@lloydcoder](https://twitter.com/lloydcoder)
- **Email:** lloydcoder@protonmail.com

Built by Nwachukwu Chinaemerem ([@lloydcoder](https://github.com/LloydCoder))
Tinlance Limited — Nigeria
