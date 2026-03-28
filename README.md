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
python main.py --pcap path/to/capture.pcapng --export

# Run on pre-converted JSON signals
python main.py --data real_c2_signal.json --export

# Specific scenario
python main.py --scenario c2_quieting --export
```

## What It Does

ThreatFade analyses network signals (from simulation or real PCAP captures) and flags fade events — periods where an adversary deliberately reduces or hides their footprint.

**Detection pipeline:** Raw signal → rolling Shannon entropy → z-score outlier detection → heuristic rule matching → confidence scoring → MITRE TTP classification → alert + visualization.

**Current capabilities:**

- Direct PCAP/PCAPNG ingestion (via --pcap flag)
- 5 simulated threat scenarios (C2 quieting, LOTL gradual, GNSS jam, mixed, normal-with-fade)
- Confidence scoring (critical / high / medium / low / info)
- MITRE ATT&CK TTP stub mapping
- Volatility memory artifact simulation (reference)
- Dark-mode PNG timeline visualization
- JSON report export
- Telegram alerts with attached visualization
- Runs completely offline

## Real-World Validation

Tested on real malware traffic from Active Countermeasures:

| Source | Packets | Sessions | Detected | Z-Score | Confidence | MITRE TTP |
|--------|---------|----------|----------|---------|------------|-----------|
| Merlin QUIC C2 | 490,565 | 521 | YES | 14.76 | HIGH | T1027 |

The Merlin QUIC capture contains 24 hours of real C2 beacon traffic with periodic quieting. ThreatFade flagged the evasion pattern with a z-score outlier of 14.76, well above the statistical significance threshold.

False-positive testing on baseline traffic is in progress.

## Architecture
```
main.py                    Entry point, CLI, PCAP ingestion
core/fade_engine.py        Detection logic (entropy + z-score + rules + confidence)
agents/signal_generator.py Multi-scenario signal simulation
viz/timeline_plot.py       Dark-mode PNG visualization
mitre/rule_parser.py       MITRE TTP stub matching
volatility/memory_sim.py   Volatility artifact simulation (reference)
alerts/telegram_alert.py   Telegram alert integration
```

## Testing
```bash
pytest test_fade_engine.py -v
python test_false_positives.py
```

The test suite covers detection accuracy, confidence scoring, edge cases, and custom configuration. The false-positive baseline runs 100 tests across 5 normal traffic patterns.

## Limitations

This is an early research prototype. Be aware of:

- **Real-world accuracy:** Validated on 1 real PCAP so far. False-positive rate on normal traffic is being measured.
- **MITRE mapping:** Stub implementation. Maps to broad TTPs, not specific sub-techniques.
- **Volatility integration:** Simulated artifacts only. No real memory dump parsing yet.
- **Alerting:** Telegram only. SIEM export (Splunk, ELK) planned for Q2.
- **Scale:** Tested on datasets under 1 GB. Performance on larger captures is untested.

## Roadmap

**Q2 2026:** False-positive baseline testing, SIEM export (JSON to Splunk HEC / ELK), endpoint agent stubs (Linux/Windows).

**Q3 2026:** Full MITRE sub-technique mapping, satellite signal fusion (proof of concept), rugged hardware integration stubs.

**Q4 2026:** Enterprise multi-tenant federation, performance optimization for large-scale captures, quantum-resistant transport layer.

## Configuration

Detection thresholds can be tuned via config.yaml. For Telegram alerts, copy .env.example to .env and fill in your bot token and chat ID.

## Contributing

Found a bug? Want to improve detection logic? Open an issue or pull request. Early feedback shapes the roadmap. See CONTRIBUTING.md for guidelines.

## License

Apache 2.0 for the open-core base. Proprietary extensions (satellite fusion, hardware integration, enterprise federation, offensive simulation) are reserved to Tinlance Limited.

## Contact

- **GitHub Issues:** Bug reports and feature requests
- **Twitter:** [@lloydcoder](https://twitter.com/lloydcoder)
- **Email:** lloydcoder@protonmail.com

Built by Nwachukwu Chinaemerem ([@lloydcoder](https://github.com/LloydCoder))
Tinlance Limited — Nigeria
