# Changelog

All notable changes to ThreatFade will be documented in this file.

## [1.0.0-beta] – 2026-03-09

### Initial Release

**Early Research MVP – Simulated data only**

#### Added
- Core fade detection engine (entropy + z-score + rule-based)
- Multi-scenario signal simulation:
  - C2 Command & Control quieting
  - Living-Off-The-Land (LOTL) gradual decline
  - GNSS jamming (cyber-physical)
  - False positive scenarios
  - Mixed scenario combinations
- Dark-mode cyberpunk PNG visualization
- MITRE ATT&CK TTP stub matching
- Volatility memory artifact simulation (reference)
- Telegram real-time alerting with PNG reports
- JSON report export
- Comprehensive pytest test suite
- Rich console output with colored formatting
- YAML configuration management
- Environment variable support for secrets
- GitHub Actions CI/CD pipeline
- Apache 2.0 open-core licensing

#### Known Limitations
- Detection trained on simulated data only
- False positive rate unknown on real traffic
- MITRE/Volatility implementations are stubs
- Telegram-only alerts (SIEM export coming Q2)
- No endpoint agents yet (Python CLI only)
- No performance benchmarks

#### Planned for Q2 2026
- Real pcap/network traffic analysis
- Endpoint agents (Windows/Linux/macOS)
- SIEM export (Splunk, ELK, Splunk HEC)
- Web dashboard prototype
- Mobile agent stubs (iOS/Android)
- Performance optimization & benchmarking

#### Planned for Q3 2026
- Satellite data fusion
- Rugged MIL-STD hardware stubs
- Cross-platform agent deployment

#### Planned for Q4 2026
- Enterprise federation protocol
- Quantum cryptography layer
- Full ecosystem integration

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH-PRERELEASE**
- Example: `1.0.0-beta`, `1.1.0-rc1`, `2.0.0`

## Contributing

Found a bug or want to contribute? See [CONTRIBUTING.md](CONTRIBUTING.md)

---

© 2026 Tinlance Limited
