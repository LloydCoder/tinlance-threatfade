# ThreatFade Codespace Lab

This is the first reproducible test environment for ThreatFade. It is designed to run inside GitHub Codespaces with no malware execution and no external C2 communication.

## Goals

- Generate deterministic packet captures for behavioral testing.
- Establish benign, beacon, and fade ground-truth scenarios.
- Keep captures reproducible so engine regressions can be measured release over release.
- Provide a foundation for later Zeek/Suricata/Security Onion validation.

## Start in Codespaces

1. Open the repository in GitHub Codespaces.
2. Wait for the post-create dependency installation to finish.
3. Run:

```bash
python lab/generate_scenarios.py --scenario all
```

Generated files are placed under:

```text
lab/pcaps/
lab/ground-truth/
```

## Scenarios

| Scenario | Ground truth | Purpose |
| --- | --- | --- |
| `normal-web` | benign | Stable short-lived web-style traffic |
| `dns-burst` | benign | UDP/DNS-like burst behavior |
| `beacon` | beacon | Stable periodic communication |
| `fade` | fade | Progressive timing/payload degradation |

## Safety boundary

The generator creates packets locally with Scapy and writes PCAP files. It does not execute malware, open sockets to external infrastructure, or provide a real C2 implementation.

## Next engineering step

Connect these PCAP fixtures to the existing ThreatFade ingestion/evaluation path and assert that the `fade` scenario produces the expected behavioral event while the benign scenarios do not.
