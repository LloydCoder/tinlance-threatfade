# ThreatFade Evaluation Corpus Methodology

## Purpose

The ThreatFade evaluation corpus is an evidence artifact for measuring detection behavior. It is not a malware distribution mechanism. Repository metadata records provenance, integrity and evaluation controls; raw malicious payloads remain outside the application repository unless their licensing and handling requirements explicitly permit inclusion.

## Required provenance

Every corpus entry must identify:

- immutable sample ID
- dataset and version
- evaluation split
- source type
- SHA-256 content digest
- content format and size
- acquisition timestamp with timezone
- source reference
- license reference
- detection label and label-confidence level
- applicable ATT&CK techniques
- capture environment and conditions where known
- privacy/restriction status
- chain-of-custody reference when applicable

MITRE ATT&CK identifies network traffic flow as a session-level source containing endpoints, ports, protocols, timestamps and data volume, and network traffic content as PCAP/session content useful for deeper C2 investigation. ThreatFade therefore preserves both flow-level metadata and, where legally permitted, references to full-content evidence rather than assuming every evaluation sample has the same granularity.

## Split policy

The four evaluation partitions are:

1. **development** — detector implementation and exploratory tuning.
2. **tuning** — threshold/calibration selection; never used for final performance claims.
3. **holdout** — final internal evaluation after detector and calibration decisions are frozen.
4. **blind** — externally governed or independently controlled evaluation where the detector owner cannot alter labels or samples during execution.

The same SHA-256 digest may not appear in multiple partitions. A split collision is a hard validation failure because duplicate content can create evaluation leakage.

## Labels

Label confidence is explicit:

- `confirmed` — directly established by controlled provenance or authoritative evidence.
- `high` — strong corroboration with minor uncertainty.
- `medium` — credible but incomplete corroboration.
- `low` — weak/indirect evidence.
- `unknown` — insufficient evidence.

Blind evaluation entries must have a governed confidence value; unknown labels are not silently accepted as truth.

## Source governance

Each source must be reviewed for:

- legal/licensing rights
- privacy and sensitive-data exposure
- acquisition method
- reproducibility
- source reliability
- timestamp and freshness
- expected label quality
- whether the source represents the target environment

ENISA's current threat-landscape methodology emphasizes explicit intelligence requirements, collection requirements, source assessment and continuous evaluation of source accuracy/relevance. ThreatFade applies the same discipline to detection-evaluation corpus construction.

## Integrity

Corpus manifests have a canonical JSON representation and SHA-256 manifest digest. Sample hashes are content identifiers; they are not a substitute for chain-of-custody records or legal provenance.

## No unsupported claims

A corpus manifest does not establish production performance. Real-world validation requires representative, labeled data, controlled evaluation, appropriate confidence intervals, and eventually independent or third-party assessment. Group 10 will add those capabilities incrementally.
