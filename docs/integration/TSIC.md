# TSIC integration

ThreatFade is the Tinlance security-engineering/threat-detection component.

- **TSIC** owns ecosystem integration and certification.
- **ThreatFade** owns threat-detection and response-domain semantics.
- **FAS** owns evidence-first forensic analysis.
- **Agent Platform** owns governed consequential execution.

A detection, finding or response recommendation is never itself execution authorization. Tenant context, evidence/provenance, trace and economic-attribution references must remain attached across the boundary.

## Conformance

`scripts/tsic_conformance.py` consumes the immutable TSIC-31 adapter revision and verifies the canonical contracts and authority invariants.

Run:

```bash
python scripts/tsic_conformance.py
```

Passing this gate certifies the reviewed contract surface, not an active production incident-response deployment.
