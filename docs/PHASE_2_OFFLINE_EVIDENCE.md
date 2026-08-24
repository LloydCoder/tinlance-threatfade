# ThreatFade Phase 2 — Resilient Transport and Offline Evidence

## Scope

Phase 2 adds a bounded store-and-forward layer after the Group 11 canonical `SignalEvent` contract. Sensors continue collecting and normalizing events when the control plane is unavailable. Transport is best-effort and never owns capture.

`capture → SignalEvent → durable bounded queue → signed batch → transmission → server verification → idempotent ingestion`

The design follows secure key-management principles from NIST SP 800-57 and uses Ed25519 signatures for compact local signing. Sigstore's bundle model also informed the separation of signed content from verification material and the requirement that offline verification have sufficient verification metadata. citeturn0search11turn0search1

## Queue policy

Default limits are deliberately bounded:

- maximum queue size: **512 MiB**
- maximum event count: **100,000**
- retention: **7 days**
- maximum canonical event: **256 KiB**
- batch limit: **256 events** / **512 KiB**
- critical priority: `100`
- ordinary priority range: `0–99`

When capacity is exhausted, eviction is oldest/lowest-priority first. Priority 100 records are retained until the queue cannot accept another record, at which point ingestion fails explicitly rather than silently losing critical evidence. Group 11's in-memory bounded queue remains unchanged and is still the immediate backpressure boundary.

## Replay and ordering

Every queued event receives a monotonic sensor-local sequence number. A batch contains `batch_id`, tenant, sensor, first sequence, last sequence, count and canonical event payloads. The receiver persists batch IDs and per-tenant/per-sensor cursors in a durable replay ledger.

- duplicate batch ID → idempotent `duplicate`
- sequence entirely behind cursor → `replay`
- sequence gap → `gap` (operator recovery required; not silently accepted)
- valid next range → `accepted`

Events are never reordered inside a batch. Cross-batch ordering is based on the sensor sequence, not wall-clock time.

## Bandwidth awareness

The transmitter uses a bounded token budget and maximum batch size. It selects complete records only and consumes no queue state until the caller receives a successful transport acknowledgement. Network failure therefore leaves the durable queue intact.

## Evidence Package v1

Media type: `application/vnd.threatfade.evidence+zip`

Required members:

- `manifest.json`
- `events.json`
- `evidence.json`
- `provenance.json`
- `signing-key.json`

Manifest fields include:

- media/protocol/schema version
- tenant and sensor identity
- event count
- ordered event SHA-256 digests
- evidence SHA-256 digests
- provenance
- signing key ID and algorithm
- signature
- manifest digest
- creation timestamp

The package uses canonical JSON (`sort_keys`, compact separators, UTF-8) for signed material. ZIP member timestamps are fixed for reproducible packaging metadata. The signature covers the canonical manifest before signature fields are added; verification reconstructs exactly that signed form and then validates event/evidence hashes.

## Signing lifecycle

Phase 2 uses Ed25519. Each key has:

- stable key ID derived from its public key
- creation time
- `not_before`
- `not_after`
- explicit revocation timestamp

`SigningTrustStore` persists trusted public keys and revocation state. Rotation is additive: a new key is trusted before the old key is revoked, allowing controlled overlap. Revoked or expired keys fail closed.

This is an application-level evidence-signing protocol, not a replacement for an organization's PKI, HSM, certificate authority or classified-key infrastructure.

## Clock handling

Wall-clock timestamps are evidence attributes, not replay authorities. Sequence numbers provide ordering. Signature validity uses the verifier's supplied verification time. Significant clock disagreement must be surfaced operationally; it does not cause sequence numbers to be rewritten.

## Failure handling

| Failure | Required behavior |
|---|---|
| control plane unavailable | keep capturing and queue durably |
| intermittent network | retry without deleting queued records |
| disk pressure | bounded priority-aware eviction; explicit exhaustion |
| corrupted package | reject before ingestion |
| modified package | signature/hash verification failure |
| replay | reject as `replay` |
| duplicate | idempotent `duplicate` |
| reordered batch | reject sequence metadata |
| revoked key | reject |
| expired key | reject |
| tenant mismatch | reject |
| malformed payload | reject |

## Air-gapped verification

`verify_evidence_package()` requires only the package and an out-of-band trusted public-key set. It does not contact the control plane, Rekor, DNS, a remote timestamp service or any other network service. This is intentional: Sigstore's current bundle model likewise documents offline verification support when the bundle carries sufficient verification material. citeturn0search0turn0search1

## Security boundary

Correlation, evidence and transport are separate concerns. A valid signature proves possession of the signing key over the signed bytes; it does **not** prove that the sensor was truthful, that an observation was malicious, or that two events were causally related.

## Production status

The protocol is implemented and covered by automated hostile-condition tests. It should be described as **implemented; production deployment validation pending** until a real deployment exercises disk exhaustion, prolonged outage, recovery, key rotation/revocation and air-gapped transfer against the target operating environment.
