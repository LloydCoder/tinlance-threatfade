# Group 11 — Detection Data Plane & Sensor Architecture

## Purpose

Group 11 establishes the canonical data-plane contract between network/endpoint capture adapters and the existing ThreatFade detection/evidence engine. The design deliberately separates **capture** from **normalization and admission control** so privileged platform-specific collection code cannot redefine the security boundary.

## Architecture

```text
PCAP / live capture / endpoint adapter
                 |
                 v
          SignalEvent v1.0
                 |
        sensor identity check
                 |
        bounded event queue
                 |
       detection / evidence engine
                 |
       tenant-scoped persistence
```

### Canonical event

`core.data_plane.SignalEvent` is immutable and versioned. It supports four observation kinds:

- `packet`
- `flow`
- `session`
- `signal`

Each event contains a sensor identity, tenant identity, observation timestamp, protocol metadata, optional endpoint addressing, bounded counters and bounded metadata. The canonical representation is deterministic and can be hashed with SHA-256 for integrity and evidence correlation.

### Backpressure

`BoundedEventQueue` is intentionally finite. A full queue does not silently allocate memory indefinitely: non-blocking producers receive an explicit failure and the queue records accepted/dropped/depth metrics. Production transports may choose blocking or durable queue implementations later, but the contract remains bounded and observable.

### Sensor lifecycle

Sensors are registered with:

- immutable tenant binding;
- software version;
- SHA-256 fingerprint;
- lifecycle state.

Only `active` sensors can emit. `draining` and `revoked` sensors are rejected. Re-registering an existing sensor to another tenant is rejected, preventing a sensor credential/identity from being rebound across tenant boundaries.

### Reference adapter

`agents.sensor.SensorAdapter` is deliberately transport-agnostic. It accepts normalized observations and places them into the bounded data-plane queue. It does not execute shell commands, open raw sockets, or accept caller-supplied tenant overrides. Platform-specific capture adapters should feed this interface rather than bypass it.

## Security properties

1. **Tenant binding:** the registry is authoritative for sensor tenancy.
2. **Admission control:** inactive/revoked sensors cannot ingest.
3. **Integrity:** canonical event serialization is deterministic and hashable.
4. **Resource safety:** event size, metadata and queue capacity are bounded.
5. **Isolation:** sensor IDs cannot be rebound to a different tenant.
6. **Least privilege:** the reference adapter has no privileged capture side effects.
7. **Observability:** queue acceptance, drops and depth are explicit.

## Deliberate non-claims

This group does not claim that ThreatFade already has a production-grade raw packet capture implementation on every supported OS, a durable distributed queue, a full sensor fleet-control service, or independently measured customer-scale throughput. Those require platform-specific engineering and operational evidence. The purpose of Group 11 is to make those future adapters converge on one secure, testable data-plane contract.

## Verification

The dedicated `group11-data-plane.yml` workflow compiles the new modules, executes the architecture gate and runs the data-plane regression suite. The normal CI/security/supply-chain workflows remain release gates for the final PR.
