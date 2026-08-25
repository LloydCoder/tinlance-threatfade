# ThreatFade Sensor Runtime

## Data path

```text
network interface
  -> platform capture adapter
  -> canonical SignalEvent
  -> bounded durable SQLite queue
  -> detection / transport
  -> evidence / SOC
```

The control plane is not required for local capture. When transport is unavailable, events remain on the sensor until they can be acknowledged by the sender.

## Linux

The reference service runs as `threatfade-sensor` and uses `CAP_NET_RAW` only for packet capture. It does not grant `CAP_NET_ADMIN`, run as root, or enable eBPF by default. eBPF can be introduced later as a separate adapter if a measured workload demonstrates that kernel-side filtering is required. Linux eBPF documentation describes granular capabilities for eBPF operations, including `CAP_BPF` and `CAP_NET_ADMIN` for relevant program classes: https://docs.ebpf.io/linux/ . Keeping the default path on capture sockets avoids adding those privileges unnecessarily.

The service unit applies `NoNewPrivileges`, filesystem protection, namespace restrictions, a dedicated writable state directory and a capability bounding set.

## Windows

Windows capture uses the Npcap architecture: a kernel-level packet filter with `packet.dll` and `wpcap.dll` user-space interfaces. ThreatFade does not introduce a custom packet-capture driver. Npcap architecture reference: https://npcap.com/guide/npcap-internals.html .

## Queue contract

The durable queue is bounded by:

- maximum event count
- maximum serialized bytes
- retention period
- FIFO sequence numbers
- idempotent event IDs

Expired records may be removed during pressure cleanup. Unexpired evidence is never silently evicted; if the configured bound is exhausted, enqueue returns `False` and the sensor exposes the rejection through health metrics.

## Identity lifecycle

Sensor identity is `(sensor_id, tenant_id, fingerprint)`. A sensor must be active before it can emit into the data plane. Cross-tenant events are rejected. Revoked sensors cannot ingest. Fingerprint rotation requires re-registration under the same tenant followed by activation.

The local CLI bootstrap is an explicit deployment mechanism, not an enterprise PKI replacement. Production enrollment should be bound to an authenticated control-plane enrollment service or device identity system.

## Benchmarking

Run:

```bash
python benchmarks/sensor_runtime.py --events 10000
```

Record the output together with host CPU, RAM, NIC, OS, Python version, packet source and test duration. The benchmark measures event construction and durable enqueue; it does **not** measure NIC line rate or packet loss. A real capture benchmark must be run on the deployment hardware using the platform capture backend.

## Evidence boundary

A working adapter is implementation evidence. Repository tests validate deterministic event construction, queue bounds, offline replay, tenant isolation and lifecycle transitions. They do not constitute field validation of packet loss, sustained throughput, kernel behavior or Windows driver installation.
