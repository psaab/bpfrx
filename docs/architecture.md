# xpf architecture

xpf is a Junos-style stateful firewall that replicates Juniper vSRX
capabilities. It has two halves:

- A **Go control plane** (`xpfd`) that compiles Junos configuration,
  manages sessions, drives HA, programs routing, and serves the CLI and
  APIs.
- A **Rust AF_XDP userspace dataplane** (`xpf-userspace-dp`) that is the
  only runtime packet-forwarding path.

## Dataplane: the runtime forwarding path

> Dataplane notice (#1373, complete): the eBPF dataplane retirement is
> done. The Rust AF_XDP userspace dataplane is the only runtime
> forwarding path. Explicit `system dataplane-type ebpf` is hard-rejected
> at commit (`ErrEBPFDataplaneRetired`) and at runtime
> (`ErrEBPFBackendRetired`); use `set system dataplane-type userspace`, or
> omit the knob for the default. The legacy BPF source (`bpf/xdp/*.c`,
> `bpf/tc/*.c`) was deleted in #1476; the only retained eBPF artifacts are
> the userspace XDP shim (`userspace-xdp/`) and the shared
> `bpf/headers/*.h` map/struct bootstrap.

A Rust forwarding engine receives packets via AF_XDP sockets and
processes them in userspace. A Rust XDP shim stamps metadata, redirects
transit traffic into AF_XDP, and hands proven local/control traffic back
to the kernel. If helper/XSK forwarding is degraded, non-local transit
fails closed in both compat and strict modes instead of bypassing
policy, NAT, or conntrack.

```
NIC → XDP shim (redirect transit, pass local/control, drop degraded transit)
    → AF_XDP socket
    → Rust worker thread (session → policy → NAT → FIB → TX)
    → AF_XDP TX ring → NIC
```

- **Per-worker architecture**: one worker per queue shard, with
  session/NAT/policy/FIB handled in Rust.
- **AF_XDP fast path**: supports both copy and zero-copy modes depending
  on driver/path behavior.
- **Kernel pass-through**: cpumap-assisted delivery keeps local/kernel-owned
  traffic out of the AF_XDP fast path.
- **Fail-closed admission**: unsupported userspace configs are gated or
  fail closed rather than bypassing policy, NAT, or conntrack.
- **Degraded mode**: when helper/XSK forwarding is unavailable, the shim
  keeps non-local transit out of the kernel forwarding path, passes only
  proven local/control traffic, and drops degraded transit.

The parser still *accepts* the `ebpf` token so that
`load merge`/`load override` of a pre-retirement config does not
syntax-error during a rolling upgrade — but `commit check` then fails
with the retirement error, and the remediation is
`set system dataplane-type userspace`. If a persisted config still names
`ebpf` on startup, the daemon runs in config-only mode until the operator
updates it.

To tune the userspace dataplane:

```junos
system {
    dataplane {
        binary /usr/local/sbin/xpf-userspace-dp;
        workers 6;
        ring-entries 8192;
    }
}
```

See [`userspace-dataplane-architecture.md`](userspace-dataplane-architecture.md)
for the full architecture and [`userspace-debug-map.md`](userspace-debug-map.md)
for the active debugging map. The current admission boundary is tracked
in [`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

### Historical note: the retired eBPF dataplane

The original dataplane ran in-kernel using 14 BPF programs chained via
tail calls (XDP ingress `main → screen → zone → conntrack → policy →
nat → nat64 → forward`; TC egress `main → screen_egress → conntrack →
nat → forward`) and reached 25+ Gbps on native XDP (mlx5, i40e, ice).
That source (`bpf/xdp/*.c`, `bpf/tc/*.c`) was deleted in #1476; the
pipeline is preserved only in git history (`git log -- bpf/xdp/ bpf/tc/`).
It is no longer a selectable backend.

> DPDK dataplane retired in #1525. Do not add new DPDK code. The
> `dpdk_worker/` C tree and `pkg/dataplane/dpdk/` Go manager were removed
> in #1527/#1528.

## Key design patterns

- **Go control plane** handles config compilation, session GC, management
  APIs, HA cluster, and routing.
- **Rust AF_XDP userspace dataplane** owns the only packet-forwarding path.
- **Retained eBPF surface** is the userspace XDP shim (`userspace-xdp/`)
  plus the shared `bpf/headers/*.h` map/struct bootstrap — not a
  forwarding backend.
- **Userspace AF_XDP shim** (`userspace-xdp/src/lib.rs`): per-CPU binding
  arrays steer packets from native XDP to userspace queues.
- **Dual session entries** (forward + reverse) in the shared conntrack
  hash map back HA session-sync.
- **Three-phase config compilation**: Junos AST → typed Go structs →
  userspace-dp control messages (no eBPF map writes after #1476).
- **FRR-managed routing**: all routes (static, DHCP, per-VRF) live in a
  managed section in `/etc/frr/frr.conf`.
- **Full interface management**: xpfd owns ALL interfaces on the firewall
  — renames them via `.link` files, configures addresses/DHCP via
  `.network` files, and brings down unconfigured interfaces.

## Command trees (two-SSOT split, #1319)

`pkg/cmdtree/tree.go` is the single source of truth for the
**operational** tree (`run`/`show`/`clear`/`request`/…): tab completion
and `?` help across local CLI, remote CLI, and gRPC. The **config-mode
`set`/`delete`/`show`/`edit` grammar** (structural completion, flat-set
token grouping, value-slot `?` completion, and commit-check typed-leaf
validation) is owned by `config.setSchema` in `pkg/config/schema.go`
(completion helpers in `pkg/config/schema_complete.go`) plus
`config.SchemaValidate` in `pkg/config/schema_walk.go` — NOT cmdtree.
Add a config-mode typed leaf by editing `setSchema` (see
[`config-schema.md`](config-schema.md)); add an operational command by
editing cmdtree.

## APIs

- **gRPC** on `127.0.0.1:50051` — 48+ RPCs (config, sessions, stats,
  routes, IPsec, DHCP, cluster).
- **HTTP REST** on `127.0.0.1:8080` — health, Prometheus `/metrics`,
  config endpoints, full gRPC parity.
- **CLI** — interactive Junos-style with tab completion, `?` help, pipe
  filters (`| match`, `| count`, `| except`).
- **Remote CLI** — the `cli` binary connects via gRPC with full tab/`?`
  parity.

## Code layout

| Path | Description |
|------|-------------|
| `bpf/headers/*.h` | Shared C structs/constants consumed by the retained Rust AF_XDP shim build and userspace-dp parity tests. The legacy `bpf/xdp/*.c` and `bpf/tc/*.c` source were deleted in #1476 |
| `pkg/config/` | Junos parser, AST, typed config, compiler |
| `pkg/cmdtree/` | Single source of truth for the operational CLI command tree |
| `pkg/configstore/` | Candidate/active/commit/rollback, atomic DB persistence, JSONL audit journal |
| `pkg/dataplane/` | Runtime contracts, retained userspace shim embed/loader, eBPF/DPDK retirement-error sentinels (#1476/#1525) |
| `pkg/dataplane/userspace/` | Go manager for the Rust userspace dataplane |
| `userspace-xdp/` | Retained Rust XDP shim that redirects packets into the AF_XDP userspace runtime |
| `userspace-dp/` | Rust AF_XDP userspace dataplane binary |
| `pkg/daemon/` | Daemon lifecycle, reconciliation, interface management |
| `pkg/cluster/` | Chassis cluster HA (state machine, session sync, config sync, IPsec SA sync) |
| `pkg/vrrp/` | Native VRRPv3 state machine (30ms RETH advertisements) |
| `pkg/ra/` | Embedded RA sender (replaces radvd) |
| `pkg/cli/` | Interactive Junos-style CLI |
| `pkg/conntrack/` | Session garbage collection (with HA delete sync) |
| `pkg/logging/` | Ring buffer reader, event buffer, syslog client |
| `pkg/dhcp/` | DHCPv4/DHCPv6 clients |
| `pkg/frr/` | FRR config generation + managed section in frr.conf |
| `pkg/networkd/` | systemd-networkd .link/.network file generation |
| `pkg/routing/` | GRE tunnels, VRFs, XFRM interfaces, rib-group + next-table route leaking |
| `pkg/ipsec/` | strongSwan config + SA queries |
| `pkg/api/` | HTTP REST API + Prometheus collector |
| `pkg/grpcapi/` | gRPC server + protobuf bindings |
| `pkg/flowexport/` | NetFlow v9 exporter |
| `pkg/feeds/` | Dynamic address feed fetcher |
| `pkg/dhcpserver/` | Kea DHCP server management |
| `pkg/dhcprelay/` | DHCP relay with Option 82 |
| `pkg/eventengine/` | Event-driven automation engine |
| `pkg/rpm/` | RPM probe manager |
| `pkg/snmp/` | SNMP agent (system + ifTable MIB) |
| `pkg/lldp/` | LLDP protocol |
| `proto/xpf/v1/` | Protobuf service definition |
| `cmd/xpfd/` | Daemon main binary |
| `cmd/cli/` | Remote CLI client binary |
| `docs/` | Protocol docs, design notes, test plans, feature gaps |
| `test/incus/` | Test environment scripts and configs |

## See also

- [`engineering-style.md`](engineering-style.md) — coding/review
  discipline and hot-path allocation rules.
- [`critical-patterns.md`](critical-patterns.md) — the project-specific
  gotchas (byte order, struct alignment, BPF verifier, SR-IOV/XDP,
  interface management) that repeatedly bite.
- [`network-topology.md`](network-topology.md) — test-VM and HA-cluster
  interface maps.
- [`feature-coverage.md`](feature-coverage.md) — the full feature matrix.
