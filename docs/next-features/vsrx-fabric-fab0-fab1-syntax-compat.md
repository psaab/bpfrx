# vSRX HA Fabric Syntax Compatibility (`fab0` + `fab1`)

## Problem

`vsrx.conf` defines two fabric interfaces:

- `interfaces fab0 { fabric-options { member-interfaces { ge-0/0/7; } } }`
- `interfaces fab1 { fabric-options { member-interfaces { ge-7/0/7; } } }`

The current bpfrx HA architecture is still single-fabric in core transport/data-plane wiring, so syntax compatibility is partial.

## Current Gaps (Code-Level)

- Cluster config model is single-fabric:
  - `pkg/config/types.go` has `FabricInterface string` and `FabricPeerAddress string`.
- Chassis compiler only reads one fabric interface/peer:
  - `pkg/config/compiler.go` reads one `fabric-interface` and one `fabric-peer-address`.
- Runtime HA comms is single endpoint:
  - `pkg/daemon/daemon.go` starts session sync/gRPC fabric listener/fabric_fwd from one `cc.FabricInterface`.
  - `clusterTransportKey` tracks only one fabric interface/peer tuple.
- Cluster CLI display model is single-fabric:
  - `pkg/cluster/cluster.go` `InterfacesInput` has `FabricInterface string`.
  - `pkg/cli/cli.go` and `pkg/grpcapi/server.go` populate a single fabric field.
- eBPF fabric forwarding state is single-entry:
  - `bpf/headers/bpfrx_maps.h` `fabric_fwd` map has `max_entries = 1`.
- DPDK parity is single-fabric:
  - `dpdk_worker/shared_mem.h` has one `fabric_port_id`.
  - `pkg/dataplane/dpdk/dpdk_cgo.go` updates a single `fabric_port_id`.
- Bond behavior is inconsistent:
  - networkd generation uses `active-backup` in `pkg/dataplane/compiler.go`.
  - netlink runtime bond creation uses `802.3ad` in `pkg/routing/routing.go`.

## Architectural Changes Required

### 1) Config/Data Model

- Introduce multi-fabric cluster transport model (list of links), not single string fields.
- Keep legacy `fabric-interface`/`fabric-peer-address` as backward-compatible shorthand that maps to one link.
- Parse/compile `fab0` and `fab1` as first-class cluster fabric links.

### 2) HA Transport Manager

- Replace single `SessionSync(local, peer)` wiring with a fabric transport manager that:
  - tracks both links (`fab0`, `fab1`),
  - selects active link by health,
  - fails over sync/config-channel transport between links without restarting cluster state.
- Track per-link health/counters and expose active link state.

### 3) Dataplane Fabric Forwarding

- Replace single `fabric_fwd` state with multi-link state:
  - eBPF map keyed per fabric link (or keyed by ifindex),
  - anti-loop validation accepts known fabric ingress set, not one ifindex.
- DPDK shared memory should hold multiple fabric ports (array/bitmap), not one `fabric_port_id`.

### 4) CLI/Operational Parity

- Update `show chassis cluster interfaces` to display both `fab0` and `fab1` rows with child interfaces.
- Show active/standby fabric transport and per-link health.

### 5) Bond Semantics

- Standardize fabric bond mode for HA semantics (active-backup default unless explicitly configured otherwise).
- Make networkd and netlink runtime bond mode consistent.

### 6) Validation and Migration

- Add validation:
  - if `fab0`/`fab1` are configured, require usable member-interface mapping for this node.
  - reject ambiguous multi-link configs that still rely on single-link-only fields without explicit mapping.
- Migration behavior:
  - single-link legacy config keeps working unchanged,
  - dual-link syntax auto-enables multi-fabric transport path.

## Acceptance Criteria

- A `vsrx.conf`-style HA config with both `fab0` and `fab1` parses and compiles without custom-only transport fields.
- Session/config sync survives loss of one fabric link with no cluster split.
- `show chassis cluster interfaces` shows both fabric links and correct link status.
- eBPF and DPDK both validate/redirect using either fabric link.
