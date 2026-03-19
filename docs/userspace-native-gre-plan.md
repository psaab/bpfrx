# Native GRE In The Userspace Dataplane

## Goal

Move GRE and `ip6gre` transit traffic fully onto the Rust userspace dataplane on
the physical NIC path.

That means:

- decapsulate GRE on the physical WAN AF_XDP ingress path
- run policy, session, NAT, and forwarding on the inner packet in Rust
- encapsulate GRE on the physical WAN AF_XDP egress path
- stop depending on `gr-0-0-0` for transit forwarding

The current `gr-0-0-0` netdevice path may still exist temporarily for host-only
traffic or migration safety, but it must not be the transit dataplane path.

## Status

Implemented on the native GRE branch:

- logical tunnel endpoint snapshots and route resolution
- native GRE decapsulation on physical NIC ingress
- native GRE encapsulation on physical NIC egress
- tunnel-aware session sync so synced userspace sessions preserve tunnel context
- ingress PBR steering into tunnel routing-instances
- tunnel-zone visibility preserved for policy evaluation
- userspace XDP now keeps outer GRE on the physical NIC path when native GRE is enabled
- tunnel netdevices are no longer userspace ingress interfaces for transit
- live isolated-cluster GRE transit validation now passes:
  - `cluster-userspace-host -> 10.255.192.41` ping succeeds
  - outer GRE packets move on `ge-*-0-2.80`
  - `gr-0-0-0` transit RX/TX deltas stay at zero

Validated on the native GRE branch:

- clean post-deploy isolated-cluster validation after primaries re-elect
- transit TCP connect from `cluster-userspace-host` to `10.255.192.41:22` works
- transit `iperf3 -c 10.255.192.41` stays up without zero-throughput intervals
- active GRE failover from `node1 -> node0` now recovers and passes the native
  GRE validator tail gate
- active GRE failover from `node0 -> node1` now recovers and passes the native
  GRE validator tail gate
- manual `request chassis cluster failover redundancy-group 1 node ...` keeps
  the single-stream `iperf3` flow alive in both directions with no
  zero-throughput intervals
- clean bidirectional failover validation on the isolated userspace cluster:
  - `PREFERRED_ACTIVE_NODE=0 ... --deploy --failover --count 3`: pass
  - `PREFERRED_ACTIVE_NODE=1 ... --failover --count 3`: pass

Still required for full migration parity:

- a separate local-origin tunnel handoff if firewall-originated GRE traffic must
  keep working without a kernel GRE device
- final cleanup of remaining hybrid tunnel assumptions outside transit forwarding
- clean post-failover validation of the new UDP and traceroute checks
  (TCP iperf failover passes per above, but the new GRE-specific probes
  have not yet been run through the full failover cycle)

Current blocker:

- local firewall-originated traffic to tunnel destinations is no longer part of
  the default transit gate once `gr-0-0-0` is replaced by a dummy anchor
- the new UDP burst and traceroute checks have not been validated through
  the full RG1 failover cycle yet (the TCP iperf failover works, but the
  broader native GRE validation script hit an unrelated TCP tail-connect
  regression that prevented a clean end-to-end run of ALL probes together)
- a broader simultaneous multi-RG move is still stricter than the exact RG1
  manual failover case and remains a separate follow-up if we want that covered

## Why This Is Necessary

The current tunnel path is hybrid:

- userspace owns Ethernet AF_XDP ingress/egress
- Linux tunnel devices do GRE decap/encap
- legacy XDP/TC/kernel glue handles tunnel exceptions and return traffic

That hybrid split is the source of the current failure mode:

- outer GRE reply reaches the WAN NIC
- decapsulated inner packet appears on `gr-0-0-0`
- the return packet does not reliably re-enter the intended BPF/userspace
  reverse-NAT path

As long as transit depends on Linux tunnel devices:

- tunnel decap timing is kernel-owned
- tunnel ingress hooks are split across XDP, TC, and kernel routing
- reverse-path bugs remain hard to reason about

Native GRE in userspace removes that split.

## Non-Goals

- ESP/XFRM in pure userspace
- replacing Linux routing for control-plane protocols
- deleting tunnel config syntax from the control plane

This is only about plaintext GRE/ip6gre dataplane transit.

## Current Baseline

Today the code explicitly treats tunnels as non-userspace transit:

- [manager.go](../pkg/dataplane/userspace/manager.go)
  says tunnel interfaces are handled by the eBPF pipeline
- [afxdp.rs](../userspace-dp/src/afxdp.rs)
  forces tunnel egress to slow-path so the kernel handles encapsulation
- [tc_main.c](../bpf/tc/tc_main.c)
  bypasses tunnel egress because kernel tunnel encapsulation happens after TC

So the required work is architectural, not a small bugfix.

## Target Architecture

### 1. Replace Tunnel Netdevices With Logical Tunnel Endpoints

Do not model GRE transit as “forward to Linux interface `gr-0-0-0`”.

Instead model GRE as a logical egress object in the userspace forwarding state:

- `TunnelEndpointId`
- outer family: IPv4 or IPv6
- outer source and destination addresses
- GRE key / checksum / sequence options if configured
- inner routing-instance / zone binding
- tunnel MTU / effective payload MTU
- outer egress resolution policy

Routes should point to a logical tunnel endpoint, not a kernel tunnel ifindex.

### 2. Ingress Decapsulation On Physical NICs

On AF_XDP ingress for physical WAN bindings:

1. parse outer Ethernet
2. parse outer IPv4 or IPv6
3. detect GRE protocol
4. parse GRE header and optional key
5. validate tunnel endpoint match
6. strip outer headers in userspace
7. produce an inner packet plus tunnel metadata
8. continue through the normal userspace session/policy/NAT path

The decapsulated packet should carry metadata like:

- `ingress_tunnel_id`
- `outer_src_ip`
- `outer_dst_ip`
- `gre_key`
- `tunnel_zone`
- `tunnel_routing_table`
- `meta_flags |= META_FLAG_TUNNEL`

The inner packet should never need to appear on `gr-0-0-0` for transit.

### 3. Egress Encapsulation On Physical NICs

When the forwarding resolution selects a tunnel endpoint:

1. perform policy/session/NAT on the inner packet first
2. compute outer route using the configured outer transport routing-instance
3. resolve outer next-hop MAC on the physical egress interface
4. prepend outer IPv4/IPv6 + GRE header in Rust
5. transmit the final encapsulated packet through the physical NIC AF_XDP TX path

This replaces the current “mark as `MissingNeighbor` and hand to kernel
slow-path because tunnel AF_XDP TX does not exist”.

### 4. Session Model

Sessions must represent both:

- inner flow identity
- tunnel transport context

For GRE transit, the session key should remain the inner flow key.
The tunnel should be part of the forwarding metadata, not the primary session key.

Recommended session additions:

- `tunnel_endpoint_id`
- `tunnel_ingress`
- `tunnel_egress`
- `outer_routing_table`
- `outer_ifindex`
- `outer_vlan_id`
- `outer_neighbor_mac`
- `gre_key` when configured

That lets a reply flow continue without recomputing tunnel selection from scratch.

### 5. NAT Semantics

NAT remains an inner-packet decision.

Correct order:

1. decapsulate outer GRE
2. parse inner flow
3. apply session hit / reverse-NAT / policy / NAT
4. route inner packet
5. if next-hop is a tunnel, encapsulate the rewritten inner packet

Do not NAT the outer GRE transport headers except where explicitly configured
by transport policy. The normal case is inner-packet NAT only.

### 6. HA / Fabric Semantics

Tunnel endpoint ownership must be explicit in userspace state.

Required behavior:

- if the logical tunnel endpoint belongs to an inactive RG on this node,
  fabric-redirect before encapsulation
- synced sessions must carry tunnel endpoint metadata, not only plain egress
  ifindex/NAT fields
- failover pickup must preserve tunnel egress information so the new owner can
  encapsulate immediately

Without that, the same HA parity gap reappears in another form.

## Policy-Based Routing Without A Tunnel Netdevice

This is the most important control-plane question.

The right answer is:

- PBR should target a routing table / logical next-hop selection
- not a kernel tunnel interface

### Recommended Model

Keep PBR exactly as an inner-packet routing decision.

Example:

- firewall filter says `then routing-instance sfmix`
- userspace sets `routing_table = sfmix.inet.0`
- inner FIB lookup in the userspace forwarding state uses that table
- the resulting next-hop is a `TunnelEndpointId`, not `gr-0-0-0`

So PBR still works, but the route result becomes:

- `ForwardPhysical(ifindex, neigh, vlan)`
- or `ForwardTunnel(tunnel_endpoint_id)`

instead of:

- `ForwardKernelTunnel(ifindex=gr-0-0-0)`

### Why This Is Better

It keeps policy semantics unchanged:

- filters still choose routing-instance
- routing-instances still choose routing tables
- routes still resolve next-hops

But the dataplane object on the result side is now native userspace instead of a
Linux netdevice.

## Should We Use Dummy Interfaces?

Dummy interfaces are acceptable only as control-plane anchors.

They are not the right dataplane object for tunnel transit.

### Good Uses For Dummy Interfaces

1. address ownership anchors
- hold tunnel local addresses if Linux services need them

2. host-originated traffic anchors
- give the host stack a place to bind/source addresses for local tools,
  keepalives, or diagnostics

3. VRF membership anchors
- keep Linux routing-instance structure sane for non-dataplane consumers

### Bad Uses For Dummy Interfaces

1. transit forwarding target
- that just recreates the kernel path under a different name

2. PBR egress object
- PBR should resolve to a logical tunnel endpoint, not a dummy ifindex

3. reverse-path dataplane dependency
- if reverse-NAT correctness depends on the dummy interface, the design is still
  hybrid and still fragile

### Recommended Compromise

Use a dummy interface only if Linux needs an address anchor.

Example:

- `du-sfmix0` in `vrf-sfmix`
- owns `10.255.192.42/30`
- never carries transit packets

Transit uses native userspace GRE on the physical WAN NICs.

That gives:

- stable local addresses for host tools
- no kernel tunnel device in the transit dataplane

## Required Code Changes

### Compiler / Snapshot / Protocol

Add native tunnel objects to the userspace snapshot:

- `TunnelEndpointSnapshot`
- inner zone binding
- outer transport routing-instance
- outer local/remote addresses
- GRE options
- payload MTU

Update:

- [pkg/dataplane/userspace/protocol.go](../pkg/dataplane/userspace/protocol.go)
- [pkg/dataplane/userspace/manager.go](../pkg/dataplane/userspace/manager.go)
- compiler route emission so route next-hops can point to logical tunnel IDs

### Rust Forwarding State

Add:

- tunnel endpoint table
- inner-table route entries whose next-hop is a tunnel endpoint
- outer route resolution cache
- GRE encap/decap helpers

Primary files:

- [userspace-dp/src/afxdp.rs](../userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/frame.rs](../userspace-dp/src/afxdp/frame.rs)
- likely a new [userspace-dp/src/afxdp/gre.rs](../userspace-dp/src/afxdp/gre.rs)

### Session Sync

Extend cluster sync for tunnel-aware sessions:

- tunnel endpoint ID
- outer route metadata
- GRE key if used
- transport egress metadata

Files:

- [pkg/daemon/daemon.go](../pkg/daemon/daemon.go)
- [pkg/dataplane/userspace/manager.go](../pkg/dataplane/userspace/manager.go)
- [userspace-dp/src/main.rs](../userspace-dp/src/main.rs)

### Slow-Path Reduction

After native GRE lands, remove tunnel transit dependence on:

- `MissingNeighbor` tunnel egress coercion
- `gr-0-0-0` transit path
- tunnel TC egress bypass as the primary encapsulation path

Kernel slow-path should remain only for:

- host-originated traffic if still needed
- control-plane exceptions
- migration fallback

## Migration Plan

### Phase 0: Design Lock

- define `TunnelEndpointId`
- define route result types
- decide whether dummy anchor interfaces are needed for host-originated traffic

### Phase 1: Read-Only Native Ingress Parser

- parse outer GRE on physical NIC ingress
- identify matching tunnel endpoint
- count / trace only
- do not change forwarding yet

Exit criteria:

- counters show the same GRE traffic now seen on `gr-0-0-0`

### Phase 2: Native Decap + Inner Pipeline

- decapsulate and process inner packet in userspace
- still use kernel path for tunnel egress

Exit criteria:

- tunnel return traffic like `10.255.192.41 -> 10.255.192.42` is reverse-NATed
  correctly back to LAN clients

### Phase 3: Native GRE Egress

- encapsulate in Rust
- transmit outer packet on physical WAN AF_XDP TX
- stop using `gr-0-0-0` for transit egress

Exit criteria:

- `lan -> sfmix` forward path no longer depends on kernel tunnel TX

### Phase 4: Remove Tunnel Netdevice From Transit Path

- keep `gr-0-0-0` only for host/control-plane if still needed
- transit counters on `gr-0-0-0` must stay at zero

Exit criteria:

- tunnel transit works with `gr-0-0-0` administratively present but dataplane-idle

### Phase 5: PBR / HA / Stress Validation

- routing-instance based tunnel selection
- failover/failback under load
- mixed IPv4/IPv6 tunnel traffic
- ICMP, TCP, UDP, traceroute, iperf, failover tests

Current state:

- PBR-based tunnel selection: done
- isolated-cluster ICMP transit + dataplane-idle `gr-0-0-0`: done
- isolated-cluster TCP connect transit/failover validation: done
- isolated-cluster `iperf3` transit/failover validation: done for single-stream
  TCP over GRE with manual RG1 failover
- failover/failback validation for transit traffic: done on the isolated
  userspace cluster
- isolated-cluster UDP burst transit validation: done in steady state on the
  active native GRE path, with the logical tunnel anchor kept dataplane-idle
- isolated-cluster traceroute/mtr transit validation: done in steady state on
  the active native GRE path, with the logical tunnel anchor kept dataplane-idle
- remaining work: local-origin tunnel handoff if host-generated GRE traffic
  must remain supported, plus a clean post-failover run of the new UDP and
  traceroute gates once the existing `node0 -> node1` TCP failover regression is
  fixed

## Validation Plan

Minimum validation matrix:

1. `lan -> sfmix` ICMP over GRE
2. `lan -> sfmix` TCP and UDP over GRE
3. reverse-NAT on tunnel replies
4. PBR selecting tunnel routing-instance
5. failover/failback with active tunnel sessions
6. traceroute / ICMP TE through tunnel path
7. host-originated traffic if dummy anchors are kept

Specific acceptance checks:

- no transit packets on `gr-0-0-0`
- GRE transit counters move on the physical WAN binding only
- reverse session hit counters increase on tunnel replies
- no `vrf-sfmix` local `ICMP host unreachable` for valid tunnel replies
- HA failover keeps tunnel sessions alive

Scripted gate:

- [`scripts/userspace-native-gre-validation.sh`](../scripts/userspace-native-gre-validation.sh)
  validates GRE transit reachability and asserts that the physical WAN device
  moves GRE packets while `gr-0-0-0` stays dataplane-idle

## Recommendation

If the goal is truly “userspace dataplane owns GRE”, then the project should:

1. stop investing in tunnel-netdevice transit fixes
2. keep only enough hybrid behavior to avoid regressions during migration
3. implement native GRE as a physical-NIC userspace feature
4. treat dummy interfaces as optional address anchors, not dataplane objects

That is the clean architecture.
