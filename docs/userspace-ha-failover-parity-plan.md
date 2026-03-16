# Userspace HA Failover Parity Plan

Date: 2026-03-16

This document tracks the remaining work to make the Rust AF_XDP userspace
dataplane preserve established TCP flows across manual redundancy-group
failover with the same reliability as the legacy eBPF dataplane.

The concrete failing case is:

```bash
iperf3 -c 172.16.80.200 -P 4 -t 60
request chassis cluster failover redundancy-group 1 node <peer>
```

Current status:

- the original userspace failover collapse is fixed in the local working tree
- exact repro now survives:
  - `iperf3 -c 172.16.80.200 -P 4 -t 60`
  - `request chassis cluster failover redundancy-group 1 node 1`
- latest manual validation result:
  - `0` zero-throughput `SUM` intervals after failover
  - final 60s sender rate: `15.8 Gbps`
- remaining work is now parity hardening and stress coverage, not first-fix
  bring-up

This is not a generic whole-node reboot problem. It is an active/active per-RG
handoff problem where existing flows must survive a WAN RG ownership move.

## Reference Behavior From The Legacy eBPF Dataplane

The pre-userspace dataplane already solved this class of failure.

Relevant reference points:

1. [test-failover.sh](../test/incus/test-failover.sh)
2. [test-stress-failover.sh](../test/incus/test-stress-failover.sh)
3. [test-double-failover.sh](../test/incus/test-double-failover.sh)
4. `3e7491a` `Fix TCP stream death during rapid active/active failovers`
5. `12ac482` `Fix mtr/traceroute on cluster secondary via fabric redirect`

The legacy dataplane already has:

1. hardened `rg_active` transition ordering
2. working fabric redirect for existing sessions that land on the wrong owner
3. direct conntrack/session-sync pickup on the peer
4. failover survivability tests that prove `iperf3` stays alive

## Userspace State On Current `master`

Important userspace HA work already landed:

1. `de88a92` `userspace: bridge session deltas into session sync`
2. `fd8a55f` `fix: publish synced sessions to BPF map for XDP shim fast-path`
3. `e5ee39c` `fix: add XSK bindings on fabric interface for HA fabric redirect`
4. `339ea27` `fix: enable userspace dataplane by fixing BPF map delete race and XSK diagnostics`

So the current problem is not “userspace has no HA/session plumbing”.
The current problem is failover-grade parity and failover-grade validation.

## Root Cause And Fixes Landed

Two concrete failover bugs were identified and fixed in the userspace path:

### 1. Fabric Redirect State Was Incomplete At Runtime

The userspace snapshot carried fabric topology, but the Rust runtime fabric
state depended on the fabric parent interface being present in
`snapshot.interfaces` so it could recover the local MAC. On the HA lab that
assumption was false for the fabric parent.

Effect:

1. the old owner classified post-failover packets as plain `HAInactive`
2. no fabric TX happened on the old owner
3. traffic died immediately after the RG move

Fix:

1. extend `FabricSnapshot` with explicit `local_mac` and `peer_mac`
2. build those values in the Go manager
3. have the Rust helper prefer those snapshot MACs when building runtime fabric
   state

Result:

1. the old owner now forwards stale-MAC traffic onto the fabric correctly
2. the first failover gap is closed

### 2. Reverse Cluster-Synced Sessions Poisoned Userspace Takeover

Cluster session sync installs both forward and reverse conntrack entries on the
peer. The userspace manager mirrored both into the Rust helper. That was wrong
for the reverse entry.

Effect:

1. the new owner hit the reverse synced session first on reply traffic
2. that mirrored reverse entry still carried forward NAT semantics
3. reply packets re-resolved toward the SNAT VIP (`172.16.80.8`) instead of
   reverse-NATing back to the client
4. the helper reported `missing_neighbor` for flows like
   `172.16.80.200:5201 -> 172.16.80.8:<client-port>`

Fix:

1. stop mirroring reverse cluster-synced sessions into the userspace helper
2. mirror only the forward synced session
3. let the helper derive/promote the reverse session locally from the forward
   synced entry and NAT reverse index

Result:

1. the new owner now preserves the TCP flow across the RG move
2. the exact 60-second `iperf3` repro survives failover

## Known Gaps Between Userspace And eBPF

### 1. Dedicated Failover Validation Needs One More Tightening Pass

The standard userspace HA validator exercises:

1. steady-state reachability
2. traceroute / `mtr` visibility
3. sustained `iperf3` throughput

That gap is mostly closed by
[userspace-ha-failover-validation.sh](/home/ps/git/codex-bpfrx/scripts/userspace-ha-failover-validation.sh),
but the scripted workflow still needs to be re-run after the new reachability
preflight tightening and then promoted to the normal acceptance path.

### 2. Synced Session Pickup Is Still More Fragile In Userspace

Userspace uses:

1. worker-local session tables
2. shared session tables
3. `USERSPACE_SESSIONS` BPF map for XDP redirect gating

The new owner must:

1. already have the synced session
2. already have the live userspace-session key published for XDP redirect
3. promote the synced session into the local forwarding path
4. resolve egress/fabric state fast enough that the first post-failover packets
   do not die permanently

That is more moving pieces than the legacy conntrack path.

### 3. Userspace Session Sync Still Preserves A Thinner Forwarding Snapshot

The userspace sync request format can carry:

1. `egress_ifindex`
2. `tx_ifindex`
3. `tx_vlan_id`
4. `next_hop`
5. `neighbor_mac`
6. `src_mac`
7. NAT rewrite fields

But the userspace delta bridge in
[pkg/daemon/daemon.go](../pkg/daemon/daemon.go)
currently rebuilds sync state mostly from:

1. session key
2. ingress/egress zones
3. `egress_ifindex`
4. NAT flags and addresses

That means the failover owner may need to re-resolve more forwarding state than
the legacy dataplane did.

### 4. Fabric Redirect Parity Still Needs Stress Proof

The userspace dataplane now has fabric XSK bindings and fabric redirect support,
but the legacy eBPF path in
[bpf/xdp/xdp_zone.c](../bpf/xdp/xdp_zone.c)
still remains the richer, more battle-tested reference for:

1. existing-session redirect on inactive RG
2. `NO_NEIGH` handling for established sessions
3. anti-loop behavior during split ownership
4. zone-encoded redirect during ownership transitions

## Implementation Checklist

### Phase A: Validation Gap

Status: Mostly Complete

1. Add a dedicated userspace RG1 failover validation script.
2. Make it prove that an existing `iperf3` flow survives a manual RG1 failover.
3. Keep artifacts and state snapshots so failures are diagnosable after the run.

### Phase B: Observability Gap

Status: Complete For Single-Failover Debugging

1. Capture pre-failover and post-failover userspace dataplane statistics on both nodes.
2. Capture RG ownership before and after the failover.
3. Capture session presence on both nodes before failover and after takeover.
4. Capture whether the new owner has userspace forwarding armed and active for RG1.

### Phase C: Synced Session Pickup Parity

Status: First Critical Gap Fixed

1. Verify synced sessions are present on the peer before failover.
2. Verify synced sessions are published into `USERSPACE_SESSIONS`.
3. Verify first packets after failover hit the synced-session path on the new owner.
4. Verify synced sessions are promoted to live sessions without waiting for a new flow open.

### Phase D: Forwarding Metadata Parity

Status: In Progress

1. Compare userspace session-sync payload shape against the legacy conntrack shape.
2. Extend userspace sync payload if failover requires more cached forwarding metadata.
3. Preserve enough forwarding state that the new owner does not depend on avoidable re-resolution.

### Phase E: Fabric Redirect Parity

Status: First Critical Gap Fixed

1. Compare userspace failover behavior against the eBPF `xdp_zone.c` reference path.
2. Verify existing-session redirect on inactive RG.
3. Verify `NO_NEIGH` handling during failover windows.
4. Verify anti-loop behavior and zone-encoded redirect under split ownership.

### Phase F: Stress Parity

Status: Not Started

1. After single RG1 failover passes, add repeated failover / failback coverage.
2. Use the legacy stress test semantics as the acceptance bar:
   - no dead streams
   - no permanent `0.00 bits/sec` intervals
   - throughput recovery after each failover window

## Success Criteria

Userspace reaches parity for this problem when all of the following are true:

1. a long-running `iperf3 -c 172.16.80.200 -P 4 -t 60` survives manual RG1 failover
2. the new owner forwards the existing sessions without requiring a reconnect
3. the dedicated userspace failover validator passes repeatably
4. the remaining failover behavior is explained by the same rules as the eBPF dataplane

## Immediate Next Steps

1. rerun the dedicated failover validator after the reachability-preflight fix
   and make it the standard RG1 gate
2. investigate the residual post-failover `missing_neighbor` exceptions on the
   new owner even though the TCP flow now survives
3. compare repeated failover / failback behavior against the legacy eBPF stress
   tests and close any remaining parity gaps
