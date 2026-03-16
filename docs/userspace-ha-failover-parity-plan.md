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
- current `master` still shows a bounded but unacceptable failover trough in the
  dedicated validator:
  - `5` zero-throughput intervals on `master` during RG1 failover
- this branch closes that remaining single-failover gap too
- exact repro now survives:
  - `iperf3 -c 172.16.80.200 -P 4 -t 60`
  - `request chassis cluster failover redundancy-group 1 node 1`
- latest manual validation result:
  - `0` zero-throughput `SUM` intervals after failover
  - final 60s sender rate: `15.8 Gbps`
- latest scripted validation result on this branch:
  - `0` zero-throughput intervals after RG1 failover
  - sender throughput: `17.4 Gbps`
- latest strict split-RG steady-state validation result on this branch:
  - `0` zero-throughput intervals before any failover
  - `0` per-stream zero-throughput intervals
  - sender throughput: `17.8 Gbps` before the stale-session handoff work
  - sender throughput: `6.99 Gbps` on the current HA perf branch after keeping
    the standby helper armed for correctness
- latest strict RG1 failover validation result on this branch:
  - repeated `3`-cycle failover/failback run now passes
  - `0` zero-throughput intervals across the full run
  - `0` per-stream zero-throughput intervals
  - sender throughput: `10.6 Gbps`
- standby HA nodes now keep the userspace helper armed and all bindings ready
  even with no locally active data RGs
- that closes the stale-MAC / stale-neighbor parity gap where traffic could
  land on the old owner during the ownership transition and fall out of the
  userspace fabric path
- the failover validator is now being hardened for stress parity:
  - repeated failover / failback cycles
  - per-stream `0.00 bits/sec` checks, not just `[SUM]`
  - minimum-duration enforcement so `iperf3` cannot finish before the cycle plan
  - zero-port TCP session preflight checks so stale session pollution does not
    invalidate stress results
- the validator now also has a `--steady-only` split-RG fabric mode and a strict
  pre-failover observe window so "streams already dead before failover" is
  caught as a steady-state fabric regression instead of a failover regression
- remaining work is now parity hardening and performance parity:
  - repeated failover stress
  - higher split-RG fabric throughput
  - higher post-failover throughput
  - post-move cold-connect latency
  not first-fix bring-up

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

### 3. Synced Sessions Lost Original `fabric_ingress`

Cluster session sync preserved the flow key, NAT fields, and cached forwarding
state, but it did not preserve whether the original flow arrived from the peer
fabric. Reconstructed synced sessions on the peer were therefore rebuilt with
`fabric_ingress=false`.

Effect:

1. the peer helper lost the correct reverse-session return semantics after takeover
2. current `master` could still show multiple zero-throughput intervals during
   the RG1 failover validator even though the flow eventually survived
3. the first post-failover packets depended on slower re-learning rather than
   landing directly on the correct fabric-aware session metadata

Fix:

1. export `fabric_ingress` in userspace session deltas
2. preserve it through the daemon session-sync bridge
3. mirror it into `SessionSyncRequest`
4. rebuild synced sessions in the Rust helper with the original
   `fabric_ingress` metadata intact

Result:

1. the dedicated RG1 failover validator now passes with `0` zero-throughput
   intervals on this branch
2. synced-session takeover preserves the same fabric-aware return semantics as
   the original forward session

### 4. Passive Peer Reverse Resolution Re-Redirected Steady-State Fabric Returns

The peer-side helper kept `fabric_ingress=true` on synced forward sessions and
then treated that as an unconditional "send the reverse path back to fabric"
signal when it had to derive a reverse session locally.

Effect:

1. the split-RG steady-state fabric path could start at line rate and then drop
   all `iperf3` streams to `0.00 bits/sec` within a few seconds
2. the passive peer accumulated huge session-miss counts while still
   transmitting fabric traffic
3. the bug reproduced even before the first failover, so it was contaminating
   HA validation with a pure steady-state fabric failure

Fix:

1. keep the `fabric_ingress` hint
2. but only use zone-encoded fabric redirect for the reverse path when the
   target egress RG is inactive on the current node
3. if the peer owns the client-side RG, resolve the reverse path locally
   instead of bouncing it back across fabric

Result:

1. the strict split-RG steady-state validator now passes with `0`
   zero-throughput intervals
2. the failover validator still passes with `0` zero-throughput intervals
3. the remaining gap is throughput parity, not stream collapse

### 5. Standby Nodes Fell Out Of The Userspace Fabric Path

The userspace manager only armed the helper when the local node owned at least
one active data RG. On the standby node that meant:

1. `Enabled=false`
2. `Forwarding armed=false`
3. `Bound bindings=0/24`

Effect:

1. stale-MAC traffic arriving on the old owner during failback did not stay in
   the userspace HA fabric path
2. repeated failover / failback runs still showed brief but real
   `0.00 bits/sec` troughs even after the stale-session demotion fix
3. the inactive owner behaved unlike the legacy eBPF dataplane, which always
   kept the fabric redirect path available

Fix:

1. keep the userspace helper armed on HA standby nodes whenever userspace
   forwarding is supported and data RGs exist
2. leave the actual per-packet forwarding decision under HA resolution, so
   inactive owners still redirect or drop according to the normal userspace HA
   path instead of forwarding locally

Result:

1. the standby node now remains `Enabled=true` with `24/24` bindings ready
2. the repeated `3`-cycle RG1 failover / failback validator passes with:
   - `0` aggregate zero-throughput intervals
   - `0` per-stream zero-throughput intervals
   - `10.6 Gbps` sender throughput
3. the remaining HA gap is now throughput parity on the split-RG fabric path,
   not stream survival

## Known Gaps Between Userspace And eBPF

### 1. Throughput Parity On The Split-RG Fabric Path Is Still Missing

Reliability is materially better now, but the fabric path is still slower than
the non-HA userspace target.

Current measured baselines on the HA perf branch:

1. strict split-RG steady-state validator:
   - `6.99 Gbps`
2. repeated `3`-cycle failover / failback validator:
   - `10.6 Gbps`
3. normal HA validator with RGs pinned to node0:
   - IPv4 `15.783 Gbps`
   - IPv6 `17.378 Gbps`

The next performance work should target the current hot symbols on the fabric
path, especially:

1. `bpfrx_userspace_dp::afxdp::poll_binding`
2. `bpfrx_userspace_dp::afxdp::frame::enqueue_pending_forwards`
3. `bpfrx_userspace_dp::afxdp::session_glue::resolve_flow_session_decision`
4. `memcpy_orig` on the copy-mode fabric path

### 2. Dedicated Failover Validation Needs Promotion To The Default HA Gate

The standard userspace HA validator exercises:

1. steady-state reachability
2. traceroute / `mtr` visibility
3. sustained `iperf3` throughput

The dedicated
[userspace-ha-failover-validation.sh](../scripts/userspace-ha-failover-validation.sh)
is now strict enough to be the real HA acceptance gate, because it catches:

1. pre-failover split-RG stream collapse
2. repeated failover / failback zero-throughput troughs
3. stale zero-port TCP session pollution

That workflow now needs to be treated as the normal HA gate instead of a debug-only script.

### 3. Synced Session Pickup Is Still More Fragile In Userspace

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

### 4. Userspace Session Sync Still Preserves A Thinner Forwarding Snapshot

The userspace sync request format now carries:

1. `egress_ifindex`
2. `tx_ifindex`
3. `tx_vlan_id`
4. `next_hop`
5. `neighbor_mac`
6. `src_mac`
7. NAT rewrite fields
8. `fabric_ingress`

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
3. Add a split-RG steady-state mode so fabric-link regressions can be isolated
   without failover churn.
4. Keep artifacts and state snapshots so failures are diagnosable after the run.

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

Status: First Critical Gap Fixed

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

Status: In Progress

1. After single RG1 failover passes, add repeated failover / failback coverage.
2. Use the legacy stress test semantics as the acceptance bar:
   - no dead streams
   - no per-stream `0.00 bits/sec` intervals during the failover window
   - no permanent `0.00 bits/sec` intervals
   - throughput recovery after each failover window
3. Require clean-state preflight before the stress run starts:
   - no stale zero-port TCP sessions for the `iperf3` target
   - no recycled old flow state hiding the current branch behavior

## Success Criteria

Userspace reaches parity for this problem when all of the following are true:

1. a long-running `iperf3 -c 172.16.80.200 -P 4 -t 60` survives manual RG1 failover
2. the new owner forwards the existing sessions without requiring a reconnect
3. repeated failover / failback stress does not collapse all streams to
   `0.00 bits/sec`
4. the dedicated userspace failover validator passes repeatably from a clean
   session baseline
5. the remaining failover behavior is explained by the same rules as the eBPF dataplane

## Immediate Next Steps

1. rerun repeated failover / failback stress from a clean deploy so the result
   is not contaminated by stale session state
2. if repeated stress still fails, identify whether the new failure is:
   - session sync corruption
   - zero-port TCP session creation
   - fabric-link forwarding continuity under repeated RG flips
3. promote the dedicated failover validator to the standard RG1 acceptance gate
   once the repeated-cycle stress case passes
4. close the remaining post-move cold-connect latency gap so the first new
   connection after RG ownership change does not need a warm-up round
