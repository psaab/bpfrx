# Userspace Branch Merge From origin/master

Date: 2026-03-10

Branch: `userspace-dataplane-rust-wip`

Baseline tag created before merge:

- `userspace-ha-xdp-fallback-baseline-20260310`

This document records what was merged from `origin/master`, what it changed in the
branch, and what still needs to be implemented in the Rust userspace dataplane.

## Merge Summary

Merged `origin/master` into `userspace-dataplane-rust-wip` after the HA userspace
lab had already been gated back to legacy XDP fallback for real traffic.

Relevant master commits that landed:

1. `c47659b` `fix: firewall filter multi-value address/port merging in set commands`
2. `b41a734` `fix: restore native XDP on loss cluster + per-interface XDP mode`
3. `dfd3ebc` `fix: generic XDP checksum corruption + cross-VRF NAT re-FIB`
4. `6dd2877` `fix: disable ip6gre encaplimit to avoid DSTOPT extension header`
5. `993f777` `fix: auto-add HOST_INBOUND_GRE for tunnel transport zones`
6. `10f10e6` `fix: MAX_INTERFACES overflow + tunnel host-inbound bypass`
7. `3bac530` `fix: TCP MSS clamping for GRE tunnel transit traffic`
8. `e95c2e1` `fix: GRE tunnel transit traffic — XDP raw IP handling + accept_local`
9. `02a293c` `fix: tunnel forwarding via XDP_PASS + TC egress passthrough`
10. `173cabd` `fix: add HOST_INBOUND_GRE for tunnel termination`

## Files And Areas Changed By The Merge

The merge was not just the parser fix. It brought a larger dataplane/tunnel series
across the branch boundary.

Main changed areas:

- BPF XDP/TC pipeline:
  - `bpf/xdp/xdp_main.c`
  - `bpf/xdp/xdp_zone.c`
  - `bpf/xdp/xdp_forward.c`
  - `bpf/xdp/xdp_conntrack.c`
  - `bpf/xdp/xdp_nat64.c`
  - `bpf/tc/tc_main.c`
  - `bpf/tc/tc_conntrack.c`
  - `bpf/headers/bpfrx_common.h`
  - `bpf/headers/bpfrx_helpers.h`

- Compiler / loader / types:
  - `pkg/config/ast.go`
  - `pkg/config/parser_test.go`
  - `pkg/dataplane/compiler.go`
  - `pkg/dataplane/loader.go`
  - `pkg/dataplane/types.go`
  - `pkg/daemon/daemon.go`
  - `pkg/routing/routing.go`

- DPDK parity updates:
  - `dpdk_worker/forward.c`
  - `dpdk_worker/shared_mem.h`

- BPF object refresh:
  - regenerated `pkg/dataplane/*_bpfel.o`

- Lab configs:
  - `docs/ha-cluster-loss.conf`
  - `docs/ha-cluster.conf`

## What These Master Changes Mean

### 1. Firewall filter parser correctness changed

`pkg/config/ast.go` now correctly merges multi-value address/port entries from
`set` commands into hierarchical filter terms instead of overwriting them. That is a
control-plane semantic fix.

Impact on userspace branch:

- the Rust userspace dataplane does not need a special port for this
- but any userspace-side policy snapshot assumptions must match the corrected parsed
  config model

### 2. Tunnel forwarding semantics changed in the legacy dataplane

The merged master changes add a significant GRE/tunnel transport series:

- tunnel forwarding can fall back to `XDP_PASS` and continue on TC egress
- GRE transport zones get automatic `HOST_INBOUND_GRE`
- GRE raw IP transit handling was corrected
- MSS clamping is applied for GRE tunnel transit
- `ip6gre` encaplimit is disabled to avoid unwanted IPv6 extension headers

Impact on userspace branch:

- the legacy dataplane reference changed
- userspace forwarding is now further behind the main dataplane on tunnel handling
- the Rust dataplane currently does not implement this tunnel behavior set

### 3. NAT and routing behavior changed

Master brought:

- generic XDP checksum corruption fix
- cross-VRF NAT re-FIB fix

Impact on userspace branch:

- Rust NAT forwarding logic needs to mirror the new re-FIB expectations
- userspace forwarding should not assume the older pre-merge NAT behavior is still
  the reference model

### 4. Loader/runtime assumptions changed

Master also brought:

- per-interface XDP mode handling
- interface-count overflow fixes
- dataplane struct changes in `pkg/dataplane/types.go`

Impact on userspace branch:

- any Rust/XDP handoff assumptions about interface indexing and config publication
  must stay aligned with the updated Go compiler/runtime types

## Runtime Result After Merge

After deploying the merged branch to the isolated userspace HA cluster:

- the safe HA/fabric capability gate still worked
- both firewalls stayed in `Forwarding supported: false` / `Enabled: false`
- real traffic stayed on legacy XDP fallback as intended

Observed runtime issue after deploy:

- `cluster-userspace-host -> 10.0.61.1` initially failed
- the failure was stale host neighbor state after rolling deploy, not a new merge
  breakage
- flushing the host neighbor cache restored LAN reachability immediately

Validated after recovery:

- IPv4 ping to `172.16.80.200`: working
- IPv6 ping to `2001:559:8585:80::200`: working
- short IPv4 `iperf3 -P 2 -t 3`: about `21.5 Gbps`

This confirms the merged branch is currently stable again in safe fallback mode.

## Implementation Plan After The Merge

The immediate goal is not to re-enable userspace forwarding on the HA/fabric lab
blindly. The merged master widened the feature gap. The next work needs to follow
the updated reference behavior.

### Phase 1: Keep the fallback safe and reproducible

1. Preserve the HA/fabric capability gate on the branch.
2. Treat the isolated HA lab as a fallback-validation environment until userspace
   implements HA ownership and fabric redirect correctly.
3. Bake post-deploy neighbor refresh into the repeatable validation workflow so the
   lab does not fail on stale LAN host neighbor state.

### Phase 2: Rebase the userspace reference model onto merged master semantics

1. Review userspace snapshot publication against the merged `pkg/dataplane/types.go`
   and `pkg/dataplane/compiler.go`.
2. Audit Rust forwarding/NAT/session code against:
   - cross-VRF NAT re-FIB behavior
   - updated interface/XDP mode assumptions
3. Add regression tests that explicitly compare the Rust userspace logic against the
   new legacy dataplane expectations.

### Phase 3: Port the merged tunnel feature set into Rust userspace dataplane

Required before claiming parity with current master:

1. host-inbound GRE handling
2. tunnel transit classification
3. `XDP_PASS -> TC` style tunnel exception handling equivalent
4. tunnel MSS clamping behavior
5. IPv6 tunnel encaplimit semantics equivalent to the master fix

### Phase 4: Implement HA ownership and fabric redirect in Rust

This remains the main blocker for the isolated HA lab:

1. RG ownership gating in userspace forwarding resolution
2. fabric redirect for peer-owned egress
3. zone-encoded fabric ingress handling
4. owner-aware session sync and replay semantics
5. watchdog/fabric readiness coupling

Only after this phase should the HA lab be allowed to arm userspace forwarding again.

### Phase 5: Resume line-rate performance work

Only after correctness is back:

1. re-enable userspace forwarding on a supported path
2. validate ping, then `iperf3`, then `perf`
3. compare IPv4/IPv6 hotspot deltas against the merged legacy dataplane

## Immediate Working Rule

For this branch right now:

- merged master is integrated
- fallback forwarding works again
- the HA/fabric userspace dataplane remains intentionally disabled

That is the correct baseline for the next implementation phases.
