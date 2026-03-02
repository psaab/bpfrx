# Next Feature: Deterministic VRRP Failover Reconciliation

Date: 2026-03-01  
Status: Proposed

Related:
- Same-L2 ownership mode proposal: `docs/next-features/ha-same-l2-vip-ownership.md` (issue #104)

## Problem

Recent hardening fixed major VRRP failover bugs, but several edge cases can still
cause transient packet loss or sticky incorrect state during repeated failover:

- `rg_active` and blackhole route updates are mostly transition-driven, not
  continuously reconciled against desired state.
- Cluster/VRRP event delivery is intentionally lossy under pressure
  (non-blocking channels), and periodic reconciliation is coarse.
- VRRP RX backpressure has limited observability when advertisement packets are
  dropped from internal channels.
- `fabric_fwd` programming is one-shot and can drift when neighbor/link state
  changes.
- IPv6 VRRP source address selection is not fully deterministic in all
  multi-address edge cases.

## Goals

- Make failover state self-healing, even after transient netlink/dataplane errors.
- Reduce failover sensitivity to dropped control events.
- Improve observability for control-plane backpressure.
- Keep behavior stable under rapid repeated VRRP/cluster transitions.

## Scope

1. Desired-vs-applied RG state
- Track desired and applied state separately per RG.
- Continue retrying `UpdateRGActive` until applied state matches desired.
- Do not gate retries only on state transition edges.

2. Declarative blackhole route reconciliation
- On each reconcile pass, assert the route set that must exist for each RG state.
- Remove stale blackholes and re-add missing ones, independent of prior transition
  success/failure.

3. Event-drop recovery improvements
- On cluster/VRRP event drop warnings, schedule immediate reconcile (fast path).
- Reduce reconcile interval or use adaptive interval during churn windows.
- Keep periodic reconcile as a safety net.

4. VRRP RX backpressure hardening
- Add explicit counters/metrics for dropped `rxCh` packets in all receivers
  (raw IPv4, raw IPv6 fallback, AF_PACKET v4/v6 paths).
- Add alerts/log rate-limited warnings when sustained drops occur.
- Re-evaluate channel sizing strategy for VRRP advert bursts.

5. `fabric_fwd` drift correction
- Periodically refresh `fabric_fwd` map contents (peer MAC, FIB ifindex).
- Trigger refresh on relevant link/neighbor changes and failover transitions.
- Ensure stale neighbor data cannot persist indefinitely.

6. Transition ordering safety
- Tighten ordering so deactivation paths do not expose windows where routing and
  `rg_active` disagree.
- Prefer route safety (blackhole presence) before forwarding-disable state flips
  when feasible.

7. IPv6 VRRP source determinism
- Pin IPv6 advert source/interface explicitly at send time.
- Ensure tie-break and self-packet filtering always compare against the actual
  source used on wire.

## Acceptance Criteria

- Repeated failover/failback cycles do not leave sticky incorrect `rg_active` or
  stale blackhole routes after transient apply failures.
- Dropped control events (cluster/VRRP) are corrected quickly without waiting for
  a long periodic interval.
- VRRP RX drop counters are visible and remain near zero in normal operation.
- `fabric_fwd` stays correct across neighbor churn without manual intervention.
- IPv6 VRRP MASTER/BACKUP transitions remain stable with equal-priority tie-breaks.

## Test Plan

- Add unit tests for desired/applied reconciliation behavior and retry loops.
- Add unit tests for route convergence from arbitrary stale kernel route state.
- Add stress tests with induced event-channel saturation and verify fast recovery.
- Add churn tests for neighbor/FIB changes while failover traffic is active.
- Extend failover regression tests with high-cycle repeated VRRP transitions.

## Non-Goals

- Changing HA architecture (VRRP + cluster model remains intact).
- Introducing new control protocols.
- Expanding feature scope beyond failover correctness and resilience.
