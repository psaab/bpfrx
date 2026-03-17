# Userspace Performance Plan

Date: 2026-03-17
Active branch baseline: `fix/userspace-cross-nic-ha-perf-baseline`

This is the current performance plan for the Rust AF_XDP userspace dataplane.
It replaces the older mixed backlog that targeted the eBPF/XDP pipeline.

## Validity Check

Current perf documentation in this tree is mixed in quality:

1. [userspace-perf-compare.md](/home/ps/git/codex-bpfrx/docs/userspace-perf-compare.md) is valid.
   - It is the right measurement workflow for current userspace branches.
2. [shared-umem-plan.md](/home/ps/git/codex-bpfrx/docs/shared-umem-plan.md) is valid, but only as a
   constrained side plan.
   - It matters for same-device `mlx5` cases.
   - It does not address the current HA lab's cross-NIC transit bottleneck.
3. [perf-ranked-backlog.md](/home/ps/git/codex-bpfrx/docs/perf-ranked-backlog.md) is not valid for
   the current branch as a primary plan.
   - It describes the older eBPF/XDP pipeline hotspots such as `xdp_main_prog`
     and `xdp_nat_prog`.
   - The current userspace dataplane hotspot stack is different.

## Current Measured Read

Latest clean cross-NIC transit perf on this branch shows:

1. `bpfrx_userspace_dp::afxdp::poll_binding` around `17.9%`
2. `__memmove_evex_unaligned_erms` around `12.7%`
3. `bpfrx_userspace_dp::afxdp::frame::enqueue_pending_forwards` around `3.7%`
4. `bpfrx_userspace_dp::afxdp::session_glue::resolve_flow_session_decision` around `2.6%`
5. `xdpilone::xsk::user::<impl RingRx>::available` around `1.5%`
6. `bpfrx_userspace_dp::afxdp::frame::build_forwarded_frame_into_from_frame` around `1.5%`

First measured Phase 2 slice on this branch:

1. `eb958ec` plus the current target-binding cache keeps a steady manual IPv4
   transit run at about `15.9 Gbps`
2. `resolve_flow_session_decision` moved from about `2.56%` in the earlier
   clean baseline to about `2.30%` in the current matched manual perf sample
3. `poll_binding` and the direct-path `memmove` remain the dominant costs

Interpretation:

1. The main remaining cost is userspace fixed poll overhead plus the direct-path
   cross-NIC frame copy.
2. The old firewall-local TUN dependence is no longer the main issue.
3. Same-device shared UMEM is worth keeping as a limited optimization track,
   but it does not solve the active HA-lab topology.

## Constraints

1. The active HA lab is cross-NIC transit.
   - The large `memmove` cost is structural in the current direct-TX design.
2. Reliability gates must stay green while optimizing.
   - no aggregate zero-throughput intervals
   - no per-stream zero-throughput intervals
   - traceroute and `mtr` must keep working
3. Shared UMEM is not a blanket answer.
   - same-device `mlx5`: plausible optimization
   - cross-device `mlx5`: not feasible in zerocopy mode for this topology

## Phases

### Phase 1: Measurement And Acceptance Discipline

Status: Complete enough to support active work

Purpose:
- make every perf change compete against a current userspace baseline, not
  stale target numbers

Current state:
1. `userspace-perf-compare.sh` is the profiling workflow
2. `userspace-ha-validation.sh` catches sustained-throughput cliffs
3. `userspace-ha-failover-validation.sh` checks stream survival and captures
   retransmit-aware `iperf3` JSON-stream artifacts

Remaining improvement:
1. turn retransmit telemetry into an enforced threshold after a stable good
   baseline is established

### Phase 2: Session-Hit And Binding-Resolution Overhead

Status: In progress on `fix/userspace-cross-nic-ha-perf-baseline`

Purpose:
- remove avoidable lookup and key-materialization work from the steady-state
  established-flow path

Landed or active slices:
1. `eb958ec` trims session-hit resolution overhead in
   [session_glue.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/session_glue.rs)
2. the current branch adds target-binding index caching for normal forward
   requests so `enqueue_pending_forwards()` does not redo the same binding
   lookup on the hot path

Measured result so far:
1. this phase is reducing lookup-side cost modestly, not changing the
   structural cross-NIC copy cost
2. the next worthwhile slice is still Phase 3, not more speculative work in
   the same request builder

Exit criteria:
1. local/shared session-hit paths stop doing avoidable key rebuilding
2. normal forward requests carry enough target-binding information to avoid
   repeated lookup work

### Phase 3: Poll Loop Fixed-Cost Reduction

Status: Pending

Purpose:
- reduce `poll_binding` cost without reintroducing stalls or failover lag

Focus areas:
1. RX wake policy only when there is evidence it is profitable
2. reduce idle binding work without skipping real traffic
3. keep `RingRx::available()` from becoming the dominant empty-poll tax

Non-goal:
1. no more blind wake-throttling or idle-thinning experiments
   - previous versions preserved correctness poorly or reduced throughput

Exit criteria:
1. `poll_binding` drops materially in perf
2. split-RG steady-state and failover gates remain green

### Phase 4: Forward Enqueue And Builder Overhead

Status: Pending

Purpose:
- reduce per-packet control overhead around the direct-TX path

Focus areas:
1. `enqueue_pending_forwards()`
2. `build_forwarded_frame_into_from_frame()`
3. unnecessary re-resolution or revalidation inside the forward loop

Known boundaries:
1. this is separate from the structural cross-NIC payload copy itself
2. `Copy-path TX` is already near zero in the current HA baseline, so work here
   should target the direct path, not the old fallback path

Exit criteria:
1. direct-path control overhead drops in perf
2. no increase in retransmits or zero-throughput intervals

### Phase 5: Cross-NIC Copy Bottleneck

Status: Planned

Purpose:
- separate the truly structural copy cost from the smaller userspace-control
  overheads

Current read:
1. the large `memmove` sample is from the direct-TX builder copying payload
   between separate UMEM regions
2. same-device shared UMEM can help on eligible topologies
3. the current HA lab's cross-NIC path will still pay this copy

Work split:
1. keep same-device shared-UMEM work isolated and topology-gated
2. do not let the cross-NIC HA branch depend on that prototype
3. if cross-NIC transit still needs more headroom after Phases 2-4, evaluate
   whether a deeper frame-ownership redesign is justified

Exit criteria:
1. same-device prototype is either validated on a real proof topology or left
   explicitly out of the HA branch
2. cross-NIC limitations are documented honestly

### Phase 6: HA Reliability And Perf Parity

Status: In progress

Purpose:
- ensure throughput work does not regress the HA behavior we already recovered

Required gates:
1. split-RG steady-state fabric `iperf3`
2. RG1 failover/failback survival
3. IPv4/IPv6 traceroute and `mtr`
4. per-stream and aggregate zero-throughput interval checks

Remaining work:
1. establish a stable retransmit baseline and then enforce it
2. keep post-failover throughput from regressing while Phases 2-4 land

## Recommended Execution Order

1. Finish Phase 2 on the active cross-NIC branch.
2. Take the next measured slice in Phase 3.
3. Move to Phase 4 only after Phase 3 has at least one kept win.
4. Keep Phase 5 isolated from the HA branch unless the topology actually makes
   it relevant.
5. Run Phase 6 gates after every kept performance slice.

## What Not To Do

1. Do not optimize against the old `xdp_main_prog` / `xdp_nat_prog` backlog for
   this branch.
2. Do not treat same-device shared UMEM as the answer for the cross-NIC HA lab.
3. Do not keep perf changes that only look good in one short run but fail the
   steady-state or failover gates.
