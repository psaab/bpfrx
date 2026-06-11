# Claude SMR hostile code review — PR #1874 round 1 (head 5e7be0d53cb9)

Stance: domain SMR (v8 lease concurrency + CoS scheduler), CPU arch,
SW design. Hostile pass over the full diff before reading the other
reviewers.

## Verified

1. **Conservation / hard cap.** Per rotation t: bank `b_t =
   cap_{t-1} − g_{t-1}` (default mode only), `cap_t = rate·e_t + d_t`,
   `carry_t = clamp(carry_{t-1} + b_t) − d_t`. Telescoping:
   `Σg = Σcap − Σb = rate·Σe + (Σd − Σb) ≤ rate·Σe + carry_max`, and
   `Σe ≤ wall time` (disjoint intervals, K-clipped, stall-dropped).
   Gate-4 unchanged. The regime-2 path banks `lag-owed + unclaimed`
   under the same `carry_max` clamp — no double-mint (a re-banked
   drawn byte was removed from carry at draw time).
2. **prev_granted linearization.** Captured by the `packed_granted`
   atomic swap; in-flight old-tag CASes after the swap fail (tag
   mismatch), before it are included. Exact, race-free.
3. **Byte-identity claims.** (a) `prev_unclaimed == 0` reduces
   regime 1 to the old code path exactly (`.min(carry_max)` is a
   no-op under the existing `carry ≤ carry_max` invariant); pinned by
   `v8_fully_claimed_epoch_banks_no_carry`. (b) EqualFlowSuppress
   mode-gate: pinned by `v8_equal_flow_mode_never_banks…` + the
   84-test pre-existing suite passing unmodified.
4. **Wire contract both sides** (per
   `feedback_wire_protocol_both_sides`): grepped BOTH
   `protocol/cos.rs` serde renames and Go `protocol.go` tags —
   `lease_v8_worker_requested_bytes` / `lease_v8_worker_granted_bytes`
   byte-equal; `skip_serializing_if = Vec::is_empty` ↔ `omitempty`
   consistent; legacy leases keep a byte-identical wire.
5. **Hot-path budget.** Two relaxed own-slot `fetch_add`s per
   acquire; the arrays are sibling boxed slices with the same
   per-worker 8 B stride (and hence the same false-sharing profile)
   as the pre-existing `worker_grants`. No allocation, no dyn, no new
   cross-worker contention point. Rotation adds one load + one
   saturating add inside the already-single-writer ODD section.

## Findings

1. **MEDIUM (accepted-risk, must be in the PR record): counters reset
   on lease rebuild.** HA failover / config change replaces the lease
   Arc → `worker_requested/granted_bytes` restart at 0 → the
   Prometheus counters step backwards. This matches the established
   semantics of every other lease-held counter
   (`equal_flow_cap_hit_events` etc.) and Prometheus `rate()`/`increase()`
   handle counter resets; but the Step-0 analysis scripts use raw
   before/after deltas — a mid-cell lease rebuild would corrupt a
   measurement. Mitigation: the cells pin versions and the manifest
   flags incident windows. No code change required; recorded here.
2. **LOW: windfall semantics of class-level re-dealing.** A worker
   that missed nothing still gains from a peer's banked miss
   (proportionally). This is the designed A-ii-class variant the plan
   reviews ratified ("re-deals it flow-proportionally"); the new
   `v8_unclaimed_carry_redeals_flow_proportionally_across_workers`
   test pins it explicitly so nobody discovers it as a surprise.
3. **LOW: regime-2 unclaimed banking untested directly.** The bound
   test covers accumulation + clamp; a dedicated regime-2 pin
   (lag > K epochs AND unclaimed > 0) would close the last branch.
   Candidate for a follow-up nit; not blocking — the branch shares
   the clamp logic and regime-2 lag banking is pre-existing-tested.
4. **Measurement sanity re-check.** fix24c aggregates 21.1-22.3 G sit
   1-2 G under the measured unshaped C_phys(mix) 23.2 G — physically
   coherent, not too-good-to-be-true; 24g stayed at its
   ceiling-division residual (≈52%) rather than being starved —
   work-conserving, not robbing the aggressor; small4-alone improving
   to ~solo-health (95%) matches the model's ~10% alone-regime
   stranding. No artifact signature.

## Verdict

**MERGE-READY** with finding 1 recorded (no code change) and finding 3
as an optional follow-up test nit.
