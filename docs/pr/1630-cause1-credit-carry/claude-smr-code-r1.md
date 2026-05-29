# Claude SMR code review — #1630 cause-1 credit carry + #1643 fence (r1)

Reviewer profile: CoS-scheduler / WFQ-DRR / token-bucket /
seqlock-concurrency / AF_XDP multi-worker-shaper / HA-failover domain SMR
+ CPU-arch/memory-model + SW-design.

Scope reviewed: the full diff on `fix/1630-cause1-credit-carry` vs
origin/master @ 0e5bb3812. This is a self-review seat in the 4-way gate
(Codex + AGY + Copilot + Claude SMR). I implemented the change, so this
review is deliberately adversarial against my own work.

## Verdict: MERGE-READY (self-seat), pending external Codex/AGY/Copilot.

## What was verified

### 1. Bounded rotation credit carry (rotate_epoch_v8 STEP 6)

- **Recovers the discarded credit (the bug).** Pre-#1630 the clamp
  computed `elapsed = min(lag, EPOCH)` then reset `epoch_start := now`,
  permanently dropping `rate × (lag − EPOCH)`. Regime 1 now grants
  `rate × raw_elapsed` (lag bounded by K), pinned by
  `v8_carry_normal_recovery_recovers_lagged_credit` (5-epoch lag → cap =
  5 × rate × EPOCH, vs the old 1 epoch). This is the precise fix for the
  measured 100m/1g SOLO floor.
- **Burst bound preserved (the invariant the clamp protected).**
  Per-rotation grant ≤ `(K + (K−1)) × rate × EPOCH`. Two tests pin it:
  `v8_carry_burst_bound_holds_after_two_second_stall` (2 s stall → 1
  epoch, NOT rate × 2 s) and
  `v8_carry_per_rotation_grant_never_exceeds_k_epoch_ceiling` (full
  reservoir drained in one regime-1 visit stays ≤ ceiling). The
  reservoir clamp (`carry_max`) and drain clamp (`carry_drain_max`) are
  the two independent bounds from plan §3.2.
- **No-cliff at K+1 (plan §5.3 / Gate 5d).** Regime 2 grants the K-epoch
  ceiling AND banks the residual instead of dropping to 1 epoch (the v2
  defect). Pinned by `v8_carry_bank_residual_no_cliff_at_k_plus_one` +
  `v8_carry_banked_residual_drains_on_next_visit`.
- **STALL decoupled from K.** `STALL_THRESHOLD_EPOCHS = 256` (≈51 ms)
  sits below the ≥500-epoch failback gap and above any legitimate visit
  tail, so a heavy-tail visit (regime 2) is never mis-classified as a
  stall (regime 3). Matches plan §5.3.1.
- **Arithmetic safety.** All carry math uses u128 intermediates then
  `as u64`, `saturating_add`, `saturating_sub`, `.min(...)`. Regime-1
  `prev_carry - draw` cannot underflow (`draw ≤ prev_carry`). Regime-2
  `overshoot_ns` is strictly positive (lag > K guaranteed). `new_cap`
  clamped at `u32::MAX` (unchanged).

### 2. HA-failover safety (the v1 hazard Codex F4 surfaced)

Leases are REUSED across an HA demote→promote when config matches
(`coordinator/mod.rs` `matches_config_v8` → `lease.clone()`), so
`epoch_start` survives and the first post-promotion rotation sees
`lag ≈ demotion_duration`. A planned failback is ≥500 epochs >> STALL,
so regime 3 fires: single-epoch grant + carry dropped. Pinned by
`v8_carry_cold_resume_drops_stale_carry_for_ha_failback` (bank a
residual, then a >STALL gap on the SAME reused lease → grant = 1 epoch,
carry = 0). The carry is per-lease per-node in-process heap state, never
serialized into session/config sync (verified: no protocol.rs reference),
so it cannot transfer between nodes. `make test-failover` is the
cluster-side gate (pending).

### 3. #1643 seqlock acquire-fence

`snapshot_epoch_v8`: payload loads downgraded to Relaxed, explicit
`fence(Acquire)` inserted before the `seq_after` re-read, `seq_after`
read Relaxed. Writer payload stores downgraded to Relaxed; the single
`epoch_seq.store(seq+2, Release)` is the sole publish. This is
byte-aligned with the verified-correct `cold_path_hist::snapshot`
reference (Acquire even-check → Relaxed payload → `fence(Acquire)` →
Relaxed re-read). I audited EVERY reader of the three payload fields
(`epoch_total_grant_cap`, `epoch_grace_expires_ns`, `worker_fair_share`):
the only non-test reader is the fenced snapshot; the rotation winner's
own `prev_cap` Acquire read at :68 is single-writer self-read. The
Relaxed downgrade is therefore safe — no reader bypasses the fence.

### 4. Carry reader-private invariant ENFORCED

`epoch_carry_bytes` is read/written only by the rotation winner inside
the seqlock ODD section; it is NOT in the snapshot payload, so it adds no
new reader-visible seqlock surface (would otherwise be the #1619 class).
`v8_carry_field_is_reader_private` greps the whole crate src and fails if
the field is referenced anywhere except the lease mod.rs (def+init),
rotate_epoch_v8.rs (the writer), and the test file. This is the §4.0
enforced guard, not a comment.

### 5. P2 frame cap + P1 token bank

- P2 splits the per-visit budget: Phase-1 gate/consumption stays on the
  rate-scaled `cos_guarantee_quantum_bytes` (`phase1_cost`) so small-first
  ordering and the `quantum_sum × fraction` Phase-1 budget are unchanged;
  the send budget is `cos_guarantee_visit_cap_bytes` = `TX_BATCH_SIZE ×
  frame`. Applied at all 5 selector sites (legacy, exact fast-path,
  waterfill phase-1, waterfill phase-2, non-exact).
- P1 banks N=8 frames in the exact-queue bucket and raises
  `max_total_leased` in lock-step via the `bank_floor` flag; the ROOT
  lease keeps `bank_floor=false` (cap unchanged). All four queue-lease
  constructors/matchers pass `bank_floor=true`; the root lease keeps the
  default helper. Verified the long-run rate is still metered by the v8
  per-epoch grant + actual-byte `consume` (the bank only widens the
  outstanding window) → Gate 4 hard-cap preserved.
- 4 P2-affected existing tests updated to the new behavior (frame-drain,
  release-on-empty, bank cap, cursor-rotation isolation via 1-frame
  priming). No assertion was weakened to pass — each new assertion
  reflects the corrected mechanism with a rationale comment.

## Residuals / scope notes

- **Cause-2 (3g/6g ~6 %) is OUT of scope** and untouched. PR closes
  #1643 and is "Part of #1630" — does NOT close #1630.
- **Aggregate simultaneous-resume burst (plan §3.5.1 global cap)** is
  Fork-B-only and intentionally NOT implemented: the §3.6 SOLO A/B
  established Fork A (small-K + P2 clears scoped Gate-1), where the
  aggregate burst at small K is one root-epoch's worth, absorbed by the
  existing root meter. Adding the global cap would re-introduce the
  BLOCKING-3 small-class-first-allocator conflict for no benefit.
- **Cluster gates pending**: scoped Gate-1 (100m/1g ≥95% SOLO), full
  smoke matrix, `make test-failover`. Run after cluster acquisition.

## Tests
`cargo test --bin xpf-userspace-dp`: 1543 passed / 0 failed / 2 ignored.
9 new carry tests + the 4 updated P2 tests all green.

## r1 review-round addenda (post-dispatch)

- **Codex r1** (1 Major + 1 Medium): both were the floored-`lag_epochs`
  boundary hole (regime-1 admitting up to `(K+1)×EPOCH−ε`, breaching the
  burst bound by one epoch; and `STALL×EPOCH+1ns` skipping regime-3).
  FIXED in `4a2b998f7` — regime selection now compares `raw_elapsed_ns`
  against exact `K×EPOCH` / `STALL×EPOCH` ns thresholds. New
  `v8_carry_regime_boundaries_use_exact_nanoseconds_not_floored_epochs`
  pins all three boundaries; ceiling test tightened to assert the
  worst-case regime-1 grant EQUALS exactly `(2K−1)×rate×EPOCH`.
- **AGY r1**: MERGE-READY across all six axes (burst bound, Relaxed-fence
  safety, regime-3 HA cold-resume, carry privacy, u128 arithmetic, P2
  ordering) with quoted-line evidence; no findings.
- **Copilot r1**: same boundary Major (already fixed) + a doc nit (PR
  plan.md held the cause-2 plan by mistake). Both addressed (`7e6f7115f`).

## Cluster validation

- **Scoped Gate-1 SOLO (v4 push, reproducible x3)**: 100m **95.0 %**,
  1g **95.3 %** of shape — PASS (baseline 81 % / 84 %). Four-class table
  for the record: parallel four-alone and v6 land 1-3 pp lower at the
  cause-2 physics floor (documented, not the pass bar).
- **`make test-failover`: 13 passed / 0 failed** — unclean fw0 reboot →
  failover → rejoin-as-secondary → manual failover, iperf3 zero-drop
  through all three transitions. Validates the carry/seqlock/epoch HA
  path (regime-3 cold-resume on the reused lease across failback).
- **cause-2 resolved-as-physics** (coordinator §5 measurement): the
  3g/6g residual improves with parallelism (`-P1` 0.878 → `-P12` 0.949),
  proving it is ACK-clocked single-flow token-bucket fill, not a
  fair-share bug. Documented in fairness-regimes.md; PR now
  `Closes #1630` + `Closes #1643`.

## r2 addenda (post-validation)

- **Codex r2 RE-CONFIRM** (fresh thread `019e7204`, checked out
  f9563b9a8 directly): **MERGE-READY**. Verified with quoted lines that
  the exact-ns thresholds resolve its boundary Major, the
  `(2K−1)×rate×EPOCH` per-rotation bound holds at BOTH boundaries and for
  repeated regime-2-bank → regime-1-drain sequences (carry clamped at
  `carry_max`, drain ≤ K−1 epochs), and the worst-case ceiling test
  exercises the tight maximum. No remaining counter-example.
- **`copilot-swe-agent` push `c1e6ee237` "Fix carry cold-resume cleanup"**
  (NOT the formal review seat). Reviewed on merits: regime-3 now stores
  `epoch_carry_bytes = 0` UNCONDITIONALLY (was guarded by `if start != 0`).
  This is a harmless defensive hardening — when `start == 0` the
  constructor already initializes carry to 0, so the store is redundant,
  never wrong. The regime-1/2 logic and ALL burst bounds are byte-
  identical to the Codex-verified f9563b9a8, so the Codex r2 verdict
  carries forward over this delta. It adds
  `v8_carry_first_rotation_drops_stale_carry_even_with_zero_start`
  (injects carry then does a `start==0` rotation, asserts carry dropped).
  Full carry suite 10/10 green.
- **Flaky pre-existing test** `tx_latency_hist_cross_thread_snapshot_skew_within_bound`
  (#812, TX latency histogram sidecar — UNRELATED to carry/seqlock):
  failed twice while the build host was under concurrent load (its
  `K_skew` bound is computed from observed wall-clock rates, so reader-
  thread starvation under CPU oversubscription transiently exceeds it).
  Proven a load artifact, not a regression: passes 5/5 isolated, branch
  full-suite 3/3 and master full-suite 3/3 on a quiet box; last touched
  by #1614/#1618, not this branch. File-and-move-past per
  feedback_retirement_blocker_keep_going.
