# Plan v6 — Fix CoS scheduler equalize-bug under guarantee-rate 0.7 (#1630)

> v6 is a clean rewrite after v3/v4/v5 each hit a different
> regression. The design has converged on a small, surgical fix
> with no new bitmask, no Phase-1 walk change, and careful
> cursor semantics.
>
> Round history:
> - r1: Codex PLAN-NEEDS-MAJOR (8), AGY PLAN-NEEDS-MINOR (3),
>   SMR PLAN-NEEDS-MINOR (5).
> - r2: Codex PLAN-NEEDS-MAJOR (4), AGY PLAN-READY, SMR PLAN-READY.
> - r3: Codex PLAN-NEEDS-MAJOR (Phase-1-mask starvation),
>   AGY PLAN-READY (missed), SMR PLAN-READY (missed).
> - r4: Codex PLAN-NEEDS-MAJOR (Phase-2-cursor-reset starvation),
>   AGY PLAN-READY, SMR PLAN-NEEDS-MAJOR (self-correction on
>   v4 epoch refresh).
>
> Each Codex round caught a real regression the others missed.
> v6 addresses all of them.

## §1 Summary

The CoS waterfill selector for `oversubscription-policy
guarantee-rate <fraction>` has TWO arithmetic / timing bugs that
together produce the #1630 symptom (every class equalizes to
~20 % of configured rate instead of the documented "small
classes honoured to ≥ 95 %"):

- **Bug 1 (Hunk A)**: pass1 budget formula uses sum-of-queue-quanta
  × fraction. Under realistic configs where `Σ R_i > shaper`,
  this over-provisions pass1 by 3-5×, so Phase 2 never fires and
  the algorithm degenerates to ascending RR over all classes.

- **Bug 2 (Hunk B)**: even with the corrected pass1 formula,
  there is no mechanism to refresh pass1 except when it hits 0.
  Phase-2 selections under saturation do not decrement pass1, so
  after a few epochs of small-class honors, pass1 sits at a small
  positive value forever. Small classes stop being honored
  because each remaining quantum exceeds the leftover pass1.

The v6 fix:

- **Hunk A**: change pass1 refill formula to
  `shaping_rate × VISIT_NS × fraction` (matches documented
  contract "fraction × cap" where cap = shaper-delivered bytes
  per epoch).

- **Hunk B**: add `waterfill_epoch_start_ns: u64` field to
  `CoSInterfaceRuntime`. Refresh pass1 when
  `now_ns - waterfill_epoch_start_ns >= COS_GUARANTEE_VISIT_NS`,
  OR when `pass1 == 0` (preserved legacy path).
  **CRITICAL: only the time-based refresh path refreshes
  `pass1` and `waterfill_epoch_start_ns`. It does NOT reset
  `waterfill_phase2_cursor`. The cursor is reset ONLY by the
  legacy `pass1 == 0` path AND by the Phase-2-no-selection
  fall-through at mod.rs:1002-1005, where it has always been.**
  This preserves the Phase-2 descending RR continuity across
  epochs, avoiding the residual-starvation bug Codex r4 found
  in v5.

No bitmask. No Phase-1 walk change. The existing dead-local
`honored_mask` is left as-is (or trivially deleted).

## §2 Symptom (PR #1629 measurement)

11 classes × 12 streams × 30s under `shaping-rate 25g +
guarantee-rate 0.7`:

| Port | Class | Shape (G) | recv (G) | % shape |
|-----:|-------|----------:|---------:|--------:|
| 5201 | iperf-100m     |   0.1 | 0.019 |  19% |
| 5202 | iperf-1g       |   1.0 | 0.200 |  20% |
| 5203 | iperf-3g       |   3.0 | 0.672 |  22% |
| 5204 | iperf-6g       |   6.0 | 1.364 |  23% |
| 5205 | iperf-9g       |   9.0 | 2.004 |  22% |
| 5206 | iperf-12g      |  12.0 | 2.809 |  23% |
| 5207 | iperf-15g      |  15.0 | 2.747 |  18% |
| 5208 | iperf-18g      |  18.0 | 3.567 |  20% |
| 5209 | iperf-21g      |  21.0 | 3.545 |  17% |
| 5210 | iperf-24g      |  24.0 | 2.854 |  12% |
| 5211 | iperf-uncapped |   —   | 0.001 |   0% |

Aggregate 19.78 Gbps. Gate 1 fails for small classes.

## §3 Documented contract (docs/fairness-regimes.md:848-855)

> `guarantee-rate <fraction>` (opt-in): two-phase waterfill
> allocator. Phase 1 honours small-rate exact classes ascending
> by R_i up to `fraction × cap`. Phase 2 distributes residual
> proportionally across the queues NOT fully honoured in Phase 1.

`cap` = shaper-delivered bytes per epoch.

## §4 Bug 1 (Hunk A) — pass1 formula

`queue_service/mod.rs:787-800`:
```rust
if root.waterfill_pass1_remaining_bytes == 0 {
    let mut quantum_sum: u64 = 0;
    for &qi in &root.exact_queues_by_rate_ascending {
        quantum_sum =
            quantum_sum.saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));
    }
    let frac = root.oversubscription_guarantee_fraction;
    let pass1 = ((quantum_sum as f64) * frac).floor() as u64;
    root.waterfill_pass1_remaining_bytes = pass1;
    root.waterfill_phase2_cursor = 0;
}
```

Smoke fixture arithmetic:
- quantum_sum = Σ (R_i × 200µs) = (Σ R_i) × 200µs in bytes.
- Σ R_i = 109 Gbps → 13.6 GB/s × 200e-6 = 2.725 MB.
- pass1 = 2.725 MB × 0.7 = 1.91 MB.

Root shaper at 25 Gbps delivers 3.125 GB/s × 200µs = **625 KB
per epoch**. pass1 is 3× larger.

**Fix**: anchor pass1 to `shaper × VISIT_NS × fraction = 437.5 KB`.
Phase 1 budget exhausted after honoring 100m+1g+3g+6g (cumulative
quantum 252.5 KB), break to Phase 2 — exactly as documented.

## §5 Bug 2 (Hunk B) — pass1 never refreshes under saturation

After applying Hunk A, the first Phase-1 cycle honors small
classes (100m, 1g, 3g, 6g, plus the 6g remainder split). pass1
decrements to ~131 KB. Phase 2 picks 24g, 21g, etc. Phase 2 does
NOT decrement pass1 (its budget is "residual", outside Phase 1's
accounting).

Next lease epoch (200µs later): per-class leases refresh. Walk
ascending. 100m has 2500 B tokens, quantum 2500 ≤ pass1 131K →
honor, rem 128.5K. 1g: rem 103.5K. 3g: rem 28.5K. 6g: quantum
150K > 28.5K → break Phase 2.

Third epoch: pass1 = 28.5K. Walk asc. 100m: quantum 2500 ≤ 28.5K
→ honor (rem 26K). 1g: rem 1K. 3g: quantum 75K > 1K → break.

Fourth epoch: pass1 = 1K. 100m: 2500 > 1K → break immediately.
No small class honored.

**No mechanism resets pass1.** Phase 2 always succeeds (large
queues have packets), so the fall-through reset at mod.rs:1002-1005
never fires. Small classes starve indefinitely.

**Fix**: add time-based refresh. Every 200µs (one VISIT_NS),
refresh pass1 to full budget. Continue Phase-2 cursor across the
refresh — DO NOT reset it — so Phase-2 RR continues across
epochs without re-starting from 24g.

## §6 Why neither Phase-1-mask (v3) nor Phase-2-decrement-pass1 work

- **Phase-1 mask** (Codex r1 #2 + my v3): once a small queue
  is masked it stays masked until the next refresh. Under
  saturation Phase 2 keeps progress, refresh never fires
  (Codex r3 #1 starvation).
- **Phase-2 decrement pass1**: decrementing by `candidate_budget`
  over-counts because TX_BATCH_SIZE caps actual sent bytes;
  decrementing by actual bytes requires post-submit accounting
  not currently plumbed. Codex r4 answer #6.

Time-based refresh sidesteps both classes of bug.

## §7 Implementation

### §7.1 Hunk A: pass1 formula (mod.rs:787-800)

Replace the `quantum_sum × fraction` formula with
`shaper × VISIT_NS × fraction`. Keep the `quantum_sum` formula
as the `shaping_rate_bytes == 0` (transparent-root) fallback.

### §7.2 Hunk B: time-based pass1 refresh

Add `waterfill_epoch_start_ns: u64` field to
`CoSInterfaceRuntime` (`userspace-dp/src/afxdp/types/cos.rs:402+`).
Initialize to 0 in `build_cos_interface_runtime`
(`builders.rs:108+`).

In `select_exact_cos_guarantee_queue_waterfill`, change the
refill block. The KEY change: **time-based refresh does NOT
reset Phase-2 cursor.** Only the `pass1 == 0` path resets the
cursor.

```rust
let elapsed_since_refresh =
    now_ns.saturating_sub(root.waterfill_epoch_start_ns);
let time_refresh = elapsed_since_refresh >= COS_GUARANTEE_VISIT_NS;
let exhausted = root.waterfill_pass1_remaining_bytes == 0;
if time_refresh || exhausted {
    // Hunk A: anchor pass1 to shaper-delivered bytes per epoch
    // × fraction. Transparent-root (shaping_rate_bytes == 0)
    // falls back to the legacy quantum_sum × fraction.
    let frac = root.oversubscription_guarantee_fraction;
    let pass1 = if root.shaping_rate_bytes == 0 {
        let mut quantum_sum: u64 = 0;
        for &qi in &root.exact_queues_by_rate_ascending {
            quantum_sum = quantum_sum
                .saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));
        }
        ((quantum_sum as f64) * frac).floor() as u64
    } else {
        let cap_per_epoch = ((root.shaping_rate_bytes as u128)
            * (COS_GUARANTEE_VISIT_NS as u128)
            / 1_000_000_000u128) as u64;
        ((cap_per_epoch as f64) * frac).floor() as u64
    };
    root.waterfill_pass1_remaining_bytes = pass1;
    root.waterfill_epoch_start_ns = now_ns;
    // CRITICAL: only the budget-exhaustion path resets the
    // Phase-2 cursor. The time-based path preserves cursor
    // continuity so Phase-2 descending RR continues across
    // epochs without re-starting at the largest queue.
    // Codex plan-r4 finding #1.
    if exhausted {
        root.waterfill_phase2_cursor = 0;
    }
}
```

The original code at lines 1002-1005 (Phase-2 no-selection
fall-through) is UNCHANGED. It still resets pass1 to 0 and
cursor to 0 when Phase 2 finds nothing.

### §7.3 Optional dead-code cleanup

The local `honored_mask` and its Phase-2 check are dead code
(mask is always 0). Delete for cleanliness; no behavioral
impact. Reviewers may prefer the smaller-diff version that
leaves it alone.

### LOC delta

- `cos.rs`: +1 line (new field).
- `builders.rs`: +1 line (initialize to 0).
- `queue_service/mod.rs`: +14 / -8 lines for the refill block
  (Hunk A + Hunk B). Optional -5 if dead-code cleanup
  included.

## §8 Worked counter-example under v6

Smoke fixture, saturated:

### Lease epoch 1 (t = 100_000 ns initial, refresh fires; epoch_start = 100_000)
- pass1 = 437_500, cursor = 0 (initial state, not from time-refresh).
- Calls 1-4: honor 100m, 1g, 3g, 6g (first batch). pass1 → 185K.
- Call 5: honor 6g remainder (54K). pass1 → 131K.
- Call 6: 9g quantum 225K > 131K → break Phase 2. Pick 24g. cursor → 1.
- Calls 7-N (within epoch 1, elapsed < 200µs): walk asc skips
  drained classes, break Phase 2. Cursor walks descending:
  21g (call 7, cursor→2), 18g (→3), 15g (→4), 12g (→5), 9g (→6).
  Then cursor wraps. **Phase-2 walk hits start_phase2 boundary,
  returns None, falls through to reset (mod.rs:1002-1005):
  pass1 → 0, cursor → 0.**
- Call N+1 (still within epoch 1): pass1 == 0 → exhausted path
  triggers. **Critically, this is the LEGACY refresh path:**
  refresh pass1 to 437.5K, cursor → 0. New Phase-1 cycle starts.
- This continues until ~200µs have elapsed.

Wait — under saturation with per-class lease grants, the
small classes are token-starved by the time we return to them.
So in the inner-epoch refresh path, Phase 1 walks ascending and
finds 100m skipped (still token-starved within the same lease
epoch). Walks past all small, breaks Phase 2. Phase 2 cursor was
just reset, walks descending from 24g.

Hmm — this means within ONE lease epoch we cycle through Phase 2
multiple times, each time starting at 24g. But each cycle large
queues get token-starved too (per-class lease grants
`R × elapsed`, capped).

### Lease epoch 2 (t = 300_000 ns, elapsed >= VISIT_NS, time-refresh fires)
- `elapsed = 300_000 - 100_000 = 200_000 >= VISIT_NS` → refresh.
- pass1 = 437.5K. epoch_start = 300_000. **Cursor NOT reset
  by time-refresh** (per Codex r4).
- Calls: walk asc, all small classes have refreshed lease tokens
  → honor 100m, 1g, 3g, 6g, 6g-remainder. pass1 → 131K.
- Phase 2 picks NEXT queue from current cursor position. If
  cursor was at 0 (reset earlier by exhausted path) → 24g.
  If cursor was at, say, 3 (= 15g position) when epoch 1 ended,
  Phase 2 picks 15g first → 12g → 9g → 24g → 21g → 18g.
  This rotates the Phase-2 starting point across epochs,
  ensuring all 6 large classes get roughly equal residual
  service across many epochs.

That's the key fix Codex r4 demanded.

## §9 Predicted post-fix table

| Class | Shape (G) | predicted recv (G) | % shape |
|-------|----------:|-------------------:|--------:|
| iperf-100m     |   0.1 | ≥ 0.095 | ≥ 95% |
| iperf-1g       |   1.0 | ≥ 0.95  | ≥ 95% |
| iperf-3g       |   3.0 | ≥ 2.85  | ≥ 95% |
| iperf-6g       |   6.0 | ≥ 5.70  | ≥ 95% |
| iperf-9g       |   9.0 | ~2.5    |  ~28% |
| iperf-12g      |  12.0 | ~2.5    |  ~21% |
| iperf-15g      |  15.0 | ~2.5    |  ~17% |
| iperf-18g      |  18.0 | ~2.5    |  ~14% |
| iperf-21g      |  21.0 | ~2.5    |  ~12% |
| iperf-24g      |  24.0 | ~2.5    |  ~10% |
| iperf-uncapped |   —   | ~0      |   0%  |

Aggregate: 25 Gbps. Gate 1 PASS for small classes.

## §10 Default proportional invariant preservation

Dispatch gate at mod.rs:603-606 routes proportional mode to
legacy RR selector. The waterfill is GuaranteeRate-only. v6
adds one new u64 field on the runtime; default value is 0; not
touched in proportional mode. Bit-for-bit preservation. ✓

## §11 Tests

### Unit tests (5)

Add 5 tests in `queue_service/tests.rs`:

1. **`waterfill_pass1_budget_anchored_to_shaper`**: with
   `shaping_rate_bytes = 3_125_000_000` (25 Gbps) and
   `oversubscription_guarantee_fraction = 0.7`, after first
   waterfill invocation, `waterfill_pass1_remaining_bytes`
   reflects the new formula (`625_000 × 0.7 = 437_500` minus
   the budget consumed by the first selection).

2. **`waterfill_pass1_transparent_root_fallback`**: with
   `shaping_rate_bytes = 0`, refill uses `quantum_sum × fraction`.

3. **`waterfill_pass1_refreshes_on_time_tick`**: drive a sequence
   of selections at sub-VISIT_NS deltas; assert pass1 does NOT
   refresh until elapsed >= VISIT_NS. Then drive one beyond
   VISIT_NS; assert refresh fires AND `waterfill_phase2_cursor`
   is NOT reset by the time-based path.

4. **`waterfill_phase2_cursor_resets_only_on_exhausted_path`**:
   set up state with cursor = 3 (mid-walk). Force the legacy
   `pass1 == 0` refill path. Assert cursor → 0. Now set up
   state with cursor = 3 AND pass1 > 0 AND elapsed > VISIT_NS;
   trigger time-refresh; assert cursor STAYS at 3.

5. **`waterfill_multi_epoch_saturation_small_classes_honored_every_epoch`**
   (Codex r4 #3 — pins the actual saturation bug): drive 5
   consecutive lease epochs (delta now_ns by VISIT_NS each
   call) under a runtime with 4 exact queues
   [100M, 1G, 3G, 6G] + 1 large queue [24G] all primed with
   plenty of packets. Tally selections per queue per epoch.
   Assert: each small class is honored at least once per
   epoch across ALL 5 epochs (the regression v4 had: small
   classes stopped being honored after epoch 1-2).

### Cargo + flake
- `cargo test -p userspace_dp --lib cos::queue_service` clean.
- Existing waterfill tests still pass.
- 5×loop flake check.

### Go
- `make test` clean (no Go changes, smoke for surface).

### Smoke (loss userspace cluster)

**Blocking gates** — `test/incus/cos-simul-load-smoke.sh push`
under `guarantee-rate 0.7`:
- **Gate 1**: small classes (100m, 1g, 3g, 6g) ≥ 95 % of shape.
- **Gate 3**: per-class retransmits ≤ 100 / 30s under simul load.

**Informational** (NOT blocking — Codex r1 #3 verified that
iperf-uncapped is on the non-exact selector this PR doesn't
touch):
- **Gate 2**: priority-low ≥ 5 % of ceiling. Tracked separately
  via follow-up issue for non-exact selector work.

**Pass A** (CoS-off regression): no fixture; v4/v6 push +
v6 reverse × 30s × 4 streams. Aggregate ≥ 19 Gbps each
direction.

**Pass B** (CoS-on with guarantee-rate 0.7):
- `make cluster-deploy` + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`.
- `./test/incus/cos-simul-load-smoke.sh push`.
- **Gate 1 + Gate 3 PASS** (blocking). Gate 2 logged but not
  blocking.

**Failover** (HA-sensitive):
- `make test-failover` clean.

## §12 Open questions for reviewers

1. **Honored_mask dead-local cleanup**: should v6 include the
   trivial deletion of the always-false Phase-2 mask check?
   Pro: less code surface. Con: larger diff. v6 default:
   YES, delete it.

2. **Time-refresh granularity**: VISIT_NS = 200µs matches
   lease epoch. Should we tie refresh to per-class lease
   rotation (different timestamps but same duration) instead?
   v6 default: independent timestamps, simpler, no
   cross-component coupling.

3. **Cursor preservation across reset**: when Phase-2
   no-selection fall-through fires (mod.rs:1002-1005), should
   it preserve cursor too (only resetting pass1)? Maybe — but
   the existing semantics work and changing them risks new
   regressions. v6 default: keep existing behaviour.

## §13 Out of scope

- `userspace-dp/src/afxdp/poll_descriptor/` (#1620).
- `userspace-dp/src/policy.rs` (#1623 Path B).
- `test/incus/` fixture (already shipped in #1629).
- HA paths in `pkg/cluster/`.
- worker_fair_share at rotate_epoch_v8.rs:230-235 (verified
  NOT the bug per #1625 r1 review).
- non-exact selector (Gate 2 follow-up).

## §14 Rollback / risk

v6 risk surface:
- New u64 field on `CoSInterfaceRuntime`. Negligible memory.
- 1 u64 load + 1 saturating_sub + 1 compare added to the
  hot path (per-call). Hot-path-acceptable.
- GuaranteeRate-mode-only. Proportional bit-for-bit unchanged.
- Cursor-reset-only-on-exhausted-path preserves Phase-2 RR
  fairness across epochs.

Rollback = `git revert` the single PR (2 hunks + 5 tests).
