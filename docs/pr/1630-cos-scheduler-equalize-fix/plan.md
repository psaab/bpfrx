# Plan v3 — Fix CoS scheduler equalize-bug under guarantee-rate 0.7 (#1630)

> v3 addresses Codex plan-r2 (PLAN-NEEDS-MAJOR, 4 new concerns)
> while preserving v2's resolution of all r1 findings.
>
> Key v3 changes:
> - **§10.2 `queues.len() > 64` runtime fallback**: replace
>   `debug_assert!` with a hard `if root.queues.len() > 64`
>   early-return to the legacy RR selector (Codex r2 #2). This
>   makes the 64-queue invariant safe in release builds too.
> - **§11.5 test made concrete** with explicit rates / shaper /
>   fraction values guaranteed to leave `0 < remainder <
>   smallest_quantum` after honoring all four queues (Codex r2
>   #1).
> - **§11.7 new test** for Phase-2 proportional-residual
>   contract (Codex r2 #3).
> - **§11 Pass B wording** corrected — "Gate 1 + Gate 3 PASS;
>   Gate 2 logged but not blocking" (Codex r2 #4).

> v2 addressed Codex plan-r1 (PLAN-NEEDS-MAJOR, 8 findings),
> AGY plan-r1 (PLAN-NEEDS-MINOR, 3 findings), and Claude SMR
> plan-r1 (PLAN-NEEDS-MINOR, 5 concerns). Key v2 changes:
>
> - **§10 implementation expanded** to fix the dead-local
>   `honored_mask` bypass defect (Codex r1 #2, AGY r1 #1). The
>   `honored_mask` becomes a persistent field on
>   `CoSInterfaceRuntime`, reset only at Phase-1 refill.
> - **§11.3 unit test corrected** for TX_BATCH_SIZE truncation
>   (Codex r1 #4); 6 Gbps quantum is split 96 KB + 54 KB so the
>   break boundary fires after the 6th selection, not the 5th.
> - **Gate 2 (priority-low ≥ 5 % of ceiling) is DEMOTED to
>   informational**, not blocking (Codex r1 #3). Waterfill Phase 2
>   only iterates exact queues; the iperf-uncapped (non-exact)
>   class is serviced by a separate selector and is out of scope.
>   Gate 2 may still improve incidentally but cannot be the
>   contract.
> - **§11 adds 3 new tests** (Codex r1 #5, AGY r1 #3, SMR
>   concern D): fraction proportionality boundary, contract small-
>   class throughput, persistent-mask Phase-2 exclusion.
> - **§4 / §10 drop the cap_eff aside** (Codex r1 #8) —
>   `priority_low_min_share_bytes` is wire-only.
> - **SMR concern A drainage worked example added in §8.5** —
>   confirms iperf-100m reaches 100 Mbps via lease tokens, NOT
>   blocked by TX_BATCH_SIZE for small classes.


## §1 Summary

PR #1629 made the smoke fixture actually activate
`oversubscription-policy guarantee-rate 0.7` and confirmed the
algorithm equalizes ~20% per class instead of honoring small
classes to their full configured rate.

This plan isolates the bug to **one specific arithmetic defect in
the Phase-1 budget formula** at
`userspace-dp/src/afxdp/cos/queue_service/mod.rs:787-800` and
proposes a small, surgical fix that aligns the implementation with
the documented contract.

## §2 Symptom (from PR #1629 measurement)

Under `shaping-rate 25g` + `oversubscription-policy guarantee-rate 0.7`,
all 11 classes get ~12-23 % of their configured shape, aggregate
19.78 Gbps. Small-class guarantee gate fails: iperf-100m gets 19 Mbps
(should be ≥ 95 Mbps), iperf-1g gets 200 Mbps (should be ≥ 950 Mbps).

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

## §3 Documented contract (docs/fairness-regimes.md:848-855)

> **`guarantee-rate <fraction>`** (opt-in): two-phase waterfill
> allocator. Phase 1 honours small-rate exact classes ascending
> by `R_i` **up to `fraction × cap`**. Phase 2 distributes residual
> proportionally across the queues NOT fully honoured in Phase 1.

Here **`cap`** means the per-epoch budget the root shaper actually
delivers — `shaping_rate × epoch_duration`. NOT the sum of
per-queue quanta.

## §4 The defect (queue_service/mod.rs:787-800)

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
```

The refill computes pass1 as `quantum_sum × fraction`, where
`quantum_sum = Σ (R_i × VISIT_NS / 1e9)` over all exact queues.

**For the smoke fixture (11 classes, sum R_i = 109 Gbps,
VISIT_NS = 200 µs, fraction = 0.7):**

```
quantum_sum = (109e9 / 8) × 200e-6      = 2_725_000 bytes
pass1       = 2_725_000 × 0.7           = 1_907_500 bytes
```

But under `shaping-rate 25g`, the root token bucket only delivers
`25e9 / 8 × 200e-6 = 625_000 bytes` per epoch.

**pass1 (1.9 MB) is 3× larger than what the shaper can actually
hand out per epoch.** Consequently:

1. Phase 1 budget never exhausts within a real epoch.
2. Phase 2 (descending residual) never fires.
3. Every queue (small AND large) is honored in Phase 1
   ascending-RR.
4. Per-class lease throttles each class to its own `R_i`-shaped
   rate, but with the root shaper as aggregate bottleneck the
   result is **rate-proportional distribution** — the default
   proportional mode behaviour, NOT the small-first guarantee
   behaviour the operator asked for.

## §5 Why the per-class lease alone doesn't save us

The per-class `SharedCoSQueueLease` (coordinator/mod.rs:1118-1126,
rate = `queue.transmit_rate_bytes`) DOES grant per-class bytes at
the configured rate. iperf-100m's lease grants 100 Mbps worth of
bytes per second. So if iperf-100m had **room** in the root
shaper, it would drain at 100 Mbps.

But under saturation, root tokens are scarce (only 25 Gbps
aggregate). The lease cap = 100 Mbps × elapsed is **soft** — it
caps the upper bound but doesn't reserve capacity from the root
shaper. When Phase 1 walks ascending, iperf-100m IS picked first,
but the selector then walks through every other class too.
Net effect: every class gets sub-rate share, proportional to
configured rate.

## §6 Why #1625's worker_fair_share suspect is NOT the bug

#1625's verdict pointed to `rotate_epoch_v8.rs:230-235`:

```rust
let my_share = ((new_cap as u128) * (my_count as u128) / (total_flows as u128)) as u64;
```

This formula computes a per-worker share of the per-class lease
cap, proportional to active-flow count on that worker. The lease
is **per-class** (one lease per (ifindex, queue_id)), so `cap`
here = `class_rate × elapsed`. Under uniform 12-stream-per-class
load, RSS-spread flows give each worker its proportional slice
of the class rate — this is correct fair-share semantics within
the class. NOT the bug.

The #1625 reviewers' "flow-proportional regardless of class rate"
concern misreads the formula: `new_cap` IS class-rate-aware
because the lease is per-class. (Verified: `acquire_v8` uses
`my_effective_share = worker_fair_share[id]` from the
per-class lease.)

## §7 Why Phase-2 lock-in is NOT the actual bug either

#1625 also suspected `queue_service/mod.rs:889-893` —
the `break` on `candidate_budget > pass1_remaining`. Audit
shows this break IS reachable (when a large queue's quantum
exceeds remaining pass1 budget). But because pass1 budget is
3× over-provisioned (per §4), the break NEVER fires under the
smoke fixture. The selector lives entirely in Phase 1.

The Phase-2 cursor logic (lines 922-1006) is unexercised under
saturation; whether it has its own bugs is a separate concern
that this PR does not touch.

## §8 Worked counter-example for the proposed fix

**Proposed**: change pass1 refill to use the **shaper-delivered
per-epoch byte cap × fraction**:

```rust
let cap_per_epoch = ((root.shaping_rate_bytes as u128)
    * (COS_GUARANTEE_VISIT_NS as u128)
    / 1_000_000_000u128) as u64;
let pass1 = ((cap_per_epoch as f64) * frac).floor() as u64;
```

With `shaping_rate_bytes = 3.125 GB/s`, `VISIT_NS = 200 µs`,
`fraction = 0.7`:

```
cap_per_epoch = 3.125e9 × 200e-6     = 625_000 bytes
pass1         = 625_000 × 0.7        = 437_500 bytes
```

Walking ascending under uniform-12-streams load (queue quanta in
bytes from §4 input):

```
Phase 1 (pass1 = 437_500):
  iperf-100m: q = 2_500   ≤ 437_500   → honor, remaining 435_000
  iperf-1g:   q = 25_000  ≤ 435_000   → honor, remaining 410_000
  iperf-3g:   q = 75_000  ≤ 410_000   → honor, remaining 335_000
  iperf-6g:   q = 150_000 ≤ 335_000   → honor, remaining 185_000
  iperf-9g:   q = 225_000 > 185_000   → BREAK to Phase 2
Phase 2 (descending residual):
  iperf-24g, iperf-21g, iperf-18g, iperf-15g, iperf-12g,
  iperf-9g serviced round-robin from remaining 185 K + Phase 2
  uses 64-packet TX_BATCH_SIZE caps.
```

Across many cycles per second:
- Small classes (100m, 1g, 3g, 6g) drain at their per-class lease
  rates (100M, 1G, 3G, 6G), totalling **10.1 Gbps** of guaranteed
  delivery — well within the 25 Gbps × 0.7 = 17.5 Gbps Phase 1
  budget envelope.
- Large classes (9g, 12g, 15g, 18g, 21g, 24g) share the
  **residual 14.9 Gbps** (25 − 10.1) via Phase 2 descending RR,
  yielding roughly 2.0-2.6 Gbps each (the existing measurement
  already shows this for these classes; they don't need to
  change).

### §8.5 Drainage worked example — does iperf-100m actually reach ≥ 95 Mbps?

The per-class lease (rate 100 Mbps = 12.5 MB/s) grants
`rate × elapsed` per 200 µs epoch = 2500 bytes per epoch. With MTU
1500 the steady-state pattern (Codex r1 worked counter-example):

```
Epoch A: grant 2500 → tokens 2500, send 1500, carry 1000
Epoch B: grant 2500 → tokens 3500, send 3000 (2 packets), carry 500
Epoch C: grant 2500 → tokens 3000, send 3000 (2 packets), carry 0
```

7500 bytes per 600 µs = 12.5 MB/s = **100 Mbps**. TX_BATCH_SIZE
(64 packets ≈ 96 KB) is NOT binding for any class with quantum
< 96 KB. The 6 Gbps class (quantum 150 KB) IS truncated:
selection 1 sends 96 KB, selection 2 sends remaining 54 KB.

So gate 1 (small classes ≥ 95 % of shape) is achievable for
{100m, 1g, 3g, 6g} under the fix.

**Expected post-fix table** (push, 12 streams × 11 classes × 30s,
target shaping 25g, guarantee-rate 0.7):

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

Aggregate predicted = 10.1 + 14.9 = 25 Gbps (root shaper full
utilization).

Gate 1 (small classes ≥ 95 % of shape) **PASS** for iperf-100m,
iperf-1g, iperf-3g, iperf-6g.

## §9 Default proportional invariant preservation

`select_exact_cos_guarantee_queue_with_lease_telemetry` (mod.rs:589-614)
**dispatches** to the waterfill selector only when:

```rust
matches!(root.oversubscription_policy, CoSOversubscriptionPolicy::GuaranteeRate)
    && root.oversubscription_guarantee_fraction > 0.0
```

Default policy is `CoSOversubscriptionPolicy::Proportional`, so
the legacy RR selector at mod.rs:619-738 is bit-for-bit
unchanged. **No fix code touches the proportional path.** Audit:

- The change at mod.rs:787-800 is INSIDE
  `select_exact_cos_guarantee_queue_waterfill` (mod.rs:771)
  which only runs in GuaranteeRate mode.
- No other function in mod.rs reads or writes
  `waterfill_pass1_remaining_bytes` or
  `waterfill_phase2_cursor`.

This satisfies the default-off invariant codified in
docs/fairness-regimes.md §"Bit-for-bit preservation".

## §10 Implementation

Two hunks: the pass1 refill formula AND the persistent honored
mask. The first is the primary fix; the second is required
because the smaller pass1 budget makes the Phase-1→Phase-2 break
hot and the current `honored_mask` is a dead local that allows
already-honored small queues to be re-serviced in Phase-2's
descending walk (Codex r1 #2, AGY r1 #1).

### §10.1 Hunk A: pass1 refill formula (queue_service/mod.rs:787-800)

Replace the `quantum_sum` accumulation with a
direct `shaping_rate × VISIT_NS × fraction` budget. The
`COS_GUARANTEE_VISIT_NS` constant is already imported at top of
file. Use `u128` arithmetic for the rate × time product (matches
the rotate_epoch_v8 pattern at line 220-221).

Skeleton diff:

```rust
-    if root.waterfill_pass1_remaining_bytes == 0 {
-        let mut quantum_sum: u64 = 0;
-        for &qi in &root.exact_queues_by_rate_ascending {
-            quantum_sum =
-                quantum_sum.saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));
-        }
-        let frac = root.oversubscription_guarantee_fraction;
-        let pass1 = ((quantum_sum as f64) * frac).floor() as u64;
-        root.waterfill_pass1_remaining_bytes = pass1;
-        root.waterfill_phase2_cursor = 0;
-    }
+    if root.waterfill_pass1_remaining_bytes == 0 {
+        // #1630 fix: pass1 budget = shaper-delivered bytes per
+        // visit × guarantee_fraction. Previously summed per-queue
+        // quanta, which under realistic configs (sum R_i ≫ shaper)
+        // produced a pass1 budget many times larger than the
+        // shaper can actually deliver per epoch — Phase 2 never
+        // fired and small classes never got their guarantee.
+        // The new formula matches the documented contract
+        // (docs/fairness-regimes.md "ascending up to fraction × cap").
+        //
+        // Transparent-root (shaping_rate_bytes == 0) preserves
+        // the legacy quantum_sum behaviour because there is no
+        // root-shaper budget to anchor against — the per-class
+        // leases still throttle each class to its own rate.
+        let frac = root.oversubscription_guarantee_fraction;
+        let pass1 = if root.shaping_rate_bytes == 0 {
+            let mut quantum_sum: u64 = 0;
+            for &qi in &root.exact_queues_by_rate_ascending {
+                quantum_sum = quantum_sum.saturating_add(
+                    cos_guarantee_quantum_bytes(&root.queues[qi]),
+                );
+            }
+            ((quantum_sum as f64) * frac).floor() as u64
+        } else {
+            let cap_per_epoch = ((root.shaping_rate_bytes as u128)
+                * (COS_GUARANTEE_VISIT_NS as u128)
+                / 1_000_000_000u128) as u64;
+            ((cap_per_epoch as f64) * frac).floor() as u64
+        };
+        root.waterfill_pass1_remaining_bytes = pass1;
+        root.waterfill_phase2_cursor = 0;
+    }
```

### §10.2 Hunk B: persistent honored mask (cos.rs + mod.rs)

Add a `waterfill_honored_mask: u64` field to `CoSInterfaceRuntime`
(`userspace-dp/src/afxdp/types/cos.rs:402+`, alongside the other
waterfill state). Initialize to 0 in
`build_cos_interface_runtime` (`builders.rs:108+`).

In `select_exact_cos_guarantee_queue_waterfill`:
- Replace the local `let mut honored_mask: u64 = 0;` (mod.rs:806)
  with reading `root.waterfill_honored_mask`.
- At Phase-1 refill (mod.rs:787-800), reset
  `root.waterfill_honored_mask = 0` alongside the pass1 refill.
- At Phase-1 honor (mod.rs:899-901), write the persistent field:
  `root.waterfill_honored_mask |= 1u64 << queue_idx` (only when
  `queue_idx < 64`).
- Phase-2's `(honored_mask & (1u64 << queue_idx)) != 0` check
  (mod.rs:938) now reads the persistent field via local
  shadowing, so already-honored small queues are correctly
  excluded from Phase-2 RR.
- **Codex r2 #2**: queues with `queue_idx >= 64` cannot be
  bit-tracked by the u64 mask. Rather than rely on `debug_assert!`
  (disappears in release), v3 adds a HARD RUNTIME FALLBACK at the
  top of `select_exact_cos_guarantee_queue_waterfill`:

  ```rust
  // #1630 r2 safety: bitmask honored-set has u64 capacity.
  // Deployments above 64 exact queues fall back to legacy RR.
  // (Junos hardware ceiling is 8-16; this is purely defensive.)
  if root.exact_queues_by_rate_ascending.len() > 64 {
      return None; // dispatch caller falls through to legacy RR
  }
  ```

  The caller (`select_exact_cos_guarantee_queue_with_lease_telemetry`
  at mod.rs:589-614) handles `None` from the waterfill by NOT
  dispatching it again — but the OUTER service loop will
  not re-invoke; we need the caller to fall through to legacy
  RR. Implementation note: the cleanest way is to NOT dispatch
  waterfill when `queues.len() > 64`; modify the dispatch gate
  at mod.rs:603-614:

  ```rust
  if matches!(root.oversubscription_policy, CoSOversubscriptionPolicy::GuaranteeRate)
      && root.oversubscription_guarantee_fraction > 0.0
      && root.exact_queues_by_rate_ascending.len() <= 64  // <-- v3 safety guard
  {
      return select_exact_cos_guarantee_queue_waterfill(...);
  }
  // legacy RR continues below
  ```

  Plus a `debug_assert!` inside the waterfill body for belt-and-braces.

Estimated LOC delta: +28 / -10 in mod.rs, +1 in cos.rs, +1 in
builders.rs. No new files. One new u64 runtime field.

## §11 Test plan

### Unit tests
Add 6 tests in `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:

1. **`waterfill_pass1_budget_anchored_to_shaper`**: with
   `shaping_rate_bytes = 3_125_000_000` (25 Gbps) and
   `oversubscription_guarantee_fraction = 0.7`, the
   `waterfill_pass1_remaining_bytes` after first refill must
   equal `437_500` (within ±1 byte for floor rounding), NOT
   the much larger `quantum_sum × 0.7` value.

2. **`waterfill_pass1_budget_transparent_root_fallback`**: with
   `shaping_rate_bytes = 0`, pass1 budget must fall back to
   `quantum_sum × fraction` (matches existing pre-fix
   behaviour for transparent-root configs).

3. **`waterfill_phase2_engages_after_full_smoke_burn`**:
   construct a 5-queue runtime with rates [100M, 1G, 3G, 6G,
   9G], shaper 25G, fraction 0.7 (smoke-fixture shape). After
   the appropriate number of exact selections (accounting for
   TX_BATCH_SIZE truncation of the 6G class into 96 KB + 54 KB
   selections — total 6 ascending exact selections to fully
   honor 100m+1g+3g+6g), the next call must return a Phase-2
   descending selection (picks queue_idx of the 9G class first
   since it's the only remaining at descending start). Per
   Codex r1 #4: the 5th call still returns a Phase-1 honor of
   the 6G remainder, not a Phase-2 pick.

4. **`waterfill_pass1_budget_fraction_proportional`** (Codex r1
   #5, AGY r1 #3, SMR D): for the same shaper (25 G) and
   fractions ∈ {0.0, 0.2, 0.5, 0.7, 1.0}, the
   `waterfill_pass1_remaining_bytes` after first refill must
   scale exactly linearly with fraction (within ±1 byte). At
   fraction == 0.0 the dispatch gate (mod.rs:603-606) must
   route to legacy RR, not waterfill — so a separate assert
   confirms `waterfill_pass1_remaining_bytes` stays 0 (no
   refill happened).

5. **`waterfill_persistent_honored_mask_excludes_phase2`**
   (Codex r1 #2 + r2 #1, AGY r1 #1): construct an
   **explicitly-sized** 4-queue runtime guaranteed to leave
   `0 < pass1_remaining < smallest_quantum` after honoring
   all four queues. Concrete config:
   - Queue rates: `[100M, 1G, 3G, 6G] bps`
     → quanta = `[2500, 25_000, 75_000, 150_000] B`
   - `shaping_rate_bytes = 781_250` (≈ 6.25 Gbps, byte form)
     → cap_per_epoch = `781_250 × 200_000 / 1e9 = 156.25 B`
     ... too tight; use higher shaper.
   - Adjusted: `shaping_rate_bytes = 1_350_000_000` (10.8 Gbps),
     `fraction = 0.25`
     → cap_per_epoch = `1_350_000_000 × 200_000 / 1e9 = 270_000 B`
     → pass1 = `270_000 × 0.25 = 67_500 B`
   - After honoring `[2500, 25000, 75000]` Phase-1 walk consumes
     `102_500 B`. Since pass1=67_500 < 102_500, Phase-1 break
     fires at queue index 2 (`75000 > 67500-2500-25000=40000`).
     → Only 2 queues honored, not 4.

   **Corrected config**:
   - rates `[100M, 1G, 3G, 6G]`, `shaping_rate_bytes = 3_125_000_000`
     (25 Gbps), `fraction = 0.6`
   - cap_per_epoch = 625_000 B, pass1 = 375_000 B
   - Walk: 2500 (rem 372_500) → 25_000 (rem 347_500) →
     75_000 (rem 272_500) → 150_000 (rem 122_500).
   - All four honored, `pass1_remaining = 122_500`.
     Smallest quantum = 2500. So `0 < 122_500 < 2500` is FALSE —
     remainder is LARGER than smallest quantum, so the next
     ascending walk would honor iperf-100m AGAIN.

   **Final config** that produces the desired state:
   - rates `[100M, 1G, 3G, 6G]`, shaper 25 Gbps, fraction = 0.41
   - pass1 = 625_000 × 0.41 = 256_250 B
   - Walk: 2500 → 25_000 → 75_000 → 150_000 = 252_500 B
   - Remaining = `256_250 - 252_500 = 3_750 B`. Smallest
     quantum = 2500. `0 < 3_750 < 25_000` (next-ascending
     quantum after iperf-100m would be empty in this test —
     we drain iperf-100m queue first). So the next call walks
     ascending, finds iperf-100m queue EMPTY (we drained it
     across the 4 prior selections), then iperf-1g (next
     ascending) — but quantum 25_000 > remaining 3_750 →
     **break to Phase 2**.

   **The test then drives Phase-2.** Without the persistent
   mask, Phase-2 would pick a queue that was already honored
   in Phase-1; WITH the mask, Phase-2 walks descending and
   finds all 4 marked honored → returns `None`. Assert:
   Phase-2 returns `None` because all 4 queues are masked.

   To make the test reliable, the queues all start with
   exactly enough packets to drain in one Phase-1 honor and
   no more — so empty-queue skip + mask check both contribute.
   Test prims queue 0 (iperf-100m) with 1 packet, queue 1 (1g)
   with 1, queue 2 (3g) with 1, queue 3 (6g) with 1. After 4
   selections, all four are EMPTY. 5th call refills pass1?
   No — pass1 = 3_750 > 0, no refill. Walk ascending, all 4
   queues empty → skip → continue. No Phase-1 selection
   possible. Fall through to Phase-2 walk. **With the mask,
   the descending walk sees all 4 marked honored and returns
   `None`** (also because they're empty). To distinguish
   mask-vs-empty: prim queue 0 (iperf-100m) with 2 packets
   so it has a remaining packet after the first honor. Then
   the 5th call: ascending walk, queue 0 not empty, runnable,
   quantum 2500 ≤ pass1 3750 → honored AGAIN (without mask).
   With mask: queue 0 marked honored → ascending walk should
   skip it? NO — current code doesn't check mask in Phase 1
   ascending walk. Mask is only checked in Phase 2.

   **This reveals a bigger issue: the mask doesn't help if
   Phase-1 re-picks the same small queue.** Codex r2 #1 is
   correctly identifying this. The fix design is INCOMPLETE.

   **v3 resolution**: the persistent mask MUST also gate the
   Phase-1 ascending walk: skip queues already honored this
   epoch. Then the ascending walk advances to the NEXT-rate
   queue. This was implicit in the AGY r1 "honor each queue
   once per epoch" recommendation.

   Update §10.2 implementation accordingly: in the Phase-1
   ascending walk (mod.rs:807-911), add a mask check BEFORE
   the runnable/non-empty checks:

   ```rust
   for queue_idx in &sorted_indices {
       let queue_idx = *queue_idx;
       if queue_idx < 64
           && (root.waterfill_honored_mask & (1u64 << queue_idx)) != 0
       {
           continue;  // already honored this epoch
       }
       /* existing runnable / non-empty / token checks ... */
   }
   ```

   With this, test 5 becomes deterministic:
   - 4 Phase-1 selections honor each queue once.
   - 5th call: ascending walk skips all 4 (mask set) → falls
     to Phase-2 walk → also skips all 4 (mask set) →
     returns `None`.

   This change increases the LOC delta by ~3 lines but
   resolves Codex r2 #1 cleanly.

6. **`waterfill_proportional_mode_bypass_under_zero_fraction`**:
   `policy = GuaranteeRate, fraction = 0.0` must dispatch to
   legacy RR per the gate condition at mod.rs:603-606. Assert
   neither `waterfill_pass1_remaining_bytes` nor
   `waterfill_honored_mask` mutate after a selection.

7. **`waterfill_phase2_distributes_residual_proportionally`**
   (Codex r2 #3): construct a 6-queue runtime where the four
   smallest are honored in Phase-1 and the two largest go to
   Phase-2 descending. Drive many selections (e.g., 100)
   across multiple epochs. Tally bytes per queue. Assert
   that the two Phase-2 queues' byte allocation ratio matches
   their rate ratio to within ±10 % — proving Phase-2
   residual IS proportional, not equal. Without this test,
   the documented contract "Phase 2 distributes residual
   proportionally" is unverified.

8. **`waterfill_fallback_to_legacy_rr_when_more_than_64_queues`**
   (Codex r2 #2): construct an interface runtime with 65
   exact queues. Assert that `select_exact_cos_guarantee_queue_with_lease_telemetry`
   dispatches to legacy RR (NOT waterfill), and
   `waterfill_pass1_remaining_bytes` stays 0 (no waterfill
   refill ever happened).

### Cargo + flake
- `cargo test -p userspace_dp --lib cos::queue_service` clean.
- Existing 3 waterfill tests pass without modification (proves
  no regression on transparent-root semantics).
- 5×loop flake check: `for i in 1..=5 { cargo test ... }`.

### Go
- `make test` clean (no Go code touched, but smoke for surface
  changes).

### Smoke (loss userspace cluster)

**Blocking gates** — `test/incus/cos-simul-load-smoke.sh push`
under `guarantee-rate 0.7`:

- **Gate 1 (BLOCKING)**: small classes (100m, 1g, 3g, 6g)
  ≥ 95 % of shape. This is the primary contract.
- **Gate 3 (BLOCKING)**: per-class retransmits ≤ 100 / 30 s under
  simul load. The CoDel-style AQM already in-tree should keep
  this in line once equalization stops; if it doesn't, file a
  follow-up.

**Informational** (NOT blocking per Codex r1 #3):

- **Gate 2 (INFORMATIONAL)**: priority-low (iperf-uncapped at
  port 5211) ≥ 5 % of cluster ceiling. The waterfill selector
  iterates exact queues ONLY (mod.rs:945-950); iperf-uncapped
  is a non-exact class serviced by
  `select_nonexact_cos_guarantee_batch` (mod.rs:1014-1069).
  This fix doesn't change non-exact scheduling. Gate 2 may
  improve incidentally if total exact throughput drops (more
  root tokens flow to the non-exact path), but it cannot be the
  contract for THIS PR. A follow-up issue should track Gate 2
  with the non-exact path as the target.

**Pass A** (CoS-off, fairness regression):
- `make cluster-deploy` (no CoS apply) + `iperf3 -c 172.16.80.200`
  v4 push, v4 -R, v6 push, v6 -R × 30s × 4 streams each.
- Aggregate ≥ 19 Gbps each direction (matches Phase 0 ceiling).

**Pass B** (CoS-on with guarantee-rate 0.7):
- `make cluster-deploy` then
  `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`.
- `./test/incus/cos-simul-load-smoke.sh push` × 30s.
- **Gate 1 + Gate 3 PASS** (blocking). Gate 2 logged but not
  blocking (Codex r2 #4 — Gate 2 is informational since
  iperf-uncapped is on the non-exact path which this PR
  doesn't touch; tracked in follow-up issue).

**Failover** (HA-sensitive):
- `make test-failover` clean (this PR doesn't touch HA but
  CoS-touching changes require it).

## §12 Open questions for reviewers

1. **`priority_low_min_share_bytes` subtraction** — confirmed
   out of scope. Per Codex r1 #8 and the inline doc at
   `userspace-dp/src/afxdp/types/cos.rs:386-401`, this field is
   wire-only ("Today no hot-path code consults this field"). No
   subtraction needed. Tracked separately.

2. **Transparent-root semantics**: with `shaping_rate_bytes = 0`
   there is no root-shaper budget to anchor to. The plan falls
   back to the old `quantum_sum × fraction` formula. Is that
   the right choice, or should transparent-root config simply
   refuse to enter GuaranteeRate mode (force back to
   Proportional)?

3. **Phase 1 "honor once per epoch" question**: the current
   selector picks ONE queue per call. A queue can be picked
   multiple times before pass1_remaining decrements enough
   to reach the next ascending queue. With the smaller pass1
   budget the per-class lease at iperf-100m (2500 B/epoch
   grant) should naturally limit per-class repicks because
   the queue gets parked on `queue.hot.tokens < head_len`.
   But under jumbo frames or short bursts this could matter.
   Do we need a persistent `phase1_consumed[idx]` mask too?

4. **Bug-not-here check**: is there a third, deeper bug we
   haven't isolated? Specifically: under the proposed fix, do
   small classes ACTUALLY reach ≥ 95% of shape, or is there
   another constraint we haven't accounted for (e.g.,
   TX_BATCH_SIZE = 64 packets capping iperf-100m to 1 packet
   per visit independent of quantum)? The worked example in §8
   assumes per-class lease grants per-epoch are honored; if
   `acquire_v8` has a separate equalization defect we'd see
   the smoke gates still fail post-deploy.

5. **AGY r1's jumbo-frame Phase-1 starvation concern**
   (#1625): the `break` at line 893 abandons all subsequent
   smaller-rate queues if ANY one queue's quantum exceeds
   remaining pass1 budget. With the corrected (smaller) pass1
   budget, this is more likely to fire than before. Is that
   a regression risk? Mitigation: change `break` to `continue`
   (skip this queue, try the next one). Out of scope unless
   the smoke shows it.

## §13 Out of scope

- `userspace-dp/src/afxdp/poll_descriptor/` (#1620 sub-agent).
- `userspace-dp/src/policy.rs` (#1623 Path B narrow).
- `test/incus/` fixture or harness changes (#1626 prerequisite).
- HA paths in `pkg/cluster/`.
- Phase 2 cursor logic in mod.rs:922-1006 (unexercised under
  current symptom; separate audit out of scope).
- worker_fair_share math at rotate_epoch_v8.rs:230-235
  (verified NOT the bug per §6).

## §14 Rollback / risk

Single hunk, default-off path. Risk surface:
- GuaranteeRate mode (opt-in) only. Proportional mode bit-for-bit
  unchanged.
- Transparent-root fallback preserves prior behaviour.
- The smaller pass1 budget could surface latent bugs in
  Phase 2 cursor logic. Smoke covers this by exercising the
  Phase 2 descending walk for the first time under real load.

Rollback = `git revert` the single-hunk PR.

## §15 Reviewer dispatch

- Plan-r1: Codex (hostile, embedded files), AGY adversarial,
  Claude SMR.
- 3-of-3 agreement required for PLAN-READY.
- Code-r1 after implementation: Codex + AGY + Claude SMR +
  Copilot (via @copilot review). 4-of-4 for MERGE-READY.
- Hostile bias: prove the bug ISN'T at queue_service:889-893
  (the #1625 suspect that this plan deprioritizes), prove the
  fix produces the predicted §8 distribution, and prove no
  regression on transparent-root or proportional mode.
