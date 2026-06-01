# Plan v1 — CoS waterfill: anchor Phase-1 budget to shaped cap + stable honor charge + time refresh (#1743)

**Status: DRAFT v1 — pending adversarial plan review**

## §1 Issue framing

Operator reports per-flow CoV too high on high-shape exact CoS
queues (iperf-21g/24g, ports 5209/5210) after this session's CoS
merges. Live telemetry: the waterfill selector's `phase2_admit=0`
— the surplus-distribution phase never admits — so the residual
capacity left after Phase-1 honors is never equalized across the
large un-honored classes. Codex root-caused it to the Phase-1
budget accounting in
`userspace-dp/src/afxdp/cos/queue_service/mod.rs`.

This is the same defect class as #1630 (CLOSED) — but #1630's fix
branch (`fix/1630-cos-scheduler-equalize` @ `57b355226`) was NEVER
merged to master. #1732/PR #1737 ("persistent honored set") landed
on master WITHOUT the #1630 pass1-anchor/time-refresh. The two
diverged: master carries #1732 (persistent `waterfill_honored_
epoch_bits`) + the #1630 P1/P2 send-budget frame-cap split, but
NOT the #1630 Hunk A (shaper-anchored pass1) nor Hunk B (time
refresh). The result is the regression re-surfacing at high shape.

## §2 Honest scope / value framing

This is a correctness fix for an opt-in feature
(`oversubscription-policy guarantee-rate <fraction>`). Default
behaviour (Proportional) is bit-for-bit unchanged via the dispatch
gate. The win is restoring the documented fairness contract
(small classes honored to ≥95% of configured rate; residual
equalized across large classes) at high shape, which the operator
empirically lost. The cost is ~3 small arithmetic/timing hunks +
one new per-binding runtime `u64` field + unit tests. The hot path
gains one `saturating_sub` + one compare per selector call (the
elapsed-time check) — negligible.

If reviewers conclude the root-cause does not hold up against the
live bisect, PLAN-KILL is an acceptable verdict — the validation
gate (§9) is mandatory before any merge.

## §3 What's already shipped / partially landed

- **#1732 (master)**: persistent `waterfill_honored_epoch_bits`
  (u64, keyed by ascending-vec ordinal), read+set by BOTH phases,
  cleared at the `pass1 == 0` lazy refill (mod.rs:814). This is
  CORRECT and MUST be preserved — do NOT revert it.
- **#1630 P1/P2 (master)**: the per-visit `send_budget` /
  `candidate_budget` frame-count cap (`cos_guarantee_visit_cap_
  bytes()`), decoupled from the Phase-1 rate-scaled quantum. Kept.
- **#1630 Hunk A/B (NOT on master)**: shaper-anchored pass1 +
  time-based refresh. This plan re-lands these on top of #1732.
- **v8 lease** (`maybe_top_up_cos_queue_lease`): per-binding
  runtime token grant. Preserved; this plan does not touch it.

## §4 Confirmed root cause (verified against master e4556085a)

### Point 1 — Phase-1 budget over-provisioned (mod.rs:793-805)
```rust
if root.waterfill_pass1_remaining_bytes == 0 {
    let mut quantum_sum: u64 = 0;
    for &qi in &root.exact_queues_by_rate_ascending {
        quantum_sum = quantum_sum.saturating_add(
            cos_guarantee_quantum_bytes(&root.queues[qi]));
    }
    let frac = root.oversubscription_guarantee_fraction;
    let pass1 = ((quantum_sum as f64) * frac).floor() as u64;
    ...
}
```
For the smoke fixture (Σ R_i = 109 Gbps over 11 classes, shaper
25 Gbps, fraction 0.7): `quantum_sum × frac ≈ 1.91 MB` vs the
shaper-delivered `cap × frac = 25e9/8 × 200µs × 0.7 = 437.5 KB`.
Phase-1 budget is ~4.24× the bytes the root can deliver per epoch
→ Phase-1 honors EVERY class → Phase-2 never reached. **CONFIRMED.**

### Point 2 — Phase-1 honor undercharged (mod.rs:941-945, :956, :975-976, :1023-1025)
```rust
let phase1_cost = queue.hot.tokens
    .min(cos_guarantee_quantum_bytes(queue))
    .max(head_len);
...
if phase1_cost > root.waterfill_pass1_remaining_bytes { break; }
...
root.waterfill_pass1_remaining_bytes =
    root.waterfill_pass1_remaining_bytes.saturating_sub(phase1_cost);
if i < 64 { root.waterfill_honored_epoch_bits |= 1u64 << i; }
```
The `.min(queue.hot.tokens)` couples the *honor charge* to the
queue's depleted lease tokens. Under v8-lease pressure
`queue.hot.tokens` collapses toward one frame, so `phase1_cost`
falls to `head_len` — passes the budget gate trivially, charges
almost nothing against pass1, yet **marks the queue fully honored**
(:975-976). Phase-2 then skips it (:1023-1025). The honor charge
should be the *stable configured quantum*, not the depleted token
count. **CONFIRMED.** (Note: the per-visit SEND budget correctly
stays token-clamped at :946-950 — only the honor-decision charge
is wrong.)

### Point 3 — #1732 exposed, did not introduce
Pre-#1732 (`70530498c`) used a function-local mask that was empty
when Phase-2 ran, so Phase-2 admitted anyway (accidentally masking
the bad accounting). #1732's persistent bits are correct and
unmasked the latent Phase-1 over-honor → Phase-2 genuinely dies.
**CONFIRMED** (#1737 = 660ecf019 on master; #1630 branch not
merged). **Do NOT revert #1732.**

### No time refresh on master
Master only refreshes pass1 on the `pass1 == 0` exhausted path.
Under saturation, Phase-2 does not decrement pass1, so once pass1
sits at a small positive value it never refills — small classes
starve across epochs (the #1630 Hunk B regression). On master this
is partially shadowed by the honored-bits clear only firing on the
exhausted path; combined with the over-budget it produces the
observed `phase2_admit=0`. A time refresh is required for
correctness and is the carrier for clearing the honored bits each
epoch.

## §5 Fix design (3 hunks)

### Hunk A — anchor pass1 to shaped cap (mod.rs:793-818)
```rust
let frac = root.oversubscription_guarantee_fraction;
let pass1 = if root.shaping_rate_bytes == 0 {
    // transparent (unshaped) root: no shaper-delivered cap to
    // anchor against — keep the legacy quantum_sum × fraction.
    let mut quantum_sum: u64 = 0;
    for &qi in &root.exact_queues_by_rate_ascending {
        quantum_sum = quantum_sum.saturating_add(
            cos_guarantee_quantum_bytes(&root.queues[qi]));
    }
    ((quantum_sum as f64) * frac).floor() as u64
} else {
    let cap_per_epoch = ((root.shaping_rate_bytes as u128)
        * (COS_GUARANTEE_VISIT_NS as u128) / 1_000_000_000u128) as u64;
    ((cap_per_epoch as f64) * frac).floor() as u64
};
```
(`root.shaping_rate_bytes` is bytes/s — same unit
`cos_guarantee_quantum_bytes` divides by 1e9 with VISIT_NS; the
cap is bytes/epoch.)

### Hunk B — stable Phase-1 honor charge (mod.rs:941-945)
```rust
// honor charge = STABLE configured quantum (not depleted tokens),
// so a token-starved small queue is charged its full guaranteed
// share and is not falsely "fully honored" for one frame.
let phase1_cost = cos_guarantee_quantum_bytes(queue).max(head_len);
```
The per-visit `send_budget` at :946-950 (token-clamped frame cap)
is UNCHANGED — only the honor/budget-gate charge changes.

### Hunk C — time-based refresh + honored-bits clear (mod.rs:793-818)
Add field `waterfill_epoch_start_ns: u64` to `CoSInterfaceRuntime`
(types/cos.rs), init 0 in `build_cos_interface_runtime`
(builders.rs) + all test literals. Refill trigger:
```rust
let elapsed = now_ns.saturating_sub(root.waterfill_epoch_start_ns);
let time_refresh = elapsed >= COS_GUARANTEE_VISIT_NS;
let exhausted = root.waterfill_pass1_remaining_bytes == 0;
if time_refresh || exhausted {
    root.waterfill_pass1_remaining_bytes = pass1; // (Hunk A)
    root.waterfill_epoch_start_ns = now_ns;
    root.waterfill_honored_epoch_bits = 0;   // clear EACH epoch
    root.waterfill_epochs = root.waterfill_epochs.wrapping_add(1);
    if exhausted {
        root.waterfill_phase2_cursor = 0;    // ONLY exhausted resets cursor
    }
}
```
**CRITICAL invariants:**
1. Honored bits cleared on BOTH refresh paths (master only clears
   on exhausted — without this the time refresh leaves stale
   honored bits and both phases skip honored queues forever; this
   is the #1732-interaction wrinkle the #1630 branch never had).
2. Phase-2 cursor reset ONLY on the exhausted path (Codex #1630
   r4 invariant — resetting on every timed refresh starves classes
   deep in the descending walk).
3. `waterfill_epochs` bump moves into the shared `if` so the
   counter still increments once per refresh on either path.

## §6 Public API preservation
No public signatures change. `select_exact_cos_guarantee_queue_
waterfill` keeps its `(root, queue_fast_path, now_ns,
lease_telemetry)` signature. The Proportional dispatch gate is
untouched.

## §7 Hidden invariants preserved
- **#1732 persistent honored bits** preserved; cleared once per
  epoch on EITHER refresh path (single clear point semantics
  maintained — both epoch-exit paths funnel through the refill).
- **Side-effect ordering**: honor charge → mark honored → advance
  RR → telemetry → return, unchanged.
- **Allocation**: no heap alloc added; iterates the persistent
  ascending vec by index (no clone).
- **HA portability**: `waterfill_epoch_start_ns` is per-binding
  worker-local runtime, NOT HA-synced (grep of pkg/cluster shows
  zero waterfill references) — same class as the existing
  `waterfill_pass1_remaining_bytes`/`_phase2_cursor`/`_honored_
  epoch_bits`. No session-sync wire change; `make test-failover`
  not strictly required but will be run if time permits since the
  field is fresh.
- **Borrow shape**: `now_ns` is `Copy u64` read before any `&mut
  root.queues` borrow; bit set uses ordinal `i` copied out.
- **>64-queue guard**: ordinal `< 64` shift guards unchanged.

## §8 Risk assessment
| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | Opt-in path only; Proportional unchanged. Validated by live bisect + #1217 gate. |
| Lifetime / borrow | LOW | One new scalar field; no new borrows. |
| Performance | LOW | +1 sub +1 cmp per selector call; no alloc. Best-effort fast path (CoS-off) untouched. |
| Architectural mismatch | LOW | Re-lands a 5-round-reviewed #1630 design adapted to #1732; not a new architecture. |

## §9 Validation gate (MANDATORY — the crux)
1. **Confirm regression**: deploy `70530498c` (pre-#1732) vs
   `e4556085a` (current master) on loss:xpf-userspace-fw0, reapply
   CoS, verify classifier counters increment, compare
   `phase2_admit` + iperf3 per-stream CoV at ports 5209/5210 -P12.
   Expected: pre-#1732 phase2_admit>0; current=0.
2. **Confirm fix**: deploy fixed build → phase2_admit MUST go >0
   AND iperf3 per-stream CoV at high shapes MUST drop materially
   vs current master. If phase2_admit stays 0 OR CoV doesn't
   improve → STOP, report BLOCKED, do NOT merge.
3. **Ground truth = iperf3 per-stream throughput CoV** (compute
   from [N] sender lines). Do NOT trust cos_active_flow_count
   (#1741). Validate counter sums vs known stream count.
4. Full CoS smoke matrix (v4/v6 × push/reverse × CoS-off/on ×
   per-class) + #1217 structural-CoV gate. MUST NOT regress
   aggregate throughput or the best-effort fast path (#1183:
   CoS-off -P12 -R line rate).

## §10 Test plan
- `cargo build` clean.
- New unit tests pinning each hunk:
  - `waterfill_pass1_anchored_to_shaper_per_epoch` (Hunk A)
  - `waterfill_pass1_transparent_root_fallback_to_quantum_sum`
  - `waterfill_phase1_honor_charge_is_configured_quantum_not_tokens`
    (Hunk B — token-starved small queue still charged full quantum,
    still admits in Phase-2 if not honored)
  - `waterfill_pass1_refreshes_on_time_tick_clears_honored_bits`
    (Hunk C — honored bits cleared on timed refresh)
  - `waterfill_phase2_cursor_only_resets_on_exhausted_path`
    (cursor preservation invariant)
- Existing waterfill + worker CoS test literals updated for the
  new field.
- 5/5 flake on the most-affected new test.
- Go suite (30 packages).
- Smoke matrix per §9.

## §11 Out of scope
- #1741 (buggy cos_active_flow_count) — not touched; ground truth
  is iperf per-stream CoV.
- Any change to v8 lease token refill.
- Proportional policy path.

## §12 Open questions for adversarial review
1. Is anchoring pass1 to `shaping_rate_bytes` correct when the
   root shaper is below the sum of exact rates AND below line rate
   (does the shaper rate reflect the actual deliverable bytes, or
   should it be `min(shaper, line_rate)`)?
2. Does charging the full configured quantum (Hunk B) over-charge
   pass1 such that FEWER small classes are honored than intended
   for a low fraction, pushing too much to Phase-2? Worked trace
   needed for fraction 0.7 fixture.
3. Clearing honored bits on the TIMED refresh (not just exhausted)
   — does this re-introduce the per-call re-honor monopoly #1732
   fixed, given the timed refresh can fire mid-epoch under clock
   skew? (Bound: timed refresh fires at most once per VISIT_NS.)
4. Phase-2 cursor preservation across a timed refresh while
   honored bits ARE cleared — can a queue be honored in Phase-1
   epoch N, then re-served in Phase-2 epoch N+1 before its bit is
   re-set, double-serving it? Trace the N→N+1 boundary.
5. Is there any config where `shaping_rate_bytes != 0` but the
   intended budget really is quantum_sum-based (e.g. shaper above
   Σ R_i, undersubscribed)? Does cap-anchoring under-budget Phase-1
   and wrongly push small classes to Phase-2 when there's plenty
   of capacity?
