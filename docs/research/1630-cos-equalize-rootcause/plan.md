# #1630 — CoS scheduler equalizes ~20%/class under `guarantee-rate 0.7`: verified root cause + plan-of-action

- Issue: #1630
- Branch: `research/1630-cos-equalize-rootcause`
- Mode: `/research` (plan only; no production code touched; STOP at PLAN-READY)
- Rev: **v3** (fix re-targeted to the lease top-up watermark after r2 convergence)
- Author: Claude SMR (CoS-scheduler / WFQ / DRR / token-bucket / AF_XDP multi-worker-shaper domain)

> **v2 reframed the root cause from live cluster telemetry** (falsifying
> BOTH #1634's selector diagnosis AND v1's "multi-worker fragmentation +
> flat root shaper"): `park_root=0` for every exact class, and small
> classes stay < 95% with ZERO competition (small-four-alone A/B:
> 69/79/87/86%). **v3 re-targets the FIX** after all three r2 reviewers
> (Codex + AGY + Claude SMR) independently proved v2's Path A (scheduler
> DRR on `secondary_budget`) was dead-on-arrival: the exact per-queue
> token bucket is WATERMARKED at `lease_bytes` (≈ rate × 200 µs, floored
> at `tx_frame_capacity`=4096) by `maybe_top_up_cos_queue_lease`, so it
> can never bank more than ~1-2 frames, and the unspent per-epoch lease
> cap is discarded at every rotation. The fix lives in the lease top-up
> watermark + per-epoch grant carry, NOT the selector quantum.

---

## 1. Problem statement

Smoke fixture `cos-iperf-config.set` on `loss:xpf-userspace-fw0/1`,
`reth0.80`: `shaping-rate 25g`, `oversubscription-policy guarantee-rate
0.7`, 11 exact classes (`transmit-rate {100m..24g} exact`),
best-effort q0, uncapped q11.

Documented contract (`docs/fairness-regimes.md` guarantee-rate section):
small-rate exact classes whose aggregate fits the Phase-1 budget should
each reach ~100% of configured rate first.

Measured (parent, #1634 binary): 5-class simul (demand 19.1 G) →
72/65/80/76/76% — proportional, not small-first.

**Correct arithmetic facts** (v1 §1 had errors, fixed here):
- Small-four sum = 0.1+1+3+6 = 10.1 G **≤** 17.5 G Phase-1 budget. ✓
- 5-class total = 19.1 G. This is **below** the 25 G shaper but **above**
  the ~18 G cluster push ceiling. (v1 wrongly said 19.1 ≤ 17.5 and 19.1
  < 18; both false.)

---

## 2. Decisive measurement (this research round)

Run on the free loss userspace cluster against the currently-deployed
binary; full data in `measurement-r1.txt`.

### 2a. Per-class park telemetry (`show class-of-service interface reth0.80`)

Every exact class's `DrainShape` shows **`park_root=0`** and a large
**`park_queue`**:

| Class | park_root | park_queue |
|-------|----------:|-----------:|
| iperf-100m | 0 | 431 452 |
| iperf-1g   | 0 | 621 624 |
| iperf-3g   | 0 | 1 790 063 |
| iperf-6g   | 0 | 1 880 244 |
| iperf-9g   | 0 | 1 564 813 |
| iperf-12g..24g | 0 | 176k-762k |
| best-effort / uncapped | 0 | 0 (surplus path) |

**`park_root=0` everywhere** ⇒ the shared root shaper
(`SharedCoSRootLease`, 25 G, the only interface-wide arbiter) NEVER
throttled any class. This **falsifies** (i) v1 §3(B) "flat root shaper
proportional starvation" and (ii) the #1634
`SMOKE-DECLINED-DIAGNOSIS.md` claim that "root tokens are distributed
proportionally" produces the equalization. The root pool was not the
gate. Every class is gated by `park_queue` — its OWN per-class token
bucket.

### 2b. Small-four-alone A/B (the discriminator all three reviewers demanded)

Ports 5201-5204 ONLY (100m+1g+3g+6g, demand 10.1 G, ZERO large-class
competition, 12 streams × 20 s, v4):

| Class | Shape | recv | % of shape |
|-------|------:|-----:|-----------:|
| 100m | 0.1 | 0.069 | **69 %** |
| 1g   | 1.0 | 0.787 | **79 %** |
| 3g   | 3.0 | 2.606 | **87 %** |
| 6g   | 6.0 | 5.130 | **86 %** |

With the ENTIRE cluster to themselves and zero competition, the small
classes STILL cannot reach 95%, and efficiency **rises monotonically
with configured rate** (69 → 79 → 87 → 86%). This is the signature of
per-visit quantum-MTU rounding (small rates lose a larger fraction of
their tiny quantum to the sub-frame remainder), exactly as AGY proved
analytically in r1.

---

## 3. Verified root cause (v3 — two discard points)

> **There are TWO budget-discard points that combine to cap a low-rate
> exact class at ~60% of its configured rate, independent of competition,
> the selector's ordering, and the root shaper:**
>
> **(P1) Exact-queue lease TOP-UP WATERMARK (dominant).**
> `maybe_top_up_cos_queue_lease` refills the per-queue token bucket only
> up to `lease_bytes = lease.lease_bytes().max(tx_frame_capacity())` ≈
> `max(rate × 200 µs, 4096)`. For 100m that watermark is ~4096 B (≈ 2
> frames). The bucket can NEVER accumulate above it (early-return when
> `tokens >= lease_bytes`; request clamped to `lease_bytes - tokens`).
> The per-epoch v8 lease cap (`rate × elapsed`) that is not consumed is
> discarded at rotation (`rotate_epoch_v8` swaps `packed_granted` to a
> fresh-tag zero). So the class can spend at most ~1-2 frames per epoch
> and loses the sub-frame / sub-cap remainder every epoch.
>
> **(P2) Selector quantum clamp.** Both exact and non-exact selectors set
> `secondary_budget = queue.hot.tokens.min(cos_guarantee_quantum_bytes).max(head_len)`,
> bounding each VISIT to one quantum (= rate × 200 µs). For non-exact
> queues (whose bucket DOES accumulate to `buffer_bytes`) this clamp is
> the sole cause; for exact queues it compounds P1.
>
> Net per-class efficiency ceiling RISES with configured rate (100m →
> 60%, 1g → 96%, ≥3g → ~100%), which under saturation reads as
> proportional equalization.

Mechanism, file:line (master @ `dbfbf680c`), verified independently by
Codex r2, AGY r2, and Claude SMR r2:

- **P1 watermark**: `token_bucket.rs:184-203` (exact branch):
  `lease_bytes = shared_queue_lease.lease_bytes().max(tx_frame_capacity()).min(buffer); if queue.hot.tokens >= lease_bytes { return; } ... acquire_via_lease(.., lease_bytes - tokens)`.
  `lease_bytes()` = `config.lease_bytes` = `target_lease_bytes = rate ×
  COS_ROOT_LEASE_TARGET_US(200 µs)` clamped (`shared_cos_lease/mod.rs:703-711`).
  `tx_frame_capacity() = UMEM_FRAME_SIZE = 4096` (`afxdp/mod.rs:314`). For
  100m: watermark = `max(2500, 4096) = 4096 B`.
- **P1 epoch discard**: `rotate_epoch_v8.rs:61-67` swaps `packed_granted`
  to `new_packed_zero` (fresh tag, 0 granted); the prior epoch's unspent
  cap is not carried.


1. **Per-visit quantum.** `cos_guarantee_quantum_bytes`
   (`queue_service/mod.rs:1534-1541`) = `transmit_rate_bytes ×
   COS_GUARANTEE_VISIT_NS(200 µs)`, clamped `[1500, 512K]`. 100m →
   `12.5 MB/s × 200 µs = 2500 B`.
2. **Selection clamps secondary_budget to the quantum** (NOT to
   accumulated tokens): `queue_service/mod.rs:879-883` and 985-989
   (`candidate_budget = queue.hot.tokens.min(cos_guarantee_quantum_bytes(queue)).max(head_len)`).
   Even when the per-queue bucket has accumulated tokens, each visit is
   capped at the quantum.
3. **Drain wastes the sub-frame remainder.** `drain.rs:69-72`:
   ```rust
   let len = req.bytes.len() as u64;
   if remaining_root < len || remaining_secondary < len { break; }
   ```
   With `secondary = quantum = 2500 B` and 1500 B frames: frame 1 sends
   (remaining → 1000 B); frame 2 (1500 > 1000) breaks. The 1000 B is not
   carried forward — `secondary_budget` is recomputed from the quantum on
   the next visit.
4. **The per-class v8 lease epoch cap also resets per epoch with no
   carry of unspent cap.** `rotate_epoch_v8.rs:215-225`: `new_cap = rate
   × min(elapsed, EPOCH_DURATION)`; published fresh each rotation. The
   lease grants up to `my_fair_share = cap × my_flows / total_flows`
   (`rotate_epoch_v8.rs:230-235`); with one owner, `= cap`. So the lease
   correctly meters the class to its rate, but in concert with the
   per-visit quantum clamp the deliverable-per-visit floor (1 frame for
   100m) means the class cannot consume its full per-epoch cap.
5. **`park_queue` is the observed gate.** `queue_service/mod.rs:684-719`
   parks the queue with `ParkReason::QueueTokenStarvation` when
   `queue.hot.tokens < head_len`. The high `park_queue` + `park_root=0`
   telemetry confirms the per-class bucket (fed by the v8 lease at the
   class's rate) is the binding constraint, not the root shaper.

### Efficiency ceiling (AGY's closed form, verified against drain.rs)

Per-visit frames = `floor(quantum / 1500)`; per-visit delivered =
`frames × 1500`; efficiency ceiling = `delivered / quantum`:

| Rate | Quantum | Frames | Ceiling |
|-----:|--------:|-------:|--------:|
| 100m | 2 500 | 1 | 60.0 % |
| 1g | 25 000 | 16 | 96.0 % |
| 3g | 75 000 | 50 | 100.0 % |
| 6g | 150 000 | 100 | 100.0 % |

Measured (small-four-alone) tracks this with a residual penalty (69/79
vs 60/96 ceilings) attributable to epoch-boundary lease cap reset (item
4) and visit cadence — i.e. real efficiency is the quantum ceiling FUR-
THER reduced by lease-epoch granularity. The DIRECTION (rises with rate,
small classes worst) is unambiguous and matches the analytic model.

### Why the full 11-class run "equalizes ~20%"

Under 11-class saturation the deliverable wire bandwidth (~18 G ceiling)
is split among classes that are EACH independently capped at their
quantum-efficiency-limited rate; what's left flows to best-effort/
uncapped surplus (q11 telemetry: `surplus=104 GB`,
`nonexact_while_exact_backlogged=3.8M`). The exact classes equalize low
because they are quantum-capped, not because of root competition or lost
small-class priority.

---

## 4. Is small-class-first / the documented contract achievable?

**Multi-worker visibility and ownership are NOT the blocker** — the
small-four-alone A/B used the whole cluster and still missed 95%. The
contract ("small classes ≥95% of configured rate first") is gated by the
**per-class quantum-MTU efficiency ceiling**, which is independent of
ownership, the selector, and the root shaper.

To deliver small classes to ≥95% of their configured rate, the fix must
attack **both discard points**, and crucially **P1 (the exact-queue lease
top-up watermark) — which all three r2 reviewers proved is the dominant
blocker.** A DRR deficit on the selector budget alone (v2 Path A) cannot
work because `secondary_budget ≤ queue.hot.tokens ≤ watermark`.

This is a **local, per-queue accounting fix** and does NOT require
cross-worker coordination (Axis B2) or single-owner collapse. v1's
single-owner recommendation and v2's selector-only DRR are both
withdrawn.

---

## 5. Multiple path options (v3)

| # | Path | Fixes P1 watermark? | Fixes P2 clamp? | Scope | Risk |
|---|------|:---:|:---:|------|------|
| A | **Raise the exact-queue lease top-up watermark to N×MTU + per-visit frame cap.** In `maybe_top_up_cos_queue_lease` exact branch, lift the watermark from `lease_bytes` (≈ rate×200 µs) to `lease_bytes.max(N × tx_frame_capacity)` so the bucket can BANK several frames; `acquire_v8` then requests up to that, and the unspent grant accumulates in the bucket (which already does `saturating_add`, token_bucket.rs:197). Keep the selector quantum as a per-VISIT frame cap (P2 fix) so a banked bucket cannot monopolize a drain pass. | Yes | Yes (quantum becomes a visit cap, not a discard) | Medium (token_bucket exact branch + selector budget; `types/cos.rs` if a persistent deficit field is used) | Watermark too large → over-deliver / burst; too small → 100m < 95%. Sweep N in the A/B. Must keep `consume(sent_bytes)` debiting actual bytes (rate cap preserved by the per-epoch `acquire_v8` grant = rate×elapsed). |
| B | **Carry the unspent per-epoch lease cap across rotations** in `rotate_epoch_v8` (don't swap `packed_granted` to a hard 0; carry the sub-frame remainder of the prior cap). | Yes (alternative to A's watermark) | No (still needs P2 fix) | Medium (touches the seqlock rotation hot path — higher risk) | Rotation is a lock-step seqlock; adding carry state risks the linearization invariants the v8 design depends on. Higher blast radius than A. |
| C | **Raise `COS_GUARANTEE_QUANTUM_MIN_BYTES` / `COS_GUARANTEE_VISIT_NS`** so the smallest quantum is several frames. | No (watermark still caps) | Partially | Tiny (constant) | Does NOT fix P1 — the watermark still pins the bucket. Insufficient alone. |
| D | **Document the floor; reframe the gate to "≥95% of achievable per-rate ceiling"; close as WAD for sub-300m.** | No | No | Doc-only | Leaves the contract unmet for small classes. Honest fallback only. |

Path A is the lowest-risk fix that hits BOTH discard points: it raises
the watermark (P1) and converts the quantum to a per-visit frame cap
(P2). Path B is an alternative P1 fix but touches the v8 seqlock
rotation (higher risk). Path C is insufficient. Path D is the fallback.

---

## 6. Recommendation

**Path A: raise the exact-queue lease top-up watermark to a bounded
N×MTU burst allowance, AND keep the guarantee quantum as a per-VISIT
frame cap (not a byte discard).** Concretely:

1. **P1 fix** — in `maybe_top_up_cos_queue_lease`'s exact branch
   (`token_bucket.rs:184-203`), raise the top-up target from
   `lease_bytes` to `lease_bytes.max(N × tx_frame_capacity())` for a small
   N (sweep; start N=8 ⇒ 32 KB). The bucket then banks up to N frames
   across epochs (the bucket already accumulates via `saturating_add`),
   so a 100m class accrues enough to send whole frames at its full
   average rate. The per-epoch `acquire_v8` grant remains `rate ×
   elapsed`, so the long-run RATE is still exactly metered — only the
   burst/accumulation window grows.
2. **P2 fix** — in the selectors, treat the quantum as a per-visit FRAME
   cap (advance RR after each visit) rather than a byte budget that
   discards the remainder; the banked tokens supply multi-frame sends but
   the per-visit cap preserves RR fairness.
3. **Rate-safety** — `consume(sent_bytes)` (tx_completion.rs) and the
   per-queue token debit continue to debit ACTUAL bytes, so Gate 4 (no
   class exceeds its rate) holds regardless of watermark size.

This is local per-queue (no B2, no single-owner, no selector-visibility
change). The #1634 waterfill selector is orthogonal to this efficiency
bug and out of scope for #1630 (it may still be useful for ORDERING under
true oversubscription, but the measurement shows it is not the #1630
gate).

---

## 7. Implementation sketch (for /engineer, NOT executed here)

Path A:

1. **P1**: in `token_bucket.rs` exact branch (lines 184-203), change
   `lease_bytes` target to `shared_queue_lease.lease_bytes().max(N *
   tx_frame_capacity() as u64).min(buffer)`. Pick N via the Gate-1 sweep
   (start 8). The early-return and the `acquire_via_lease(lease_bytes -
   tokens)` request naturally fill toward the higher watermark; banked
   tokens persist across epochs (existing `saturating_add`).
2. **P2**: in the exact selectors (`queue_service/mod.rs` ~879-883 and
   985-989) and the nonexact path (~1064-1068), keep `secondary_budget`
   bounded by a per-visit frame cap (e.g. `min(tokens, FRAME_CAP ×
   tx_frame_capacity)`), NOT by the recomputed single quantum, and always
   advance the RR cursor after a visit. Optionally a persistent
   `guarantee_deficit_bytes` on `CoSQueueRuntime` (`types/cos.rs`) for
   exactness, but the banked token bucket may make it unnecessary —
   decide during implementation (Q2).
3. **Per-visit burst cap (mandatory, AGY/Codex r2)**: bound each visit to
   a fixed frame count so a banked large class (24g, quantum clamp 512 KB
   = 341 frames) cannot transmit thousands of frames in one drain pass.
   `TX_BATCH_SIZE = 64` (afxdp/mod.rs:225) already caps the drain loop at
   64 frames/call; verify that cap is the binding per-visit bound and
   keep it.
4. **Rate-safety**: confirm `consume(sent_bytes)` + per-queue debit meter
   actual bytes; the v8 lease per-epoch grant (`rate × elapsed`) is what
   enforces the rate cap (Gate 4) — the watermark only changes burst.
5. **Non-exact**: apply the P2 visit-cap fix to
   `select_nonexact_cos_guarantee_batch` too (its bucket already
   accumulates to `buffer_bytes`, so it needs only the P2 half).
6. Docs: `docs/fairness-regimes.md` — describe the raised watermark / DRR
   burst window and the small-class efficiency behavior.

---

## 8. Acceptance gate (v3 — measurement-grounded)

- **Gate 1 (primary)**: small-four-alone A/B (100m/1g/3g/6g, demand
  10.1 G, no large classes) → each ≥ **95% of configured shape**. This is
  the clean ceiling test; it is currently 69/79/87/86% and MUST rise to
  ≥95% for all four. (This replaces v1's confounded 5-class gate.)
- **Gate 2**: 5-class simul (demand 19.1 G) → small-four each ≥ 95% of
  shape; iperf-9g takes residual. v4 AND v6.
- **Gate 3**: 11-class simul → no exact class starved; priority-low /
  uncapped ≥ 5% of cluster ceiling.
- **Gate 4 (rate cap preserved)**: no class EXCEEDS its configured rate
  in steady state (the deficit must not leak rate). Verify 1g ≤ ~1.0 G,
  etc., under solo and simul.
- **Gate 5 (no-regression)**: default multi-worker aggregate reverse
  throughput ≥ ~22 G; CoS-off path unchanged.
- **Gate 6 (full matrix)**: v4/v6 × push/-R × CoS-off/CoS-on per
  `feedback_cos_iperf3_per_class` + `feedback_smoke_push_and_reverse`.

If Path A cannot push the 100m class to ≥95% even at large N (e.g. an
irreducible lease-epoch granularity surfaces), fall back to Path D and
reframe the gate to "≥95% of the achievable per-rate ceiling" — but the
mechanism analysis shows raising the watermark removes the only structural
loss, so ≥95% should be reachable.

---

## 9. Risk / rollback

- Path A is a per-queue local accounting change in `token_bucket.rs` +
  the selectors; **no change to the v8 seqlock rotation
  (`rotate_epoch_v8`)**, no cross-worker atomic protocol change, no
  root-lease change, no HA/failover surface (no `make test-failover`
  trigger). Path B (carry across rotation) is explicitly NOT chosen
  precisely because it would touch the seqlock linearization.
- **Watermark N is the main correctness lever**: too large → small
  classes burst / over-deliver (Gate 4) and RR latency suffers; too small
  → 100m stays < 95% (Gate 1). Sweep N in the small-four-alone A/B.
- The per-visit frame cap (`TX_BATCH_SIZE = 64`) must remain the binding
  per-visit bound so a banked large class cannot monopolize a drain pass
  (AGY/Codex r2 RR-fairness finding).
- Rollback = revert the watermark + selector visit-cap change; behavior
  reverts to the recomputed-per-visit quantum (current ~60% small-class
  ceiling).

---

## 10. Documentation contract

`docs/fairness-regimes.md` guarantee-rate / quantum section MUST document
the raised lease top-up watermark (burst window) and the small-class
efficiency behavior. The #1614 §5.B2 cross-worker follow-up remains a
separate future tracker (NOT needed for #1630 per the measurement).

---

## 11. Open questions for hostile reviewers (≥5)

The r1/r2 questions are now RESOLVED in-text (root cause + the P1
watermark dominance). v3 open questions for the round-3 hostile pass:

- **Q1 (watermark sizing)**: What N (watermark = N × MTU) lifts the 100m
  class to ≥95% WITHOUT over-delivering (Gate 4) or hurting RR latency
  (Gate 3)? Is there a closed-form N, or must it be swept empirically?
  Does the same N work for the 1g class (already 79-96%) or does each
  rate need a different burst window — and if so, should the watermark be
  `max(lease_bytes, k × lease_bytes)` (rate-scaled) rather than a flat
  N×MTU? Rate-scaled risks giving large classes huge buckets.

- **Q2 (need for an explicit deficit field?)**: Given the per-queue
  token bucket already accumulates (token_bucket.rs:197), does raising the
  watermark ALONE suffice, or is a separate persistent
  `guarantee_deficit_bytes` still needed for exactness? If the bucket
  banks N frames and the selector visit-cap spends them, is there any
  residual sub-frame loss that a deficit counter would catch? Decide
  whether `types/cos.rs` needs the new field at all.

- **Q3 (RR / burst with raised watermark)**: With the watermark at N×MTU,
  a 24g class banks up to N frames too. Combined with `TX_BATCH_SIZE=64`
  per drain call, is 64 frames/visit an acceptable burst for the smallest
  (best-effort/100m) class's latency? Should the per-visit cap be
  rate-independent (64) or smaller for latency-sensitive classes?

- **Q4 (rate-cap proof)**: Prove Gate 4 (no class exceeds its rate)
  formally: the v8 `acquire_v8` per-epoch grant is `rate × elapsed`
  (rotate_epoch_v8.rs:220-235) regardless of watermark, and
  `consume(sent_bytes)` debits actual bytes. Is there ANY path where a
  larger watermark lets a class exceed `rate × elapsed` over a window?
  (I believe not — the watermark caps the BUCKET, the lease caps the
  GRANT — but a reviewer should verify the bucket can't be refilled from
  a source other than the rate-metered lease.)

- **Q5 (non-exact path)**: The non-exact selector
  (queue_service/mod.rs:1064-1068) clamps to the quantum but its bucket
  accumulates to `buffer_bytes` (refill_cos_tokens). AGY r2 showed it
  STILL caps at 60% because the selector clamp discards. Does the v3 P2
  visit-cap fix fully address non-exact, and is there a non-exact case in
  the smoke fixture (best-effort q0 / uncapped q11 are non-exact) that
  the gate must cover?

- **Q6 (master-binary confirmation)**: The measurement ran on the
  deployed binary. `park_root=0` is argued structural (root rate 25 G ≥
  demand 19.1 G). Should /engineer re-confirm on a freshly-built master
  binary before relying on it? (Low risk; the root-rate-≥-demand argument
  is rate-arithmetic, not binary-specific.)
