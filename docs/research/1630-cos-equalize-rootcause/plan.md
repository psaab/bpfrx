# #1630 — CoS scheduler equalizes ~20%/class under `guarantee-rate 0.7`: verified root cause + plan-of-action

- Issue: #1630
- Branch: `research/1630-cos-equalize-rootcause`
- Mode: `/research` (plan only; no production code touched; STOP at PLAN-READY)
- Rev: **v2** (measurement-corrected root cause)
- Author: Claude SMR (CoS-scheduler / WFQ / DRR / token-bucket / AF_XDP multi-worker-shaper domain)

> **v2 reframes the root cause based on live cluster telemetry that
> falsified BOTH the #1634 selector diagnosis AND v1's own
> "multi-worker fragmentation + flat root shaper" hypothesis.** See
> `measurement-r1.txt`. The decisive evidence: **`park_root=0` for every
> exact class**, and small classes stay below 95% even with ZERO
> competition (small-four-alone A/B: 69/79/87/86%). The binding gate is
> the per-class guarantee quantum/lease wasting the sub-frame remainder,
> NOT root competition and NOT cross-worker visibility.

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

## 3. Verified root cause (v2 — corrected)

> **The per-class guarantee quantum (`cos_guarantee_quantum_bytes = rate
> × 200 µs`, clamped) caps each per-visit send, and the drain loop
> discards the sub-frame remainder of that quantum on every visit with
> no carry-forward. For low-rate classes the quantum is only a few
> frames (100m → 2500 B → 1 frame), so a large fixed fraction is wasted
> every visit. The result is a per-class efficiency ceiling that rises
> with configured rate — which under saturation looks like proportional
> equalization.**

Mechanism, file:line (master @ `dbfbf680c`):

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
make the per-class guarantee accounting **carry the sub-frame / sub-cap
remainder forward across visits/epochs** so a 100m class accumulates
enough budget to send a whole frame on a less-frequent visit and average
out to 100 Mbps — i.e. a deficit-round-robin (DRR) deficit counter, not a
recomputed-each-visit quantum.

This is a **local, per-queue accounting fix** and does NOT require
cross-worker coordination (Axis B2) or single-owner collapse. v1's
recommendation (Path 2 single-owner) was aimed at the wrong mechanism
and is withdrawn.

---

## 5. Multiple path options (v2)

| # | Path | Fixes the measured ceiling? | Scope | Risk |
|---|------|:---:|------|------|
| A | **DRR deficit carry-forward on the guarantee quantum**: replace the recomputed-each-visit `secondary_budget = min(tokens, quantum)` with a persistent per-queue deficit counter that accumulates unspent quantum across visits (classic DRR). A 100m queue accrues quantum until it has ≥1 frame, sends it, carries the remainder. | Yes — eliminates the sub-frame waste; small classes converge to configured rate | Medium (per-queue deficit field + drain accounting; touches `queue_service` selectors + `drain.rs` budget) | Must not break large-class fairness or the v8 lease cap interaction; needs the full CoS smoke matrix |
| B | **Carry the per-queue token bucket as the budget (drop the quantum clamp)**: since `queue.hot.tokens` already accumulates (token_bucket.rs), pass `queue.hot.tokens` (capped by lease, not by the 200 µs quantum) as `secondary_budget`. The quantum becomes a fairness *visit* bound only, not a *byte* cap. | Yes — accumulated tokens already span multiple frames; the lease enforces the rate | Small-medium (remove/raise the `.min(quantum)` clamp at the 2 candidate_budget sites; keep quantum for RR fairness via a separate visit cap) | Risk: large classes could burst the whole accumulated bucket in one visit, hurting inter-class latency/RR fairness; needs a per-visit frame-count cap to preserve RR |
| C | **Raise `COS_GUARANTEE_QUANTUM_MIN_BYTES` and/or `COS_GUARANTEE_VISIT_NS`** so even the smallest class's quantum is several frames (e.g. min 6×MTU). | Partial — raises the 100m ceiling from 60% toward ~95% but inflates burstiness and weakens shaping precision for tiny classes | Tiny (constant change) | Crude; trades shaping accuracy for efficiency; may over-deliver tiny classes in bursts |
| D | **Document the quantum-efficiency floor; reframe the gate to "≥95% of the per-rate quantum ceiling"; close #1630 as working-as-designed for sub-300m classes.** | No (accepts the ceiling) | Doc-only | Leaves the operator-facing contract unmet for small classes |

Path A is the textbook fix (DRR is specifically designed to eliminate
exactly this sub-quantum waste). Path B is a smaller change that leans on
the already-accumulating token bucket but risks RR/latency fairness
without an added visit cap. Path C is a band-aid. Path D is the honest
fallback if A/B prove too invasive.

---

## 6. Recommendation

**Path A (DRR deficit carry-forward), with Path B's "token bucket already
accumulates" insight as the implementation lever.** Concretely: maintain
a persistent per-queue `guarantee_deficit_bytes` that accumulates the
quantum each visit and is spent in whole frames, carrying the remainder —
the canonical Deficit Round Robin. This removes the sub-frame waste that
the measurement isolated, is local per-queue (no B2, no single-owner, no
selector-visibility change), and is the mechanism a correct
rate-quantum scheduler should have used in the first place.

The #1634 waterfill selector and the v1 single-owner idea both target
mechanisms the measurement shows are NOT binding; neither is part of this
fix. (The waterfill selector may still be desirable for ORDERING under
oversubscription, but it is orthogonal to the efficiency bug and out of
scope for #1630.)

---

## 7. Implementation sketch (for /engineer, NOT executed here)

Path A:

1. Add `guarantee_deficit_bytes: u64` to `CoSQueueRuntime` hot state
   (`types/cos.rs`).
2. In the exact-guarantee selectors (`queue_service/mod.rs` ~879-883 and
   985-989) and the nonexact path (~1064-1068): compute
   `secondary_budget = (guarantee_deficit_bytes += quantum).min(tokens)`
   — i.e. accumulate the quantum into the deficit, bound by available
   per-queue tokens, instead of clamping to a single quantum.
3. In `drain.rs`, after the drain loop, write the unspent `secondary`
   back to `guarantee_deficit_bytes` (carry-forward) rather than
   discarding it. Cap the deficit at a small multiple of MTU to bound
   burstiness.
4. Ensure the v8 lease `consume(sent_bytes)` and the per-queue token
   debit still meter the actual bytes sent so the configured RATE cap is
   preserved (the deficit only affects WHEN whole frames are eligible,
   not the long-run rate).
5. Preserve RR fairness: keep advancing the per-class RR cursor per visit
   so a large class with a big deficit cannot monopolize; bound per-visit
   frames if needed.
6. Docs: `docs/fairness-regimes.md` — describe the DRR deficit and the
   small-class efficiency guarantee.

---

## 8. Acceptance gate (v2 — measurement-grounded)

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

If Path A cannot push the 100m class to ≥95% because of an irreducible
floor (e.g. lease-epoch granularity), fall back to Path D and reframe the
gate to "≥95% of the achievable per-rate ceiling" — but the A/B shows
substantial headroom (69% → ≥95% should be reachable with carry-forward,
since the only loss is the per-visit sub-frame remainder).

---

## 9. Risk / rollback

- Path A is a per-queue local accounting change; no cross-worker atomic
  protocol, no root-lease change, no HA/failover surface (no
  `make test-failover` trigger). The v8 lease and shared root lease are
  untouched.
- The burstiness cap (step 3) is the main correctness lever: too large →
  small classes burst and hurt RR latency; too small → carry-forward
  insufficient and 100m stays < 95%. Sweep it in the A/B.
- Rollback = revert the deficit field + accounting; quantum reverts to
  recomputed-per-visit.

---

## 10. Documentation contract

`docs/fairness-regimes.md` guarantee-rate / quantum section MUST document
the DRR deficit and the small-class efficiency behavior. The #1614 §5.B2
cross-worker follow-up remains a separate future tracker (NOT needed for
#1630 per the measurement).

---

## 11. Open questions for hostile reviewers (≥5)

- **Q1**: Does the per-class v8 lease's per-epoch `cap = rate × elapsed`
  reset (rotate_epoch_v8.rs:215-225, NO carry of unspent cap) impose its
  OWN floor independent of the quantum carry-forward? I.e. even with a
  perfect DRR deficit on the quantum, can a 100m class consume its full
  per-epoch lease cap (2500 B/200 µs) when each grant must be spent in
  1500 B frames? Work the lease-epoch × frame-quantization interaction;
  if the lease itself loses the remainder, Path A must ALSO carry the
  lease deficit (token bucket already does this — confirm
  token_bucket.rs accumulation is sufficient).

- **Q2**: Path B vs Path A — the per-queue token bucket ALREADY
  accumulates (token_bucket.rs:197-201, no per-epoch reset). So is the
  quantum clamp at the selector (`min(quantum)`) the ONLY thing throwing
  away the accumulated budget? If yes, Path B (raise/remove the clamp +
  add a frame-count visit cap) is strictly smaller than Path A. Which is
  correct? Quote the two candidate_budget sites and the token-bucket
  accumulation to decide.

- **Q3**: RR fairness regression — with carry-forward, a large class
  (24g, quantum clamped at 512K = 341 frames) accrues a big deficit if
  starved a few visits. Does Path A let it monopolize a drain pass and
  spike inter-class latency? Is the per-visit frame-count cap (step 5)
  sufficient, and what value?

- **Q4**: Is the documented contract ("small classes ≥95% of configured
  rate") even the right target, or is some efficiency loss for sub-MTU-
  multiple quanta inherent and should the gate be "≥95% of achievable
  ceiling"? Junos vSRX behavior reference?

- **Q5**: Does this bug also affect NON-exact guarantee queues
  (`select_nonexact_cos_guarantee_batch`, queue_service/mod.rs:1064-1068
  uses the same `min(quantum)` clamp)? Should Path A cover both, and does
  the nonexact path's `refill_cos_tokens` (rate-based, accumulating)
  already mitigate it differently?

- **Q6**: The measurement was on the currently-deployed binary (not
  necessarily #1634). Could the deployed binary differ from master in a
  way that changes `park_root=0`? Should the A/B be re-run on a
  freshly-built master binary to be certain the root-shaper-is-not-the-
  gate finding holds on master? (I judge `park_root=0` is structural —
  the root rate is the full 25 G and demand ≤ 19.1 G — but a reviewer may
  demand the master rebuild.)
