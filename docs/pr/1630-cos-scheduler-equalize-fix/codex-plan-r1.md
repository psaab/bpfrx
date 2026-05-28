# Codex plan-r1 — task-mppog9mq-uxhug3 (verbatim)

## Verdict: PLAN-NEEDS-MAJOR
## Confidence: 0.91

### Findings
1. [HIGH] The plan is right that the refill scalar is wrong, but only that part. Quote: docs require `Phase 1 honours small-rate exact classes ... up to fraction × cap` at `docs/fairness-regimes.md:848-853`, while code does `let pass1 = ((quantum_sum as f64) * frac).floor() as u64;` at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:787-800`. Disposition: the primary bug really is at the refill formula; `quantum_sum × fraction` violates the documented `fraction × cap` contract when `ΣQ_i > cap`.

2. [HIGH] The plan rules out the `break` / Phase-2 suspect too aggressively, but the fix makes that exact path hot and the implementation is not sound enough to dismiss. Quote: `Tracks honored queues via a bitmask so Phase 2 can skip them` at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:802-806`, then `let mut honored_mask: u64 = 0;` at line 806, then later `honored_mask is empty on this call ... we must rely on the persistent honored set` at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:913-921`. There is no persistent honored-set field in `userspace-dp/src/afxdp/types/cos.rs:402-419`. Disposition: `break` is not the original smoke-fixture trigger, but after the proposed fix it becomes in-scope immediately, and the current Phase-2 state tracking is internally inconsistent.

3. [HIGH] Gate 2 in the test plan is wrong on the code path. Quote: the plan claims `The fix unblocks Phase 2 which gives uncapped a fair turn in the descending walk` at `docs/pr/1630-cos-scheduler-equalize-fix/plan.md:333-336`. But `drain_shaped_tx` runs exact first and only builds non-exact after exact returns `None` at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:177-190`, and waterfill Phase 2 iterates only exact queues at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:945-950`. Non-exact service is a separate selector at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:1014-1069`. Disposition: this fix does not, by itself, give `iperf-uncapped` a turn in exact Phase 2. Gate 2 cannot be a blocking proof for this PR.

4. [HIGH] Unit test §11.3 has the wrong model of a “call” because `TX_BATCH_SIZE` truncates a visit before a high-rate queue exhausts its quantum. Quote: the plan says `After 4 ascending honors, the 5th call must return a Phase-2 selection` at `docs/pr/1630-cos-scheduler-equalize-fix/plan.md:311-315`. But batches stop at `while items.len() < TX_BATCH_SIZE` at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:1399-1423`, so the 6 Gbps queue (`Q=150000 B`) needs two exact selections: first `96000 B`, then `54000 B`. Disposition: the proposed unit test is arithmetically wrong; under the smoke fixture shape it is the 6th exact selection, not the 5th, that first reaches the 9 Gbps break boundary.

5. [MEDIUM] The tests do not prove the documented contract. Quote: existing coverage already admits `this test does NOT pin the VISIBLE per-queue distribution change under oversubscription` at `userspace-dp/src/afxdp/cos/queue_service/tests.rs:2288-2292`, while the new plan adds only a refill-scalar test and a first-Phase-2-pick test at `docs/pr/1630-cos-scheduler-equalize-fix/plan.md:299-315`. The contract requires `Phase 2 distributes residual proportionally across the queues NOT fully honoured in Phase 1` at `docs/fairness-regimes.md:850-853`. Disposition: tests are insufficient. They do not verify small-class throughput, do not verify exclusion of already-honored queues, and do not verify proportional residual behavior.

6. [MEDIUM] The worker-fair-share suspect is correctly ruled out as the primary bug. Quote: `new_cap_raw = ((self.config.rate_bytes ...` and then `my_share = ((new_cap as u128) * (my_count as u128) / (total_flows as u128))` at `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:220-234`. Disposition: `my_share` is derived from the per-class `new_cap`, not a class-agnostic pool. That is not the smoke-fixture equalize bug.

7. [MEDIUM] Transparent-root fallback is compatible with the current config surface; there is no existing validator basis to forbid it in this plan. Quote: the parser accepts `guarantee-rate` without checking `ShapingRateBytes` at `pkg/config/compiler_class_of_service.go:339-379`, while oversubscription validation skips units with `unit.ShapingRateBytes == 0` at `pkg/config/compiler.go:1075-1078`. Disposition: keeping the `shaping_rate_bytes == 0` fallback is reasonable for now. If the product wants to forbid transparent-root `guarantee-rate`, that is a separate config-contract change.

8. [LOW] The plan’s `cap_eff` discussion is sloppy because that mechanism does not exist yet. Quote: `priority_low_min_share_bytes` is `WIRE SURFACE ONLY` and `Today no hot-path code consults this field` at `userspace-dp/src/afxdp/types/cos.rs:386-401`. Disposition: not a smoke-fixture blocker, but the plan should stop reasoning as if an existing subtraction path needs to be mirrored.

### Worked counter-example for the fix
With `shaping-rate = 25 Gbps`, `VISIT_NS = 200000`, `fraction = 0.7`:

- Root cap per epoch = `(25e9 / 8) * 200e-6 = 625000 B`.
- Proposed Phase-1 budget = `floor(625000 * 0.7) = 437500 B`.
- Exact quanta are `Q100m=2500`, `Q1g=25000`, `Q3g=75000`, `Q6g=150000`, `Q9g=225000` bytes.

`iperf-100m` really can clear `>=95 Mbps` on arithmetic, but not for the reason the plan writes. The lease epoch is `200 us` and the v8 tests pin the 100 Mbps cap at `<=2500 B` per epoch in `userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs:185-198`. With MTU `1500`, the steady-state pattern is:

- Epoch A: grant `2500`, send `1500`, carry `1000`
- Epoch B: add `2500` => `3500`, send `3000`, carry `500`
- Epoch C: add `2500` => `3000`, send `3000`, carry `0`

That is `1500 + 3000 + 3000 = 7500 B` every `600 us`, i.e. `12.5 MB/s = 100 Mbps`. `TX_BATCH_SIZE = 64` is not binding for 100m.

The higher-rate arithmetic is where the plan is too loose. Because `userspace-dp/src/afxdp/cos/queue_service/mod.rs:1399-1423` caps one visit at `64 * 1500 = 96000 B`, the 6 Gbps queue cannot be honored in one call:

- Selection 1 on 6g: `candidate_budget = 150000`, actual send `96000`, leftover queue tokens `54000`, Phase-1 remaining `335000 -> 185000`
- Selection 2 on 6g: `candidate_budget = 54000`, actual send `54000`, Phase-1 remaining `185000 -> 131000`

So the smoke-fixture Phase-1 burn before the first 9 Gbps break is not the plan’s `252500 B`; it is:

- 100m: average Phase-1 burn `3666.67 B/epoch`, actual send `2500 B/epoch`
- 1g: average Phase-1 burn `26166.67 B/epoch`, actual send `25000 B/epoch`
- 3g: `75000 B/epoch`
- 6g: `204000 B/epoch` because the `150000 B` quantum is split into `96000 + 54000`

Total average Phase-1 burn for the four small classes is `308833.34 B/epoch`, leaving `437500 - 308833.34 = 128666.66 B`. The next 9 Gbps queue arrives with `candidate_budget = 225000 B`, so `225000 > 128666.66` and the `break` at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:889-893` fires only after all four small classes have been fully honored. So the smoke fixture does not hit the `break`-starves-smaller-queues failure mode. But the plan’s “4 honors then 5th call is Phase 2” test is wrong.

### Verdict rationale
The refill formula is genuinely wrong and anchoring Phase 1 to the shaper cap is the right direction. But the plan is not ready: it misstates what Phase 2 affects, ignores the hot-path state bug it is about to activate, and proposes tests that do not prove the documented contract and are wrong once `TX_BATCH_SIZE` is included.
