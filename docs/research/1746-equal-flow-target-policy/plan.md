# Plan of Action — #1746 CoS equal-flow target-policy knob

- **Issue**: #1746 — Explore: CoS equal-flow target is clip-to-SLOWEST
  (non-work-conserving); evaluate mean / global-fair-rate target.
- **Mode**: `/research` — converge a plan; STOP at PLAN-READY/PLAN-KILL.
  No PR, no production code in this skill.
- **Revision**: r2 — resolves the r1 naming knot (default ≡ `slowest`),
  fixes the §10 model (consistent observed-band model), adds the F1
  live-measurement ship-gate, commits to the sibling info-metric.
- **Branch**: `research/1746-equal-flow-target-policy`
- **Base**: `origin/master` @ `ecdc16f2e` (post-#1745 fail-open fix +
  audit regen).
- **Author**: Claude SMR (driving), reviewers Codex + AGY + Claude-SMR.

---

## 1. Problem statement

The CoS equal-flow-enforcement feature (`set class-of-service schedulers
<s> equal-flow-enforcement`, gated on `transmit-rate <r> exact`) installs
a per-flow rate **target** on a shared v8 queue lease. Each worker's
per-epoch grant is then capped at `target_per_flow_bps × active_flows`
on that worker (`my_effective_share = my_share.min(cap)`,
`shared_cos_lease/mod.rs:1237`).

The target is currently computed as the **minimum** sampled per-flow
rate across all sampled workers:

```
publish_equal_flow_epoch_v8.rs:129
    candidate_target = candidate_target.min(per_flow);   // clip-to-SLOWEST
```

i.e. the published target is the SLOWEST worker's achieved per-flow rate.
This was the original design intent (drag fast flows down to the slowest
to equalize), but #1745's live A/B (issue comment, 2026-06-01) proves it
is a **no-op in the capacity-limited regime** that the loss cluster
actually runs in:

- `target_per_flow_bps = 2.00e9` was observed live, but every flow ran
  0.87–1.82 Gb/s, **all below** the target. The cap
  `target × active_flows` never binds on any worker, so the suppressor
  clips nothing. `cap_hit_events` stay ~flat.
- Equal-flow ON vs OFF: CoV 19%/29% vs 14%/28.5% across two runs —
  statistically indistinguishable.

Two facts collide:

1. The **denominator is wrong for the regime.** The target is
   `prev_grants[id] / active_flows[id]` minimised across workers — but
   under RSS flow-count imbalance the *slowest worker* is the one with
   the MOST flows (4-flow worker → 0.87 G/flow), so the min target
   (~0.87 G) is below where any flow on a *lightly-loaded* worker
   actually runs (1.8 G). Clip-to-slowest at 0.87 G *would* bind on the
   1-flow worker — but the EWMA smoothing + valid-streak gate + the
   `LowDemandWorker`/`UnsampledActiveWorker` fail-opens mean it
   frequently fails open instead, and when it does enforce the published
   2.0 G figure shows the sample set collapsed to the lightly-loaded
   workers, not the heavy ones.

2. **A per-flow cap is structurally one-directional.** It can only push
   fast flows DOWN (`min(my_share, cap)`); it can NEVER lift slow flows
   UP, because the slow flows are starved by an *overloaded worker* and
   the freed capacity lands on a *different* worker's queue they can't
   reach. Cross-worker capacity reallocation is the separate, repeatedly
   plan-killed lineage (#937/#840/#1211/#1693/#1742) and is now tracked
   for a fresh mlx5-VF evaluation in **#1748** (cross-worker per-flow
   rebalance on native-XDP ntuple-capable VFs). **#1746 must NOT
   duplicate #1748.**

**Scope of #1746**: make the equal-flow *target policy* an
operator-selectable knob with THREE genuinely distinct values, each
computed from the **live cross-worker achieved rates** the #1745 sampler
already collects:

- **`slowest`** — the CURRENT math (`candidate_target.min(per_flow)`,
  clip every flow to the slowest sampled per-flow rate). **This is the
  byte-unchanged default**: unset config (`""`) maps to `slowest`, and
  the named value `slowest` produces byte-identical lease behavior.
  Named honestly after what the code actually does (the r1 plan
  mis-named this `ideal-share`).
- **`mean`** — `Σ prev_grants[id] / Σ active_flows[id]` over the sampled
  set (aggregate-weighted mean achieved per-flow rate). Clips the lucky
  outliers toward the mean; keeps more aggregate than `slowest`.
- **`ideal-share`** — literal `scheduler_rate / total_active_flows` (the
  Junos-style nominal equal share). Documented as a **no-op in
  capacity-limited regimes** (the #1745 A/B target was exactly this
  2.0 G figure and clipped nothing). Offered only for operators who want
  the nominal-share semantics; NOT the default.

Ship an HONEST throughput-vs-fairness tradeoff table per policy
(§10), a metric to confirm which policy is active (§5.3), and
**byte-unchanged default behavior** when the knob is unset (default ≡
`slowest` ≡ current `min` math — no `"" vs named` divergence).

PLAN-KILL is an acceptable outcome if reviewers conclude that *no*
cap-based target policy delivers meaningful operator-visible fairness in
the regime that matters, i.e. #1748 supersedes this entirely. The
mitigating design choice for that risk is the **F1 live-measurement
ship-gate** (§8.2 / §9 Q3): `mean` ships only if the /engineer smoke
shows a *measured* material CoV reduction; if it is a live no-op
(sample-set collapse), the issue PLAN-KILLs at /engineer time.

---

## 2. Current behavior (ground truth from code)

Data flow, end to end:

1. **Config leaf** `schema.go:867` `"equal-flow-enforcement": {children:
   nil}` (childless bool flag). Compiled at
   `compiler_class_of_service.go:252-253` → `sched.EqualFlowEnforcement =
   true`. Guarded: requires `transmit-rate <r> exact`
   (`compiler_equal_flow_worker_cap*` + `compiler.go`), plus the #1733
   worker-cap strict validator.
2. **Snapshot** `pkg/dataplane/userspace/protocol.go:235`
   `EqualFlowEnforcement bool` → Rust
   `protocol/cos.rs:111 equal_flow_enforcement: bool`.
3. **Forwarding build** `forwarding_build/cos.rs:293` gates the bool on
   `guarantee_enabled && transmit_rate_exact && equal_flow_enforcement`.
4. **Rate-mode select** `coordinator/mod.rs:1518`
   `if queue.equal_flow_enforcement { V8RateMode::EqualFlowSuppress }
   else { V8RateMode::CstructDefault }`. Lease built via
   `new_v8_with_rate_mode(...)`.
5. **Sampler (acquire side)** `mod.rs:1222-1233`: in EqualFlowSuppress
   only, records a tag-checked sticky-max active-flow sample per worker
   (`record_equal_flow_active_sample`).
6. **Target compute (rotation side)** `rotate_epoch_v8.rs:121-150` swaps
   the sample slots (sticky-max captured per worker as
   `sampled_active_flows_by_worker[id]`) then calls
   `publish_equal_flow_epoch_v8(...)`.
7. **publish_equal_flow_epoch_v8.rs**:
   - Fail-open guards: unsampled active worker, <2 sampled workers, zero
     target, low-demand worker (`prev_grant × 5 < prior_share × 4`),
     prior_share==0.
   - **Target = `min` over sampled workers of `prev_grants[id] /
     active_flows[id]`** (line 129) — clip-to-slowest.
   - EWMA smooth: `smoothed = (3·prev + candidate) / 4` (line 142-149).
   - `max_worker_cap = max over sampled set of smoothed × sample` (line
     158-172) — TELEMETRY ONLY (see below).
   - Valid-streak gate: must hold 2 consecutive valid epochs
     (`EQUAL_FLOW_VALID_STREAK_REQUIRED = 2`) before `enforce_epoch`.
8. **enforce_epoch** `mod.rs:566` stores `current_target_per_flow` +
   `current_worker_cap`, sets `enforced=1`, publishes `epoch_tag` last.
9. **Enforcement (consumer)** `equal_flow_cap_v8` `mod.rs:1647-1681`:
   returns `Some(target × active_flows_on_this_worker)`. Then
   `mod.rs:1237 my_effective_share = my_share.min(cap)`.

**Key code findings the plan rests on:**

- **The enforced quantity is `current_target_per_flow`, NOT
  `current_worker_cap`.** `current_worker_cap` / `max_worker_cap` is
  published into status (`status.rs:467
  equal_flow_max_worker_cap_bytes`) and Prometheus
  (`xpf_userspace_cos_equal_flow_max_worker_cap_bytes`) but is **not
  read on the enforcement path**. (`grep current_worker_cap` →
  enforcement uses only `current_target_per_flow`.) So a target-policy
  change is a one-line change to how `candidate_target` is reduced; the
  cap-publication is telemetry that we keep consistent.
- **The reduction `candidate_target.min(per_flow)` is the ONLY place the
  policy is decided.** Replacing `min` with mean / a different statistic
  over the same `(prev_grants[id], active_flows[id])` samples changes the
  policy with zero change to the enforcement consumer, the fail-open
  guards, the smoothing, or the streak gate.
- **The cap is one-directional** (`my_share.min(cap)`), confirming the
  issue's structural insight: NO policy choice here can lift slow flows.

---

## 3. Goal / success criteria

- Operator can select the equal-flow target policy per-scheduler.
  Default (knob unset, `""`) ≡ `slowest` = current `min` math →
  **byte-for-byte identical** lease behavior and identical snapshot/wire
  bytes for existing configs (proven by an unchanged-snapshot test).
- `mean` computes its target (`Σgrants / Σflows`) from the same
  per-worker samples already collected, and must show a **measured**
  per-flow CoV reduction vs `slowest` in the binding regime (ground-truth
  iperf per-stream CoV, NOT `cos_active_flow_count`, #1741) — the F1
  ship-gate (§8.2). `ideal-share` is the literal nominal share, retained
  as a documented no-op for nominal-share semantics.
- A single operator-visible signal states which policy is active per
  queue (extend the existing fail-open-reason / target telemetry; no new
  high-frequency control-socket traffic).
- An HONEST tradeoff table (this doc, §10) backed by the measured #1745
  A/B numbers, stating plainly that NONE of these policies lift
  slow-worker flows — that is #1748.

**Out of scope (explicit):** cross-worker capacity reallocation / per-
flow XDP_REDIRECT rebalance (#1748); changing RSS steering; touching the
surplus-sharing (#915) or flow-fair (#1735) paths; changing the default.

---

## 4. The structural problem, worked precisely

Loss cluster, 6 mlx5 VF workers. The exact per-flow banding the #1745 A/B
reported is **0.87 / 1.29 / 1.63 / 1.81 G**. Those four bands are
internally consistent with a **10-flow** distribution of `{4, 3, 2, 1}`
flows on four loaded workers (the remaining workers idle): a worker with
`k` flows gives each `≈ W/k`. The nominal run was `-P12`; with RSS
hashing two of the twelve flows collide onto already-loaded workers, so
the *observed* banding is the 10-distinct-flow shape above. To keep the
arithmetic checkable we model the **observed-band (10-flow)** case — the
exact A/B numbers — and note the `-P12` nominal separately. (The r1 plan
mixed a `-P12=12` claim with a `{1,2,3,4}=10` model and a wrong 16–17 G
baseline; both Codex and AGY flagged this. Corrected below.)

The shaper rate is 24 G `exact`, but the **achievable** aggregate is
bounded by per-worker core capacity, NOT 24 G — the class is
*worker-capacity-limited*, not *shaper-limited*, in this test. That is
why `ideal-share = 24G/12 = 2.0 G` clips nothing: every flow is already
below 2.0 G.

For a per-flow CAP at target `T`, a flow on a worker with `k` flows runs
at `≈ min(W/k, T)`. Workers with `W/k > T` get clipped; the rest are
untouched. Freed bytes on a clipped worker **cannot** migrate to a
starved worker (different queue/CPU) → aggregate drops by the clipped
amount: **non-work-conserving** for any `T < max_k(W/k)`.

Corrected observed-band (10-flow) model — flow rates
`[0.87×4, 1.29×3, 1.63×2, 1.81×1]`, baseline aggregate **12.42 G**,
baseline per-flow CoV **27.7 %** (matches the independent Codex and AGY
recomputations):

| Policy | Target `T` | Flows clipped | Aggregate | Per-flow CoV | Lifts 0.87 G floor? |
|---|---|---|---|---|---|
| `ideal-share` | 24G/12 = 2.0 G | none (all < 2.0 G) | 12.42 G (no-op) | 27.7 % (no-op) | NO |
| `mean` | Σgrants/Σflows = **1.242 G** | 1.29 / 1.63 / 1.81 bands → 1.242 G | **10.93 G** (−12.0 %) | **16.7 %** (−40 % relative) | NO |
| `slowest` (= current default `min`) | min achieved = 0.87 G | every band > 0.87 G | **8.70 G** (−30.0 %) | **~0 %** | NO |

The hard limit, restated: **the 0.87 G floor is identical across ALL
three policies.** Raising it requires work-conserving cross-worker
capacity = **#1748** (which the AGY r1 review correctly shows yields
+101 % to the starved flows, +40.9 % aggregate, 0 % CoV — but that is a
different, repeatedly-killed hardware-steering problem, not this issue).

NOTE the resolved asymmetry vs. the issue title: the title says current
behavior IS clip-to-slowest; the #1745 A/B observed a no-op at 2.0 G.
Both are explained by the fail-open guards + sample-set collapse + EWMA:
the `min` reduction *intends* `slowest` (~0.87 G) but frequently fails
open or collapses the sampled set to the lightly-loaded subset, so the
*published* target drifts up to ~2.0 G and clips nothing live. **This is
exactly the F1 risk** — see §8.2/§9 Q3: `mean` is subject to the SAME
sample-set-collapse failure mode, so it ships only on a measured live
win.

---

## 5. Design — the target-policy knob

### 5.1 Config surface (Go)

Add a childless-value leaf under each scheduler, adjacent to
`equal-flow-enforcement` at `schema.go:867`:

```
set class-of-service schedulers <s> equal-flow-target-policy (slowest | mean | ideal-share)
```

- `schema.go`: replace the childless `"equal-flow-target-policy"` with a
  value-slot leaf offering the 3 enum tokens (mirror an existing enum
  value-leaf, e.g. `priority`/`drop-profile` pattern in setSchema). Add
  the value-slot `?` completion + commit-check typed-leaf validation per
  `docs/config-schema.md`.
- `compiler_class_of_service.go`: parse the value into a new
  `sched.EqualFlowTargetPolicy string`. **Default `""` maps to
  `slowest`** (the current `min` math) — there is NO `"" vs named`
  divergence, because `slowest` IS the current default behavior.
  Commit-check WARNING (not error) if the policy is set but
  `equal-flow-enforcement` is absent (matches the existing #1733
  warn-not-strip discipline). Additional WARNING when `mean`/`slowest`
  is selected, documenting the §10 aggregate cost (operator-footgun
  mitigation per AGY r1).
- Snapshot: add `EqualFlowTargetPolicy string
  json:"equal_flow_target_policy,omitempty"` to the scheduler snapshot
  in `protocol.go`. `omitempty` + empty-default keeps the wire bytes
  byte-identical for existing configs (the unchanged-snapshot test).

### 5.2 Rust runtime

- `protocol/cos.rs`: add a small
  `enum EqualFlowTargetPolicy { Slowest, Mean, IdealShare }` with
  `#[serde(default)]` → `Slowest` (NOT IdealShare — `Slowest` is the
  byte-unchanged default). `default` keeps old snapshots decoding to the
  current behavior. The empty string `""` and missing field both decode
  to `Slowest`.
- `forwarding_build/cos.rs`: copy the policy onto the intermediate
  `CoSQueueConfig`, gated identically to `equal_flow_enforcement` (only
  meaningful when that is on).
- `coordinator/mod.rs:1518`: the rate-mode stays
  `EqualFlowSuppress`; thread the policy into the lease via
  `new_v8_with_rate_mode` (extend signature OR carry it on the existing
  config struct the lease already stores). `matches_config_v8` must
  include the policy so a policy change rebuilds the lease.
- `publish_equal_flow_epoch_v8.rs`: this is the ONLY math change. Replace
  the single `candidate_target = candidate_target.min(per_flow)` (line
  129) with a policy-driven reduction over the SAME sampled
  `(prev_grants[id], active_flows[id])` pairs (Codex r1 angle 3 + AGY r1
  angle 3 both confirmed these are already in scope at lines 97-101):
  - `Slowest` (DEFAULT, `""` decodes here): preserve the EXACT current
    code path byte-for-byte — keep `candidate_target.min(per_flow)`. No
    behavior change vs master for unset configs.
  - `Mean`: accumulate `sum_grants += prev_grants[id]` and
    `sum_flows += active_flows[id]` over the sampled set inside the
    existing loop, then `candidate_target = sum_grants / sum_flows`
    (single division, no per-flow loop growth, same zero/overflow
    guards as today's `per_flow == 0` check).
  - `IdealShare`: `candidate_target = self.config.rate_bytes_per_epoch /
    total_active_flows` (the literal nominal share = the documented
    ~2.0 G no-op). `total_active_flows` is already summed in the
    rotation (`rotate_epoch_v8.rs:226-231`); thread it in or recompute
    over the sampled set.
  - All three keep the EWMA smoothing, the valid-streak gate, the
    fail-open guards, and the `max_worker_cap` telemetry publication
    unchanged — they only choose `candidate_target`. The r1 "Q1 identity"
    problem is GONE: `Slowest` = `min`, `Mean` = `Σ/Σ`, `IdealShare` =
    nominal share — three distinct values, and the default is `Slowest`
    (not `IdealShare`), so unset and named never diverge.

### 5.3 Telemetry (which policy is active)

- Add `equal_flow_target_policy: String` to the queue status
  (`protocol/cos.rs` status struct + `status.rs:464-473` population).
- **COMMIT to a sibling info metric**
  `xpf_userspace_cos_equal_flow_target_policy{iface,queue,policy="slowest|mean|ideal-share"} 1`
  — do NOT relabel the existing `cosEqualFlowTargetPerFlowBPS` gauge
  (Codex r1 angle 5 + AGY r1 angle 4: relabeling changes downstream
  series identity). The operator confirms the active policy via
  `show class-of-service` and `/metrics`. **No new control-socket
  request** — the status poll already carries the queue block at 1/s
  (`status.rs:464-473`); this piggybacks on it (CLAUDE.md control-socket
  contention rule, confirmed compliant by both r1 reviewers).

---

## 6. Multiple path options

### Path A — three-value enum knob (`slowest`/`mean`/`ideal-share`), default ≡ `slowest`, gated on F1 (this plan, §5)
- Minimal blast radius: one Rust match in `publish_equal_flow_epoch_v8`,
  one Go enum leaf, one snapshot field, one status field + one sibling
  info-metric. Default byte-unchanged (`slowest` = current `min`).
- The r1 naming knot is resolved: three numerically distinct targets,
  default is `slowest` (not the literal share), so unset and named never
  diverge.
- `mean` ships ONLY if the F1 live-measurement gate (§8.2) shows a
  measured material CoV win — so it cannot ship as a third silent no-op.

### Path B — "fix the denominator" silently in the default
- Make the default correctly clip-to-slowest-of-ACHIEVED (fix the live
  no-op) without a knob. Rejected: changes default behavior (violates the
  byte-unchanged contract) AND silently imposes the ~30 % aggregate cost
  of `slowest` on every existing equal-flow config — operator-hostile.
  The honest version of this is simply `slowest` as an OPT-IN value with
  a commit-check cost warning (folded into Path A).

### Path C — PLAN-KILL in favor of #1748 (AGY r1 verdict)
- AGY r1 argues: the cap is one-directional (`mod.rs:1237`), so `mean`
  and `slowest` destroy 12 % / 30 % aggregate while the 0.87 G starved
  floor is *identical* to baseline — a throughput-destroying footgun; the
  only real fix is #1748 (work-conserving rebalance: +101 % to starved
  flows, +40.9 % aggregate, 0 % CoV).
- **Counter (Claude-SMR r1):** AGY's kill is a *default-policy*
  objection. The plan keeps the default unchanged and makes `mean` /
  `slowest` strictly opt-in with a commit-check cost WARNING. By AGY's
  OWN numbers `mean` delivers a **40 % relative CoV reduction at 12 %
  aggregate cost** — a legitimate jitter-vs-throughput trade an operator
  with a latency-sensitive class may rationally choose
  (`feedback_junos_feature_parity`: do not refuse operator knobs because
  one setting can be misused). "#1748 is better" ≠ "#1746 is worthless":
  #1748 is multi-month, repeatedly plan-killed hardware steering
  (#937/#840/#1211/#1693/#1742); `mean` is a ~1-day opt-in math branch.
  The two are complementary, not exclusive. AGY's "ideal-share ==
  clip-to-slowest" identity claim was the r1 naming defect, now resolved
  — it is not a structural impossibility.

**Recommended: Path A** with the F1 ship-gate as the safety valve that
addresses AGY's footgun concern empirically. If the /engineer smoke shows
`mean` is a live no-op (sample-set collapse, the §4 failure mode), the
issue PLAN-KILLs at /engineer time — converting AGY's blanket kill into a
measured decision rather than a pre-emptive one.

---

## 7. Files touched (estimate)

Rust (`userspace-dp/`):
- `src/protocol/cos.rs` — config + status fields (+enum).
- `src/afxdp/forwarding_build/cos.rs` — copy policy to intermediate.
- `src/afxdp/coordinator/mod.rs` — thread policy into lease build +
  `matches_config_v8`.
- `src/afxdp/cos/builders.rs` — copy onto runtime config state.
- `src/afxdp/types/shared_cos_lease/mod.rs` — store policy on V8 config;
  `matches_config_v8` arg; status getter.
- `src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs` —
  the policy-driven `candidate_target` reduction (THE math change).
- `src/afxdp/coordinator/status.rs` — populate status policy field.
- Tests: `publish_equal_flow_epoch_v8`/`shared_cos_lease_tests.rs`,
  `forwarding_build/tests.rs`, `coordinator/tests.rs`,
  `protocol/tests.rs`.

Go (`pkg/`):
- `pkg/config/schema.go` — value-leaf + enum tokens.
- `pkg/config/schema_complete.go` — value-slot completion.
- `pkg/config/schema_walk.go` — typed-leaf validation.
- `pkg/config/compiler_class_of_service.go` — parse → `EqualFlowTargetPolicy`.
- `pkg/config/types or scheduler struct` — new field.
- `pkg/dataplane/userspace/protocol.go` — snapshot field (+ status field).
- `pkg/api/metrics_descriptors.go` + collector — policy metric/label.
- `pkg/cmdtree/` — `show class-of-service` surfacing if needed (likely no
  new op command; the existing CoS show already iterates queue fields).
- Tests: `compiler_class_of_service_test.go`, schema completion tests,
  snapshot round-trip test (byte-unchanged for unset).

Docs (contract — required by CLAUDE.md):
- `docs/config-schema.md` — new typed leaf.
- `docs/fairness-regimes.md` and/or `docs/cos-traffic-shaping.md` — the
  §4 corrected tradeoff table + the explicit "no policy lifts the floor →
  #1748" statement + the per-policy commit-check cost warning.

---

## 8. Test / validation plan

### 8.1 Unit (no hardware)
- `publish_equal_flow_epoch_v8`: table test with synthetic
  `(prev_grants, sampled_active_flows)` per worker proving:
  - `Slowest` (default) → byte-identical `candidate_target` vs master for
    the same inputs (the `min`).
  - `Mean` → `Σgrants / Σflows` over the sampled set.
  - `IdealShare` → `rate_per_epoch / total_active_flows`, distinct from
    both.
  - Fail-open guards / EWMA / streak gate fire identically for all three.
- Go snapshot round-trip: a config WITHOUT the policy leaf serializes to
  byte-identical JSON vs master (omitempty proof); a config WITH
  `equal-flow-target-policy slowest` ALSO serializes such that the Rust
  side produces byte-identical lease behavior to unset.
- Go compiler: policy parsed; warning (not error) when set without
  enforcement; per-policy cost warning emitted for `mean`/`slowest`;
  rejected enum value caught at commit.
- Schema completion: the 3 enum tokens (`slowest`/`mean`/`ideal-share`)
  complete at the value slot.
- Coordinator: a live policy change (e.g. `slowest` → `mean`) forces a
  lease rebuild (`matches_config_v8` includes the policy) — assert the
  stale lease is NOT reused (F3).

### 8.2 Smoke (loss userspace cluster — at /engineer time, NOT in /research)
Per `feedback_cos_iperf3_per_class` + `feedback_smoke_v4_and_v6` +
`feedback_smoke_push_and_reverse`, the eventual implementation PR's smoke
must run the full matrix on `loss:xpf-userspace-fw0`:
- v4 (172.16.80.200) + v6 (2001:559:8585:80::200), push + `-R`,
  per-CoS-class, for EACH of the 3 policies on port 5210 (`-P12`).
- Capture ground-truth **iperf per-stream CoV** (not
  `cos_active_flow_count`), aggregate Gb/s, and `cap_hit_events` /
  `suppressed_grant_bytes` / `fail_open_reason` for each policy.
- **F1 SHIP-GATE (the safety valve for AGY's footgun concern):** `mean`
  ships ONLY if it shows a **measured** material per-flow CoV reduction
  vs `slowest`-disabled baseline (target: ≥~30 % relative CoV reduction
  at ≤~15 % aggregate cost, Q3). If `mean` is a LIVE NO-OP — i.e. the
  same sample-set-collapse / EWMA-drift failure mode that makes the
  current target a no-op (§4) pushes `Σgrants/Σflows` above the top band
  so it clips nothing — then **PLAN-KILL the issue at /engineer time** in
  favor of #1748. This converts AGY r1's pre-emptive blanket kill into a
  measured, evidence-based decision.
- Acceptance baseline: `slowest`-as-default ≈ master baseline; the named
  `slowest` value reproduces it; `ideal-share` ≈ no-op; `mean` per F1.
- Per `feedback_runnable_repro_before_measurement_claim`: ≥2–3× per cell,
  validate the per-flow counter sums to N streams, re-apply CoS after
  deploy (deploy wipes CoS).

### 8.3 Regression
- `make test` (Go) green. `cargo test -p userspace-dp` green.
- HA untouched (no cluster/VRRP/session-sync code in scope) → no
  `make test-failover` requirement, but state so explicitly in the PR.

---

## 9. Open questions for reviewers

- **Q1 (RESOLVED in r2):** the naming knot is closed. Default `""` ≡
  `slowest` ≡ current `min` math (byte-unchanged); `mean` = `Σ/Σ`;
  `ideal-share` = literal nominal share. Three distinct values, no
  `"" vs named` divergence. Reviewers: confirm this resolution is
  coherent.
- **Q2 (cap telemetry):** `current_worker_cap` is published but never
  enforced (`mod.rs:1647-1681` enforces only `current_target_per_flow`).
  Do we (a) leave it as-is, (b) wire it as a secondary per-worker
  ceiling, or (c) delete the dead telemetry? Recommend (a) for this issue
  (no behavior change); flag (c) as a possible follow-up refactor.
- **Q3 (F1 ship-gate threshold):** confirm the §8.2 gate threshold —
  `mean` ships only on ≥~30 % relative CoV reduction at ≤~15 % aggregate
  cost; otherwise PLAN-KILL at /engineer time. Reviewers may tighten the
  numbers.
- **Q4 (default policy) — RESOLVED:** default MUST remain the current
  `min` (`slowest`) behavior, byte-unchanged; we add opt-in policies
  only, we do NOT improve out-of-box behavior. Confirm.

---

## 10. Throughput-vs-fairness tradeoff table

The corrected, internally-consistent tradeoff table is **§4** (the
observed-band 10-flow model: baseline 12.42 G / CoV 27.7 %; `mean`
T=1.242 G → 10.93 G / 16.7 % (−12 % agg, −40 % rel CoV); `slowest`
T=0.87 G → 8.70 G / ~0 %; 0.87 G floor identical across all three). The
r1 placeholder table that lived here (with the `-P12`/`{1,2,3,4}` flow-
count mismatch and the 16–17 G baseline) is superseded — see §4. The
/engineer smoke (§8.2) replaces the §4 predictions with measured
per-policy values and applies the F1 ship-gate.

**The freed capacity from clipping CANNOT reach the slow flows** (they
are on different saturated workers). Lifting the 0.87 G floor is
work-conserving cross-worker rebalance = **#1748**, NOT this issue.

## 11. Risks & rollback

- **Risk: default behavior drift.** Mitigated by the omitempty snapshot
  field + `#[serde(default)]` → `Slowest` + the byte-unchanged snapshot
  test + the `Slowest`-maps-to-current-`min` rule (Q1/Q4). If any slip,
  the smoke's default cell diverging from master baseline catches it.
- **Risk: lease rebuild churn.** `matches_config_v8` must include the
  policy so a live policy change rebuilds; otherwise a stale lease keeps
  the old policy. Covered by the F3 coordinator test (§8.1).
- **Risk: non-work-conserving footgun (AGY r1).** `slowest` costs ~30 %
  and `mean` ~12 % aggregate; mitigated by both being strictly opt-in +
  a commit-check WARNING documenting the §4 aggregate cost + the F1
  live-measurement ship-gate that PLAN-KILLs `mean` if it is a measured
  no-op. The default is unaffected.
- **Risk: `mean` is a live no-op (the §4 sample-set-collapse failure
  mode).** This is the central technical risk; the F1 ship-gate (§8.2)
  is the explicit mitigation — `mean` does not ship unless it measurably
  works.
- **Rollback**: revert the PR; unset configs are unaffected (default
  unchanged). No data migration.
