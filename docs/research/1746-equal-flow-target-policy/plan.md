# Plan of Action — #1746 CoS equal-flow target-policy knob

- **Issue**: #1746 — Explore: CoS equal-flow target is clip-to-SLOWEST
  (non-work-conserving); evaluate mean / global-fair-rate target.
- **Mode**: `/research` — converge a plan; STOP at PLAN-READY/PLAN-KILL.
  No PR, no production code in this skill.
- **Revision**: r1 (DRAFT)
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
operator-selectable knob — `ideal-share` (current/default, documented as a
no-op in capacity-limited regimes), `clip-to-mean`, `clip-to-slowest` —
where each policy is computed from the **live cross-worker achieved
rates** the #1745 sampler already collects. Ship an HONEST throughput-vs-
fairness tradeoff table per policy, a metric to confirm which policy is
active, and **byte-unchanged default behavior** when the knob is unset.

PLAN-KILL is an acceptable outcome if reviewers conclude that *no*
cap-based target policy delivers meaningful operator-visible fairness in
the regime that matters, i.e. #1748 supersedes this entirely.

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
  Default (knob unset) = current `ideal-share` semantics → **byte-for-byte
  identical** lease behavior and identical snapshot/wire bytes for
  existing configs (proven by an unchanged-snapshot test).
- `clip-to-mean` and `clip-to-slowest` compute their target from the
  same per-worker samples already collected; both reduce per-flow CoV vs
  default in the binding regime, measured by **ground-truth iperf per-
  stream CoV** (NOT `cos_active_flow_count`, #1741).
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

Loss cluster, 6 mlx5 VF workers, `-P12` → 12 flows RSS-hashed across 6
workers. Observed banding (issue comment): per-flow rates 0.87 / 1.29 /
1.63 / 1.81 G corresponding to workers carrying 4 / 3 / 2 / 1 flows
respectively (each worker ≈ saturated at ~3.5 G aggregate). Aggregate
≈ 16–17 G; CoV(per-flow) ≈ 14–29 %.

The shaper rate is 24 G `exact`, but the **achievable** aggregate is
bounded by the 6-worker × per-worker-core ceiling, NOT 24 G — the class
is *worker-capacity-limited*, not *shaper-limited*, in this test. That is
why `target = 24G/12 = 2.0 G` clips nothing: the binding constraint is
worker CPU, and every flow is already below 2.0 G.

For a per-flow CAP at target `T`:
- A flow on a worker with `k` flows runs at ≈ `min(W/k, T)` where `W` ≈
  per-worker capacity (~3.5 G).
- Workers with `k` such that `W/k > T` get clipped to `T`; the rest are
  untouched.
- Freed bytes on a clipped worker **cannot** migrate to a starved worker
  (different queue/CPU) → aggregate drops by the clipped amount; it is
  **non-work-conserving** for any `T < max_k(W/k)`.

So the candidate policies, with `W ≈ 3.5 G` and flow distribution
{1,2,3,4} flows on 4 of the 6 workers (2 idle):

| Policy | Target `T` | Flows clipped | Per-flow CoV effect | Aggregate effect |
|---|---|---|---|---|
| `ideal-share` (current default) | scheduler/flows = 2.0 G | none (all < 2.0 G) | none (no-op) | none |
| `clip-to-mean` | mean achieved ≈ 1.3 G | 1-flow (1.8 G) and 2-flow (1.63 G) workers → 1.3 G | top outliers removed; floor (0.87 G) UNCHANGED → partial CoV win | drops by clipped surplus (~1–2 G) |
| `clip-to-slowest` | min achieved ≈ 0.87 G | every worker with >0.87 G | near-flat (all ≈ 0.87 G) | ~40 % aggregate loss (17 → ~10.5 G) |

The hard limit, restated for the plan record: **the 0.87 G floor is never
raised by any of these.** Raising it requires cross-worker capacity =
#1748.

NOTE the asymmetry vs. the issue title: the issue title says current
behavior IS clip-to-slowest, and the #1745 A/B says current behavior is a
no-op at 2.0 G. Both are true at different times: the `min` reduction
*intends* clip-to-slowest (~0.87 G) but the fail-open guards + sample-set
collapse + EWMA frequently push the *published* target up to the
lightly-loaded subset's rate (2.0 G) or fail open entirely, which is why
it behaves as a no-op live. **This is a design tension the plan must
resolve, not paper over** (see §6 Path A vs the "fix the denominator"
alternative).

---

## 5. Design — the target-policy knob

### 5.1 Config surface (Go)

Add a childless-value leaf under each scheduler, adjacent to
`equal-flow-enforcement` at `schema.go:867`:

```
set class-of-service schedulers <s> equal-flow-target-policy (ideal-share | clip-to-mean | clip-to-slowest)
```

- `schema.go`: replace the childless `"equal-flow-target-policy"` with a
  value-slot leaf offering the 3 enum tokens (mirror an existing enum
  value-leaf, e.g. `priority`/`drop-profile` pattern in setSchema). Add
  the value-slot `?` completion + commit-check typed-leaf validation per
  `docs/config-schema.md`.
- `compiler_class_of_service.go`: parse the value into a new
  `sched.EqualFlowTargetPolicy string` (default `""` ≡ `ideal-share`).
  Commit-check WARNING (not error) if the policy is set but
  `equal-flow-enforcement` is absent (matches the existing #1733
  warn-not-strip discipline for equal-flow on a non-exact scheduler).
- Snapshot: add `EqualFlowTargetPolicy string
  json:"equal_flow_target_policy,omitempty"` to the scheduler snapshot
  in `protocol.go`. `omitempty` + empty-default keeps the wire bytes
  byte-identical for existing configs (the unchanged-snapshot test).

### 5.2 Rust runtime

- `protocol/cos.rs`: add `#[serde(rename =
  "equal_flow_target_policy", default)] pub equal_flow_target_policy:
  String` (or a small `enum EqualFlowTargetPolicy { IdealShare,
  ClipToMean, ClipToSlowest }` with `#[serde(default)]` →
  `IdealShare`). `default` keeps old snapshots decoding to the current
  behavior.
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
  `(prev_grants[id], active_flows[id])` pairs:
  - `IdealShare` (default): preserve the EXACT current code path
    byte-for-byte (the `min` reduction) — see §6 caveat: "default = byte-
    unchanged" means default is the current `min`, even though §1
    describes that as a no-op. We do NOT change the default's math.
  - `ClipToMean`: target = `sum(prev_grants[id]) /
    sum(active_flows[id])` over the sampled set (aggregate-weighted mean
    per-flow rate). Single division, no per-flow loop growth.
  - `ClipToSlowest`: target = `min` (identical to current default math),
    but distinguished from `IdealShare` ONLY by the metric label
    (they compute the same value today). **OPEN QUESTION for reviewers
    (§9 Q1):** is a distinct `ClipToSlowest` label justified if it is
    numerically identical to `IdealShare`'s `min`? Candidate
    resolution: make `IdealShare` literally publish `scheduler_rate /
    total_active_flows` (the "ideal" 2.0 G — the documented no-op) and
    make `ClipToSlowest` the `min`-of-achieved (~0.87 G). That gives
    three genuinely distinct targets and matches the operator's mental
    model from the A/B comment.
  - All policies keep the EWMA smoothing, the valid-streak gate, the
    fail-open guards, and the `max_worker_cap` telemetry publication
    unchanged — they operate on the chosen `candidate_target`.

### 5.3 Telemetry (which policy is active)

- Add `equal_flow_target_policy: String` to the queue status
  (`protocol/cos.rs` status struct + `status.rs:464-473` population) and
  a Prometheus label/gauge — reuse the existing
  `cosEqualFlowTargetPerFlowBPS` desc; add a sibling info-style metric
  `xpf_userspace_cos_equal_flow_target_policy{policy="..."}` OR a label
  on the existing target gauge. The operator confirms policy via
  `show class-of-service ... ` and `/metrics`. No new control-socket
  request (status poll already carries the queue block at 1/s).

---

## 6. Multiple path options

### Path A — three-value enum knob, default = current `min` math (this plan, §5)
- Minimal blast radius: one Rust math branch, one Go enum leaf, one
  snapshot field, one status field/metric. Default byte-unchanged.
- Honest: ships clip-to-mean as the only *new* useful policy; documents
  that none lift the floor.
- Risk: `clip-to-slowest` vs `ideal-share` numeric identity (Q1).

### Path B — "fix the denominator" instead of a knob
- Argument: the live no-op is a BUG (the published 2.0 G is the
  lightly-loaded subset's rate, not the slowest), so just make the
  default correctly clip-to-slowest-of-ACHIEVED and skip the knob.
- Rejected as the *primary* path because (a) it changes default behavior
  (violates the byte-unchanged contract), and (b) clip-to-slowest is
  non-work-conserving (~40 % aggregate loss) — making it the silent
  default is operator-hostile. But the underlying observation (published
  target ≠ slowest achieved) IS a real defect; Path A's Q1 resolution
  (make the three policies genuinely distinct) folds the fix in as an
  opt-in.

### Path C — PLAN-KILL
- Argument: a per-flow cap is structurally one-directional; clip-to-mean
  buys a partial CoV win at an aggregate cost and clip-to-slowest is
  strictly worse than doing nothing for most operators; the only policy
  an operator would actually want (lift the floor) is #1748. So the knob
  is busywork that ships two footguns.
- Counter: clip-to-mean is a legitimate, Junos-absent-but-defensible
  "shave the lucky outliers" policy an operator MIGHT want for jitter-
  sensitive workloads; and the telemetry/honesty improvements have
  standalone value. Reviewers decide whether that justifies the surface.

**Recommended: Path A with the Q1 resolution** (three genuinely distinct
targets), pending reviewer convergence. PLAN-KILL (Path C) is on the
table if reviewers judge clip-to-mean's win too marginal to justify the
config surface.

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
  §10 tradeoff table + the explicit "no policy lifts the floor → #1748"
  statement.

---

## 8. Test / validation plan

### 8.1 Unit (no hardware)
- `publish_equal_flow_epoch_v8`: table test with synthetic
  `(prev_grants, sampled_active_flows)` per worker proving:
  - `IdealShare` → unchanged value vs master for the same inputs
    (byte-identical default).
  - `ClipToMean` → `Σgrants / Σflows`.
  - `ClipToSlowest` → distinct from IdealShare per Q1 resolution.
  - Fail-open guards / EWMA / streak gate fire identically for all three.
- Go snapshot round-trip: a config WITHOUT the policy leaf serializes to
  byte-identical JSON vs master (omitempty proof).
- Go compiler: policy parsed; warning (not error) when set without
  enforcement; rejected enum value caught at commit.
- Schema completion: the 3 enum tokens complete at the value slot.

### 8.2 Smoke (loss userspace cluster — at /engineer time, NOT in /research)
Per `feedback_cos_iperf3_per_class` + `feedback_smoke_v4_and_v6` +
`feedback_smoke_push_and_reverse`, the eventual implementation PR's smoke
must run the full matrix on `loss:xpf-userspace-fw0`:
- v4 (172.16.80.200) + v6 (2001:559:8585:80::200), push + `-R`,
  per-CoS-class, for EACH of the 3 policies on port 5210 (`-P12`).
- Capture ground-truth **iperf per-stream CoV** (not
  `cos_active_flow_count`), aggregate Gb/s, and `cap_hit_events` /
  `suppressed_grant_bytes` / `fail_open_reason` for each policy.
- Acceptance: `ideal-share` ≈ master baseline (no-op); `clip-to-mean`
  shows lower CoV than `ideal-share` AND aggregate within the predicted
  band; `clip-to-slowest` shows lowest CoV at the predicted ~40 %
  aggregate cost. Numbers replace the §10 placeholders.
- Per `feedback_runnable_repro_before_measurement_claim`: ≥2–3× per cell,
  validate the per-flow counter sums to N streams, re-apply CoS after
  deploy (deploy wipes CoS).

### 8.3 Regression
- `make test` (Go) green. `cargo test -p userspace-dp` green.
- HA untouched (no cluster/VRRP/session-sync code in scope) → no
  `make test-failover` requirement, but state so explicitly in the PR.

---

## 9. Open questions for reviewers

- **Q1 (identity):** Is `clip-to-slowest` worth a distinct enum value if
  it equals the current `min` math, OR should we adopt the Q1 resolution
  (IdealShare = literal `scheduler_rate/total_flows`; ClipToSlowest =
  `min`-of-achieved) so all three are distinct? The Q1 resolution makes
  the DEFAULT (`""` → IdealShare) byte-unchanged only if today's default
  ALSO publishes `scheduler_rate/total_flows`. **It does NOT** — today's
  default is the `min`. So adopting Q1 means: default(`""`) MUST map to
  the current `min` math to stay byte-unchanged, and `ideal-share` the
  *named* value becomes the literal-share variant — i.e. the unset
  default and the named `ideal-share` would DIFFER. Reviewers must
  resolve this naming/back-compat knot. (Candidate: name the default-
  equivalent value `slowest` and reserve `ideal-share` for the literal
  share; document `""` ≡ `slowest`.)
- **Q2 (cap telemetry):** `current_worker_cap` is published but never
  enforced. Do we (a) leave it as-is, (b) wire it as a secondary
  per-worker ceiling, or (c) delete the dead telemetry? Recommend (a)
  for this issue (no behavior change); flag (c) as a possible follow-up
  refactor.
- **Q3 (kill threshold):** If clip-to-mean's measured CoV win is <~30 %
  relative reduction at >~10 % aggregate cost, is the knob worth the
  config surface, or PLAN-KILL in favor of #1748?
- **Q4 (default policy):** Confirm default MUST remain the current `min`
  behavior (byte-unchanged), NOT clip-to-mean — i.e. we do not improve
  the out-of-box behavior, only add opt-in policies. Per the standing
  "default byte-unchanged" contract, yes; reviewers confirm.

---

## 10. Throughput-vs-fairness tradeoff table (HONEST; #1745 A/B-backed)

`-P12`, port 5210, scheduler-24g exact, 6 mlx5 VF workers, loss cluster.
Per-flow values are the observed banding 0.87 / 1.29 / 1.63 / 1.81 G.

| Policy | Target | Binds on | Per-flow CoV (predicted) | Aggregate (predicted) | Lifts floor? |
|---|---|---|---|---|---|
| `ideal-share` / default (current `min`→published ~2.0 G in practice) | ~2.0 G | nothing | 14–29 % (= baseline, no-op) | ~16–17 G (baseline) | NO |
| `clip-to-mean` | Σgrants/Σflows ≈ 1.3 G | 1-flow + 2-flow workers | partial ↓ (top outliers gone; 0.87 floor stays) | ~14–16 G (−1 to −2 G) | NO |
| `clip-to-slowest` | min achieved ≈ 0.87 G | every >0.87 G flow | near-0 (all ≈ 0.87) | ~10.5 G (−40 %) | NO |

**The freed capacity from clipping CANNOT reach the slow flows** (they
are on different saturated workers). Lifting the 0.87 G floor is
work-conserving cross-worker rebalance = **#1748**, NOT this issue.
Numbers above are predictions from the #1745 A/B banding; the /engineer
smoke replaces them with measured per-policy values (§8.2).

## 11. Risks & rollback

- **Risk: default behavior drift.** Mitigated by the omitempty snapshot
  field + `#[serde(default)]` + the byte-unchanged snapshot test + the
  IdealShare-maps-to-current-`min` rule (Q1/Q4). If any of those slip,
  the smoke's `ideal-share` cell diverging from master baseline catches
  it.
- **Risk: lease rebuild churn.** `matches_config_v8` must include the
  policy so a live policy change rebuilds; otherwise a stale lease keeps
  the old policy. Covered by a coordinator test.
- **Risk: non-work-conserving footgun.** `clip-to-slowest` costs ~40 %
  aggregate; mitigated by it being strictly opt-in + a commit-check
  WARNING documenting the aggregate cost + the §10 table in operator
  docs.
- **Rollback**: revert the PR; unset configs are unaffected (default
  unchanged). No data migration.
