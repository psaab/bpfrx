# fable-review-166 — CoS / Flow-Fairness Coverage Campaign

**Focus:** Class of Service on the Rust AF_XDP userspace dataplane — scheduler
correctness, per-flow fairness, shaping, classification, control-plane
compile, validation harnesses — plus a NEW-IDEAS section (operator ask:
"new ideas to get this working well, especially around fairness of flows"),
constrained by the project's extensively documented kill-list of rejected
approaches.

## 1. Base commit reviewed

`426cc3f78` — "Merge pull request #4152 from psaab/fix/hb164-m6m7-http-dos"
(tip of `origin/master` at review time).

Same worktree note as fable-review-165: the primary checkout still carries the
stale unmerged `UU _Log.md` index entry, which blocks `git pull --rebase`;
the review ran against a fresh detached worktree of `origin/master`
(fetched at campaign start), leaving the operator's tree untouched.

## 2. Output path

`/tmp/fable-review-166.md` (highest existing campaign number 165; fable owns
it, so this campaign takes 166).

## 3. Duplicate suppression summary

Read for dedup: all `/tmp/{codex,agy,fable}-review-*.md` (fable-161's
dedicated CoS modules, codex-162's flow-cache/CoS-classify audit,
codex-133's DSCP/policer audit, agy-146's MQFQ vtime review are the
CoS-bearing ones), the full CoS/fairness issue history (≈120 issues/PRs
mapped), and the design docs: `docs/fairness-regimes.md` (ratified structural
contract), `docs/cross-worker-flow-fairness-research.md` (algorithm survey),
`docs/cos-traffic-shaping.md`, `docs/cos-design-steps.md`,
`docs/cos-wan-sqm.md` (#1828 cookbook), `docs/cos/` review trail,
`docs/cos-best-effort-contention-harness.md`.

**Suppressed prior campaign findings (still-open or unverified ones):**
fable-161 F-097 (transmit-rate percent/remainder unsupported), F-205
(dual-AST collector duplication), F-079 (dispatch double-free on debug
tuple-mismatch), F-126 (enqueue_pending_forwards monolith), F-234 (None-arm
frame drops), F-235 (FIFO settle bypasses accounting), F-268 (shared-queue
wakeup underestimates refill), F-210 (ValidateConfig mutates live config),
F-080/F-128 (filter double-count / hot-path allocs), codex-162 M1/M3/M4/M8/
L2/L8/L9 (cache family-gate / silent rewrite failure / stale debug counts /
engine unification / test gaps), codex-133 H01-H03/M01/M07/M08 (DSCP wire
masks, policer lowering), agy-146-01..03 (vtime rollover, heap re-parent,
TSC jitter — flagged for path re-verification), codex-001 H03 (reject on TX
path).

**Suppressed as fixed on master** (prior findings that landed): F-027→#3993
(residual #3995 is a KNOWN open issue), F-028→#4021, F-078→#3968,
F-194→#4002, codex-162 H3→(#counted), H4/H5→#3778, #2447, #1809, #2955,
#2981, #2646, #2624, #1743, #1732, #1830, #1745, #1763, #1863.

**Suppressed as known-open tracker issues:** #1359 (surplus-sharing p99.9
mouse gate FAIL), #1365 (high-rate cwnd settle), #3995 (loss-priority
rewrite at apply time), #3618 (global reject bucket cross-zone), #739/#738
(lab CPU isolation), #2354 (QinQ), plus the contract's own open questions
(ε policy, ECN-split mouse gates, `{aᵢ}` measurement trust).

**The kill-list (approaches that MUST NOT be re-proposed without citing the
kill):** #840 RSS rebalance (implemented+REVERTED, CoV 37.7% vs 18.5%);
#1203/#1204 reactive ntuple re-steer (49-55% CoV); #1215/#837/#936/#899/#937
cross-worker vtime table / cross-queue XDP_REDIRECT (kernel `xsk_rcv_check`
forbids); #1649 hardware ntuple placement (Monte-Carlo: no static map beats
the multinomial floor); #1748/#1750/#1751 ntuple controller (parked);
#1742 same-queue fanout; #1238 per-flow-bucket token bucket (breaks work
conservation); #1243 dedicated cores (−17% throughput); #1244 auto-tuned
Toeplitz key; #1245 multi-receiver; #831/#834/#838/#1211 AFD/CSFQ overlays
(explored; MQFQ+V_min won); #1229 vtime+RWND throttle; #1829 Phase 2
FQ-CoDel dequeue law (PLAN-KILLED on gate evidence); #1849 CAKE overhead
compensation (3/3 PLAN-KILL, demand-gated); kernel tc/qdisc SQM (#1828
verdict: no-op for forwarded traffic); flat per-flow CoV gates (#1614
original, formally dropped for the Cstruct-relative gate).

## 4. Module checklist

| # | Module | Status |
|---|--------|--------|
| 1 | `userspace-dp/src/afxdp/cos/` core (admission, token_bucket, fairness, flow_hash, ecn, queue_ops, queue_service, tx_completion, cross_binding, builders) | reviewed (§6/§7 R-*) |
| 2 | `userspace-dp/src/afxdp/tx/` (cos_classify, dispatch, drain incl. phase_shaped, transmit, rings, stats) | reviewed (T-*) |
| 3 | `types/cos.rs`, `types/shared_cos_lease/`, sojourn | reviewed (T-*) |
| 4 | worker/coordinator CoS state + leases (`worker/cos_state.rs`, `worker/cos/`, `coordinator/cos_state.rs`, `cos_leases.rs`) | reviewed (T-*) |
| 5 | `forwarding_build/cos.rs` (admission gate, synthetic queue) | reviewed (T-*/G-*) |
| 6 | `pkg/config` CoS compile (compiler_class_of_service, schema, validate-warn) | reviewed (G-*) |
| 7 | protocol boundary (`protocol/cos.rs` ↔ Go emitters) | reviewed (G-*) |
| 8 | CLI/gRPC/Prometheus CoS observability | reviewed (G-*) |
| 9 | vSRX CoS parity surface | reviewed (G-*) |
| 10 | fairness/CoS harnesses (`test/incus/fairness-*`, `cos-*`, iperf parsers) | reviewed (V-*) |
| 11 | `src/fairness.rs`, `fairness_eval/`, `bin/fairness-eval.rs` | reviewed (V-*) |
| 12 | Contract docs vs code (fairness-regimes gates, wan-sqm anchors) | reviewed (V-*/G-*) |
| 13 | Fairness ideas space (literature 2022-2026 + kill-list-compatible design) | §9 |

## 5. Module-by-module inspection log

1. **pkg/config CoS compile + schema** — full pass over
   `compiler_class_of_service.go`, `schema_cos.go`, `types_cos.go`,
   validate-warn/strict. Clean (verified negative): unit conversions
   (bits/s decimal-k → bytes/s, no 1024 confusion), percent-buffer
   dual-form strict rejects, FC↔queue bijection, out-of-range DSCP/PCP
   rejects, equal-flow gating, #4021 interface-level fold semantics.
   Findings G-1..G-6, G-8, G-11.
2. **protocol boundary + Go emitters** — CoS rides the full snapshot and
   per-interface snapshots; helper restart/reconnect re-applies via the
   1 s status loop (`process.go:531-535`) and unhealthy-restart path —
   the "deploy wipes CoS" gotcha is test-harness design (deploy pushes a
   CoS-less baseline conf + `rm -rf .configdb`), NOT a persistence bug
   (verified negative, G-7).
3. **CLI/gRPC/Prometheus observability** — the fairness-regimes
   "Required metrics — production" list EXISTS in code (all four
   xpf_fairness_* gauges + per-queue drops/parks/sojourn; verified
   negative). Gaps: no `show interfaces queue` / `show class-of-service
   <classifier|scheduler-map|forwarding-class>` command surface (G-8.7).
4. **Rust CoS core (afxdp/cos/)** — findings R-*.
5. **TX/scheduler path (afxdp/tx/, types, leases, coordinator)** —
   findings T-*.
6. **fairness_eval + fairness.rs** — Cstruct math is a faithful,
   test-pinned implementation of the contract's worked examples
   (verified negative); windowing/trim/{aᵢ} pipeline defects V-4..V-7.
7. **test/incus CoS/fairness harnesses** — fail-closed plumbing is
   strong (13 hunted vacuous-pass shapes came back clean, V-13) but the
   two guarantee-asserting harnesses never propagate failure (V-1, V-2)
   and Gate 3 is circular (V-3).
8. **Contract docs vs code** — priority-low-min-share acceptance gate
   asserts an unimplemented knob (G-2); Gate-3 text self-contradicts
   (V-3); required-metrics list vs fairness-eval report divergence
   (V-10).

Confidence tiers: **High** = evidenced in code read this run (top items
re-verified line-by-line by the coordinating reviewer); **Medium** = likely
defect needing runtime validation; **Low** = design smell / parity gap.

---

## 6. Findings — HIGH CONFIDENCE

### V-1. `cos-simul-load-smoke.sh` can never fail: gate booleans are computed, printed, and discarded

- **Title:** the canonical all-11-class CoS smoke (declared "part of the
  canonical smoke matrix for any PR that touches CoS scheduling" in
  fairness-regimes.md) always exits 0
- **Severity:** High
- **Confidence:** High (verified: zero `sys.exit`/exit-propagation in the
  script; reducer heredoc ends after printing `gates`)
- **Evidence:** `test/incus/cos-simul-load-smoke.sh:226-233` — verdict.json
  written, gates printed, no exit-status wiring; iperf launchers are
  `|| true` (:79), so even total generator failure exits 0. Gates computed
  but unenforced: `gate_1_small_class_divided_ceiling_floor`,
  `gate_2_priority_low_min_share`, `gate_3_retrans_floor` (:191-225).
- **Trace:** a starve-to-zero collapse of 100m/1g/3g/6g — the exact
  regression the divided-ceiling floor exists to catch — prints FAIL in
  JSON and exits 0; any CI or `&&`-chained invocation passes silently.
- **Why it matters:** this is the ONLY harness asserting the #1614
  divided-ceiling floors under simul load; as wired, the assertion exists
  only for a human reading stdout.
- **Fix direction:** end the reducer with
  `sys.exit(0 if all(gates.values()) else 1)` and propagate — the
  `cos_be_contention_validate.py` pattern already used elsewhere.
- **Labels:** bug, test-infra, cos
- **Dedup note:** no prior campaign finding or issue covers harness exit
  wiring; #1614/#1630 shipped the gates themselves.

### V-2. `cos-gate1-small-four-alone.sh` — same defect on the SOLO ≥95% guarantee gate

- **Title:** the one harness asserting the #1630 cause-1 acceptance gate
  (100m/1g ≥ 95% of shape SOLO) prints `GATE1 FAIL` and exits 0
- **Severity:** High
- **Confidence:** High (verified: no sys.exit; `|| true` launchers; a JSON
  parse error marks ERR/all_pass=False and still exits 0)
- **Evidence:** `test/incus/cos-gate1-small-four-alone.sh:63-74`.
- **Why it matters:** fairness-regimes.md delegates the ≥95% SOLO
  guarantee to exactly this harness after the full-11 rescope — the
  guarantee is currently unenforceable by machine.
- **Fix direction:** as V-1.
- **Labels:** bug, test-infra, cos
- **Dedup note:** unreported.

### V-3. Gate 3 (saturated aggregate ≥ 95% of the Nₐ/Nᵥ-scaled cap) is vacuous by construction — saturation labeling and the gate use the same predicate

- **Title:** a shaped class delivering 50% of its cap is simply labeled
  non-saturated (labeling predicate = ≥95%-of-cap in ≥80% of buckets),
  and non-saturated runs exempt aggregate from gating — so no single-run
  harness can fail on aggregate throughput at all
- **Severity:** High (gate soundness)
- **Confidence:** High (verified: `fairness_eval/verdict.rs:109-117`
  computes `saturated` report-only; `failure_reasons` (:119-147) contains
  starved/gap/a_i-sum/RSS/cos-binding — no aggregate reason exists;
  `is_saturated` in `fairness.rs:113-124` is the same ≥95%/80% test the
  doc's Gate 3 asserts)
- **Trace:** fairness-neutral throughput regression (class at half shape,
  flows evenly slow → CoV≈0 ≤ Cstruct+0.05) passes fairness-harness,
  passes fairness_multi_sample (gap-only), passes the class sweep
  (`avg_rate_utilization` informational); the docs' non-shaped "±5% of
  measured baseline" clause has NO implementation anywhere.
- **Why it matters:** the contract's throughput leg is unenforced; only
  `cos_be_contention_validate.py` (0.70×cap) and the non-exiting V-1/V-2
  harnesses assert any throughput floor.
- **Fix direction:** break the circularity with an input observed data
  can't launder: an operator-declared offered-load≥cap flag (then gate
  aggregate ≥ 0.95×scaled-cap), or a prior-tip baseline artifact (the
  documented ±5% clause). Reconcile the two contradictory doc sections
  ("applies" vs "labeling does not change pass/fail").
- **Labels:** bug, test-infra, cos, docs
- **Dedup note:** unreported; distinct from the #1614 flat-CoV-gate
  rescope (that dropped a per-flow gate; this is the aggregate leg).

### G-1. `priority-low-min-share` (#1614 A2) is inert in the engine while the ratified contract lists an acceptance gate asserting it works

- **Title:** the knob compiles, rides the wire, is stored — and is read by
  no scheduler code; the queue_service comment cites a `cap_eff`
  subtraction that does not exist; fairness-regimes.md gate 2 asserts
  "the priority-low queue receives ≥ 95% of its configured
  priority-low-min-share"
- **Severity:** High
- **Confidence:** High (verified by repo-wide grep: writes at
  `forwarding_build/cos.rs:511`, `cos/builders.rs:146`, declarations in
  `types/cos.rs:58,520` (whose own comments say "WIRE SURFACE ONLY in PR
  #1618 — reserved for the deferred cap_eff"), zero reads; no `cap_eff`
  identifier exists in code, only comments)
- **Evidence:** `userspace-dp/src/afxdp/cos/queue_service/mod.rs:606-611`
  claims "see service_exact_guarantee_queue_direct_with_info for the
  cap_eff subtraction that handles priority-low orthogonality (per AGY r3
  finding B)" — that function contains no such logic. Also absent from
  `setSchema` (no completion/validation; garbage parses to 0) and zero
  tests reference it (Go or Rust).
- **Trace:** operator sets `priority-low-min-share 500m` per the docs →
  commit succeeds → the low-priority queue gets NOTHING beyond ordinary
  rank-5 servicing under contention; the documented gate would fail if
  any enforcing harness ran it (none does — the V-1 harness computes
  gate_2 but never exits non-zero, and the knob does nothing anyway).
- **Why it matters:** contract/doc/code three-way contradiction on a
  starvation-protection knob; the misleading comment will defeat the next
  reviewer.
- **Fix direction:** implement the deferred cap_eff subtraction (reserve
  `min_share` bytes of each root-bucket pass for the priority-low queue
  before rank servicing) or annotate knob + docs + comment as
  NOT-IMPLEMENTED and warn at commit; add the schema leaf; add tests.
- **Labels:** bug, cos, docs, vsrx-parity
- **Dedup note:** unreported anywhere; distinct from the documented-inert
  `codel-target` (G-3) whose cookbook already warns operators.

### G-2. Dangling scheduler reference in a scheduler-map silently strips a class's guarantee (warn-only, then fail-open in Rust)

- **Title:** `scheduler-map M forwarding-class ef scheduler <typo>`
  commits with a warning; the Go emitter forwards the dangling name; Rust
  builds the queue `guarantee_enabled=false`, rate = whole interface
  shaping rate, priority low — the EF class silently loses its guarantee
- **Severity:** Medium
- **Confidence:** High
- **Evidence:** `compiler_validate_warn.go:704-712` (warn);
  `pkg/dataplane/userspace/cos.go:220-231` (filters only undefined
  forwarding classes); `forwarding_build/cos.rs:307-345`
  (`guarantee_enabled = explicit_transmit_rate_bytes.is_some()`,
  `unwrap_or(iface.cos_shaping_rate_bytes_per_sec)`, priority default
  "low").
- **Why it matters:** Junos hard-rejects unresolved scheduler refs; here a
  typo yields a live config whose premium class is best-effort — invisible
  except in runtime queue rows.
- **Fix direction:** promote dangling scheduler/scheduler-map/classifier
  refs to commit errors in `validateClassOfServiceStrict` (lenient-load
  downgrade for boot per the #1960 pattern); flag "scheduler unresolved"
  in the runtime row meanwhile.
- **Labels:** bug, cos, config, vsrx-parity
- **Dedup note:** unreported; adjacent to but distinct from #2704/#2706
  (undefined forwarding-class no-op, fixed).

### G-3. Inert-`codel-target` operator surface: no commit warning, no schema leaf, silently-ignored garbage values, zero tests

- **Title:** the knob is documented inert in the WAN-SQM cookbook, but the
  config system accepts it without the warning the project's own doctrine
  mandates, offers no completion, and `codel-target banana` is silently
  dropped by the `err == nil` parse guard
- **Severity:** Medium (documented-inert; the gap is the missing
  guard-rails, not the inertness)
- **Confidence:** High (verified: `codel_target_ns` written into runtime
  structs at `types/cos.rs:236,824` via `builders.rs:195` and read by no
  scheduler logic; `compiler_class_of_service.go:267-274` swallows parse
  errors; absent from `schema_cos.go` schedulers children)
- **Fix direction:** commit warning (mirroring
  `validateFilterLossPriorityWarnings`) until #1829-Phase-2-style evidence
  reopens enforcement; typed schema leaf; tests.
- **Labels:** bug, cos, config
- **Dedup note:** the inertness itself is documented
  (docs/cos-wan-sqm.md "Do not set codel-target expecting AQM today") and
  #1829 Phase 2 is PLAN-KILLED — this finding is the missing warn/schema/
  test guard-rails only.

### G-4. `shaping-rate`/`burst-size` schema leaves are untyped: garbage commits as 0 — silent shaper removal

- **Title:** `set class-of-service interfaces reth0 unit 80 shaping-rate
  10gg` commits; `parseBandwidthLimit("10gg")` → 0 → the root shaper
  silently disappears (unshaped 25G egress instead of the intended cap)
- **Severity:** Medium
- **Confidence:** High (`schema_cos.go:111-113` has no
  valueType/validator, unlike sibling `transmit-rate`/`buffer-size` which
  were typed in #1319 for exactly this reason;
  `compiler_protocols.go:930-932,993-995` returns 0 on garbage)
- **Fix direction:** `valueType: ValueRate, validator: ValidateRate` (+
  `ValidateByteSize` for burst-size) — the validators already exist.
  Same treatment for `oversubscription-policy`/`guarantee-rate` (absent
  from schema entirely; `guarantee-rate 1.7` silently clamps to 1.0,
  `typo-rate` falls back to proportional — G-5).
- **Labels:** bug, cos, config
- **Dedup note:** unreported.

### G-5. `oversubscription-policy` + `priority-low-min-share` missing from setSchema — no completion, no typed validation, silent-intent no-ops

- **Title:** the #1614 A1/A2 knobs the harness fixture itself uses are
  invisible to `set ... ?` completion and SchemaValidate; unknown policy
  strings commit and fall back to proportional
- **Severity:** Medium
- **Confidence:** High (`schema_cos.go:102-132` unit children:
  classifiers/rewrite-rules/shaping-rate/scheduler-map only;
  `compiler_class_of_service.go:431-478` parses both; fixture sets one at
  `cos-iperf-config.set:71`; #1746's `equal-flow-target-policy` shows the
  correct precedent — it IS in schema)
- **Fix direction:** typed leaves — fraction validator [0,1] for
  guarantee-rate, enum for the policy; commit-reject unknown policy
  strings (fail-closed like #2458 did for equal-flow-target-policy).
- **Labels:** bug, cos, config
- **Dedup note:** unreported.

### G-6. CoS binding on a nonexistent interface/unit is a silent no-op

- **Title:** `class-of-service interfaces <typo> unit N ...` commits
  cleanly and shapes nothing — CoS bindings only take effect inside the
  `cfg.Interfaces` iteration, and the warn validator checks named objects
  but never that the IFL exists
- **Severity:** Medium
- **Confidence:** High (`pkg/dataplane/userspace/interfaces.go:228-237`;
  `compiler_validate_warn.go:774-813`)
- **Why it matters:** Junos rejects CoS on a nonexistent IFL; here a
  `reth0`-vs-`reth1` typo leaves the WAN unshaped with only a "Runtime:
  unavailable" tell.
- **Fix direction:** warn (or strict) that each
  `cos.Interfaces[name].Units[n]` resolves against `cfg.Interfaces`.
- **Labels:** bug, cos, config, vsrx-parity
- **Dedup note:** unreported.

### V-4. fairness-eval's a_i overcount trim removes flows from the LARGEST bucket — which can RAISE Cstruct and loosen the Gate-2 tolerance

- **Title:** an accepted stale-entry overcount on an evenly-loaded
  distribution manufactures skew: `{3,3}` observed with target sum 5
  trims to `{2,3}` (Cstruct 0.00 → 0.204), widening the allowed CoV from
  0.05 to ~0.254 — fail-open in exactly the wrong direction
- **Severity:** Medium
- **Confidence:** High on the math (agent-verified against
  `per_worker.rs:186-202` + `verdict.rs:91-98`), Medium on real-world
  frequency
- **Fix direction:** choose the trim that MINIMIZES Cstruct (or gate on
  min(Cstruct_raw, Cstruct_trimmed)) — fail-closed.
- **Labels:** bug, test-infra, fairness
- **Dedup note:** unreported; the #1281 stale-entry tolerance itself is
  known — the trim direction is the novel defect.

### V-5. CoS-source `{aᵢ}` medians ignore absent (zero) samples — dead workers stay "active"

- **Title:** the exporter emits CoS active-flow rows only for live flows,
  and `aggregate_cos_per_worker` medians over PRESENT samples only — a
  worker whose flows died 10 s into a 114 s window keeps median 2, not 0,
  inflating Nₐ and distorting Cstruct (the binding-source path zero-fills
  and is immune — two sources, different statistics for the same contract
  quantity; the canonical class sweep uses the CoS source)
- **Severity:** Medium
- **Confidence:** High (mechanism: `per_worker.rs:145-160`,
  `umem/debug_state.rs:263-273`, `metrics_userspace.go:795-806` vs the
  zero-filling `emitBindingActiveFlowCount` at :720-731)
- **Fix direction:** zero-fill each worker's samples to the full
  in-window timestamp universe before the median.
- **Labels:** bug, test-infra, fairness
- **Dedup note:** unreported; interacts with the docs' own caveat (b)
  about the ~650 ms recency window (V-12.7 coverage gap).

### V-6. fairness-eval anchors the steady window to scrape-file min/max, not the iperf epoch — stale pre-run samples land inside the window

- **Severity:** Medium. **Confidence:** High.
- `per_worker.rs:46-57` (min/max heuristic) vs
  `fairness_equal_flow_capture.py:237-255` (iperf `timesecs` anchoring)
  in the SAME sweep — two reducers disagree on "steady-state"; the
  cooldown-era staleness the sweep guards against can still contaminate
  the head of the fairness-eval window.
- **Fix direction:** pass the iperf epoch window into the per-worker
  aggregation (already available in `inputs.iperf.start`).
- **Labels:** bug, test-infra, fairness
- **Dedup note:** unreported.

### V-7. The ≥60 s steady-state minimum checks DECLARED duration, not observed samples (and `omitted` intervals aren't filtered)

- **Severity:** Medium. **Confidence:** High.
- `windowing.rs:17-33` gates on `iperf.start.test_start.duration`; a
  truncated JSON with a handful of intervals passes and produces a CoV
  from a few buckets, violating the contract's "must reject such runs
  with an explicit error". `-O` omitted intervals would count as data
  (latent — harness never passes -O, but fairness-eval is a CLI).
- **Fix direction:** require `aggregate_buckets_bps.len() ≥ 60±slack`;
  skip `omitted:true` intervals.
- **Labels:** bug, test-infra, fairness
- **Dedup note:** unreported.

### V-8. Surplus give-back contract: validator with no live runner, and the handback timestamp is self-attested

- **Severity:** Medium (coverage). **Confidence:** High.
- `fairness_surplus_giveback_validate.py:113-132` accepts the first
  list-order sample matching the thresholds — no monotonic-t_sec check,
  no pre-handback-state sample, no density requirement; a one-element
  artifact passes the ≤5 s gate. And NOTHING in the tree produces
  `phases.json` — the 100E100M give-back contract is exercised only by
  hand-built artifacts (the docs explicitly claim the validator "must
  derive the handback point from auditable data").
- **Fix direction:** ≥2 samples, monotonic t_sec, first-sample
  pre-handback state, max gap; build the live reducer from
  iperf/Prometheus.
- **Labels:** bug, test-infra, cos
- **Dedup note:** #1321 defined the contract; the runner absence and
  validator laxity are unreported.

### V-9. fairness-eval verdict omits doc-mandated required metrics (per-flow quantiles, window timestamps, saturation series)

- **Severity:** Medium (contract divergence). **Confidence:** High.
- `fairness_eval/report.rs:5-60` vs fairness-regimes.md required-metrics
  items 1/6/12; raw artifacts persist only when ARTIFACT_DIR set, so a
  routine verdict cannot satisfy the MUST list post-hoc.
- **Fix direction:** add quantiles, window epoch, per-bucket series (or a
  mandatory artifact pointer) to Report.
- **Labels:** cleanup, test-infra, docs
- **Dedup note:** unreported.

### G-7/V-13. Verified-clean core (negative results — recorded per the contract's honesty rule)

- **"Deploy wipes CoS" is NOT a persistence bug:** committed CoS persists
  in the configstore and recompiles on restart; helper
  restart/reconnect re-applies the full snapshot (generation-gated 1 s
  loop, `process.go:531-535`); the deploy script explicitly pushes a
  CoS-less baseline conf and `rm -rf /etc/xpf/.configdb`
  (`cluster-setup.sh:925-933`) — by construction, not by defect.
  Quality-of-life fix: bake the CoS fixture into the deploy baseline or
  chain `apply-cos-config.sh` from `cluster-deploy`.
- **Production fairness metrics exist as documented:** all four
  `xpf_fairness_*` gauges + per-queue admission drops, parks, waterfill
  counters, v8 lease claim flow, sojourn triplet, flow-fair occupancy —
  registered and emitted (`metrics_descriptors.go:1460-1483`,
  `metrics_userspace.go:43-47`).
- **Cstruct math:** `compute_cstruct` implements the contract exactly;
  unit tests pin all five worked-example values (0.00/0.47/0.20/0.58/
  0.00); ε=0.05 matches.
- **Harness fail-closed plumbing:** 13 hunted vacuous-pass shapes all
  refused (dead traffic fails Gate 1; empty scrapes exit 2; zero `{aᵢ}`
  fails the sum guard; env-shape guard #1365 implemented exactly as
  documented; port-grid drift cross-pinned; be-contention validator
  genuinely fail-closed; multi-sample wrapper robust).
- **Units/percent/bijection in the Go compiler:** clean (see §5.1).

### G-8. vSRX CoS parity gaps (grouped; label vsrx-parity)

- **Severity:** Medium in aggregate. **Confidence:** High (keyword-absence
  verified across pkg/config + schema).
- (1) **`drop-profiles`/WRED + `drop-profile-map`: absent entirely.**
  Combined with inert codel-target (G-3) there is NO configurable AQM;
  early-drop signals are the fixed admission buffer threshold + ECN mark.
  For the operator's "CoS working really well" goal this is the largest
  parity hole. (2) `transmit-rate percent <n>` / `remainder`: refuses
  commit loudly (typed leaf) — but it is the single most common Junos
  scheduler idiom; imported vSRX configs won't commit (also
  `buffer-size temporal`, `shaping-rate percent`). (3) `excess-priority`/
  `excess-rate` absent (xpf-specific `surplus-sharing` instead).
  (4) `rewrite-rules ieee-802.1` absent (DSCP only — no PCP rewrite on
  trunk egress). (5) `classifiers inet-precedence` + Junos default
  forwarding classes/classifier absent (no scheduler-map → only a
  synthetic best-effort queue 0). (6) `strict-high` is merely rank 0 of a
  6-rank ladder — no unbounded-priority semantic; dead `"medium"` arm;
  unknown priority strings silently rank 5. (7) No `show interfaces
  queue`, no `show class-of-service classifier|scheduler-map|
  forwarding-class`, no `clear class-of-service statistics` — the data
  exists but not under the names a Junos operator types.
- **Fix direction:** triage as separate parity issues; (7) is pure
  cmdtree/formatting over existing data — cheapest high-value win;
  (2) percent-form transmit-rate is a compiler feature with the schema
  precedent already present; (1) WRED is the big one and should be
  designed against the shipped admission/ECN machinery rather than as a
  literal RED port.
- **Labels:** vsrx-parity, cos
- **Dedup note:** fable-161 F-097 covered transmit-rate percent
  (suppressed as prior — listed here only as part of the grouped parity
  surface); the remaining six items are unreported. #2008's general
  parity catalog does not enumerate CoS internals.

### G-9. `fairness rss-expectation` config is keyed by kernel ifindex — silently wrong after NIC re-enumeration

- **Severity:** Low. **Confidence:** High (`types_cos.go:169-173`,
  documented-intentional).
- A config keyed to a transient kernel id evaluates the wrong port after
  reboot/hotplug; the guard it feeds then judges the wrong interface's
  `{aᵢ}`.
- **Fix direction:** key by interface name, resolve to ifindex at
  compile/apply.
- **Labels:** cleanup, cos, config
- **Dedup note:** unreported.

### G-10. Level-vs-unit CoS merge nit: unit shaping-rate override inherits the LEVEL's burst-size

- **Severity:** Low. **Confidence:** High
  (`mergeCoSInterfaceLevelInto`, `compiler_class_of_service.go:541-548`).
- A unit that overrides `shaping-rate` keeps the interface-level
  `burst-size`, pairing a level burst with a unit rate. Defensible but
  undocumented; a 10× rate mismatch makes the burst 10× of intent.
- **Fix direction:** doc line, or reset burst when rate is overridden.
- **Labels:** cleanup, cos, docs
- **Dedup note:** #4021 shipped the fold; this interaction unreported.

### G-11/V-14. Test-coverage gaps (grouped)

- **Severity:** Medium in aggregate. **Confidence:** High.
- Go/config: zero tests for `codel-target` and `priority-low-min-share`
  (both directions); no test for dangling-scheduler degraded-queue shape
  (G-2); none for CoS-on-undefined-unit no-op (G-6); no negative test
  that `transmit-rate percent` is rejected (the vSRX-import failure
  mode).
- Contract: the **Regression bounds section has zero tooling** (gap
  ≤0.02 vs prior tip, aggregate ≤5%, mouse p99 ≤10% — no harness accepts
  a baseline artifact; enforced by human diligence only). No UDP or
  mixed TCP/UDP fairness harness exists at all (grep `-u/--udp` → zero
  hits — the entire contract is validated with TCP elephants). Simul
  floors cover only 5201-5204 + 5211; a zero-collapse of 5205-5210 trips
  no gate. Mixed-CoS multi-sampling unsupported (wrapper rejects
  two-verdict output). No production-vs-harness Cstruct parity check.
  Low-rate `{aᵢ}` hollowing (contract caveat (b)) unquantified.
- **Fix direction:** baseline-artifact support in fairness-harness (fixes
  the Regression-bounds hole and gives V-3 its non-circular input); a UDP
  leg (even one iperf3 `-u` class) in the sweep; extend SIMUL_FLOOR_PCT
  to all 11 ports; unit tests per the Go list.
- **Labels:** test-gap, cos, fairness
- **Dedup note:** unreported.

### R-1. Stale `flow_bucket_observed_bps` never decays or resets — the cap-aware MQFQ selector punishes new flows with a dead flow's rate

- **Title:** bucket-idle reset clears only finish tags; the per-bucket
  observed-rate EWMA survives flow death, so a newcomer hashing into a
  recycled bucket is deferred as if it were the old elephant
- **Severity:** High (fairness under flow churn)
- **Confidence:** High (re-verified: `accounting.rs:120-129` resets only
  `flow_bucket_head/tail_finish_bytes`; the only writer of
  `flow_bucket_observed_bps` is the EWMA at `cos/fairness.rs:92-104`,
  whose skip-ramp arms only at 0 — and nothing ever returns it to 0)
- **Evidence:** selector at `cos/queue_ops/mod.rs:134-138` defers any
  bucket with `observed > target_bps` while another is under-cap;
  fallback only when ALL are over-cap.
- **Trace:** elephant drives bucket B's EWMA to 2 Gbps against an
  ~83 Mbps target (1 G queue / 12 active buckets); flow ends; EWMA stays
  2 Gbps indefinitely (decay requires TX commits, which require service).
  A new flow hashing into B gets bursty fallback-only service for ~25
  EWMA rolls; after hours of churn most of the 4096 buckets carry stale
  nonzero rates.
- **Why it matters:** inverts the mechanism's purpose — built to protect
  cool flows, it throttles the coolest (a newcomer). Invisible to
  steady-state iperf smoke; bites real traffic (short-flow churn).
- **Fix direction:** on the bucket nonzero→0 transition also zero
  `observed_bps/last_tx_ns/pending_bytes` (bucket identity ends there);
  and/or make the EWMA old-term dt-aware so idle time decays it. Add the
  missing selector-defers-at-finite-target test (the positive action of
  the cap-aware selector is completely untested today).
- **Labels:** bug, cos, fairness, dataplane
- **Dedup note:** unreported; distinct from the killed #1238 (per-flow
  token buckets) and from #1229's v7 design (this is a defect IN that
  shipped mechanism's state lifecycle).

### R-2. Non-exact guaranteed classes are admitted at up to N_workers × configured rate on shared interfaces

- **Title:** each worker's replica of a non-exact guaranteed queue
  refills at the FULL configured transmit-rate; class-wide shared
  metering exists only for exact queues — a 1g non-exact guarantee on
  the 6-worker cluster can take ~6 Gb/s at guarantee priority
- **Severity:** High
- **Confidence:** High on the mechanism (re-verified:
  `worker/cos/mod.rs:198-201` attaches `shared_queue_lease` only when
  `queue.exact`; `queue_service/mod.rs:1250-1257` refills per-worker at
  `queue.transmit_rate_bytes()`); Medium on production impact (depends
  on non-exact guaranteed classes being used on shared egresses — the
  standard fixtures use exact classes)
- **Why it matters:** the excess bypasses both the surplus-phase DWRR
  and the `SharedCoSExactBacklog` residual bound — the whole
  cross-worker constraint machinery constrains only the surplus leg.
  Directly relevant to #1359's surplus-vs-guarantee interactions.
- **Fix direction:** attach a shared legacy lease to non-exact
  guaranteed queues (the non-exact-with-lease path at
  `token_bucket.rs:281-300` already exists and is unreachable in
  production), or divide the per-worker refill by active shards. Add an
  N-worker aggregate-admission test (none exists).
- **Labels:** bug, cos, fairness, dataplane
- **Dedup note:** unreported; same *class* as closed #4002/#2955
  (over-admission via split state) but a different, still-open site.

### R-3. v8 epoch seqlock writer publishes payload with no ordering after the EVEN→ODD claim — torn snapshots on weakly-ordered CPUs

- **Title:** the claim CAS's release half orders PRIOR writes only; the
  payload stores are Relaxed and the sole Release is the final ODD→EVEN
  store, so a reader can pass seq validation while seeing new-epoch
  payload against an old even sequence — the #1619 tearing class, of
  which #1643 fixed only the reader half
- **Severity:** Medium (latent on x86-TSO — today's target; real on
  ARM/POWER; a specification bug regardless)
- **Confidence:** High (agent verified at the memory-model level:
  `rotate_epoch_v8.rs:50-57` claim, `:392-411` Relaxed payload +
  Release publish; the in-code comment reasons from single-thread
  program order)
- **Fix direction:** `fence(Ordering::Release)` after the successful
  claim CAS (Boehm's seqlock recipe — one instruction per 200 µs);
  add a loom test (the codebase has zero weak-memory tests across
  seqlock/V_min/backlog/residual-budget).
- **Labels:** bug, cos, dataplane, x-hpc
- **Dedup note:** #1643 (reader) and #1619 (tearing class) are closed;
  the writer half is unreported.

### R-4. Refill fractional dust systematically under-runs low-rate classes (same failure shape as #1630, one decade lower)

- **Title:** every granting refill floors the byte grant and advances
  `last_refill_ns` to now, discarding the fraction: a 64 kbps class
  refilled at the 200 µs drain cadence delivers 5,000 B/s against an
  8,000 B/s shape — 37.5% under; ~2% at 1 Mbps; negligible ≥100 Mbps
- **Severity:** Medium (kbps voice/control classes)
- **Confidence:** High (arithmetic verified: `token_bucket.rs:322-329`
  — `added = 1.6 → 1`, timestamp advanced, 0.6 B discarded per
  interval; same pattern in lease refill and the v8 rotation's
  `epoch_start_ns := now`)
- **Fix direction:** advance the timestamp by the time-value of granted
  bytes or carry a remainder; add a conservation unit test (N refills
  at non-integral cadence sum to rate×time ±1 — `refill_cos_tokens`
  currently has zero direct unit tests).
- **Labels:** bug, cos, dataplane
- **Dedup note:** #1630 cause-1 fixed the epoch/visit-cap layer of this
  shape at 100m/1g; the ns-integer-division dust layer is unreported.

### R-5. Lease give-back on queue-empty destroys or strands credit (two defects, one site)

- **Title:** (a) private-lease exact queues: `mem::take(tokens)` is
  unconditional but the give-back only happens when a shared lease
  exists — a momentarily-empty single-owner exact queue's banked burst
  is silently destroyed; (b) v8 shared leases: `release_unused` moves
  outstanding→available, but v8 acquire never consults `available` and
  rotation banks only `cap − granted` — released bytes are treated as
  claimed, re-creating #1630/#1863-style evaporation for bursty
  low-rate exact classes (~1-2.5 Mb/s at 10 empties/sec on a 100m class)
- **Severity:** Medium
- **Confidence:** Medium-High (call site `tx_completion.rs:713-742`
  verified by agent; `packed_granted` rollback absence grep-verified)
- **Fix direction:** (a) take only when a shared lease resolves;
  (b) roll released bytes back against `packed_granted` or feed them to
  the rotation bank. `release_unused` has no tests at all.
- **Labels:** bug, cos, dataplane
- **Dedup note:** #1630/#1863 fixed the rotation/claim legs; the
  release-on-empty leg is unreported and partially regresses their
  guarantee for bursty private-lease configurations.

### R-6. Shared residual-surplus budget is read-then-consume — up to (W−1)× burst over-admission per refill window

- **Severity:** Low-Medium. **Confidence:** High.
- `types/shared_cos_lease/backlog.rs:125-140`: budget read with
  `.min(burst)` clamp, consumption deferred to post-send saturating_sub
  — six workers can each admit the same 96 KB window (~6× entitlement),
  exactly the cross-worker pressure the residual bound protects
  backlogged exact guarantees from. Self-correcting next window
  (jitter, not sustained violation).
- **Fix direction:** CAS-claim at read (fetch_sub-with-floor), return
  unspent.
- **Labels:** bug, cos, dataplane, x-hpc
- **Dedup note:** same class as closed #2955/#4002 — third instance,
  different site; cites both.

### R-7. Cross-worker V_min gate compares absolute vtimes — a reset/rejoining worker at vtime≈0 permanently traps peers in the throttle duty-cycle

- **Severity:** Medium. **Confidence:** Medium (gate code verified;
  reset-path lifecycle inferred).
- `queue_ops/v_min.rs:215-239`: `queue_vtime` is cumulative
  served-bytes, never rebased. After an XDP rebind/config commit the
  rejoining worker publishes near-zero vtimes; the surviving worker
  (terabytes ahead) loops 8-throttles → hard-cap → 1000-suspended-drains
  forever — the fairness brake effectively off ~99% of the time, with
  only `v_min_hard_cap_overrides` climbing. The existing vacate handles
  stale-HIGH only.
- **Fix direction:** publish deltas since a floor epoch, seed rejoiners
  from the max peer slot, or version the floor on membership change.
  Add a runtime-reset-vs-surviving-peers test.
- **Labels:** bug, cos, fairness, dataplane
- **Dedup note:** #917 shipped V_min; #2624/#2646/#2981 fixed cadence/
  advance/floor bugs; the absolute-vs-relative rebasing defect is
  unreported.

### R-8. Grouped LOW dataplane findings (verified by the core sweep)

- **Severity:** Low each. **Confidence:** High unless noted.
- (a) `drain_shaped_tx` abandons the whole pass when exact selection
  fires but services nothing (`queue_service/mod.rs:184-196`) —
  work-conservation micro-violation, worst under TX-ring pressure.
- (b) `NOT_PARTICIPATING = u64::MAX` collides with the saturating
  vtime domain (unreachable ~46 yr at 100G; clamp at MAX-1).
- (c) `cos_queue_flow_share_limit` panics if `buffer_limit < 24_000`
  (`admission.rs:172-180`, clamp(min>max)); safe today only via the
  96 KB floor path — add the const pin + panic-free form (operator
  `buffer-size 16k` is legal config).
- (d) foreign-UMEM frame falls into the local free ring when
  `shared_recycles` is None (`tx/transmit/mod.rs:39-47`) — convention-
  enforced invariant; make the param non-optional.
- (e) zero-length items desync byte/item bookkeeping (latent).
- (f) empty-snapshot-stack `push_front` silently applies the aggregate
  vtime rewind (convention-enforced; add tripwire).
- (g) post-rotation tag-mismatched `worker_grant_bump` discarded while
  bytes granted — one-epoch misclassification of the 60% peer gate.
- (h) ECN IPv4 marker trusts ethertype, no version-nibble check
  (`ecn.rs:98-117`; contained by ECT gating).
- (i) over-horizon park replays the tick loop O(lag)
  (`tx_completion.rs:291-319`): `transmit-rate 8` (legal) parks ~30 M
  ticks out → ~50-150 ms poll-loop stall per idle→drain transition —
  a legal-config DoS of one worker; clamp wake to the wheel horizon.
- (j) budget-miss at a cadence position re-runs the full peer-slot
  Acquire scan every drain until refill (add a gate memo).
- **Labels:** bug/cleanup, cos, dataplane
- **Dedup note:** all unreported (i is the operational standout).

### R-9. Performance: unpadded `worker_active_flow_buckets` lease slots (false sharing on the per-flow-fairness hot path) + timer-wheel per-slot allocations

- **Severity:** Medium (perf). **Confidence:** High.
- `lease.rs:406-409`: 16 workers' `AtomicU32`s share one cache line,
  written per flow-bucket activation/teardown, read on every
  `acquire_v8`/`equal_flow_cap_v8` — found independently by three
  reviewers; contradicts the lease's own documented isolation rule
  (every other per-acquire array IS padded). Worst under short-flow
  churn — the regime where per-flow fairness matters most.
- Timer wheel (`tx_completion.rs:331-374`): `mem::take` destroys slot
  Vec capacity + two temporaries per processed slot — ~10⁵ allocator
  ops/s worst case on a drain thread the module elsewhere de-allocated.
- **Fix direction:** `PaddedAtomicU32`; persistent scratch vectors.
- **Labels:** performance, cos, dataplane, x-hpc
- **Dedup note:** unreported.

### R-10. Rust CoS core test-coverage gaps (consolidated)

- **Severity:** Medium (aggregate). **Confidence:** High.
- The cap-aware selector's positive action untested (R-1 invisible to
  CI); zero weak-memory/loom coverage (R-3, V_min, backlog, residual);
  `refill_cos_tokens`/`cos_refill_ns_until` zero direct tests (R-4);
  every `apply_cos_*_result` test passes an EMPTY retry deque (the
  pre−batch+retry math unexercised); v8 `release_unused` zero tests
  (R-5b); no N-worker aggregate admission test (R-2); plus
  runtime-reset-vs-peers, bucket-reuse EWMA inheritance, FlowRrRing
  wraparound, `flow_fair && shared_exact` ECN branch, timer-wheel
  multi-cascade, end-to-end demotion.
- Also two owner cross-checks worth a look: CoS submit paths may not
  bump `binding.live.tx_packets/tx_bytes` (shaped non-exact traffic
  invisible in binding TX counters?); no `dehydrate` counterpart to
  `rehydrate_worker_active_count` (a dropped runtime with
  `active_flow_buckets > 0` would permanently inflate that worker's
  fair share).
- **Labels:** test-gap, cos, dataplane
- **Dedup note:** unreported.

### R-NEG. Rust CoS core negative results (verified clean)

MQFQ vtime arithmetic (saturating, wrap-free, re-anchor + idle-reset
correct); snapshot/rollback round-trip exact with fail-on-revert pins;
fused peek+pop safe at both call sites; #2646 cadence contract holds at
every no-pop exit; seqlock READER (#1643) correct; epoch rotation
single-winner CAS + carry regimes exactly as documented (constants
match fairness-regimes.md); legacy lease conservation lost-update-free;
RFC 1624 incremental checksum + RFC 3168 ECN semantics correct
(hand-verified); flow-hash seeding decorrelates cross-queue collisions
(simulated: full distinctness at 12/48 flows); DRR cursors persist —
no scan-from-zero favoritism ANYWHERE; timer-wheel index math exact;
retry-restore accounting double-count-free (cross-slice invariant
checked twice); cross-binding redirects leak-free; all lease/epoch
structs genuinely 64-aligned except R-9's one exception.

### T-1. v8 lease give-back never re-credits the epoch ledger — released bytes are double-charged; the best-fitting mechanism yet for the "unfixable" #1630 cause-2 ~6% mid-rate residual

- **Title:** `shared_cos_lease_release_unused` moves outstanding→available
  but never decrements `packed_granted`; the drain releases the entire
  banked residual whenever an exact queue goes empty
  (`tx_completion.rs:711-715`), so a mid-rate class oscillating
  empty↔backlogged at epoch timescale is charged for bytes it returned —
  hitting `ClassCap` early and parking until rotation
- **Severity:** High
- **Confidence:** High that the accounting hole exists (found
  INDEPENDENTLY by both Rust review passes — `lease.rs:245-270` grep:
  no release path touches `packed_granted`; rotation banks only
  `cap − granted`); Medium-High that it is #1630 cause-2
- **Trace (concrete):** 1 G exact class → epoch cap 25,000 B; queue
  drains 23,500 and empties mid-epoch; 1,500 B released; granted stays
  25,000 = cap → next arrivals break ClassCap → park till rotation →
  ~94% effective service. The cause-2 fingerprint matches: mid-rate
  only (100m banks whole frames across epochs, 10g never empties), and
  IMPROVES with parallelism (-P12 keeps the queue backlogged → fewer
  empty transitions), which is exactly the discriminator #1630 used to
  declare it "transport physics".
- **Why it matters:** fairness-regimes.md documents cause-2 as a floor
  "no scheduler change recovers" — this finding says it may be a
  recoverable ledger bug. Cheap empirical test available today: sum
  `release_unused` bytes against the class undershoot.
- **Fix direction:** tag-checked `release_unused_v8(worker_id, tag,
  bytes)` that CAS-decrements `packed_granted`/`worker_grants` on tag
  match (mirror of the existing `tag_checked_rollback`); validate
  against the 100E100M gate + a mid-rate on/off iperf pattern. The v8
  `consume`/`release_unused` pair has ZERO tests.
- **Labels:** bug, cos, fairness, dataplane
- **Dedup note:** #1630 cause-2 is documented-not-fixed as physics —
  this is a specific falsifiable mechanism, not a re-report; the
  private-lease half is R-5(a). Unreported anywhere.

### T-2. Waterfill Phase-1 honor is consumed at SELECTION, not service — a zero-byte TX failure burns the class's entire 200 µs epoch

- **Title:** `waterfill_pass1_remaining_bytes` is debited and the
  honored bit set before the service call; TX-ring-full / no-free-frame
  / V_min-first-pop failures return `Some(None)` with no refund — the
  honored small class is then skipped by BOTH phases for the rest of
  the epoch while big Phase-2 classes stay re-selectable
- **Severity:** High
- **Confidence:** High on mechanism (`queue_service/mod.rs:1070-1095`
  debit; `:436-463` wrapper; zero-insert sites verified); Medium on
  production magnitude (needs ring-full incidence data)
- **Trace:** at 5% ring-full incidence a 100 Mb/s Phase-1 class loses
  ~5% of its guarantee — inverting the #1732/#1743 small-class-first
  intent precisely under load, and compounding T-1 on the same classes.
- **Fix direction:** commit honor/debit only on service progress (or
  refund + clear bit on `progress == false`); add
  `selected_no_progress` counter (today `phase1_admissions` counts
  selections, not service — a stats lie). No
  waterfill-under-failed-service test exists.
- **Labels:** bug, cos, fairness, dataplane
- **Dedup note:** #1732/#1743 fixed honored-bitset and budget-anchor
  bugs in the same allocator; the selection-vs-service commit point is
  unreported. Plausible co-mechanism (with T-1) for the #1863-era
  honored-realization residue and #1359's surplus-leg latency behavior.

### T-3. ANY egress output filter — even counter/log-only — silently cancels input-filter forwarding-class classification

- **Title:** the ingress tx-selection evaluation is gated on
  `!has_output_filter`, and `has_output_filter` is true for
  counter/log/terminal-action-only egress filters — adding an
  audit-only `then count` filter on the WAN moves EF traffic to the
  default best-effort queue
- **Severity:** High
- **Confidence:** High (re-verified: `tx/cos_classify.rs:426-455`
  `(!has_output_filter && has_input_tx_selection)`; the needs-tx-eval
  predicate includes counter/log terms; cached twin same shape)
- **Why it matters:** a routine observability change silently
  reclassifies whole traffic classes; Junos semantics are
  output-overrides-when-set, not presence-clears-ingress. Commit
  `a15a6120` fixed only the zero-effect-output-filter subcase.
- **Fix direction:** suppress only when
  `output_result.forwarding_class.is_some()` (fold output.or(ingress));
  mirror in the cached resolver; add the missing middle-case test.
- **Labels:** bug, cos, filter, dataplane
- **Dedup note:** unreported; adjacent to (not covered by) #4085's
  counter-dedup and codex-162's cache-consistency findings.

### T-4. BA classifier code-point → unmaterialized queue = 100% silent blackhole; the config commits cleanly

- **Title:** the per-interface DSCP table is built from the GLOBAL
  classifier without filtering against materialized queues; admission
  is any-match; the enqueue path has no default fallback for an
  explicit miss — every packet of that code-point takes
  Err → one rescue → drop, with no CoS-specific counter
- **Severity:** High
- **Confidence:** Medium-High (build/gate/resolve all verified:
  `forwarding_build/cos.rs:36-58,413-421`,
  `cos_classify.rs:836-853` position()→None; drop path read by agent)
- **Trace:** scheduler-map materializes queue 0 only; classifier maps
  ef(46)→5 → commit passes (any-match on 0) → all DSCP-46 traffic
  dropped forever while be flows normally.
- **Fix direction:** filter classifier entries per-interface at build
  (fallback to default queue) OR fail the snapshot closed
  (#2409/#2410 posture); range-check queue ids in the Go commit gate;
  remove the dead-looking `queue_idx >= len → 0` branch that suggests a
  fallback that isn't real. Related sentinel bug: queue id 255 collides
  with the `u8::MAX` no-entry sentinel (commits, silently defaults).
- **Labels:** bug, cos, config, dataplane
- **Dedup note:** #2704/#2706 fixed undefined-FC no-ops at a different
  layer; the classifier→unmaterialized-queue blackhole and the 255
  sentinel are unreported.

### T-5. Unshaped flow-fair queues: the #717 delay-cap computes 0 at rate 0, collapsing the flow-aware buffer expansion — resurrecting the #704/#707 new-flow-first-packet drop

- **Title:** `delay_cap = rate × 5 ms` is 0 for `transmit_rate == 0`
  queues, so `.min(delay_cap.max(base))` pins the aggregate limit at
  `base` regardless of flow count — a mouse's first packet is dropped
  while resident elephant bytes stay (drop-newest at the aggregate cap)
- **Severity:** High
- **Confidence:** High (arithmetic re-verified at
  `cos/admission.rs:218-234`; post-#1735 every CoS queue is
  flow-fair-eligible, and elsewhere rate-0 means "unshaped" — this
  site treats it as "zero drain rate")
- **Fix direction:** early-return `base.max(prospective × MIN_SHARE)`
  at rate 0 (or use the root shaping rate for the delay cap); add the
  rate-0 twin of the existing boundary test.
- **Labels:** bug, cos, fairness, dataplane
- **Dedup note:** #704/#707/#717 fixed this boundary for shaped
  queues; the rate-0 regime is unreported and untested.

### T-6. TX-path MEDIUM cluster (verified by the TX sweep; overlaps with R-* noted)

- **Severity:** Medium each. **Confidence:** per item.
- (a) **V_min hard-cap suspension self-disables fairness under
  persistent skew** (`HARD_CAP=8`, `SUSPENSION=1000` → brake active
  ~0.8% of the time), and suspended batches are UNCOUNTED — telemetry
  reads "brake idle" while it is off 99.2%. With R-7/M1 (absolute-vtime
  rejoin poisoning, found by both agents) this is the V_min pair to fix
  together. Add `v_min_suspended_batches`; decaying re-arm policy.
- (b) **Exact-demand surplus reservation is not work-conserving**: a
  v8-starved exact class that ships zero bytes still zeroes the
  best-effort residual (`mod.rs:279-343`), starving BE while the link
  idles — plus busy-poll (budget-0 queues never park; no wake source
  for the residual bucket). Gate the reservation on the published
  serviceability signal. Directly relevant to the #1368/#1371
  BE-vs-exact contention contract.
- (c) **shared_exact ECN aggregate arm marks innocent ECT mice for a
  non-ECT UDP elephant's queue depth** (`admission.rs:349-353`) — the
  #784 positive-feedback shape; the "double-signal" rationale covers
  ECT-vs-ECT only. Move shared_exact to the rate-aware per-flow arm
  (#914 removed the original blocker) or include own-bucket
  contribution in the mark decision. No mixed-ECT test exists.
- (d) **`transmit_batch` Drop-unwind reverses staged requests**
  (`drain(..)`+push_front vs the correct pop() idiom two sites over) —
  intra-flow TCP reordering on the error path.
- (e) **Missing `publish_committed_queue_vtime` on the CoSBatch settle
  path** (4 of 5 boundaries publish) — surplus-phase service by
  shared_exact surplus-sharing queues advances vtime unpublished →
  peers spuriously self-throttle exactly when surplus works hardest.
- (f) **Mirror-clone mid-batch drops desync the per-bucket sidecar**
  — TX bytes/sojourn charged to wrong flows, and `observed_bps` feeds
  the MQFQ selector, so fairness DECISIONS are distorted (known-live
  per in-code comment; no red test).
- (g) **Admission drops bump `tx_errors` + per-drop `format!` String**
  — designed shaping behavior reported as errors, ~1M allocs/sec under
  a drop storm (hot-path allocation rule violation). Dedicated
  admission counters already exist; stop double-reporting.
- (h) **`enqueue_tx_owned` swallows redirect-inbox overflow** — the
  documented Step-2/Step-3 fallbacks are dead code on the Arc path;
  drop-newest with no fairness under inbox saturation.
- (i) **`max_total_leased` floors at ONE bank while every shard banks**
  (`lease.rs:148-151`): 96 KiB burst / 6 workers → ~5/6 of top-ups hit
  OutstandingCap — a measurable cause-2 CO-factor (the #1782 counters
  can confirm today). Plus: worker teardown holding credit permanently
  leaks `outstanding` on reused leases (no reconcile path).
- (j) **Equal-flow publisher divides a whole-window grant by the
  sticky-MAX flow count** — mouse churn drags the Slowest target ~N×
  below ideal; Slowest/Mean never got the #1746 window normalization.
- (k) **Stale shared state survives coordinator Arc reuse** (phantom
  backlog slots, stale vtime slots, additive-only
  `rehydrate_worker_active_count`) — same symptom family as R-7;
  needs a coordinator-side scrub on binding unregister.
- (l) **`local_item_count` leaks on exact-FIFO settle paths would
  permanently demote the Prepared zero-copy path** — dead today ONLY
  via a silently-truncating `zip` in the flow-fair promotion
  (`admission.rs:403`) that would arm it with no diagnostic; those
  paths also record no sojourn samples (the #1829 gate metric would
  read 0 against a standing FIFO backlog).
- (m) **Fragments/flowless packets bypass BA classification entirely**
  (`flow_key = None` → default queue despite DSCP present) — EF
  fragments straddle queues; the #2357/#3290 suppression rationale
  covers port-matching filters, not BA lookups.
- **Labels:** bug, cos, fairness, dataplane
- **Dedup note:** all unreported; (c) deliberately-aggregate design is
  documented in cos-wan-sqm.md but the non-ECT interaction is not;
  (l)'s FIFO-accounting leak was fable-161 F-235 (suppressed) — the
  NEW parts are the truncating-zip reachability and the sojourn hole.

### T-7. TX-path LOW cluster + stats-that-lie family (grouped)

- **Severity:** Low each. **Confidence:** High unless noted.
- Rotation floors fractional bytes (≤1 B/epoch → 2-4% undershoot for
  sub-Mb/s exact classes — pairs with R-4); Step-A/C rotation straddle
  (≤1 request/rotation); lease rebuild churn (every worker-count change
  rebuilds every lease; birth epoch grants a free full cap; old+new
  grant concurrently during lazy detach); rotation-under-seqlock on a
  worker thread (preempted winner blanks the class; SeqlockGiveUp
  uncounted); bypass detector misclassification (5-epoch FCFS surplus
  inversion, bounded); V_min throttle mislabeled "no free TX frame";
  wake-tick estimator uses full class rate for shared queues (spurious
  wake/park); busy-poll park gaps (surplus-0 and Phase-2 selections
  never park); waterfill honored-bit tracking silently off for
  ordinals ≥ 64 (nothing rejects >64 exact classes at commit);
  snapshot-push-before-fallible-pop converts a recoverable desync into
  a release-mode worker panic; u64::MAX head-finish sentinel makes a
  bucket permanently unselectable (overloaded with NOT_PARTICIPATING —
  pairs with R-8(b)); drain_all→restore_front not finish-time-neutral;
  keyless traffic shares SFQ bucket 0 unsalted with a real victim flow
  (reserve a dedicated bucket); drop-newest at the aggregate cap is an
  arrival lottery biased against mice (consider drop-from-longest-
  bucket); runtime `pcp.min(7)` clamp contradicts the #2447 fail-closed
  posture; surplus-weight 16-quanta quantization (≤16× proportionality
  error at the bottom — widen to 1024); defensive None arms drop retry
  batches (frame leak, uncounted); dead deferred-CoS dispatch path
  carries two latent bugs (delete it); **stats-that-lie family**:
  partial TX-ring inserts invisible, `timer_level*_sleepers` unbounded
  inflation, `buffer_bytes` summed N× across workers,
  `worker_instances` counts bindings, ShareExhausted conflates policy
  with capacity, `active_flow_buckets_peak` is lifetime-not-live,
  cross-binding frames missing from submit-latency histogram,
  copy-TX counters misattributed, classifier-name-unresolvable yields
  silent all-MISS + wasted per-hit reclassify work, duplicate-entry
  semantics diverge between rewrite (first-wins) and classifier
  (last-wins) tables, unknown priority string silently ranks lowest
  (vs #2458 fail-closed next door).
- **Labels:** bug/cleanup, cos, dataplane, observability
- **Dedup note:** all unreported.

### T-NEG. TX-path negative results (verified clean)

Token/credit conservation (no double-debit; drops never consume
budget; cause-1 regime math conserves); seqlock READER + tag-CAS
discipline; MQFQ snapshot-rollback round-trip neutrality (excellent
differential coverage); ECN/DSCP wire mechanics (RFC 3168 + RFC 1624
correct in both paths, VLAN-aware, marked-then-dropped impossible);
frame conservation on every dispatch exit (#4041 contract holds);
committed-prefix settle reconciliation; three-RR-cursor independence
(no low-index bias); status SUM/MAX/MIN merge choices; #4085, #3642,
#3778 core logic, #1598 routing gate, #926/#940 demote round-trip,
#1946 fabric fail-closed — all intact.

---

## 7. Findings — MEDIUM CONFIDENCE

### V-10. Independent Python CoV math in the smoke reducers diverges from the Rust SSOT

- **Severity:** Low-Medium. **Confidence:** High on the divergence,
  Medium on impact (decorative today per the #1614 rescope).
- `cos-simul-load-smoke.sh:137` uses SAMPLE stddev over whole-run means
  (warmup included) and silently drops zero-bps streams — a fully starved
  class prints CoV 0 (the "good" value); `fairness.rs` uses population
  stddev over steady-window means. Printed CoV% won't reproduce
  fairness-eval on identical traffic, inviting misdiagnosis.
- **Fix direction:** reuse fairness-eval or match its estimator; never
  filter zero streams; label the column "whole-run CoV".
- **Labels:** cleanup, test-infra, fairness
- **Dedup note:** unreported.

### V-11. Single-class harness silently defaults SHAPER_RATE_BPS=25G for unknown ports

- **Severity:** Low (Medium once V-3 gives Gate 3 teeth).
  **Confidence:** High (`fairness-harness.sh:225-231`; mixed mode
  correctly refuses to guess — unexplained asymmetry).
- **Fix direction:** warn loudly or require explicit rate in single mode.
- **Labels:** cleanup, test-infra
- **Dedup note:** unreported.

### V-12. Minor harness notes (grouped)

- **Severity:** Low. **Confidence:** High.
- Scrape cadence can stretch toward 2 s under a slow endpoint (sleep-1 +
  max-time-1 serial); `iperf3_sum_parse.py` would match final-summary and
  `(omitted)` rows if a future consumer misused it (current consumers
  safe; `_last_n_sum_bps` is dead code — delete);
  `fairness_equal_flow_capture.py` hard-fails a whole class on one
  transient curl hiccup (maximally fail-closed; burns sweep runs).
- **Labels:** cleanup, test-infra
- **Dedup note:** unreported.

---

## 9. NEW IDEAS — getting CoS + flow fairness working well

Every idea below is checked against the kill-list (§3) and cites the
relevant kill/decision where it comes close. Ordering is by
leverage-per-effort.

### Idea 1 — Falsify "cause-2 is physics" before building anything new (1-2 days)

Three independent, convergent accounting leaks found this campaign all
undershoot exactly the mid/low-rate exact classes: the v8 give-back
double-charge (T-1), the waterfill honor burned on zero-byte service
(T-2), and the refill/rotation fractional dust (R-4, T-7). #1630
cause-2 (~6% mid-rate residual) is documented as an unfixable
transport-physics floor — but T-1's fingerprint matches it point for
point, including the improves-with-parallelism discriminator that was
used to declare it physics. **Experiment:** add two counters (bytes
released via `release_unused` per class; honors consumed with zero
progress), run the existing `cos-gate1-small-four-alone.sh` SOLO matrix
and a mid-rate on/off iperf pattern, and compare released/burned bytes
against the undershoot. If they match, fix the ledger (tag-checked v8
re-credit + honor-on-progress) and re-measure — the documented floors
in fairness-regimes.md §cause-2 get rewritten, and every rate-metering
epsilon downstream tightens for free. This is instrument-first, the
same method that resolved the #1863 realization gap.

### Idea 2 — Replace the v8 epoch-deal with a shared EDT clock per class (the Google/Cilium pattern)

The v8 machinery (200 µs epochs, per-worker deals, claim windows,
lag-carry, cold-resume, banks) exists to answer one question — "may
this worker send N more bytes of class C now?" — and this campaign
found four+ bug classes in its seams (T-1, T-2, R-5, the T-7 rotation
items; historically #1630 cause-1 and #1863's whole gap). The
production-proven alternative (Google netdev 0x14 "Replacing HTB with
EDT+BPF"; Cilium Bandwidth Manager; Justitia as the kernel-bypass
analog) is ONE atomic per shaped class: `next_tstamp`, advanced by
`fetch_add(len × NS_PER_SEC / rate)` from any worker; a packet whose
computed departure exceeds `now + horizon` is queued-back/dropped
(admission control built in); per-worker enforcement is local — the
timing wheel already exists in `tx_completion.rs`. No epochs → no
rotation credit loss, no claim-miss evaporation, no give-back ledger,
no deal skew: those failure classes vanish BY CONSTRUCTION rather than
via more carry logic; burst bound = horizon parameter. Kill-list
check: NOT #1238 (per-flow buckets — this is per-CLASS, coarser than
today's per-worker deals); NOT #1215/#937 (no packet movement; one
cacheline per class, the same sharing granularity as the existing v8
lease Arc). Ship behind `oversubscription-policy edt` for exact
classes; A/B on the 100E100M + gate1 + simul harnesses. The
worker-share question it eliminates is named in the literature:
Distributed Rate Limiting / Flow Proportional Share (SIGCOMM'07).
Effort ~2-4 weeks, risk contained by the flag.

### Idea 3 — Demand-weighted (not flow-count-weighted) worker shares for whatever remains dealt

Where per-worker dealing survives (equal-flow mode keeps evaporation
semantics deliberately), #1863 deals the class budget
flow-count-proportionally. DRL/FPS's 19-year-old lesson: raw flow
counts are the wrong weight — an app-limited flow inflates its
worker's share without being able to use it. Weight by unbottlenecked
demand instead (per-worker per-class EWMA of claimed +
would-have-claimed bytes, water-filled — both already observable at
the drain), and smooth reallocation at TCP timescale (~100 ms EWMA;
the Confucius lesson: abrupt re-division causes cwnd overshoot and CoV
oscillation). Kill-list check: cross-worker rates at control-plane
cadence are exactly what the lease already shares; this changes the
deal formula, not the architecture.

### Idea 4 — Cebinae-style heavy-flow taxation as the evolution of `equal-flow-enforcement`

For the unshaped/BE regime where per-worker CPU is the resource and
the RSS multinomial floor rules (all placement fixes are killed
territory), #1746's own analysis concluded the realistic win is "clip
lucky outliers" — shipped as a hard, non-work-conserving clip
(strict-SLA mode). Cebinae (SIGCOMM'22) is the principled, convergent
version of exactly that: periodically compute the max-min fair share
from aggregate counters (control-plane cadence), then tax ONLY flows
above it with a worker-local leaky bucket admitting at
slightly-below-measured-rate — repeated nudging converges to max-min
fairness, is CC-agnostic (CUBIC/BBR/unresponsive all taxed), needs
per-heavy-flow state only (the #3315 count-min sketch and per-bucket
`observed_bps` already exist), and never re-steers anything. Ship as
`equal-flow-target-policy cebinae` — work-conserving enough for
general use, unlike the current clip. No software port exists; xpf
would be first. Kill-list check: #831/#834/#838/#1211 explored
AFD/CSFQ drop OVERLAYS and were not adopted (MQFQ won the scheduling
question); Cebinae is admission-side taxation of heavy flows only,
with a convergence proof and bounded degradation. Measurement plane:
OctoSketch-style change-based delta aggregation (NSDI'24) turns the
per-worker sketches into a continuously-fresh global fair-share view
over the existing control channel.

### Idea 5 — Fix the fairness machinery already built (findings-first; plausibly dominates the CoV-to-Cstruct gap)

Four found defects each degrade per-flow fairness inside the shipped
MQFQ/AQM path, and each is a small fix: R-1 (stale per-bucket EWMA
punishes newcomers — three stores on a cold transition), T-5 (rate-0
delay-cap collapse drops mouse first-packets — one early-return),
T-6(c) (aggregate ECN arm lets non-ECT elephants CE-mark innocent mice
on shared_exact — the per-flow arm is unblocked since #914), and the
V_min pair R-7 + T-6(a) (absolute-vtime rejoin poisoning + an
uncounted brake that is off 99.2% of the time under sustained skew).
Prediction worth testing: these plus Idea 1's ledger fixes close most
of the observed CoV-minus-Cstruct gap and the #1765-era variance —
cheaper than any new scheduler.

### Idea 6 — Close the production fairness-observability loop (contract open question 3)

The gauges exist; nothing computes the verdict outside the harness.
Add (a) `show class-of-service fairness` — live per-queue CoV, `{aᵢ}`,
Cstruct, gap, computed by the same Rust code fairness-eval uses;
(b) a sustained-gap alarm (observed CoV > Cstruct + ε for N windows →
system alarm); (c) fix the stats-that-lie family (T-7) so the loop is
trustworthy — most urgently `v_min_suspended_batches`,
admission-drops-as-tx_errors, and the equal-flow sticky-max
denominator (T-6(j)). Converts every future fairness regression from a
lab rerun into a dashboard read, and enables tuning ε/T online.

### Idea 7 — #1359 (surplus-sharing mouse-latency FAIL): an instrument-first hypothesis set

The one open functional CoS defect. Three campaign findings form a
coherent mechanism: T-6(b) (a zero-progress exact class zeroes the
surplus residual — bursty on/off residual), T-2 (honor burn under ring
pressure — epoch-scale service gaps), and the L9 park gaps (busy-poll
jitter). All three inject epoch-timescale burstiness into exactly the
surplus leg whose p99.9 fails while strict-exact passes. Proposal:
extend the #1782 instruments with per-phase grant/park/burst
histograms on the surplus path; if confirmed, pace surplus grants
sub-epoch — which Idea 2's EDT clock provides for free (surplus =
spare clock time, naturally paced). Kill-list check: #1829 Phase 2
killed the DEQUEUE CoDel control law; grant-issuance pacing is
upstream of it and untouched by that verdict.

### Idea 8 — Cross-egress aggregate download shaper (promote the WAN-SQM caveat to a feature)

docs/cos-wan-sqm.md documents the gap: per-egress shaping lets
concurrent downloads to multiple LAN segments oversubscribe the real
WAN downstream ("an aggregate-root shaper across egresses would be a
future engine feature — not claimed here"). The shared-lease/EDT
machinery already coordinates cross-worker; a named `shaping-group`
(members = egress units, one shared clock/bucket) is the same sharing
pattern one level up, with Junos parity precedent (interface-set /
shared schedulers). One config stanza + one Arc level; no new
per-packet cost class.

### Idea 9 — L4S/DualQ-ready low-latency class (small, demand-gated)

RFC 9331/9332 are mainline (`sch_dualpi2`, Linux 6.17) and deployed
(Comcast LLD). xpf already CE-marks at admission; adding ECT(1)
recognition + the RFC 9332 square-coupling between L4S mark
probability and classic drop/mark probability yields a standards-track
low-latency class composing with existing forwarding-classes. Propose
in the #1849 demand-gated style (don't build without a driver); the
literature verdict is clear that marking-only is NOT a fairness
mechanism (keep drops as backstop) — scope as a latency class, not a
fairness fix.

### Idea 10 — Give the contract teeth first

V-1/V-2 (exit codes), V-3 (Gate-3 baseline artifact — doubling as the
missing Regression-bounds tooling, V-14.1), a UDP leg in the sweep,
and the `{aᵢ}`-pipeline fixes (V-4..V-7). Every idea above is measured
through this harness, and today it cannot fail on the two things that
matter most. Sequence this first or in parallel with Idea 1.

---

## 10. Suggested issue split

1. **[bug][cos][fairness]** v8 give-back double-charge + honor-burn +
   refill dust: instrument, fix, re-measure the #1630 "cause-2" floor —
   T-1, T-2, R-4, R-5 (Idea 1).
2. **[bug][test-infra]** CoS gate harnesses cannot fail: exit wiring +
   Gate-3 circularity + baseline artifact — V-1, V-2, V-3, V-14.1
   (Idea 10).
3. **[bug][cos][filter]** output-filter presence cancels ingress FC
   classification — T-3.
4. **[bug][cos][config]** classifier→unmaterialized-queue blackhole +
   queue-255 sentinel + Go range gate — T-4.
5. **[bug][cos][fairness]** rate-0 flow-fair delay-cap collapse — T-5.
6. **[bug][cos][fairness]** stale flow-bucket EWMA punishes new flows —
   R-1.
7. **[bug][cos][fairness]** non-exact guaranteed classes unmetered
   across workers — R-2.
8. **[bug][cos][fairness]** V_min: rejoin poisoning + uncounted
   suspension + coordinator-reuse scrub — R-7, T-6(a), T-6(k).
9. **[bug][cos]** BE/surplus starvation by zero-progress exact classes
   + park gaps — T-6(b), L9; feeds #1359 (Idea 7).
10. **[bug][cos][docs]** priority-low-min-share inert while the
    contract asserts it; codel-target guard-rails — G-1, G-3.
11. **[bug][cos][config]** fail-loud batch: dangling scheduler refs,
    nonexistent IFL bindings, untyped shaping-rate/burst-size,
    missing oversubscription-policy schema — G-2, G-4, G-5, G-6.
12. **[bug][cos]** ECN: shared_exact aggregate arm vs non-ECT
    elephants; version-nibble check — T-6(c), R-8(h).
13. **[bug][cos][x-hpc]** seqlock writer fence + residual-budget CAS
    claim + loom coverage — R-3, R-6.
14. **[bug][cos]** fragments/flowless bypass BA classification —
    T-6(m).
15. **[bug][cos][observability]** stats-that-lie batch +
    admission-drop tx_errors/alloc storm + false-sharing pair —
    T-6(g), T-7 stats family, R-9.
16. **[test-gap][cos]** Rust corridors (cap-aware selector, retry
    deques, release_unused, N-worker admission, reincarnation,
    mixed-ECT, loom) + `{aᵢ}` pipeline (V-4..V-7) + UDP leg — R-10,
    V-14.
17. **[enhancement][cos][fairness]** EDT shared-clock shaping behind a
    policy flag — Idea 2 (+ Idea 3 deal refinement).
18. **[enhancement][cos][fairness]** `equal-flow-target-policy
    cebinae` + OctoSketch delta aggregation — Idea 4.
19. **[enhancement][cos][observability]** `show class-of-service
    fairness` + sustained-gap alarm — Idea 6.
20. **[enhancement][cos]** cross-egress shaping-group — Idea 8.
21. **[vsrx-parity][cos]** parity batch: WRED/drop-profiles,
    transmit-rate percent, ieee-802.1 rewrite, `show interfaces
    queue`, strict-high semantics, default classifiers — G-8.
22. **[enhancement][cos]** L4S/DualQ demand-gated issue — Idea 9.
23. **[cleanup][cos]** surplus give-back live runner + validator
    tightening (V-8); equal-flow sticky-max denominator (T-6(j)).

## 11. Campaign summary

- **~58 findings** (10 High-severity: T-1..T-5, R-1, R-2, V-1..V-3,
  G-1), each with a dedup note against ~120 mapped issues, the 4 prior
  CoS-bearing campaign reports, and the 17-item kill-list — plus 10
  ranked ideas with explicit kill-list compliance notes.
- **The headline reframe:** several documented "floors" look like
  ledger bugs. The v8 give-back double-charge (found independently by
  both Rust review passes) matches the #1630 cause-2 fingerprint
  exactly — including the improves-with-parallelism discriminator used
  to declare it physics. A 1-2 day instrumented experiment settles it.
- **The machinery is architecturally sound but leaks at the seams:**
  MQFQ core, rollback, ECN wire mechanics, byte conservation, RR
  cursors, and the Cstruct math all survived adversarial line-level
  reading (extensive negative results recorded). The defects cluster
  in state lifecycle (stale EWMAs, rejoin vtimes, Arc-reuse ghosts),
  regime boundaries (rate-0, mid-rate queue-empties, non-exact
  guarantees), and the validation layer (harnesses that cannot fail, a
  circular Gate 3, a contract gate asserting an inert knob).
- **Ideas thread the kill-list:** EDT shared clocks (production
  practice at Google/Cilium) and Cebinae taxation (SIGCOMM'22) are the
  two genuinely new, architecture-legal directions; everything else is
  fix-first — and the fix-first list plausibly closes most of the
  CoV-to-Cstruct gap on its own.


