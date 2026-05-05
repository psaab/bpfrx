---
status: DRAFT v1 — pending adversarial plan review
issues: #786, #793, #794, #837, #917, #936, #937
phase: Triage — close-or-keep decision per issue
---

## 1. Why one triage doc for 7 Tier B issues

These 7 issues form the "cross-worker fairness on shared_exact CoS"
backlog tail after the #785 / #913 / #917 stream landed substantial
shipping work. The user-set workflow (`feedback_difficult_path_pragmatism`)
is to triple-review umbrella issues for closure when the achievable
scope has shipped or has been demonstrated structurally blocked.

This triage assesses each issue against current master (`dab78ef6`)
and against shipped PRs (#796 Phase 3, #939 Phase 4 V_min, #950 V_min
publish correctness, #952/#1139 V_min telemetry, #1191 P=128 ceiling
NEEDS-NO-FIX, #1194 surplus-sharing flag). The recommendation per
issue is **close**, **keep**, or **reframe**.

## 2. Shipped landscape (master HEAD `dab78ef6`)

| Scope | Status | Tracking PR |
|---|---|---|
| #785 Phase 3 — MQFQ virtual-finish-time ordering | SHIPPED | PR #796 |
| #913 — MQFQ vtime semantics fix | SHIPPED | PR #928 |
| #914 — rate-aware per-flow cap on shared_exact | SHIPPED | PR #931 |
| #918 — 4-way set-associative flow cache w/ LRU | SHIPPED | PR #933 |
| #917 Phase 4 — cross-worker V_min synchronization | SHIPPED | PR #939 + #950/#952/#1139 trio closeout |
| #940/#941/#942/#943 — V_min hardening (publish correctness, vacate, hard-cap, telemetry) | SHIPPED | PR #950/#952/#953/#1139/#1143 |
| #915 — opt-in surplus-sharing flag for exact CoS | SHIPPED | PR #1194 |
| #944 — P=128 ceiling | NEEDS-NO-FIX | PR #1191 (diagnostic) |

Telemetry counters confirm V_min is live in code:
`v_min_throttles`, `v_min_throttle_hard_cap_overrides`,
`queue_vtime_floors` (`coordinator/cos_state.rs:8-13`).

## 3. Per-issue assessment

### #786 — Research: cross-worker per-flow fair queueing at 100G+ scale

**Scope:** umbrella tracking issue + survey research doc
(`docs/cross-worker-flow-fairness-research.md`).

**Reality:**
- Research doc is in-tree as committed source.
- Actionable scope has been split into #793/#917 (V_min, both shipped),
  #794 (AFD, deferred), #936 (per-flow shared finish-time), #937
  (cross-binding redirect), #911 (HOL on shared_exact).
- The umbrella has no remaining unscoped work — it has done its job.

**Recommendation:** **Close** as research-tracker-complete. Point
follow-on work at the scoped issues.

### #793 — #785 Phase 4 — Full MQFQ with shared V_min + lag throttle

**Scope:** "Phase 4: shared `V_min` anchor + lag-threshold throttle …
this is the architecturally correct answer per cross-worker-flow-
fairness-research.md".

**Reality:**
- **Shipped under issue #917** as PR #939 + closeout PRs
  #950/#952/#953/#1139. The `V_min` `AtomicU64` exists on
  `SharedCoSQueueLease`; CAS update on dequeue exists; lag-threshold
  throttle exists with hard-cap escape.
- #793 and #917 describe the same Phase 4 work; #917 carried it.

**Recommendation:** **Close** as duplicate of #917 (which is itself
a close-as-shipped candidate).

### #794 — #785 Phase 5 — AFD policer for misbehaving flows (optional)

**Scope:** "AFD … kick off only if Phase 4 hits the fairness target
BUT pathological flows starve well-behaved flows".

**Reality:**
- Phase 4 (#917) has shipped. No evidence of pathological-flow
  starvation in cluster smoke matrices that triggered AFD as a
  needed mitigation.
- Issue body explicitly marks itself "optional".
- The AFD design (Count-Min sketch ECN marking) remains the right
  architecture if/when a pathological-flow starvation case is
  measured. But there's no current trigger.

**Recommendation:** **Close as deferred** with explicit reopen
trigger: "if cluster smoke or production shows a flow exceeding 2×
its fair share starving well-behaved flows under shared_exact at
multi-Gbps shapers, file a fresh issue or reopen with the
measurement."

### #837 — Slice C-a: full HOL-finish cross-binding MQFQ with shared vtime + per-bucket state machine

**Scope:** Full HOL-finish cross-binding MQFQ. Successor to #836
(plan-killed) and to #830 Slice B (reverted via PR #842 due to
outage-class regression #841).

**Reality:**
- #836 returned PLAN-READY NO with 7 HIGH + 4 MED architectural
  issues from Codex.
- #841 (Slice B) caused 100% CPU pegging on all 6 workers + 0 Gbps
  forwarding — outage-class regression. Reverted via PR #842.
- #843 (Slice B post-mortem) documents three failure modes that
  shipped without detection: gate-fire `continue` without
  `park_cos_queue`; `wake_tick` scale confusion; cross-binding
  fence racing.
- The achievable scope on this seam has repeatedly proven elusive
  — every plan attempt has either plan-killed or shipped with
  regressions.

**Recommendation:** **Close as wontfix-with-rationale** (like #946
closure today). Reopen trigger: a concrete burst-snapshot or
delta-log seam plan + cluster smoke proving correctness, **plus**
#843's post-mortem prereqs landed (which should be a separate
issue if anyone takes them up).

### #917 — MQFQ Phase 4 missing — cross-worker virtual time synchronization (V_min)

**Scope:** Implement `V_min: AtomicU64` on `SharedCoSQueueLease`,
CAS-update on dequeue, lag-throttle when `vtime > V_min + T`.

**Reality:**
- **All four bullet points in the issue body are SHIPPED:**
  - V_min global atomic — `coordinator/cos_state.rs:8` (#917 PR #939).
  - Workers CAS-update V_min on dequeue — landed PR #939; correctness
    repaired via PR #950 (#940 work).
  - Lag throttle with yield/park — landed; hard-cap escape via PR
    #952 (#941 work item D).
  - Telemetry — `v_min_throttles` + `v_min_throttle_hard_cap_overrides`
    counters via PR #1139 (#943).

**Recommendation:** **Close as shipped.** The follow-up trio
#940/#941/#942/#943 closed; this is the umbrella that should close
last.

### #936 — Cross-worker MQFQ: shared per-flow vtime across workers (V_min sync alternative)

**Scope:** Per-flow finish-time table shared across workers. Issue
body explicitly states (REFRAMED per Gemini hostile review): "this
design only equalizes flows by inducing CPU stalls on the fast
workers. It is NOT a work-sharing mechanism."

**Reality:**
- Trade-off is explicit and large: ~43% aggregate-throughput hit
  on degenerate flow distribution (1 flow on worker A, 3 on B
  scenario reduces aggregate from 9.3 Gb/s to ~5.3 Gb/s) for
  per-flow CoV → 0.
- Issue body states "the user must agree the trade-off is
  acceptable BEFORE committing build effort" — this is the gating
  decision and it has not been made.
- #937 (cross-binding redirect) is presented in the same issue as
  the strictly-better aggregate alternative if feasible.
- Per `feedback_cross_binding_impossible.md`: cross-NIC shared UMEM
  is blocked on this lab; same-device sharing exists but is gated
  off due to FQ/CQ ownership bug. So #937 has its own constraints.

**Recommendation:** **Keep open with explicit gating note.** The
issue is genuinely awaiting a user decision on the
fairness-vs-aggregate tradeoff. Suggest adding a clarifying comment
that this work is blocked on user approval of the trade-off, not on
implementation.

### #937 — Re-evaluate #899 cross-binding flow re-steering — RSS-degenerate case path

**Scope:** Redistribute flows at ingress XDP layer to fix
RSS-degenerate cases (0/2/2/2/3/3 distribution observed in #917
diagnostic).

**Reality:**
- Aggregate-cap arithmetic is real: 5/6 active workers at 25 Gb/s
  shaper = 20.8 Gb/s ceiling. This is observable.
- `feedback_cross_binding_impossible.md` updates the original
  "impossible" framing: same-physical-NIC shared UMEM IS feasible
  via XDP_SHARED_UMEM, but cross-NIC fails on this lab and same-
  device prototype is gated off due to FQ/CQ ownership bug.
- Issue proposes XDP-layer redirect at ingress (before UMEM
  binding), which is a different mechanism than shared UMEM.
- #840 attempted NIC RSS table tuning to fix this and was reverted
  (`project_rss_rebalance_negative.md`) — long-lived flows can't
  be moved by table tuning.

**Recommendation:** **Keep open with refined scope.** The XDP-redirect
mechanism is distinct from #840's NIC RSS approach (which failed)
and from cross-NIC shared UMEM (which is blocked on this lab). The
aggregate-cap problem is real but unfixable by the existing
mechanisms. Note that #937 is the strictly-better-aggregate
alternative to #936 — if either ships, the other becomes redundant.

## 4. Recommendation summary

| # | Recommendation | Justification |
|---|---|---|
| #786 | **Close** | Research-tracker complete; actionable scope split out |
| #793 | **Close** | Duplicate of #917 (which is shipped) |
| #794 | **Close-as-deferred** | Phase 4 shipped without triggering AFD need; reopen on measured starvation |
| #837 | **Close-as-wontfix** | Multiple plan-fails + outage regression; needs different architecture |
| #917 | **Close** | All four bullet points shipped via PR #939 + closeout trio |
| #936 | **Keep** | Awaiting user trade-off decision (43% aggregate hit for CoV → 0) |
| #937 | **Keep** | Distinct mechanism from prior attempts; aggregate-cap problem is real |

**Net effect:** 5 closures, 2 stay open with refined gating notes.

## 5. Out of scope

- Implementing #936 or #937. Triage scope is close-or-keep only.
- Any work on #911 (Tier A — same-class HOL on shared_exact) or
  #843 (Tier A — Slice B post-mortem) — those are not in this batch.

## 6. Open questions for adversarial review

1. Is the "shipped" determination for #917 actually complete? The
   issue body's 4 bullet points map to PR #939 + closeout trio —
   does adversarial reading find any of the 4 still open?
2. For #793: is there a Phase 4 component (e.g., the lag-threshold
   `T` constant tuning) that didn't land via #917 and should keep
   #793 open as a tuning issue?
3. For #837: is "close-as-wontfix" too aggressive? Should it stay
   open as a long-term direction like #946 (which closed today
   wontfix-with-rationale) or be re-scoped?
4. For #936/#937: is the keep-open framing accurate, or should
   either be closed as duplicates of the other (since they're
   alternatives addressing the same RSS-degenerate problem)?

## 7. Verdict request

PLAN-READY → execute the close-or-keep recommendations.
PLAN-NEEDS-MINOR → tweak per-issue rationale, then execute.
PLAN-NEEDS-MAJOR → revise close vs keep per finding.
PLAN-KILL → don't execute; rationale wrong.
