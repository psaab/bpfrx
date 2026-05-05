---
status: REVISED v2 — Codex pushed back on #837 (keep) and #793/#917 framing (slot-floor not CAS-global)
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
- **Functionally absorbed by #917 — but not as the literal sketch.**
  The original Phase 4 plan in `docs/pr/785-umbrella/perf-fairness-plan.md:235`
  proposed a global `AtomicU64 V_min` on `SharedCoSQueueLease` with
  CAS-update on dequeue and an empirically-tuned lag threshold `T`.
- What actually shipped (per #917 PR #939 + closeout) is a different
  design: per-worker padded atomic slots
  (`shared_cos_lease.rs:49,132`), single-writer Release store per
  slot, peer min-scan reduction over participating slots
  (`shared_cos_lease.rs:95`), const-threshold v1 (configurability
  deferred per `docs/pr/917-mqfq-phase4/plan.md:352`).
- The slot-floor design is functionally equivalent for the
  fairness mechanism but architecturally different from the Phase
  4 sketch.

**Recommendation:** **Close as superseded/absorbed by #917.** Do
not claim "literal CAS-global V_min implemented." Be explicit that
the design landed via slot-floor + min-scan, with config tuning
deferred.

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
- **Repo explicitly preserves #837** per
  `docs/pr/838-afd-lite/findings.md:142`:
  > "Do not retire #837. It captures the larger redesign that
  > would be needed for true cross-binding MQFQ; if mouse-latency
  > data later shows we need it, the design context is preserved."
- `docs/pr/838-afd-lite/plan.md:617` defers cross-binding shared-
  exact AFD/MQFQ work back to #837.

**Recommendation:** **Keep open as parked/gated** — not
implementation-ready, but preserved as design-context anchor for
the larger cross-binding redesign. Add a comment that documents
the gating: "parked pending mouse-latency data, post-mortem
prerequisites from #843, or a concrete burst-snapshot seam plan."

This is **different from #946's wontfix-closure** because the
repo's own design docs preserve #837 explicitly; #946 had no
such preservation. The two issues have superficially similar
"plan-killed redesign" shapes but #837's design context is
actively load-bearing for downstream work.

### #917 — MQFQ Phase 4 missing — cross-worker virtual time synchronization (V_min)

**Scope:** Implement `V_min: AtomicU64` on `SharedCoSQueueLease`,
CAS-update on dequeue, lag-throttle when `vtime > V_min + T`.

**Reality:**
- **Functional V_min mechanism shipped, but not as the literal
  CAS-global atomic the issue body sketched.** What landed (PR #939
  + closeout #950/#952/#953/#1139) is a **slot-floor design**:
  - `queue_vtime_floors` map — per-shared-exact-queue
    (`coordinator/cos_state.rs:13`).
  - `PaddedVtimeSlot` — per-worker padded atomic slot
    (`shared_cos_lease.rs:49,132`). Each worker writes its OWN
    slot (Release store, single-writer).
  - V_min is computed as min-scan reduction over participating
    slots, NOT a single CAS-updated global atomic
    (`shared_cos_lease.rs:95`).
  - Lag throttle + hard-cap escape exist
    (`cos/queue_ops/v_min.rs:142`).
  - Telemetry: `v_min_throttles` + `v_min_throttle_hard_cap_overrides`
    counters (`protocol.rs:1230,1240`).
- The slot-floor design is functionally equivalent for the
  fairness goal but architecturally **different** from the Phase
  4 sketch. Worth being explicit about this in the closure
  rationale so future readers don't search for a non-existent
  CAS-global atomic.

**Recommendation:** **Close as shipped (with corrected rationale).**
The closeout trio (#940/#941/#942/#943) is already closed. This
is the umbrella; close it last with the slot-floor description.

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

## 4. Recommendation summary (revised v2 per Codex review)

| # | Recommendation | Justification |
|---|---|---|
| #786 | **Close** | Research-tracker complete; actionable scope split out |
| #793 | **Close as superseded by #917** | Functional scope absorbed; literal CAS-global sketch did NOT land — slot-floor design did |
| #794 | **Close-as-deferred** | Phase 4 shipped without triggering AFD need; reopen on measured starvation |
| #837 | **Keep as parked/gated** | Repo explicitly preserves it (`838-afd-lite/findings.md:142`) for cross-binding redesign |
| #917 | **Close as shipped** | Functional V_min landed via slot-floor design (NOT CAS-global atomic); be explicit in closure |
| #936 | **Keep** | Awaiting user trade-off decision (~43% aggregate hit for CoV → 0) |
| #937 | **Keep** | Distinct mechanism from prior attempts; aggregate-cap problem is real |

**Net effect:** 4 closures (#786, #793, #794, #917), 3 stay open
with refined gating notes (#837, #936, #937). Down from v1's
"5 closures" — Codex correctly rejected closing #837 as wontfix.

**Codex review applied:**
1. #837 reframed from close-as-wontfix → keep-as-parked (per
   `838-afd-lite/findings.md:142`).
2. #917 closure rationale corrected: slot-floor design, not
   literal CAS-global atomic.
3. #793 closure framing corrected: superseded/absorbed by #917,
   not "literal duplicate whose full original tuning scope landed."

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
