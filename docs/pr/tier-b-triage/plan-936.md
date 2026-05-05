---
status: DRAFT v1 — focused single-issue closure plan for #936
issue: #936
phase: Closure proposal — pending explicit user opt-in
prior:
  - plan.md v3 kept #936 open (commit ea0b7ba1)
  - plan-v4.md proposed close-as-declined; Codex rejected wording
---

## 1. Closure proposal (corrected per Codex v4 review)

Close #936 as **"pending explicit user opt-in"** (per Codex round-1
suggested reframing). Not "declined by default" — that overstates
silence. Just removes the issue from active backlog until the user
explicitly accepts the trade-off in the issue body.

## 2. Why #936 is structurally a user-decision issue

The issue body itself states the gate:

> "this design only equalizes flows by inducing CPU stalls on the
> fast workers. It is NOT a work-sharing mechanism."
>
> "**Wins:** per-flow CoV approaches 0 if the design is correct."
>
> "**Loses:** aggregate throughput drops to `min_per_flow_rate ×
> N_flows` when stalls bind. The 1+3 example would cap aggregate
> at ~5.3 Gb/s (4 × 1.33), not 5.33 + 1 × 4 = 9.3 Gb/s — a 43 %
> aggregate-throughput hit for fairness."
>
> "**Compare to #937** (cross-binding redirect) which redistributes
> flows instead of stalling — strictly better aggregate throughput
> if feasible."
>
> "**This is a fundamental limit; the user must agree the
> trade-off is acceptable BEFORE committing build effort.**"

The issue is explicitly architected around a user-approval gate.
There is no measurement that resolves it; it's a values choice
about what xpf optimizes for on degenerate flow distributions.

## 3. Why "pending explicit user opt-in" is the right action

**What "stays open" currently means:** the issue sits in the
active backlog forever, indefinitely waiting for a user comment.
There is no measurement that closes it; no PR that closes it; no
upstream blocker whose change would close it. It is an open
question waiting to be answered. Without an answer, it accumulates
triage cycles each pass.

**What "close pending explicit opt-in" means:** issue moves out of
active backlog into closed state. The reopen condition is
explicit and easily reachable — user posts a comment opting in,
or files a fresh issue with the trade-off accepted. No information
is lost; the analysis stays in the issue body verbatim.

**The functional difference:** triage no longer pretends this is
"work in progress." It is correctly labeled "awaiting user
decision; nothing to triage."

## 4. What the closure rationale should NOT say

Per Codex round-1 review of v4:

- ❌ "Trade-off declined by default" — overstates silence; user
  hasn't said no, just hasn't said yes.
- ❌ "Wontfix" — implies engineering judgment that the work
  shouldn't be done; the trade-off may be acceptable in some
  topologies / use cases.
- ❌ "Superseded by #937" — incorrect; #937 is an alternative,
  not a duplicate, and is itself blocked.

## 5. What it SHOULD say

Per Codex round-1 reframing suggestion:

- ✅ "Closed pending explicit user opt-in to the ~43%
  aggregate-throughput trade-off documented in the issue body."
- ✅ "Reopen trigger: post a comment confirming the trade-off
  is acceptable for the target workload, then this becomes
  actionable per the design in the issue body (Option A: lock-
  free per-flow finish atomic)."
- ✅ "If the trade-off is not acceptable, #937 (cross-binding
  redirect) is the strictly-better-aggregate alternative —
  itself currently blocked on shared-UMEM availability per #776."

## 6. Recommendation

**Close #936** as "pending explicit user opt-in." Single-issue
closure; doesn't affect #837 or #937 (those stay open per
Codex v4 verdict).

**Net effect:** 1 close, +1 to today's running total. Today's
final tally would be 16 close, 24 stay open.

## 7. Hostile review questions

1. Is "pending explicit user opt-in" actually distinguishable
   from "stays open"? What's the substantive difference?

2. Does closing #936 risk losing the design analysis for someone
   who later wants to do this work? (Answer: no — issue body
   stays verbatim; reopening restores it to active backlog.)

3. Is there a measurement that would close this without a user
   decision (e.g., evidence that no real workload triggers
   degenerate flow distribution)? If so, that's the better path.

4. Does this set a precedent for closing other "user decision
   gated" issues that may exist?

## 8. Verdict request

PLAN-READY → close #936 with "pending opt-in" rationale.
PLAN-NEEDS-MINOR → tweak rationale, then close.
PLAN-NEEDS-MAJOR → keep #936 open; "pending opt-in" too
permissive.
PLAN-KILL → premise wrong; the user-decision gate isn't a
closeable state.
