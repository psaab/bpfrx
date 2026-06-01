# #1735 (#1731-d) reviewer task IDs

Generalize per-flow MQFQ to all shaped queues. Record reviewer
task-ids here so continuations can fetch by id (long-running agents
lose Codex session state).

## Plan review (round 1)
- Codex: task-mpuie4sw-l40kxh
- AGY: adversarial-review-mpuieaih-7pfw74
- Claude-SMR: in-conversation (this agent)

## Code review
- Codex: task-mpujl4vn-yt2an6
- AGY: adversarial-review-mpujlac9-54uf0b
- Copilot: requested on PR #1740

## Plan-review outcome (converged DESIGN-READY)
- Codex r1 (task-mpuie4sw-l40kxh): PLAN-KILL on Q2 fragility → all findings folded into v2.
- AGY (adversarial-review-mpuiw502-ogiynq): PLAN-READY — mathematical proof that the
  Codex Q2 counter-example is invalid under the synchronous single-thread worker model;
  best-effort fast-path cost <0.5 ns CoS-OFF / ~1-3 ns CoS-ON, within noise.
- Codex r2 (task-mpuizo8z-l91skn): "PLAN-KILL" but ONLY because the commit is docs-only
  (no code yet — expected for a plan review). Codex explicitly confirmed every v2 plan-side
  remedy is coherent/correct (Q2 mem::take+per-item-hash, Q4 tightened predicate+ordering,
  Q3 admission, Q5 gate). No surviving DESIGN objection. Resolved by implementing, then
  Codex code-review validates the real source.
- Claude-SMR (in-conversation): PLAN-READY — independently verified FACT-A (every queue
  primitive dispatches on flow_fair()), the Q2 induction, and the demotion ordering.

Converged: DESIGN-READY. Proceed to implement; full hostile CODE review (Codex+AGY+Copilot)
re-runs on the implemented source before merge.
