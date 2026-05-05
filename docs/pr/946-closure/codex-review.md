# Codex hostile PLAN review — #946 closure plan

Task ID: task-mosq4ggd-310tsq
Codex session ID: 019df88a-816a-7cc1-bc6a-98e152f20061

---

Verdict: **PLAN-NEEDS-MINOR**.

I would close after wording tweaks, not as-is.

Findings:

- `gh issue view 946 --comments --json title,body,comments` could not run here: GitHub API access is blocked by sandbox network policy. I verified against local branch history, the Phase 1/Phase 2 plans, Tier D review docs, and current local `origin/master` at `dab78ef6`.

- The core blocker still holds on `origin/master`: `poll_binding_process_descriptor` is still descriptor-by-descriptor; `poll_stages.rs` explicitly says "No batch reordering"; flow-cache lookup still mutates LRU/eviction state; session resolution still takes `&mut SessionTable` and materializes/promotes/installs; MissingNeighbor still does probe → seed session → publish maps → queue packet in-order.

- The "structurally impossible" claim is valid only if phrased narrowly: **semantics-preserving per-stage batching of stages 12-16 is not incremental in the current architecture**. It is not impossible in the absolute sense. A snapshot/delta-log redesign could exist, but that is exactly the reopen condition and is not Phase 2-sized work.

- I found no committed evidence that `frontend-retired.l1i_miss`, `L1-icache-load-misses`, or `stalled-cycles-frontend` shows frontend/L1-i dominance. Existing `perf stat` evidence is cycles/instructions/cache/L1-dcache focused. So "no measured frontend-bound case" is true, but the plan should avoid saying current costs are definitively "not L1-i-bound"; say "not shown to be L1-i-bound."

- One dangling scope needs explicit handling: Phase 1 docs mention future extraction of stages 12-16 as pure per-packet helper work. Before closing #946, either state that this is not part of #946's L1-i batching goal, or file a small separate maintainability issue for "extract flow-cache/session/MissingNeighbor per-packet helpers." I would not block closure on implementation.

Required tweaks:

1. Replace "structurally impossible" with "not semantics-preserving as an incremental per-stage batching refactor without burst snapshot/delta redesign."
2. Replace "not L1-i-bound" with "no evidence currently shows frontend/L1-i dominance."
3. Add a close-comment sentence resolving the Phase 1.5 helper-extraction dangling scope.

After those edits: close as **wontfix-with-rationale**, not complete.

---

# Gemini Pro 3 review — failed

Task ID: task-mosq4kf1-t5qi5i
Status: ACP initialize timed out after 30s

Per `feedback_gemini_infra_outage_merge_policy.md`, proceeded on
Codex alone. This is the third consecutive Gemini infra failure
(SIMD batch and Tier D batch were both rate-limited; this run
hit ACP timeout). Doc-only closure branch with no PR — no Copilot
gate needed.
