---
status: DRAFT v1 — pending adversarial review for issue closure
issue: #946 (Refactor: Pipeline / Chain of Responsibility Pattern)
phase: Closure proposal
---

## 1. Closure proposal

Close #946 as **wontfix-with-rationale** (not "complete").

**Rationale, in three parts:**

1. **The original framing is technically correct.** The worker is
   batched at descriptor acquisition (`RX_BATCH_SIZE = 64`) but is
   *per-packet* through the pipeline body (`flow_cache → session →
   policy → NAT → forwarding → tx`). The L1-i thrashing claim and
   the OCP critique are not literally false. So this issue has a
   real, identifiable target.

2. **The achievable incremental scope shipped — Phase 1, PR #1179.**
   `userspace-dp/src/afxdp/poll_stages.rs` extracts the pipeline
   stages into named helper functions while preserving per-packet
   ordering. The header comment on the file explicitly notes
   "per-packet, no batch reordering" — Phase 1 is intentionally
   pure code motion, not a behavior change.

3. **The full scope is not semantics-preserving as an incremental
   per-stage batching refactor.** Phase 2 — swapping to per-stage
   iteration over the RX burst — was independently PLAN-KILLED on
   2026-05-03 by both Codex and Gemini Pro 3 because **stages 12-16
   cannot be reordered without rebuilding session/NAT/MissingNeighbor
   around immutable per-burst snapshots or a delta-log redesign**.
   The full VPP-style rewrite is not impossible in the absolute
   sense — a snapshot/delta-log redesign could land — but it is
   not Phase-2-sized incremental work. Specifically the blockers:
   - `flow_cache.rs:384,409,436` — lookup mutates LRU; reordering
     evicts entries packet N+1 would have hit.
   - `session_glue/mod.rs:954` — `resolve_flow_session_decision`
     takes `&mut SessionTable` and may install/promote sessions
     mid-burst; install-before-lookup invariant breaks under
     reorder.
   - `poll_descriptor.rs:1903,1981,2038` — MissingNeighbor side
     queue (probe → install seed → publish maps → push
     pending_neigh) is explicitly order-coupled.

   The full VPP/`rte_graph` rearchitecture would require rebuilding
   session lookup, NAT slot allocation, FIB caching, and
   MissingNeighbor handling around immutable burst-boundary
   snapshots. That is multi-quarter, has no incremental seam, and
   has no measured win — **no evidence currently shows
   frontend/L1-i dominance**. Existing perf data on this branch
   profiles backend / dispatch / memory cost (#776 cross-worker
   memcpy, #777 RX poll, #779 TX dispatch) — `frontend-retired.l1i_miss`,
   `L1-icache-load-misses`, and `stalled-cycles-frontend` have not
   been measured, so the L1-i thrashing premise is unproven.

**What this closure is not:**

- It is **not** "Phase 1 shipped, parent effectively complete."
  Phase 1 is intentionally per-packet; the parent goal (per-stage
  batched iteration with L1-i locality) was not achieved.
- It is **not** "the design pattern is wrong on principle." A
  VPP-style batched dataplane is the correct design at sufficient
  scale; xpf's current shape just doesn't have the snapshot
  invariants that would let the rewrite land incrementally.

**What would reopen this:**

- A measurement showing frontend/L1-i dominance — e.g., `perf stat
  -e frontend-retired.l1i_miss,stalled-cycles-frontend` against
  the loss userspace cluster under sustained `iperf3 -P 12 -R`
  load, with frontend stalls a non-trivial share of cycles.
  Current top hotspots (#776, #777, #779) profile as backend /
  memory / dispatch cost, not frontend-bound, but this has never
  been formally measured as L1-i.
- A concrete plan that solves the immutable-snapshot problem at
  burst boundaries (e.g., lookup-only flow_cache snapshot, deferred
  session install at burst end, MissingNeighbor side queue resolved
  before stage advance, or a delta-log applied at burst boundary).

**Phase 1.5 dangling scope (resolved here, not blocking closure):**

The Phase 1 doc on `poll_stages.rs` mentions future extraction of
stages 12-16 as **per-packet helper functions** (pure code motion,
mirroring Phase 1's scope). That work is not part of #946's L1-i
batching goal — it's a maintainability cleanup. **Out of scope for
#946**. If/when someone wants to do it, file a fresh issue scoped
as "Phase 1.5: extract per-packet stages 12-16 into named helpers"
— do not reopen #946 for that.

## 2. What's already documented in the issue

The #946 thread is already long and self-consistent: the original
issue body states the goal, comment 1 (2026-04-28) corrects the
"purely scalar" framing, comment 2 (2026-04-29) summarizes Codex's
investigation that this is "not a normal refactor" but a
multi-month VPP redesign, comment 3 (2026-04-29) files #961 as the
intended first step (since superseded by #1179's Phase 1), comment 4
(2026-05-04) records the Phase 2 PLAN-KILL with both reviewers
converging, and comment 5 (2026-05-05, today) records Codex's Tier D
triage NEEDS-MAJOR pushing back on the framing of "parent complete".

The closure rationale here is consistent with that thread: every
prior comment supports closing as wontfix-with-rationale; the only
thing missing is the actual close action plus a final summary
comment.

## 3. Why triple-review this closure

The Tier D triage's earlier framing was "Phase 1 shipped, parent
effectively complete" — Codex specifically rejected that. This
closure plan replaces that with "Phase 1 is the achievable
incremental scope; full Phase 2 is structurally impossible without
a state-snapshot redesign; close as wontfix-with-rationale until
someone produces a measured frontend-bound case + an incremental
seam plan."

Adversarial review checks:

1. Is the structural-impossibility argument actually airtight, or
   is there a Phase 2 framing the original PLAN-KILL didn't
   consider (e.g., snapshot-based, or with the lookup mutability
   removed)?
2. Is "no measured frontend-bound case" actually true — has
   `perf stat -e frontend-retired.l1i_miss` been run? If not, is
   running it cheap enough to require before close?
3. Does the closure rationale leave room for a future reopen with
   a concrete trigger, or does it close-as-final-decision?
4. Is there any work that would naturally land under #946 but
   isn't covered by the existing related issues (#961, #1146,
   #1163-#1189)?

## 4. Out of scope

- Implementing any portion of Phase 2 here. Closure does not
  preclude future work; it just stops this specific issue from
  acting as an open umbrella for unscoped speculative refactor.
- Changing #961, #1146, etc. — those are the durable scoped
  follow-ups to #946 and remain open.

## 5. Verdict request

PLAN-READY → close issue with rationale comment.
PLAN-NEEDS-MINOR → tweak rationale wording, then close.
PLAN-NEEDS-MAJOR → don't close; revise rationale.
PLAN-KILL → don't close; rationale is wrong.
