# Claude-SMR hostile plan review — #1750 r3 (convergence)

Reviewing plan v3→v4 (@ 5f44e6fc4 + the helpers.rs consumer fix). Hostile.

## Verdict: PLAN-READY

v3 closed the sole r2 defect (StaleFlowSnapshot livelock) with a bounded
snapshot-AGE check; both Codex r3 and AGY r3 independently confirmed it is
livelock-free AND still covers the real transient (rate-vector-vs-rows publish
lag). The only r3 finding — Codex + AGY both flagged it — is that
`flow_worker_map()` has a SECOND consumer (`server/helpers.rs:124`, the
status/wire path), so the plan's "controller is the only consumer" line was
wrong and the API change must preserve/update that caller. **That is now folded
into §5 and §6.1** (add a controller-facing accessor OR update both call sites;
do not break the status/wire row export). With that, no open defect remains.

## Why PLAN-READY (not another MINOR round)
- The r3 finding is a one-line factual correction about a second call site,
  already incorporated, with a concrete two-option resolution. It is an
  implementation note, not a design hole.
- The design spine is sound and triple-verified: flow_cache scan is the
  authoritative per-worker enumeration (Q1); per-flow RATES unnecessary for the
  homogeneous P12 live gate (Q2, both r2 reviewers concur); the
  observed_bytes-reset is fixable cold-path via a side-table, deferred (Q3);
  reactive controller is the right mechanism (Q4); PLAN-KILL is wrong (Q5).
- The two structural fixes (bundle count+timestamp into one ArcSwap snapshot;
  bounded snapshot-age defer) are minimal, hot-path-free, and close the real
  causes (A publish skew, B-age-out transient). Cause D was already fixed on the
  branch; cause C (post-filter loss) is to be diagnosed from the mandatory
  pre-code live trace, not papered over.
- Acceptance is the LIVE CoV gate (installs>0, CoV≤10%, aggregate preserved),
  which is the right bar — the #1748 ledger proved unit tests + miri + 9 review
  rounds missed the behavioral defects, so the increment is correctly gated on
  live behavior + the debug-log trace.

## Residual risk (acceptable, documented)
- If the live trace shows cause C (post-filter loss) dominates, the fix is a
  trivial `rebalance.rs` filter correction — still cheap, still ship.
- Heterogeneous (elephant+mice) selection remains weak until Path 2; explicitly
  out of scope for the homogeneous blocker-clearing increment and documented.

No further round needed. PLAN-READY.
