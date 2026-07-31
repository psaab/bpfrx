# AGY hostile plan-review — round 113 (v10.29.0)

Reviewer: AGY (direct binary). Verdict: UNSOUND with two findings: (1) a causal-ordering conflict — the lookup-phase establishment promote fires inside lookup_with_origin before materialize_shared_session_hit produces the effective_transition it must consume (folded v10.29.1 as the compute-at-lookup/apply-at-resolve-end split); (2) §9's consumer count was stale (five vs six). Everything else verified sound, including the canonical token threading.

## Verbatim review

UNSOUND

### 1. Causal Ordering Conflict for Establishment Promote (Consumer 6)
* **Plan Traces:** [`plan.md:6-10`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6-L10), [`plan.md:1146-1148`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1146-L1148), [`plan.md:1897-1901`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1897-L1901), [`plan.md:2696-2708`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2696-L2708)
* **Code Traces:** [`userspace-dp/src/session/lookup.rs:129-149`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L129-L149), [`userspace-dp/src/session/lookup.rs:198-218`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L198-L218), [`userspace-dp/src/afxdp/shared_ops.rs:602`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L602), [`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1092-L1121), [`userspace-dp/src/afxdp/session_glue/mod.rs:1197`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1197)

**Description:** 
Section 5.5 specifies that the establishment promote fires during the arrival dispatch's LOOKUP phase inside `lookup_with_origin`'s post-borrow phase (`lookup.rs:198-218`). Section 5.8 (consumer vi) specifies that the establishment promote must consume `MaterializeReport.effective_transition` and be suppressed when the transition is `OverdueSkipped` or `UpsertRefused`.

However, `lookup_with_origin` is invoked inside `lookup_session_across_scopes` ([`shared_ops.rs:602`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L602)). `MaterializeReport` (and its `effective_transition`) is produced later by `materialize_shared_session_hit` ([`session_glue/mod.rs:1197`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1197)), which executes **after** `lookup_session_across_scopes` returns. 

If `lookup_with_origin` matches a local fabric-wire placeholder entry $K$, the post-borrow establishment promote executes inside `lookup_with_origin` before `materialize_shared_session_hit` is ever called. If `materialize_shared_session_hit` subsequently runs and yields `OverdueSkipped` or `UpsertRefused`, the establishment promote on $K$ has already fired and cannot be suppressed by `MaterializeReport`, creating a pipeline ordering contradiction.

---

### 2. Stale Consumer Count in Section 9 Test Plan
* **Plan Traces:** [`plan.md:1854`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1854), [`plan.md:2620`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2620), [`plan.md:3095`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3095)

**Description:** 
Section 5.8 (line 1854) and Section 11 (line 3095) establish six normative consumers of `MaterializeReport` / `effective_transition` (adding establishment promote as the sixth consumer in round 113). However, Section 9 (line 2620) under "OverdueSkipped propagation" states: `assert each of the five consumers honors it (teardown suppressed at all three sites — :698-714, :768-784, :824-840; no anchor write; no cache insert; no clear+refresh; no promote)`. The Section 9 test plan was not updated to reflect the six-consumer model and omits assertion coverage for the establishment promote suppression.

---

### Review Summary & Checklist Verification
1. **Lookup-phase Promote Timing:** Fails pipeline ordering against `MaterializeReport` generation (Finding 1).
2. **Canonical Token Threading:** Verified. Threading `actual_key` from `lookup_with_origin` ([`lookup.rs:85-102`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L85-L102)) onto `ResolvedSessionLookup` / `FlowCacheEntry` ensures table mutations via `record_by_key_mut` ([`session/mod.rs:1045-1051`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1045-L1051)) operate on canonical keys rather than reverse-translated query aliases.
3. **Consumer Walkthrough:** Uncovered inconsistent consumer counts between §5.8 and §9 (Finding 2).
4. **Surviving Surface & Consistency Sweep:** Analyzed alias invalidation, transient purge parity, missing neighbor buffer-only composition, and probation reap locality.
