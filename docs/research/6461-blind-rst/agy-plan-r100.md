# AGY hostile plan-review — round 100 (v10.17.0)

Reviewer: AGY (direct binary). Verdict: SOUND — full verification of the v10.17.0 folds (OverdueSkipped field/carriage/composition/guards, invalidation lifecycle, parity text reconciliation, inertness scoping).

## Verbatim review

SOUND

### 1. Verification of Round-100 Folds Against Dataplane Codebase and Master Deltas
- **Purge-Path Parity & Documented Demote-Gate Exception** ([`plan.md:730-762`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L730-L762), [`shared_ops.rs:594-635`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L594-L635), [`session_glue/mod.rs:1157-1196`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1157-L1196)):
  The plan text accurately reflects full master parity for the purge path with exactly one documented exception: the local lookup runs before the purge decision (`shared_ops.rs:594-635`, `session_glue/mod.rs:1157-1196`), so upstream marks the matched entry and propagates the shortened closing lifetime (2 s/30 s) before purging. On an anchorless peer-synced entry, the demote gate refuses this mark. The flag-agnostic purge then deletes only the matched local key and forward shared aliases (`promote.rs:181-207`, `shared_ops.rs:960-1013`), leaving the local reverse companion on its ordinary peer-synced trajectory (the §2 absorbing-state residual).
- **Cache Parity Claims** ([`plan.md:1622-1631, 2253-2285`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1622-L1631)):
  All cache Claims match master: a purged pure-ACK segment is cache-eligible and populates the flow cache normally (`flow_cache.rs:352-394`, `poll_descriptor/mod.rs:3900-3959`). Any follow-up cache-eligible packet hits the sessionless flow cache prior to session resolution (`poll_descriptor/mod.rs:298-327`), and the full `ForwardFlow` install with Open emission occurs on the next cache-missing packet's clean miss.
- **Refused-Close Inertness Scoping** ([`plan.md:8-9, 1093-1098, 1561-1574`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L8-L9)):
  Refused-close inertness is correctly scoped to mark creation, `last_seen_ns` timestamp refresh, and timing wheel re-queue operations. Upstream's own flag-agnostic purge (`purge_translated_synced_hit`) operates independently of packet closing flags.

---

### 2. Complete Transport Trace of `OverdueSkipped` Carriage
- **Field Definition & Origin** ([`shared_ops.rs:563-578`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L563-L578), [`session_glue/mod.rs:1092-1122`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1092-L1122)):
  `materialize_shared_session_hit` yields an explicit outcome when an overdue probation entry ($D \le \text{now\_ns}$) is encountered. `ResolvedFlowSessionDecision` carries `materialization_outcome: Option<MaterializationOutcome>`, initialized to `None` on all non-materialize paths and set to `Some(MaterializationOutcome::OverdueSkipped)` when the skip fires.
- **Poller Hoisting & Pipeline Survival** ([`poll_descriptor/mod.rs:370, 509, 883`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L509)):
  The poller hoists `overdue_skipped` into descriptor-loop local scope alongside `flow_cache_install_failed` at `poll_descriptor/mod.rs:509`. Hoisting before line `:883` (where `resolved` is reduced to `resolved.decision`) ensures the signal survives past the reduction down to downstream consumers.
- **Consumer Enforcement Checklist**:
  1. *Teardown Sites* ([`poll_descriptor/mod.rs:698-714, 768-784, 824-840`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L698-L714)): `delete_terminal_filtered_session` calls are explicitly guarded by `if !overdue_skipped` (suppressed because this dispatch installed nothing).
  2. *Anchor Commit Hook*: Skipped (`if !overdue_skipped`).
  3. *Flow-Cache Insert* ([`poll_descriptor/mod.rs:3900-3959`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3900-L3959)): Guarded by `if !flow_cache_install_failed && !overdue_skipped`.
  4. *Probation Clear + Refresh*: Skipped (overdue entries never refresh or clear).
  5. *Ownership Promote*: Cannot engage because no local entry is installed or returned.
- **`MissingNeighbor` Composition Rule** ([`poll_descriptor/mod.rs:4034, 4662-4829`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4034)):
  `OverdueSkipped` + `MissingNeighbor` correctly routes to the `ExistingResolved` buffer-only arm (live backing by overdue entry $K$), bypassing the seed block at `:4662-4829`.

---

### 3. Verification of the Flow-Cache Invalidation Lifecycle
- **Transitions Covered** ([`shared_ops.rs:594-628`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L594-L628), [`install.rs:310-322`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L310-L322)):
  1. *Initial Probation Construction*: Covers new site-2c materializations, including fabric-wire placeholder substitutions (`shared_ops.rs:594-628`).
  2. *S1 $\to$ S2 Adoption*: At adopt time, the prior S1 identity's full alias set is invalidated.
  3. *Non-Probation Predecessor Replacement*: `upsert_synced_with_origin` replacement of a non-probation predecessor (`install.rs:310-322`) invalidates the prior entry's full alias set.
- **Immediate Local Invalidation & Sibling Fan-Out** ([`poll_descriptor/mod.rs:110-131`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L110-L131), [`loop_body/mod.rs:1467-1520`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L1467-L1520)):
  The full alias set (canonical key, reverse companion key, reverse-translated aliases, forward-wire aliases, reply-match tuples) is invalidated in the current binding's cache immediately before descriptor $D_{i+1}$ processing (`poll_descriptor/mod.rs:110-131`) and fanned out to sibling bindings via `reap_expired_sessions` iteration (`loop_body/mod.rs:1467-1520`).

---

### 4. Stress Analysis of Surviving Surface & Invariant Boundaries
- **Matched/Target Probation Skipping** ([`plan.md:1176-1193, 1445-1458`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1176-L1193)):
  An accepted close hitting a reverse-key probation entry validates against forward anchor $F$, marks $F$, but skips restamping/marking the matched probation row. Target propagation similarly skips any probation target.
- **Probation Deadline Integrity** ([`plan.md:1430-1444`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1430-L1444), `expire.rs:168`):
  Expired probation entries bypass `SelfHeal`, `Hold`, and `companion_keeps_alive` retention at `expire.rs:168`, proceeding directly to local-only removal without NAT releases or Close delta emission. `refresh_for_ha_transition` leaves probation deadlines untouched.
- **Overdue Entry Reaping under One-per-Tick Spray** ([`plan.md:1331-1370`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1331-L1370)):
  When $D \le \text{now\_ns}$, the overdue skip avoids re-queuing $K$ on tick zero, preventing continuous spray from pinning overdue entries ahead of timing wheel GC.

---

### 5. Full-Document Consistency Sweep
- **5-Location Consistency**: Gating rules, citation line numbers, and test assertions in §1, §3, §5, §7, §9, and §11 are aligned.
- **Retraction Integrity**: Retractions ($RWoLB$ re-entry, close-aware purge gate, pending-neighbor re-resolve hold, seed-lifecycle completion) are cleanly reconciled to master-split behavior without leaving orphan specifications.
- **Telemetry Accounting**: Packet query tuple accounting (#2501) is preserved across all dispatch paths including `OverdueSkipped`.

---

### Summary of Review
The document is fully consistent internally, accurately accounts for master branch deltas up to `fff7a4ab5`, and completely specifies the transport and invalidation lifecycle for all edge conditions.
