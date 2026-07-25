PLAN NO

1. **BLOCKER — helper-authoritative selection can atomically delete the wrong incarnation because historical predicates lack a temporal cut.**

   The helper transaction at [plan.md:1044](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1044) closes the post-selection E1→E2 race, but does not make a stale predicate authoritative:

   - Policy invalidation runs after the new policy snapshot is active ([daemon_apply_commit.go:245](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go:245), especially lines 256–270) and targets old numeric IDs ([daemon_policy_invalidate.go:129](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:129), lines 160–168 and 261–266). A flow admitted after activation by the new, still-permitting version of a modified policy already needs no rematch, yet the delayed helper scan selects and deletes it. Deleted-policy IDs can also collide with a different new policy; that cross-config reuse is explicitly documented at [policies_ids.go:60](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/policies_ids.go:60).
   - Cluster cleanup is BulkStart-snapshot-driven ([sync.go:1069](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go:1069), lines 1080–1126). The existing test expressly permits a secondary→primary ownership flip mid-bulk ([sync_test.go:1535](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_test.go:1535), lines 1573–1585). A locally authoritative E2 committed after that flip still satisfies the old “peer-owned at BulkStart and key absent” predicate, so the helper deletes E2 and propagates E2’s correctly captured identity. For SNAT, that can release its final hold and force a mid-flow re-seed.
   - Filtered administrative clearing is different: its intent is to delete whatever matches when executed, so current-state selection is correct.

   Policy invalidation needs an admission/config-epoch boundary; bulk cleanup needs sender/bulk-epoch provenance or a helper-owned candidate cut. `flow_incarnation_id` alone cannot distinguish “new but still matches the old predicate.”

2. **BLOCKER — the peer incarnation fence is unimplementable under the plan’s simultaneous no-wire requirement.**

   The helper must send the selected `(origin_process_nonce, flow_incarnation_id)` and the peer must compare it ([plan.md:1061](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1061), [plan.md:1111](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1111)). Yet §§5.8/6 still require no HA-wire field additions ([plan.md:1517](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1517), lines 1531–1533).

   Today deletes carry only key plus generation ([sync_conn_write.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:69), [sync_conn_read.go:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:150)); the receiver then key-deletes after the generation guard ([sync_conn_gen.go:493](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:493)). A freshly generated delayed E1 tombstone can therefore still outrank E2. Part B requires an explicit additive install/delete wire schema, receiver identity storage, and mixed-version behavior; it cannot also promise an unchanged wire.

3. **HIGH — r19-H2’s obsolete fence tuple remains in the acceptance criteria.**

   The normative tuple is `(origin_process_nonce, flow_incarnation_id)` at [plan.md:1115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1115), but §9 still mandates `(origin_node_id, session_id)` at [plan.md:1803](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1803). `session_id` is only worker ID plus a per-worker counter initialized from one each process ([session/mod.rs:755](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:755), lines 766–789). It is not boot-qualified, so the test contract can authorize stale E1 cleanup against a post-restart E2.

4. **HIGH — a claimed replay command has no bounded terminal transition.**

   The plan releases an allocation keeper only at `pending == 0`, while a claimed command converts only on worker death ([plan.md:918](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:918)). The cited supervisor marks death only after panic unwind ([supervisor.rs:95](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/supervisor.rs:95)); `dead` is explicitly panic-only ([worker_runtime.rs:239](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker_runtime.rs:239)), and stopping blocks in `join` ([worker_manager.rs:146](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/worker_manager.rs:146)).

   Thus a command claimed just before the deadline and stuck in an alive worker either pins the keeper/reconcile forever, or “abandonment drains escrow,” losing the live flow’s continuity before the late verify-and-retain aborts. The design needs a finite `Claimed → Abandoned` transition with a commit-time permit recheck, detached bounded keeper ownership, or process-fatal recovery. The present barrier is not bounded.

5. **MEDIUM — the new tests do not exercise the operative races, and helper scanning loses an existing bounded-work invariant.**

   The test at [plan.md:1748](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1748) says E1 is selected, E2 replaces it, then deletion compares E1. That schedule cannot occur inside the declared single canonical-lock select/delete transaction. Missing cases include E2-before-selection for policy and bulk predicates, claimed-alive non-completion, and same-`session_id`/different-process-nonce.

   Filtered clear is currently deliberately limited to 1,024-key chunks because it is fabric-reachable and collect-all caused an O(matches) memory/CPU DoS ([server_sessions.go:1193](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/grpcapi/server_sessions.go:1193), lines 1216–1231 and 1293–1373). The helper contract supplies no bounded cursor/chunk rule and appears to hold the canonical lock across selection and deletion.

6. **MEDIUM — the claimed contract sweep did not land.**

   - [plan.md:729](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:729) still says reverse synthesis marks only the reverse entry, contradicting atomic forward-family marking at lines 1407–1413.
   - [plan.md:1583](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1583) says there is no packet-driven origin flip, then retains packet-driven `SharedPromote` at lines 1588–1590; current promotion does exactly that at [promote.rs:86](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86).
   - The introduction and §11 still describe #6522 as separately filed ([plan.md:18](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:18), lines 2034–2041), while Part B explicitly ships its refcount at lines 1872–1875.
   - “Single producer/no duplicates” and “exactly one” remain at lines 1796–1798, 1842–1844, and 1875–1878, contradicting the accepted bounded duplicate case at lines 759–762.

7. **LOW — absolute blind-close wording remains false.**

   The precise acceptance-window statement at lines 24–30 is correct, but “the blind close remains inert” at [plan.md:1128](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1128) and “blind closes refused” at line 1679 still omit the refused/out-of-window/no-baseline qualification. In-window guesses remain accepted by design.

### Round-19 dispositions

- **r19-B1 — partially resolved.** Helper selection removes the post-selection replacement window for current-state predicates, but policy/bulk predicates still lack their historical cut, and peer propagation remains contradictory.
- **r19-H2 — not resolved.** The obsolete tuple remains verbatim in §9.
- **r19-M3 — partially resolved.** Claim-before-execute fixes the deadline race for unclaimed work; claimed-alive non-completion remains unbounded.
- **r19-M4 — partially resolved.** Tests were added, but the principal race schedule is impossible and the real temporal/claimed-forever cases are absent.
- **r19-M5 — not resolved.** All cited reverse-synth, authority, #6522, and duplicate-emission contradictions remain.
- **r19-M6 — not resolved.** Some new qualification was added elsewhere, but the cited absolute claims remain.

Part A remains converged: I found no renewed blind-close bypass in the dataplane demotion gate. Part B does not yet converge because its helper can make a stale cleanup decision about current E2, then faithfully delete that live incarnation locally and cluster-wide, while its required peer identity cannot be transported under the declared no-wire contract. The plan needs predicate-specific epochs/cuts, an explicit HA identity protocol, and a genuinely terminal replay-claim state before implementation is safe.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
