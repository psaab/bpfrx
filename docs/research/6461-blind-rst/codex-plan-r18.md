PLAN NO

## Findings

1. **BLOCKER — join-first destroys the allocation before escrow can acquire its keeper.**

   V9.8 stops and joins workers before snapshot/keeper transfer ([plan.md:879](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:879)). Joining waits for worker-local state to destruct ([worker_manager.rs:146](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/worker_manager.rs:146)); the proposed RAII side map therefore drops every old hold before the coordinator proceeds ([plan.md:920](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:920)). At refcount zero the live allocation is freed—the current analogue removes `live_by_flow` ([allocator.rs:1324](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1324)).

   A surviving `Arc<PortAllocator>` preserves the allocator object, not the deleted allocation. The post-join snapshot may retain a detached session clone, but it cannot transfer a nonexistent hold; replay then rejects or another flow can acquire the port. A routine compatible-config reconcile can therefore destroy live SNAT continuity and permit a pool-port change.

   The architecture needs a two-phase stop: quiesce packet commits while worker tables still hold tokens, acquire/transfer keepers, then exit/join—or have workers hand tokens into pre-existing coordinator escrow during shutdown.

2. **BLOCKER — conditional non-Close Go deletions cannot present the E1 incarnation required by the helper fence.**

   The helper-only rule and per-syscall alias reread are normative at [plan.md:995](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:995), but current conditional control-plane scans possess only detached BPF values, whose ABI lacks `flow_incarnation_id` ([plan.md:987](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:987)).

   Concrete trace: the new policy snapshot is already active before invalidation ([daemon_apply_commit.go:256](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go:256)); invalidation detaches E1 entries ([daemon_policy_invalidate.go:311](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:311)) and deletes them later ([daemon_policy_invalidate.go:357](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:357)). Meanwhile the dataplane can replace E1 with same-key E2. `DeleteBatchKnown*` reduces the operation to keys ([session_store.go:391](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:391)); Go constructs an explicitly tuple-only helper delete ([manager_ha.go:1498](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/manager_ha.go:1498)), and Rust reconstructs that key and deletes unconditionally ([sync_session.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/sync_session.rs:29)).

   The helper cannot know the source was E1: rereading the current alias finds E2 and authorizes deleting E2. For translated E2 this destroys live NAT ownership and enables re-seeding. Cluster-bulk reconciliation has the same detached-selection shape ([session_store.go:626](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:626)). Go conntrack GC itself is not the live userspace path because it is disabled for this backend ([daemon_run.go:230](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_run.go:230)).

   Every conditional delete must capture and carry `(origin_process_nonce, flow_incarnation_id)` from selection through helper commit, or the selection/filtering must move into the helper. Deliberately unconditional administrative clears need separate semantics.

3. **HIGH — replay acknowledgement and keeper release are not a complete state machine.**

   The plan first requires all outcomes before keeper release, then says a rejected entry releases immediately ([plan.md:902](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:902)). Because one keeper covers multiple replica commands, an early rejection can drop the keeper before a later replica retains.

   There is also no missing-outcome rule. Workers report READY before consuming commands ([loop_body/mod.rs:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:150), [loop_body/mod.rs:682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:682)); a subsequent panic or hang can leave an acknowledgement permanently absent, while launched workers retain the complete queue-map `Arc` ([bringup.rs:598](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:598)). “Collect all outcomes” can then stall reconcile after the old dataplane is gone.

   Keeper accounting must be per allocation with a pending-command count, a bounded replay barrier, worker-death/abandonment conversion, and `Installed` emitted only after side-map token insertion. Once those conditions hold, allocator-lock serialization makes keeper release versus a late retain safe.

4. **HIGH — the required fence test still specifies the wrong identity.**

   Section 9 still requires `(origin_node_id, session_id)`-conditional deletion ([plan.md:1716](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1716), contradicting the normative `(origin_process_nonce, flow_incarnation_id)` fence ([plan.md:1050](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1050)). That is an executable acceptance-test contract and would omit the per-boot/incarnation protection.

5. **MEDIUM — the promised contract sweep remains internally contradictory.**

   The plan still says a reverse-synth close marks only the reverse entry ([plan.md:729](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:729), while the normative path atomically marks the forward family ([plan.md:1345](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1345)). It says “No origin flip anywhere” immediately before retaining committed `SharedPromote` ([plan.md:1521](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1521)). The test plan still says “required reserve” and “pending #6522” ([plan.md:1774](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1774), although verify-and-retain/refcounting is mandatory Part B. These leave competing implementation contracts.

6. **LOW — absolute blind-close claims remain false.**

   Section 11 still says “a blind close never marks” ([plan.md:1932](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1932), contradicting the correct statement that an in-window blind guess can mark at the documented probability ([plan.md:1902](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1902)). It must say refused/out-of-window/no-baseline closes never mark.

## Round-17 dispositions

- **r17-B1 — NOT RESOLVED.** The acknowledgement concept improved, but join-first destroys the source holds before keeper acquisition; outcome accounting is also incomplete.
- **r17-B2 — PARTIALLY RESOLVED.** Helper ownership and per-syscall rereads fix the delayed-Close ordering in principle, but conditional non-Close Go paths lack an expected incarnation.
- **r17-H3 — RESOLVED.** Exact allocator identity, handle-keyed side-map placement, and panic-unwind RAII are implementable. `PortAllocator` already shares live state through `Arc` ([allocator.rs:742](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:742)).
- **r17-M4 — RESOLVED.** The two probation branches are now stated explicitly at [plan.md:1664](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1664).
- **r17-M5 — PARTIALLY RESOLVED.** The reverse-synth test and Phase-2 labels were corrected, but the fence-tuple, reverse-marking, origin, reserve, and #6522 contracts remain inconsistent.
- **r17-M6 — NOT RESOLVED.** Unqualified blind-close claims remain.

## Bottom line

Part A remains converged: I found no new path around the sequence demote gate. Part B has not converged. Join-first makes its keeper impossible to acquire, and conditional Go deletion paths cannot authenticate a detached E1 against current E2, preserving a concrete live-SNAT deletion/re-seed class. The replay barrier and written contracts also remain underspecified. V9.8 therefore cannot be implemented safely as written.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
