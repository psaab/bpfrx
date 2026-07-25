PLAN NO

Reviewed HEAD `d488c7fdf` against plan v9.9.18 (`31f39f4ba`). Part A remains converged. No files were edited.

1. **BLOCKER — Park overflow loses peer state because `syncBackfillNeeded` operates in the opposite direction.**

   The receiver is instructed to discard its oldest inbound session deltas and set `syncBackfillNeeded` ([plan.md:1108](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1108)). That flag is sender-local: outbound `sendCh` overflow arms it ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:36)), and the sweep retransmits only sessions owned locally by that node ([sync_conn_sweep.go:65](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:65), [sync_conn_sweep.go:137](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:137)). Setting it on receiver B cannot make owner A resend a frame B discarded. A has already advanced its local sweep window after queue success ([sync_conn_sweep.go:180](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:180)).

   Concrete trace: B parks A’s g2 E1 INSTALL; overflow discards E1; C2 subsequently publishes and B’s epoch fence becomes satisfied, but B’s local backfill contains no A-owned E1. A then fails, and B is promoted without E1 or P’s reservation, producing connection loss or mid-flow SNAT re-resolution. A discarded DELETE is even less recoverable because the sender journals it only when local enqueue fails ([sync_conn_write.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:69)); only authoritative bulk repair can reconstruct absence.

   A lossy bulk must also not reach the current BulkEnd reconciliation/ACK path ([sync_conn_read.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:205), [sync_conn_read.go:241](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:241)). Required change: B must send an authenticated replay/full-resync request to A, or use an acknowledged replay window; any bulk that discarded a member must neither reconcile nor ACK.

2. **BLOCKER — Typed receipts can undo ownership another worker has already committed.**

   The fold closes blind `rollback_flow`, but reserve→publish is not one transaction. The coordinator currently publishes the canonical shared entry first ([session_import.rs:115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:115)), then fans the identical entry to all workers ([session_import.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:215)). Each worker independently imports it ([session_glue/mod.rs:744](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:744)) through one Arc-shared allocator ([allocator.rs:742](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:742)).

   Concrete trace:

   1. W0 reserves fresh F/P and receives `Inserted`.
   2. Before W0 publishes/disarms its guard, W1 observes F/P, receives `NoChange`, and publishes E1.
   3. W0 suffers the expressly covered post-reservation failure/panic; its `Inserted` guard removes F/P.
   4. W1 and the canonical shared entry still forward E1 using P, while E2 can claim P through the normal bitmap CAS ([allocator.rs:1018](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1018)).

   `NoChange` therefore needs to distinguish committed ownership from another transaction’s pending ownership. `Replaced(old_state)` also needs to retain the old tuple as a shadow hold until publication commits; preserving its data does not prevent P from being claimed between allocator unlock and later rollback.

   The `Retained` inverse is incomplete as written: retention changes `live_by_flow`, expiry indexes, activation metadata, and `active_flows` ([allocator.rs:1238](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1238)); address-only retention also creates a reverse owner ([allocator.rs:2018](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:2018)). The plan specifies only a refcount decrement ([plan.md:1174](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1174)).

   Required change: centralize one prepare/commit before the first publication, or add allocator-visible `Pending(txid)`/`Committed` state with conditional, reference-counted undo. Replacement must dual-hold old and new ownership until commit.

3. **BLOCKER — Slot retarget is not linearized with token release.**

   The plan drains A under its migration WRITE permit, copies ownership into B, then atomically retargets the slot ([plan.md:1427](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1427), [plan.md:1463](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1463)). An atomic pointer swap alone does not make “load allocator, acquire allocator gate, release” atomic:

   1. E1’s token loads `slot.current == A`, then pauses before acquiring A’s READ permit.
   2. Migration acquires A WRITE, snapshots E1’s holder into B, retargets A→B, and closes A.
   3. The token resumes with cached A. Releasing A cannot decrement B’s copied holder.

   Current ownership calls operate through a cloned allocator handle ([allocator.rs:742](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:742), [source.rs:814](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:814)). The lost release leaves a permanent B ghost; repeated refreshes exhaust the finite pool. Omitting that copied holder instead permits B to reissue P while E1 remains live.

   Required change: define a linearizable `slot.with_current()` operation: load `(generation,A)`, acquire A READ, then revalidate the slot while holding READ; mismatch or closed-A must reload and retry B even from RAII `Drop`. Migration needs the corresponding slot-WRITE→allocator-WRITE lock order. The test must pause specifically between slot load and gate acquisition.

4. **HIGH — Epoch equality can permit takeover before the parked FIFO is consumed.**

   Successful apply advances `lastAppliedConfigGen` and clears `applyingConfigGen` immediately ([sync_conn_config.go:389](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_config.go:389)); the fold’s takeover condition checks only that the published epoch reaches the peer high-water ([plan.md:1116](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1116)). It does not require the parked FIFO to be empty or loss repair to finish. A crash in the apply-success→FIFO-drain interval can therefore promote B while E1 is still unapplied.

   Additionally, today the received peer high-water advances only from Config frames ([sync_conn_read.go:301](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:301)), while A can publish/admit under C2 before the subsequent peer push ([daemon_apply_commit.go:245](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go:245), [daemon_apply_commit.go:270](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_apply_commit.go:270)). Required change: takeover readiness must also require empty parked queues and no outstanding repair; peer high-water must include every authenticated observed INSTALL epoch, not only Config receipt.

5. **MEDIUM — The test contract still prescribes the superseded bare rollback.**

   Normative text forbids blind `rollback_flow` ([plan.md:1177](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1177)), but §9 still says a post-retain failure “rolls back via `rollback_flow`” ([plan.md:2759](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2759)). The v9.9.18 tests also omit receiver-directed overflow repair/lossy-BulkEnd suppression, cross-worker receipt interleaving, and the slot-load→gate-read race ([plan.md:2773](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2773)). The remaining “whole-stream,” reset/rebulk, exact-handle, and BulkStart-reset mentions are explicitly historical or qualified, not operative contradictions.

**Round-33 dispositions**

1. **r33-B1 — partially resolved.** `applying==stamp`, control-frame bypass, heartbeat progress, non-resettable node-global watermarks, and active/active directional-zero are closed. Receiver-loss recovery and takeover-after-drain are not.
2. **r33-B2 — partially resolved.** The literal failed-claim and idempotent blind-rollback traces are closed inside one allocator critical section. Receipt ownership across publication, workers, and concurrent allocator mutations is not.
3. **r33-B3 — partially resolved.** Stable indirection is the correct lifetime model, but the specified swap lacks the slot/gate handshake needed to make every release land on exactly one side of the cut.

Part A still exposes no blind-demote trace, and the identity-enforced DELETE folds expose no new propagated stale-kill trace. Sign-off nevertheless remains unsafe: inbound park loss can leave the takeover node without a live flow, receipt rollback can free a tuple still published by another replica, and a slot-retarget race can strand reservations until pool exhaustion. These are concrete HA-loss, SNAT alias/mid-flow-swap, and denial-of-service paths, so v9.9.18 has not converged.
