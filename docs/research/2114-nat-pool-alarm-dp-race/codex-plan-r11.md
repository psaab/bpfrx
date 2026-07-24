# Codex hostile plan-review — round 11 (plan v11 @ `a89504f6b`)

Reviewer: Codex (companion task `task-mrylebih-92b79h`, session
`019f92ee-618f-7c41-bca8-87f9026d37c5`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications recorded in plan v12.

---

Fold verification:
1. FOLDED — v11 places stopping.Store(true) before applyCancel as runShutdownSequence's first statement (plan.md:468-476,489-496), closing the uncancelled interactive-exit window at pkg/daemon/daemon_run.go:741-756. Startup abort publishes finishStartup(false) before teardown (plan.md:529-539; pkg/daemon/daemon_run.go:827-830), so first-statement stopping publication cannot release a waiter into teardown.
2. PARTIAL — the proposed capture precedes every current tree mutation: ReadActiveMeta and scalar marker assignments occur at pkg/configstore/store_persist.go:26-55; migrations begin at :65 and :74. Ordered Keys/Children/Inactive survive JSON round-trip (pkg/config/ast.go:10-45,124-127), and SyncApply hashes the same migrated tree it writes (pkg/configstore/store.go:661-670,687-689,738,763-766). However, commit-time and decoded pre-migration hashes are not universally equal for the same generation because JSON persistence normalizes invalid UTF-8; see MAJOR below.
3. FOLDED — H explicitly reuses the expired FirstCommit revert body (plan.md:641-644), whose state reset is pkg/configstore/store_persist.go:171-228. The subsequent file-import behavior is the same existing path at pkg/daemon/daemon_run_bringup.go:308-334.
4. FOLDED — the proposed guard is nil-safe and uses runCtxOrBackground (plan.md:438-485), mirroring applyCancelCtx's fallback at pkg/daemon/daemon_apply.go:118-125. V11 also inventories the direct executor fixtures and requires runCtx: context.Background() in each (plan.md:550-568).
5. FOLDED — Run preserves the raw parent separately at pkg/daemon/daemon_run.go:63-70 and derives the signal child at :72-87; v11 stores that child and test leg 3b distinguishes it from the parent (plan.md:489-497,1221-1224).
6. FOLDED — master currently enters immediately and runs a non-cancellable admitted body (pkg/daemon/daemon_apply_commit.go:629-631,693-722). V11 accurately admits that gating can increase overlap likelihood while neither lengthening that body nor enlarging the existing unbounded-after-5s worst case (plan.md:1064-1087; pkg/daemon/daemon_run_shutdown.go:50-58).
7. FOLDED — v11 schedules updates to the recovery outcomes, confirmRecord documentation, and #5835 arm-site comment at plan.md:999-1008, covering pkg/configstore/db.go:161-168 and pkg/configstore/store_commit.go:543-548.
8. FOLDED — the daemon uses semaphore.NewWeighted(1) (pkg/daemon/daemon.go:1107) with x/sync v0.19.0 (go.mod:17); Acquire on a held weight observes cancellation and returns promptly. V11 installs defer Release only after successful acquisition (plan.md:445-450), so the error path cannot release an unacquired weight; leg 2b exercises exactly that path (plan.md:1213-1215).

M3 adjudication: ACCEPT — the guard produces the same empty-tree/compiled-nil/never-committed state as existing expired recovery (pkg/configstore/store_persist.go:171-228), xpf.conf is an independent install-time seed rather than a DB mirror (pkg/configstore/README.md:1134-1143), and node-id forces HA nodes to NORMAL boot (pkg/daemon/bootstrap.go:237-248). I found no H-specific harm that differs from expired-path semantics.

New findings:

MAJOR — GuardedHash is a content hash, not a generation or durable-resolution identity, so H can revert an already-confirmed FirstCommit+cluster record. The hash is only SHA-256 of tree.Format() (pkg/configstore/store_persist.go:329-339). In the admitted recurrence state (plan.md:254-267), an RG0 demotion calls ConfirmPendingOnDemotion (pkg/daemon/daemon_ha.go:466-474), which confirms without changing active content and ignores the confirm.json removal error (pkg/configstore/store_commit.go:762-792). If deletion fails and the process crashes before retry healing—the expressly documented failure window at :575-608—the lingering record's GuardedHash still matches active content, so stale-drop does not run and H immediately reverts it to empty (plan.md:603-608,633-637). That recreates the exact standby divergence forbidden by #4378 (pkg/configstore/commit_confirm_demote_4378_test.go:5-17,50-72). H needs durable generation/resolution identity or a tombstone, plus a demotion-delete-failure/restart regression; content equality cannot solve this.

MAJOR — the claimed same-generation commit/load hash equivalence fails for invalid UTF-8. Quoted strings preserve arbitrary bytes (pkg/config/lexer.go:296-323); strict validation rejects only ASCII C0/DEL bytes, not malformed UTF-8 (pkg/config/freetext.go:54-64,158-181). Interface description is a free scalar copied verbatim by compilation (pkg/config/schema_interfaces.go:36-38; pkg/config/compiler_interfaces.go:25-39). Thus a description containing raw 0xff can pass commit: writeActive serializes it through json.MarshalIndent, which replaces invalid UTF-8 with U+FFFD (pkg/configstore/db.go:435-440), while GuardedHash is subsequently computed from the still-raw promoted tree (pkg/configstore/store_commit.go:437,487-491,543-548). On restart, even the proposed pre-migration hash sees the normalized decoded tree and falsely stale-drops the live record, violating #4577 and bypassing H. Normalize or reject invalid UTF-8 before both persistence and hashing, or derive the arm hash from the persisted canonical representation.

MINOR — "on-disk-bytes basis" is technically false at plan.md:1006-1008. journalConfigHash hashes decoded tree.Format() text (pkg/configstore/store_persist.go:329-339), not the JSON, compatibility envelope, or possibly randomized AES-GCM bytes written by pkg/configstore/db.go:435-450 and pkg/configstore/crypto.go:262-298. Call it the "pre-migration decoded-tree Format() basis" to prevent future literal-byte implementations.

MINOR — regression viii is under-specified: plan.md:1245-1249 permits hand-constructing active.json and confirm.json, which tests recovery placement but not whether production CommitConfirmed generated a binding matching its own persisted tree. Require the test to arm through pkg/configstore/store_commit.go:407-548 and verify the persisted record against a freshly decoded ReadActiveMeta tree before restart; otherwise serialization divergences such as the invalid-UTF case remain invisible.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v12)

Both MAJORs and both MINORs code-verified before folding:

- M1 (resolution ambiguity) VERIFIED — `ConfirmPendingOnDemotion`
  confirms WITHOUT changing content (`store_commit.go:777-792`);
  `resolveConfirmRemovalLocked` deletes-only (:575-590) and
  `noteConfirmRemoveFailureLocked` (:596-608) itself documents the
  resurrect window. Content-hash equality cannot distinguish
  pending vs resolved-pending-deletion; on master today recovery
  re-arms a confirmed record; H would revert it at Load. Folded as
  work item H2 (resolution tombstone: `Resolved: true` written BEFORE
  deletion, recovery drops tombstoned records, retry re-drives
  tombstone→removal) + regression (x) including the
  crash-between-arm-and-tombstone leg.
- M2 (invalid UTF-8 divergence) VERIFIED — `hasControlChars` rejects
  only C0/DEL (`freetext.go:57-65`); lexer preserves quoted bytes
  (`lexer.go:296+`); Go `encoding/json` normalizes invalid UTF-8 to
  U+FFFD on Marshal (`db.go:435-457` is the persistence format). The
  arm-time raw-tree hash then diverges from ANY decoded-tree hash.
  Folded as the CANONICAL basis:
  `canonicalConfigHash(tree) = sha256(Format(jsonRoundTrip(tree)))` at
  BOTH arm and recovery (the Load decode is the recovery side's first
  round-trip leg — already canonical).
- m1 (terminology) VERIFIED — folded: "canonical (round-tripped)
  decoded-tree `Format()` basis".
- m2 (regression viii) VERIFIED — folded: arm through the production
  `CommitConfirmed` path; verify against a freshly decoded
  `ReadActiveMeta` tree; hand-constructed files forbidden.

Verdict recorded: **NEEDS-REVISION (2 MAJOR, 2 MINOR)**; M3
adjudication **ACCEPTED** (no H-specific harm beyond expired-path
semantics).
