# Adversarial Architecture Review (Round 14 — Convergence)

**Target**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` (v14)  
**Base Repo**: `psaab/xpf` @ `origin/master` (`ed6999000`)  
**Verdict**: **`PLAN-READY-WITH-NITS`**

---

## Executive Verdict & Summary

The v14 revision successfully addresses the critical defects raised in r13. The scoping of tombstones to content-preserving confirmations (keep-active class), the identity-keyed removal debt, the dual-basis hash binding, and the explicit structural proof of `d.dp` conversion hold up under rigorous inspection against `origin/master`.

All fresh attacks evaluated in r14 are either cleanly resolved by the proposed invariants or bounded by existing master contracts. One minor implementation detail regarding `rec == nil` handling in the tombstone helper is identified as a nit.

---

## Part A: Verification of v14 Folds Against Master Code

### A1. Exhaustiveness of the Three-Class Resolution Assignment

**Verdict**: **FOLDED / EXHAUSTIVE**

A manual enumeration of every resolution path in `pkg/configstore` confirms that all paths map cleanly into the plan's three classes:

1. **Class (i): Content-Preserving Confirmations (Keep-Active)**
   - `ConfirmCommit()` / `ConfirmCommitAs()` ([store_commit.go:736-760](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L736-L760)): Confirms pending window without changing `s.active`.
   - `ConfirmPendingOnDemotion()` ([store_commit.go:780-794](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L780-L794)): Confirms on HA demotion event without changing `s.active`.
   - *v14 Behavior*: Tombstone-first linearization (read-mutate-write `Resolved: true` durably before in-memory timer clear).

2. **Class (ii): Content-Changing Supersessions (Active Advances)**
   - Plain `CommitWithDescription` ([store_commit.go:203, 245](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L203)): Promotes a new candidate config.
   - HA `SyncApply` advancing active ([store.go:738-760](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L738-L760)): Applies a new config from primary.
   - *v14 Behavior*: No tombstone written. Relies on #5835 `GuardedHash` mismatch stale-drop during boot recovery ([store_persist.go:159-165](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L159-L165)).

3. **Class (iii): Replacement / Rollback Resolutions (Intent Preservation)**
   - Timeout auto-rollback (`PromoteRollback`, [store_commit.go:867-937](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L867-L937)).
   - Boot recovery expired-during-downtime revert ([store_persist.go:171-227](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L171-L227)).
   - HA `SyncApply` supersede when local active write fails ([store.go:745](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store.go#L745)).
   - *v14 Behavior*: Tombstoning explicitly **forbidden**. Retains #5473 durable-intent semantics: target persisted first, record removed only on durable success, `confirmResolvePendingPersist` debt retained on failure ([confirm_rollback_durable_5473_test.go:221-293](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/confirm_rollback_durable_5473_test.go#L221-L293)).

4. **Other System Resolution / Teardown Paths**:
   - Factory Reset (`daemon_apply_reset.go:18`): Completely purges `.configdb/` including `confirm.json`.

*Conclusion*: The 3-class assignment is complete and exhaustive across `pkg/configstore`.

---

### A2. Identity Sufficiency of `(GuardedHash, Deadline)` Across Nested Re-arms

**Verdict**: **FOLDED / VERIFIED**

- **Evidence**: In `CommitConfirmed` ([store_commit.go:507-509](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L507-L509)), every call under `s.mu` recomputes:
  ```go
  deadline := time.Now().Add(time.Duration(minutes) * time.Minute)
  ```
- **Nested Re-arm Dynamics**: When a nested `CommitConfirmed` occurs while a window is already pending ([store_commit.go:470-475](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L470-L475)), the new active tree is promoted, advancing `journalConfigHash(s.active)`. Even if `s.active` were identical, `deadline` advances because `time.Now()` has moved forward.
- **Sufficiency**: `(GuardedHash, Deadline)` is guaranteed to change on every arming invocation. The pair forms a strictly unique identity for each `confirmRecord` generation.

---

### A3. Keyed Debt Interaction with #5473 `confirmResolvePendingPersist` Finalization

**Verdict**: **FOLDED / VERIFIED**

- **Code Evidence**: In `CommitConfirmed` ([store_commit.go:445-451, 467](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L445-L451)), arming window B calls `clearConfirmResolutionPendingLocked()` **before** `writeConfirmState` ([store_commit.go:524](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L524)).
- **Sequence Analysis**:
  1. If prior resolution of record A had deferred removal debt (`confirmResolvePendingPersist`), line 445 tries to finalize A's removal.
  2. If that attempt fails, debt is registered as keyed to A: `(A.GuardedHash, A.Deadline)`.
  3. `writeConfirmState` then overwrites `confirm.json` with B's record `(B.GuardedHash, B.Deadline)`.
  4. When the background retry loop for A's debt executes, it inspects `confirm.json` (now B), detects `(B.GuardedHash, B.Deadline) != (A.GuardedHash, A.Deadline)`, clears A's debt, and leaves B's record untouched.
- Master's ordering already protects window B from being destroyed by A's background retry loop.

---

### A4. Canonical vs. Legacy Identity for Normal Records

**Verdict**: **FOLDED / VERIFIED**

- **Code Evidence**: Inspecting `ConfigTree` and `Node` ([ast.go:26-45, 124-127](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/config/ast.go#L26-L45)):
  - Fields in `Node`: `Keys []string`, `Children []*Node`, `IsLeaf bool`, `Annotation string`, `InheritedFrom string`, `Inactive bool json:",omitempty"`, `Line int`, `Column int`.
  - For normal records (valid UTF-8 scalar values, standard AST nodes without retired leaf migrations), unmarshaling JSON (`jsonRoundTrip`) restores the exact AST structure, and `Format()` emits identical Junos configuration text.
- **Result**: `canonicalConfigHash(tree) == legacyConfigHash(tree)` for all normal records.
- **Cross-Version Case**: As v14 honestly documents, exceptional records (raw `0xff` invalid UTF-8 bytes normalized to `U+FFFD` by Go's `json.Unmarshal`, or retired leaf migrations) cannot match across upgrades/downgrades because raw bytes are unrecoverable post-parse. Logging these rare exceptional cases as admitted loss is the mathematically correct behavior.

---

## Part B: Fresh Attacks Evaluation

### B1. The No-Record-at-Resolution Branch

- **Scenario**: `writeConfirmState` is best-effort ([store_commit.go:530-535](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L530-L535)). If `WriteConfirm` failed when arming window A, `confirm.json` is missing from disk, but `s.confirmTimer` is armed in memory. Later, `ConfirmCommit()` is called.
- **Analysis**:
  - The tombstone helper performs a read-mutate-write of `confirm.json`.
  - When `ReadConfirm()` returns `(nil, nil)` (`os.IsNotExist`, [db.go:245-247](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L245-L247)), there is no record on disk to tombstone or resurrect.
  - The tombstone helper must treat `rec == nil` as a successful no-op (matching `DeleteConfirm`'s `os.IsNotExist` handling, [db.go:284](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L284)) and return `nil`, allowing in-memory resolution to complete cleanly.
- **Status**: Sound. *(See Nit 1 below for explicit pseudocode/test pinning).*

---

### B2. Tombstoned Record A Lingering During Arming of Record B

- **Scenario**: Record A was tombstoned (`Resolved: true`), but its durable deletion failed. Before background retry deletes it, a new `CommitConfirmed` arms record B.
- **Analysis**:
  - Arming B calls `writeConfirmState(B)` ([store_commit.go:524](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go#L524)), which invokes `fsatomic.WriteFileDurable` ([db.go:217](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L217)).
  - `WriteFileDurable` atomically replaces `confirm.json` with B's live record.
  - A's lingering retry debt inspects `confirm.json` (now B), detects key mismatch `(B.GuardedHash, B.Deadline) != (A.GuardedHash, A.Deadline)`, and clears A's debt without modifying B.
- **Status**: Sound. Neither A's tombstone nor A's debt interferes with B.

---

### B3. Legacy Record Tombstoned by New Build, Recovered by Old Build

- **Scenario**: A node running the new build writes a tombstone (`Resolved: true`, `HashBasis: "canonical-v1"`) to `confirm.json`. The binary is downgraded to an older release.
- **Analysis**:
  - The old build's `confirmRecord` struct ([db.go:169-192](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L169-L192)) lacks the `Resolved` field.
  - Go's `json.Unmarshal` ignores unknown JSON keys. The old build unmarshals `Deadline` and `PrevTree` normally.
  - If unexpired, the old build re-arms the timer; if expired, it rolls back.
  - This matches master's existing behavior on a failed `DeleteConfirm`. As documented in §5.1 / §5.5, additive JSON fields with ignore-unknown-fields is the established contract ([db.go:200-205](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L200-L205)).
- **Status**: Sound.

---

### B4. Recovery Total Order Against Tombstoned FirstCommit+Cluster Records

- **Scenario**: A `FirstCommit+cluster` record was tombstoned (`Resolved: true`) by `ConfirmCommit`, but disk deletion failed. The daemon restarts.
- **Analysis**:
  - Recovery total order in `recoverPendingConfirmLocked` ([store_persist.go:136-256](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go#L136-L256)):
    1. `ReadConfirm()` parse gate ([db.go:242-282](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/db.go#L242-L282))
    2. `rec.Resolved == true` check $\rightarrow$ Drop record, return early.
    3. `GuardedHash` mismatch $\rightarrow$ Stale-drop.
    4. Expired during downtime $\rightarrow$ Revert.
    5. Work item H predicate (`FirstCommit && Chassis.Cluster != nil`) $\rightarrow$ Revert-at-Load.
    6. Unexpired normal record $\rightarrow$ Re-arm.
  - Because `rec.Resolved == true` is checked at step 2 **before** Work Item H (step 5), a tombstoned `FirstCommit+cluster` record is dropped immediately. Work Item H never fires on a confirmed config.
- **Status**: Sound.

---

## Nits & Implementation Guidance for `/engineer`

1. **Nit 1 (Tombstone Helper `rec == nil` Handling)**:
   In the read-mutate-write tombstone helper, if `ReadConfirm()` returns `(nil, nil)` (no file on disk because arm-time `writeConfirmState` failed), the helper must explicitly treat `rec == nil` as a clean no-op (`return nil`). A test case covering `ConfirmCommit` when `confirm.json` is absent should verify no error is returned.

---

## Final Verdict

**`PLAN-READY-WITH-NITS`**

The v14 plan is complete, mathematically sound against the repo's concurrency and store invariants, and ready for implementation execution via `/engineer 2114`.
