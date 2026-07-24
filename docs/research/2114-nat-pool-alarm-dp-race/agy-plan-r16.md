# AGY adversarial plan-review — round 16 (plan v16 @ 0b8e7cc97)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim.

---

# Adversarial Architecture Review (Round 16 — Convergence Round)

**Verdict**: `PLAN-READY`

---

## (A) Verification of v16 Folds Against Worktree Code

### 1. Uniform Rule & #5473 Crash Semantics
* **Status**: `FOLDED`
* **Evidence**:
  * **Replacement / Rollback paths checked**:
    * `SyncApply` (`pkg/configstore/store.go:738–760`): On `s.writeActive` failure (line 738), `syncSupersededConfirm` sets `s.confirmResolvePendingPersist = true` (line 745) and **does not** call `s.resolveConfirmRemovalLocked`. Line 754 calls `resolveConfirmRemovalLocked` *only* inside the `else` block (when `writeActive` succeeds).
    * `PromoteRollback` (`pkg/configstore/store_commit.go:867–937`): When `writeActive` fails (`perr != nil`, line 917), `s.confirmResolvePendingPersist = true` is set (line 926) without invoking `resolveConfirmRemovalLocked`. Line 937 calls `resolveConfirmRemovalLocked` *only* when `perr == nil`.
    * `recoverPendingConfirmLocked` expired-window recovery (`pkg/configstore/store_persist.go:171–227`): When `writeActive` / `writeActiveMarker` fails (`perr != nil`, line 203), `s.confirmResolvePendingPersist = true` is set (line 205). Line 219 calls `resolveConfirmRemovalLocked` *only* when `perr == nil`.
    * Post-durability finalize (`clearConfirmResolutionPendingLocked`, `store_commit.go:631–649`, `store_persist.go:414–428`): When `writeActive` succeeds in `persistRetryLoop` (line 419), `clearConfirmResolutionPendingLocked()` clears `confirmResolvePendingPersist` and invokes `resolveConfirmRemovalLocked("confirm_resolution_finalize")` (line 649).
* **Conclusion**: Pre-durability retention is strictly preserved for all replacement paths; removal is reached only post-durability where the uniform tombstone rule executes.

### 2. Tombstone Helper Invocation Scope
* **Status**: `FOLDED`
* **Evidence**:
  * Plan §4 H2 (line 1030), §5.1 (line 1366), and §9 (line 1826) specify that the read-mutate-write tombstone helper is the **sole** tombstone producer and is invoked **only** from inside `resolveConfirmRemovalLocked` (`pkg/configstore/store_commit.go:584`).
  * In the codebase, `resolveConfirmRemovalLocked` acts as the single entry point for durable `confirm.json` removals across all store workflows.

### 3. Durability of `WriteConfirm`
* **Status**: `FOLDED`
* **Evidence**:
  * `pkg/configstore/db.go:216` executes `fsatomic.WriteFileDurable(db.confirmPath(), data, 0600)`.
  * `fsatomic.WriteFileDurable` completes the full `fsatomic` cycle: write to temporary file $\rightarrow$ `fsync` file $\rightarrow$ atomic rename $\rightarrow$ `fsync` parent directory (`db.go:199–200`).

### 4. Election Neutrality of Terminal-Degraded State
* **Status**: `FOLDED`
* **Evidence**:
  * `pkg/cluster/manager.go:321–336` (specifically lines 334–336) documents that node-global diagnostic health annotations (`ConfigPersistDegraded` / `configSyncFailing`) annotate node health for operator visibility, but **never** alter priority weights, modify monitor weights, or gate cluster election and failover.

---

## (B) Fresh Attacks & Analysis

### 1. B-Rewrite Debt Identity Discipline
* **Finding**: **SOUND**.
* **Analysis**: B-rewrite debt is not an unkeyed third mechanism; it is an instance of `confirmRemoveDegraded` keyed to B's `ArmID`.
  * When `writeConfirmState` fails post-rename, `confirmRemoveDegraded` is raised carrying `ArmID_B`.
  * The 4-state retry machine evaluates `confirm.json`:
    * **Match** (`ArmID == ArmID_B`): Retry calls `WriteConfirm` to rewrite B durably. On success, `confirmRemoveDegraded` clears.
    * **Mismatch** (`ArmID_C != ArmID_B`): Arm C has superseded B. Retry durably rewrites C (matching `s.pendingArmID`) and clears B's debt.
  * The identity discipline remains pinned to the active `ArmID` throughout.

### 2. Empty-`pendingArmID` Edge & Unreadable Records
* **Finding**: **SOUND**.
* **Analysis**:
  * **Legacy Records**: Unmarshal sets `ArmID = ""`. Recovery restores `s.pendingArmID = ""`. Debt raised on resolution is keyed to `""`. On retry, comparing debt key `""` with legacy disk record `""` yields `MATCH`, safely tombstoning and deleting the legacy record. If a new arm B overwrites, `ArmID_B != ""` yields `MISMATCH`, preventing stale deletion.
  * **Unreadable Records at Recovery**: `pkg/configstore/store_persist.go:140–145` performs an early return (`return`) on `ReadConfirm()` error. No timer is re-armed, `s.pendingArmID` remains empty, and no invalid resolution occurs. Under #5637, semantic parse errors transition to terminal degraded state for manual remediation.

### 3. Stale-Drop Path (`store_persist.go:159–165`) Tombstoning
* **Finding**: **SOUND**.
* **Analysis**:
  * On `GuardedHash` mismatch at recovery, `recoverPendingConfirmLocked` calls `resolveConfirmRemovalLocked("stale_confirm_recovery")`.
  * Under v16, writing `Resolved: true` to `confirm.json` before unlink ensures that if deletion fails and the daemon crashes, subsequent boots see `Resolved: true` and immediately drop the record without re-arming. This enhances crash robustness without side effects.

### 4. Re-Arm Path `pendingArmID` Restoration (`store_persist.go:231–253`)
* **Finding**: **SOUND**.
* **Analysis**:
  * `recoverPendingConfirmLocked` sets `s.pendingArmID = rec.ArmID` when re-arming an unexpired window.
  * When the timer fires or explicit resolution occurs, `s.pendingArmID` matches the `ArmID` on disk, maintaining total identity consistency.

### 5. Coexistence of Three Debts & Interaction Matrix
* **Finding**: **SOUND**.
* **Analysis**:
  * `confirmResolvePendingPersist` (unkeyed bool) defers `confirm.json` deletion while active config persistence (`persistDegraded`) is broken.
  * `confirmRemoveDegraded` (keyed on `ArmID`) handles `confirm.json` removal or rewrite failures. B-rewrite debt is unified into `confirmRemoveDegraded`.
  * `persistRetryLoop` (`store_persist.go:414–428`) enforces a deterministic sequence: it resolves `persistDegraded` first by landing `writeActive`. Upon success, line 428 calls `clearConfirmResolutionPendingLocked()`, which clears `confirmResolvePendingPersist` and invokes `resolveConfirmRemovalLocked`. If the removal/rewrite step fails, `confirmRemoveDegraded` retry takes over. The interaction matrix is fully ordered and free of races.

---

## Summary

The v16 plan closes all runtime-state idempotence holes, pins identity discipline across legacy and multi-debt paths, and maintains complete compatibility with existing `#5473` and `#4577` store invariants. The plan is ready for implementation.
