# AGY adversarial plan-review — round 21 (plan v21 @ bbd9fd43c)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim.

---

(A) Verification of Folds 1-4

1. FOLDED
- W-kind debt re-keying & `s.armedRecord` retention: FOLDED (plan.md lines 1469-1540).
- File:line evidence:
  - `pkg/configstore/store.go:168-179`: Memory state (`confirmGen`, `confirmTimer`, `confirmPrevTree`, `confirmPrevCfg`) lacks absolute deadline, GuardedHash, HashBasis, or ArmID, proving retention of `s.armedRecord` on `Store` is required for verbatim (w-c) restore without recomputation.
  - `pkg/configstore/store_commit.go:503-553`: `CommitConfirmedGen` and `writeConfirmState` show where nested arming (`s.confirmGen++`) occurs and where `s.armedRecord` is installed and updated on each arm outcome.
  - Interleaving verification: When B fails post-rename, W_B is set. A nested arm C replaces `s.armedRecord` with C, and W re-keys to C. When W_C runs against disk record B (case w-b), it restores `s.armedRecord` (C) over B (subject to same-record dominance if R_B exists).

2. FOLDED
- Eager supersession replacing in-memory marker: FOLDED (plan.md lines 1693-1707, 1739-1748).
- File:line evidence:
  - `pkg/configstore/store_commit.go:548-553`: Establishes master's best-effort arm posture on writeConfirm failure.
  - `pkg/configstore/db.go:40-60`: `confirm.json` and `active.json` share the same `.configdb/` directory, so `DeleteConfirm`'s parent directory fsync (`SyncDir`) covers the prior `active.json` rename.
  - Full chain verification: Permanent BOOT latch -> plain commit/SyncApply lands durably -> eager delete (unlink + dir-fsync) removes `confirm.json` -> probe observes absence -> clears latch. Restart before repair sees absent `confirm.json`, preventing any re-arm or rollback replay on content match / legacy empty hash.
  - Delete rule attack checks:
    - Pre-rename `writeActive` failure: `writeActive` returns error before the post-durability point is reached; eager delete is withheld, leaving unreadable `confirm.json` and BOOT latch intact.
    - Post-rename `writeActive` failure: Eager delete (unlink + dir-fsync) is attempted immediately. A successful eager delete proves `active.json` rename durable via the same-directory barrier; a failed eager delete retains `persistDegraded` and confirm deletion debt.

3. FOLDED
- Health snapshot carriers & precedence: FOLDED (plan.md lines 1804-1843).
- File:line evidence:
  - `pkg/configstore/store_persist.go:342-353`: Master's legacy boolean getter `ConfigPersistDegraded()`.
  - `pkg/api/metrics.go:951-957`: Metric emission using `configPersistDegradedFn`.
  - Precedence verification: `TerminalUnreadable > RestartRecoveryOwed > ConfirmDebt > ActivePersist`. When a BOOT latch (`TerminalUnreadable`) coexists with R-kind debts, `TerminalUnreadable` correctly takes precedence because an unreadable/corrupt record requires urgent operator remediation. All 4 messages are uniquely carryable by the `{ActivePersistDegraded, ConfirmDebtKindMask, ConfirmRecordState}` snapshot.

4. FOLDED
- Stale-expectation repairs: FOLDED (plan.md lines 1857-1875, 1950-1970).
- Evidence: x9 substate-keyed remediation (plan.md:1950-1960), x11 transient/permanent class split (plan.md:1965-1970), and three additive JSON schema fields (`Resolved`, `HashBasis`, `ArmID`, `pkg/configstore/db.go:200-205`).

---

(B) Fresh Attacks with Outcomes

1. Eager Delete Crash Window (crash between `unlink(confirm.json)` and `dir-fsync`)
- Attack: Plain commit lands durably during a BOOT latch. Eager delete unlinks `confirm.json`, but system crashes before `SyncDir` completes. OS directory journal replays dirent on reboot, leaving `confirm.json` present and unreadable.
- Outcome: FAILED.
- Rationale: On reboot, `Load` reads `confirm.json`, encounters the unreadable file again, and re-applies the failure classification: transient errors fail-close `Load`; permanent errors re-arm the permanent BOOT latch (503). The active config remains the durable plain commit. Recovery never parses or re-arms an unreadable file. Subsequent retry or operator action finishes the deletion barrier.

2. `(w-b)` Restore Overwrite vs. Same-Record Dominance Interleaving
- Attack: Window A resolves (`R_A` raised). Nested window B arms, but `writeConfirmState` fails PRE-rename (`W_B` raised, key=B, `s.armedRecord`=B, disk record=A). Same-record dominance forces `R_A` to run first (deleting A). A crash between `R_A`'s delete and `W_B`'s restore leaves window B live in memory/active.json with no `confirm.json` on disk.
- Outcome: FAILED.
- Rationale: `R_A` deleting A before `W_B` restores B leaves `confirm.json` absent on disk. If the daemon crashes before `W_B` runs, restart sees absent `confirm.json`, so active config B stands without auto-rollback. This is master's admitted best-effort posture for arm persistence failure (`pkg/configstore/store_commit.go:548-553`). If no crash occurs, `W_B` executes next, sees absence (case w-c), and restores record B durably.

---

Verdict: PLAN-READY
