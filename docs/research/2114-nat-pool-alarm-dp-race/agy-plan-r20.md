# AGY adversarial plan-review — round 20 (plan v20 @ d37961cd7)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim. NOTE (claude-smr-plan-r20.md): AGY's attack-3 rationale covers only the GuardedHash-MISMATCH sub-case; the content-match/legacy-empty binding sub-case is the SMR M1 finding.

---

(A) Verification of each fold 1-7:

1. Same-record dominance: FOLDED
   - Evidence: `pkg/configstore/store_persist.go:402-465`, `pkg/configstore/store_commit.go:535-554`.
   - Verification: Under any pass ordering, while an R-kind debt keys the current on-disk record K (`s.onDiskArmID == K`), any W-kind rewrite for K is suppressed and stale-keyed mismatch rewrites (such as R_A's mismatch branch when K = B) are blocked by the per-debt membership guard. R_K's durable tombstone serves as the universal barrier, after which stale-keyed debts clear. The pass re-checks `s.onDiskArmID` under `s.mu` at each debt's turn, closing the interleaving across all pass orderings and crash legs (x16).

2. Debt-kind split: FOLDED
   - Evidence: `pkg/configstore/store_commit.go:503-553`, `pkg/configstore/store_persist.go:402-465`, `pkg/configstore/db.go:200-282`.
   - Verification: R-kind debts execute the four-state removal table (match → tombstone→delete; absent → DeleteConfirm re-drive; mismatch → stale-clear; read error → typed). W-kind debts execute the three-state rewrite table ((w-a) match → WriteConfirm durable → clear; (w-b) mismatch → A/B/C transitions; (w-c) absent → restore from in-memory window state if live, else stale-clear). The restore fields (`Deadline`, `PrevTree`, `FirstCommit`, `GuardedHash`, `ArmID`) exist in `Store` under `s.mu` (`store_commit.go:503-553`). A W debt whose window was resolved while pending has `armedArmID != debt.ArmID` and clears as stale without resurrecting a tombstone or abandoning a live recovery record.

3. BOOT-origin persistent substates: FOLDED
   - Evidence: `pkg/configstore/store_persist.go:136-165,342-353`, `pkg/api/health.go:65-71`.
   - Verification: Substate (ii-a) RESTART-RECOVERY-OWED keeps the latch held and surfaces a distinct 503 message ("commit-confirmed recovery record readable again; restart required to complete recovery") upon clean read without in-process revert/re-arm; the deadline continues running on disk and an expired window reverts at restart per #4577. Substate (ii-b) SUPERSEDED-WHILE-UNREADABLE sets `confirmRecordSupersededDuringLatch` upon a durable plain commit or SyncApply during the latch; clean read converts the record into an R-kind removal debt that tombstones and deletes it. Across a second boot before repair, if the record remains unreadable it re-latches; if repaired before a new commit on boot 2, RESTART-RECOVERY-OWED holds 503 until boot 3 where standard `Load` recovery and GuardedHash mismatch (`store_persist.go:149-165`) safely stale-drop the superseded record.

4. Convergence measure: FOLDED
   - Evidence: `pkg/configstore/store_persist.go:402-465`.
   - Verification: The lexicographic measure per debt `(tombstone-pending > delete-pending > rewrite-pending > done)` strictly decreases to zero given quiescence and a failure-free suffix. On merge, tombstone-required dominates delete-finishing (`tombstone-pending`). Same-record dominance prevents stage inversion (a rewrite raising a new tombstone-pending debt for an already-resolved record).

5. Confirmed-commit orphan BY OVERWRITE: FOLDED
   - Evidence: `pkg/configstore/store_commit.go:437-468,503-524`.
   - Verification: A seeded orphan record A is resolved at arm time by `writeConfirmState` overwriting `confirm.json` directly with fresh record B, avoiding two extra durable operations (unlink + dir-fsync) in the recordless window. If `writeConfirmState` fails PRE-rename, orphan A remains intact on disk and an R-kind debt keyed A (`onDiskArmID = A`) is raised for the retry loop to tombstone and delete (regression x17).

6. Envelope: FOLDED
   - Evidence: `pkg/configstore/store_persist.go:21-24`, `pkg/configstore/bootstrap.go:36-63`.
   - Verification: `LoadContext(ctx)` executes an initial read + up to 3 retries (4 reads total) with backoff 100 ms → 200 ms → 400 ms (~0.7 s max delay), select-driving on `ctx.Done()`. `Load()` is preserved as a wrapper passing `context.Background()`. Transient exhaustion routes to fail-closed via `ErrConfirmStateUnreadable`.

7. Generic confirm-persist health message & sweep: FOLDED
   - Evidence: `pkg/api/health.go:65-71`, `pkg/configstore/db.go:239-241`, `pkg/daemon/daemon.go:1042-1053`, `pkg/api/metrics_descriptors.go:625-630`, `pkg/configstore/README.md:470-473,937-968`.
   - Verification: `/health` renders degraded confirm-persist as a generic removal/rewrite message with a debt-kind detail field under precedence `terminal > confirm-persist > active-persist`. `db.go:239-241` and `README.md:470-473,937-968` reflect the four `Load` error shapes and seeding read. The "BOTH" aggregate framing is updated to all three causes across metrics descriptors and options. The orphan premise rests on single-Store ownership per node (`daemon.go:1042-1053`).

---

(B) Fresh attacks with outcomes:

- Attack 1: (w-c) restore hash computation `journalConfigHash(s.active)` at restore time vs arm time.
  - Outcome: FAILED.
  - Rationale: Under `s.mu`, any operation that mutates `s.active` (plain commit, nested `CommitConfirmed`, `PromoteRollback`, `SyncApply`, `FactoryReset`) cancels or resolves the live window W first, clearing or re-keying `s.armedArmID`. Therefore, while any given window W remains live (`s.armedArmID == ArmID_W`), `s.active` is strictly immutable. Computing `journalConfigHash(s.active)` at (w-c) restore time while window W is live is guaranteed to yield the exact hash computed at arm time.

- Attack 2: Dominance guard per-pass current-record determination under concurrent arms or pass orderings.
  - Outcome: FAILED.
  - Rationale: `s.onDiskArmID` is updated atomically under `s.mu` on every write, delete, or load outcome. Evaluating `s.onDiskArmID` under `s.mu` at each debt's turn dynamically and accurately reflects the current on-disk record identity K. If an arm or removal completes mid-pass, the next debt's turn observes the updated `s.onDiskArmID` under `s.mu` before performing any I/O, keeping the dominance guard exact under all pass orderings.

- Attack 3: `SUPERSEDED-WHILE-UNREADABLE` in-memory marker loss across a second boot before repair.
  - Outcome: FAILED.
  - Rationale: If a daemon reboots before repair, the in-memory marker is lost. On boot 2, if confirm.json is still unreadable, `Load` re-latches. If confirm.json becomes readable on boot 2 without a new commit on boot 2, substate (ii-a) RESTART-RECOVERY-OWED holds the latch and 503 until boot 3. On boot 3, `Load` recovery runs before managers serve: `rec.GuardedHash` (from record A) is compared against `journalConfigHash(s.active)` (from active config B written by boot 1's commit). The hashes mismatch, and `recoverPendingConfirmLocked` (`store_persist.go:149-165`) stale-drops record A.

Verdict line:
PLAN-READY
