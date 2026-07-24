# Codex hostile plan-review — round 13 (plan v13 @ `19bc6c977`)

Reviewer: Codex (companion task `task-mrynd5fi-73uuip`, session
`019f9320-ce71-7f90-b03e-17caffb3d0eb`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications recorded in plan v14.

---

Fold verification:
1. PARTIAL — Tombstone-first correctly linearizes content-preserving confirmations, and the later confirmGen bump still defeats callbacks blocked on s.mu (pkg/configstore/store_commit.go:717-726,815-823,856-865). The unqualified order in docs/research/2114-nat-pool-alarm-dp-race/plan.md:864-881 is unsafe for replacement/rollback paths.
2. PARTIAL — A successful durable B overwrite satisfies A's debt, and s.mu serializes arm against retry (pkg/configstore/store_commit.go:368-397,524-550; pkg/configstore/store_persist.go:402-444). WriteConfirm failure ordering remains unspecified.
3. FOLDED — confirm.json uses direct additive JSON evolution, not the #1917 envelope (pkg/configstore/db.go:199-218,242-264); the compatibility envelope applies through writeTreeMarked, not WriteConfirm (pkg/configstore/db.go:435-450; pkg/configstore/envelope.go:111-126). An envelope bump would make old recovery parse-error and abandon genuinely pending state (pkg/configstore/store_persist.go:140-144).
4. PARTIAL — Normal legacy records compare faithfully: JSON preserves the ordered ConfigTree structure used by Format when Load migrations are no-ops (pkg/config/ast.go:10-50,124-127; pkg/config/ast_format.go:80-145; pkg/configstore/db.go:377-380; pkg/configstore/store_persist.go:65-75). The exceptional upgrade test is impossible and downgrade remains unfixed. No intermediate implementation build exists: this branch is plan-only and assigns the changes to one later PR (plan.md:7-11,665-666,765-780).
5. FOLDED — writeConfirmState is the sole production confirm-record arm (pkg/configstore/store_commit.go:524,535-550). Recovery only re-arms an existing timer (pkg/configstore/store_persist.go:249-253), while SyncApply cancels/resolves and writes no record (pkg/configstore/store.go:697-760).
6. FOLDED — ReadConfirm supplies the complete record and rejects degenerate shapes (pkg/configstore/db.go:242-281); arms, confirmations, SyncApply, rollback, recovery, and retry are serialized by s.mu (pkg/configstore/store_commit.go:368-397,736-784,856-858; pkg/configstore/store.go:642-643; pkg/configstore/store_persist.go:22-24,405-460). No arm can interleave between tombstone read and write. Resolved-first recovery is correct even after a later hash-changing commit (plan.md:896-899).

New findings:

MAJOR — The universal tombstone-first order destroys #5473 recovery intent on state-changing resolutions. SyncApply must retain the original pending record when its replacement active write fails (pkg/configstore/store.go:697-760), timeout rollback retains it until the rollback target is durable (pkg/configstore/store_commit.go:867-937), and boot recovery does likewise (pkg/configstore/store_persist.go:171-220). Tombstoning first would make Resolved-first recovery discard the only intent capable of reverting the still-unconfirmed disk config; the required crash behavior is explicitly tested at pkg/configstore/confirm_rollback_durable_5473_test.go:221-293. Scope tombstone-first to keep-active confirmations; replacement/rollback paths must persist their target first and retain a pending record on failure.

MAJOR — Arm supersession lacks a valid WriteConfirm failure state machine. B is armed in memory before its warning-only durable write, and the commit still succeeds when that write fails (pkg/configstore/store_commit.go:503-527,530-553). A pre-rename failure leaves A on disk, so clearing debt loses A's cleanup; a post-rename directory-sync error leaves B visible, so retaining the unkeyed delete debt lets retry delete B (pkg/fsatomic/fsatomic.go:45-79,354-366; pkg/configstore/db.go:207-218; pkg/configstore/store_persist.go:439-449). x4 covers only successful B persistence (plan.md:908-911,1532-1535). The plan needs success, pre-rename, and post-rename cases, with post-rename uncertainty converted to rewrite/fsync-B debt—not A-deletion debt.

MAJOR — x6 contradicts the plan's own hash analysis, and HashBasis fixes only readers that understand it. The plan proves a legacy raw hash containing invalid UTF-8 differs from every decoded-tree hash (plan.md:755-763), then requires that exact record to bind (plan.md:798-800,1536-1539). Legacy arm hashes the raw tree (pkg/configstore/store_commit.go:539-550), while active persistence normalizes through JSON and recovery has only the decoded tree (pkg/configstore/db.go:435-440,377-380); the lost bytes cannot be reconstructed. Conversely, a downgraded reader ignores HashBasis, interprets canonical GuardedHash using its legacy post-migration comparison, and still stale-drops a canonical record with an inactive retired leaf (pkg/configstore/db.go:262-264; pkg/configstore/store_persist.go:65-75,149-164; plan.md:788-790). Admit the irrecoverable legacy case and either preserve an old-reader-compatible hash separately or explicitly prohibit/accept downgrade during a pending window.

MINOR — The "full record" inventory is wrong. plan.md:852-856 claims preservation of Gen but omits FirstCommit; confirmRecord has FirstCommit and no Gen, while confirmGen is memory-only (pkg/configstore/db.go:169-192; pkg/configstore/store.go:168-179). x5 checks only the Deadline/PrevTree parse gate (plan.md:909-911,1534-1535; pkg/configstore/db.go:275-280); it should explicitly assert FirstCommit preservation.

MINOR — "Bounded by the new build's retry loop" is false for downgrade (plan.md:847-850). Process exit abandons that retry goroutine (pkg/configstore/store_persist.go:397-401), after which the old reader can re-arm the ignored-Resolved tombstone through its deadline.

MINOR — plan.md:843-844 says wrapEnvelope covers only active.json, but writeTreeMarked also wraps candidate and rollback files (pkg/configstore/db.go:105-149,435-450). The material conclusion that confirm.json has no compatibility envelope remains correct.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v14)

All 3 MAJOR + 3 MINOR code-verified before folding:

- M1 (scope) VERIFIED — #5473's retention semantics
  (`store.go:738-760`, `store_commit.go:867-937`,
  `store_persist.go:171-227`) make the RECORD the rollback intent on
  replacement/rollback resolutions; `confirm_rollback_durable_5473_test.go:221-293`
  pins the crash behavior. Folded as the three-class split: tombstone
  ONLY on keep-active confirmations (explicit ConfirmCommit /
  demotion); content-changing supersessions rely on the #5835
  stale-drop; replacement/rollback keeps #5473 untouched (tombstone
  explicitly forbidden there).
- M2 (failure state machine) VERIFIED — `writeConfirmState` is
  best-effort (`store_commit.go:530-535`); fsatomic's phases (temp →
  fsync → rename → dir-fsync) make pre-rename vs post-rename failure
  observably different. Folded as the IDENTITY-KEYED debt (carries
  GuardedHash+Deadline; retry acts on match, clears on mismatch —
  phase-safe with no eager arm-time clearing), which subsumes the r13
  SMR m1 / AGY nit1 success-path ordering pin; regressions
  (x4a)/(x4b)/(x4c).
- M3 (cross-version) VERIFIED — the invalid-UTF-8 legacy-upgrade case
  is impossible to bind (the plan's own M2 analysis proves the raw
  basis uncomputable from the decoded tree); folded as documented
  irrecoverable-by-construction with loud logs + x6 rewritten for
  NORMAL records (canonical == legacy when nothing diverges).
  Dual-hash evaluated and rejected (identical irrecoverable set — the
  reader-side mutation bug is not fixed by shipping the old basis).
- m1 (inventory) VERIFIED — `confirmRecord` fields are
  Deadline/PrevTree/FirstCommit/GuardedHash (`db.go:169-192`); no Gen.
  Folded (inventory corrected; x5 asserts FirstCommit).
- m2 (downgrade bound) VERIFIED — retry dies with the process; the
  bound is the record's deadline. Folded.
- m3 (wrapEnvelope scope) VERIFIED — candidate/rollback also wrapped
  (`db.go:105-149`). Folded (cite corrected; conclusion unchanged).

Verdict recorded: **NEEDS-REVISION (3 MAJOR, 3 MINOR)**.
