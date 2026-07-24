# Codex hostile plan-review — round 14 (plan v14 @ `658c0036c`)

Reviewer: Codex (companion task `task-mryo9wh2-1bdhg9`, session
`019f9338-1e35-76d0-abbd-8c648238d1ad`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications recorded in plan v15.

---

Fold verification:
1. NOT-FOLDED — #5473 replacement ordering and FirstCommit replay are sound/idempotent (pkg/configstore/store_commit.go:867-937; pkg/configstore/store_persist.go:175-220), and stale-drop really invokes durable removal (pkg/configstore/store_persist.go:159-164), but class (ii) is false for same-hash supersessions and legacy empty-GuardedHash records; factory reset is also an unlisted terminal-wipe path (pkg/configstore/factory_reset.go:252-268).
2. NOT-FOLDED — x4 works only for distinct identities with A still present, and confirmResolvePendingPersist is arm-B-safe because it is finalized before writeConfirmState (pkg/configstore/store_commit.go:437-468,503-524); GuardedHash+Deadline is not unique, and the retry omits absent/read-error durability states (pkg/configstore/db.go:297-315).
3. FOLDED — For valid UTF-8 with no Load migration, JSON preserves every Format-relevant field, including Annotation (pkg/config/ast.go:10-49,124-127; pkg/config/ast_format.go:130-143; pkg/configstore/store_persist.go:65-75). New-reader Resolved-first and old-reader unknown-field behavior are correct (plan.md:986-989; pkg/configstore/db.go:262-264).
4. FOLDED — Master has Deadline, PrevTree, FirstCommit, and GuardedHash; confirmGen is memory-only, and x5 now preserves FirstCommit plus planned HashBasis (pkg/configstore/db.go:169-192; pkg/configstore/store.go:168-179; plan.md:1004-1007).
5. NOT-FOLDED — Deadline is a rollback trigger, not a bound on the stale-record hazard: retry dies with the process, while a surviving record booted arbitrarily later after Deadline immediately rolls back (pkg/configstore/store_persist.go:397-401,171-228).
6. FOLDED — Active/candidate/rollback all use writeTreeMarked→wrapEnvelope, while WriteConfirm directly marshals/encrypts/writes JSON (pkg/configstore/db.go:105-149,199-218,435-450).

New findings:

MAJOR — The method-based class split misclassifies plain commit and SyncApply. Edits mark the candidate dirty unconditionally, and edit-away/edit-back can restore byte-identical content (pkg/configstore/store_command.go:32-37,72-77; pkg/configstore/gen_commit_5848_test.go:65-90). That dirty candidate follows normal commit, which clears the timer although the resulting GuardedHash is unchanged (pkg/configstore/store_commit.go:220-246); failed removal followed by restart therefore binds and re-arms/rolls back (pkg/configstore/store_persist.go:149-164,231-253). SyncApply can likewise produce active-identical content (pkg/configstore/store.go:645-717). Worse, legacy empty GuardedHash categorically disables mismatch detection (pkg/configstore/store_persist.go:149-159). Tombstone necessity must follow actual binding ambiguity after the replacement is durable—not the API method.

MAJOR — Identity-matching loses the post-unlink directory-fsync state. DeleteConfirm may unlink A, fail SyncDir, and leave A absent but non-durably removed; absent retries intentionally re-drive SyncDir (pkg/configstore/db.go:297-315; pkg/configstore/confirm_durable_resolution_5835_test.go:132-168). Under plan.md:939-950, an absent read cannot match A and may clear the debt; a crash can then replay A. Pin four states: matching A → act; absent → call DeleteConfirm/SyncDir; different B → clear; read error → retain and retry.

MAJOR — GuardedHash+Deadline is not a generation identity. Same-content arms share GuardedHash, Deadline is an absolute wall-clock value, and each arm merely recomputes time.Now().Add(minutes) (pkg/configstore/db.go:170-191; pkg/configstore/store_commit.go:503-524). Clock adjustment or equal resulting deadlines can make B share A's key, letting A's retry tombstone/delete live B. The only actual uniqueness token, confirmGen, is memory-only (pkg/configstore/store.go:168-179); use a persisted opaque arm ID.

MINOR — The downgrade/tombstone hazard is unbounded until durable removal or hash supersession, not bounded by Deadline. Boot before the deadline re-arms; boot after it immediately rolls back (pkg/configstore/store_persist.go:171-253).

MINOR — Factory reset is a fourth, out-of-band resolution class. It erases active state and confirm.json together under a terminal reset generation, so its no-tombstone behavior is sound, but the claimed exhaustive three-way inventory omits it (pkg/configstore/factory_reset.go:252-268; pkg/daemon/daemon_apply_reset.go:59-89).

MINOR — The promised exceptional-content "loud log" is dishonest as currently cited: it categorically attributes mismatch to a later commit/confirm, although basis incompatibility can cause it with a still-live record (pkg/configstore/store_persist.go:159-164; plan.md:842-850). The implementation plan must change that diagnostic, not only comments.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v15)

All 3 MAJOR + 3 MINOR code-verified before folding:

- M1 (scope predicate) VERIFIED — edit-away/edit-back restores
  byte-identical content with a dirty candidate
  (`store_command.go:32-37,72-77`; `gen_commit_5848_test.go:65-90`);
  legacy empty-`GuardedHash` skips the mismatch check
  (`store_persist.go:149-159`). Folded as the
  NON-IDEMPOTENT/IDEMPOTENT-REVERT split: tombstone on ALL
  confirm-type resolutions (keeps + supersessions), never on
  idempotent-revert replacements (whose lingering records are safe BY
  DESIGN), factory reset as class 0.
- M2 (post-unlink state) VERIFIED — master's retry re-drives
  `DeleteConfirm` on ABSENT precisely for the dir-fsync-owed state
  (`store_persist.go:441-443`; `db.go:297-315`). Folded as the
  four-state retry table (match → act; absent → DeleteConfirm;
  mismatch → clear; read error → retain+retry).
- M3 (identity) VERIFIED — same-content arms share `GuardedHash`;
  `Deadline` recomputed per arm (`store_commit.go:507-509`) but
  wall-clock can collide; `confirmGen` memory-only
  (`store.go:168-179`). Folded as the persisted opaque `ArmID`.
- m1 (deadline wording) VERIFIED — hazard resolves at next boot;
  after the deadline the erroneous expired-revert executes. Folded.
- m2 (factory reset) VERIFIED — `factory_reset.go:252-268`. Folded
  into the exhaustive inventory.
- m3 (diagnostic) VERIFIED — the stale-drop warn categorically says
  "a later commit/confirm superseded it"; folded as hedge-the-cause
  text in the implementation scope.

Verdict recorded: **NEEDS-REVISION (3 MAJOR, 3 MINOR)**.
