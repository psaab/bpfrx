# Claude SMR hostile plan-review — round 14 (plan v14 @ `658c0036c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r14 verifies
the v14 folds (three-class tombstone scope, identity-keyed debt,
cross-version honesty) against worktree code and mounts fresh attacks.
All line numbers re-verified (origin/master `ed6999000` + plan-doc-only
branch).

## A. Fold verification (r13 findings → v14)

### 1. Three-class scope split (Codex M1) — FOLDED

- Class (iii) verified: the #5473 retention semantics make the RECORD
  the rollback intent — SyncApply supersede (`store.go:738-760`:
  replacement-not-durable → `confirmResolvePendingPersist = true`, keep
  the record; durable → `resolveConfirmRemovalLocked`), timeout
  rollback (`store_commit.go:899-937`: same pattern at :926), boot
  recovery (`store_persist.go:196-220`: remove ONLY when the boot
  rollback's `writeActive` succeeded). `confirm_rollback_durable_5473_
  test.go:221-293` pins the crash re-drive. Tombstoning there would
  indeed destroy the intent — the v14 prohibition is correct.
- Class (ii) verified: after a content-advancing supersession, the
  lingering record's hash mismatches the active tree → the #5835
  stale-drop (`store_persist.go:159-165`) disambiguates without any
  tombstone.
- Class (i) verified as the only ambiguity: explicit ConfirmCommit and
  demotion-confirm preserve content, so the hash keeps matching and
  only the tombstone expresses the resolution durably.
- EXHAUSTIVENESS: I walked the resolve call sites —
  `clearPendingConfirmLocked` callers (ConfirmCommitAs, plain commit,
  HA sync, demotion), `PromoteRollback` (timeout),
  `recoverPendingConfirmLocked` (boot), `resolveConfirmRemovalLocked`
  (shared removal), `clearConfirmResolutionPendingLocked` (#5473
  finalize). Every path lands in exactly one class. COMPLETE.

### 2. Identity-keyed debt (Codex M2) — FOLDED

- Identity sufficiency: a nested commit-confirmed computes a FRESH
  deadline per arm (`store_commit.go:507-509`
  `time.Now().Add(minutes)`), serialized under `s.mu`, so
  (`GuardedHash`, `Deadline`) uniquely identifies a record instance;
  JSON RFC3339Nano round-trips the precision. SUFFICIENT.
- The sibling debt already has its arm-B protection on master: the
  #5473 pre-arm finalization (`store_commit.go:445-451,461-467` —
  "so the stale flag does not survive to make the degraded retry's
  heal delete E's OWN fresh record") covers
  `confirmResolvePendingPersist`; the v14 keyed debt closes the same
  race for the #5835 `confirmRemoveDegraded` — the two mechanisms are
  now consistent.
- Phase analysis (success / pre-rename / post-rename) verified against
  fsatomic's documented ordering (temp → fsync → rename → dir-fsync);
  the match→act / mismatch→clear rule is correct in all three.

### 3. Cross-version honesty (Codex M3) — FOLDED

canonical == legacy for normal records: the JSON round trip is an
identity when no invalid UTF-8 and no migration fires (verified
empirically in r12 for UTF-8; the migration no-op case is structural —
the rewrite/sanitize only fire on matching content). The
irrecoverable-by-construction admission is the honest call; the
dual-hash rejection reasoning (identical irrecoverable set) is sound.

### 4-6. Inventory / downgrade bound / wrapEnvelope cite — all FOLDED

`confirmRecord` fields verified at `db.go:169-192` (Deadline, PrevTree,
FirstCommit, GuardedHash — no Gen); retry dies with the process;
`writeTreeMarked` wraps candidate+rollback (`db.go:105-149`).

## B. Fresh attacks on the v14 delta

**Attack 1 (SUCCEEDED, MINOR m1) — the no-record-at-resolution case is
unpinned.** `writeConfirmState` is best-effort
(`store_commit.go:530-535`): an arm whose `WriteConfirm` failed leaves
NO confirm.json on disk while the in-memory window is armed. At
resolution time the read-mutate-write tombstone has nothing to mutate.
v14's text says "the tombstone is the EXISTING record read back" but
never states the no-record branch. REQUIRED pin: when no confirm.json
exists at resolution (best-effort arm failed to persist, or an earlier
cleanup already removed it), the tombstone step is a NO-OP and the
in-memory resolution proceeds exactly as today — there is nothing to
resurrect and nothing to tombstone; the absence of a record is the
safest possible state for recovery (no re-arm possible).

**Attack 2 (FAILED) — tombstoned-A blocks later record B.** A's
tombstone lingers after a failed deletion; a later
`writeConfirmState` for B overwrites confirm.json via fsatomic rename —
A's tombstone is gone, B's record is live, and B's (fresh) deadline
keeps the keyed debt identity distinct. No blocking. FAILED.

**Attack 3 (FAILED) — legacy tombstone across bases.** A new build
tombstones a legacy record: the helper preserves the legacy
`GuardedHash` and adds only `Resolved`. New-build recovery: Resolved-first
drops it before any basis compare (correct). Downgrade reader: ignores
`Resolved`, compares legacy-basis — faithful to its build. FAILED.

**Attack 4 (FAILED) — H ordering vs tombstone.** Recovery order:
Resolved check precedes the GuardedHash mismatch, the expired branch,
AND work item H — a tombstoned FirstCommit+cluster record (resolved
via demotion-confirm, deletion failed) is dropped before H can revert
it. The ordering is exactly right. FAILED.

## C. Findings

### MAJOR (0)

None. The three-class split is the correct shape (it matches the
pre-existing #5473/#5835 disambiguation structure rather than fighting
it), and the identity-keyed debt closes the last verified race class.

### MINOR (1)

**m1.** Pin the no-record-at-resolution branch: tombstone is a NO-OP
when confirm.json does not exist (best-effort arm-write failure or
prior cleanup); the in-memory resolution proceeds regardless.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — a one-branch spec pin).
A v15 containing only this pin is PLAN-READY by inspection from me.
