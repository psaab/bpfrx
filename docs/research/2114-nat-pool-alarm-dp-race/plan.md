# #2114 (residual): publish `d.dp` through one synchronized accessor — plan-of-action

- **Status**: DRAFT v20 — r19 findings folded (Codex NEEDS-REVISION
  3M/6m + SPLIT-REJECTED; AGY PLAN-READY; Claude SMR
  PLAN-READY-WITH-NITS 0M/2m — both nits folded here); pending
  convergence review r20
- **Issue**: psaab/xpf#2114 (OPEN; `bug`, `audit`)
- **Branch**: `research/2114-nat-pool-alarm-dp-race` (plan docs only — NO
  production code in `/research`)
- **Base**: origin/master @ `ed6999000`
- **Mode**: `/research` — stops at PLAN-READY. Implementation requires manual
  `/engineer 2114`.
- **Revision history**: v1 @ `1d62be758` (initial). v2 @ `61568128f` (r1:
  deleted false invariants, deleted A2, canary redesign, sampler-only scope,
  snapshot boundaries, table regeneration). v3 @ `f0c1605cd` (r2: kind-gated
  typed-nil, four-link exclusion, STRUCTURAL sampler-only via
  `CachedStatusProvider`, real-sampler barrier, untruncated table). v4 @
  `e9ac48db1` (r3: two-sided barrier, exact 134 count, RACE-1 scoped,
  all-kind nil gate, honest Option D). v5 @ `ee5f54484` (r4: RACE-3
  documented; readiness `:202` into RACE-1; residuals). v6 @ `ee270c729`
  (r5: startup-readiness gate v1 for the pre-existing vrrpMgr nil-deref /
  bootstrap-armed defects). v7 @ `5de29ed7d` (r6: gate redesigned as
  startupDone+startupOK outcome; exclusion scoped to current-version
  records after the cross-upgrade counterexample). v8 @ `9c2bc5bbd` (r7:
  `finishStartup(ok)` Once-guarded publisher; END-of-PHASE-5 linearization;
  gate-test strengthening; work item H admitted as narrow recovery guard).
  v9: r8 convergence — work item G gains a shutdown-admission fence (Codex
  M1, verified: shutdown drains applySem once and releases at
  `daemon_run_shutdown.go:50-53`, so a gate-released rollback can re-acquire
  and run the full apply against live teardown — a `stopping` flag published
  before the drain, checked by the executor under applySem), a Run-scoped
  `defer d.finishStartup(false)` for panic/unwind safety (Codex m1), and
  corrected rationales (gate-before-applySem prevents the executor holding
  applySem ACROSS its gate-wait and deadlocking the phase-4 boot apply —
  the boot does NOT hold applySem across startup, `daemon_apply.go:50-51`;
  END-of-PHASE-5 is "all server construction complete", NOT "first server
  contact" — HTTP already serves from `daemon_run.go:586-589`). Work item H
  is REDESIGNED (Codex M2 subsuming Claude SMR M1, both verified): the
  guard is a PERMANENT recovery invariant (a current-version regeneration
  chain re-creates FirstCommit+cluster records after any seeded hybrid —
  Codex M3, verified through `store_commit.go:901-907` +
  `bootstrap.go:321-334` + the runtime-keyed preflight) and its semantics
  change from keep-active/drop-record to REVERT-AT-LOAD (running the
  expired-branch FirstCommit revert body for UNEXPIRED records), because
  keep-active silently confirms an unconfirmed config — the #4577 contract
  violation both reviewers caught. Expired records keep flowing through the
  existing branch untouched. Fixture list completed for real (adds
  `bootstrap_rollback_test.go:74`, `rollback_resync_test.go:81`,
  `startup_signal_5807_test.go:118,157` — the last two need an initialized
  open gate or `close(nil)` panics). Fwdstatus deletion inventory completed
  (`var _` assertion :10, userspace wrapper :52-75, `userspaceStatusProbe`
  :83-87); §5.1 "no other package touched" corrected (work item H touches
  `pkg/configstore`).
  v10: r9 convergence — the shutdown fence is REDESIGNED as a deterministic
  double guard (Codex M1, verified: ctx cancellation starts gRPC/HTTP
  teardown immediately — `grpcapi/server.go:489-491`,
  `api/listener.go:64-72` — while `stopping` was only published in
  PHASE 7's `runShutdownSequence`, so a gate-released rollback could see
  `stopping=false` and apply against ctx-driven server teardown, incl.
  `reconcileWebManagement` at `daemon_apply.go:208`): the executor's
  under-applySem guard becomes `d.stopping.Load() || d.runCtx.Err() !=
  nil` where `runCtx` is Run's signal context stored at Run entry
  (`d.daemonCtx` is the never-cancelled parent, #5807 — context
  cancellation is synchronous, so the `Err()` check has no scheduling
  race); `runShutdownSequence` still publishes `stopping` for the
  non-ctx path (interactive CLI exit). Invariant 11 restated honestly
  (Codex M2, verified `applyCloseoutDrainTimeout = 5s` at
  `daemon_run_shutdown.go:15`): the guard orders ENTRY absolutely; an
  in-flight rollback at signal time is bounded-drain-covered and beyond
  the 5 s budget can overlap teardown exactly as on master today —
  pre-existing, admitted, not worsened. Work item H's predicate switches
  from a raw-tree scan to the AUTHORITATIVE compiled topology (Codex M3,
  verified: `ActiveConfig()` returns `s.compiled`,
  `store_format.go:55-60`; the compiler prunes `inactive:` subtrees and
  expands apply-groups before compilation, `config/compiler.go:2257-2268`
  — a raw scan false-positives on `inactive: chassis cluster` and
  false-negatives on group-inherited cluster): `rec.FirstCommit &&
  s.compiled != nil && s.compiled.Chassis.Cluster != nil` (`s.compiled`
  is set at `store_persist.go:111` before recovery at :113), plus
  apply-groups-positive and inactive-negative tests. Residuals: fence
  test gains an actual-path leg driving the real `runShutdownSequence`
  publication (pattern `daemon_shutdown_wiring_5523_test.go:113-129`);
  the two-outcomes recovery-contract docs (`store_persist.go:127-135`,
  `pkg/configstore/README.md:417-449`) join the §5.5 sweep; the
  monotonic single-use lifecycle of `stopping`/`startupDoneOnce`/
  `startupOK` is documented (Run called once per Daemon,
  `cmd/xpfd/main.go:490-507`). Claude SMR r9 nits folded: fence check
  joins the `isResetting()` early-return; the guard path gets DISTINCT
  journal/slog text from the expired branch.
  v11: r10 convergence — `stopping.Store(true)` moves to the FIRST
  statement of `runShutdownSequence`, BEFORE `d.applyCancel()`
  (`daemon_run_shutdown.go:34-35`) (Codex M1, verified: "before the
  drain" left an interactive-exit admission window between shutdown
  entry and the Store; the actual-path test's injected `applyCancel`
  now asserts the flag is already raised). The executor's semaphore
  wait becomes cancellable (AGY f2): `Acquire` uses a nil-safe
  `runCtxOrBackground()` helper (mirroring `applyCancelCtx`,
  `daemon_apply.go:118-125`) and CHECKS the error — a signal mid-wait
  abandons instead of parking the goroutine on a wedged semaphore until
  systemd `TimeoutStopSec=20` reaps the process. The double guard is
  nil-safe (Codex m1 / AGY f1: `.Err()` on a nil `context.Context`
  interface panics) AND the executor fixtures initialize
  `runCtx: context.Background()`; a wiring-test leg asserts Run stores
  the signal CHILD, not the raw parent (Codex m2). The "not worsened"
  claim is narrowed (Codex m3): the gate delays an early-fired timer to
  END-of-PHASE-5, which can INCREASE overlap likelihood vs master's
  immediate dispatch — the honest claim is no longer admitted body and
  no larger worst case. Two work-item-H hardening folds: (a) the
  GuardedHash binding is captured from the ON-DISK tree BEFORE Load
  migrations (Codex M2, verified pre-existing #5835 gap:
  `rewriteRetiredDataplaneType` drops even INACTIVE retired leaves —
  `isRetiredDataplaneLeaf` has no Inactive check,
  `dataplane_retire.go:215-224` — and the sanitize pass mutates the
  tree, so `journalConfigHash(s.active)` at `store_persist.go:159`
  diverges from the commit-time hash of the raw promoted tree,
  `store_commit.go:543-549`; a current-build record carrying
  `inactive: system dataplane-type ebpf` is misclassified STALE and
  dropped, retaining the unconfirmed config — a master #4577 violation
  that also bypasses H in the recurrence state); (b) the
  bootstrapFromFile interaction is DOCUMENTED as deliberate consistency
  (Codex M3, adjudicated: H's end state is bit-identical to the
  existing expired-window path — empty tree, compiled=nil,
  everCommitted=false — and master's expired path flows into the same
  `shouldBootstrapFromFile` import, `bringup:313-334`; the seed file is
  an independent day-0 source the daemon never writes from DB state;
  on an HA node the boot class resolves NORMAL via the node-id guard,
  `bootstrap.go:243-245`, never the hybrid; SUPPRESSING the import
  would strand the node and diverge from #4577's own expired-path
  semantics — rejected, with a `loadAndBootstrapConfig` regression
  asserting no-hybrid + import parity). Docs sweep gains
  `pkg/configstore/db.go:161-168` (Codex m4).
  v12: r11 convergence — two more binding-layer defects folded (both
  verified pre-existing on master, both bypassing work item H):
  (a) RESOLUTION TOMBSTONE (Codex M1, verified: confirm paths —
  `ConfirmPendingOnDemotion` `store_commit.go:777-792` et al — confirm
  WITHOUT changing active content, so a lingering record's GuardedHash
  still matches after a failed durable removal; the retry-debt comment
  itself documents the window, `:596-608` "a restart before the
  background retry heals could resurrect a stale rollback"; recovery
  then re-arms an ALREADY-CONFIRMED window on master today — and H
  would revert it at Load, recreating the #4378 standby divergence).
  Resolution paths now write a `Resolved: true` TOMBSTONE into
  confirm.json BEFORE deletion (retry debt re-drives
  tombstone→removal); recovery treats a Resolved record exactly like
  the stale-drop (remove + return; no re-arm, no H). A crash between
  arm and tombstone-write is genuinely pending (re-arm — correct); a
  crash after the tombstone is resolved (drop — correct). Closes the
  master's re-arm-after-confirmed residual for ALL record classes, not
  just H's.
  (b) CANONICAL BINDING BASIS (Codex M2, verified: `hasControlChars`
  rejects only C0/DEL — invalid UTF-8 passes commit validation,
  `freetext.go:57-65`; the lexer preserves quoted bytes verbatim,
  `lexer.go:296+`; `json.MarshalIndent` normalizes invalid UTF-8 to
  U+FFFD, so the arm-time hash of the RAW promoted tree diverges from
  ANY decoded-tree hash — even the v11 pre-migration capture —
  stale-dropping a LIVE record on restart). The binding is re-derived
  as `canonicalConfigHash(tree) = sha256(Format(jsonRoundTrip(tree)))`
  at BOTH the arm sites (`store_commit.go:543-549`, SyncApply
  `:407-437`) and the recovery capture: the round-trip normalizes at
  arm exactly as the Load decode does. Terminology corrected (Codex
  m1): "canonical (round-tripped) decoded-tree `Format()` basis", not
  "on-disk bytes" (encryption randomizes file bytes regardless,
  `db.go:435-450`, `crypto.go:262-298`). Regression viii strengthened
  (Codex m2): arm through the PRODUCTION `CommitConfirmed` path and
  verify the persisted record against a freshly decoded
  `ReadActiveMeta` tree — hand-constructed files stay blind to
  serialization divergence.
  v13: r12 convergence — the tombstone design is hardened against four
  verified defects (three reviewers converged on the first two
  independently): (a) the envelope claim was FALSE (Claude SMR m1 = AGY
  Attack 1 = Codex M3): `WriteConfirm` uses NO #1917 envelope —
  "confirmRecord evolves via additive JSON fields"
  (`db.go:200-205`), and the real format floor
  (`EnvelopeFormatVersion`/`EnvelopeMinReaderVersion`,
  `envelope.go:111-123`) governs only `active.json`; DECIDED NOW (not
  deferred): `Resolved` and `HashBasis` are additive JSON fields per
  that contract, with documented downgrade semantics (an old reader
  ignores them: `Resolved` → re-arms — bounded by the new build's
  retry, no worse than today's delete-failure window; `HashBasis` →
  legacy-basis compare — faithful to its own build). (b) tombstone
  write is READ-MUTATE-WRITE preserving ALL record fields (Claude SMR
  m2 = AGY Attack 2): a minimal `{"resolved":true}` record would trip
  the #5637 degenerate gate (`db.go:275-281`) and wedge recovery at
  the early error return (`store_persist.go:141`) — the full-field
  tombstone passes the gate unmodified; atomicity via
  `fsatomic.WriteFileDurable`. (c) tombstone LINEARIZATION (Codex M1,
  verified `cancelPendingConfirmTimerLocked` `store_commit.go:717-726`
  resolves in memory FIRST and nils the record content): the durable
  tombstone is the resolution linearization point — order pinned:
  (1) read-mutate-write tombstone durably, (2) in-memory resolution
  (timer stop + confirmGen bump + state clear), (3) best-effort delete
  with retry; tombstone-write failure proceeds with in-memory
  resolution + debt (the residual write-fail-and-crash-before-retry
  window is documented as irreducible — making confirm
  durability-gated would invert a disk failure into a rollback, which
  is worse). (d) generation-safe removal debt (Codex M2, verified
  pre-existing: `confirmRemoveDegraded` is an unkeyed bool and the
  retry at `store_persist.go:439-444` removes WHATEVER confirm.json
  exists — a resolved-A/delete-failed → arm-B sequence lets the retry
  destroy B's genuinely-pending crash-recovery record on master
  TODAY): the arm path SUPERSEDES the debt — `writeConfirmState`
  clears `confirmRemoveDegraded` with a journal note (the overwrite
  satisfies the debt: A's record no longer exists); regression
  delete-failure→new-arm→retry→restart added. (e) VERSIONED HASH BASIS
  (Codex M4, verified: `confirmRecord` has no basis discriminator;
  upgrade-in-window with an invalid-UTF-8 record or
  downgrade-in-window with a canonical record both spuriously
  stale-drop a LIVE record): additive `HashBasis: "canonical-v1"` on
  newly armed records; recovery compares dual-basis — canonical for
  canonical records, the legacy mutated-tree comparison for legacy
  records (faithful to the arming build; the fixed basis applies only
  to new records); upgrade/downgrade window tests. (f) arm-site
  inventory corrected (Codex m1): the sole production confirm-record
  arm is `writeConfirmState` (`store_commit.go:524,535-550`);
  `SyncApply` arms NO timer (`daemon_apply_commit.go:710-713`).
  v14: r13 convergence — the tombstone's SCOPE is corrected against
  three verified defects: (a) tombstone-first is valid ONLY for
  keep-active (content-preserving) confirmations (Codex M1, verified
  against the #5473 durable-intent semantics and their tests
  `confirm_rollback_durable_5473_test.go:221-293`): for
  REPLACEMENT/ROLLBACK resolutions (timeout rollback
  `store_commit.go:867-937`, boot-recovery revert
  `store_persist.go:171-227`, SyncApply supersede `store.go:738-760`)
  the record IS the rollback intent — those paths persist their target
  first, remove the record only when the replacement is durable, retain
  it + `confirmResolvePendingPersist` debt on failure, and re-execute
  idempotently on crash; tombstoning there would destroy the only
  durable intent capable of reverting a still-unconfirmed disk config.
  For CONTENT-CHANGING supersessions (plain commit, HA sync) the #5835
  hash-mismatch stale-drop already disambiguates — no tombstone needed.
  The tombstone therefore exists precisely where resolution intent is
  otherwise unrecoverable: explicit `ConfirmCommit/ConfirmCommitAs` and
  `ConfirmPendingOnDemotion`. (b) the removal debt is IDENTITY-KEYED
  (Codex M2, subsuming SMR m1 + AGY nit1): the debt carries the
  resolved record's `GuardedHash`+`Deadline`; the retry
  tombstones+deletes ONLY on identity match and CLEARS the debt on
  mismatch — phase-safe across WriteConfirm success, pre-rename
  failure (A intact → match → act), and post-rename failure (B live →
  mismatch → clear → B kept) with NO eager arm-time clearing. (c) the
  cross-version story is stated honestly (Codex M3): for NORMAL records
  the canonical and legacy bases are IDENTICAL (round trip is identity
  when no migration/UTF-8 divergence fires), so upgrade and downgrade
  of normal records bind correctly under dual-basis; the
  exceptional-content cross-version cases (a legacy-armed invalid-UTF-8
  record upgraded; a canonical record carrying an inactive retired leaf
  downgraded) are IRRECOVERABLE-BY-CONSTRUCTION — the arming basis is
  uncomputable from the decoded tree (the bytes are lost at
  persistence) — documented with loud logs, NOT papered over (a
  dual-hash alternative was evaluated and rejected: the irrecoverable
  set is identical). Residual repairs: record inventory corrected
  (`Deadline`/`PrevTree`/`FirstCommit`/`GuardedHash` — there is NO
  `Gen` field; `confirmGen` is memory-only, `store.go:168-179`), the
  downgrade bound corrected (bounded by the record's DEADLINE, not the
  retry loop — process exit abandons the retry goroutine), the
  `wrapEnvelope` cite corrected (active/candidate/rollback files,
  never confirm.json).
  v15: r14 convergence — three final-precision folds (all verified):
  (a) the tombstone scope is re-based from API-method classes to the
  actual BINDING-AMBIGUITY predicate (Codex M1, verified: edit-away/
  edit-back restores byte-identical content while marking the candidate
  dirty — `store_command.go:32-37,72-77`,
  `gen_commit_5848_test.go:65-90` — so a "content-changing" plain
  commit can leave the record's hash MATCHING; SyncApply can likewise
  produce active-identical content; and legacy empty-`GuardedHash`
  records categorically disable the mismatch check,
  `store_persist.go:149-159`): the split is now NON-IDEMPOTENT
  confirm-type resolutions (keep-active confirms AND content-changing
  supersessions — a lingering record is NOT safe to re-arm) →
  tombstone; IDEMPOTENT-REVERT replacement resolutions (timeout
  rollback, boot-recovery revert, SyncApply supersede-with-failed-
  replacement — re-execution yields the same state BY DESIGN, which is
  why #5473 tolerates lingering records there) → NO tombstone; plus
  class 0, factory reset (terminal wipe of state+record,
  `factory_reset.go:252-268` — no tombstone, inventory completed).
  (b) the keyed-debt retry is a FOUR-STATE machine (Codex M2, verified
  the post-unlink dir-fsync state — `DeleteConfirm` can unlink A then
  fail SyncDir, and master's retry intentionally re-drives it on
  ABSENT, `db.go:297-315`, `store_persist.go:441-443`): matching A →
  tombstone+delete; ABSENT → call DeleteConfirm (finish the dir
  fsync); different B → clear; read error → retain+retry.
  (c) the debt identity is a persisted opaque `ArmID` (Codex M3,
  verified: same-content arms share `GuardedHash`, and wall-clock
  `Deadline` can collide under clock adjustment — the only true
  uniqueness token, `confirmGen`, is memory-only): additive `ArmID`
  field (crypto/rand, written at arm); the debt keys on `ArmID` alone.
  Residual repairs: the irreducible-residual wording corrected (the
  hazard is bounded by the NEXT BOOT's resolution, not the deadline —
  booted after the deadline, the lingering pending-shaped record
  executes the erroneous expired-revert; irreducible without
  durability-gated confirm); the stale-drop diagnostic text itself is
  updated to hedge the cause ("superseded OR basis-incompatible") —
  the v14 "loud log" cite misattributed it categorically
  (`store_persist.go:159-165`).
  v16: r15 convergence — the idempotence premise itself is corrected
  (Codex M1, verified and accepted over the r15 AGY/SMR sign-off): a
  replayed revert is CONFIG-STATE idempotent but NOT RUNTIME-STATE
  idempotent — the full apply deletes the XDP link pins and re-attaches
  AF_XDP (`manager_compile.go:162-172`), publishes a new
  `config_generation` that the flow cache keys on
  (`flow_cache.rs:122-139` — generation bump invalidates entries →
  cold-path churn + NAT64 fragment-association loss), reloads FRR, and
  can restart heartbeat (`daemon_apply_routing.go:203-226`,
  `daemon_apply_dataplane.go:425-436` — an HA event on a cluster
  node). Retention WITHOUT tombstone is therefore safe ONLY
  PRE-DURABILITY (the record is the rollback intent and the
  replacement has not landed — the #5473 case); the rule is
  reformulated UNIFORMLY: every removal through
  `resolveConfirmRemovalLocked` TOMBSTONES FIRST, and
  replacement/rollback paths simply never REACH removal until the
  replacement is durable — at which point the finalize
  (`clearConfirmResolutionPendingLocked`,
  `store_persist.go:414-428`) tombstones like every other path. The
  failed-SyncApply divergence is closed (Codex M2, verified: SyncApply
  supersedes the window before persistence, `store.go:697-700`; a
  crash between durable-B and removal left durable B + A's
  binding record → revert of the SYNCED config the peer holds).
  The keyed debt gains an in-memory identity and a B-durability
  precondition (Codex M3/M4, both verified: the arm stores
  `s.pendingArmID` and recovery restores it from the record when
  readable — so a resolution-time READ ERROR still constructs the
  keyed debt; and mismatch→clear now FIRST durably persists B via a
  `WriteConfirm` rewrite — a post-rename B is merely VISIBLE, not
  durable, `fsatomic.go:45-79` and master's own
  `store_commit.go:443-451` — and `writeConfirmState`'s post-rename
  failure raises a B-rewrite debt instead of only logging). Retry
  errors are TYPED (Codex m1): transient IO → retain+retry; #5637
  semantic parse-gate errors → TERMINAL degraded state (stop the
  loop, health 503, loud journal, documented manual remediation — no
  infinite capped-backoff loop, `store_persist.go:402-465`).
  Consistency: H2's intro sentence and §5.1 corrected (plain commit /
  SyncApply DO change active content; `pkg/configstore/store.go`
  added to the touch list).
  v17: r16 convergence — the debt identity model and terminal taxonomy
  are completed (four majors, all verified): (a) the identity model is
  TWO fields with explicit update rules (Codex M2, verified the
  nested-arm tangle: a nested arm updates memory BEFORE its
  best-effort write's outcome, so timer-arm identity and on-disk
  identity diverge on write failure): `s.armedArmID` (in-memory window
  identity — set at arm, cleared at resolution) and `s.onDiskArmID`
  (known-on-disk record identity — successful durable `WriteConfirm` →
  the written record's ArmID; PRE-rename failure → UNCHANGED;
  POST-rename failure → the visible record's ArmID + a rewrite debt
  keyed on that identity; readable recovery → `rec.ArmID`; unreadable
  → empty). Debts key on `onDiskArmID`; the retry never rewrites a
  record whose identity differs from it; a debt whose key went stale
  clears once the current on-disk record is durably established — the
  A/B/C supersession transitions (Codex M3) fall out of the model
  rather than being enumerated per case. (b) the post-rename finalize
  durability proof is stated honestly (Codex M1, verified master's
  post-rename branches call `clearConfirmResolutionPendingLocked`
  with only VISIBLE active config, `store_commit.go:180-196,437-452`):
  a SUCCESSFUL tombstone `WriteConfirm` is a same-directory durability
  barrier (its dir-fsync covers the earlier active.json rename too —
  documented coupling); a FAILED tombstone write retains both debts
  (persist retry for the active write + keyed removal retry), and the
  namespace-replay residual (both fail + power loss) joins the
  documented irreducible set; the new regression drives the REAL
  post-rename failure seam, not the pre-completed-WriteActive seam the
  #5473 tests use (`confirm_rollback_durable_5473_test.go:334-349`).
  (c) the terminal taxonomy covers the FULL ReadConfirm error set
  (Codex M4, verified: parse gates PLUS crypto/envelope/auth/PRF/
  master-key permanent errors, `crypto.go:307-453`) — and the degraded
  latch is set at RECOVERY read failure too (boot reconstruction:
  `store_persist.go:140-144` currently logs and returns bare, so a
  restart launders a corrupt terminal record from 503 to healthy,
  health deriving solely from in-memory flags,
  `store_persist.go:342-353`); the terminal state is PER-DEBT (the
  singleton retry loop keeps healing active-config persistence — only
  the terminally-flagged confirm-record debt stops retrying); the
  remediation/clear transition is pinned (operator removes or repairs
  confirm.json; the next clean ReadConfirm or confirmed absence clears
  the latch). Residual repairs: the "HA sync auto-confirm" misnomer
  dropped from class (i) (SyncApply's supersede is unequivocally
  replacement-class, `store.go:697-760`); the docs-sweep "confirm-type
  -scoped" corrected to uniform; the NAT64 citation corrected
  (ordinary flow caching EXCLUDES NAT64, `flow_cache.rs:385-393` —
  fragment loss follows its own generation guard,
  `nat64.rs:244-263,528-553`); the election-neutral terminal-503
  policy stated explicitly and the health response gains a distinct
  terminal confirm-record message (`pkg/api/health.go` — `pkg/api`
  IS touched after all, declaration corrected).
  v18: r17 convergence — the durability barrier is GENERALIZED from a
  finalize-time observation into a failure-phase classification on
  every replacement path (Codex M1, verified the single-failure hole:
  SyncApply treats a POST-rename `writeActive` error as plain
  not-durable and defers with NO tombstone attempt,
  `store.go:738-746`, so one post-rename failure + one restart inside
  the retry window replays B + binding-A — contradicting the x7
  closure; the same shape exists at `store_commit.go:917-937` and
  `store_persist.go:196-227`): all three replacement paths now
  classify with the existing `isPostRenameDurabilityFailure` check —
  PRE-rename → retain per #5473 (the replacement is INVISIBLE; the
  record is the rollback intent); POST-rename → immediately attempt
  the tombstone barrier via `resolveConfirmRemovalLocked` (success
  PROVES the replacement durable — that is #5473's precondition, with
  the tombstone success as the durability witness; failure retains
  BOTH debts). The #5473 tests' observable retention expectations
  change (the record now survives until the barrier, not until the
  retry heals; the invariant "survives until the replacement is
  durable" is preserved) and the m1-broadened residual is restated
  (active POST + tombstone failure in ANY phase + restart before a
  successful barrier). The identity model gains its missing edges
  (Codex M2, verified: `Load`'s absent-DB and compile-failed returns
  never `ReadConfirm`, `store_persist.go:26-42,81-113`, and a plain
  commit does not resolve an orphan record,
  `store_commit.go:678-682`): `Load` reads confirm.json on EVERY
  outcome and seeds a THREE-STATE identity (Present(ArmID) / Absent /
  unreadable→terminal latch) — "" is then only ever a PRESENT legacy
  record's value; the orphan lifecycle is documented (next successful
  boot's stale-drop or first keyed resolution). The debt-set claim is
  corrected (Codex M3 = SMR M3, independently walked: R_A + W_B + R_B
  CAN coexist inside one retry sleep): the retry carries a KEYED SET
  (multiple removal debts, one per unresolved resolution; at most one
  rewrite debt, re-keyed by the latest arm outcome) with STRICT
  per-pass convergence (complete-own-record or stale-clear once the
  current record is durable) — the false ≤1+1 bound is deleted. The
  terminal machine is repaired at both ends (Codex M4): master-key IO
  is reclassified TRANSIENT (a plain `os.ReadFile`,
  `crypto.go:446-449` — only invalid OBSERVED key length is
  deterministic-permanent), and the remediation transition gains a
  LIVE observer — the terminal latch keeps the singleton loop alive
  in PROBE-ONLY mode (read-only `ReadConfirm` per pass: a clean read
  clears the latch and re-arms the debt's retry; a confirmed absence
  clears and drops), and the boundary made MECHANICAL via a shared
  `ConfirmRecordPermanentError` sentinel (the zero-deadline and
  nil-target #5637 gates were plain `fmt.Errorf`, `db.go:271-280`). The boot transient hole is closed (Codex M5,
  verified master's pre-existing #4577 violation:
  `store_persist.go:140-145` log-and-return lets an unconfirmed
  config stand for the process's lifetime): TRANSIENT boot read
  failures retry bounded INSIDE Load and then FAIL Load (fail-closed,
  systemd `RestartSec=1` re-drives); PERMANENT-class keeps
  proceed+latch+503 (failing Load forever on a deterministically
  corrupt record would brick the node; the louder hammer —
  auto-revert on a corrupt record — is considered and rejected). The
  health channel becomes cause-bearing (Codex M6, verified
  `ConfigPersistDegradedFn func() bool` is the only signal,
  `server.go:139,338,424`): a typed snapshot accessor with a
  precedence rule (terminal confirm-record > active-persist) feeds
  the distinct /health message; the gauge stays the aggregate OR, and
  the Prometheus descriptor + option + wiring comments
  (`metrics_descriptors.go:625-630`, `server.go:132-140`,
  `daemon_run_servers.go:370-374`, `metrics.go:951-957`) join the
  sweep (Codex m2), as do the SyncApply source-doc confirmations
  (`store.go:716-717`, `pkg/configstore/README.md:663-672`, Codex m3).
  SMR r17 m1 folded: the rewrite debt is raised ONLY by the ARM path
  (`writeConfirmState`); a post-rename failure of a resolution-side
  or retry-side `WriteConfirm` retains the ORIGINATING debt.
  v19: r18 convergence — the remaining semantic pins land (Codex
  7M/5m; SMR's r18 M1/m1/m2 independently anticipated Codex M6/M5/m2;
  AGY's r18 PLAN-READY rationales for the Load routing and the probe
  re-arm were factually wrong and are corrected here): (a) the
  convergence guarantee is CONDITIONAL (Codex M1 — arms/resolutions
  are not gated by degraded persistence, `store_lock.go:9-28`, and
  transient/terminal outcomes retain entries, so "strict per-pass
  convergence" was false universally): strict reduction given
  quiescence + eventually-successful I/O; distinct keys + the single
  on-disk slot keep the live set small; health stays visible; no
  liveness claim under continuous churn. (b) SAME-KEY removal
  DOMINATES rewrite (Codex M2, verified: a pre-rename tombstone
  failure leaves PENDING-shaped B visible, so a W_B-first rewrite
  would durably restore it and a crash before R_B would re-arm an
  already-resolved window): R subsumes W for the same key; a rewrite
  never runs against a record a removal debt also keys; the
  crash-between-debts regression (x16) drives it. (c) SEEDED-ORPHAN
  resolution (Codex M3): every superseding replacement (plain commit,
  confirmed commit, SyncApply) resolves a seeded Present(record) when
  no in-memory window pends — the `clearPendingConfirmLocked`
  early-return no longer strands the orphan to bind at the next
  recovery (x17). (d) The probe's confirmed-absence re-drives the
  `DeleteConfirm` barrier before clearing (Codex M4 — an operator
  `rm` without dir-fsync + power loss replays the dirent; x18), and
  the clean-read continuation keys on LATCH ORIGIN (Codex M5 = SMR
  m1): DEBT-origin resumes the four-state retry with `onDiskArmID`
  re-seeded (NEVER a window re-arm); BOOT-origin clears + re-seeds +
  DEFERS record action to the next boot's normal recovery (no
  in-process revert/re-arm after managers serve) (x19). (e) The
  fail-closed boot path is ROUTED (Codex M6 = SMR M1, verified:
  `ErrConfigDBUnreadable` is active.json-specific and
  `classifyLoadError` maps every other error to warn+PROCEED): a new
  `ErrConfirmStateUnreadable` sentinel maps to the fail-closed class,
  the fatal diagnostic names confirm.json, `bootstrap_test.go:10-36`
  gains legs, the retry envelope is pinned (3 attempts,
  100/200/400 ms, ctx-aware sleep, clock seam), and the management
  posture is stated (Load runs in the first startup phase, before
  naming — no fxp0 stranding; the exit-vs-preserve trade is
  deliberate, systemd re-drives) (x20). (f) The health snapshot is
  THREE-field (Codex M7 — the two-field version dropped the existing
  nonterminal confirmRemoveDegraded cause from the aggregate):
  `{ActivePersistDegraded, ConfirmPersistDegraded,
  ConfirmRecordTerminal}` with precedence terminal > confirm-persist
  > active-persist; the gauge keeps the aggregate OR; the wiring is a
  Config FIELD (this server has no functional options,
  `server.go:93-140`) with a Config → NewServer plumbing test (Codex
  m5) (x21). Residual pins: the barrier outcome is STAGED (tombstone
  success + unlink failure retains only the delete-finishing debt —
  Codex m1); the probe lifecycle keeps master's plain-goroutine
  posture (Codex m3); the docs sweep gains README.md:476-540,
  pkg/api/README.md:30-36, store_commit.go:556-570,667-695,732-735,
  health.go:10-16, bootstrap.go:36-47 (Codex m4); §6's health
  "preserved exactly" claim corrected to contract-preserved,
  message-repertoire-grown.
  v20: r19 convergence — the debt machinery's last semantic pins land
  (Codex 3M/6m + SPLIT-REJECTED with reasoning recorded: H-without-H2
  would turn master's DELAYED lingering-record hazard into an
  IMMEDIATE revert-at-load for the confirmed FirstCommit+cluster
  class, so the only sound split would move H WITH H2 — the split
  question is moot if r20 converges; AGY PLAN-READY; SMR
  PLAN-READY-WITH-NITS with both nits folded here): (a) the same-key
  rule GENERALIZED to same-RECORD dominance (Codex M1, verified:
  R_A's mismatch branch rewrites the CURRENT record B, so R-before-W
  same-key ordering did not constrain R_A-vs-R_B — a stale-keyed
  removal's mismatch rewrite could still durably restore a
  pending-shaped record before its own removal ran): while ANY
  R-kind debt keys the current record K, NO other write of K runs
  (no W-kind rewrite, no stale-keyed mismatch rewrite); R_K's
  tombstone is the universal barrier; x16 gains the R_A-first crash
  leg. (b) DEBT-KIND SPLIT (Codex M2, verified: the v19 continuation
  processed rewrite debts with removal semantics — tombstoning a
  LIVE window's record or abandoning its recovery file): R-kind runs
  the four-state removal table; W-kind runs a three-state rewrite
  table (match → rewrite durable; mismatch → supersession
  transitions; absent → restore-from-in-memory-window-state or
  stale-clear); absent-for-W is NO-OP-and-clear ONLY when a same-key
  R consumed it. (c) BOOT-origin persistent substates (Codex M3,
  verified the clear-and-defer hole: health went green with the
  record's fate unsettled, and a replacement landing DURING the
  unreadable window left the record superseded-unknown):
  RESTART-RECOVERY-OWED keeps the latch + a distinct
  restart-required 503 until reboot (never green-while-unsettled);
  SUPERSEDED-WHILE-UNREADABLE (a marker set by a durable plain
  commit/SyncApply during the latch) converts the repaired record to
  an R-kind debt. (d) Confirmed-commit orphan resolution BY
  OVERWRITE (Codex m2 — a pre-arm tombstone+delete would add two
  durable ops to the admitted recordless window): the arm's
  WriteConfirm replaces the orphan; a PRE-rename arm failure leaves
  it intact + an R-kind debt keyed A; x17 gains the leg. (e) The
  convergence MEASURE corrected (Codex m1): lexicographic
  remaining-stage per debt, eventual zero given quiescence + a
  failure-free suffix; tombstone-required dominates delete-finishing
  on merge. (f) Envelope arithmetic pinned (Codex m3): initial read
  + ≤3 retries (4 reads), 100/200/400 ms delays, `LoadContext(ctx)`
  with `Load()` preserved. (g) The confirm-persist health message is
  GENERIC removal/rewrite + a debt-kind detail (Codex m4). (h) The
  sweep gains db.go:239-241 + README.md:470-473 (stale
  log-and-continue) + README.md:937-968 (three Load shapes → four,
  plus the every-outcome seeding read), the "BOTH causes" r17
  framing corrected to three (Codex m5), and the orphan premise
  documented as single-Store ownership, not the mutex (Codex m6,
  `daemon.go:1042-1053`). SMR r19 nits folded: x17's confirmed-commit
  leg (as (d)) and the Load-seeding unreadable branch names the
  class split explicitly.

---

## 1. Issue framing

#2114 originally reported that the #2079 NAT pool-utilization-alarm monitor
(PR #2109) ran a 10 s sampler goroutine reading the daemon's `d.dp` interface
field with no synchronization, racing the bootstrap-exit `d.dp = nil` write on
a dataplane-arm failure. PR #2116 (merged) closed the *narrow* monitor race
(`atomic.Pointer` monitor, `!inBootstrap()` gating, rollback discard, `-race`
tests).

The issue remains OPEN on the Paladin-audit **residual**: the field `d.dp
dataplane.RuntimeDataPlane` (`pkg/daemon/daemon.go:73`) is a plain interface
field with **5 writers** and **129 read sites** in `pkg/daemon` (134
non-comment greppable references total — exact enumeration in §5.4), most
of them unsynchronized or synchronized only by non-local reasoning. Required closeout (verbatim):

1. Publish the runtime dataplane through one synchronized/immutable accessor
   used by **every reader and writer**, or bind the sampler to an immutable
   backend and restart/replace it transactionally.
2. Eliminate direct unsynchronized reads in the forwarding-status adapters
   and the bootstrap writer.
3. Add a deterministic `-race` regression covering sampler ticks/status calls
   concurrent with bootstrap-exit `Start` failure, plus backend-type
   transition assertions.
4. Audit all remaining `d.dp` background/request readers so this does not
   become another per-monitor patch.

## 2. Honest scope/value framing

This is a correctness/robustness change, not a performance change. There are
no cycles/MB/retransmits to win back. The win, at absolute scale:

- **Eliminates a real data race on a multiword Go interface value** on three
  structurally distinct, reviewer-verified interleavings:
  - **RACE-1 (HA boot publication — no bootstrap needed, WATCHER-CHAIN
    ONLY)**: `initManagers` starts the cluster event watcher
    (`daemon_run_bringup.go:203`; the election inside `UpdateConfig` at :181
    can synchronously enqueue the initial transition) BEFORE
    `setupDataplaneAndInitialConfig` assigns `d.dp` (:448/:469/:497). The
    watcher's event-handler chain reads `d.dp` at
    `daemon_ha.go:297,299,337,348,362,367` AND — via the promotion/demotion
    blackhole paths (`daemon_ha.go:311` → `removeBlackholeRoutes`
    :1124; `:359-360` → `:1064-1066`) — at
    `daemon_ha_userspace_readiness.go:202`, with no happens-before edge to
    the assignment. **Scope note (r3/r4)**: this is the ONLY pre-publication
    reader chain on the CLUSTER side — every other HA goroutine
    (`startClusterComms` `daemon_run.go:396`, VRRP watcher :578, reconcile
    :582, session sync `daemon_ha_sync.go:790`) starts AFTER publication
    and is goroutine-start HB-safe against the boot writer. (The recovered
    confirm-timer chain is the SEPARATE pre-publication entrant documented
    as RACE-3 below.)
  - **RACE-2 (bootstrap-exit arm failure — standalone/bootstrap nodes)**:
    `runBootstrapExitStartup` writes `d.dp = nil`
    (`daemon_run_naming.go:234`) on the apply goroutine under `d.applySem`
    while the 1 Hz forwarding-status sampler, the standalone userspace
    event stream (`daemon_ha_userspace_stream.go:122`, launched when
    `d.cluster == nil` at `daemon_run.go:365`), the REST simulator probe
    (`daemon_run_servers.go:409-417`), the neighbor listener
    (`daemon_neighbor_listener.go:303-310,469-476`), and the shutdown
    final-stats/Close/Teardown reads (`daemon_run_shutdown.go:214-229` —
    applySem is released immediately at :50) read `d.dp` unsynchronized.
  - **RACE-3 (recovered commit-confirmed rollback timer vs boot
    publication — any restart inside a confirm window)**: the rollback
    executor is registered at daemon init, before any startup phase
    (`daemon_run.go:136`); phase-1 `Store.Load` re-arms a pending
    commit-confirmed timer for the remaining window — arbitrarily short
    (`store_persist.go:251`); the timer goroutine fires the executor
    (`store_commit.go:819` → `daemon_apply_commit.go:629`, taking
    `d.applySem`) and the rollback reads `d.dp` (`bootstrap.go:472-473` on
    the first-commit path; the full apply pipeline — from
    `daemon_apply_dataplane.go:98` through `daemon_apply_interfaces.go:42`,
    `daemon_apply_tail.go:491`, `daemon_apply_routing.go:367`, the
    scheduler, ipmon, policy-invalidate — on a non-nil rollback) WHILE the
    phase-3 boot writers (`daemon_run_bringup.go:448,464,469,497`) assign
    `d.dp` WITHOUT holding applySem. The executor's semaphore orders
    apply-vs-apply but never met the boot writes. Precondition is mundane:
    operator issued `commit confirmed` and rebooted inside the window.
    **r5 consequence discovery (pre-existing, worse than the field race)**:
    the same early fire can run the apply tail's unconditional
    `d.vrrpMgr.UpdateInstances` (`daemon_apply_tail.go:50`) BEFORE
    `d.vrrpMgr` is constructed (`daemon_run_bringup.go:219`) — a nil-deref
    panic on boot; and on the first-commit branch `enterBootstrapMode`
    (`bootstrap.go:322` Store(true) + `:472-473` Teardown) can land between
    the boot's `inBootstrap()` check (`daemon_run_bringup.go:490`) and its
    `d.dp.Start` (:494), arming the dataplane inside bootstrap mode. These
    are DISPATCH-ORDERING defects the atomic cell cannot fix — they need
    the startup-readiness gate (§4 A1, work item G).
  A torn `(type, data)` read can panic the daemon process (fatal on a
  firewall) or yield an inconsistent type assertion.
- **Bootstrap/cluster mutual exclusion — scoped to current-version records
  (r2 four-link proof, r6-scoped)**: HA background readers cannot coexist
  with the RACE-2 writer on configurations produced by CURRENT-version
  guards: (i) compile-failed boot ⇒ `ActiveConfig() == nil`
  (`daemon_run_bringup.go:287`); (ii) `d.cluster` is constructed EXACTLY
  ONCE, at boot, only from a non-nil active cluster config
  (`daemon_run_bringup.go:164`, documented `cluster_topology_preflight.go:117`);
  (iii) standalone↔cluster topology transitions are rejected at commit
  (`daemon_apply_commit.go:558` `clusterTopologyCommitPreflight`) and a
  peer SyncApply that would transition returns BEFORE `applyConfigLocked`
  (`daemon_apply_commit.go:364-379`); (iv) `enterBootstrapMode` fires only
  for a nil rollback target (`daemon_apply_commit.go:650-652`), which cannot
  follow a config that had a live cluster runtime.
  **r6 boundary (verified counterexample)**: link (iv) fails on the
  cross-upgrade path. A pre-topology-guard build allowed a first confirmed
  standalone→cluster commit; that commit marks the store ever-committed AT
  COMMIT (`store_commit.go:458-461`) while persisting `FirstCommit=true`;
  recovery accepts an empty legacy `GuardedHash` (`store_persist.go:149-159`)
  and reconstructs `confirmPrevCfg=nil` solely from `FirstCommit`
  (`store_persist.go:239-240`); the ACTIVE cluster config constructs
  `d.cluster` at boot (`daemon_run_bringup.go:164`); a later timeout rolls
  into `enterBootstrapMode` — which does NOT stop cluster comms
  (`bootstrap.go:321-478`). Result: bootstrap-with-live-cluster-runtime,
  and a later corrected re-exit can run the RACE-2 writer against live HA
  readers. On current-version records this cannot happen (the preflight
  rejects the topology add), and a never-committed marker cannot coexist
  with a same-version committed cluster config (r8-verified:
  `bootstrapFromFile` imports the seed config via a REAL commit —
  `daemon_apply_commit.go:57` → `store_commit.go:203` sets
  `everCommitted=true` — so a file-seeded node's first operator commit
  records `FirstCommit=false`; a truly fresh store's first cluster commit
  is preflight-rejected; factory-reset stops the daemon).
  **r8 recurrence (Codex M3, verified)**: the hybrid REGENERATES on
  current-version code once seeded. The legacy record's timeout runs
  `PromoteRollback`'s FirstCommit leg (`store_commit.go:901-907`:
  `everCommitted=false`, empty active tree) into `enterBootstrapMode`,
  which leaves `d.cluster` ALIVE; a subsequent cluster `commit confirmed`
  passes the runtime-keyed preflight (`d.cluster != nil`,
  `daemon_apply_commit.go:558`), records `firstCommit=true`, and persists
  a NEW FirstCommit+cluster record with a CURRENT nonempty GuardedHash —
  whose next recovery re-arms the same hybrid. **Consequence (r8-resolved)**:
  the plan does NOT rely on the exclusion for safety — it converts every
  reader uniformly, which covers the legacy path by construction — AND a
  PERMANENT recovery invariant ships in this PR (work item H, §4): at
  recovery, ANY FirstCommit record whose recovered active config declares
  a cluster is reverted at Load (before manager construction), terminating
  every recurrence generation at the next boot. Only the BROADER
  cluster-runtime lifecycle question (stop cluster comms in
  `enterBootstrapMode` when `d.cluster != nil`) defers to a follow-up
  issue (§10).
- **Converts non-local safety arguments into local ones.** r1-r4 review
  proved three of the plan's own non-local arguments false as stated. One
  publication mechanism makes each of the 129 read sites locally correct
  and keeps it correct when the next runtime writer appears.
- **Cost**: ~134 production references + ~110 test sites (32 selector-style
  + ~79 `Daemon{dp: ...}` keyed literals) in `pkg/daemon`; 3 files in
  `pkg/fwdstatus`; the field is package-private, zero references outside
  `pkg/daemon`. No Rust/helper/FFI changes; no packet-path changes.

*If reviewers conclude the race windows are too narrow to justify the churn,
PLAN-KILL is an acceptable verdict.*

## 3. What's already shipped / partially batched

- **PR #2116 (merged)** — the narrow monitor fix: `d.natPoolAlarm
  atomic.Pointer[natpoolalarm.Monitor]`, lifecycle helpers
  (`daemon_natpoolalarm.go:100-129`), `!inBootstrap()` gating, rollback
  stop+discard (`bootstrap.go:334`), `SetTickForTest` seam, three `-race`
  tests. Composed with, not replaced by, this plan.
- **eBPF/DPDK retirements (#1476/#1527)** — one live backend type
  (`*dpuserspace.LegacyDataPlaneAdapter`, plus test fakes). The only live
  `d.dp` transition on master is `non-nil → nil` (terminal — nothing
  re-constructs the backend; `buildRuntimeDataPlane` has exactly one caller,
  `daemon_run_bringup.go:421`).
- **#1922 bootstrap mode + #5840 topology preflight** — the RACE-2 writer
  context and the four-link exclusion above.
- **#5868** — `enterBootstrapMode` best-effort rollback; keeps the dataplane
  object (`bootstrap.go:472-475`).
- **`runtime_probes.go` probe-interface idiom** — preserved by the accessor
  shape.
- **#3970 `CachedStatus`** — the sampler's only dataplane call; no
  control-socket rate change.

## 4. Multiple path options (explicit)

### Option A1 (RECOMMENDED): atomic publication cell + uniform accessor, compiler-enforced full conversion

Replace `dp dataplane.RuntimeDataPlane` (`daemon.go:73`) with an atomic cell
and route **all** references through one accessor pair. The field's *type*
changes, so every direct `d.dp` read/write fails to compile — conversion
completeness is compiler-enforced (old selectors, aliases, keyed literals,
embedding, method values; external packages cannot name the unexported
field). r2 verification (Codex): no `package daemon_test` bypasses, no
reflective/unsafe field lookup, no alternate receiver alias, no production
method-value capture exists.

```go
// daemon.go — #2114: single synchronized publication point for the runtime
// dataplane. nil cell == no dataplane (NoDataplane mode, create failure, or
// an arm-failure teardown). The slot is immutable once stored.
type dpSlot struct{ v dataplane.RuntimeDataPlane }

dpCell atomic.Pointer[dpSlot]

// dataplane returns the currently published runtime dataplane, or nil.
// One atomic load; safe from any goroutine. Callers that nil-check AND use
// the value must load ONCE into a local (§5.3 snapshot boundaries).
func (d *Daemon) dataplane() dataplane.RuntimeDataPlane {
    if s := d.dpCell.Load(); s != nil {
        return s.v
    }
    return nil
}

// setDataplane publishes dp (nil clears). The kind-gated typed-nil check
// keeps a non-nil interface wrapping a nil value out of the cell WITHOUT
// panicking on non-nillable kinds (r2: reflect.IsNil panics on struct
// values) and WITHOUT missing non-pointer nillable kinds (r3: named
// Chan/Func/Map/Slice types can have methods — in-repo precedent
// pkg/dataplane/userspace/wire_uint8list.go:32). RuntimeDataPlane has no
// pointer-only constraint and the registry (pkg/dataplane/dataplane.go:152,
// 215) returns arbitrary constructor results unchecked.
func (d *Daemon) setDataplane(dp dataplane.RuntimeDataPlane) {
    if dp == nil {
        d.dpCell.Store(nil)
        return
    }
    v := reflect.ValueOf(dp)
    switch v.Kind() {
    case reflect.Chan, reflect.Func, reflect.Map,
        reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
        if v.IsNil() {
            d.dpCell.Store(nil)
            return
        }
    }
    d.dpCell.Store(&dpSlot{v: dp})
}
```

Why `atomic.Pointer[dpSlot]`, not `atomic.Value`: `Store(nil)` panics and
mixed concrete types panic; the cell must hold "interface or absent". One
allocation per Store (≤5 per daemon lifetime), zero per read; matches the
#2116 precedent.

**Canary redesign (explicit work item)**: the retype breaks
`TestDaemonRuntimeEntryPointUsesRuntimeDataPlane`
(`pkg/dataplane/retirement_boundary_canary_test.go:1711`, helper
:3314-3348), which requires a Daemon field NAMED `dp` of AST type exactly
`dataplane.RuntimeDataPlane`. The /engineer pass must:
  1. extend the matcher to accept the new shape — field
     `dpCell atomic.Pointer[dpSlot]` AND a `dpSlot` struct whose `v` field is
     `dataplane.RuntimeDataPlane`. `atomic.Pointer[dpSlot]` parses as
     `*ast.IndexExpr` (generic instantiation), which the canary's
     `canaryExprString` renderer (:3352-3360) does not yet handle — add
     `*ast.IndexExpr`/`*ast.IndexListExpr` support (r2 AGY MINOR 1). The
     guarded boundary is preserved semantically: the daemon's dataplane IS a
     `RuntimeDataPlane`, now published atomically.
  2. add a NEW AST canary in `pkg/daemon/daemon_dp_canary_test.go` (named
     per r2 AGY MINOR 2) forbidding direct `dpCell` /
     `.dpCell.Load()/.Store()` references outside the accessor definitions
     and the field declaration — a future package-local bypass then fails
     `make test-go`.
  3. give the redesigned canary its own unit coverage: it must FAIL on a
     raw `dp dataplane.RuntimeDataPlane` field AND on an unguarded `dpCell`
     access (both directions asserted).

**Work item G — startup-readiness gate for the rollback executor (r5 B1,
r6/r7-redesigned; closes the pre-existing dispatch-ordering defect the
RACE-3 audit exposed).** The recovered commit-confirmed timer can fire
before `initManagers` completes (§2 RACE-3), which today can nil-deref
`d.vrrpMgr` (`daemon_apply_tail.go:50` vs construction at
`daemon_run_bringup.go:219`) and can arm the dataplane inside bootstrap
mode (`daemon_run_bringup.go:490` check vs `:494` Start, interleaved with
`enterBootstrapMode`). Design — one exactly-once startup OUTCOME, published
through a `sync.Once`-guarded helper (r6: `d.daemonCtx` never cancels, so
a select on it has no live arm on a failed startup; r7: a literal
`defer close(...)` plus the success close double-closes on normal
shutdown):

```go
// daemon.go — the startup outcome. startupDone is initialized in the
// production constructor (daemon.go:1086-1108) BEFORE the executor
// registration (daemon_run.go:136) — a nil channel would hang the
// executor even on success. finishStartup publishes the outcome exactly
// once on EVERY startup-exit path; startupOK is true only for a fully
// successful startup.
startupDone     chan struct{}
startupDoneOnce sync.Once
startupOK       atomic.Bool

func (d *Daemon) finishStartup(ok bool) {
    d.startupDoneOnce.Do(func() {
        if ok {
            d.startupOK.Store(true)
        }
        close(d.startupDone)
    })
}

// executeConfirmedRollback (daemon_apply_commit.go:629) — wait for the
// outcome, then check it, THEN take applySem. Gate-before-applySem is
// mandatory (r8-corrected rationale): the executor must NOT hold applySem
// across its gate-wait — an early-fired timer would otherwise acquire the
// semaphore before the phase-4 boot apply (`daemon_apply.go:50-51`, called
// from the bringup phases) and park on the gate, the boot apply would
// block on applySem, startup would never finish, and the gate would never
// open: deadlock. (The v8 claim "the boot apply holds applySem across
// startup" was wrong — it holds it only around the phase-4 apply; the
// deadlock conclusion stands on the corrected reasoning, Codex m4a.)
<-d.startupDone
if !d.startupOK.Load() {
    slog.Warn("commit-confirmed rollback abandoned: daemon startup did not complete; " +
        "the persisted confirm record is re-resolved on the next boot (expired-window path)")
    return
}
// The semaphore wait is CANCELLABLE (r10 AGY f2, verified): an
// unbounded Acquire(context.Background()) parks the executor on a wedged
// apply through teardown until systemd TimeoutStopSec=20 reaps the
// process. runCtxOrBackground mirrors applyCancelCtx's nil-safe fallback
// (daemon_apply.go:118-125): Run's signal context when stored,
// context.Background() otherwise (unit fixtures). A signal mid-wait
// errors the Acquire and abandons.
if err := d.applySem.Acquire(d.runCtxOrBackground(), 1); err != nil {
    slog.Warn("commit-confirmed rollback abandoned: shutdown while waiting for the apply semaphore; " +
        "the persisted confirm record is re-resolved on the next boot (expired-window path)")
    return
}
defer d.applySem.Release(1)
// r8/r9/r10 shutdown-admission guard (Codex r8 M1 + r9 M1 + r10 M1, all
// verified): shutdown drains applySem ONCE and releases it
// (`daemon_run_shutdown.go:50-53`) before tearing down managers/dataplane
// (:95-230), and ctx cancellation starts gRPC/HTTP teardown IMMEDIATELY
// at signal time (`grpcapi/server.go:489-491`, `api/listener.go:64-72`) —
// BEFORE PHASE 7 ever runs. A gate-released waiter that only consulted a
// PHASE-7 flag could therefore apply against ctx-driven server teardown
// (the apply path touches the listeners, `reconcileWebManagement`
// `daemon_apply.go:208`). The guard is a DOUBLE NIL-SAFE check under
// applySem — deterministic, no scheduling race:
//   - d.runCtx: Run's SIGNAL context stored on the Daemon at Run entry
//     (d.daemonCtx is the never-cancelled parent, #5807 — checking it
//     would never fire). Context cancellation is synchronous: if the
//     signal landed before this check, Err() != nil, guaranteed. The
//     nil check is mandatory (r10 Codex m1 / AGY f1): .Err() on a nil
//     context.Context interface PANICS, and the executor fixtures
//     construct &Daemon{} directly.
//   - d.stopping: published as the FIRST statement of
//     runShutdownSequence, BEFORE d.applyCancel()
//     (`daemon_run_shutdown.go:34-35`) — r10 Codex M1: "before the
//     drain" left an interactive-exit admission window between shutdown
//     entry (applyCancel) and the Store; first-statement placement
//     closes it by construction, and the actual-path test's injected
//     applyCancel asserts the flag is already raised. Covers the non-ctx
//     path (interactive CLI exit returns from PHASE 6 WITHOUT ctx
//     cancellation, `daemon_run.go:741-748`).
// Placement (r9 SMR m1): the double guard JOINS the existing
// d.isResetting() early-return (daemon_apply_commit.go:634-638) — one
// combined admission check immediately after applySem acquisition. The
// persisted confirm record is re-resolved on the next boot's
// expired-window path, same as the startup-failure abandon.
if d.stopping.Load() || (d.runCtx != nil && d.runCtx.Err() != nil) {
    slog.Warn("commit-confirmed rollback abandoned: daemon shutdown in progress; " +
        "the persisted confirm record is re-resolved on the next boot (expired-window path)")
    return
}
```

- **`stopping` fence publication + `runCtx` storage**: `stopping` is a
  new `atomic.Bool` on `Daemon` (no general shutdown flag exists today —
  only `resetting` for factory reset, `daemon_apply_reset.go:18`), stored
  as the FIRST statement of `runShutdownSequence` (before
  `d.applyCancel()`). `runCtx` is a new field storing Run's signal
  context at Run entry — the signal CHILD derived at
  `daemon_run.go:86`, NOT the raw parent (a wiring-test leg asserts this,
  r10 Codex m2); `runCtxOrBackground()` provides the nil-safe fallback
  for direct-constructed fixtures. Run is called exactly once per Daemon
  (`cmd/xpfd/main.go:490-507`). An executor already INSIDE its critical
  section when the signal lands is covered by the existing bounded drain
  — see invariant 11 for the HONEST bound on that statement (r9 Codex
  M2, r10-narrowed). `isResetting()` stays as the factory-reset guard.
- **Monotonic single-use lifecycle (r9 Codex m3)**: `stopping`,
  `startupDone`/`startupDoneOnce`, and `startupOK` are single-use
  monotonic state — set/closed at most once per Daemon lifetime and never
  reset. The fields carry a contract comment: Run is single-use per
  Daemon (production calls it once, `cmd/xpfd/main.go:490-507`); a second
  Run would observe a stale published outcome and a raised fence.
  Document-only (no runtime guard) — matches the Daemon's existing
  single-use lifecycle for `startTime`/`daemonCtx`.
- **Panic/unwind safety (r8 Codex m1)**: a `Run`-scoped
  `defer d.finishStartup(false)` covers a panic out of a phase
  (`daemon_run.go:799` bypasses the explicit failure returns at :828/:832)
  and any future recovered unwind; `sync.Once` makes the deferred publish
  a no-op after a successful `finishStartup(true)`. (A process-fatal panic
  kills the waiters with the process; the defer makes the invariant local
  rather than argued.)

- **Success publish**: `d.finishStartup(true)` at the linearization point —
  the END of PHASE 5 (after `startGRPCServer` returns, before PHASE 6).
  r8-corrected claim (Codex m4b): this is the point where ALL server
  CONSTRUCTION is complete — zero applies can race server construction
  (the r7 defect — the earlier before-exposure point permitted a promoted
  rollback to race gRPC's `ActiveConfig` snapshot at
  `daemon_run_servers.go:216`). It is NOT "first server contact": HTTP
  already serves from `daemon_run.go:586-589`, before gRPC construction at
  :599. Serving-path concurrency between a dispatched rollback and live
  HTTP/gRPC requests is the ORDINARY steady-state apply-vs-request kind,
  identical to any post-startup commit — not a new exposure.
- **Failure publish**: `d.finishStartup(false)` from the startup-failure
  paths — placed inside `runStartupOrAbort`'s failure handling (or its
  immediate wrapper) so BOTH the plain-phase-error return AND the
  signal-abort return reach it (existing tests drive `runStartupOrAbort`
  directly, `startup_signal_5807_test.go:131`; the publish must live where
  those paths reach it). On the signal-abort leg the publish fires BEFORE
  `teardown(err)` is invoked, bounding the waiter's lifetime (a gated
  waiter during teardown is harmless — it holds nothing — but abandoning
  early is strictly cleaner). The waiter wakes and abandons. No leak on any
  path; no context-cancellation semantics involved. Plus the Run-scoped
  `defer d.finishStartup(false)` above for panic/unwind.
- **Signal-during-PHASE-5 (r8-rewritten, r9-hardened, Codex M1×2)**: a
  rollback released by `finishStartup(true)` while a shutdown is pending
  is NOT safely "applySem-ordered" — shutdown drains applySem once and
  releases it (`daemon_run_shutdown.go:50-53`), AND ctx cancellation
  starts gRPC/HTTP teardown at signal time (`grpcapi/server.go:489-491`,
  `api/listener.go:64-72`), before PHASE 7 ever publishes a flag. The
  double guard above closes both arms: `runCtx.Err()` catches the
  signal-cancelled case synchronously; `stopping` catches the
  non-ctx interactive-exit path. The honest in-flight bound is invariant
  11.
- **Test-fixture migration (r8-completed, Codex m2 + Claude SMR m1;
  r10-extended)**: existing executor fixtures construct `Daemon` directly
  and must initialize the outcome (closed + OK): `rollback_resync_test.go:31,81`,
  `bootstrap_rollback_test.go:24,74`, `rollback_serialize_test.go:71,150,
  201,247` — v8 omitted `:81` and `:74`; both drive the executor
  (`rollback_resync_test.go:85` direct call,
  `bootstrap_rollback_test.go:82` registers + fires) and would hang on a
  nil gate until the go-test timeout. ADDITIONALLY
  `startup_signal_5807_test.go:118,157` construct bare `&Daemon{}` and
  drive `runStartupOrAbort` directly — with the failure publish inside
  that helper, a nil `startupDone` panics at `close(nil)`; these fixtures
  initialize an OPEN gate (no waiter). r10: EVERY executor fixture ALSO
  initializes `runCtx: context.Background()` (the nil-safe guard makes
  this belt-and-braces rather than load-bearing, but the fixtures should
  exercise the guard's non-nil arm); the `runCtxOrBackground()` fallback
  keeps any missed future fixture safe by construction. A nil gate must
  never silently mean "ready", an uninitialized gate must never panic
  the failure publish, and an uninitialized context must never panic the
  admission guard.
- **Contract comments**: the "acquires applySem FIRST" lock-order notes at
  `store_commit.go:327-334` and `daemon_apply_commit.go:611-628` are
  reworded for the gate-before-applySem order.
- Store-internal fallback (`performAutoRollback`, `store_commit.go:822-823`)
  is untouched — it is store-state-only, no daemon managers. (Executor
  dispatch is `store_commit.go:819-820`.)
- Scope note: small companion fix inside the same PR (~55 LoC + tests —
  gate + fence + defer),
  landed as a SEPARATE PREREQUISITE COMMIT in the same PR/stack (both r7
  reviewers) so it stays reviewable and bisectable ahead of the mechanical
  `dpCell` conversion.

**Work item H — permanent FirstCommit+cluster recovery invariant,
revert-at-Load semantics (r8-REDESIGNED; ships IN this PR).** The r6
cross-upgrade boundary AND the r8 recurrence (§2, both verified) boot a
node into live-cluster-runtime + pending first-commit-rollback, and the
timeout rolls into bootstrap-with-cluster — a live-topology hybrid the
repo's own preflight classifies as unsafe
(`cluster_topology_preflight.go:27`). The atomic cell fixes field tearing
on that path but not the lifecycle semantics. v8's guard design
(keep-active, drop record) was broken twice over in r8: (a) placed before
the expired branch it would keep an already-expired unconfirmed config
whose window lapsed during downtime — reverting is exactly what the
expired branch does safely today at Load, BEFORE any cluster manager is
constructed (Claude SMR M1); (b) even for UNEXPIRED records,
keep-active/drop-record silently converts an UNCONFIRMED config into a
permanent one — the precise failure #4577 exists to prevent ("the
operator never confirmed, so the unconfirmed config on disk must NOT
stand", `store_persist.go:172-175`; contract at
`pkg/configstore/README.md:417-449`) (Codex M2). The only rollback of
this record class that is EVER safe is the Load-time one (the cluster
runtime does not exist yet — `d.cluster` constructs in PHASE 3,
`daemon_run_bringup.go:164`), so the window resolves EARLY, at recovery,
by reverting — the operator's remaining confirm window is sacrificed for
this narrow hybrid-generating class, loudly and on purpose. Guard, at
confirm-record recovery (`recoverPendingConfirmLocked`,
`store_persist.go:136-251`), placed AFTER the GuardedHash-mismatch branch
(:159-165) AND AFTER the expired-during-downtime branch (:171-227) —
expired records keep flowing through the existing branch untouched — and
BEFORE the unexpired re-arm (:229+):

```go
// PERMANENT invariant (r8): a FirstCommit record whose recovered ACTIVE
// config declares a cluster cannot be safely rolled back post-boot: its
// rollback target is the empty bootstrap tree, and executing that
// rollback after d.cluster is constructed strands a live cluster runtime
// in bootstrap (the r6/r8 hybrid — and a subsequent re-exit REGENERATES
// a fresh FirstCommit+cluster record, §2 r8 recurrence). Re-arming is
// what produces the hybrid; keeping the unconfirmed config would
// silently confirm it (#4577). Resolve the window NOW, at the only safe
// point — Load, before manager construction — by running the SAME revert
// the expired branch's FirstCommit leg runs.
//
// Predicate on the COMPILED topology (r9 Codex M3, verified): runtime
// cluster construction keys on ActiveConfig() == s.compiled
// (store_format.go:55-60, daemon_run_bringup.go:161-164). The compiler
// prunes `inactive:` subtrees FIRST and expands apply-groups
// (config/compiler.go:2257-2268) — a RAW tree scan false-positives on
// `inactive: chassis cluster` (dormant stanza; no runtime would be
// constructed; reverting would be WRONG) and false-negatives on a
// group-inherited cluster (no literal stanza in the raw tree; the hybrid
// would proceed). s.compiled is set at store_persist.go:111 before
// recovery runs at :113 (the compile-failed path returns early at :108
// and never reaches recovery).
if rec.FirstCommit && s.compiled != nil && s.compiled.Chassis.Cluster != nil {
    // revert-at-Load: s.active = empty prevTree, s.compiled = nil,
    // persistMarkerCommitted/everCommitted = false,
    // writeActiveMarker(prevTree, false) with the #5473 durable-removal
    // debt handling, candidate reset, journal + loud warn; NO re-arm.
}
```

The implementation REUSES the expired branch's FirstCommit revert body
(:177-184 + the shared persist/removal/candidate/journal tail) — factor
it into a helper both branches call rather than duplicating it; the
guard's observable end state is identical to an expired-window recovery.
Journal/log distinguishability (r9 SMR m2): the guard path uses DISTINCT
journal detail + slog text from the expired branch's "commit-confirmed
window expired while the daemon was down" (`store_persist.go:222-227`) —
the guard fires on UNEXPIRED records, and the journal must record the
real trigger ("confirm-confirmed recovery: FirstCommit+cluster record
resolved by Load-time revert; remaining window abandoned (#2114)") rather
than a false expired-during-downtime entry.

**GuardedHash binding: canonical (round-tripped) basis (r10 Codex M2 +
r11 Codex M2 — verified PRE-EXISTING #5835 gaps, in scope because H
depends on the same binding).** TWO independent divergences between the
arm-time and recovery-time hash bases exist on master:

1. **Load migrations (r10)**: Load mutates the on-disk tree BEFORE
   recovery — `rewriteRetiredDataplaneType` (`store_persist.go:65`)
   drops retired `dataplane-type` leaves WITHOUT an Inactive check
   (`isRetiredDataplaneLeaf`, `dataplane_retire.go:215-224`), and
   `SanitizeTreeControlChars` scrubs values in place (:75-82). Recovery
   then compares `rec.GuardedHash` against `journalConfigHash(s.active)`
   computed over the MUTATED tree (:159), while the commit persisted the
   hash of the RAW promoted tree (`store_commit.go:543-549`). A
   current-build candidate carrying `inactive: system dataplane-type
   ebpf` commits cleanly (the compiler prunes inactive subtrees BEFORE
   validation, `config/compiler.go:2257-2268`), the reboot-time rewrite
   deletes the leaf, the hashes diverge, and the record is dropped as
   STALE — the unconfirmed config silently stands.
2. **Invalid UTF-8 normalization (r11)**: `hasControlChars` rejects only
   C0/DEL (`freetext.go:57-65`); the lexer preserves quoted bytes
   verbatim (`lexer.go:296+`); and `json.MarshalIndent` — the DB
   persistence format (`db.go:435-457`) — normalizes INVALID UTF-8 to
   U+FFFD. A free scalar (e.g. interface `description`) carrying a raw
   `0xff` byte commits fine, persists normalized, and the arm-time hash
   over the RAW promoted tree diverges from ANY decoded-tree hash —
   including the r10 pre-migration capture — stale-dropping a LIVE
   record on restart.

Both are master #4577 violations TODAY for every record class, and in
the r8 recurrence state both bypass this guard. Fix (same commit as H):
bind via the CANONICAL representation at BOTH ends —
`canonicalConfigHash(tree) = sha256(Format(jsonRoundTrip(tree)))` —
computed at the arm site (SOLE production arm:
`writeConfirmState`, `store_commit.go:524,535-550`, reached via
`CommitConfirmedGen`; r12 Codex m1 — `SyncApply` arms NO timer, it
cancels/resolves, `daemon_apply_commit.go:710-713`; the v12 ":407-437
SyncApply arm" citation was wrong) and at the recovery capture (Load,
over the decoded tree BEFORE migrations at `:65`/`:75`, threaded as a
parameter — the decode itself is the first round-trip leg, so the
recovery basis is already canonical; verified empirically: Go's
`json.Marshal` replaces invalid UTF-8 with U+FFFD and the decode side
normalizes identically). The arm-side round-trip normalizes invalid
UTF-8 exactly as the Load decode does; the pre-migration capture
removes the migration divergence. The migrated tree still drives
compilation and the guard's `s.compiled` predicate — only the BINDING
basis changes.
**Versioned basis (r12 Codex M4, verified)**: `confirmRecord` has no
hash-basis discriminator — only an EMPTY `GuardedHash` reads as legacy
(`db.go:182-191`, `store_persist.go:149-159`) — so an unversioned
basis change misfires across upgrades: a pre-fix binary arms a RAW-tree
hash (invalid-UTF-8 record) and the post-fix recovery's canonical
compare stale-drops a LIVE record; a post-fix canonical record read by
a downgraded binary gets the legacy mutated-tree compare and
stale-drops on an inactive retired leaf. Fix: additive
`HashBasis: "canonical-v1"` on newly armed records (per the
additive-field contract, above); recovery compares DUAL-BASIS —
`HashBasis == "canonical-v1"` → canonical compare; anything else
(legacy/empty) → the legacy mutated-tree comparison exactly as the
arming build computed it. The fixed basis applies ONLY to new records;
legacy records get faithful-to-their-build semantics.
**Cross-version truth in full (r13 Codex M3)**: for NORMAL records (no
invalid UTF-8, no migration-firing content) the canonical and legacy
bases are IDENTICAL — the round trip is an identity — so upgrade AND
downgrade of normal records bind correctly under dual-basis. The
exceptional-content cross-version cases are IRRECOVERABLE-BY-CONSTRUCTION:
a legacy-armed invalid-UTF-8 record's raw bytes are lost at persistence
(no decoded tree can reproduce the raw basis), and a downgraded reader
applying its legacy mutated-tree compare to a canonical record carrying
an inactive retired leaf hits the same information loss. Those cases
are DOCUMENTED with loud logs (the stale-drop journal already exists,
`store_persist.go:159-165`) — NOT papered over; a dual-hash alternative
(record carries BOTH bases) was evaluated and REJECTED: the
irrecoverable set is identical (the reader-side mutation bug is not
fixed by shipping the old basis), at double the binding surface. The
v13 x6 test as drafted was self-contradictory (it required an
invalid-UTF-8 legacy record to BIND — impossible by the plan's own M2
analysis); v14's x6 uses NORMAL records for both directions and
documents the exceptional cases as admitted loss.
Tests: upgrade-in-window (legacy NORMAL record → legacy compare BINDS →
no spurious stale-drop; recovery proceeds to its normal outcome) and
downgrade-shape (a canonical-basis NORMAL record unmarshalled by a
reader that ignores `HashBasis` → legacy compare binds identically —
canonical == legacy for normal content — plus a JSON fixture asserting
the additive field is inert).
Terminology (r11 Codex m1): the basis is the "canonical (round-tripped)
decoded-tree `Format()`" — NOT "on-disk bytes" (the envelope + optional
AES-GCM encryption randomizes file bytes regardless, `db.go:443-450`,
`crypto.go:262-298`). The alternative (reject invalid UTF-8 at commit
validation) is rejected: a new commit-rejection class is a behavior
change beyond this PR's scope, and the sanitize/retire migrations would
remain divergent. Regressions: (viii-strong, r11 Codex m2) arm through
the PRODUCTION `CommitConfirmed` path with a candidate carrying an
inactive retired leaf AND an invalid-UTF-8 description → verify the
persisted record's GuardedHash against a freshly decoded
`ReadActiveMeta` tree, then restart → recovery binds (NO stale-drop)
and the guard fires on its own predicate; hand-constructed fixture
files are forbidden for this regression (they stay blind to
serialization divergence).

**Work item H2 — resolution tombstone + ArmID-keyed removal debt (r11
Codex M1 + r12 Codex M1/M2/M3 + r13 Codex M1/M2/M3 + r14 Codex M1/M2/M3
+ r15 Codex M1/M2/M3/M4 + r16 Codex M1/M2/M3/M4/m1/m2/m3, Claude SMR
m1/m2 + r16 SMR m1, AGY Attacks 1/2 — all verified; in scope because
H's correctness depends on resolution identity).** Confirm-type
resolution paths (explicit confirm, demotion, plain-commit supersession)
resolve a pending window by DELETING confirm.json
(`resolveConfirmRemovalLocked`, `store_commit.go:575-590`);
replacement/rollback resolutions (timeout rollback, boot-recovery
revert, HA SyncApply supersede — `store.go:697-760`, unequivocally
replacement-class, r16 Codex m1) retain the
record as rollback intent until the replacement is durable (#5473) and
only then reach the same removal. Keep-active confirmations do not
change active content, so after a failed durable removal (retry debt
retained, `:596-608`, which itself documents "a restart before the
background retry heals could resurrect a stale rollback"), the lingering
record's GuardedHash STILL MATCHES the active tree — and even on
content-changing paths the hash can keep matching (byte-identical
edit-away/edit-back, legacy empty hash, SyncApply-identical). Recovery
cannot distinguish "window pending" from "window RESOLVED but deletion
failed". On master TODAY, recovery re-arms such a record and the timer
later rolls back an ALREADY-CONFIRMED config
(`ConfirmPendingOnDemotion`, `:777-792`, exists precisely to prevent
the #4378 standby divergence — a crash in the retry window reopens it).
For FirstCommit+cluster records, work item H would instead revert the
confirmed config AT LOAD — immediate divergence. Fix (configstore,
~80 LoC + tests), with the r12-r15-hardened mechanics:

- **SCOPE: UNIFORM tombstone-before-delete at every removal; the class
  distinction governs only WHEN removal is reached (r13-r15, final
  form after r15 Codex M1/M2 corrected the idempotence premise).**
  The idempotence premise that licensed "no tombstone on replacement
  paths" was HALF-TRUE: a replayed revert is CONFIG-STATE idempotent
  (store content, FRR running config, nft) but NOT RUNTIME-STATE
  idempotent — the full apply deletes the XDP link pins and re-attaches
  AF_XDP (`manager_compile.go:162-172`: fresh attach reinitializes the
  XSK buffer pool), publishes a new `config_generation` whose bump
  evicts generation-stamped flow-cache entries at lookup
  (`flow_cache.rs:992-999` — the stamp field is defined at :122-139;
  ordinary flow caching EXCLUDES NAT64 outright, :385-393) → cold-path
  churn, and ages out NAT64 fragment associations under their OWN
  generation guard (`nat64.rs:244-263,528-553` — #5624), reloads FRR
  (`daemon_apply_routing.go:203-226`), and can restart heartbeat
  (`daemon_apply_dataplane.go:425-436` — an HA EVENT on a cluster
  node). A lingering record's replay is therefore never free, so the
  rule is uniform: EVERY removal through `resolveConfirmRemovalLocked`
  writes the tombstone FIRST. What the classes still govern is WHEN
  removal is reached:
  (i) CONFIRM-TYPE resolutions (keep-active confirms — explicit
  `ConfirmCommit/ConfirmCommitAs`, `ConfirmPendingOnDemotion` — AND
  content-changing supersessions — plain commit):
  removal is reached immediately at resolution; tombstone-first is THE
  linearization point (the intent "the active config stands" is
  otherwise invisible in durable state).
  (ii) REPLACEMENT/ROLLBACK resolutions (timeout rollback
  `store_commit.go:867-937`, boot-recovery revert
  `store_persist.go:171-227`, SyncApply supersede `store.go:738-760`):
  the record IS the rollback intent UNTIL the replacement is durable,
  and these paths reach `resolveConfirmRemovalLocked` EITHER after the
  replacement lands durably (`clearConfirmResolutionPendingLocked`,
  `store_persist.go:414-428`, or the direct durable-success call) OR
  IMMEDIATELY on a POST-rename replacement-write failure — the
  failure-phase classification every replacement path now performs
  (r17 Codex M1): the existing `isPostRenameDurabilityFailure` check
  (`store_commit.go:181` precedent) splits writeActive failures into
  PRE-rename (the replacement is INVISIBLE — RETAIN the record per
  #5473, `confirmResolvePendingPersist` debt, NO tombstone attempt)
  and POST-rename (the replacement is VISIBLE — immediately attempt
  the tombstone barrier: a successful tombstone `WriteConfirm` PROVES
  the replacement durable, which is exactly #5473's precondition, so
  the finalize proceeds; a failed attempt retains BOTH debts —
  `persistDegraded` for the active write + the keyed removal debt).
  Pre-v18 the paths treated a post-rename failure as plain
  not-durable and deferred with no tombstone attempt
  (`store.go:738-746`, `store_commit.go:917-937`,
  `store_persist.go:196-227`), leaving a SINGLE-failure restart hole:
  one post-rename writeActive failure + one restart inside the retry
  window replays the visible replacement B next to a binding
  pending-shaped A (SyncApply-identical content, byte-identical
  edit-back, or a legacy empty hash) → re-arm → the timer reverts B →
  the #4378-class divergence r15 Codex M2 named. The classification
  closes it: the record now survives until the barrier, not until
  the retry heals — #5473's invariant "the recovery record survives
  until the replacement config is DURABLE on disk" is preserved, with
  the tombstone success as the durability WITNESS — and the #5473
  tests' observable retention expectations are updated accordingly
  (retention now only when the barrier attempt ALSO fails). The
  residual crash window is thereby shrunk to the m1-broadened
  irreducible set below. "No tombstone on replacement paths" now
  means exactly: no tombstone UNTIL the replacement is durable — or
  is PROVEN durable by the barrier the post-rename failure
  immediately triggers.
  (iii) CLASS 0 — factory reset (`factory_reset.go:252-268`): terminal
  wipe of active state AND confirm.json under a reset generation; no
  tombstone, nothing to resolve.
  Exhaustiveness (AGY r14, verified): every master resolution path
  lands in exactly one of (i)/(ii)/(iii).
- **Linearization order — UNIFORM tombstone-first at every removal
  (r12 Codex M1, r15-universalized).** Master resolves in memory first —
  `cancelPendingConfirmTimerLocked` (`store_commit.go:717-726`) stops
  the timer, bumps `confirmGen`, and NILS the in-memory record content
  — then deletes durably; a crash between leaves a matching
  pending-shaped record that recovery re-arms. At EVERY
  `resolveConfirmRemovalLocked` call site the order is pinned:
  (1) READ-MUTATE-WRITE the tombstone durably — THE resolution
  linearization point (NO-OP when no confirm.json exists — the
  best-effort arm failed to persist or an earlier cleanup removed it;
  there is nothing to resurrect and nothing to tombstone, and the
  in-memory resolution proceeds regardless — r14 SMR m1 = AGY nit1);
  (2) in-memory resolution (timer stop + confirmGen bump + state clear
  — still covering the in-flight callback race, `:717-726` +
  `PromoteRollback`'s gen check `:860`); (3) best-effort delete with
  the keyed retry below. On replacement paths the in-memory resolution
  happened at the rollback/supersede itself; the finalize performs
  (1) and (3) only (the in-memory side is long settled — the
  tombstone's job there is purely to make the already-fulfilled intent
  visible so a lingering record can never replay), and it runs EITHER
  at post-durability OR immediately on a POST-rename replacement-write
  failure (r17 Codex M1's classification — the immediate attempt is
  the durability barrier; a PRE-rename failure attempts nothing and
  retains per #5473). Tombstone-write FAILURE: proceed with the in-memory side and
  retain retry debt (re-driving tombstone→delete) — making the confirm
  itself durability-gated would invert a disk failure into a rollback
  of a confirmed config, which is strictly worse. The outcome is
  STAGED (r18 Codex m1): the durability barrier keys on the TOMBSTONE
  write alone — tombstone-success + unlink-failure means the barrier
  HELD (the replacement is durable; the record is Resolved-durable and
  can never re-arm), so what is retained is a DELETE-finishing debt
  only (the four-state table's absent/match-delete path re-driving
  `DeleteConfirm` for the directory fsync, `db.go:297-315` — NO
  re-tombstone). "Retention only when the barrier attempt fails" is
  thereby precise: the re-tombstone debt exists only for
  tombstone-write failure; the unlink-failure debt is the lighter
  delete-finishing kind. The irreducible
  residual (write-failure AND crash before retry heals) re-arms a
  resolved window — and the hazard is bounded by the NEXT BOOT's
  resolution, NOT by the record's deadline (r14 Codex m1: booted after
  the deadline, the lingering pending-shaped record executes the
  erroneous expired-revert immediately; booted BEFORE it, recovery
  merely re-arms — r15 Codex fold-4: the hazard also does not "resolve"
  pre-deadline, it detonates AT the deadline). Irreducible without
  durability-gated confirm; strictly smaller than today's window (which
  spans the entire deletion, not just the tombstone write).
- **TWO-FIELD debt identity — `armedArmID` + `onDiskArmID` (r15 Codex
  M4 + r16 Codex M2/M3, subsuming r13 SMR m1 + AGY nit1 + r16 SMR m1;
  r16 Codex M2 verified the single-field model's nested-arm tangle: an
  arm updates memory BEFORE its best-effort write's outcome —
  `writeConfirmState`, `store_commit.go:531-553` — so timer-arm identity
  and on-disk identity diverge on write failure, and a debt keyed from
  arm memory can misname the record the retry will actually find).**
  The debt identity is a persisted opaque `ArmID` (crypto/rand, additive
  field, written at arm) tracked in TWO in-memory fields with explicit
  update rules:
  (a) `s.armedArmID` — IN-MEMORY WINDOW identity: set at every arm and
  nested re-arm (`CommitConfirmedGen`, `store_commit.go:503-524`),
  restored from the record at readable recovery
  (`store_persist.go:231-253`), cleared at resolution. It names the live
  timer window, NOT the disk (r15 Codex M4: the in-memory pending state
  otherwise carries NO disk identity, `store.go:168-179`).
  (b) `s.onDiskArmID` — KNOWN-ON-DISK RECORD identity, updated ONLY by
  write outcomes and Load: a fully successful durable `WriteConfirm`
  (arm write, tombstone write, or rewrite) → the written record's ArmID;
  a PRE-rename `WriteConfirm` failure → UNCHANGED (the prior record
  stands, `fsatomic.go:45-55`); a POST-rename failure → the VISIBLE
  record's ArmID — and the REWRITE DEBT is raised ONLY by the ARM path
  (`writeConfirmState`, r17 SMR m1's pin: a post-rename failure of a
  RESOLUTION-side or RETRY-side `WriteConfirm` retains the ORIGINATING
  debt, which re-drives the same write next pass — no second debt is
  raised for the same record); Load seeding below. A LEGACY record (no
  `ArmID` field) unmarshals with `ArmID = ""`, so the empty string is a
  MATCHABLE LEGACY SENTINEL, not a third state: a debt keyed `""`
  matches the legacy record's own empty field (tombstone+delete —
  correct), and a later real arm mismatches (`"" != B.ArmID` → the
  mismatch branch — correct); only a NEWLY ARMED record ever carries a
  non-empty key.
  (c) LOAD SEEDING ON EVERY OUTCOME (r17 Codex M2, verified:
  `store_persist.go:26-42` absent-DB and `:81-113` compile-failed
  returns never `ReadConfirm` — only the success path reaches
  `recoverPendingConfirmLocked` at :113 — so "" conflated
  never-observed with the legacy sentinel, and a plain commit does NOT
  resolve an orphan record: `clearPendingConfirmLocked` returns early
  with no in-memory window, `store_commit.go:678-682`): `Load` reads
  confirm.json on EVERY outcome (absent-DB, compile-failed, success)
  and seeds a THREE-STATE identity — PRESENT(ArmID) / ABSENT /
  unreadable (the unreadable branch itself splits by class per the
  taxonomy bullet: TRANSIENT → the bounded-retry-then-fail-closed
  boot path; PERMANENT → the terminal latch) — so "" is only ever a
  PRESENT legacy record's value, never "not observed". The
  absent-DB path logs a PRESENT orphan loudly and leaves it keyed: its
  lifecycle is the next successful boot's stale-drop (GuardedHash
  mismatch) or the first keyed resolution that targets it — never a
  phantom-empty debt that would durably PRESERVE it (the r17 Codex M2
  chain: orphan A + unresolved-by-plain-commit + B-arm-pre-rename
  failure + B-resolution read error now keys the debt on A, so the
  retry MATCHES and tombstones it). SEEDED-ORPHAN RESOLUTION (r18
  Codex M3, verified the shorter unsafe path: a seeded Present(A) on
  the absent-DB path survives a superseding plain commit because
  `clearPendingConfirmLocked` early-returns with no in-memory window,
  `store_commit.go:678-682` — and a legacy empty-`GuardedHash` or
  byte-identical-content A then BINDS at the next recovery,
  `store_persist.go:149-165`, re-arming or reverting a config the
  commit already superseded): every superseding replacement that
  lands durably ALSO resolves a SEEDED Present(record) when NO
  in-memory window is pending: the record is by construction an
  orphan (its window died with the last process — the
  SINGLE-STORE-OWNERSHIP invariant, r19 Codex m6: exactly one Store
  owns the `.configdb/` directory per node, created once at
  `daemon.go:1042-1053`; the orphan premise rests on THAT ownership,
  not on `s.mu`, which serializes only within one Store), the
  replacement supersedes whatever it guarded. The MECHANICS differ
  by path (r19 Codex m2): a PLAIN COMMIT or SYNCAPPLY (no fresh
  confirm record of its own) resolves the orphan at the same
  post-durability finalize point as every other removal
  (keyed tombstone→delete); a CONFIRMED COMMIT resolves the orphan
  BY OVERWRITE — the arm's `writeConfirmState` replaces the record
  with the fresh window's (no pre-arm tombstone+delete: that would
  add two durable operations to the admitted recordless crash window
  between `writeActive` and `writeConfirmState`,
  `store_commit.go:437-468,503-524`) — and a PRE-rename arm failure
  leaves the orphan INTACT and converts it to an R-kind removal debt
  keyed A (from the seeded identity; the retry's R-kind table
  tombstones→deletes it). Regression (x17)
  drives BOTH legs: absent-DB-Load → bootstrap/plain-commit → orphan
  tombstoned+deleted (pre-fix: the orphan survives to bind), AND
  absent-DB-Load → commit-confirmed → pre-rename arm failure →
  orphan intact + R_A → retry completes the removal (no binding
  record survives).
  Debts key on `onDiskArmID`, NEVER on `armedArmID` and never on a fresh
  disk read at debt-construction time (a resolution-time READ ERROR must
  still construct the right debt, r15 Codex M4). A resolution keys its
  removal debt from `onDiskArmID` — which names the exact record the
  retry will find in every interleaving: the arm's write succeeded (key
  = the arm's ArmID), failed PRE-rename (the prior on-disk record — the
  one the retry must act on), or failed POST-rename (the visible record,
  which also carries the rewrite debt). The nested-arm counterexample
  that broke the single-field model — B arms over A, B's write fails
  PRE-rename leaving A on disk, B resolves against a read error — now
  keys the debt on A (onDiskArmID was never updated), so the retry
  MATCHES and tombstones A instead of preserving it as a phantom "newer
  mismatch" that a same-content or legacy-empty-hash replay could bind
  after restart (r16 Codex M2, closed by construction).
- **The retry's FOUR-STATE table keys on the debt's `onDiskArmID` copy
  (states from r14/r15, re-keyed).** The retry reads the CURRENT
  confirm.json and runs: (a) record present, `ArmID` MATCHES → tombstone
  (if not already) → delete; (b) record ABSENT → call `DeleteConfirm`
  again (the unlink may have landed without a durable dir sync — finish
  it, `store_persist.go:441-443`, `db.go:297-315`); (c) record present,
  `ArmID` MISMATCH (a new arm B overwrote — in ANY `WriteConfirm`
  phase) → FIRST durably persist the current record (rewrite via
  `WriteConfirm` — a post-rename record is merely VISIBLE, not durable,
  `fsatomic.go:45-79` and master's own post-rename converge comment
  `store_commit.go:443-451`) → THEN clear the stale debt (if the rewrite
  fails, RETAIN the debt — a power-loss replay is handled by recovery
  exactly as today); (d) READ ERROR → the TYPED taxonomy below. No eager
  arm-time clearing — the identity check at retry time is phase-safe by
  construction. Master's unkeyed version of this race destroys a fresh
  pending record's crash-recovery file TODAY; the keyed debt closes it.
- **The B-REWRITE debt is the SAME keyed mechanism one level down — its
  A/B/C supersession transitions fall out of the two-field model rather
  than being enumerated per case (r16 Codex M3 + SMR m1).**
  `writeConfirmState`'s POST-rename failure sets `onDiskArmID = B` and
  raises a rewrite debt keyed B (r15 Codex M3 — raised, not merely
  logged). The rewrite retry re-reads confirm.json and rewrites ONLY if
  the current record is still B (ArmID match); it NEVER rewrites a
  record whose identity differs (r16 SMR m1's pin, verbatim).
  Transitions: (i) rewrite succeeds → B durable → debt clears,
  `onDiskArmID` stays B; (ii) a later arm C lands DURABLY before the
  retry runs (the singleton sleeps OUTSIDE the store lock,
  `store_persist.go:402-405`, so C can legally supersede) →
  `onDiskArmID = C` → the retry reads C, mismatch → C is durable by its
  own successful write → B's stale debt CLEARS (a debt whose key went
  stale clears once the current on-disk record is durably established);
  (iii) C's own write fails POST-rename → the debt TRANSFERS by
  re-keying: `onDiskArmID = C`, the rewrite debt now keys C (B's key is
  stale — C's visibility supersedes it); (iv) C's write fails PRE-rename
  → `onDiskArmID` stays B and B's rewrite debt stands (B is still the
  on-disk record). Composition with the other two debts is ordered, not
  concurrent: `persistRetryLoop` (`store_persist.go:414-428`) heals
  `persistDegraded` FIRST (the active write), then
  `clearConfirmResolutionPendingLocked` finalizes the deferred removal.
  The confirm-side retry carries a KEYED DEBT SET (r17 Codex M3 = SMR
  M3: MULTIPLE R-kind debts — one per unresolved resolution — + AT
  MOST ONE W-kind debt, re-keyed by the latest arm outcome since
  `writeConfirmState` is the sole serialized arm; the v17 "≤1 removal
  + 1 rewrite" bound stays deleted — R_A + W_B + R_B can coexist
  inside one retry sleep, `store_persist.go:402-405`).
  DEBT-KIND SPLIT (r19 Codex M2, verified the v19 conflation: the
  retry and the probe continuation must NOT process a rewrite debt
  with removal semantics — tombstoning a record whose window is still
  LIVE would resolve an unconfirmed window, and DeleteConfirm-and-clear
  on an absent one would abandon the live window's crash-recovery
  file): R-kind (removal) debts run the FOUR-STATE removal table
  (match → tombstone→delete; absent → `DeleteConfirm` re-drive;
  mismatch → stale-clear once the current record is durable; read
  error → typed). W-kind (rewrite) debts run a THREE-STATE rewrite
  table: (w-a) record present, ArmID MATCHES → `WriteConfirm` the
  record durable → clear; (w-b) MISMATCH → the A/B/C supersession
  transitions above (stale-clear, or re-key on the newer post-rename
  arm); (w-c) record ABSENT → if the keyed window is still LIVE
  (in-memory `armedArmID` matches), RESTORE the record from the
  in-memory window state (the same fields `writeConfirmState` used at
  arm — deadline/`confirmPrevTree`/FirstCommit/GuardedHash/ArmID) via
  a durable `WriteConfirm`; if the window has since resolved, the debt
  is stale → clear. Absent-for-W is NO-OP-and-clear ONLY when a
  same-key R-kind debt atomically consumed W (below). MERGE semantics
  (r19 Codex m1): for the same record, tombstone-required dominates
  delete-finishing — a removal debt needing tombstone+delete and a
  removal debt needing only the delete-finish merge into the
  tombstone-required action.
  SAME-RECORD DOMINANCE (r18 Codex M2 + r19 Codex M1, which generalized
  it past the r18 same-KEY rule, verified: R_A's mismatch branch
  rewrites the CURRENT record B — so R_A running before R_B durably
  restores pending-shaped B even with R-before-W same-key ordering;
  a crash before R_B re-arms the resolved window,
  `store_persist.go:149-165,231-253`): the removal debt keyed to the
  CURRENT on-disk record dominates EVERY write of that record — while
  any R-kind debt keys the current record K, NO other write of K runs
  (no W-kind rewrite, NO mismatch-branch rewrite from a stale-keyed
  removal debt); R_K's tombstone write IS the universal durability
  barrier for K, and every stale-keyed debt (R_A, W_B superseded, or
  mismatch-waiting) clears once R_K's barrier lands. The retry
  evaluates the current-record removal FIRST; the guard is a
  membership check at each debt's turn (no sort required). The x16
  regression drives both counter-cases: W_B-first (r18) AND R_A-first
  (r19) with the crash between.
  The convergence guarantee is stated HONESTLY and with the right
  MEASURE (r18 Codex M1 + r19 Codex m1 — "every pass shrinks the set"
  was false: debts can be ADDED between passes since mutation is gated
  only by cluster read-only, `store_lock.go:9-28`, and retained
  outcomes need not shrink the set): the measure is LEXICOGRAPHIC
  per-debt remaining-stage (tombstone-pending > delete-pending >
  rewrite-pending > done), and the guarantee is: given quiescence (no
  new arms/resolutions) and a failure-free suffix, every debt's stage
  strictly decreases to done — eventual zero; under continuous churn
  the live set stays small in practice (keys are distinct per debt —
  a second resolution of the same record cannot arise while its
  removal debt pends — and the single on-disk confirm.json slot
  bounds live-action debts), per-pass work is bounded by the live
  debt count, and health stays degraded and VISIBLE the whole time.
  No liveness claim is made under adversarial continuous churn — the
  retry is a best-effort background healer, and the degraded signal
  is the contract.
- **Post-rename FINALIZE durability barrier — stated honestly (r16
  Codex M1, verified: master's post-rename commit branches call
  `clearConfirmResolutionPendingLocked` with the replacement only
  VISIBLE, not durable — `store_commit.go:180-200,437-452`, finalize at
  `store_commit.go:641-649`).** Finalizing A's removal while B is not
  yet durable is safe ONLY because the tombstone write is itself a
  durability barrier: confirm.json and active.json live in the SAME
  `.configdb/` directory, so a SUCCESSFUL tombstone `WriteConfirm`'s
  directory fsync (`db.go:207-218`, `fsatomic.go:310-369`) persists ALL
  pending namespace operations in that directory — including the earlier
  active.json rename. The barrier is PROGRAM-ORDERED: writeActive's
  rename precedes the finalize's tombstone write, so tombstone-durable
  ⟹ B-durable — exactly the precondition for A's removal to be
  #4577-safe (a replay must never find A's binding record guarding a
  config whose rename was lost). A FAILED tombstone write retains BOTH
  debts — `persistDegraded` keeps owing the active write AND the keyed
  removal debt owes tombstone→delete — and any later successful
  `WriteConfirm` on either side re-establishes the barrier. Admitted
  irreducible residual (r17 Codex m1's broadening — the v17 "both fail
  post-rename" framing was too narrow): the replacement write fails
  POST-rename AND the tombstone attempt fails in ANY phase (pre- OR
  post-rename) AND a restart/power loss lands before any retry
  completes a directory barrier — the namespace can then replay to a
  combination where A's record survives untombstoned while B's rename
  is lost (or vice versa); recovery treats that exactly as today's
  post-rename crash (re-arm or stale-drop by GuardedHash). That
  residual exists on master TODAY for the active write alone; the
  plan shrinks it to the replacement-failure ∧ barrier-failure
  intersection and states it instead of hiding it. The
  new regression (x8) drives the REAL post-rename seam — a writeActive
  whose rename lands and whose directory fsync genuinely fails — NOT
  the #5473 tests' seam, which first completes a successful durable
  `WriteActive` and only then fabricates the typed error
  (`confirm_rollback_durable_5473_test.go:334-349`, r16 Codex M1's
  test-blindness finding).
- **TYPED errors — permanent taxonomy with the CORRECT boundary,
  PER-DEBT terminal state, a LIVE probe observer, boot reconstruction,
  pinned remediation (r16 Codex M4 + r17 Codex M4/M5, subsuming r15
  Codex m1).** The retry's READ ERROR branch distinguishes TWO classes
  across the ENTIRE `ReadConfirm` error set, not just the #5637 gates:
  (a) TRANSIENT — open/read/dir errors, short reads, AND master-key IO
  (r17 Codex M4's boundary correction: `readMasterKey` is a plain
  `os.ReadFile`, `crypto.go:446-449` — a missing mount or EACCES is
  recoverable, so key-IO failures retain + retry like any other IO
  error; only an invalid OBSERVED key length, `:452,:461`, is
  deterministic); (b) PERMANENT — the #5637 semantic parse gates
  (malformed JSON, zero deadline, nil rollback target, `db.go:226-281`)
  PLUS the deterministic crypto/envelope failures (corrupt envelope,
  authentication failure, unsupported PRF, invalid observed master-key
  length, `crypto.go:307-356,366-395,409-453`) → TERMINAL for THAT
  DEBT: the confirm-record debt stops retrying (no infinite
  capped-backoff loop) while the singleton retry loop KEEPS healing
  `persistDegraded` — `persistRetryLoop` also owns active-config
  persistence (`store_persist.go:402-465`), so stopping the loop
  outright is unsafe (r16 Codex M4's per-debt correction). The
  classification is MECHANICAL, not string-matching (r16 Codex item-5
  follow-through, verified: today only the malformed-JSON path wraps
  — the zero-deadline and nil-rollback-target gates construct PLAIN
  `fmt.Errorf` values with no sentinel, `db.go:271-280`): the #5637
  gates and the deterministic crypto/envelope failures gain a shared
  `ConfirmRecordPermanentError` sentinel wrapper (`errors.As` at the
  call sites), and every `ReadConfirm` error NOT carrying it is
  transient by construction. The terminal
  latch is a distinct `confirmRecordTerminal` flag folded into
  `ConfigPersistDegraded` (`store_persist.go:342-353`), so health stays
  503 + the #1799 gauge reads 1. THE LIVE OBSERVER (r17 Codex M4,
  verified the v17 gap: the only production `ReadConfirm` is boot
  recovery, `store_persist.go:140`, and the singleton EXITS when
  neither degradation flag is set, `:405-412` — a lone terminal latch
  never cleared in-process): the terminal latch keeps the singleton
  loop ALIVE in PROBE-ONLY mode — a READ-ONLY `ReadConfirm` per pass,
  NO writes — until the latch clears, with the clear transition keyed
  on the LATCH ORIGIN (r18 Codex M5 = SMR m1, kind-split + persistent
  substates per r19 Codex M2/M3): (i) DEBT-origin latch (a
  removal/rewrite retry's read failed permanently) → a CLEAN READ
  re-seeds `onDiskArmID` from the record (the ONE identity update
  outside Load and writes — stated explicitly) and RESUMES the debt's
  retry BY KIND (r19 Codex M2: an R-kind debt resumes the four-state
  removal table — tombstone→delete, NEVER a window re-arm, which
  would roll back a confirmed config; a W-kind debt resumes the
  THREE-STATE rewrite table — rewrite-durable / supersession
  transitions / restore-or-stale — NEVER a tombstone of a live
  window's record); (ii) BOOT-origin latch (recovery's read failed —
  no timer, no debt, the record never classified) splits into TWO
  persistent substates (r19 Codex M3, verified the clear-and-defer
  hole: clearing at the clean read turns health GREEN while the
  record's fate is unsettled — a pending record can expire under a
  green light, AND a replacement that landed DURING the unreadable
  window leaves the record superseded without the store knowing):
  (ii-a) RESTART-RECOVERY-OWED (not superseded while unreadable) —
  the latch does NOT clear at the clean read; health STAYS 503 with a
  DISTINCT message ("commit-confirmed recovery record readable again;
  restart required to complete recovery") until the daemon restarts
  and the normal total order classifies the record (Resolved → drop;
  stale → stale-drop; expired → revert — the deadline keeps running,
  and an expired window reverting at restart is the #4577-correct
  outcome for a window that lapsed unconfirmed; H → guard; pending →
  re-arm). NO in-process recovery (re-running the total order after
  managers are serving could revert a config the daemon has been
  running); the journal + runbook direct the operator to restart
  promptly. (ii-b) SUPERSEDED-WHILE-UNREADABLE — a plain commit or
  SyncApply that lands durably while the BOOT latch stands sets a
  `confirmRecordSupersededDuringLatch` marker (the seeded-orphan rule
  cannot fire on an unreadable record — the seeded state is LATCH,
  not Present): the probe's clean read then converts the record to an
  R-kind removal debt (keyed from the re-seeded read — the record is
  stale by construction: its window died with the last process AND a
  newer durable config supersedes whatever it guarded), the R-kind
  table tombstones→deletes it, and the latch clears when the delete
  is durable. A CONFIRMED ABSENCE (record
  removed — observed by the probe's actual read, never assumed) does
  NOT drop an R-kind debt directly (r18 Codex M4, verified: an external
  `rm` without a directory fsync + power loss replays the dirent on
  reboot): it REACTIVATES the debt's absent-state — the retry
  re-drives `DeleteConfirm` (a no-op unlink + the directory fsync
  that supplies the barrier, `db.go:297-315`) — and only the
  successful barrier clears the latch and the debt; for a W-kind debt
  the same absence instead runs (w-c) — restore-or-stale per the
  in-memory window, since a live window's crash-recovery file must
  not be abandoned. The
  loop-exit condition gains "and no terminal latch set"; the
  probe keeps the same plain-goroutine shutdown posture as master's
  persistDegraded loop (r18 Codex m3: the worker was never joined —
  process exit abandons it; tests that construct repeated Store
  lifecycles use short probe intervals and clear latches). BOOT
  RECONSTRUCTION + the r17 Codex M5 hardening: master's recovery
  read-failure path logs and returns BARE (`store_persist.go:140-145`)
  while `Load` SUCCEEDS — a TRANSIENT boot read error silently loses
  the rollback window for the process's lifetime, a pre-existing #4577
  violation (an unconfirmed config stands with no timer, no debt, no
  retry) that v17 had enshrined. The boot path now splits by class:
  TRANSIENT → bounded retry INSIDE `Load` (before manager
  construction) with a PINNED envelope (r18 Codex m2 = SMR m2, r19
  Codex m3's arithmetic: the INITIAL read + up to 3 RETRIES — 4 reads
  total — with delays 100 ms → 200 ms → 400 ms between them, ≤ ~0.7 s
  of added boot latency plus I/O, boot-path-only — NOT the runtime
  loop's cadence), driven through a NEW `LoadContext(ctx)` variant
  (`Load()` is preserved as `LoadContext(context.Background())` —
  `store_persist.go:21-24` keeps its signature for existing callers;
  the startup phase passes its own ctx,
  `daemon_run.go:157-161`), so shutdown cancellation interrupts the
  sleeps (the sleep select-drives on ctx), plus a test seam on the
  clock, and still-failing →
  `Load` FAILS with a NEW TYPED error `ErrConfirmStateUnreadable`
  (r18 Codex M6 = SMR M1, verified the routing hole:
  `ErrConfigDBUnreadable` is explicitly active.json-specific,
  `envelope.go:11-19`, and `classifyLoadError`, `bootstrap.go:52-63`,
  maps ONLY it to fail-closed — every other error falls to
  `loadOtherError` = warn + PROCEED, `bootstrap.go:45-47` +
  `daemon_run_bringup.go:297-298`, which would silently re-open the
  never-stand hole one indirection later): `classifyLoadError` gains
  the `ErrConfirmStateUnreadable` → fail-closed mapping, the fatal
  diagnostic names CONFIRM.JSON (the existing message points at
  active.json, `daemon_run_bringup.go:280-285` — misdirecting here),
  and `bootstrap_test.go:10-36` gains the classification legs.
  Because `Load` runs in the FIRST startup phase
  (config-load-bootstrap, `daemon_run.go:157-177` — before interface
  naming, manager init, dataplane setup), the fail-closed exit does
  NOT strand fxp0 (naming never ran). The management posture is
  stated honestly: unlike `loadCompileFailed` (which deliberately
  does NOT exit to preserve management, `bootstrap.go:41-44`), the
  confirm-read fail-closed EXITS — a device whose only management is
  in-band through the dataplane requires console remediation if the
  confirm read keeps failing; failing closed is still the right
  posture (the alternative boots into a possibly-unconfirmed config —
  the security contract loses), and systemd `RestartSec=1` re-drives
  the boot into a readable disk; PERMANENT →
  proceed + set the terminal latch + 503 + runbook (failing `Load`
  forever on a deterministically corrupt record would brick the node —
  the admitted residual is "unconfirmed stands, LOUDLY, until operator
  action" for the permanent class only; the larger hammer —
  auto-revert to the last rollback archive on a corrupt record — is
  considered and REJECTED as out of scope: discarding the operator's
  active config on a corrupt confirm record is a far bigger semantic
  change than this PR carries). REMEDIATION/CLEAR transition pinned:
  the operator inspects, repairs, or removes confirm.json; the probe
  observes the clean `ReadConfirm` (continuation kinds above) or the
  confirmed absence (barrier re-drive above) and
  performs the clear in-process (no restart required for the
  debt-origin case; the boot-origin case defers record action to the
  next boot per the continuation kinds). Manual
  remediation is documented loudly in the journal and the
  `pkg/configstore/README.md` contract prose.
- **Election-neutral terminal-503 policy — stated explicitly, with a
  CAUSE-BEARING channel (r16 Codex m3 + r17 Codex M6/m2).** A permanent
  HTTP 503 from the degraded latch does NOT gate internal HA promotion:
  config-persist degradation surfaces to operators via the REST health
  endpoint AND the Prometheus gauge (`daemon_run_servers.go:370-374`,
  `api/health.go:65-71`, `api/metrics.go:951-957` — r17 Codex m2: the
  v17 "wired ONLY to REST health" was false, the same callback drives
  the gauge); cluster health annotations are DIAGNOSTIC ONLY
  and election-neutral (`pkg/cluster/readiness.go:20-24` — annotate
  health without perturbing the failover math; manual failover stays
  gated solely by `ConfigStale()`), and crash takeover bypasses the
  readiness gate by design (`pkg/cluster/election.go:427-432` — a dead
  peer means the survivor promotes immediately). The 503 exists for
  operators and load balancers, never for the cluster's own election.
  The CAUSE-BEARING CHANNEL (r17 Codex M6 + r18 Codex M7/m5, verified:
  `ConfigPersistDegradedFn func() bool` is the ONLY signal,
  `server.go:139,338,424` — the bool-only channel cannot carry the
  distinct message v17 promised, AND a two-field snapshot would DROP
  an existing cause: today's aggregate is
  `persistDegraded || confirmRemoveDegraded`,
  `store_persist.go:342-353` + `store.go:152-166` — the NONTERMINAL
  confirm-removal debt must stay visible): the store gains a typed
  snapshot accessor `ConfigPersistDegradedState()` returning THREE
  fields `{ActivePersistDegraded, ConfirmPersistDegraded,
  ConfirmRecordTerminal bool}` — ConfirmPersistDegraded covers the
  removal + rewrite debts (the H2-expanded confirmRemoveDegraded
  category) — with PRECEDENCE terminal > confirm-persist >
  active-persist: `api/health.go` renders the terminal confirm-record
  message first ("commit-confirmed recovery record is
  unreadable/corrupt; operator remediation required — see journal"),
  then a GENERIC confirm-persist message (r19 Codex m4 — the category
  covers BOTH removal and rewrite debts, and a rewrite-only failure
  risks LOSING the live window's recovery record, not resurrecting a
  stale rollback): "commit-confirmed recovery record persistence
  degraded (removal/rewrite not yet durable; retry in progress)" with
  a detail field naming the live debt kind(s),
  then the existing active-persist message (`api/health.go:65-71`). The aggregate
  `ConfigPersistDegraded()` stays the OR for the gauge (health can
  never read healthy while the gauge reads 1). The wiring is a
  `Config` FIELD, not a functional option (r18 Codex m5, verified:
  this server takes fields on `api.Config`, `server.go:93-140`, and
  existing health/metric tests inject private callbacks directly,
  `health_test.go:220-275`, `metrics_persist_degraded_test.go:25-27`):
  `ConfigPersistDegradedStateFn` joins the Config struct, the daemon
  populates BOTH callbacks (`daemon_run_servers.go:370-374` — the
  state accessor does NOT subsume the bool, which the gauge still
  consumes, `metrics.go:948-958`), and a Config → NewServer plumbing
  test pins the wiring. The Prometheus descriptor
  (`metrics_descriptors.go:625-630`), the field doc
  (`server.go:132-140`), and the wiring comment
  (`daemon_run_servers.go:370-374`) are updated to name ALL THREE
  causes (aggregate semantics), closing r17 Codex m2 + r18 Codex M7
  (`pkg/api` IS touched — §5.1 corrected).
- **Tombstone write = READ-MUTATE-WRITE, full record (r12 Claude SMR m2
  = AGY Attack 2; inventory r13-corrected).** The tombstone is the
  EXISTING record read back, `Resolved` set, rewritten via the same
  `WriteConfirm` fsatomic path — preserving `Deadline`, `PrevTree`,
  `FirstCommit`, `GuardedHash`, and `HashBasis` (r13 Codex m1:
  `confirmRecord` has NO `Gen` field — `confirmGen` is memory-only,
  `store.go:168-179`; the v13 inventory was wrong), so the #5637
  degenerate-record gate (`db.go:275-281`) passes UNMODIFIED. The
  helper mutates ONLY `Resolved` — in particular it never ADDS
  `HashBasis` to a legacy record (a downgrade reader then stays
  faithful to its own basis). A minimal `{"resolved":true}` tombstone
  is explicitly REJECTED: it trips #5637 and wedges recovery at the
  early error return (`store_persist.go:141`).
- **Additive schema fields — DECIDED, not deferred (r12 Codex M3 =
  Claude SMR m1 = AGY Attack 1).** `Resolved bool`, `HashBasis string`,
  and `ArmID string` are ADDITIVE JSON fields on `confirmRecord`, per
  the `WriteConfirm` contract comment itself: "No #1917 compatibility
  envelope is used — the file is transient recovery state, not a
  committed config, and confirmRecord evolves via additive JSON fields"
  (`db.go:200-205`). The v12 claim that the schema change "rides the
  existing envelope versioning" was FALSE — `wrapEnvelope` covers
  `active.json` AND the candidate/rollback files
  (`db.go:105-149,435-450`; r13 Codex m3) but NEVER confirm.json; the
  real format floor (`EnvelopeFormatVersion`/
  `EnvelopeMinReaderVersion`, `envelope.go:111-123`) does not apply.
  Downgrade semantics (documented, accepted): an old reader's
  `json.Unmarshal` silently IGNORES the unknown fields — `Resolved` →
  it re-arms a resolved record (master's delete-failure semantics; the
  hazard resolves at the next boot — after the deadline the erroneous
  expired-revert executes); `HashBasis` → it compares on its own legacy
  basis (faithful to its build); `ArmID` → inert (only the new build's
  keyed debt consumes it).
- **Recovery total order (AGY r12, verified; r17-extended)**: the
  `Load`-time confirm.json read happens on EVERY `Load` outcome
  (identity seeding) → read-failure class split (TRANSIENT → bounded
  retry → fail `Load`; PERMANENT → terminal latch + proceed) →
  ReadConfirm parse gate
  → `rec.Resolved` check (tombstone → drop) → GuardedHash mismatch
  (dual-basis → stale-drop) → expired (existing revert) → work item H
  (unexpired FirstCommit+cluster → revert-at-Load) → re-arm.

Regressions: (x1) demotion-confirm (confirm-type class) + injected
deletion failure + restart → recovery drops the tombstoned record (no
re-arm, no H, no rollback of the confirmed config; the #4378
`commit_confirm_demote_4378_test.go:5-17,50-72` divergence stays
closed); (x2) crash BETWEEN arm and tombstone → genuinely pending →
normal re-arm; (x2b) resolution with NO confirm.json on disk
(best-effort arm-write failure) → tombstone NO-OP, in-memory
resolution completes, no error (r14 SMR m1 = AGY nit1); (x2c)
resolution-time READ ERROR → the debt is still constructed (keyed from
`onDiskArmID`, NEVER the arm memory — r15 Codex M4 + r16 Codex M2) and
the typed-error table applies; (x3) tombstone-write failure → in-memory resolution proceeds,
keyed retry converges tombstone→delete, health degraded until healed;
(x4) four-state keyed debt: (x4a) arm-B SUCCESS → mismatch → B rewrite
already durable → A's debt cleared, B intact; (x4b) PRE-RENAME failure
(A intact) → match → A's removal completed; (x4c) POST-RENAME failure
(B visible, not durable) → mismatch → retry FIRST durably rewrites B
(`WriteConfirm`) → only then clears A's debt (B kept; if B's rewrite
fails, A's debt retained); (x4d) record ABSENT at retry (post-unlink
dir-fsync owed) → `DeleteConfirm` re-driven to finish the sync;
(x4e) READ ERROR, transient → retained, retried; (x4e') READ ERROR,
PERMANENT — the FULL taxonomy (#5637 parse gates AND
crypto/envelope/auth/PRF/master-key classes) → PER-DEBT TERMINAL: that
debt stops, the singleton loop KEEPS healing `persistDegraded`, health
503, loud journal, pinned remediation (no infinite loop, no loop
outright-stop); (x4c') B-REWRITE supersession transitions (r16 Codex
M3 + SMR m1): arm C lands DURABLY while B's rewrite debt pends → B's
stale-keyed debt CLEARS; C's POST-rename failure TRANSFERS the debt by
re-keying to C; C's PRE-rename failure leaves B's debt standing; and
the retry NEVER rewrites a record whose ArmID differs from its key;
(x4f) same-content re-arm → distinct `ArmID`s (crypto/rand) — no key
collision even with identical `GuardedHash`+`Deadline`; (x5) the
read-mutate-write helper is the ONLY tombstone producer — #5637 gate
passes unmodified and `FirstCommit`/`Deadline`/`PrevTree`/`GuardedHash`/
`HashBasis`/`ArmID` are preserved exactly (no `Gen` field exists);
(x6) HASH-BASIS cross-version: legacy NORMAL record upgrade binds;
canonical NORMAL record downgrade-shape binds (canonical == legacy for
normal content); exceptional-content cross-version cases documented
irrecoverable-by-construction (admitted loss — the stale-drop
diagnostic text is updated to hedge "superseded OR
basis-incompatible", r14 Codex m3); (x7) SCOPE regressions: a
byte-identical plain-commit supersession (edit-away/edit-back) with
injected removal failure + restart → the TOMBSTONED record is dropped
(stale-drop would have bound); a legacy empty-`GuardedHash` record
superseded + removal failure → tombstoned → dropped; REPLACEMENT-class
resolutions (timeout rollback, SyncApply supersede, boot-recovery
revert) assert the FAILURE-PHASE CLASSIFICATION (r17 Codex M1): a
PRE-rename replacement-write failure writes NO tombstone and retains
per #5473, while a POST-rename failure immediately attempts the
tombstone barrier — success finalizes (the barrier proves the
replacement durable), failure retains BOTH debts — and the
post-durability finalize (`clearConfirmResolutionPendingLocked`) DOES
tombstone before deleting, covering the r15 failed-SyncApply
divergence (durable B + lingering binding A → recovery drops A, never
reverts the synced config) — the #5473 tests' retention expectations
are UPDATED to the new observable semantics (retention only when the
barrier attempt also fails), the invariant preserved;
factory reset erases state+record with no tombstone; (x8) REAL
post-rename seam (r16 Codex M1): drive `writeActive` with a GENUINE
directory-fsync failure (the rename lands; the fsync fails — via
`fsatomic.SetAfterRenameSyncDirForTesting`, `test_seams.go:9-32`, NOT
the `modalWriteActive` fabricate-after-durable-success seam,
`confirm_rollback_durable_5473_test.go:334-349`) → the finalize's
successful tombstone `WriteConfirm` acts as the same-directory
durability barrier (no durable A-removal without a barrier write;
tombstone-durable ⟹ replacement-durable), and a tombstone-write
failure retains BOTH debts; (x9) BOOT RECONSTRUCTION (r16 Codex M4 +
r17 Codex M5): a
PERMANENT-class corrupt confirm.json at boot sets the terminal latch at
recovery — health stays 503 ACROSS the restart (no laundering via the
bare return, `store_persist.go:140-144`) — while a TRANSIENT-class boot
read error retries bounded inside `Load` and then FAILS `Load`
(fail-closed, (x13)); remediation (repair/remove + the probe's clean
`ReadConfirm` or confirmed absence, (x12)) clears the latch IN-PROCESS; (x10)
health response (r16 Codex m3): the terminal confirm-record state
renders the DISTINCT message, never "active configuration failed to
persist to disk", and the 503 remains election-neutral (no promotion
gate, crash takeover ungated); (x11) LOAD
SEEDING (r17 Codex M2): absent-DB / compile-failed / success `Load`
outcomes ALL seed the three-state identity (Present(ArmID) / Absent /
unreadable→latch) — the orphan chain (orphan A + plain commit + B
pre-rename arm failure + B resolution read error) now keys the debt
on A so the retry tombstones it, never preserves it; (x12) PROBE
OBSERVER (r17 Codex M4 + r18/r19 refinements): a terminal-latched debt
keeps the singleton ALIVE probe-only — a DEBT-origin clean read
re-seeds the identity and resumes the debt's retry BY KIND (R-kind:
tombstone→delete; W-kind: rewrite/restore) IN-PROCESS; a BOOT-origin
clean read splits into RESTART-RECOVERY-OWED (latch HELD, 503 +
restart-required message until reboot) or SUPERSEDED-WHILE-UNREADABLE
(marker set by a durable plain commit/SyncApply during the latch →
clean read converts the record to an R-kind debt); an operator
`rm` reactivates the absent-state (`DeleteConfirm` barrier for
R-kind; (w-c) restore-or-stale for W-kind) — only the barrier clears;
the loop still exits when no debt and no latch remain; (x13) BOOT
FAIL-CLOSED (r17 Codex M5): a TRANSIENT boot `ReadConfirm` failure
retries bounded inside `Load` (initial read + ≤3 retries,
100/200/400 ms, `LoadContext(ctx)`) then FAILS `Load` via
`ErrConfirmStateUnreadable` routed fail-closed (no manager
construction, systemd re-drives)
— an unconfirmed config never stands from a lost read; a
PERMANENT-class boot failure proceeds with the latch + 503;
(x14) TYPED HEALTH CHANNEL (r17 Codex M6/m2 + r18 M7 + r19 m4):
`ConfigPersistDegradedState()` carries all THREE causes; /health
renders by precedence terminal > confirm-persist (generic
removal/rewrite message + debt-kind detail) > active-persist; the
gauge stays the aggregate OR; the
descriptor/option/wiring comments name all three causes; (x15)
TAXONOMY
BOUNDARY (r17 Codex M4): master-key IO (missing mount/EACCES) →
TRANSIENT retry (no latch); invalid observed key length + envelope/
auth/PRF/parse classes → PERMANENT latch; (x16) SAME-RECORD DOMINANCE
(r18 Codex M2 + r19 Codex M1): W_B + R_B coexisting with B's tombstone
failed PRE-rename → R_B runs FIRST (tombstone barrier → delete), W_B
clears as stale — the crash-between-debts leg proves a W_B-first
implementation would durably restore the pending record and re-arm an
already-resolved window; AND the r19 generalization: R_A + R_B
coexisting → R_A's mismatch branch may NOT rewrite current B while
R_B exists (the current-record removal dominates EVERY write of that
record, from W-kind debts AND from stale-keyed mismatch branches) —
the R_A-first crash leg proves B never becomes durable before R_B;
(x17) SEEDED-ORPHAN resolution (r18 Codex M3 + r19 Codex m2):
absent-DB `Load` with Present(A) → a superseding plain commit →
the orphan tombstoned+deleted post-durability with NO in-memory
window; AND the confirmed-commit leg: the arm's `writeConfirmState`
resolves the orphan BY OVERWRITE, while a PRE-rename arm failure
leaves the orphan INTACT + an R-kind debt keyed A → the retry
completes the removal (no binding record survives); (x18) PROBE
ABSENCE BARRIER (r18 Codex M4 + r19 Codex M2): operator `rm` →
probe ENOENT reactivates the absent-state — `DeleteConfirm` re-drive
for an R-kind debt; (w-c) restore-or-stale for a W-kind debt (a live
window's recovery file is never abandoned);
only the successful directory barrier clears the latch; (x19)
CONTINUATION KINDS (r18 Codex M5 = SMR m1 + r19 Codex M2/M3):
DEBT-origin clean read → identity re-seeded + retry resumed BY KIND
(R-kind tombstone→delete, never a window re-arm; W-kind
rewrite/restore, never a tombstone of a live window); BOOT-origin →
RESTART-RECOVERY-OWED (latch HELD, 503 + restart-required message
until reboot — never green-while-unsettled) or
SUPERSEDED-WHILE-UNREADABLE (marker → R-kind debt); (x20) FAIL-CLOSED
ROUTING (r18 Codex M6 = SMR M1 + r19 Codex m3):
`ErrConfirmStateUnreadable` →
`classifyLoadError` fail-closed mapping (`bootstrap_test.go:10-36`
legs), confirm.json-named diagnostic, pinned retry envelope (initial
read + ≤3 retries, 100/200/400 ms, `LoadContext(ctx)`); (x21)
THREE-FIELD HEALTH PRECEDENCE (r18 Codex M7/m5 + r19 Codex m4): all
three causes in
the snapshot, /health precedence terminal > confirm-persist (generic
removal/rewrite message + debt-kind detail) >
active-persist, gauge aggregate OR, Config → NewServer plumbing
pinned. This closes the
master's re-arm-after-confirmed residual for the whole confirm-type
class AND the post-durability replacement finalize — the two places a
lingering record's replay is unsafe.

**bootstrapFromFile interaction — DOCUMENTED CONSISTENCY, suppression
rejected (r10 Codex M3, adjudicated).** After the guard's revert,
`ActiveConfig() == nil` + `configCompileFailed == false` ⇒
`shouldBootstrapFromFile` (`bootstrap.go:77-79`) imports the seed
`xpf.conf` via a real commit (`bringup:313-334`,
`daemon_apply_commit.go:17-60`); if the seed declares a cluster, PHASE 3
constructs `d.cluster` from it. Codex framed this as "H's revert can be
undone in the same boot". Adjudication: (a) the guard's end state is
BIT-IDENTICAL to the existing expired-during-downtime FirstCommit path
(empty tree, `compiled=nil`, `everCommitted=false`, `committed=0`
marker) — master's expired path flows into the SAME import, so this is
established #4577/#1922 recovery semantics, not a new H defect; (b) the
seed file is an independent day-0 source — the daemon NEVER writes DB
state back to `xpf.conf` (writes go to `.configdb/`, confirm.json,
rollback archives) — so the import cannot resurrect the unconfirmed DB
config, only the operator's baked seed; the unconfirmed DELTA is gone,
which is exactly the rollback contract; (c) on an HA node the boot class
resolves NORMAL via the node-id guard (`bootstrap.go:243-245`), never
bootstrap — no hybrid can arise post-guard, which is the guard's actual
safety goal; (d) SUPPRESSING the import would strand the node config-less
and diverge from the expired path — rejected. A
`loadAndBootstrapConfig`-level regression asserts both properties:
post-guard boot never enters the bootstrap-with-live-cluster hybrid, and
the file-import behavior is identical to the expired-window path
(including the loud journal trail distinguishing the two).

Tests (configstore/daemon seams, no cluster needed): (i) UNEXPIRED legacy
empty-`GuardedHash` FirstCommit+cluster record → guard fires: active
reverted to the empty tree, `everCommitted=false`, record removed (or
removal debt retained on persist failure), NO re-arm, loud log; (ii)
UNEXPIRED nonempty-hash FirstCommit+cluster record (the r8 recurrence
generation) → guard fires identically; (iii) UNEXPIRED standalone
FirstCommit record (no cluster) → normal re-arm + rollback proceeds
unchanged; (iv) EXPIRED FirstCommit+cluster record → the existing expired
branch handles it (revert to empty) and the guard does NOT double-fire
(no guard log, single journal entry) — the r8 negative case both
reviewers required; (v) recurrence test: synthesize the post-hybrid state
(`everCommitted=false`, live `d.cluster`, bootstrap mode) → a cluster
`commit confirmed` persists a fresh nonempty-hash FirstCommit record →
recovery → guard fires — proving the invariant terminates the
regeneration chain at the next boot; (vi) COMPILED-topology positive
(r9): the cluster stanza arrives ONLY via `apply-groups` (no literal
`chassis cluster` in the raw tree) → compiled config has
`Chassis.Cluster != nil` → guard FIRES; (vii) COMPILED-topology negative
(r9): the raw tree carries `inactive: chassis cluster` (pruned by the
compiler, `config/compiler.go:2257-2268`) → compiled
`Chassis.Cluster == nil` → guard does NOT fire, normal re-arm — a
raw-scan implementation false-positives on both directions and fails
these; (viii) CANONICAL-BINDING regression (r10/r11): production-armed
record with an inactive retired leaf AND an invalid-UTF-8 description →
binding holds across restart, guard fires (see the GuardedHash
paragraph); (ix) bootstrapFromFile parity regression (r10): no hybrid,
import identical to the expired path (see the bootstrapFromFile
paragraph); (x) RESOLUTION-TOMBSTONE regression (r11): demotion-confirm
+ deletion failure + restart → tombstoned record dropped, no re-arm, no
H (see work item H2). The BROADER cluster-runtime
lifecycle question (should `enterBootstrapMode` stop cluster comms when
`d.cluster != nil`) stays a follow-up issue.

**fwdstatus adapter: STRUCTURALLY sampler-only (r2 M1 — Codex's structural
argument adopted over AGY's comment-level one, per this repo's
compile-time-invariant discipline).** The sampler only ever calls
`CachedStatus` (`sampler.go:113-125`); `fwdstatus.DataPlaneAccessor`
requires only `IsLoaded`+`GetMapStats` (`builder.go:35-41`); `Build` keys
backend identity on `Status()` PRESENCE (`builder.go:116-123`) and maps a
Status error to `StateUnknown` (:219). Therefore:

- `pkg/fwdstatus` gains
  `type CachedStatusProvider interface { CachedStatus() (userspace.ProcessStatus, bool) }`;
  `NewSampler` takes it (was `DataPlaneAccessor`); `Sampler.dp` retypes;
  `sample()` calls `s.dp.CachedStatus()` directly (the per-tick type
  assertion at :113 is deleted). 3 files touched: `sampler.go`,
  `sampler_test.go` (the `countingAccessor` fake already has
  `CachedStatus`), and the daemon adapter file. `Build` untouched.
- The daemon adapter collapses to a SINGLE method, probing the CURRENT
  dataplane per call:

```go
// forwardingStatusDaemonDataPlane is the daemon's sampler-only dataplane
// adapter (#2114). It deliberately does NOT satisfy
// fwdstatus.DataPlaneAccessor and has no Status method: Build keys backend
// identity on Status() presence (builder.go:116-123), so this type can
// never be misrouted into a Build path.
type forwardingStatusDaemonDataPlane struct{ daemon *Daemon }

func (a forwardingStatusDaemonDataPlane) CachedStatus() (dpuserspace.ProcessStatus, bool) {
    if a.daemon == nil {
        return dpuserspace.ProcessStatus{}, false
    }
    return a.daemon.userspaceDataplaneCachedStatus() // one d.dataplane() load; userspaceCachedStatusProbe
}
```

- `forwardingStatusDataplane()` now returns `fwdstatus.CachedStatusProvider`
  (nil iff `d.opts.NoDataplane`); `IsLoaded`/`GetMapStats`/`Status` leave
  the daemon adapter (verified: no production callers — the gRPC/CLI Build
  paths construct their OWN adapters per request from boot-captured probes,
  `server_show_forwarding.go:21-22`, `cli_show_chassis.go:59-60`, and are
  untouched); the now-dead `userspaceDataplaneStatus()` helper is removed;
  `userspaceDataplaneCachedStatus()` is retained.
  **Deletion inventory (r8-completed, Codex m3 + Claude SMR m2 — all in
  `daemon_forwarding_status.go`)**: the
  `var _ fwdstatus.DataPlaneAccessor = forwardingStatusDaemonDataPlane{}`
  assertion (:10 — the collapsed type no longer satisfies the interface;
  the line fails to compile, forcing its removal), the
  `forwardingStatusDaemonUserspaceDataPlane` wrapper type (:52-75 — its
  `Status`/`CachedStatus` methods and the embedding), and the
  `userspaceStatusProbe` interface (:83-87 — dead once the Status-capable
  wrapper selection and `userspaceDataplaneStatus()` are gone);
  `userspaceCachedStatusProbe` is retained. A NEW unit test asserts the
  negative: the collapsed type must NOT satisfy
  `fwdstatus.DataPlaneAccessor` (plain type-assertion test — the `var _`
  idiom cannot express negation).

### Option B: eliminate the writer (write-once `d.dp` + degraded adapter)

REJECTED: its "write once before goroutines" premise is already false
(RACE-1); it re-audits every `d.dp == nil` check for nil-vs-degraded
semantics; it changes config-only-mode apply behavior
(`daemon_apply_dataplane.go:139` — blackhole-relevant); it leaves the
unsynchronized-read pattern latent for any future writer.

### Option C: `sync.RWMutex`-guarded accessor

Viable (an accessor that copies under RLock and unlocks before returning
cannot deadlock — r1 correction stands). Not chosen: #2116 `atomic.Pointer`
precedent, cheaper reads, hold-nothing-by-construction.

### Option D: immutable owner + atomic presence flag (r1 addition, REJECTED)

Write-once `dpOwner` + `atomic.Bool dpPresent`; arm failure clears only the
flag. It cleanly represents never-constructed (`owner == nil && !present`)
vs cleared (`owner != nil && !present`), and the immutable owner RETAINS
identity for post-clear introspection (`%T` logging, shutdown final stats)
— a genuine advantage over A1's nil-slot (which discards identity on clear).
Rejected on its real weaknesses: (a) two-word state requires every reader
to follow a flag-then-load ordering discipline with zero compiler help (A1
makes the correct read the only read; D would need its own canary to be
enforced); (b) the write-once premise forbids backend REPLACEMENT by
construction — a future hot-swap/re-arm with a fresh object cannot be
expressed, whereas A1 republishes trivially; (c) it deviates from the
merged #2116 `atomic.Pointer` precedent. A1 carries identity+presence in
ONE atomic word and is the simpler invariant to hold.

### Option E: per-consumer lifecycle gating

REJECTED: the per-monitor patch pattern issue requirement #4 rules out;
cannot cover request-goroutine readers.

### The honest fork

**A1 as specified, or PLAN-KILL** (accept both races as documented
known-issues and rebind only the sampler per transition — fails issue
requirements #1/#4 and leaves RACE-1 open). v1's A2 (raw field + cell
coexistence) is deleted as incoherent (r1 B3).

## 5. Concrete design (A1)

### 5.1 New/changed types

- `pkg/daemon/daemon.go`: `dpSlot`, `dpCell atomic.Pointer[dpSlot]`
  replacing `dp`; `dataplane()` / `setDataplane()` (kind-gated); field doc
  comment mirroring the `natPoolAlarm` contract (`daemon.go:211-223`).
  PLUS the work-item-G state: `startupDone chan struct{}`,
  `startupDoneOnce sync.Once`, `startupOK atomic.Bool`, `finishStartup`,
  and the r8 `stopping atomic.Bool` shutdown-admission fence.
- `pkg/daemon/daemon_forwarding_status.go`: single-method sampler-only
  adapter (§4 A1); `userspaceDataplaneStatus()` removed;
  `userspaceCachedStatusProbe` retained; `forwardingStatusDataplane()`
  returns `fwdstatus.CachedStatusProvider`, nil iff `d.opts.NoDataplane`;
  the §4 A1 deletion inventory (`var _` assertion, userspace wrapper,
  `userspaceStatusProbe`) executed.
- `pkg/daemon/daemon_apply_commit.go`: gate + fence checks in
  `executeConfirmedRollback`; lock-order contract comments reworded.
- `pkg/daemon/daemon_run.go` / `daemon_run_shutdown.go`: `finishStartup`
  publish points (END-of-PHASE-5 success; `runStartupOrAbort` failure
  handling; Run-scoped defer); `stopping` publication before the applySem
  drain.
- `pkg/configstore/store_persist.go` (r8 correction — work item H DOES
  touch configstore): the permanent FirstCommit+cluster recovery guard +
  the factored expired-branch FirstCommit revert helper + the canonical
  binding capture at Load.
- `pkg/configstore/store_commit.go` + `db.go` + `store.go` +
  `store_persist.go` (r11-r17): the `canonicalConfigHash` binding at
  the sole arm site (`writeConfirmState`); the additive `Resolved` +
  `HashBasis` + `ArmID` fields on `confirmRecord` (per the
  `db.go:200-205` additive-evolution contract — NO envelope bump, none
  exists for confirm.json); the TWO-FIELD in-memory identity
  (`armedArmID` window identity — arm stores, recovery restores,
  resolution clears; `onDiskArmID` known-on-disk identity — updated
  ONLY by write outcomes + the EVERY-outcome `Load` seeding:
  Present(ArmID) / Absent / unreadable→latch); the read-mutate-write
  tombstone helper (the ONLY tombstone producer — its output always
  passes the #5637 gate; NO-OP on absent record); the uniform
  tombstone-first ordering at EVERY `resolveConfirmRemovalLocked`
  call site; the FAILURE-PHASE CLASSIFICATION on all three replacement
  paths (PRE-rename → retain per #5473, no tombstone attempt;
  POST-rename → immediate tombstone barrier attempt via the existing
  `isPostRenameDurabilityFailure` check — success proves the
  replacement durable, failure retains both debts; the finalize's
  tombstone write doubles as the same-directory durability barrier
  for the replacement's active.json rename; factory reset untouched;
  the #5473 tests updated to the new observable retention semantics);
  the `onDiskArmID`-keyed typed-error debt SET + retry tables
  (MULTIPLE R-kind removal debts — four-state table: match →
  tombstone→delete, absent → `DeleteConfirm` re-drive, mismatch →
  stale-clear, read error → typed — + AT MOST ONE W-kind rewrite debt
  — three-state table: match → rewrite durable, mismatch → the A/B/C
  supersession transitions, absent → restore-from-window-state or
  stale-clear; SAME-RECORD dominance: the current-record removal
  dominates EVERY write of that record, from W-kind debts AND
  stale-keyed mismatch branches alike; tombstone-required dominates
  delete-finishing on merge; CONDITIONAL convergence on a
  lexicographic remaining-stage measure — eventual zero given
  quiescence + a failure-free suffix, health visible throughout; the
  PER-DEBT terminal
  state over the permanent `ReadConfirm` taxonomy — #5637 parse gates
  + envelope/auth/PRF/invalid-key-length behind a new
  `ConfirmRecordPermanentError` sentinel, with master-key IO
  classified TRANSIENT); the SEEDED-ORPHAN resolution under the
  single-Store-ownership invariant (plain commit/SyncApply: the
  post-durability finalize resolves a seeded Present(record) with no
  in-memory window; confirmed commit: the arm resolves BY OVERWRITE,
  a PRE-rename failure converts the orphan to an R-kind debt); the
  `confirmRecordTerminal` latch folded
  into `ConfigPersistDegraded` with boot reconstruction, the LIVE
  probe-only observer (the latch keeps the singleton alive read-only;
  continuation kinds — DEBT-origin resumes the debt's retry BY KIND;
  BOOT-origin splits into RESTART-RECOVERY-OWED (latch held,
  restart-required 503 until reboot) and SUPERSEDED-WHILE-UNREADABLE
  (marker → R-kind debt); a confirmed absence re-drives the
  `DeleteConfirm` barrier for R-kind / runs (w-c) restore-or-stale
  for W-kind before clearing), the
  TRANSIENT-boot bounded-retry (pinned envelope: initial read + ≤3
  retries, 100/200/400 ms, `LoadContext(ctx)` with `Load()` preserved,
  clock seam) then fail-`Load` with
  the NEW `ErrConfirmStateUnreadable` sentinel routed fail-closed
  through `classifyLoadError`, and the
  typed THREE-FIELD `ConfigPersistDegradedState()` snapshot accessor
  (`{ActivePersistDegraded, ConfirmPersistDegraded,
  ConfirmRecordTerminal}`); the
  SyncApply finalize ordering in `store.go`; the hedge-the-cause
  stale-drop diagnostic (`store_persist.go:159-165`).
- `pkg/api` (r16 Codex m3 + r17 Codex M6/m2 + r18 Codex M7/m5 + r19
  Codex m4 — `pkg/api` IS touched):
  the new `ConfigPersistDegradedStateFn` Config FIELD (`server.go`,
  alongside the retained aggregate `ConfigPersistDegradedFn` the gauge
  consumes) wired from the store's typed snapshot;
  `api/health.go` renders the messages by precedence
  (terminal confirm-record > confirm-persist — GENERIC removal/rewrite
  text + a debt-kind detail field — > active-persist), plus the
  DISTINCT restart-recovery-owed message for the BOOT-origin substate;
  `metrics.go` keeps the gauge on the aggregate OR;
  `metrics_descriptors.go` + the field/wiring comments name all three
  causes; a Config → NewServer plumbing test pins the wiring.
- `pkg/fwdstatus/sampler.go`: `CachedStatusProvider` interface; `NewSampler`
  + `Sampler.dp` retyped; `sample()` direct call.
- `pkg/dataplane/retirement_boundary_canary_test.go`: matcher extension
  (incl. `*ast.IndexExpr` renderer support).
- `pkg/daemon/daemon_dp_canary_test.go` (new): dpCell-access AST canary.
- `pkg/grpcapi`, `pkg/cli` untouched.

### 5.2 Writer conversion (5 sites — complete, both reviewers verified)

| Site | Context | After |
|---|---|---|
| `daemon_run_bringup.go:448` (DPDK retired) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:464` (eBPF retired) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_bringup.go:469` (construct) | boot, Run goroutine — RACE-1 window | `d.setDataplane(dp)` |
| `daemon_run_bringup.go:497` (Start fail) | boot, Run goroutine | `d.setDataplane(nil)` |
| `daemon_run_naming.go:234` (bootstrap-exit arm fail) | apply goroutine, `d.applySem` — RACE-2 | `d.setDataplane(nil)` |

### 5.3 Per-site snapshot boundaries (normative conversion rules)

1. **Per-tick loop readers** (HA watchdog `daemon_ha_sync.go:750`,
   reconcile loops, neighbor listener): ONE load per tick/iteration before
   any per-element loop (watchdog: one load shared across the RG loop — not
   per-RG, not a lifetime capture).
2. **Spawn-gated loops** (`daemon_ha_sync.go:733`): gate check is one load;
   the loop body loads per tick per rule 1.
3. **Multi-use straight-line sites** (`daemon_run_naming.go:230-248`): ONE
   local for nil-check + `Start` + seeding; `setDataplane(nil)` only on the
   failure branch.
4. **Two-assertion sites** (`daemon_neighbor_listener.go:469-476`):
   provider and `indexEnumerator` derive from ONE load.
5. **Snapshot-per-operation** (fence `daemon_ha_sync.go:1286,1297`,
   `warmNeighborCache` `daemon_ha.go:1521-1545`, shutdown
   `daemon_run_shutdown.go:161-173` and :214-229 — one snapshot for the
   HA-clear block, a SECOND for final-stats+Close/Teardown, matching
   today's two separate reads).
6. **Capture-once at goroutine start** (`daemon_gc.go:22`,
   `daemon_ha_userspace_stream.go:67,122,259`): exactly one load at start —
   preserves today's semantics deliberately.
7. **Per-request / per-callback readers** (REST
   `PolicySchedulerActiveStateFn`, NAT pool sampler closure, health, the
   full-resync exporter read at `daemon_ha_userspace_stream.go:235`): one
   load per invocation.
8. **Apply-path readers under `d.applySem`**: same load-once rules; the
   accessor is lock-free, orthogonal to applySem.
9. **`%T` logging** (`daemon_ha_sync.go:311`): `%T` of the loaded value —
   same output.

### 5.4 Reader audit table (issue requirement #4 — untruncated, exact)

**134 executable production references** (163 greppable lines over
`pkg/daemon/*.go` minus `_test.go` matching `'d\.dp\b|a\.daemon\.dp\b'`,
minus 29 full-line comments): **5 writers + 129 readers**. Classes:
**W** = writer; **APPLY** = applySem-serialized reader; **BOOT-SYNC** =
Run-goroutine read before any server can deliver a commit; **CONCURRENT** =
background/request-goroutine reader. Reachability: RACE-2 reaches only
standalone/bootstrap consumers (§2 four-link exclusion); RACE-1 reaches
ONLY the pre-publication watcher chain (§2 scope note); RACE-3 reaches
every apply-PIPELINE reader (`applyConfigLocked` and its callees — the
APPLY-class rows) via the recovered confirm timer PRE-gate — POST-gate
(work item G) all timer dispatch is ordered after startup, collapsing
those rows back to plain APPLY-serialized, with the atomic cell as the
uniform defense. (The NAT start gate `daemon_natpoolalarm.go:101` is
APPLY-class but lives on the bootstrap-EXIT path, not the rollback apply
path — not timer-reachable.) "RACE-2 reaches only standalone/bootstrap"
and the exclusion statements are current-version claims; the legacy
cross-upgrade path is handled by work item H. Everything not labeled
with a live exposure is converted for uniformity, not reachability. The compiler
(field retype) proves the conversion total; this table is the
classification snapshot.

| File:lines | Context | Class | RACE exposure |
|---|---|---|---|
| `daemon_run_bringup.go` 448,464,469,497 | boot writes | W | — |
| `daemon_run_naming.go` 234 | bootstrap-exit write | W | — |
| `daemon_forwarding_status.go` 108,111,124,128 | sampler tick (`CachedStatus`) + adapter construction | CONCURRENT | RACE-2 (sampler) |
| `daemon_forwarding_status.go` 21,24,36,39,97,100 | `IsLoaded`/`GetMapStats`/`Status` methods — DELETED by the narrowing, not converted | — | — |
| `daemon_run_servers.go` 409,412 | REST simulator probe | CONCURRENT | RACE-2 |
| `daemon_neighbor_listener.go` 304,307,473 | netlink listener/regen (started when `ActiveConfig() != nil` at boot, `daemon_run.go:518-533` — incl. never-committed-restart bootstrap) | CONCURRENT | RACE-2 |
| `daemon_ha_userspace_stream.go` 122 | event-stream start assertion; launched standalone (`daemon_run.go:365-369`, RACE-2) and on cluster (`daemon_ha_sync.go:1176`, post-publication) | CONCURRENT | RACE-2 (standalone) / uniformity (cluster) |
| `daemon_ha_userspace_stream.go` 67,259 | drainer captures at goroutine/fallback-loop start (capture-once; :67 is mixed standalone/HA — the standalone fallback at :125 reads `d.dp` BEFORE the `d.cluster == nil` check at :68) | CONCURRENT | RACE-2 (:67 standalone) / uniformity |
| `daemon_ha_userspace_stream.go` 235 | full-resync exporter read, per-callback (HA-only) | CONCURRENT | uniformity |
| `daemon_natpoolalarm.go` 18,21 | monitor sampler goroutine (#2116 lifecycle-gated) | CONCURRENT (gated) | gated off by lifecycle |
| `daemon_natpoolalarm.go` 101 | start gate (boot block + `runBootstrapExitStartup` under applySem — exit path, NOT traversed by a rollback apply) | APPLY/BOOT-SYNC | serialized |
| `daemon_run.go` 312,324 | `er.AddCallback` per-SESSION_OPEN reads (registered :284 iff `getSessionSync() != nil`, post-publication) | CONCURRENT | unreachable-by-writer (uniformity) |
| `daemon_run.go` 611,612 | CLI probe after gRPC start (:598) | CONCURRENT | RACE-2 (micro-window) |
| `daemon_run_servers.go` 117,118 | gRPC construction probes (HTTP already serving) | CONCURRENT | RACE-2 (micro-window) |
| `daemon_run_servers.go` 255,256 | API construction probes (before HTTP serving starts) | BOOT-SYNC | program order |
| `daemon_run_shutdown.go` 161,167,173 | HA-only rg_active clear (requires cluster config) | CONCURRENT | unreachable via exclusion (current-version; legacy path guarded by work item H) |
| `daemon_run_shutdown.go` 214,219,220,225,229 | final stats / Close / Teardown (applySem released at :50) | CONCURRENT | RACE-2 |
| `daemon_ha_fabric.go` 533,537,554,555,567,570,724,728,750,753 | fabric probe/refresh goroutines (post-publication start) | CONCURRENT | uniformity |
| `daemon_ha_sync.go` 193,299,300,311,733,750,1117,1124,1164,1165,1286,1297 | watchdog/sync/fence/SetRuntime goroutines (post-publication start) | CONCURRENT | uniformity |
| `daemon_ha.go` 297,299,337,348,362,367 | `watchClusterEvents` handler chain (started `daemon_run_bringup.go:203`, PRE-publication) | CONCURRENT | **RACE-1** |
| `daemon_ha.go` 542,549,578,583 | `watchVRRPEvents` (:511-604, post-publication) | CONCURRENT | uniformity |
| `daemon_ha.go` 813,826,842 | `reconcileRGState` (:707+, post-publication) | CONCURRENT | uniformity |
| `daemon_ha.go` 1521,1531,1545 | `warmNeighborCache` (:1520, failover paths, post-publication) | CONCURRENT | uniformity |
| `daemon_ha_userspace_readiness.go` 202 | `userspaceDataplaneActive` — reached from the PRE-publication watcher via `removeBlackholeRoutes` (`daemon_ha.go:311` → :1124; demotion `:359-360` → `:1064-1066`) | CONCURRENT | **RACE-1** |
| `daemon_ha_userspace_readiness.go` 230,233 | takeover-readiness probes (post-publication) | CONCURRENT | uniformity |
| `daemon_health.go` 141 | standby-neighbor refresh (session-sync trigger, `daemon_ha_sync.go:970`, post-publication) | CONCURRENT | uniformity |
| `daemon_apply_dataplane.go` 53,98,122,139,141,293,295,390,393,397,455,459,463,482,485,497,501,505 | apply path (incl. `reapplyAfterDeferredMAC`, `recordDataplaneWorkerArmDebt`) — applySem-serialized vs RACE-2, but a timer-triggered rollback apply (§2 RACE-3) runs this path while the boot writers hold no applySem | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_apply_tail.go` 491,494 | apply path | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_apply_interfaces.go` 42 | apply path | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_apply_routing.go` 367 | apply path | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_scheduler.go` 211,221,224,230,239 | scheduler republish under applySem | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_ipmon.go` 304 | route-overlay actuate under applySem | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_policy_invalidate.go` 286,290 | callers hold applySem (:114-116; `daemon_apply_commit.go:270`) | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_system.go` 41 | applySyslogConfig (boot-time and apply-path callers) | APPLY/BOOT-SYNC (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon.go` 1012 | `applyResult()` (boot-time and apply-path callers) | APPLY/BOOT-SYNC (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `bootstrap.go` 472,473 | rollback teardown under applySem — but the recovered commit-confirmed TIMER path (§2 RACE-3) reaches it while the phase-3 boot writers run WITHOUT applySem | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | **RACE-3** (pre-gate) |
| `daemon_run_naming.go` 230,231,236 | exit arm block (nil-check, Start, seeder) | APPLY (vs RACE-2) / CONCURRENT (vs RACE-3) | serialized / **RACE-3** (pre-gate) |
| `daemon_run_bringup.go` 476,477,493,494,506 | boot post-construct reads (same goroutine as W) | BOOT-SYNC | program order |
| `daemon_run.go` 212,223,238,270,354,365 | boot PHASE 3-5 setup, pre-server | BOOT-SYNC | program order |
| `daemon_gc.go` 22 | GC construction capture (boot) | BOOT-SYNC (capture-once) | program order |

### 5.5 Docs contract

- `pkg/daemon/README.md`: publication-cell contract in the ARCHITECTURE
  section (:13); update the bootstrap-mode bullet (:556-568), the
  first-commit rollback bullet (:578-585), AND the live
  `d.dp.ApplyConfig` reference (:936) (r2 Codex MINOR 3).
- Source comments contradicting the rollback recurrence get reworded in
  the same PR: `daemon_run_naming.go:200-206` ("one-way ... at most once"),
  `bootstrap.go:284-289` ("one-way for the daemon's lifetime"),
  `daemon_apply.go:213-220` ("Exit is one-way"), plus the r3 additions
  `daemon.go:901`, `bootstrap.go:276` ("written once at startup and at most
  once more"), `bootstrap.go:303` ("re-suppress takeover for the daemon's
  lifetime"), `cluster_topology_preflight.go:117`'s stale
  `daemon_run.go:1868` cite (now `daemon_run_bringup.go:164`), plus the r4
  additions `daemon_apply_commit.go:156` ("one-way"),
  `daemon_natpoolalarm.go:88` ("exactly once" vs discard-and-rearm at
  `:118-126`), `cluster_topology_preflight.go:59` (second stale
  `daemon_run.go:1868` cite), plus the r5 stale-cite additions
  `pkg/daemon/cluster_identity_preflight_6192_test.go:27` and
  `docs/ha-no-hitless-restart.md:85,130` — the recurrence (exit →
  `enterBootstrapMode` → re-exit) is real and now tested; the comments must
  say "one-way per bootstrap episode; rollback can re-enter" (r2-r5 Codex
  comment sweeps).
- `docs/` sweep: `docs/ha-failover-status.md:279`,
  `docs/ha-no-hitless-restart.md:22`, `docs/rib-group-route-leaking.md:94`
  (the /engineer pass greps `docs/` for `d\.dp` and updates or justifies
  each hit).
- Recovery-contract docs for work item H's third outcome (r9 Codex m2,
  r10 Codex m4, r11): the "Two outcomes" comment at
  `store_persist.go:127-135` (expired → revert, future → re-arm) gains
  the third outcome (unexpired FirstCommit+cluster → revert-at-Load,
  remaining window abandoned), and the matching contract prose at
  `pkg/configstore/README.md:417-449` and the `confirmRecord` doc at
  `pkg/configstore/db.go:161-168` ("Store.Load re-arms the timer when
  the deadline is still in the future") are updated in the same commit.
  The canonical-binding fix (r10/r11/r12) updates the #5835 binding comment
  at `store_commit.go:543-548` to name the canonical basis + the
  `HashBasis` discriminator, and the tombstone (r11/r12/r13) updates the
  `confirmRecord` struct doc (`db.go:161-168`), the `WriteConfirm`
  additive-evolution contract comment (`db.go:200-205` — gains the two
  new fields' downgrade semantics AND the correction that
  `wrapEnvelope` covers active/candidate/rollback, never confirm.json),
  and the `resolveConfirmRemovalLocked` / `noteConfirmRemoveFailureLocked`
  comments (`store_commit.go:575-608`) for the UNIFORM tombstone-first
  linearization + the `onDiskArmID`-keyed four-state debt
  semantics. The terminal taxonomy + remediation runbook joins the
  `pkg/configstore/README.md:417-449` contract prose and the
  `ConfigPersistDegraded` doc comment (`store_persist.go:342-353`), and
  the health-response string gains its terminal confirm-record variant
  (`api/health.go:65-71`). The r17 additions (Codex m2/m3): the
  SyncApply confirm-type source terminology — "Treat the sync as the
  confirmation" (`store.go:716-717`) and the matching
  `pkg/configstore/README.md:663-672` prose — is reworded to the
  replacement-class framing (supersede-on-sync with the #5473/#5835
  ordering), and the aggregate-cause surfaces
  (`metrics_descriptors.go:625-630`, `server.go:132-140`,
  `daemon_run_servers.go:370-374`) name the degradation causes
  (active-persist retry pending, confirm-record removal/rewrite debt,
  AND terminal confirm-record corruption — "BOTH" was the r17
  two-cause framing, corrected to three in r18/r19). The r18 additions
  (Codex m4): the #5473 ordering prose
  at `pkg/configstore/README.md:476-540` gains the failure-phase
  classification (PRE-rename retention vs POST-rename immediate
  barrier); `pkg/api/README.md:30-36` describes the THREE-cause typed
  snapshot (not the bare bool); the stale single-unkeyed-delete-retry
  comments at `store_commit.go:556-570,667-695,732-735` are reworded
  to the keyed debt-set semantics; the health contract header at
  `pkg/api/health.go:10-16` names all three causes; and the
  `classifyLoadError` class comments at `bootstrap.go:36-47` gain the
  `ErrConfirmStateUnreadable` fail-closed class. The r19 additions
  (Codex m5): the "every confirm-read failure logs and skips"
  comment at `db.go:239-241` and the matching `README.md:470-473`
  prose are reworded to the transient/permanent taxonomy + the
  fail-closed transient boot path; and `README.md:937-968` ("`Load`
  returns one of three error shapes") gains the fourth
  (`ErrConfirmStateUnreadable`) and the every-outcome confirm.json
  seeding read. The irrecoverable cross-version cases are documented in
  the same comments, AND the stale-drop diagnostic text at
  `store_persist.go:159-165` is updated to hedge the cause
  ("superseded OR basis-incompatible", r14 Codex m3).
- `_Log.md` entries for every implementation edit (CLAUDE.md).

## 6. Public API preservation

`Daemon` and its field are package-private; nothing outside `pkg/daemon`
references them.

**Intentional signature change (the only one)**: `fwdstatus.NewSampler`
takes `CachedStatusProvider` instead of `DataPlaneAccessor` (r2 M1).
Callers: exactly one production (`daemon_run.go:595`) + two test sites
(`sampler_test.go:69,106`); the test fake already satisfies the narrow
interface. `DataPlaneAccessor`/`Build`/`Format` are unchanged for their
real consumers (grpcapi/cli adapters).

Preserved exactly:

- gRPC/CLI `show chassis forwarding` output (their per-request adapters
  untouched; no type divergence against an immutable captured object).
- Sampler behavior: worker counters hold-last on `ok=false` (unchanged code
  path, now a direct call instead of an assertion).
- `conntrack.NewGC` capture at boot; boot probe results
  (`cliDataPlane`/`grpcDataPlane`/`apiDataPlane`).
- NAT pool-alarm monitor lifecycle (#2116) and `show security alarms`.
- NoDataplane mode: cell nil for the daemon lifetime.
- `applyResult()`, the health endpoint's 200/503 CONTRACT (the response
  TEXT repertoire grows by two cause-distinct degraded messages — the
  503 semantics are unchanged, r18 Codex item-7), REST simulator
  fail-closed `ok=false` (#3414).

## 7. Hidden invariants the change must preserve

1. **Snapshot boundaries per §5.3** — the one way to introduce a NEW bug in
   a mechanical conversion.
2. **Publication atomicity (RACE-1)**: boot writers publish via the cell in
   the same program order; readers see nil or the full slot — never a torn
   interface.
3. **Capture-once semantics**: GC/event-stream captures keep the object
   grabbed at start (same as today). Deliberately preserved.
4. **applySem orthogonality**: lock-free accessor; no lock-ordering
   interaction with the "Locked" conventions.
5. **#2116 monitor lifecycle**: sampler closure switches to the accessor;
   gating/discard untouched; existing race tests re-point `writeDPFor` at
   `setDataplane`.
6. **Terminal nil**: nothing re-publishes a backend on current master; the
   accessor is correct under ANY Store sequence; tests assert observable
   post-nil state without relying on terminality for safety.
7. **Typed-nil exclusion without panic**: kind-gated guard over ALL
   nillable kinds (§4 A1); a value-type implementation Stores normally; a
   typed-nil of any nillable kind (pointer, named slice/map/chan/func)
   Stores as nil. All shapes covered by unit tests (r2 B1, r3 m1).
8. **Shutdown ordering** (#5807): two snapshots per §5.3 rule 5; post-nil
   shutdown skips final stats exactly as today.
9. **Allocation rules**: one `dpSlot` per Store (≤5/lifetime); zero per
   read. Go control plane only.
10. **Retirement boundary**: the canary's invariant (daemon holds a
    `dataplane.RuntimeDataPlane` built by `NewRuntimeDataPlane`) preserved
    through the redesigned matcher; both-direction canary self-tests (§4).
11. **Shutdown-admission guard (r8/r9/r10)**: the double nil-safe guard
    (`d.stopping.Load() || (d.runCtx != nil && d.runCtx.Err() != nil)`,
    checked by the executor UNDER applySem, joining the `isResetting()`
    early-return) orders ENTRY absolutely: after ctx cancellation OR
    after `runShutdownSequence`'s FIRST-STATEMENT `stopping` publication
    (before `d.applyCancel()`), no rollback newly enters its critical
    section; the cancellable `Acquire(runCtxOrBackground())` abandons a
    wait interrupted by the signal instead of parking through teardown.
    HONEST BOUND (r9 Codex M2, r10-narrowed per Codex m3, verified
    `applyCloseoutDrainTimeout = 5s`, `daemon_run_shutdown.go:15,50-58`):
    a rollback ALREADY in flight when the signal lands is
    bounded-drain-covered for ≤5 s; beyond the drain budget the shutdown
    proceeds (`:54-58`, logged) and the rollback — deliberately
    non-cancellable work — can overlap manager/dataplane teardown. That
    overlap exists on master today for every commit-confirmed timer (the
    executor has no shutdown guard at all). NARROWED CLAIM: the guard
    does not lengthen the admitted body and does not enlarge the existing
    worst case — but by delaying an early-fired timer to END-of-PHASE-5
    it CAN increase overlap likelihood vs master's immediate dispatch;
    that is the price of closing the partial-init dispatch class, stated
    openly. Closing the in-flight class would require a cancellable
    apply — out of scope. The abandoned timer's persisted record
    re-resolves on the next boot's expired-window path (same semantics as
    the startup-failure abandon).
12. **#4577 confirm contract (r8/r10/r11/r12/r13/r14/r15)**: an
    unconfirmed config must NEVER stand, and a CONFIRMED config must
    never be rolled back. Work item H's revert-at-Load honors the first
    half for the FirstCommit+cluster class by resolving the window
    EARLY (revert before manager construction) rather than by keeping
    the config; the operator's remaining confirm window is sacrificed
    for this narrow hybrid-generating class, loudly and on purpose.
    Expired records keep the existing expired-branch behavior
    bit-for-bit. The second half is enforced by a UNIFORM rule with a
    pinned linearization point: EVERY removal through
    `resolveConfirmRemovalLocked` writes the durable tombstone FIRST —
    because a lingering record's replay is never free (r15: a replayed
    apply re-attaches AF_XDP, bumps the dataplane `config_generation`
    the flow cache keys on, reloads FRR, and can restart heartbeat).
    Replacement/rollback paths retain the record as intent ONLY until
    the replacement is durable (#5473) — with the r17 failure-phase
    classification: a PRE-rename replacement-write failure retains
    (the replacement is invisible; the record is the rollback intent),
    a POST-rename failure immediately attempts the tombstone barrier
    (success PROVES the replacement durable — the #5473 precondition,
    with the tombstone success as witness), and every path tombstones
    at the finalize like every other path; factory reset is a terminal
    wipe. The TWO-FIELD (`armedArmID` window identity + `onDiskArmID`
    known-on-disk identity, seeded by `Load` on EVERY outcome)
    ArmID-keyed, four-state, typed-error debt SET makes the retry act
    only on the record it resolved, in every `WriteConfirm` failure
    phase — with the current record's durability established BEFORE
    any stale debt is cleared, SAME-RECORD dominance (the removal debt
    keyed to the CURRENT on-disk record dominates EVERY write of that
    record — from W-kind rewrite debts AND from stale-keyed removal
    debts' mismatch branches alike; its tombstone is the universal
    barrier for that record), debt-kind-correct actions (R-kind:
    tombstone→delete; W-kind: rewrite/restore — never a tombstone of
    a live window's record, never an abandoned recovery file), and
    convergence guaranteed CONDITIONALLY on a lexicographic
    remaining-stage measure (eventual zero given quiescence + a
    failure-free suffix; health stays degraded and visible under
    churn — no liveness claim against it), and the
    finalize's tombstone write doubling as the same-directory
    durability barrier for the replacement's active.json rename
    (tombstone-durable ⟹ replacement-durable, the barrier keying on
    the tombstone write alone — an unlink failure retains only the
    delete-finishing debt). The irreducible
    residuals are documented, not hidden: tombstone-write failure +
    crash before retry (hazard detonates AT the deadline or the next
    boot's expired branch), the replacement-POST ∧ barrier-failure
    namespace replay (the replacement write fails post-rename AND the
    tombstone attempt fails in ANY phase + restart/power loss before
    any successful directory barrier — master's active-write residual,
    shrunk to the intersection), exceptional-content cross-version
    windows (information lost at persistence — admitted with
    hedge-the-cause diagnostics), terminal-degraded corrupt records
    (PER-DEBT terminal latch over the permanent taxonomy with
    master-key IO classified transient, boot-reconstructed at
    recovery, kept under a LIVE probe-only observer, election-neutral,
    manual remediation, loudly surfaced — never silently cleared), and
    the PERMANENT-class boot-read residual (a deterministically
    corrupt record at boot proceeds degraded with the latch — an
    unconfirmed config may stand, LOUDLY, until operator action;
    transient boot reads fail `Load` closed instead).

## 8. Risk assessment

| Class | Rating | Assessment |
|---|---|---|
| Behavioral regression | **MED** | Large but mechanical diff; compiler-enforced completeness + regenerated §5.4 table + the new dpCell canary. Real risks: (a) a §5.3 snapshot-boundary mistake; (b) canary redesign errors (mitigated by both-direction self-tests); (c) the fwdstatus narrowing touching `NewSampler` (contained: 1 prod caller + 2 test sites; full-suite gate); (d) work item H narrows commit-confirmed recovery semantics for the FirstCommit+cluster class (revert-at-Load vs re-arm) — deliberate, loudly logged, covered by five dedicated tests including the expired-record negative case. |
| Lifetime / borrow | **LOW** | Immutable slots; captured references keep backends alive exactly as today. No FFI/Rust interaction. |
| Performance regression | **LOW** | One atomic load + indirection per control-plane read (1 Hz sampler, request rate, watchdog 2/s, HA ≤15/s). One small allocation per Store, ≤5/lifetime. No per-packet Go code. |
| Architectural mismatch | **LOW** | #2116 `atomic.Pointer` precedent; daemon atomics-for-publication idiom; no dataplane-lifecycle redesign (Option B rejected); canary redesign extends the existing boundary-guard pattern. Work item G IS a deliberate lifecycle change (startup-outcome gating of the rollback executor + the r8 shutdown-admission fence) — scoped, ~55 LoC + tests, with its own invariants: startup-outcome handled on EVERY exit path (no goroutine leak on failure leg, no rollback against partial init, panic-safe via the Run-scoped defer); gate-before-applySem ordering (no executor-held applySem across the gate-wait — that is what deadlocks the phase-4 boot apply); fence-before-drain ordering (no rollback admitted against live teardown); timer-retention on abandon is INTENTIONAL (the persisted confirm record is re-resolved by the next boot's expired-window path, `store_persist.go:225-228`). Work item H reuses the expired-branch FirstCommit revert body — no new persistence semantics, no new failure modes beyond the class it terminates. |

## 9. Test plan

1. `go build ./... && go vet ./pkg/daemon/... ./pkg/fwdstatus/...` — the
   field retype makes the compiler enumerate every conversion site.
2. New `pkg/daemon/daemon_dp_race_test.go` (under `-race`, `-count=5`):
   - `TestDataplaneCell_ConcurrentReadersVsWriter` — N goroutines hammer
     accessor-routed readers (narrowed adapter `CachedStatus`,
     `applyResult()`, a `PolicySchedulerActiveStateFn`-shape probe, the NAT
     pool sampler closure, a watchdog-shape per-tick load) while a writer
     alternates `setDataplane(nil)` / `setDataplane(fake)`. Revert-guard.
   - `TestDataplaneCell_TypedNilAndValueShapes` (r2 B1, r3+r4 broadened) —
     TABLE-DRIVEN over every guarded nillable kind: typed-nil pointer,
     typed-nil named slice, typed-nil named map, typed-nil named chan,
     typed-nil named func (each Stores as nil, `d.dataplane() == nil`);
     plus a value-receiver fake (Stores normally, no panic, non-nil read).
   - `TestForwardingStatusAdapter_BackendTypeTransitions` — start
     `readyProbeOnlyFake` (adapter `CachedStatus` ok=false) →
     `setDataplane(userspaceFake)` (ok=true, injected status) →
     `setDataplane(nil)` (ok=false). Proves per-call capability adaptation;
     the OLD construction-time wrapper selection (base wrapper permanently
     lacking `CachedStatus`, or nil accessor when nil-at-construction,
     `daemon_forwarding_status.go:123-125`) cannot express the middle leg.
   - `TestBootstrapExit_ArmFailureWithConcurrentReaders` — REAL writer via
     the extracted `armBootstrapExitDataplane(nodeID int)` helper
     (Start + seeder + `maybeStartNATPoolAlarm` + nil-on-failure, split
     from `runBootstrapExitStartup` so the test avoids the netlink/sysctl
     takeover steps); failing-Start fake; churn readers; assert `-race`
     clean, `d.dataplane() == nil`, monitor not started.
   - `TestBootstrapExit_RealSamplerOverlap` (r2 M2, r3 B1 — the barrier
     must NOT happens-before-order the conflicting accesses): the adapter's
     `CachedStatus` loads `d.dataplane()` BEFORE invoking the provider, so
     a gate inside the provider's `CachedStatus` would serialize
     `read(d.dp) → entered → writer`, keeping even the pre-fix plain field
     race-clean (silent green). The gate must therefore sit BEFORE the
     `d.dp` access on BOTH sides with NO channel between the two
     conflicting accesses:
     - Reader side: the fake `ProcReader.ReadSelfStat` (which
       `Sampler.sample()` calls before touching the adapter,
       `sampler.go:93`) signals `readerEntered` and blocks on a shared
       `release` channel. `go fwdSampler.Start(ctx)` — `Start` MUST run on
       its own goroutine because its prime sample is synchronous
       (`sampler.go:64-67`).
     - Writer side: the failing fake dataplane's `Start()` signals
       `writerEntered` and blocks on the SAME `release` before returning
       its error (the `setDataplane(nil)` store happens after `Start`
       returns in `armBootstrapExitDataplane`).
     - Test: wait for BOTH `readerEntered` and `writerEntered`, then
       `close(release)`. The adapter's `d.dp` load and the writer's store
       now proceed with no happens-before edge between them: on the plain
       field the race detector fires (only the ABSENCE of an HB edge is
       required — deterministic as a memory-model proposition, not a
       timing one); on the atomic cell it is clean.
     - Teardown: the sampler loop exposes no join handle (`Start` returns
       nothing) — `cancel(ctx)` and then require SUSTAINED quiescence: the
       fake `ProcReader` records `ReadSelfStat` entries under a mutex and
       returns a successful stat; the test polls the counter until it has
       been stable for ≥ 2× `SampleInterval` (≥2.5 s margin at the 1 s
       cadence) — bounded by an overall test timeout so it cannot hang.
   - `TestDataplaneCell_RollbackRearmRecurrence` — real helpers: successful
     arm → monitor starts → `enterBootstrapMode` (discarded) → re-exit with
     failing Start → `d.dataplane() == nil`, no monitor, `-race` clean with
     watchdog-shape readers churning.
   - `TestDataplaneCell_ClusterStartPublication` — RACE-1 shape:
     watcher-shape reader loop racing the boot `setDataplane(dp)`
     publication; nil-or-full-slot assertion; `-race` clean.
   - `TestDataplaneCell_ConfirmTimerVsBootPublication` — RACE-3 + work
     item G (r5 pivot, r6/r7-strengthened):
     (a) GATE test: with `startupDone` OPEN, a fired
     `executeConfirmedRollback` must BLOCK before applySem — a test-only
     ENTRY HOOK (counter/channel signalled immediately before the
     `<-startupDone` wait) proves the executor is AT the gate before the
     test contends (without it, a wrong acquire-then-wait implementation
     passes if the contender runs first). While gated: assert no rollback
     side effects AND that a second goroutine CAN acquire and release
     `d.applySem`. Then: `finishStartup(true)` ⇒ rollback proceeds;
     `finishStartup(false)` (failure leg) ⇒ abandon with no side effects
     and no leaked waiter. The failure leg is ALSO driven through BOTH
     REAL failure paths (plain phase error AND signal abort via
     `runStartupOrAbort`, mirroring `startup_signal_5807_test.go:131`)
     to prove the production publish fires, not just the manual one.
     (b) Cell revert-guard, post-startup shape: two-sided gate — a
     `setDataplane(dp)` publication gated immediately before the store vs
     an applySem-holding reader gated immediately before its
     `d.dataplane()` load; shared release; no channel between the pair.
     (c) REAL-path ordering test, phase-level orchestration (NOT a full
     host-mutating `Run`): stubbed store with a persisted confirm record
     + the phase functions driven in order (config-load → manager-init →
     dataplane-setup), a per-Daemon BACKEND-FACTORY SEAM (test-only var
     substituted for `buildRuntimeDataPlane` — the production factory
     hard-codes userspace at `daemon_run.go:53-60` and phase 4 overwrites
     `d.dp` at `daemon_run_bringup.go:421`) supplying a fake
     `RuntimeDataPlane`, the existing `linkDir` test override for naming
     side effects, and a deterministic post-`Load`/pre-`initManagers`
     phase-hook. Fire the timer while paused: assert EXECUTOR ENTRY (the
     hook) with NO `PromoteRollback`/apply side effects (the gate holds —
     "no dispatch" is unobservable since `fireConfirmTimer` invokes the
     executor directly at `store_commit.go:819-820`). Resume: assert the
     rollback lands after the linearization point with the fake dataplane
     intact AND a LATE-MANAGER milestone initialized (`snmpBootReady`
     true / LLDP manager non-nil — a close placed immediately after
     phase 4 fails this).
     (d) SHUTDOWN-GUARD test (r8/r9/r10, Codex M1×3 + AGY f2): with the
     gate OPEN (post-startup): leg 1 — publish `d.stopping` (mirroring
     the production publication), fire the executor — it must pass the
     gate, acquire applySem, observe the guard, and ABANDON with zero
     `PromoteRollback`/apply side effects; leg 2 — same via the `runCtx`
     arm (cancel a stored signal context; the executor observes
     `runCtx.Err() != nil` and abandons — deterministic, no flag
     publication involved); leg 2b (r10 AGY f2) — park the executor in
     `Acquire` behind a held applySem, cancel `runCtx`, assert the
     Acquire errors and the executor abandons (no parked goroutine);
     leg 3 (r9 Codex m1 + r10 Codex M1 — ACTUAL-PATH ordering, pattern
     `daemon_shutdown_wiring_5523_test.go:113-129`): drive the REAL
     `runShutdownSequence` in a goroutine with an INJECTED `applyCancel`
     that asserts `d.stopping` is ALREADY raised at `applyCancel` time —
     proving first-statement publication, which a "before the drain"
     placement fails; leg 3b (r10 Codex m2 — production runCtx binding):
     assert Run stores the SIGNAL CHILD (derived at `daemon_run.go:86`)
     not the raw parent — a reverted assignment fails (pattern
     `startup_signal_5807_test.go:16-42`); leg 4 — an executor already
     inside its critical section blocks the drain until it releases
     (pre-existing bounded-drain behavior, unchanged).
   - Work item H tests (r8/r9-reworked; configstore/daemon seams, no
     cluster): (i) UNEXPIRED legacy empty-`GuardedHash`
     FirstCommit+cluster record → guard reverts AT LOAD: active = empty
     tree, `everCommitted=false`, record removed (or removal debt
     retained), NO re-arm, loud log; (ii) UNEXPIRED nonempty-hash
     FirstCommit+cluster record (recurrence generation) → identical
     revert; (iii) UNEXPIRED standalone FirstCommit record → normal
     re-arm + rollback unchanged; (iv) EXPIRED FirstCommit+cluster
     record → existing expired branch reverts, guard does NOT double-fire
     (single journal entry, no guard log) — the mandatory already-expired
     negative case (Codex M2 / Claude SMR M1); (v) recurrence test:
     synthesize the post-hybrid state (`everCommitted=false`, live
     `d.cluster`, bootstrap mode) → cluster `commit confirmed` persists a
     fresh nonempty-hash FirstCommit record → recovery → guard fires
     (Codex M3); (vi) COMPILED-topology positive (r9 Codex M3): cluster
     stanza arrives ONLY via `apply-groups` → guard FIRES; (vii)
     COMPILED-topology negative: raw tree carries
     `inactive: chassis cluster` → guard does NOT fire, normal re-arm;
     (viii) CANONICAL-BINDING regression (r10, strengthened r11 Codex
     m2): arm through the PRODUCTION `CommitConfirmed` path with a
     candidate carrying `inactive: system dataplane-type ebpf` AND an
     invalid-UTF-8 interface description → verify the persisted record's
     GuardedHash equals the canonical hash of a freshly decoded
     `ReadActiveMeta` tree → restart → recovery BINDS (no stale-drop)
     and the guard fires on its own predicate — hand-constructed fixture
     files forbidden (they stay blind to serialization divergence);
     (ix) bootstrapFromFile parity regression (r10 Codex M3
     adjudication): post-guard boot never enters the
     bootstrap-with-live-cluster hybrid, and the seed-file import
     behavior is identical to the expired-window path (same
     `shouldBootstrapFromFile` decision, distinct journal trail);
     (x) RESOLUTION-TOMBSTONE regressions (r11-r16): (x1)
     demotion-confirm + injected confirm.json deletion failure +
     restart → recovery drops the TOMBSTONED record (no re-arm, no H,
     no rollback of the confirmed config — the #4378 divergence stays
     closed); (x2) crash BETWEEN arm and tombstone → genuinely pending
     → normal re-arm; (x2b) resolution with NO confirm.json on disk →
     tombstone NO-OP, in-memory resolution completes; (x2c)
     resolution-time READ ERROR → debt still constructed (keyed from
     `onDiskArmID`, never the arm memory); (x3) tombstone-write failure →
     in-memory resolution proceeds, keyed retry converges
     tombstone→delete; (x4) four-state typed keyed debt: (x4a) arm
     success → mismatch → B already durable → clear, B intact;
     (x4b) pre-rename failure → match → act; (x4c) post-rename failure
     → mismatch → durably rewrite B FIRST → then clear (B KEPT; if the
     rewrite fails, A's debt retained); (x4c') B-rewrite supersession
     (r16 Codex M3 + SMR m1): durable arm C while B's rewrite debt
     pends → stale debt clears; C post-rename failure → debt re-keys
     to C; C pre-rename failure → B's debt stands; the retry NEVER
     rewrites an ArmID-mismatched record; (x4d) record absent →
     DeleteConfirm re-driven (dir-fsync); (x4e) transient read error →
     retain+retry; (x4e') PERMANENT read error — full taxonomy (#5637
     parse gates + crypto/envelope/auth/PRF/master-key) → PER-DEBT
     TERMINAL (that debt stops, the singleton loop KEEPS healing
     `persistDegraded`, health 503, pinned remediation); (x4f)
     same-content re-arm → distinct ArmIDs; (x5) the read-mutate-write
     helper is the ONLY tombstone producer — #5637 gate passes
     unmodified and FirstCommit/Deadline/PrevTree/GuardedHash/
     HashBasis/ArmID preserved exactly (no `Gen` field exists); (x6)
     HASH-BASIS cross-version: legacy NORMAL record upgrade binds;
     canonical NORMAL record downgrade-shape binds (canonical ==
     legacy for normal content); exceptional-content cross-version
     cases documented irrecoverable-by-construction (admitted loss;
     the stale-drop diagnostic hedges "superseded OR
     basis-incompatible"); (x7) SCOPE: byte-identical plain-commit
     supersession (edit-away/edit-back) + removal failure + restart →
     tombstoned record dropped; legacy empty-GuardedHash record
     superseded + removal failure → tombstoned → dropped;
     REPLACEMENT-class resolutions (timeout rollback, SyncApply
     supersede, boot-recovery revert) assert the FAILURE-PHASE
     CLASSIFICATION (r17 Codex M1): PRE-rename replacement-write
     failure → NO tombstone, retained per #5473; POST-rename failure
     → immediate tombstone barrier attempt (success finalizes;
     failure retains BOTH debts); the post-durability finalize DOES
     tombstone before deleting (the failed-SyncApply divergence —
     durable B + lingering binding A — dropped, never reverting the
     synced config); the #5473 tests' retention expectations are
     UPDATED to the new observable semantics; factory reset erases
     state+record tombstone-free; (x8) REAL post-rename seam (r16
     Codex M1): a
     `writeActive` whose rename lands and whose directory fsync
     GENUINELY fails (via `fsatomic.SetAfterRenameSyncDirForTesting`,
     `test_seams.go:9-32` — the selective seam that fails active.json's
     dir-fsync while confirm.json's succeeds, NOT the `modalWriteActive`
     fabricate-after-durable-success seam) → the finalize's successful
     tombstone `WriteConfirm` is the same-directory durability barrier
     (tombstone-durable ⟹ replacement-durable; no durable A-removal
     without a barrier write), tombstone-write failure retains BOTH
     debts; (x9) BOOT RECONSTRUCTION (r16 Codex M4): permanent-class
     corrupt confirm.json at boot → terminal latch set at recovery,
     health 503 ACROSS restart (no laundering); transient-class →
     bounded retry then fail-`Load` per (x13); remediation (clean
     `ReadConfirm` or confirmed absence) clears the latch IN-PROCESS
     per (x12); (x10) health response (r16
     Codex m3): terminal confirm-record state renders the DISTINCT
     message, and the 503 remains election-neutral (no promotion gate,
     crash takeover ungated); (x11) LOAD SEEDING (r17 Codex M2): all
     three `Load` outcomes (absent-DB, compile-failed, success) seed
     the three-state identity; the orphan chain (orphan A + plain
     commit + B pre-rename arm failure + B resolution read error)
     keys the debt on A → retry tombstones it, never preserves it;
     (x12) PROBE OBSERVER (r17 Codex M4 + r18/r19 refinements):
     terminal-latched debt keeps
     the singleton ALIVE probe-only — DEBT-origin clean read →
     identity re-seeded + retry resumed BY KIND (R-kind
     tombstone→delete; W-kind rewrite/restore) IN-PROCESS;
     BOOT-origin clean read → RESTART-RECOVERY-OWED (latch held,
     503 + restart-required message until reboot) or
     SUPERSEDED-WHILE-UNREADABLE (marker → R-kind debt);
     operator `rm` → absent-state re-drive (`DeleteConfirm` barrier
     for R-kind; (w-c) restore-or-stale for W-kind);
     loop exits only
     with no debt AND no latch; (x13) BOOT FAIL-CLOSED (r17 Codex M5):
     TRANSIENT boot `ReadConfirm` failure → bounded retry inside
     `Load` (initial read + ≤3 retries, 100/200/400 ms,
     `LoadContext(ctx)`) → `ErrConfirmStateUnreadable` →
     `classifyLoadError` fail-closed mapping (NOT
     `loadOtherError` — `bootstrap_test.go:10-36` legs); the fatal
     diagnostic names confirm.json; (x14) TYPED HEALTH CHANNEL (r17
     Codex M6/m2 + r18 M7 + r19 m4): `ConfigPersistDegradedState()`
     carries all THREE causes;
     /health precedence terminal > confirm-persist (generic
     removal/rewrite message + debt-kind detail) > active-persist;
     the gauge stays the aggregate OR;
     descriptor/option/wiring comments name all three causes; (x15) TAXONOMY BOUNDARY (r17 Codex M4): master-key
     IO → TRANSIENT retry, no latch; invalid observed key length +
     envelope/auth/PRF/parse → PERMANENT latch; (x16) SAME-RECORD
     DOMINANCE (r18 Codex M2 + r19 Codex M1): W_B + R_B coexisting
     with B's tombstone
     failed PRE-rename (visible record PENDING-shaped) → the retry
     runs R_B FIRST (tombstone barrier → delete) and clears W_B as
     stale — a W_B-first implementation DURABLY RESTORES the pending
     record and the crash-between-debts leg proves the re-arm hazard
     is closed; AND R_A + R_B coexisting → R_A's mismatch branch may
     NOT rewrite current B while R_B exists (the current-record
     removal dominates EVERY write of that record) — the R_A-first
     crash leg proves B never becomes durable before R_B; (x17)
     SEEDED-ORPHAN resolution (r18 Codex M3 + r19 Codex m2):
     absent-DB `Load` with Present(A) → bootstrap/plain commit lands
     durably → the orphan is tombstoned+deleted at the post-durability
     finalize even with NO in-memory window (pre-fix: the orphan
     survives to bind at the next recovery); AND the confirmed-commit
     leg: the arm resolves the orphan BY OVERWRITE; a PRE-rename arm
     failure leaves the orphan INTACT + an R-kind debt keyed A → the
     retry completes the removal; (x18) PROBE ABSENCE
     BARRIER (r18 Codex M4 + r19 Codex M2): operator `rm confirm.json`
     → the probe's
     ENOENT REACTIVATES the absent-state (`DeleteConfirm` re-drive for
     the directory fsync) — only the successful barrier clears the
     latch (a power-loss replay without the fsync resurrects the
     dirent, and the regression proves the re-drive happens);
     (x19) CONTINUATION KINDS (r18 Codex M5 = SMR m1 + r19 Codex M2/M3):
     DEBT-origin clean read → identity re-seeded + retry resumed BY
     KIND (R-kind: tombstone→delete, NEVER a window re-arm; W-kind:
     rewrite/restore, NEVER a tombstone of a live window); BOOT-origin
     → RESTART-RECOVERY-OWED (latch HELD, 503 + restart-required
     message until reboot — never green-while-unsettled) or
     SUPERSEDED-WHILE-UNREADABLE (marker set by a durable replacement
     during the latch → clean read converts the record to an R-kind
     debt → tombstone→delete → latch clears); (x20) FAIL-CLOSED
     ROUTING (r18 Codex M6 = SMR M1 + r19 Codex m3):
     a transient-exhausted boot
     confirm-read returns `ErrConfirmStateUnreadable`;
     `classifyLoadError` maps it to the fail-closed class (NOT
     `loadOtherError` — `bootstrap_test.go:10-36` legs); the fatal
     diagnostic names confirm.json; the pinned envelope (initial read
     + ≤3 retries, delays 100/200/400 ms, `LoadContext(ctx)` with
     `Load()` preserved, clock seam) is asserted;
     (x21) THREE-FIELD HEALTH PRECEDENCE (r18 Codex M7/m5):
     `ConfigPersistDegradedState()` carries all three causes; /health
     renders terminal > confirm-persist > active-persist; the gauge
     stays the aggregate OR (never healthy-while-gauge-1); the
     Config → NewServer plumbing test pins both callbacks wired.
3. Update `daemon_natpoolalarm_race_test.go` (`writeDPFor` →
   `setDataplane`) and `daemon_forwarding_status_test.go` (rewrite against
   the narrowed adapter: `ProjectsMapStats`/`UsesUserspaceStatusAdapter`
   move to asserting `CachedStatus` per-call probing;
   `UsesCurrentDataplaneAfterSwap` maps onto the narrowed shape with
   `setDataplane` swaps).
4. Scoped race gate: new `test-race-dp` make target —
   `go test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit' -count=2`
   — invoked from `test-go` (r1/r2: plain `go test ./...` has no race
   teeth; full-repo `-race` stays out of scope).
5. Canary tests: redesigned matcher self-tests both directions; new
   `daemon_dp_canary_test.go` asserts no direct `dpCell` access outside the
   accessors.
6. `make test` explicitly (Go + Rust legs), plus the full Go suite.
7. Smoke gates (engineering-style.md:93-103 — NOT waivable; r2 Codex M6
   specifics folded):
   - `make test-deploy` on the standalone VM + ping with **0% loss**.
   - `make cluster-deploy` on the loss userspace cluster, then RE-APPLY CoS
     (`./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` — deploy
     wipes CoS, engineering-style.md:422), then `iperf3 -P 16 -t 30 -p 5203`
     to `172.16.80.200` with **≥23 Gbit/s, no regression** vs the pre-change
     baseline.
   - `make test-failover` AND `make test-ha-crash` (mechanical
     `daemon_ha*.go` touches mandate both per CLAUDE.md), with explicit
     HA loss/convergence criteria recorded in the PR (failover <1s traffic
     loss, cluster reconverges, no stale dataplane state) — all under the
     #1875/`with-cluster.sh` lock discipline.
8. Bootstrap-window coverage stays unit/`-race`-level (no bootstrap
   integration env; same as #2116).

## 10. Out of scope (explicitly)

- Option B (write-once `d.dp` / degraded-adapter semantics).
- Swapping capture-once consumers (GC, event stream) to per-tick re-probe.
- `pkg/grpcapi` / `pkg/cli` boot-captured forwarding-status probes (stale
  after a daemon-side transition, never racy — separate consistency
  follow-up if wanted).
- The `apply.go:29` TODO (HA session sync → `SessionDeltas()` migration).
- `pkg/fwdstatus` `Build`/`Format` internals (the ONLY fwdstatus change is
  the `CachedStatusProvider` narrowing in `sampler.go` + its test).
- Any Rust/helper change; dataplane hot-swap/re-arm support (the accessor
  ENABLES it safely later).
- Full-repo `go test -race` wiring.
- **Broader cluster-runtime lifecycle question (follow-up issue, filed at
  /engineer time)**: should `enterBootstrapMode` stop cluster comms when
  `d.cluster != nil`? The permanent recovery invariant (work item H) ships
  in this PR and prevents the bootstrap-with-cluster state from persisting
  past the next boot; the lifecycle redesign is a pre-existing policy
  question, not a `d.dp` publication concern.

## 11. Open questions for adversarial review (r20)

Resolved in v2-v9 (for the record): A2 deletion; atomic cell choice;
sampler-only adapter — now STRUCTURAL via `CachedStatusProvider`;
policy-invalidate APPLY-class; HA smoke gates mandatory + specific;
typed-nil kind-gated guard over all nillable kinds with a table-driven
matrix; docs scope (README architecture + :936 + docs/ sweep + stale
comments incl. the r3/r4/r5 additions + `_Log.md`); audit table
completeness AND exact count (134 = 5 + 129) with consistent per-row
exposure cells and narrowed preamble; deterministic real-sampler barrier
as a two-sided gate with a bounded sustained-quiescence teardown;
bootstrap/cluster exclusion scoped to current-version records with the r6
cross-upgrade coexistence documented; RACE-1 scoped to the
pre-publication watcher chain INCLUDING the blackhole→readiness hop;
RACE-3 documented; the pre-existing startup-ordering defect addressed by
work item G — `finishStartup(ok)` Once-guarded outcome publisher (no
double-close, no leak on any exit path, no rollback against partial
init), linearization at END of PHASE 5 (all server construction complete;
serving concurrency is ordinary steady-state), constructor
initialization, fixture migration (ALL executor fixtures —
`rollback_resync_test.go:31,81`, `bootstrap_rollback_test.go:24,74`,
`rollback_serialize_test.go:71,150,201,247` — plus open-gate
initialization for the `runStartupOrAbort` fixtures
`startup_signal_5807_test.go:118,157`), contract-comment updates, gate
tests with entry hook + dual real failure paths + backend-factory seam +
phase-level orchestration + late-manager milestone; r8 additions: the
`stopping` shutdown-admission fence (published before the applySem drain,
re-checked under applySem — closing the gate-release-vs-teardown race
Codex proved against the v8 "applySem-ordered" claim), the Run-scoped
`defer d.finishStartup(false)` panic/unwind backstop, and the corrected
gate-before-applySem rationale (the executor must not hold applySem
ACROSS its gate-wait); work item G lands as a separate prerequisite
commit in the same PR/stack (OQ6); work item H REDESIGNED in v9 as a
PERMANENT recovery invariant with revert-at-Load semantics — placed after
the expired branch (expired records untouched), reusing the
expired-branch FirstCommit revert body, terminating the r8
current-version regeneration chain, honoring #4577 (an unconfirmed
config never stands) — with five tests including the expired-record
negative case and the recurrence test; broader cluster-lifecycle work
defers to a follow-up; fwdstatus deletion inventory completed (`var _`
assertion, userspace wrapper, `userspaceStatusProbe`) with a
negative-satisfaction unit test; §5.1 package-touch list corrected
(work item H touches `pkg/configstore`); r9 additions: the shutdown
guard is a DETERMINISTIC DOUBLE CHECK (`d.stopping.Load() ||
d.runCtx.Err() != nil` under applySem — ctx-driven server teardown at
signal time made a PHASE-7-only flag insufficient; interactive-exit
keeps the flag arm), invariant 11's honest in-flight bound (5 s drain,
pre-existing overlap admitted), work item H's predicate on the
AUTHORITATIVE compiled topology (apply-groups positive / inactive
negative tests (vi)/(vii)), fence-test actual-path leg (5523 pattern),
recovery-contract docs join the sweep (`store_persist.go:127-135`,
`pkg/configstore/README.md:417-449`), monotonic single-use lifecycle
documented, fence check joins `isResetting()`, distinct guard-path
journal/slog text; r10 additions: `stopping.Store(true)` as the FIRST
statement of `runShutdownSequence` (before `applyCancel`, with an
injected-applyCancel ordering assertion), cancellable
`Acquire(runCtxOrBackground())` with error check (no parked executor
through teardown), nil-safe double guard + `runCtx` fixture
initialization + signal-child wiring-test leg, the narrowed "not
worsened" claim (admission timing shift admitted), the GuardedHash
pre-migration binding capture (closing the verified pre-existing #5835
inactive-retired-leaf stale-drop that also bypasses H), the
bootstrapFromFile DOCUMENTED-CONSISTENCY adjudication (import
suppression rejected; parity regression (ix)), `db.go:161-168` into the
docs sweep; r11 additions: the RESOLUTION TOMBSTONE (work item H2 —
resolution paths write `Resolved: true` into confirm.json BEFORE
deletion, recovery drops tombstoned records, closing the verified
master re-arm-after-confirmed residual for ALL record classes and
protecting H from reverting a confirmed config; Codex + AGY both
ACCEPTED the M3 bootstrapFromFile adjudication), the CANONICAL binding
basis (`canonicalConfigHash = sha256(Format(jsonRoundTrip(tree)))` at
both arm and recovery — closing the invalid-UTF-8 divergence Codex
proved against the v11 pre-migration capture), terminology corrected to
"canonical decoded-tree Format() basis", regression viii strengthened
to arm through the production commit path; r12 additions: the
envelope claim corrected to the additive-JSON-field contract with
DECIDED downgrade semantics (three reviewers converged independently),
read-mutate-write full-record tombstones (minimal tombstones rejected
— they trip the #5637 gate and wedge recovery), tombstone-first
linearization (the durable write is the resolution linearization
point; the irreducible write-fail+crash residual documented),
generation-safe removal debt (arm supersedes by overwrite — the
master retry could otherwise destroy a fresh pending record),
VERSIONED hash basis (`HashBasis: "canonical-v1"` + dual-basis
recovery compare — the basis transition itself no longer
stale-drops), arm-site inventory corrected (sole arm:
`writeConfirmState`); r13 additions: the tombstone is SCOPED to
keep-active confirmations only (content-changing supersessions rely on
the #5835 stale-drop; replacement/rollback resolutions keep #5473
durable-intent semantics — tombstoning there would destroy rollback
intent), the removal debt is IDENTITY-KEYED (match → act; mismatch →
clear — phase-safe across all WriteConfirm failure modes, no eager
arm-time clearing), the cross-version story is honest (normal records
bind both directions — canonical == legacy when nothing diverges;
exceptional-content cases admitted irrecoverable-by-construction with
loud logs, dual-hash evaluated and rejected as equivalent), record
inventory corrected (`FirstCommit`, no `Gen`), downgrade bound
corrected (deadline, not retry loop), `wrapEnvelope` cite corrected
(active/candidate/rollback, never confirm.json); r14 additions: the
tombstone scope re-based to the BINDING-AMBIGUITY/IDEMPOTENCE
predicate (confirm-type resolutions — keep-active confirms AND
content-changing supersessions — get the tombstone, closing the
byte-identical-supersession and legacy-empty-hash holes; idempotent-
revert replacements keep #5473; factory reset listed as class 0), the
keyed debt is a FOUR-STATE machine (match → act; absent →
DeleteConfirm to finish the dir fsync; mismatch → clear; read error →
retain+retry), the debt identity is a persisted opaque `ArmID`
(same-content hash collisions and clock-adjusted deadline collisions
eliminated), the no-record-at-resolution NO-OP branch pinned (SMR m1
= AGY nit1), the irreducible-residual wording corrected (hazard
resolves at next boot, not the deadline), the stale-drop diagnostic
hedges its cause, factory reset joins the exhaustive inventory; r15
additions: the idempotence premise CORRECTED (a replayed revert is
config-state idempotent but NOT runtime-state idempotent — AF_XDP
re-attach, dataplane `config_generation` bump invalidating the flow
cache, FRR reload, possible heartbeat restart — so retention without
tombstone is safe only PRE-durability and the rule is now UNIFORM:
every `resolveConfirmRemovalLocked` tombstones first; replacement
paths retain per #5473 and tombstone at the post-durability finalize),
the failed-SyncApply divergence closed (durable B + lingering binding
A → dropped at recovery via the finalize tombstone), `pendingArmID`
in-memory identity (arm stores, recovery restores — the keyed debt is
constructible even on resolution-time read errors), the mismatch
state gains a B-durability precondition (durably rewrite B before
clearing A's debt; `writeConfirmState` post-rename failure raises a
B-rewrite debt), typed retry errors (transient → retry; #5637
semantic → TERMINAL degraded + manual remediation), H2 intro and §5.1
consistency (store.go added); r16 additions: the debt identity model
completed to TWO fields with explicit update rules (`armedArmID` window
identity — set at arm, restored at readable recovery, cleared at
resolution; `onDiskArmID` known-on-disk identity — updated ONLY by
write outcomes + recovery; debts key on the latter, closing the
nested-arm miskeying Codex proved against the single-field model), the
B-rewrite debt's A/B/C supersession transitions derived from the model
(stale-key clearing, re-key transfer, rewrite-on-match/never-on-mismatch
— SMR m1's pin), the post-rename finalize durability barrier stated
honestly (the tombstone `WriteConfirm`'s directory fsync covers the
earlier same-directory active.json rename — tombstone-durable ⟹
replacement-durable; the double-failure namespace-replay residual
admitted; the (x8) regression drives the REAL post-rename seam, not the
#5473 fabricate-after-durable-success seam), the terminal taxonomy
completed to the FULL permanent `ReadConfirm` error set (#5637 parse
gates + crypto/envelope/auth/PRF/master-key) with a PER-DEBT terminal
latch (the singleton loop keeps healing `persistDegraded`), boot
reconstruction (a permanent-class recovery read failure sets the latch —
no 503→healthy laundering), pinned remediation (clean `ReadConfirm` or
confirmed absence clears), the election-neutral terminal-503 policy
stated explicitly + a distinct terminal confirm-record health message
(`pkg/api` touched — declaration corrected), the H2 classification
contradiction repaired (SyncApply is unequivocally replacement-class),
and the NAT64 churn citation corrected (flow-cache eviction at lookup
`flow_cache.rs:992-999` with NAT64 excluded :385-393; fragment
associations age under their own `nat64.rs` generation guard); r17
additions: the durability barrier GENERALIZED into a failure-phase
classification on every replacement path (PRE-rename → retain per
#5473 with NO tombstone attempt; POST-rename → immediate tombstone
barrier attempt via the existing `isPostRenameDurabilityFailure`
check — success proves the replacement durable and is #5473's
witness, failure retains both debts; the #5473 tests' observable
retention expectations updated), closing the single-failure
SyncApply restart hole Codex proved against the x7 closure; the
identity model's missing edges closed (`Load` reads confirm.json on
EVERY outcome — absent-DB, compile-failed, success — seeding a
three-state Present(ArmID)/Absent/latch identity so "" is only ever
a PRESENT legacy record's value; the orphan-record lifecycle
documented); the debt-set claim corrected (the false ≤1+1 bound
deleted — MULTIPLE removal debts + at most one rewrite debt, STRICT
per-pass convergence); the terminal machine repaired at both ends
(master-key IO reclassified TRANSIENT — only invalid OBSERVED key
length is permanent; the remediation transition gains a LIVE
probe-only observer: the latch keeps the singleton alive read-only,
a clean read clears + re-arms, a confirmed absence clears + drops);
the pre-existing transient-boot #4577 hole closed (bounded retry
inside `Load`, then `Load` FAILS — fail-closed; PERMANENT-class
keeps proceed+latch+503 with the bricking alternative and the
auto-revert hammer both rejected); the health channel made
cause-bearing (`ConfigPersistDegradedState()` typed snapshot + a new
wiring callback — initially framed as a functional option, corrected
to a Config FIELD in r18; /health precedence terminal-confirm-record >
active-persist; the gauge stays the aggregate OR with the
descriptor/option/wiring comments updated to name both causes); the
residual broadened to replacement-POST ∧ barrier-failure-in-any-phase
∧ restart; the SyncApply confirm-type source terminology swept
(`store.go:716-717`, `pkg/configstore/README.md:663-672`); SMR r17
m1 folded (the rewrite debt is raised ONLY by the arm path — a
post-rename failure of a resolution-side or retry-side `WriteConfirm`
retains the ORIGINATING debt); r18 additions: the convergence
guarantee restated CONDITIONALLY (strict reduction given quiescence +
successful I/O; no liveness claim under churn), SAME-KEY removal
dominates rewrite (R subsumes W; the crash-between-debts regression
x16), SEEDED-ORPHAN resolution by every superseding replacement even
with no in-memory window (x17), the probe confirmed-absence
`DeleteConfirm` barrier re-drive (x18), latch-origin continuation
kinds (DEBT-origin resume vs BOOT-origin defer-to-next-boot, x19),
the fail-closed boot path ROUTED via a new `ErrConfirmStateUnreadable`
sentinel + `classifyLoadError` mapping + confirm.json-named diagnostic
+ pinned retry envelope + stated management posture (x20), the
THREE-field health snapshot `{ActivePersistDegraded,
ConfirmPersistDegraded, ConfirmRecordTerminal}` with precedence and a
Config-field plumbing test (x21), the STAGED barrier outcome
(tombstone success + unlink failure retains only the delete-finishing
debt), the probe lifecycle posture, and the docs sweep completed
(README.md:476-540, pkg/api/README.md:30-36,
store_commit.go:556-570,667-695,732-735, health.go:10-16,
bootstrap.go:36-47); r19 additions: same-RECORD dominance (while any
R-kind debt keys the current record, NO other write of it runs — the
r18 same-key rule generalized to cover stale-keyed mismatch rewrites;
x16 gains the R_A-first crash leg), DEBT-KIND SPLIT (R-kind four-state
removal table vs W-kind three-state rewrite table — never a tombstone
of a live window's record, never an abandoned recovery file), BOOT-origin
persistent substates (RESTART-RECOVERY-OWED keeps the latch + a
restart-required 503 until reboot; SUPERSEDED-WHILE-UNREADABLE marker
converts the repaired record to an R-kind debt), confirmed-commit
orphan resolution BY OVERWRITE (pre-rename failure → orphan intact +
R-kind debt; x17 leg), the lexicographic remaining-stage convergence
measure with tombstone-required-dominates-delete-finishing merge
semantics, the envelope arithmetic (initial read + ≤3 retries,
100/200/400 ms, `LoadContext(ctx)` with `Load()` preserved), the
GENERIC confirm-persist health message + debt-kind detail, the sweep
gaining db.go:239-241 + README.md:470-473,937-968 and the
three-cause "BOTH" correction, the single-Store-ownership invariant
documented for the orphan premise, and Codex's SPLIT-REJECTED
reasoning recorded (H-without-H2 turns the delayed master hazard into
an immediate revert-at-load — the only sound split moves H WITH H2).

Still open:

1. **PLAN-KILL fork**: with RACE-1 (watcher chain), RACE-2 (bootstrap-exit)
   and RACE-3 (recovered confirm timer) all proven structural, does any
   reviewer still judge the ~244-site conversion (134 prod + ~110 test)
   unjustified? A PLAN-KILL here means accepting all three races as
   documented known-issues — state the reasoning explicitly if so.
2. The `CachedStatusProvider` narrowing (§4 A1) is the one intentional
   public-signature change (`fwdstatus.NewSampler`). Any objection, or an
   alternative that keeps the adapter structurally excluded from `Build`
   without touching `pkg/fwdstatus`?
3. The `armBootstrapExitDataplane` extraction splits
   `runBootstrapExitStartup` for testability. Any objection to the helper
   boundary (naming/sysctl stay in the caller; arm+seed+monitor+nil in the
   helper)?
4. The new `dpCell`-access AST canary in `pkg/daemon` — accepted
   enforcement mechanism (precedent: the retirement canary), or do
   reviewers want a lighter `grep`-based `make` check instead?
5. `test-race-dp` wiring into `test-go`: acceptable growth of the
   pre-commit gate, or documented-manual-gate only?

---

*Review ledger: see `reviewer-ids.md`. Round docs: `claude-smr-plan-r<N>.md`,
`codex-plan-r<N>.md`, `agy-plan-r<N>.md`.*
