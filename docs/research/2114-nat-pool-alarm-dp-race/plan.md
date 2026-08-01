# #2114 (residual): publish `d.dp` through one synchronized accessor — plan-of-action

- **Status**: DRAFT v62 — r61 findings folded (Codex NEEDS-REVISION
  5M/3m; AGY PLAN-READY; Claude SMR PLAN-READY-WITH-NITS 0M/1m
  — the alias-collapse pin, IS Codex M4; all three confirm
  the §4.7 structure); pending convergence review r62
- **Issue**: psaab/xpf#2114 (OPEN; `bug`, `audit`)
- **Branch**: `research/2114-nat-pool-alarm-dp-race` (plan docs only — NO
  production code in `/research`)
- **Base**: origin/master @ `ed6999000`
- **Mode**: `/research` — stops at PLAN-READY. Implementation requires manual
  `/engineer 2114`.
- **Delivery** (r28 split ruling, §4.7): TWO units — the #2114 PR ships
  the `d.dp` accessor core (work item A1 + the full site conversion +
  canaries + sampler narrowing); the named follow-up issue ships
  G+H+H2 (startup-readiness gate + FirstCommit+cluster Load recovery +
  confirm-record durability machinery) seeded from this document.
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
  stale-clear — the (w-u) UNREADABLE-slot restore-over leg joins
  in r23, making it four-legged); absent-for-W is NO-OP-and-clear
  ONLY when a same-key
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
  v21: r20 convergence — the last three structural pins land (Codex
  3M/3m; SMR's r20 M1 CONVERGED with Codex M2 on the marker-loss
  hole; AGY PLAN-READY with its attack-3 rationale again covering
  only the non-binding sub-case): (a) the W-kind debt re-keys to the
  LIVE window at EVERY arm outcome (Codex M1 [NEW], verified: the
  on-disk-keyed transition (iv) let W_B durably rewrite B while C
  was LIVE — a nested arm stops the prior timer and installs the new
  generation/deadline/timer, `store_commit.go:470-524` — producing a
  stale-drop that leaves C recordless or a re-arm of B's OLD
  deadline): the debt keys the live window's DESIRED record;
  durable arm → no debt; post-rename → make durable; pre-rename →
  restore; a nested arm re-keys (the dead window's W is stale); the
  restore's overwrite consumes the dead record; and the arm retains
  the immutable attempted record `s.armedRecord` (Codex m1 — the
  in-memory pending state carries no absolute deadline or hash,
  `store.go:168-179` — the restore is VERBATIM, never a
  recomputation). (b) The SUPERSEDED-WHILE-UNREADABLE marker is
  REPLACED by eager durable deletion at the landing (Codex M2/M3 =
  SMR M1 — the marker is lost at restart, the restart-before-repair
  chain replays a repaired stale record into a binding re-arm on
  content match or legacy empty hash, and the marker was unscoped
  across confirmed arms): a plain commit/SyncApply landing durably
  with the BOOT latch standing DELETE the unreadable confirm.json +
  dir-fsync barrier at the post-durability point (no tombstone
  possible or needed for an unparseable record); a confirmed
  commit's successful arm overwrites, and its PRE-rename failure
  applies the same delete rule (master's best-effort arm posture,
  `store_commit.go:548-553`); the probe's confirmed-absence barrier
  then clears the latch — no restart can resurrect a superseded
  record. (c) The health snapshot becomes
  `{ActivePersistDegraded, ConfirmDebtKindMask (REMOVAL|REWRITE),
  ConfirmRecordState (OK|TerminalUnreadable|RestartRecoveryOwed)}`
  with precedence TerminalUnreadable > RestartRecoveryOwed >
  ConfirmDebt > ActivePersist (Codex m2 — three booleans could not
  carry the promised subtypes — WriteUnverified joins between
  ConfirmDebt and ActivePersist in r32/r33). Stale-expectation repairs (Codex
  m3): the x9 legs no longer claim an in-process boot-latch clear
  (substate-keyed remediation), the x11 seeding legs name the
  transient/permanent class split, and the docs sweep says THREE
  new schema fields (`Resolved`, `HashBasis`, `ArmID`).
  v22: r21 convergence — the ordering and eager-delete semantics are
  completed (Codex 3M/2m; AGY PLAN-READY; SMR PLAN-READY-WITH-NITS —
  its handoff-window nit is subsumed by (a)): (a) dominance is
  SCOPED and the restore is PRIORITIZED (Codex M1, verified the v21
  restore-last reading created the worse recordless-live-window gap:
  R_B's tombstone→delete lands, crash before W_C's restore → B
  dropped as Resolved, durable active C, NO recovery record — an
  unconfirmed config silently permanent): D1 — an R-kind debt
  dominates every IDENTITY-PRESERVING write of its record (W-kind
  rewrites keyed to it, stale-keyed mismatch rewrites); D2 — a LIVE
  window's restore is a SUPERSESSION, not a write of that record —
  it replaces the dead record with `s.armedRecord`, runs FIRST, and
  the pending R_K clears on the restore's dir-fsync (the restore's
  barrier covers K's removal); a restore failure returns K to D1's
  tombstone→delete. The crash cases collapse to the admitted
  residual class — never a recordless live window. (b) The eager
  supersession is a TWO-STEP SYNTHESIZED TOMBSTONE + DELETE with a
  D-KIND SLOT DEBT (Codex M2, verified the bare-delete happy-path
  critique: unlink can fail either side of the fsync, no ArmID-keyed
  debt can name an unreadable record, and a crash-replayed dirent
  re-opened the binding chain): `WriteConfirm` a full-field
  `Resolved:true` record with NON-DEGENERATE synthetic fields
  (passes #5637 unmodified; `PrevTree` = clone of the current active
  tree — a no-op revert if ever misread; `Deadline` non-zero;
  `GuardedHash` = canonical hash of the current active; fresh
  `ArmID`) — any replay drops at the Resolved-first check — then
  `DeleteConfirm`; any failure raises the D-kind slot debt (keys the
  SLOT, not an ArmID) retried by the same loop; the residual is the
  already-admitted tombstone-write-failure ∧ crash-before-heal
  class; the confirmed-commit pre-rename case is handled by the
  W-kind restore REPLACING the unreadable record (no tombstone
  needed — the restore IS the tombstone-equivalent). (c) The
  contradicted v20 remnants are swept (Codex M3/m1/m2): the two
  identities are split explicitly (R-kind debts key RECORDS via
  `onDiskArmID`; the W-kind debt keys the LIVE WINDOW via
  `armedArmID`/`s.armedRecord`), both x4c' regression copies now
  state the live-window re-key + restore-overwrite (ArmID-mismatch
  overwrite is the POINT), the §9 x19 copy loses the marker
  workflow, the health legs carry the four-level precedence
  (TerminalUnreadable > RestartRecoveryOwed > ConfirmDebt >
  ActivePersist — WriteUnverified joins between ConfirmDebt and
  ActivePersist in r32/r33) with the enum + mask, and §6 says THREE new
  degraded messages (grown to FIVE in r29 and SIX in r32/r33).
  v23: r22 convergence — the D-kind machinery and the acceptance text
  are completed (Codex 4M/3m; SMR's r22 M1 CONVERGED with Codex M2 on
  the D-kind retry hazard; AGY PLAN-READY with its attack-1 rationale
  again assuming the unspecified clear transition): (a) the remaining
  R-first table copy is rewritten to D2 (Codex M1). (b) The D-kind
  retry RE-READS and RE-CLASSIFIES (Codex M2 = SMR M1, independently
  walked: an arm landing between the debt's raise and its retry
  installs a LIVE window's record on the slot, and an unconditional
  re-run would synthesized-tombstone and delete it): still-unreadable
  → proceed; absent → `DeleteConfirm` re-drive → clear; READABLE →
  clear as moot (the superseded unreadable record was already
  replaced) and the readable record follows its normal path; a
  successful arm on the slot clears the debt as moot. (c) The D-kind
  debt is PROCESS-LOCAL with operator-mediated crash remediation
  (Codex M3 — the retry is abandoned on exit, BOOT-origin is "no
  timer, no debt", and auto-recreating D at boot would delete
  genuinely-pending records the boot cannot distinguish): a
  pre-tombstone crash reconstructs the LATCH and the runbook governs;
  the residual is the admitted tombstone-write-failure ∧
  crash-before-heal class with an operator-paced heal for this one
  case. (d) The acceptance text is swept (Codex M4): all three
  x12/x19 bare-delete copies now state the two-step synthesized
  tombstone + D-kind debt, and all four "ONLY tombstone producer"
  copies are scoped (the read-mutate-write helper is the only
  READ-BACK producer; the synthesized producer writes only the
  superseded-UNREADABLE slot — full fields, not the rejected minimal
  form). (e) The recordless guarantee is SCOPED (Codex m1):
  restore-first ORDERING never creates the gap; a restore FAILURE
  returns K to D1, and a subsequent R_K delete + crash before the
  next SUCCESSFUL W restore (failed passes do not close the gap)
  is the admitted best-effort arm-persistence residual.
  (f) The synthetic record's pins land (Codex m2 = SMR m1):
  `FirstCommit=false` (LOAD-BEARING per r24 Codex M2 — on the NEW
  reader `Resolved` precedes H; on the OLD reader `FirstCommit=true`
  forces `compiled=nil` + `everCommitted=false` + `committed=0` →
  bootstrap handling), `Deadline` = now + 60 s exactly, and the
  downgrade behavior is documented (config-state neutral,
  runtime-churning, self-limiting) with a downgrade-shape regression.
  (g) The health schema carries D (Codex m3): the mask gains
  `SLOT_DELETE` and the aggregate is defined as the OR of
  `persistDegraded`, every confirm-side debt kind, and the latch.
  v24: r23 convergence — the last classification pins land (Codex
  2M/3m; SMR's r23 m1 CONVERGED with Codex M1 on the (d-i) transient
  boundary; AGY PLAN-READY): (a) the D-kind retry's read split is
  completed (Codex M1 = SMR m1 — an arm C may have become VISIBLE
  through a post-rename failure while D pends, and a transient
  EACCES/short-read/master-key-IO error cannot distinguish
  A-unreadable from C-visible): (d-i) proceeds with the synthesized
  tombstone ONLY on a CONFIRMED NON-KEY-CLASS-PERMANENT slot read
  failure (the r26 key-class gate below);
  (d-i') a TRANSIENT read failure RETAINS the debt UNTRIED — no
  write, no delete — with a dedicated regression; the acceptance
  copies are restated to the qualified split. (b) The W-kind table
  gains (w-u) and the W-before-D priority (Codex M2 — the tables
  defined only readable match/differ/absent while the global
  taxonomy terminalized the read): record UNREADABLE
  NON-KEY-CLASS-PERMANENT → restore `s.armedRecord` over the slot
  (the rename needs no read; KEY-CLASS and any
  missing/unreadable key file BLOCK the write —
  `readOrCreateMasterKey` would auto-create a fresh key and launder
  the unreadable-active state); W runs BEFORE the slot-keyed D — a
  successful restore installs the live record and subsumes D as
  moot; a restore FAILURE returns the slot to D's (d-i) path
  (SUPERSEDED in r25: a failed W restore RETAINS the W debt — write
  failures never terminalize — and D stays SUPPRESSED while W
  pends; D re-evaluates the slot FRESH only when W resolves); crash
  regression drives both. (c) The recordless claim is scoped
  everywhere (Codex m1 — invariant 12's "no recordless live window
  ever" became "restore-first ORDERING never creates the gap", and
  the restore-failure → R-delete → crash-before-next-SUCCESSFUL-W
  (failed passes do not close the gap)
  arm-persistence residual joins the residual set). (d) The
  synthetic record's remaining pins (Codex m2): `HashBasis` =
  `"canonical-v1"` (the hash's actual basis, never a "current"
  default); the downgrade regression is scoped to NORMAL content
  (legacy-basis binds → re-arm → revert-to-identical → consumed)
  with the exceptional-content leg asserting the stale-drop; and
  the `FirstCommit=false` rationale is corrected (on the NEW reader
  `Resolved` precedes H; the load-bearing case is the OLD reader's
  EXPIRED-first-commit path, where `FirstCommit=true` would revert
  to the EMPTY tree instead of the no-op revert to `PrevTree`).
  (e) The health schema is unified (Codex m3): the snapshot is
  exactly `{ActivePersistDegraded, ConfirmDebtKindMask
  (REMOVAL|REWRITE|SLOT_DELETE), ConfirmRecordState
  (OK|TerminalUnreadable|RestartRecoveryOwed)}` — r28 grows TWO
  NON-SECRET cause fields: `ConfirmDebtKeyClassMask` (per-debt
  key-class cause — r29 refines: each debt's state is the class of
  its LATEST retained failure and the mask is DERIVED OR-by-kind
  over live debts) and
  `ConfirmRecordKeyClass` (the latch-level cause) — and the aggregate
  `ConfigPersistDegraded()` is a DERIVED value
  (`persistDegraded || mask ≠ 0 || enum ≠ OK`), not a snapshot
  field.
  v25: r24 convergence — the doctrine contradictions are resolved
  (Codex 2M/4m; AGY PLAN-READY; SMR PLAN-READY-WITH-NITS — its two
  nits are subsumed by (a) and (e)): (a) the permanent-error state
  machine is unified (Codex M1, verified the self-contradiction:
  (w-u)/(d-i) require repair writes after PERMANENT read failures
  while the taxonomy terminalized every such debt): terminalization
  is SCOPED to CONTENT-DEPENDENT debts (the R-kind read-back
  tombstone — a permanent read makes its action impossible, and
  auto-erasure would hide a corruption the operator should inspect);
  CONTENT-INDEPENDENT debts (W-kind restore from `s.armedRecord`,
  D-kind synthesized tombstone) are EXEMPT — their purpose is
  precisely to overwrite a provably-superseded unreadable record;
  and WRITE failures on ANY debt kind NEVER terminalize (retain +
  capped-backoff retry + degraded health — a read-only filesystem
  loops at 503, the intended loud posture; the invalid-master-key
  case fails both read and write and loops degraded until the
  operator repairs the key). (b) The downgrade oracle is corrected
  (Codex M2, verified: recovery assigns `s.active = rec.PrevTree`
  ALWAYS — the synthetic `PrevTree` = current tree is content-right
  either way; `FirstCommit=true` on the OLD reader forces
  `compiled=nil`, `everCommitted=false`, `committed=0` →
  FIRST-COMMIT/BOOTSTRAP handling, NOT an empty-tree revert as v24
  claimed): the regression now asserts serialized `FirstCommit=false`
  + `compiled` present + `committed=1` + NON-bootstrap boot class,
  with the `FirstCommit=true` variant landing in bootstrap handling
  to prove the pin load-bearing. (c) The (w-u) restore failure is
  phase-qualified (Codex m1): PRE-rename → unreadable record stands
  → D's (d-i) (the PRE-rename leg is SUPERSEDED in r25: the W debt
  stays pended and D stays SUPPRESSED — there is NO D path while W
  pends); POST-rename → live C VISIBLE → W stays owed ((w-a))
  and D's mandatory re-read reaches (d-iii) READABLE → clear as
  moot; phase regressions for both legs. (d) The residual wording is
  corrected (Codex m4): the crash must land INSIDE the seconds-wide
  retry window for the loss to materialize — there is NO post-crash
  heal (the process-local W debt dies with the process; the window's
  crash-recovery file is lost outright). (e) The operator-ownership
  posture is pinned (Codex m3 = SMR m2): confirm.json is STORE-OWNED
  — a repaired record is CLASSIFIED, never trusted; sanctioned
  remediations are REMOVAL (confirmed absence) or
  repair-to-valid-then-classify; an arm/restore overwriting a
  differing record is intentional (the single-Store invariant covers
  processes; this pin covers hand edits). (f) The remaining schema
  copies are unified (Codex m2): §5.1 and the x14/x21 copies all
  carry the exact three-value breakdown with the aggregate DERIVED
  (`persistDegraded || mask ≠ 0 || enum ≠ OK`) and the four-level
  precedence.
  v26: r25 convergence — the key-class and W/D-suppression boundaries
  are completed (Codex 2M/4m; AGY PLAN-READY; SMR
  PLAN-READY-WITH-NITS — its two nits were sharpened into (c) and
  (d)): (a) the exemption is scoped BY FAILURE CLASS (Codex M1,
  verified the laundering scenario: a W debt created under key K,
  then master.key replaced by another VALID 32-byte K′ —
  `readOrCreateMasterKey` accepts K′, the restore's `WriteConfirm`
  rewrites the confirm record under K′ and the debt clears — while
  active.json stays encrypted under K: health goes green and the
  next `Load` fails closed on the ACTIVE side): KEY-CLASS permanent
  failures (authentication failure — indistinguishable wrong-key vs
  corrupt ciphertext, master-key IO, invalid master-key length) do
  NOT proceed with repair writes at all — the debt retains and the
  message names MASTER.KEY RESTORATION (the set is REFINED in r26:
  master-key IO moves OUT to the two-sided classification —
  READ-side TRANSIENT, WRITE-side BLOCKED — leaving authentication
  failure + invalid observed key length as the mechanical
  `ConfirmRecordKeyClassError` subtype); and ANY latch/debt clear
  following a key-class failure validates that active.json is ALSO
  readable under the current key before clearing (never the confirm
  slot alone) — GENERALIZED in r26 to EVERY repair action and clear;
  only NON-key-class permanent failures take the
  repair-write exemption. (b) D is FULLY SUPPRESSED while any W
  debt pends (Codex M2, verified the kill-shot: an earlier
  post-rename W attempt may have left LIVE C visible; a later W
  restore failing PRE-rename then leaves C standing — and routing D
  to (d-i) would synthesize a tombstone over a live window;
  concretely, C's config removed `master-password` while
  `s.armedRecord` retains a master-password-bearing `PrevTree` — an
  invalid key length BLOCKS W's encrypted write while D's plaintext
  synthesized tombstone SUCCEEDS — tombstoning and deleting live C)
  — BROADENED in r26 to ANY live window (any W debt pended OR
  `armedArmID != ""`):
  the W debt — or the live window itself — holds exclusive access to
  the slot; D acts ONLY when NO live window exists (the
  plain-commit/SyncApply eager rule); when W resolves, D
  re-evaluates the slot FRESH via
  its re-read classification — never on a stale phase assumption.
  (c) The R terminalization rationale is corrected (Codex m1): the
  payload COULD be synthesized — blind action is unsafe because a
  permanent read error leaves the slot's OCCUPANT unprovable (a
  newer LIVE record may stand where R_K's resolved record used to),
  not because "the owner is known". (d) The key-class remediation is
  operator-correct (Codex m2 = SMR m2 sharpened): the journal
  carries the exact crypto cause and the health detail + runbook
  point at ORIGINAL master.key restoration — never at confirm.json
  blindly — with the explicit warning that removing a record that
  might be a LIVE window's sacrifices its crash recovery. (e) The
  exposure window is stated honestly (Codex m3): seconds-wide under
  TRANSIENT failure but UNBOUNDED up to the confirm window's end
  under a deterministic write failure (invalid key, read-only FS)
  that retries until operator repair — and NO post-crash heal
  either way. (f) The Store-ownership invariant is stated as
  OPERATIONAL (Codex m4): one xpfd per `.configdb/` (systemd unit
  singleton, `daemon.go:1042-1053`) — NO flock exists; documented as
  an assumption with enforcement a follow-up. Partial-copy repairs:
  both x15 legs now split NON-KEY-CLASS (latch) vs KEY-CLASS
  (retain + master.key message); both FirstCommit rationale copies
  corrected (NEW reader: `Resolved` precedes H; OLD reader:
  `FirstCommit=true` → compiled=nil/everCommitted=false/committed=0
  → bootstrap handling); the generic ConfirmDebt message names
  slot-delete; the §5.1 seeding shorthand names the class split.
  v27: r26 convergence — the laundering guard is generalized and the
  D suppression is completed (Codex 3M/1m; AGY PLAN-READY; SMR
  PLAN-READY-WITH-NITS — its master-key-IO nit folded into (c)): (a)
  the active-side validation gates EVERY repair action and clear,
  not just key-class-observed ones (Codex M1, verified the
  absence-path bypass: a pre-rename arm failure leaves the slot
  ABSENT — `ReadConfirm` returns `(nil, nil)` without touching the
  key — so no key-class failure is ever observed, yet the (w-c)
  restore writes C under a swapped K′ and clears while active.json
  remains K-encrypted; a malformed/too-new slot masks the wrong key
  the same way): EVERY W/D repair action (restore, synthesized
  tombstone, delete) AND every confirm-side clear is gated on the
  ACTIVE side being readable under the current key — a healthy
  confirm slot never outruns an unreadable active config; the gate
  is a no-op for plaintext active configs. (b) D's suppression is
  broadened to ANY live window (Codex M2, verified the durable-arm
  gap: a DURABLE arm creates no W debt, yet the window is live —
  and if the active-validation rule blocks D's (d-iii) moot-clear,
  D stays alive beside the window, routable to (d-i) by a later
  non-key permanent read error): D NEVER acts while any W debt
  pends OR `armedArmID != ""`; it acts ONLY when no live window
  exists (the plain-commit/SyncApply eager rule). (c) The taxonomy
  is made mechanically consistent (Codex M3 = SMR m1): the sentinel
  family gains a `ConfirmRecordKeyClassError` subtype
  (authentication failure + invalid observed key length) consumed
  via `errors.As` — the key-class rule never string-matches; every
  repair-permitting copy now says NON-KEY-CLASS-PERMANENT; and
  master-key IO carries the TWO-SIDED classification (READ-side
  TRANSIENT per the r17 taxonomy — a missing mount/EACCES is
  recoverable; WRITE-side BLOCKED — `readOrCreateMasterKey`
  AUTO-CREATES and persists a fresh key on `IsNotExist`,
  `crypto.go:457-479`, so a repair write with the key file missing
  would encrypt under a NEW key and launder the state). (d) The
  key-class remediation is representable (Codex m1): the path is
  corrected to `<confdir>/.configdb/master.key`
  (`masterKeyPath()` = `filepath.Join(db.dir, "master.key")`,
  `crypto.go:34-35`, `store.go:302-305`), and the health DETAIL
  field carries a key-class indicator (from the retained failure's
  `errors.As` check) so the operator-facing guidance names the real
  remediation — restore the ORIGINAL key — never at confirm.json
  blindly. (e) The residual partial copies are swept (Codex
  fold-verification items 1/3/4/5/7): the R-kind contrast no longer
  says "the corrupt record's owner is known" (a permanent read error
  leaves the slot's occupant UNPROVABLE — the occupant-uncertainty
  rationale holds uniformly); the arm-persistence residual copy no
  longer promises a seconds-wide next-pass restore (the W retry has
  NO success guarantee and dies with the process — seconds-wide
  under TRANSIENT failure, UNBOUNDED up to the confirm window's own
  end under a deterministic write failure, NO post-crash heal); the
  §5.1 `pkg/api` inventory and the docs-inventory aggregate-cause
  copy name removal/rewrite/SLOT-DELETE; every repair-permitting
  summary table (the v24 history (d-i) half, the §11 r22/r23
  addition copies, the §11 (w-u) copy) says NON-KEY-CLASS-PERMANENT
  with the key-class RETAIN leg — no copy authorizes a repair write
  on an unqualified permanent failure; the v25 history entry and the
  §11 cumulative summary are annotated to the r26 refinements
  (master-key IO two-sided, the every-action active-side guard, D
  suppressed while ANY live window exists); and the x15 taxonomy
  boundary copy generalizes its clear guard to every repair action
  and clear.
  v28: r27 convergence — the guard is made EXECUTABLE and the last
  debt-interaction hole closes (Codex NEEDS-REVISION 4M/2m, folds
  0/5 clean — all PARTIAL; AGY PLAN-READY 5/5 with 3 fresh attacks
  FAILED; SMR PLAN-READY-WITH-NITS 0M/1m — its plaintext-write
  over-block nit is folded into (b)): (a) the active-side guard
  becomes an executable THREE-WAY state machine (Codex M1, verified
  the under-specification: an error-only predicate accepts ABSENT
  active state — `ReadActiveMeta` returns `(nil, true, nil)` for a
  missing active.json, `db.go:319-330` — and a non-nil-tree
  predicate blocks the sanctioned both-files-removed barrier):
  (g-ok) tree != nil && err == nil → PROCEED; (g-absent) tree ==
  nil && err == nil → PROCEED only for the sanctioned
  `DeleteConfirm` barrier, WITHHOLD everything else; (g-err) err !=
  nil → WITHHOLD + retain, NO terminalization, the message names
  the ACTIVE side — with IDENTICAL placement at boot (consuming the
  same `ReadActiveMeta` result `Load` already took,
  `store_persist.go:26-35`) and runtime (a fresh read under `s.mu`
  at action time), and the (x23) regression matrix. (b) ALL
  confirm-side repair writes become NO-CREATE, SINGLE-SNAPSHOT
  (Codex M2, verified: every current `WriteConfirm` reaches
  `readOrCreateMasterKey` through `db.go:207-217` +
  `crypto.go:262-270,457-479`, so check-then-ordinary-write left
  the auto-create path live and raced a K→K′ swap): the key is
  sourced via `readMasterKey` (never creates), a missing/invalid
  key file FAILS the write, and ONE key snapshot under `s.mu`
  feeds both the gate's validation and the write's encryption;
  PLAINTEXT repair writes are EXEMPT by construction (SMR m1,
  `crypto.go:262-265` — the write-block predicate IS the encryption
  predicate; a plaintext restore/tombstone/delete performs no key
  access). (c) D's actionable precondition gains the THIRD conjunct
  (Codex M3, verified the undurable-replacement outrun: SyncApply
  cancels live C BEFORE persisting its replacement —
  `store.go:687-717,738-746` — so a PRE-rename failure leaves no W
  and `armedArmID == ""`, yet #5473 retention keeps C's window
  record as the only crash-recovery intent for the still-on-disk
  UNCONFIRMED C; an actionable D would (d-i) tombstone+delete it
  while the active gate PASSES on readable C): D acts ONLY when no
  W debt pends AND `armedArmID == ""` AND `persistDegraded ==
  false`; the precondition is now stated at the D-table head, and
  the (d-ii)/(d-iii) clear legs are gated like every other action.
  (d) The key-class subtype gets TYPED SOURCES (Codex M4, verified:
  Go's GCM auth error has no exported sentinel —
  `crypto.go:354-356` wraps it untyped, invalid length is a plain
  `fmt.Errorf` at `crypto.go:451-453,460-462`): `crypto.go` gains
  `ErrMasterKeyAuth` + `ErrMasterKeyLength`, each matching
  `errors.As(err, &ConfirmRecordKeyClassError)` AND preserving
  `ConfirmRecordPermanentError`; the four classification boundaries
  are regression-pinned (x24); `crypto.go` JOINS the §5.1 change
  inventory. (e) The health snapshot gains the NON-SECRET
  `ConfirmDebtKeyClass` bool (Codex m2 = fold-partial 4: the
  three-field snapshot + callback payload exposed no key-class bit,
  so the ORIGINAL-key guidance was unrenderable — grown PER-STATE
  in r28 and made PER-DEBT-DERIVED in r29: each debt carries the
  class of its LATEST retained failure and
  `ConfirmDebtKeyClassMask` is the OR-by-kind over live debts, +
  `ConfirmRecordKeyClass` latch-level) populated from the
  retained failure's `errors.As` check — NEVER message text — with
  the key-class `/health` variant regression-pinned against the
  generic one. (f) The acceptance suite gains the DURABLE-ARM
  D-suppression leg (Codex m1 — seed D, land a fully durable arm
  with no W, block the moot-clear, assert D inert) and the
  SyncApply-pre-rename leg (x22). (g) Residual copies swept: the
  arm-persistence residual everywhere says "before the next
  SUCCESSFUL W restore (failed passes do not close the gap)"; the
  v24-history/§11 "a restore FAILURE returns the slot to D's (d-i)
  path" copies are annotated SUPERSEDED-in-r25 (a failed W restore
  RETAINS W; D stays suppressed while W pends); the duplicate x15
  copy generalizes to every repair action and clear; the r24
  phase-qualification's PRE-rename → D leg is annotated SUPERSEDED.
  v29: r28 convergence — the producer inventory completes and the
  delivery structure splits (Codex NEEDS-REVISION 3M/3m, folds 2
  FOLDED / 3 PARTIAL, split ruling (B) with the G-moves-with-H+H2
  ordering constraint; AGY PLAN-READY 5/5 with 3 fresh attacks
  FAILED, split ruling (A); SMR PLAN-READY 0M/0m, split ruling
  (B)): (a) the no-create single-snapshot primitive and the
  active-side gate extend to EVERY non-arm `WriteConfirm` producer
  (Codex M1, verified the v28 list omitted retry-side producers —
  the W (w-a) durable rewrite and the R-kind (a) MATCH tombstone /
  (c) MISMATCH rewrite also reach `readOrCreateMasterKey` via
  `db.go:207-217` + `crypto.go:262-270,457-479`): the complete
  enumeration is (w-a), (w-b)/(w-c), R (a), R (c), D tombstone; the
  ordinary arm write keeps create-on-first-use (the #1894 fresh-box
  design); x23 covers the full producer matrix. (b) The key-path
  generation residual closes (Codex M2, verified: one byte snapshot
  proves nothing about the unlocked `master.key` PATH across the
  action — an operator K→K′ swap between snapshot and write leaves
  both files K-encrypted under an installed K′): key remediation is
  OFFLINE/SERIALIZED BY RUNBOOK (restore with xpfd stopped, or the
  next probe validates the restored key first), AND every debt
  clear that consumed a key snapshot RE-READS the path and compares
  bytes at clear time — a mismatch RETAINS with the restoration
  message; the both-files operator-provenance assumption is stated
  (ENOENT proves no provenance; the store never deletes active.json,
  so the absence is operator intent by construction — and the
  barrier is safe-if-wrong: it only dir-fsyncs an already-absent
  slot). (c) The key-class health cause goes PER-STATE (Codex M3,
  verified: a singular bool cannot represent coexisting debts, and
  the boot key-class latch carries NO debt while terminal
  precedence would have rendered the generic message): the snapshot
  gains `ConfirmDebtKeyClassMask` (r29 refined to PER-DEBT-DERIVED:
  each keyed debt carries the class of its LATEST retained failure
  per `errors.As`; the mask is the OR-by-kind over LIVE debts — a
  cleared debt drops out, so coexisting same-kind R debts can never
  lose a live cause) AND `ConfirmRecordKeyClass` (the latch-level
  cause, cleared
  with the latch); the /health key-class variant renders per the
  rendered level's cause bit, both variants regression-pinned at
  both levels. (d) The successful-arm D clear is pinned as the
  ARM'S OWN supersession (Codex m3 — not a D action, not subject to
  the D precondition or the gate; absent such an arm, D stays inert
  until fresh re-classification). (e) x24 gains the COMBINED
  plaintext-active / K-encrypted-confirm scenario asserting ZERO
  write/delete (Codex m1) and the nonce boundary is qualified
  (Codex m2: bad nonce ENCODING/length fails before AEAD →
  non-key-class, `crypto.go:328-353`; a well-formed TAMPERED nonce
  reaches `gcm.Open` → key-class, `crypto.go:354-356`). (f) Stale
  copies swept: the x14/x21 health copies and the normative
  snapshot definition carry the per-state causes; the (x4e') legs
  split NON-KEY-CLASS TERMINAL vs KEY-CLASS RETAIN with the
  content-INDEPENDENT exemption; the v24-history
  crash-before-next-W copy says next-SUCCESSFUL-W; the formal §9
  list gains x22-x24. (g) The SPLIT delivery structure lands (§4.7,
  2-of-3 ruling): PR-1 = the `d.dp` accessor core (A1 + 5-site
  writer conversion + snapshot boundaries + full reader conversion
  + sampler narrowing + canaries); the follow-up issue = G+H+H2
  (Codex's ordering constraint: G-without-H would extend the
  pre-manager timer window into the post-manager
  bootstrap-with-live-cluster hybrid, so G moves with H+H2; the
  core introduces no new exposure, so the follow-up trails without
  a hard gate); AGY's (A) CONVERGE dissent is recorded — the design
  closes under EITHER packaging and the user makes the final call.
  v30: r29 convergence — the runbook gains its provenance branch
  and the key-class cause goes per-debt-derived (Codex
  NEEDS-REVISION 2M/5m, folds 1 FOLDED / 7 PARTIAL, structure
  confirmed with stale-copy corrections required; AGY PLAN-READY
  7/7 with 3 fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY 0M/0m, structure confirmed): (a) the key-remediation
  runbook splits BY STATE PROVENANCE (Codex M1, verified the
  stopped-restore hazard: a keep-active confirmation can resolve A
  in memory while a wrong key retains R_A process-locally, and
  stopping xpfd abandons that retry —
  `store_persist.go:397-401`; after restoring K and restarting, the
  pending-shaped A hash-matches and recovery re-arms or
  expired-reverts an ALREADY-CONFIRMED config,
  `store_persist.go:149-165,231-255`): DEBT-ORIGIN state (live
  process-local debts) → restore the key with xpfd RUNNING and WAIT
  for health/debt clearance — NEVER stop mid-debt; BOOT-ORIGIN
  state (terminal latch, no live debts) → the stopped-restore path
  is safe (the latch survives restart and re-validates at boot);
  the message names the branch via the same DEBT-origin vs
  BOOT-origin substate the snapshot already renders. (b) The
  key-class cause is PER-DEBT with a DERIVED mask (Codex M2,
  verified: one REMOVAL bit cannot represent coexisting same-kind R
  debts — clearing R_A would erase R_B's live cause — and a sticky
  cause misdirects after key revalidation when the latest retain is
  a non-key write failure): each keyed debt carries the class of
  its LATEST retained failure (re-evaluated at every raise/retain
  via `errors.As`); `ConfirmDebtKeyClassMask` is DERIVED at
  snapshot time as the OR-by-kind over LIVE debts (a cleared debt
  drops out); the mixed-R regression pins the OR semantics; the
  latch-level cause likewise tracks the latch's LATEST observed
  failure class. (c) The clear-time re-read gains its ERROR branch
  (Codex m1): EACCES/ENOENT/invalid-length/other → RETAIN + journal
  the EXACT verification error with a key-state-UNVERIFIABLE
  message (restoration-required is reserved for byte-MISMATCH or
  key-class-observed); the exact-bytes compare deliberately passes
  a legitimate same-content rewrite. (d) The producer enumeration
  and every matrix name the (w-u) unreadable-slot restore leg
  (Codex m2): (w-a), (w-b)/(w-c), (w-u), R (a), R (c), D tombstone.
  (e) x22 is re-specified (Codex m3, verified the contradiction:
  "D inert beside a durable arm" is the WRONG expectation — the
  arm's own overwrite SUBSUMES D): (x22a) ARM-BARRIER CLEARANCE (D
  cleared by the arm's own supersession, gate-independent); (x22b)
  SYNCAPPLY-PRE-RENAME (D inert while `persistDegraded`); the
  `armedArmID` conjunct stands as defense-in-depth with a
  test-seam leg. (f) The normative nonce classification is
  qualified (Codex m4: bad nonce ENCODING/length fails before AEAD
  → non-key-class; a well-formed TAMPERED nonce reaches `gcm.Open`
  → key-class). (g) Delivery copies swept (Codex m5): the G scope
  note and the §11 prerequisite-commit copy point at the FOLLOW-UP
  unit; the §9 test plan gains the [CORE]/[FOLLOW-UP] partition;
  §6's response-text count grows to FIVE (the two key-class
  variants); the both-files provenance assumption is scoped
  outside FACTORY RESET (`factory_reset.go:252-268` — itself an
  operator action).
  v31: r30 convergence — the remediation protocol is sealed against
  the split-key interleave and the latch/debt branch confusion
  (Codex NEEDS-REVISION 2M/2m, folds 2 FOLDED / 5 PARTIAL,
  structure confirmed; AGY PLAN-READY 7/7 with 3 fresh attacks
  FAILED, structure confirmed; SMR PLAN-READY-WITH-NITS 0M/1m —
  its barrier-choice nit folded into (d)): (a) the runbook branch
  keys on LIVE DEBT, not latch origin (Codex M2, verified: a
  confirmed commit during the BOOT latch can fail its arm
  pre-rename and create a W debt, so TerminalUnreadable and a
  nonzero mask coexist — the stop branch would abandon the live
  debt): ANY live process-local debt (`ConfirmDebtKindMask ≠ 0`,
  whatever the latch origin) forces the running/wait branch; only
  `mask == 0` permits the stopped-restore path; the mixed-state
  regression pins BOOT latch + live W → running/wait rendered.
  (b) The split-key interleave closes structurally (Codex M1,
  verified: with R_A and persistDegraded live under K, installing
  wrong-but-valid K″ lets the active-persist heal re-encrypt
  active.json under K″ — `store_persist.go:414-428` heals active
  FIRST, `crypto.go:262-270,457-465` encrypts with the installed
  key — after which no single key converges): WHILE ANY KEY-CLASS
  FAILURE IS OUTSTANDING, EVERY ENCRYPTED config-DB write is
  blocked (the active-persist retry withholds its encrypted write;
  NEW arms/commits are REFUSED at the persistence layer with a
  key-remediation error) — no file is ever re-encrypted under an
  unverified key, so the split cannot form; the loop order stays
  active-heal → resolution-finalize (the #5473 ordering), so the
  gate evaluates the previous pass's confirm-side state (one pass
  of lag, zero hazard); intentional key ROTATION is out of scope
  (no tooling exists on master either). (c) The clear-time re-read
  taxonomy is representable (Codex m1, verified the sole keyClass
  bit could not hold it): byte-MISMATCH sets the debt's keyClass
  state EXPLICITLY (the key's identity changed) and invalid-length
  matches `ErrMasterKeyLength` — BOTH restoration-required;
  EACCES/ENOENT/mount-IO → key-state-UNVERIFIABLE (generic text,
  NO restoration claim); all three branches carry x23/x24 legs.
  (d) The arm-supersession barrier is the dir-fsync DURABILITY
  barrier (SMR m1 = Codex m2): NEVER mere rename visibility — a
  FAILED barrier (pre- or post-rename) leaves D standing,
  suppressed by the resulting W debt; and a successful (w-a)
  durability completion IS the deferred barrier — D clears WITH W
  (the post-rename arm's live record made durable), pinned in the
  m3 text and both x22a legs. (e) Residual copies swept: both x23
  copies name (w-u); both x24 copies carry the re-read taxonomy;
  the W table is four-legged everywhere (the v20-history and §5.1
  "three-state" copies annotated); the §9 partition is consistent
  (item 1 untagged both-units, items 3-5 [CORE]); the
  source-comment rewording block points at the FOLLOW-UP unit.
  v32: r31 convergence — the write-safety predicate becomes an
  explicit state machine (Codex NEEDS-REVISION 2M/3m, folds 1
  FOLDED / 4 PARTIAL, structure confirmed; AGY PLAN-READY 5/5 with
  3 fresh attacks FAILED, structure confirmed; SMR PLAN-READY
  0M/0m, structure confirmed): (a) the config-DB carries an
  explicit WRITE-UNVERIFIED state (Codex M1, verified the v31
  predicate's hole: a missing/unreadable key file classifies
  READ-side TRANSIENT — UNVERIFIABLE, NOT key-class — so a
  latest-failure-class predicate REOPENS the gate exactly where
  the auto-create hazard lives, with the active heal creating K′
  or accepting K″ before the confirm read runs): ENTER on (i) any
  key-class-observed failure, (ii) any key-path write-side probe
  failure (ENOENT/EACCES/mount-IO — the UNVERIFIABLE outcomes),
  (iii) any byte-mismatch; HOLD through every non-positive outcome
  (EVERY encrypted config-DB write blocked — active heal
  withheld, repair writes withheld, commits refused; plaintext
  unaffected); EXIT ONLY on POSITIVE validation — a successful
  key-path read PLUS a decrypt-validation of an on-disk encrypted
  record under the SAME bytes. (b) The restoration flow is
  non-circular (Codex M2, verified: W/R healing itself writes
  encrypted, so a block keyed on the debt's own bit deadlocks or
  reopens): the operator restores K → the same pass's key-path
  read + confirm re-read decrypt-validate under K (POSITIVE
  validation, single snapshot) → the state EXITS → the healing
  write proceeds same-snapshot; wrong-K″ → the re-read fails auth
  → the state HOLDS → no split; a fresh box never enters (the
  #1894 first-write auto-create still works). (c) The commit
  refusal carries an EARLY Store-level precheck (Codex m1,
  verified the post-promotion hole: CommitConfirmed writes active
  BEFORE promotion and the confirm record's encryption keys off
  the PREV tree's master-password leaf — `store_commit.go:437-524,
  530-553`, `crypto.go:262-270` — so a PLAINTEXT candidate with an
  encrypted PrevTree still produces an encrypted confirm record):
  refuse at entry when write-unverified AND the commit would
  produce ANY encrypted write, with a regression for the
  plaintext-candidate/encrypted-PrevTree case. (d) The keyClass
  source of truth is unified (Codex m2): per `errors.As` OR
  explicit assignment at a byte-mismatch clear-time verification,
  in every schema copy. (e) The last three-state W copies are
  swept (Codex m3: the retry-table reference and the §5.1
  inventory now say FOUR-LEGGED with the (w-u) leg). (f) The (x25)
  WRITE-UNVERIFIED state-machine legs land in the formal §9 list
  (ENTER/HOLD/EXIT, the split-key leg, the restoration leg, the
  early-refusal leg, the pass-N/N+1 transition, the fresh-box
  leg).
  v33: r32 convergence — the write-unverified EXIT is made
  sufficient, total, observable, and swap-proof (Codex
  NEEDS-REVISION 2M/2m, folds 3 FOLDED / 2 PARTIAL, structure
  confirmed; AGY PLAN-READY 5/5 with 3 fresh attacks FAILED,
  structure confirmed; SMR PLAN-READY-WITH-NITS 0M/1m — its
  irrecoverable-generation nit folded into (b)): (a) the EXIT is
  ACTION-SCOPED AND CONTINUOUS, not a one-shot global clear (Codex
  M1a, verified: validating "an" encrypted record says nothing
  about a second on-disk generation): the state is the ABSENCE of
  a current positive validation; EVERY gated encrypted write —
  including the active heal — re-performs the FRESH same-snapshot
  validation IMMEDIATELY before encryption, covering BOTH SIDES'
  present encrypted generations (the dual of the laundering
  guard: an active write must never outrun an unreadable CONFIRM
  generation); any mismatch withholds and RE-ENTERS. (b) The EXIT
  is TOTAL and observable (Codex M1b + SMR m1): a CONFIRMED-EMPTY
  exit joins the decrypt exit — when no encrypted or unreadable
  record remains (all plaintext, or the final unreadable record
  sanctioned-removed), the state exits with the data-loss warning
  surfaced — and this IS the irrecoverable-generation path (the
  single-file removal is itself withheld by (g-err), so the
  operator exits through the BOTH-FILES removal → (g-absent) →
  the absent/plaintext posture, with the explicit sacrifice
  warning); the state joins the snapshot as NON-SECRET
  `ConfigWriteUnverified` (aggregate OR + /health message; §6's
  repertoire grows to SIX) and the retry loop ACTIVELY probes the
  key path every pass while the state holds. (c) The second-swap
  leg closes (Codex M2, verified: an operator swap to K″ between
  the exit pass and the deferred active write would re-encrypt a
  PLAINTEXT-on-disk active under K″ while a K-era CONFIRM record
  stands — the (g-ok) active-side no-op would pass): the active
  heal's write consumes the fresh both-sides validation from (a)
  — a plaintext active side does not exempt the write while a
  confirm-side encrypted generation exists and fails validation.
  (d) The keyClass copies unify on errors.As-OR-explicit-mismatch
  (Codex m1; the last two errors.As-only copies swept). (e) The
  missing-key message is class-split everywhere (Codex m2:
  invalid-LENGTH or byte-MISMATCH → `.configdb/master.key`
  RESTORATION; ENOENT/EACCES/mount-IO → key-state UNVERIFIABLE,
  NO restoration claim — the (w-u)/(d-i) block copies reconciled
  with the normative taxonomy). (f) The x25 legs gain the
  second-swap, confirmed-empty, irrecoverable-generation, and
  observability cases.
  v34: r33 convergence — the state machine survives its own
  composition with the repair exemptions (Codex NEEDS-REVISION
  3M/2m, folds 1 FOLDED / 4 PARTIAL, structure confirmed; AGY
  PLAN-READY 5/5 with 3 fresh attacks FAILED, structure
  confirmed; SMR PLAN-READY 0M/0m, structure confirmed): (a) the
  both-sides validation becomes SIDE-ASYMMETRIC (Codex M1,
  verified the deadlock: requiring the write's OWN target to
  validate kills the content-INDEPENDENT escape hatch — the (w-u)
  restore-over and the D synthesized tombstone exist precisely to
  overwrite a NON-KEY-CLASS-PERMANENT unreadable slot that can
  never validate): the OPPOSITE side's present encrypted
  generations MUST validate; the own-target is validated ONLY
  when it is supposed to be readable — a content-INDEPENDENT
  repair is EXEMPT from own-target validation exactly when its
  target classifies NON-KEY-CLASS PERMANENT (the overwrite IS the
  repair); the (w-u)/(d-i) legs cross-reference the exemption.
  (b) The CONFIRMED-EMPTY exit gains an executable proof and
  priority (Codex M2: a key-path probe failure over an
  all-plaintext DB satisfied BOTH the HOLD and the empty exit):
  ONE fresh under-`s.mu` classification of BOTH files using ONE
  key byte snapshot (the envelope-detected bit surfaced at both
  call sites — `crypto.go:306-314`, `db.go:95-103`, `db.go:242-253`)
  proves all-plaintext/all-absent and exits AUTHORITATIVE BEFORE
  the key-probe HOLD; the under-`s.mu` scan excludes Store-origin
  arm interleavings by construction. (c) The observability
  contradictions are swept (Codex M3): every loop-exit copy now
  keeps the loop alive on the outstanding state; every exact
  schema/aggregate copy carries `ConfigWriteUnverified`; the
  precedence list inserts WriteUnverified between ConfirmDebt and
  ActivePersist. (d) `Save()` takes `s.mu.Lock()` (Codex m1,
  verified the RLock race/deadlock: a failed validation must
  mutate the state and start/retain the loop). (e) SyncApply's
  admission is pinned (Codex m2: PROMOTE in-memory per the #1799
  Option-B degrade-not-fail contract — the cluster never diverges
  over a key-remediation window — while the encrypted persistence
  attempt is WITHHELD under the state and raises the
  active-persist debt). (f) The last errors.As-only per-debt
  definition and the three missing-key-file restoration lumps are
  swept to the class-split.
  v35: r34 convergence — the remediation race and the state-only
  false clear close (Codex NEEDS-REVISION 3M/1m, folds 4 FOLDED /
  2 PARTIAL, structure confirmed; AGY PLAN-READY 6/6 with 3 fresh
  attacks FAILED, structure confirmed; SMR PLAN-READY 0M/0m,
  structure confirmed): (a) the two sanctioned remediations split
  by race safety (Codex M1, verified: the classify→overwrite
  sequence is not serialized against an operator's in-flight hand
  repair — `db.go:242-253` ordinary read, then an unconditional
  atomic replacement at `db.go:207-218` + `fsatomic.go:310-366` —
  so D's tombstone or the (w-u) restore can delete a record the
  operator JUST repaired to valid): REMOVAL is safe LIVE (the
  confirmed-absence barrier is idempotent — a removal cannot be
  destructively overwritten); repair-to-valid FILESYSTEM
  remediation requires xpfd STOPPED (the BOOT-origin offline
  posture); and every content-INDEPENDENT repair write RE-VERIFIES
  the target's classification inside the SAME `s.mu` hold
  immediately before the rename (abort + re-classify on any
  change — defense-in-depth; the stopped requirement is the
  authoritative closure). (b) The state exit re-verifies the key
  identity (Codex M2, verified the state-only false clear:
  `Save()` can ENTER the state with NO persistence debt; a pass
  validates both files, the key path is swapped to K′ before the
  exit, and the debt-clear compare does not apply — with no debt,
  clearing the state exits the loop and health goes GREEN while
  the installed K′ decrypts neither record): the positive-
  validation exit performs its OWN final key-path re-read and
  EXACT-BYTES compare against the validation snapshot immediately
  before clearing — mismatch → RETAIN with the byte-mismatch
  classification, the loop keeps probing; the x25 state-only
  second-swap regression pins it. (c) The observability sweep
  completes (Codex M3): the §5.1 implementation inventory, both
  formal test inventories, and the API precedence copy now carry
  `ConfigWriteUnverified` in the aggregate AND the WriteUnverified
  precedence position. (d) The cumulative-summary master-key-IO
  sentence is re-punctuated (Codex m1: KEY-CLASS permanent →
  restoration; master-key IO READ-side → TRANSIENT retry with the
  UNVERIFIABLE message, NO restoration claim).
  v36: r35 convergence — the stopped-repair precondition and the
  re-verify mechanism are pinned (Codex NEEDS-REVISION 1M/2m,
  folds 3 FOLDED / 1 PARTIAL, structure confirmed; AGY PLAN-READY
  4/4 with 3 fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — its m1 IS the same finding as
  Codex M1, raised independently): (a) the repair-to-valid
  stopped remediation gains the MANDATORY `mask == 0`
  precondition EXPLICITLY (Codex M1 = SMR m1, both verified:
  stopping with live process-local debts abandons them,
  `store_persist.go:397-401`, and a repaired pending-shaped
  record hash-matches into expired-revert or a future re-arm at
  the next boot, `store_persist.go:149-165,171-255` — rolling
  back an ALREADY-CONFIRMED config, with H able to Load-revert
  the FirstCommit+cluster class on top): any live debt forces
  the RUNNING probe/removal path (removal is the live-safe
  remediation for the same corrupt record); and the operator is
  warned that a SUCCESSFUL-active `Load` runs the full total
  order while an absent/compile-failed `Load` only seeds an
  orphan. (b) The re-verify-before-rename mechanism is pinned
  (Codex m1, verified the gap: `WriteConfirm` calls the
  MONOLITHIC `WriteFileDurable`, `db.go:207-218` — temp+write+
  fsync+close then an unconditional rename, `fsatomic.go:310-355`
  — with no staged seam): `fsatomic` gains
  `WriteFileDurableStaged(path, data, perm, preRename func()
  error)` — the classification re-verify runs INSIDE the
  pre-rename hook (still under the same `s.mu` hold), a hook
  error UNLINKS the temp (the `fsatomic.go:41-44` cleanup
  discipline, defer-driven per `fsatomic.go:315-321`;
  crash-leaked temps swept by `NewDB` at open) and re-classifies,
  and a test
  seam drives the failure path; a post-write read-back is
  explicitly REJECTED (it sees only the daemon's own
  replacement when the operator's write lands first). (c) The
  stale three-cause documentation copies are swept (Codex m2:
  the `pkg/api/README.md` snapshot description, the
  `health.go:10-16` header, and the descriptor/wiring comment
  copies now name all the causes incl. `ConfigWriteUnverified`).
  v37: r36 convergence — the mask==0 observation is fenced and
  the temp fate is pinned (Codex NEEDS-REVISION 1M/1m, folds 2
  FOLDED / 1 PARTIAL, structure confirmed; AGY PLAN-READY 3/3
  with 2 fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — its temp-cleanup nit IS Codex m1,
  the second independent convergence this run): (a) the stopped
  remediation runs a PRODUCER-QUIESCE protocol, not a point
  check (Codex M1, verified the TOCTOU: the mask is derived at
  snapshot time while a later confirmed commit or an
  asynchronous HA demotion resolving a window —
  `daemon_ha.go:466-474`, `store_commit.go:575-608,652-702,
  780-792` — can re-raise debt between the observation and the
  stop, and post-restart health is too late because recovery
  runs inside `Load` before service,
  `store_persist.go:110-114`): (1) no live commit-confirmed
  window stands (confirm or roll back first), (2) refrain from
  commits and wait ONE debt-pass interval, (3) RE-CHECK
  `mask == 0` (a mid-wait debt shows), (4) stop and repair; the
  blind-spot residual is explicitly ADMITTED (a window whose
  deadline fires between the re-check and the stop — the same
  process-local provenance loss admitted since r29) with the
  post-restart recovery path NAMED (the recovered timer's
  operator-scale deadline allows confirming away an
  inappropriately re-armed window or removing the record via
  the sanctioned live path; the expired-revert is bounded to
  records whose own deadline had already passed). (b) The hook
  fate is pinned (Codex m1 = SMR m1, both verified: "abandons
  the temp file" was loose against the `fsatomic.go:41-44`
  discipline — "the temp file is removed on every failure path
  before rename", defer-driven per `fsatomic.go:315-321`): a
  hook error UNLINKS the temp; crash-leaked `.<base>.tmp-*`
  temps are swept by `NewDB` at open (`db.go:61-68`) — never
  accumulated; a target-unchanged/no-temp regression pins both
  per `fsatomic_test.go:297-347`. (c) The last two stale
  cause-count copies are swept (the §5.1 "ALL THREE causes"
  wiring comment and the docs-inventory enumeration now name
  the key-class causes AND `ConfigWriteUnverified`).
  v38: r37 convergence — the fence gains its async-producer
  barrier and the recovery guidance is corrected to the real
  semantics (Codex NEEDS-REVISION 2M/2m, folds 2 FOLDED / 1
  NOT-FOLDED, structure confirmed; AGY PLAN-READY 3/3 with 2
  fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — its wait-interval nit is folded
  into (a)): (a) the quiesce step (2) verifies CLUSTER-SYNC
  QUIESCENCE (Codex M1, verified the gap: peer reconnect,
  promotion, or the 30-second reconciler can initiate SyncApply
  independently of operator commits,
  `daemon_ha_sync.go:417-430,500-522,926-956`, and a post-re-check
  SyncApply under the BOOT latch can raise a process-local D
  debt that the stop abandons) and waits ONE full pass at the
  loop's CAPPED backoff (the `maxBackoff` parameter — SMR m1:
  debts are raised SYNCHRONOUSLY in memory under `s.mu` at the
  producing operation's failure, so the re-check observes them
  regardless of backoff phase, but an in-flight resolution's
  finalize runs inside a pass); the post-re-check SyncApply
  residual is ADMITTED and BENIGN by construction: D's target is
  a DEAD record (its window already resolved), so abandonment
  leaves either an unreadable record the next boot re-classifies
  into the SAME terminal latch (the sanctioned live removal
  remediates) or a readable dead record the seeded-orphan
  machinery resolves at the next commit — NO live-window replay
  is possible from an abandoned D. (b) The post-restart recovery
  path is corrected to the real semantics (Codex M2 + m1, all
  three verified): the recovered timer re-arms for the record's
  ORIGINAL REMAINING interval — possibly arbitrarily short, NOT
  a fresh default window (`store_persist.go:231-253`) — so the
  operator reads the deadline from the record/journal; an
  inappropriately re-armed window is CONFIRMED away with a BARE
  `commit` (confirmation cancels the timer,
  `store_commit.go:729-748,796-823` — NEVER `commit check`,
  which only validates, `cli_config.go:177-185,257-271`, and
  NEVER manual record removal, which does NOT cancel the
  in-memory timer); and the FirstCommit+cluster class has NO
  service-time escape BY DESIGN — H reverts INSIDE `Load`, so
  the operator RE-COMMITS after the revert rather than
  confirming. (c) The fsatomic package comment
  (`fsatomic.go:1-4`) and `pkg/fsatomic/README.md:3-12` — both
  claiming exactly two writers — join the docs inventory for the
  third (Codex m2).
  v39: r38 convergence — the fence becomes enforceable and the
  offline repair shape is pinned (Codex NEEDS-REVISION 4M/1m,
  folds 1 FOLDED / 2 NOT-FOLDED, structure confirmed; AGY
  PLAN-READY 3/3 with 2 fresh attacks FAILED, structure
  confirmed; SMR PLAN-READY 0M/0m, structure confirmed): (a) the
  quiescence check becomes an ENFORCEABLE barrier (Codex M1,
  verified the observability gap: the SyncApply apply flag and
  queue are PRIVATE — `cluster/sync.go:594-616` — and the public
  status surfaces expose only cumulative/history data —
  `cluster/sync.go:191-228`, `cluster/status.go:340-356` — so no
  observable predicate can fence peer-driven syncs): the
  operator STOPS THE PEER xpfd (the v39 text also offered
  "downs the cluster control link `em0`" as an alternative —
  WITHDRAWN in v40: sync falls back to fabric over possibly two
  redundant paths, `daemon_ha_sync.go:774-785,820-860`) BEFORE
  the fence wait — a stopped peer is a
  deterministic barrier for every peer-driven SyncApply. (b)
  The abandoned-D offline repair shape is pinned (Codex M2,
  verified the conflation: a tombstone FAILURE leaves the
  ORIGINAL unreadable pending record, and a PENDING-SHAPED
  offline repair of that DEAD record can BIND at the next boot
  — legacy-empty or same-content `GuardedHash`,
  `store_persist.go:149-165,171-255` — and replay the RESOLVED
  window): the offline repair of a DEAD (D-target) record is
  NEVER pending-shaped — the operator REMOVES it (always
  live-safe, offline too) or writes the repair with
  `Resolved: true` (dropped at the Resolved-first check). (c)
  The recovery instruction splits on the record's deadline at
  restart (Codex M3: a deadline that fired before shutdown is
  already PAST at restart — `Load` reverts immediately and bare
  `commit` then returns "no pending confirmed commit",
  `store_commit.go:729-746`): still-pending → CONFIRM AWAY with
  a bare `commit` within the ORIGINAL remaining interval;
  already-expired → the config is already reverted, so RE-COMMIT
  the intended configuration — never confirm. (d) The
  H-class recovery is the preflight's OWN named path (Codex M4,
  verified: H leaves no cluster runtime and a live CLUSTERED
  commit is REJECTED — `daemon_apply_commit.go:194-205`,
  `cluster_topology_preflight.go:59-97`, the HA runtime is
  boot-only-constructed): restart xpfd INTO the clustered
  configuration (the `xpf.conf` boot import re-imports the seed
  and commits it on the normal day-0 path), or an offline
  seed-and-restart. (e) The deadline's operator surface is the
  startup journald log line (Codex m1: the audit journal carries
  no deadline field, `journal.go:59-80`, and confirm.json may be
  encrypted, `db.go:199-216` — the remaining interval is read
  from `store_persist.go:254-255`).
  v40: r39 convergence — the fence becomes a full-state,
  peer-preflighted, ordered procedure and the runbook's operator
  contract is corrected end-to-end (Codex NEEDS-REVISION 6M/0m,
  folds 2 FOLDED / 2 NOT-FOLDED / 1 PARTIAL, structure confirmed;
  AGY PLAN-READY-WITH-NITS — its attack-2 IS the same
  prefer-removal nit as SMR m1, the third independent convergence;
  SMR PLAN-READY-WITH-NITS 0M/1m): (a) the re-check becomes a
  FULL-STATE check (Codex M1, verified: a queued local apply can
  promote, cancel the old window, and FAIL its active write —
  `store.go:687-717,738-746` — leaving `ActivePersistDegraded`
  while the old record stands as the SOLE crash-recovery intent,
  which a mask-only check reads as clean):
  `ConfirmDebtKindMask == 0` AND `persistDegraded == false`; and
  the capped pass is noted to drain the local receiver's queued
  apply (a LOCAL operation whose promotion/cancellation/debt-raise
  lands synchronously within the pass it runs in,
  `cluster/sync.go:594-616,850-857`,
  `sync_conn_config.go:325-351`). (b) The peer fence gains its
  peer-side preflight and lifecycle ordering (Codex M2, verified:
  the peer stop abandons the PEER's process-local debts
  symmetrically, so the peer needs the SAME full-state preflight;
  and the ordering is keep-the-peer-fenced until the target is
  fully stopped, then START THE LOCAL first — its `Load`
  classification completes BEFORE cluster comms,
  `daemon_run.go:157-177,393-398` — and only then restart the
  peer; an unclean peer makes the stopped path UNAVAILABLE — use
  live removal). (c) The `down em0` alternative is dropped
  (Codex M3, verified: config sync uses the configured control
  interface only when both control fields exist and otherwise
  falls back to the fabric, possibly over TWO redundant paths —
  `daemon_ha_sync.go:774-785,820-860`; the peer stop is the
  universal fence over every transport). (d) The dead-record
  offline repair is REMOVAL, PREFERRED IN EVERY CASE (Codex M4 =
  SMR m1 = AGY attack-2, three-way convergence: the
  `Resolved: true` shape is the MACHINERY's own synthesized form
  — a new reader's validation runs BEFORE the Resolved check and
  requires a nonzero parseable `Deadline` and non-null
  `PrevTree`, `db.go:254-281`, and the downgrade-old reader
  IGNORES `Resolved`, requiring the FULL synthetic field set —
  never hand-authored); the two stale copies permitting
  pre-tombstone/pending-shaped restoration are swept to the
  shape-split (a LIVE window's record repairs pending-shaped; a
  DEAD record is REMOVED). (e) The offline removal carries the
  durability barrier (Codex M5, verified: a bare `rm` is an
  unlink WITHOUT the parent-directory fsync — a power loss can
  replay the stale record, `db.go:284-315`): `rm` then `sync -f`
  on the `.configdb/` directory — the `DeleteConfirm`-equivalent
  barrier. (f) The bare-`commit` probe after expiry is FORBIDDEN
  (Codex M6, verified: only the explicit `ConfirmCommitAs` path
  returns "no pending confirmed commit"; a BARE commit falls
  through to an ORDINARY promotion — `cli_config.go:257-280`,
  `grpcapi/server_config.go:257-282`, `api/config.go:238-256`,
  `store_commit.go:155-225` — and after the expired recovery
  reset the candidate to the reverted tree, that ordinary
  promotion COMMITS THE REVERTED (possibly EMPTY) configuration,
  after which the HA node guard and the active-config predicate
  SUPPRESS the later `xpf.conf` import,
  `bootstrap.go:65-79,237-247`): the operator STAGES the
  intended configuration first, then commits.
  v41: r40 convergence — the fence gains its observable join and
  the H-branch config-shape split is made explicit (Codex
  NEEDS-REVISION 2M/1m, folds 3 FOLDED / 3 PARTIAL, structure
  confirmed; AGY PLAN-READY 6/6 with 2 fresh attacks FAILED,
  structure confirmed; SMR PLAN-READY-WITH-NITS 0M/1m): (a) the
  cluster status surface (gRPC/CLI, BOTH nodes) gains a
  config-sync QUEUE-DEPTH + APPLY-IN-FLIGHT indicator (Codex M1,
  verified the barrier gap: the private 64-slot channel's
  consumer invokes `syncAndApply(context.Background())` and can
  block INDEFINITELY on `applySem` —
  `sync_conn_config.go:325-351`, `daemon_apply_commit.go:326-335`
  — so NO time-based wait drains the queue; the currently-private
  queue and flag, `cluster/sync.go:594-616`, are exposed
  read-only) and the fence drains BOTH directions through it —
  (2a) LOCAL DRAIN until the indicator shows queue-empty AND no
  apply-in-flight locally, then one capped pass; (2b) PEER-SIDE
  full-state preflight (a just-landed sync's debts are raised
  synchronously at the peer and visible on its own status — and
  the reverse-direction TOCTOU is closed by the local drain: no
  local→peer push can be in flight when the peer stops);
  (2c) STOP THE PEER; (3) local full-state re-check; (4) stop
  and repair. (b) The H-branch config-shape split is explicit
  (SMR m1): in the H case the M6 staged-commit path works ONLY
  for a NON-clustered intended config — a staged CLUSTERED commit
  is preflight-REJECTED (cleanly, BEFORE store promotion,
  `daemon_apply_commit.go:194-205`, with the restart instruction
  in the error text) — so the operator stages+commits only when
  the intended configuration is standalone, and uses the
  restart/import path when it is clustered. (c) The §11
  question-6 baseline is corrected ("the current design", not
  "the v29 design" — Codex m1) and the retained v39 history
  entry's `down em0` alternative is annotated WITHDRAWN (Codex
  fold-partial 3).
  v42: r41 convergence — the observable join is REDESIGNED as a
  gap-free outstanding-sync counter and the fence is reordered
  around it (Codex NEEDS-REVISION 4M/1m, folds 1 FOLDED /
  2 NOT-FOLDED — both NOT-FOLDEDs are the v41 queue-length +
  gen-fence pair this v42 replaces — structure confirmed; AGY
  PLAN-READY 3/3 with 2 fresh attacks FAILED, structure
  confirmed; SMR PLAN-READY-WITH-NITS 0M/1m): (a) the join is a
  single atomic `ConfigSyncOutstanding` counter per node
  (Codex M1, verified the three false-idle windows in the v41
  pair: dequeue precedes flag publication —
  `sync_conn_config.go:325-350`; legacy gen-0 applies leave the
  flag zero — `sync_conn_config.go:289-309`,
  `sync_protocol.go:704-712`; `resetRecvGen` can clear the flag
  during an apply — `sync_conn_read.go:183-195`,
  `sync_conn_gen.go:340-362`) — INCREMENTED at frame receipt
  BEFORE enqueue (`sync_conn_read.go:298-324`) and DECREMENTED
  only AFTER the apply returns, including the applySem-blocked
  duration (`sync_conn_config.go:325-351`,
  `daemon_apply_commit.go:326-335`), independent of generation
  numbers and epoch resets, so `outstanding == 0` is a true join
  with no false-idle window; exposed read-only on the cluster
  status surface (gRPC/CLI, BOTH nodes) and read LIVE at check
  time (a single atomic — Codex m1's joint-protection coherence
  note answered by construction). (b) The fence sequence is
  reordered (Codex M2, verified neither direction was actually
  drained: local→peer writes can start after the local
  observation — `QueueConfig` writes directly,
  `sync_conn_config.go:230-250`, asynchronously triggerable,
  `daemon_ha_sync.go:417-522` — and peer→local writes can start
  after the local drain while the peer still runs; and the final
  debts-only re-check misses a merely-enqueued or
  applySem-blocked apply that has not raised debt yet —
  `store.go:687-746` — which process exit then abandons,
  `store_persist.go:397-401`, with degraded health
  election-neutral, `cluster/readiness.go:20-24`,
  `cluster/election.go:427-432`): (2a) PEER-SIDE PREFLIGHT (peer
  `ConfirmDebtKindMask == 0` AND peer `persistDegraded == false`
  AND peer `ConfigSyncOutstanding == 0`); (2b) STOP THE PEER
  xpfd FIRST (the universal fence — a stopped peer cannot push
  over ANY transport and no new inbound frames initiate);
  (2c) LOCAL OUTSTANDING DRAIN to zero (every in-flight inbound
  apply completes, including any applySem-blocked one); (3)
  local full-state re-check now INCLUDING
  `ConfigSyncOutstanding == 0`; (4) stop and repair. (c) The
  peer full-state read path is PINNED (Codex M3, verified the
  peer debt mask + active-persist state had no designed read
  path — `ConfigPersistDegradedState()` was wired only into
  pkg/api health, `plan.md:4608-4654`, and cluster status
  exposed only config-sync counters, `cluster/status.go:340-356`):
  the peer's own `/health` endpoint on its localhost ALREADY
  carries the debt mask and active-persist state per the
  health-snapshot work (operator reads it via the peer's
  localhost or SSH), and the cluster-status RPC gains the
  outstanding counter AND wires the confirm-side debt mask +
  active-persist state — the §5.1 inventory gains the
  `pkg/cluster` entry. (d) The formal acceptance copy is
  rewritten to the CURRENT fence (Codex M4, verified
  plan.md:5553-5569 still specified peer preflight → peer stop →
  capped timer wait): no timer anywhere; the peer-side preflight
  includes the counter read via the peer's `/health`; the local
  drain waits on the counter to ZERO; the re-check includes the
  counter. (e) The live-read pin + its regression (Codex m1 +
  SMR m1): the counter is read LIVE at check time (never a
  cached or periodically-refreshed value), and §9 gains the
  JOIN-COHERENCE leg — a framed-blocking-apply regression (frame
  dequeued, apply blocked on `applySem` via the test seam)
  asserts the counter NEVER reads zero until the apply returns,
  covering all three false-idle windows the gapful pair had.
  v43: r42 convergence — the counter gains TOTAL retirement and
  NODE-LIFETIME ownership, the drain gains the EOF witness, and
  the admitted residuals gain shape (iii) (Codex NEEDS-REVISION
  3M/2m, folds 2 FOLDED / 3 PARTIAL, structure confirmed; AGY
  NEEDS-REVISION 1M — the same balance gap, folds 4 FOLDED /
  1 PARTIAL, structure confirmed; SMR PLAN-READY-WITH-NITS
  0M/1m — the same balance gap at MINOR; all three reviewers
  independently caught the counter-balance defect, severity
  MAJOR on 2-of-3 because a leaked token hangs the mandatory
  drain forever — the SMR under-called it and the fold treats
  it as MAJOR): (a) TOTAL RETIREMENT (Codex M1 + AGY M1 + SMR
  m1, all verified against the code): every received token has
  exactly one retirement owner — the increment is taken ONLY in
  the successful-enqueue arm (the nil-channel guard and the
  queue-full `default:` drop arm, `sync_conn_read.go:321-331`,
  do NOT increment — a dropped frame never reaches an apply, so
  an unconditional receipt-side increment leaks +1 and
  `outstanding == 0` becomes unreachable); the decrement is
  DEQUEUE-SCOPED via a per-item `defer` in the consumer,
  covering the stale-generation skip
  (`sync_conn_config.go:331-336`), the nil-handler skip
  (`sync_conn_config.go:337-341`), apply failure, and panic
  unwind; and session TEARDOWN retires every still-buffered
  token (the ctx-cancel abandonment path,
  `sync_conn_config.go:325-330`, and `SessionSync.Stop`,
  `sync_conn.go:349-385`). (b) NODE-LIFETIME OWNERSHIP + the
  EOF witness (Codex M2, both windows verified): the counter
  lives in daemon-scope node-lifetime state, NOT on the
  replaceable `SessionSync` stats provider — a received
  transport-changing config replaces the session MID-CALLBACK
  (apply step 20, `daemon_apply_tail.go:238-255`, teardown
  5s-capped, `daemon_ha_sync.go:1405-1415`,
  `sync_conn.go:349-385`; the manager re-points at the fresh
  provider, `sync_state.go:47-63`, `daemon_ha_sync.go:906-913`),
  so a provider-scoped counter would false-idle the fresh
  provider while the old apply is still blocked; and the LOCAL
  drain (2c) first observes the LOCAL EOF/disconnection of the
  stopped peer's session(s) (the read loop terminates on
  header-read EOF, `sync_conn_read.go:28-60`) — bytes the peer
  sent before dying are either fully dispatched (counted) or
  abandoned mid-frame at EOF (never counted, never applied) —
  closing the partial-frame-in-flight window. (c) Admitted
  residual shape (iii) (Codex M3, verified the admitted set
  covered only (i)/(ii)): a local→peer push
  (`daemon_ha_sync.go:417-522`, `sync_conn_config.go:230-250`)
  initiated BETWEEN the peer preflight (2a) and the peer stop
  (2b) can promote at the peer and FAIL its active write
  (`store.go:687-717,738-746`), raising peer
  `ActivePersistDegraded` that the stop abandons
  (`store_persist.go:397-401`); bounded — the loss is the
  in-memory promote only (the peer's persisted active stays the
  prior config), the peer's restart `Load` classifies its
  records, the reconnect re-drive re-pushes the current config
  (`daemon_ha_sync.go:926-956`), and a permanent persist
  failure surfaces as the peer's `/health` 503; deterministic
  closure would require a producer-pause knob (new machinery) —
  per the runbook's admit+bound idiom (r29/r37/r38) the
  residual is admitted and bounded. (d) The acceptance copy
  names the RIGHT read surface (Codex m1): the peer's debt mask
  + active-persist state come from the peer's `/health`; the
  peer's `ConfigSyncOutstanding` comes from the peer's
  cluster-status RPC. (e) The JOIN-COHERENCE leg names its
  sub-legs (Codex m2): framed-blocking-apply, LEGACY GEN-0
  payload, CONCURRENT `resetRecvGen`, PROVIDER-REPLACEMENT
  (node-lifetime survival), and RETIREMENT-TOTALITY (drop /
  stale-skip / nil-handler-skip / teardown-with-buffered each
  leave the counter balanced at zero).
  v44: r43 convergence — the counter's publication order is
  pinned, the counter is recognized as the all-ingress join,
  residual (iii)'s bound is restated honestly, and the witness
  is generalized (Codex NEEDS-REVISION 3M/2m, folds 1 FOLDED /
  4 PARTIAL, structure confirmed; AGY PLAN-READY 5/5 with 2
  fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — the witness-surface pin, folded
  here): (a) PUBLICATION ORDER (Codex M1, verified the Go
  semantics — a `select` send completes, and the item becomes
  receivable, BEFORE the arm body runs,
  `sync_conn_read.go:321-324` vs `sync_conn_config.go:325-351`):
  the increment is an OWNERSHIP RESERVATION taken BEFORE the
  enqueue attempt with a ROLLBACK decrement on the nil-channel /
  queue-full dispositions — a transient false-BUSY between
  reservation and rollback is conservative (the drain merely
  waits longer); false-idle is the only forbidden direction; §9
  gains the publication-order leg (a test seam after the send
  completes, before the producer's continuation). (b) THE
  COUNTER IS THE ALL-INGRESS JOIN (Codex M2, all three reader
  classes verified): the reservation lives in the DISPATCH path
  (the `syncMsgConfig` case), so the pre-install pending-frame
  dispatch (`sync_conn.go:122-127` — a legacy/unkeyed peer's
  first frame is processed BEFORE `installConn`), the
  superseded reader of a same-fabric replacement
  (`sync_conn.go:244-267`, its disconnect ignored as stale,
  :480-498), and a reader alive past Stop's 5s cap
  (`sync_conn.go:349-385`) all reserve identically; unkeyed
  third-party/stale-process ingress (dual-accepted
  unauthenticated, `sync_admission.go:58-83`,
  `sync_auth.go:321-334`) is equally COUNTED — observed, never
  invisible. (c) RESIDUAL (iii)'s BOUND RESTATED HONESTLY
  (Codex M3, both sub-claims verified): the abandoned-write
  outcome SPLITS on failure class — PRE-rename: replacement
  invisible, prior persisted active intact, promote lost;
  POST-rename (the directory-fsync `*PostRenameSyncError`,
  `fsatomic.go:45-53,66-72`, the plan's own :2381-2391): the
  NEW content is VISIBLE with durability unproven, the restart
  loads it (`store_persist.go:21-55,110-114`,
  `daemon_run_bringup.go:516-520`), an equal-and-applied
  re-push skips `SyncApply` (`daemon_ha_sync.go:550-568`), and
  the abandoned degradation is NOT reconstructed (`/health` can
  be green with durability unproven) — and convergence is
  AUTHORITY-CONDITIONAL (the re-drive skips until
  peer-connected + RG0-authority + 30s-stable,
  `daemon_ha_sync.go:447-465`; the stale peer can preempt,
  `cluster/election.go:172-193`), so the cluster converges to
  the AUTHORITY's config, possibly the peer's older persisted
  one — a bounded REGRESSION to a persisted state, never a
  silent divergence. The operational closure is pinned without
  new machinery: the stopped-filesystem repair ends with a
  directory `sync` of the configdb, and a POST-RESTART
  VERIFICATION step requires both nodes to hold the same
  intended config AND `ConfigWriteUnverified == false` AND
  `ConfirmDebtKindMask == 0` before the repair is declared
  done; the same shape covers the LOCAL post-re-check window
  from any ingress source. (d) The acceptance copy enumerates
  residual (iii) (Codex m1). (e) The witness is the TERMINAL
  EXIT of every relevant ingress reader (Codex m2 — EOF,
  heartbeat-timeout, bad-magic, oversized/partial payload,
  auth-trailer failure, cancellation, read errors; dispatch
  only after complete verification, `sync_conn_read.go:22-93`),
  observed on the EXISTING sync-peer connection-state surface
  (`IsSyncConnected`, `sync_state.go:66-74`, rendered
  `status.go:263-267`, aggregating both redundant sessions —
  SMR m1). (f) The JOIN-COHERENCE retirement-totality leg now
  names EVERY path (Codex fold-5): nil-channel, queue-full,
  stale-skip, nil-handler-skip, callback failure, panic unwind,
  partial-frame exit, pre-install dispatch, superseded-reader
  dispatch, teardown-with-buffered.
  v45: r44 convergence — the reservation is gated on session
  liveness, the instantaneous-join claim is withdrawn in favor
  of the composition, the disabled-sync subclass is named, the
  durability sync pins every affected node, and the done
  predicate is the full aggregate (Codex NEEDS-REVISION 5M/2m,
  folds 1 FOLDED / 4 PARTIAL / 1 NOT-FOLDED, structure
  confirmed; AGY PLAN-READY 5/5 with 1 fresh attack FAILED,
  structure confirmed; SMR PLAN-READY 0 findings with 5
  documented fresh attacks FAILED): (a) SESSION-LIVENESS GATE
  (Codex M1, verified: Stop can return with readers alive past
  the 5s cap, `sync_conn.go:349-385`, after the consumer
  selected ctx.Done, `sync_conn_config.go:325-330` — a
  surviving reader could reserve+send into the still-open queue
  after its one-shot drain with no consumer left to retire it):
  a session-dead flag is published at Stop START (before the
  drain); a dispatch that observes it takes the DROP path — no
  reservation, an alarm, re-convergence on the next push; §9
  gains the enqueue-after-teardown seam leg. (b) THE
  INSTANTANEOUS-JOIN CLAIM IS WITHDRAWN (Codex M2, verified all
  three verified-undispatched windows: a reader paused between
  verification and `handleMessage`, `sync_conn_read.go:84-93`;
  a legacy peer's first frame in the handshake's `pendingFrame`,
  `sync_auth.go:352-369`; a WRITER-side failure publishing Down
  while that conn's reader remains runnable,
  `sync_conn_config.go:234-248` + `sync_conn.go:480-497`):
  witness-Down + counter==0 at the (2c) instant can precede a
  late dispatch; the fence's safety is the COMPOSITION — (2c)
  drains, (3) RE-READS the counter (a pre-(3) dispatch is
  caught by (3)'s counter term), and a post-(3) dispatch is
  residual (iii)'s admitted local window. (c) THE DISABLED-SYNC
  SUBCLASS IS NAMED (Codex M3, verified: `ConfigSync` defaults
  false unless `configuration-synchronize` exists,
  `compiler_system.go:1872-1874`, `types_chassis.go:113`; the
  reconciler also skips on the sync-disabled gate,
  `daemon_ha_sync.go:461-465`): a preempting peer whose older
  loaded config has ConfigSync=false leaves NEITHER side
  pushing — the divergence does NOT self-heal; the
  intended-config comparison DETECTS it and the runbook pins
  the MANUAL re-convergence action. (d) THE DURABILITY SYNC
  PINS EVERY AFFECTED NODE (Codex M4, verified: the barrier is
  the resolved target's parent-directory fsync,
  `fsatomic.go:354-366`, and residual (iii)'s post-rename
  failure can belong to the PEER's filesystem; the peer can
  otherwise restart, load the visible content, and have
  equality suppress the rewrite, `daemon_apply.go:49-70`,
  `daemon_ha_sync.go:550-568`): a successful directory `sync`
  of the configdb parent on BOTH nodes before EITHER restart.
  (e) THE DONE PREDICATE IS THE FULL AGGREGATE (Codex M5,
  verified: a restart-time push can promote+apply the intended
  config while its disk write fails,
  `store.go:687-689,738-769`, leaving the aggregate true while
  the parts pass, `store_persist.go:342-352`):
  `ConfigPersistDegraded() == false` — over
  ActivePersistDegraded, the mask, ConfirmRecordState, and
  ConfigWriteUnverified — on BOTH nodes. (f) The intended-config
  capture is an OFF-NODE canonical digest taken BEFORE the
  fence (Codex m1, verified the show/export/compare surfaces
  redact secrets, `grpcapi/server_config.go:347-356`,
  `api/config.go:304-312` — a secret-only regression would
  compare equal on them). (g) The direct-injection tests are
  migrated (Codex m2, verified:
  `sync_config_gen_test.go:226-237,256-267`,
  `sync_config_epoch_sweep_race_6284_test.go:104-108` enqueue
  unreserved items that would underflow the unconditional
  dequeue defer) — each routed through dispatch or given an
  explicit reservation.
  v46: r45 convergence — the gate becomes atomic, the
  composition gains the sticky epoch witness, the residual
  wording aligns on the apply's landing, the done predicate
  gains ActiveApplied, and the disabled-sync recovery becomes
  executable (Codex NEEDS-REVISION 5M/4m, folds 1 FOLDED /
  6 PARTIAL, structure confirmed; AGY NEEDS-REVISION 1M — the
  gate atomicity, IS Codex M1 + SMR m1, folds 6 FOLDED /
  1 PARTIAL, structure confirmed; SMR PLAN-READY-WITH-NITS
  0M/2m — the gate atomicity + the withdrawal-consistency
  scoping; all three reviewers independently caught the
  gate-atomicity gap): (a) CHECK+RESERVE+ENQUEUE IS ONE
  CRITICAL SECTION (Codex M1 + AGY M1 + SMR m1, the narrower
  interleaving verified: a reader observing LIVE and preempted
  before the send can enqueue after Stop's one-shot drain with
  no consumer left) — serialized against Stop's
  dead-publication and drain under `s.mu` or an equivalent
  lock, the drain holding the same exclusion; the §9 seam moves
  to after the live observation/reservation. (b) THE STICKY
  EPOCH WITNESS (Codex M2, verified: a dispatch can land,
  apply cleanly, and retire between (2c) and (3) — the level
  returns to zero): (3) now ALSO compares the MONOTONIC
  config-sync epoch (`lastAppliedConfigGen` /
  `ConfigsReceived`, already surfaced, `status.go:340-356`)
  against the (2c) observation — a clean pulse MOVES the epoch
  even though the level returns to zero; §9 gains the
  pulse-between-reads leg. (c) THE RESIDUAL COVERS THE APPLY'S
  LANDING, NOT THE PUSH'S INITIATION (Codex M3, verified: a
  complete frame paused pre-dispatch, `sync_conn_read.go:84-93`,
  or held as the handshake's `pendingFrame`,
  `sync_auth.go:352-369`, can be RECEIVED before the preflight
  yet dispatch after it — "initiated BETWEEN" excluded exactly
  that frame, and the acceptance copy's "landing" disagreed):
  both copies now read "whose APPLY lands between the preflight
  and the stop, regardless of when the frame was received".
  (d) THE DONE PREDICATE GAINS `ActiveApplied() == true` ON BOTH
  NODES (Codex M4, verified: SyncApply promotes before the
  dataplane apply; a nonfatal apply failure leaves
  ActiveApplied false, `store.go:797-809`,
  `daemon_apply_commit.go:464-494`, while every persistence
  field and both digests pass; the config-apply health alarm is
  delayed and diagnostic-only, `sync_conn_config.go:369-379`).
  (e) THE DISABLED-SYNC RECOVERY IS EXECUTABLE (Codex M5,
  verified: no operator-callable unconditional push exists —
  `syncConfigToPeer` enforces authority, `pushConfigToPeer`
  enforces ConfigSync, `daemon_ha_sync.go:336-370` — and the
  intended holder can be the read-only secondary,
  `store.go:344-354`): the operator captures the COMPLETE
  UNREDACTED artifact off-node before the fence (the cleartext
  Show* SSOT backs HA sync and the DR archive,
  `grpcapi/server_config.go:349-352` — a digest alone cannot
  reconstruct text), and the recovery is an AUTHORITY-SIDE
  `load override` + `commit` from the captured
  artifact. (f) The surviving instantaneous-join claims are
  scoped (Codex m1 + SMR m2): the counter is a true join OVER
  DISPATCHED FRAMES; "gap-free" is qualified at both surviving
  sites; the witness registers REGISTERED readers (unregistered
  readers are the counter's domain). (g) The post-(3) closure
  wording is corrected (Codex m2): the closure is the directory
  barrier + the intended-digest/full-aggregate/ActiveApplied
  verification, NOT next-boot reclassification. (h) The digest
  gains an executable surface (Codex m3): the active-config
  canonical digest is wired onto the same cluster-status RPC
  the counter joins; the "grpcapi/cli untouched" scoping is
  amended to admit exactly that field. (i) The test inventory
  is COMPLETE (Codex m4, grep-verified): 17 direct sends —
  `sync_config_gen_test.go:236,237,266,267,293,322,340,357`,
  `sync_config_epoch_sweep_race_6284_test.go:108,163,198`,
  `sync_config_health_6387_test.go:152,207,253,281,330,338`.
  v47: r46 convergence — the epoch becomes a pinned
  node-lifetime dispatch epoch, the done predicate becomes
  observable and closed, and the capture surface becomes the
  on-disk active file (Codex NEEDS-REVISION 3M/3m, folds 3
  FOLDED / 5 PARTIAL / 1 NOT-FOLDED, structure confirmed; AGY
  PLAN-READY 9/9 with 3 fresh attacks FAILED, structure
  confirmed; SMR PLAN-READY-WITH-NITS 0M/1m — the
  epoch-lifetime pin, IS Codex M1): (a) THE NODE-LIFETIME
  MONOTONIC DISPATCH EPOCH (Codex M1, verified the
  provider-scoped candidates fail: `lastAppliedConfigGen`
  ignores gen-0 and failed applies and resets on bulk re-prime,
  `sync_conn_config.go:275-286,351-395`,
  `sync_conn_gen.go:340-367`; `ConfigsReceived` increments
  before disposition and is provider-scoped,
  `sync_conn_read.go:298-330`, `sync.go:293-301,805-857` — a
  transport-changing apply's provider swap ABA-erases a pulse,
  `daemon_apply_tail.go:238-255`): ONE explicitly named epoch,
  incremented in the same critical section on each SUCCESSFUL
  reservation, living in node-lifetime state beside the counter
  and preserved across every SessionSync replacement, exposed
  beside the counter; the (3) comparison uses it, and the
  runbook's conservative-false-positive rule is EXPLICIT
  (re-baseline and repeat the (2c)→(3) pass — the peer is
  stopped, so the epoch settles). (b) THE DONE PREDICATE IS
  OBSERVABLE AND CLOSED (Codex M2): ActiveApplied is exposed
  beside the counter/epoch/digest on the cluster-status
  rendering (internal today, `health.go:65-84`); the predicate
  gains `IsConfirmPending() == false` AND `IsDirty() == false`
  (or the candidate explicitly discarded) on BOTH nodes
  (verified independent exposed state, `store_commit.go:796-800`,
  `store_lock.go:334-338`, via `GetConfigModeStatus`,
  `grpcapi/server_config.go:98-103`; a `LoadOverride` can set
  dirty without touching active/applied/persistence,
  `store_command.go:304-334`); and the marker-invalidation ask
  (Codex M2c) is RULED ON WITH EVIDENCE rather than folded —
  the appliedDigest is text-scoped by #4957 design: a failed
  SAME-TEXT reapply (`daemon_dhcp.go:73-90`,
  `daemon_apply.go:49-70`) leaves the same text's prior
  converged enforcement (the #5679 deferred commit error is
  the running-node signal, `daemon_apply_dataplane.go:145-159`),
  a failed DIFFERENT-text apply reads ActiveApplied=false via
  the digest mismatch, and a fresh boot's empty digest makes a
  failed bringup read false — the post-restart predicate reads
  the post-bringup state, exactly when it is consulted. (c)
  THE CAPTURE IS THE ON-DISK ACTIVE FILE (Codex M3, verified:
  every rendered surface is redacted,
  `grpcapi/server_config.go:347-380`, `api/config.go:304-352`,
  `cmd/cli/show.go:81-120`; the embedded-TTY cleartext show is
  not instantiated in service mode, `daemon_run.go:601-616`):
  the capture is (α) the canonical digest from the
  cluster-status surface (redaction-free) for verification and
  (β) the intended config's TEXT — the OPERATOR'S OWN committed
  configuration (the procedure changes no config) — for
  re-convergence, with the on-disk `.configdb/active.json` copy
  as the in-box fallback RESTORE artifact, its format caveats
  named (a JSON envelope, not Junos text — it cannot feed
  `load override` directly, `store_command.go:306-309` — and
  key-encrypted when the config carries a master password,
  `crypto.go:262-285`). (d) The JOIN-COHERENCE teardown leg is rewritten as
  reader-wins / Stop-wins (Codex m1 — a freeze INSIDE the
  critical section is impossible under the exclusion; the
  exclusion prevents the interleaving by construction). (e)
  `load replace` dropped (Codex m2 — modes are
  override/merge/set, `cmd/cli/main.go:549-590`). (f) The
  residual unscoped claims are scoped (Codex m3): the live
  GAP-FREE heading, the ALL-INGRESS JOIN phrasing, and the
  witness's "every relevant ingress reader" all now say
  REGISTERED readers / DISPATCHED frames; and the §5.1
  contradiction is resolved — pkg/configstore (canonical
  accessor) + pkg/daemon (injection) + pkg/cluster (rendering)
  are touched, pkg/grpcapi/pkg/cli stay CODE-untouched as
  relays (`server_show_cluster_text.go:66-74`).
  v48: r47 convergence — the epoch publishes with the
  reservation, the same-text rebuttal is withdrawn, the capture
  is ordered after the window resolution and the automation
  quiesce, and the encrypted fallback is pinned to its origin
  node (Codex NEEDS-REVISION 5M/2m, folds 3 FOLDED / 3 PARTIAL,
  structure confirmed; AGY PLAN-READY 6/6 with 2 fresh attacks
  FAILED, structure confirmed; SMR PLAN-READY-WITH-NITS 0M/2m
  — the capture ordering IS Codex M3, the encrypted-fallback
  scope IS Codex M5): (a) THE EPOCH PUBLISHES WITH THE
  RESERVATION (Codex M1, verified the race: an epoch
  incremented only on a successful reservation can publish
  AFTER a fast consumer applies and retires, letting (3)
  observe the stale epoch with a zero counter): the epoch
  advances WITH the provisional pre-enqueue reservation and
  NEVER rolls back — nil/full attempts move the epoch without
  moving the counter (conservative false-positives, covered by
  the re-baseline rule); acceptance leg (f) asserts the epoch's
  visibility at the seam too. (b) THE SAME-TEXT REBUTTAL IS
  WITHDRAWN (Codex M2's counterexample verified: a DHCP lease
  change reapplies the same T to build address-scoped
  host-inbound enforcement for the NEW address,
  `daemon_dhcp.go:231-245`; an nft failure leaves the prior
  kernel generation covering only its former destinations,
  `daemon_nft.go:262-272`; the error returns without clearing
  the old digest, `daemon_apply_tail.go:83-89,316-327`,
  `daemon_apply.go:56-70` — ActiveApplied compares H(T) only):
  the done predicate ALSO requires NO dataplane apply failure
  since the post-restart bringup on EITHER node — the
  last-apply-outcome + a monotonic apply-failure count tracked
  in the daemon's health state and rendered beside
  ActiveApplied. (c) THE CAPTURE IS ORDERED (Codex M3 = SMR m2,
  the sharper construction verified: capturing T1 while a
  commit-confirmed window is live, then rolling back to T0 at
  step (1), leaves the captured pair stale —
  `store_commit.go:427-461,503-524` — and a stale-pair restore
  Loads T1 AS committed, `store_persist.go:21-55`): the
  runbook gains (1a) the AUTOMATION QUIESCE and (1b) the
  capture AFTER the window resolution + the moratorium; any
  commit that lands anyway forces a re-capture. (d) THE
  AUTOMATION MORATORIUM (Codex M4, verified: the event engine
  autonomously stages and commits, `engine.go:920-948`, via
  `commitAndApply` WITHOUT peer sync,
  `daemon_apply_tail.go:446-455` — invisible to the counter and
  the epoch — and shutdown does not fence it,
  `daemon_run_shutdown.go:25-59`, `engine.go:354-367,583-595`):
  if any `event-options` policy is configured, the operator
  `deactivate event-options` and commits FIRST (before the
  capture); the post-restart digest comparison is the backstop
  detection. (e) THE ENCRYPTED FALLBACK IS ORIGIN-NODE-PINNED
  (Codex M5 = SMR m1, verified: the body is keyed by the
  source's independently-random master.key,
  `crypto.go:262-285,457-480`, and a different authority cannot
  AEAD-open it, `crypto.go:307-356,443-455`): the file-level
  restore applies to the ORIGIN node when encrypted; only the
  cleartext-body (no master password) file is portable; the
  operator's config TEXT is the primary artifact in all cases.
  (f) Residual (iii)'s window runs from the preflight's FIRST
  sub-read (Codex m1 — the /health and cluster-status reads
  are not one coherent snapshot; a promote+fail-persist+retire
  can slip between them, `store.go:687-746`; the post-restart
  closure handles the outcome). (g) The on-disk file is an
  opaque config-DB artifact (Codex m2 — magic-header framing
  line + possibly-encrypted JSON body, `envelope.go:78-99`,
  `db.go:445-450` — preserved byte-for-byte).
  v49: r48 convergence — the epoch contract is unified, the
  apply-failure predicate is executable, the quiesce is a
  verified two-node step with a re-activation ending, and the
  encrypted-fallback recovery has its choreography (Codex
  NEEDS-REVISION 5M/2m, folds 2 FOLDED / 5 PARTIAL, structure
  confirmed; AGY PLAN-READY 7/7 with 2 fresh attacks FAILED,
  structure confirmed; SMR PLAN-READY-WITH-NITS 0M/1m — the
  missing re-activation, IS part of Codex M3): (a) THE EPOCH
  CONTRACT IS UNIFIED (Codex M1, verified the contradiction:
  the live runbook said provisional-and-never-rollback while
  §5.1, the formal (3), and JOIN leg (h) still said
  "successful reservation"): ALL sites now read advanced WITH
  the provisional pre-enqueue reservation, NEVER rolled back;
  a nil/full attempt moves the epoch without the counter; and
  the (h) leg asserts a nil/full attempt advances the epoch
  permanently. (b) THE APPLY-FAILURE PREDICATE IS EXECUTABLE
  (Codex M2, verified the existing surfaces do not carry it:
  compile health is compile-specific, `daemon.go:871-880`,
  `daemon_health.go:79-125`; `ConfigsApplyFailed` is
  SessionSync-only, `sync.go:110-119`,
  `sync_conn_config.go:351-379`; the DHCP/boot/feeds applies
  run separate wrappers, `daemon_apply.go:49-86`): a
  PROCESS-LIFETIME apply-failure counter + last-outcome flag,
  initialized BEFORE the restarted process's boot apply and
  instrumented CENTRALLY at every full-apply entry (the §5.1
  pkg/daemon inventory carries it), rendered beside
  ActiveApplied; the predicate is failure-count == 0 AND
  last-outcome-success; §9 gains the sticky same-text
  regression. (c) THE QUIESCE IS A VERIFIED TWO-NODE STEP WITH
  A RE-ACTIVATION ENDING (Codex M3 + M4 + SMR m1, all parts
  verified: an operator commit syncs only from the RG0
  authority and is suppressed when ConfigSync is disabled,
  `daemon_apply_commit.go:578-601`, `daemon_ha_sync.go:336-370`;
  a promoted secondary is writable and commits locally with
  syncPeer=false, `daemon_ha.go:438-450`,
  `daemon_apply_tail.go:446-455`; a promotion can persist
  before an apply aborts ahead of tail step 17, leaving the
  durable tree deactivated while the live engine retains its
  policies, `daemon_apply.go:282-309,404-409`,
  `daemon_apply_tail.go:194-202`): the deactivation is applied
  per-node with each commit's own success required (the tail
  abort surfaces as the #5679 deferred error); the quiesce's
  config change is admitted (it is NOT "no config change" —
  `store_command.go:111-129`, `config/inactive.go:5-10`); the
  PRE-QUIESCE digest is captured before (1a) and the procedure
  ENDS with the re-activation commit + re-verification against
  the pre-quiesce digest (the two-digest discipline). (d) THE
  ENCRYPTED-FALLBACK CHOREOGRAPHY (Codex M5, verified the
  contradiction: the intended holder can be the read-only
  secondary AND non-portable): restart the INTENDED-CONFIG
  HOLDER first — its `Load` classification completes before
  cluster comms, `daemon_run.go:157-177,393-398` — and ensure
  it is the RG0 authority before any older-config peer can
  overwrite it; only then restart the other node. (e) The
  acceptance copy's residual (iii) window is aligned to the
  FIRST sub-read (Codex m1). (f) The re-baseline rule gains
  the TERMINATION CLAUSE (Codex m2, verified: unkeyed
  third-party ingress keeps advancing the never-rolled-back
  epoch, `sync_admission.go:58-83`, `sync_auth.go:321-334`):
  if the epoch STILL advances after the second re-baseline,
  the stopped remediation is UNAVAILABLE while pulses continue
  (fail-closed); the operator fences the ingress source or
  uses the live removal path.
  v50: r49 convergence — the apply-health state machine is
  fully specified, the re-activation mirrors the quiesce, and
  the restart choreography becomes election-aware (Codex
  NEEDS-REVISION 3M/2m, folds 2 FOLDED / 4 PARTIAL, structure
  confirmed; AGY NEEDS-REVISION 1M — the restart contradiction
  plus the preemption sub-point, IS Codex M3, structure
  confirmed; SMR PLAN-READY-WITH-NITS 0M/2m — the re-capture
  scope IS Codex m2, the restart reconciliation IS Codex M3 /
  AGY M1; all three reviewers independently caught the
  restart-choreography contradiction): (a) THE APPLY-HEALTH
  STATE MACHINE IS SPECIFIED (Codex M1, verified the v49 fold
  referenced §5.1/§9 artifacts that were absent — an
  honest-fold failure repaired here — and the false-green
  in-flight window: a DHCP/feed reapply can be mid-flight with
  ActiveApplied true and the count still zero,
  `daemon_dhcp.go:73-90`, `daemon_feeds.go:26-42`,
  `store.go:797-809`): the §5.1 pkg/daemon inventory now
  carries the state — process-lifetime `applyFailureCount` +
  `lastApplyOK`, initialized BEFORE the boot apply, written
  centrally at the single full-apply entry with `lastApplyOK`
  set FALSE AT ENTRY and TRUE only on a nil return
  (`daemon_apply.go:49-86,141-355`) — and §9 gains BOTH legs:
  the sticky-failure regression (a failed same-text reapply
  keeps ActiveApplied true while the count moves) and the
  parked-mid-apply regression (an in-flight apply reads
  lastApplyOK == false from entry). (b) THE RE-ACTIVATION
  MIRRORS THE QUIESCE (Codex M2, verified: with
  ConfigSync=false one commit cannot update the peer,
  `daemon_ha_sync.go:336-364`, and the Store promotes before
  apply, `daemon_apply_commit.go:225-246`, so a reactivation
  apply can abort before the engine's reconciliation,
  `daemon_apply_tail.go:194-202`, leaving the digest restored
  while automation stays empty): the re-activation is applied
  ON BOTH NODES with each commit's own success required, and
  is followed by the COMPLETE predicate again (not merely
  digest equality). (c) THE CHOREOGRAPHY IS ELECTION-AWARE
  (Codex M3 + AGY M1, both verified: restart order does NOT
  hold authority — a higher-effective-priority peer preempts
  after joining, `election.go:172-193`; the reconciliation is
  authority-gated and stability-delayed,
  `daemon_ha_sync.go:447-465`): restart the intended holder
  first, start the peer, LET THE ELECTION SETTLE, read the
  post-election RG0 state, and `load override` + `commit` the
  intended text on WHICHEVER node holds authority — with sync
  disabled no config flows and the re-convergence is per-node
  (`daemon_ha_sync.go:336-370,461-465`); the precedence rule is
  explicit: intended-holder-first GOVERNS, the plain repair
  case (holder == local) IS the r39 local-first pin's case,
  and the pin's protection is per-node (each node's `Load`
  completes before its own comms). (d) The acceptance copy
  gains the re-baseline termination branch (Codex m1). (e) The
  re-capture rule covers BOTH baselines (Codex m2 = SMR m1).
  v51: r50 convergence — the apply-health state publishes as
  one coherent snapshot with truth at the convergence point,
  the choreography joins the outbound reconciler, and the
  authority-dependent branches become executable (Codex
  NEEDS-REVISION 4M/1m, folds 2 FOLDED / 3 PARTIAL, structure
  confirmed; AGY PLAN-READY-WITH-NITS 0M/1m — the acceptance
  re-activation copy, IS Codex fold-2's PARTIAL, folded here;
  SMR PLAN-READY-WITH-NITS 0M/1m — the push-window clause, IS
  part of Codex M3, folded here): (a) THE COHERENT SNAPSHOT
  CONTRACT (Codex M1, verified the render race: independent
  atomics rendered beside the independently-locked
  ActiveApplied with the show path taking no applySem can read
  old-lastOK=true then count==0 then still-true ActiveApplied
  while an apply is parked, `store.go:797-809`,
  `server_show_cluster_text.go:66-74`): the apply-health fields
  publish as ONE immutable snapshot struct swapped under a
  single `atomic.Pointer`; the renderer reads exactly one
  snapshot; §9 gains the mid-render-entry leg. (b) TRUTH AT
  THE CONVERGENCE POINT (Codex M2, verified both false-green
  paths: the mandatory deferred-MAC second `ApplyConfig` can
  fail while merely recording retry debt and the commit still
  succeeds, `daemon_apply_dataplane.go:390-402,466-489`,
  `manager_worker_arm_5134.go:10-21`; a `dp.Start` failure
  clears `d.dp` yet still runs the boot apply whose dataplane
  phase skips nil `d.dp`, `daemon_run_bringup.go:493-520`,
  `daemon_apply_dataplane.go:137-163`): `lastApplyOK` reads
  TRUE only when the dataplane phase actually converged — both
  outcomes record NOT-converged (count++, lastOK false). (c)
  THE OUTBOUND-RECONCILER JOIN (Codex M3, verified the
  stale-capture construction: the reconciler captures old text
  and claims the old marker without applySem serialization,
  `daemon_ha_sync.go:462-497`; a paused reconciler can
  `QueueConfig` the OLD text with a NEWER wire generation,
  `sync_conn_config.go:222-243`, which the receiver accepts and
  applies, `sync_conn_config.go:254-272,325-395` — AFTER the
  predicate passed — and the claimed marker suppresses the
  self-heal, `daemon_ha_sync.go:479-484`): the re-convergence
  commit runs only AFTER the authority's first post-election
  post-stability reconcile pass is OBSERVED complete (the
  `ConfigsSent` tick, `status.go:340-356`); the stale pass's
  old-text push is overwritten by the operator's newer-gen
  commit push, and every later pass carries the intended text.
  (d) THE AUTHORITY-DEPENDENT BRANCHES ARE EXECUTABLE (Codex
  M4, verified both dead ends: the read-only secondary rejects
  mutations, `store.go:346-353`, `store_lock.go:9-27`; only
  the RG0 primary is writable and promotion clears the gate,
  `daemon_ha.go:438-475`): a per-node commit on a read-only
  secondary is executed by PROMOTING it first with the
  existing manual-failover request, then restoring the intended
  mastership; and the terminal corner (encrypted origin-pinned
  artifact + no operator text + cross-node need) is NAMED
  runbook-unrecoverable — fail-closed, rebuild from config
  management. (e) The acceptance re-activation copy gains the
  two-node + complete-predicate form (r50 AGY m1 = Codex
  fold-2's PARTIAL), and the acceptance apply-failure term
  gains the executable failure-count == 0 AND
  last-outcome-success form (Codex m1).
  v52: r51 convergence — the snapshot gains a single-owner
  versioned contract with a seqlock read side, the convergence
  signal covers the pending-XSK deferral, and the reconciler
  join becomes the interval-bracketed double digest check
  (Codex NEEDS-REVISION 4M/1m, folds 2 FOLDED / 3 PARTIAL,
  structure confirmed; AGY NEEDS-REVISION 1M — the tick-hang,
  IS Codex M4's second half; SMR PLAN-READY-WITH-NITS 0M/1m —
  the witness clause, IS Codex M4): (a) THE SINGLE-OWNER
  VERSIONED SNAPSHOT (Codex M1, verified the ownership gap:
  the store's promotion changes ActiveApplied's computed truth
  BEFORE `applyConfigLocked` begins while the MarkActiveApplied
  stamps land AFTER the boundary,
  `daemon_apply_commit.go:194-246,277-286,464-475`,
  `store.go:781-809,831-848` — copying ActiveApplied at the
  boundary can read false after success): the CONFIGSTORE owns
  the converged-state snapshot; every promotion and every
  applied-digest/apply-outcome stamp publishes the same
  versioned snapshot. (b) THE SEQLOCK READ SIDE (Codex M2,
  verified the load→failed-apply→resume race: a one-load
  reader descheduled through a failed apply returns the
  captured green, `daemon_dhcp.go:73-90`,
  `daemon_feeds.go:26-41`, `server_show_cluster_text.go:66-74`):
  read the version, read the snapshot, RE-READ the version,
  retry on change — the versioned re-read is the linearization
  point (the show path takes no applySem). (c) THE PENDING-XSK
  FEED (Codex M3, verified: the userspace compile records the
  desired snapshot and returns nil while deferring publication,
  `manager_compile.go:230-257,289-298`,
  `manager.go:348-357`, and the rejection is merely logged and
  retried, `process_status.go:118-131,183-186`): the deferral
  records NOT-converged until the publication completes, and a
  deferred-publication failure drives lastOK=false / count++.
  (d) THE INTERVAL-BRACKETED DOUBLE DIGEST CHECK (Codex M4 +
  AGY M1, both verified: a marker no-op pass returns before
  QueueConfig and never ticks ConfigsSent,
  `daemon_ha_sync.go:478-485`, `sync_conn_config.go:234-250` —
  the tick-hang — and a pass paused after claiming can survive
  a reconnect's epoch bump and resume with a newer wire
  generation, `daemon_ha_sync.go:51-57,474-489`,
  `sync_conn_config.go:222-243,254-272,325-395`, the claimed
  marker suppressing repair, `daemon_ha_sync.go:479-484`):
  the tick/no-op witness is dropped; the operator re-reads BOTH
  nodes' digests after the re-convergence and again after ONE
  FULL reconcile interval (`periodic = 30s`,
  `configSyncReconcileLoop`), re-driving the intended text on
  ANY flip (the operator's commit push always carries the
  newest wire generation); a still-flipping state after two
  intervals is a stuck-lock incident — fail-closed. (e) §9
  gains the contract legs (Codex m1): stale-snapshot-return,
  mid-render-entry, single-owner publication order,
  pending-XSK rejection, the paused-outbound-claimant /
  reconnect / commit / release ordering, and marker-no-op
  rejection.
  v53: r52 convergence — the composite reader joins the
  snapshot, the convergence signal becomes an attempt-tokened
  multi-arm join with a pending/failed distinction, and the
  obsolete witness gate is struck (Codex NEEDS-REVISION 4M/1m,
  folds 2 PARTIAL / 2 NOT-FOLDED / 1 PARTIAL, structure
  confirmed; AGY PLAN-READY 5/5 with all fresh attacks FAILED,
  structure confirmed; SMR PLAN-READY-WITH-NITS 0M/2m — the
  publication-method name and the seqlock writer double-bump,
  both folded into the §5.1 contract text): (a) THE COMPOSITE
  READER JOINS THE SNAPSHOT (Codex M1, verified:
  `handleConfigSync`'s #4957 converged shortcut reads
  `ShowActive` and `ActiveApplied` in SEPARATE store lock
  transactions, `daemon_ha_sync.go:544-568`,
  `store_format.go:31-36`, `store.go:803-809` — an A→B
  promotion/apply between those reads combines cached text A
  with ActiveApplied(B)==true, returns success for incoming A,
  and advances the receiver high-water,
  `sync_conn_config.go:319-324,390-395`): the shortcut's
  (text, applied) pair is read from ONE versioned snapshot;
  §9 gains the composite-reader leg. (b) THE ATTEMPT-TOKENED
  MULTI-ARM JOIN (Codex M2 + M3, verified: the status loop
  runs outside applySem, `process_status.go:150-186` — an old
  or early completion can stamp lastOK=true during a newer
  apply; and the pending publication is not the only
  asynchronous nil/void outcome — Compile publishes nil before
  XSK liveness is resolved, `manager_compile.go:338-402`, with
  the later probe able to fail closed while merely logging,
  `maps_sync.go:461-545`, and the link-cycle rebind is a void
  call whose failure is swallowed,
  `daemon_apply_dataplane.go:390-401`,
  `process_linkcycle.go:184-224`): EVERY asynchronous arm —
  deferred-MAC, pending-XSK publication, XSK-liveness probe,
  link-cycle rebind — carries the apply's ATTEMPT TOKEN, and
  the signal reads CONVERGED only when the pipeline AND every
  arm's completion carry the CURRENT attempt token; the
  two-phase join is pipeline complete AND publication complete.
  (c) THE PENDING/FAILED DISTINCTION (Codex m1, verified the
  contradiction: pending was NOT-converged and every
  non-converged return incremented the process-lifetime count,
  while acceptance required count==0 — so even clean
  completion could never rehabilitate the predicate): the
  state machine distinguishes CONVERGED / PENDING / FAILED —
  a PENDING arm holds the predicate WITHOUT moving the failure
  count (the count moves only on a terminal failure); the
  predicate requires count==0 AND no pending arm outstanding
  AND lastOK. (d) THE OBSOLETE WITNESS GATE IS STRUCK (Codex
  M4, verified the leftover: the runbook still required
  observing the ConfigsSent tick or the marker no-op
  immediately before admitting neither is faithful; the marker
  is private, `daemon.go:420-424`): the interval-bracketed
  double digest check is the ONLY join. (e) The §9 legs gain
  the composite-reader leg, the attempt-token legs across all
  four arms, and the pending/failed distinction leg.
  v54: r53 convergence — the reconciler gains the pre-send
  staleness re-check, the token lifecycle and the pending
  state are fully inventoried, the count semantics align to
  the tri-state, and the v53 claimed-but-missing folds are
  actually written (Codex NEEDS-REVISION 4M/1m, folds 1
  FOLDED / 4 PARTIAL, structure confirmed; AGY
  PLAN-READY-WITH-NITS 0M/1m — the pending-arm inventory, IS
  Codex M3; SMR PLAN-READY-WITH-NITS 0M/2m — the token seeding
  IS part of Codex M2, the pending observability IS Codex M3):
  (a) THE PRE-SEND STALENESS RE-CHECK (Codex M1, verified the
  paused-claimant class has no timing bound: the reconciler
  claims its marker and unlocks BEFORE `QueueConfig`,
  `daemon_ha_sync.go:462-497`, and a claimant paused past both
  digest reads can resume and take a fresh wire generation,
  `sync_conn_config.go:230-243`): the reconciler RE-VALIDATES
  its captured generation against the store's current active
  generation immediately before `QueueConfig` — a stale
  capture drops with an alarm — closing the class by
  construction, not timing; the observation order is also
  de-circularized (the post-election read DETECTS, the
  re-convergence commit follows, the two bracketing reads
  FOLLOW the re-convergence). (b) THE TOKEN LIFECYCLE (Codex
  M2): uint64 monotonic, minted at the central full-apply
  entry, daemon-owned and published with the configstore's
  versioned snapshot, threaded through the deferring manager
  calls (the tokenless interfaces at `apply.go:37-40,130-134`
  gain it), with manager/helper-restart inheritance seeded
  from the helper's reported generation on attach (the #6034
  resume pattern, `process_status.go:165-172`). (c) THE
  PENDING STATE IS INVENTORIED AND OBSERVABLE (Codex M3 = AGY
  m1 = SMR m2): the snapshot carries the current attempt
  token + a pending-arm count (incremented on deferral,
  decremented on a token-matching completion), rendered beside
  lastOK/count. (d) THE COUNT SEMANTICS ALIGN TO THE
  TRI-STATE (Codex M4, verified the contradiction: §9's h2d
  leg and the §5.1 text still drove count++ on retryable
  rejections while the tri-state said pending does not
  increment and acceptance requires count==0): a retryable
  rejection is PENDING (count unmoved); the count moves only
  on a TERMINAL failure (an apply pipeline failure or an arm's
  retry budget exhausted). (e) THE PUBLICATION METHOD AND THE
  WRITER DOUBLE-BUMP ARE ACTUALLY WRITTEN (Codex m1 — the v53
  revision entry claimed them folded but the normative text
  never gained them, the second honest-fold failure of this
  loop, repaired here): the store's `NoteApplyOutcome`-shaped
  boundary method is the single publication entry every
  failure class flows through, and the writer bumps the
  version BEFORE and AFTER publishing (odd-in-flight /
  even-stable; the reader retries on an odd or changed
  version).
  v55: r54 convergence — the reconciler gains the full
  send-boundary protocol, the token mints at the outer
  apply-attempt entry, the pending state becomes per-arm
  registration, and the arm inventory completes at six (Codex
  NEEDS-REVISION 6M/2m, folds 1 FOLDED / 3 PARTIAL /
  1 NOT-FOLDED, structure confirmed; AGY PLAN-READY 5/5 with
  3 fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — the claim-ordering pin, IS
  part of Codex M1/M2): (a) THE SEND-BOUNDARY PROTOCOL (Codex
  M1 + M2 + M3 + m1, all verified: a re-check alone is not an
  exclusion boundary — `ShowActive` releases the store lock
  before the send, `store_format.go:31-36`, and a paused
  claimant resumes with a newer wire generation,
  `sync_conn_config.go:234-243,267-272`; a stale drop poisons
  the CLAIMED-is-PUSHED marker — the A→B→A case reachable via
  the event engine's syncPeer=false commits,
  `daemon_apply_commit.go:596-599`; the capture's gate reads
  and text read are separate transactions,
  `daemon_ha_sync.go:462-471`; authority can change after the
  gate check, `daemon_ha_sync.go:451-454,544-548`; and the
  capture is a uint64 FNV hash while ActiveDigest is SHA-256,
  `daemon_ha_sync.go:381-388,467-472`,
  `store.go:772-779,812-829`): under `configSyncMu` HELD FROM
  VALIDATION THROUGH SEND-COMPLETION — with EVERY push path
  (reconciler AND commit push) taking the same mutex — the
  reconciler at the boundary (i) revalidates authority +
  connection epoch/liveness + ConfigSync-enabled, (ii)
  recomputes `configGenerationHash(ShowActive())` — same
  function, same type — and drops with an alarm on a
  mismatch, and (iii) claims the marker ONLY at the send
  boundary (validate-then-claim-then-send: a drop never
  claims, so the marker never suppresses a needed push). (b)
  THE OUTER MINT (Codex M4, verified: preflight/compile
  failures return before `applyConfigLocked`,
  `daemon_apply_commit.go:98-126,194-222,551-575`, and
  `commitWithGenBinding` still invokes commitFn after an
  initial compile error): the token mints at the OUTER
  apply-attempt entry (`commitAndApply` and the background
  wrappers, before preflight); a preflight/compile failure is
  a FAILED attempt with no arms. (c) PER-ARM REGISTRATION
  (Codex M5, verified: a scalar pending count is not a join —
  a duplicate completion decrements twice; a post-return
  increment can lose an early completion because ApplyConfig
  can launch a callback before returning,
  `manager_compile.go:357-402`, `maps_sync.go:451-457`):
  (token, arm-ID) registrations recorded BEFORE launch; the
  pending state is a per-arm-ID set; a completion retires its
  own registration exactly once; unregistered or duplicate
  completions are ignored. (d) THE SIX-ARM INVENTORY (Codex
  M6, verified: `OnXSKBound` launches a goroutine whose
  fabric-IPVLAN failure is merely logged,
  `maps_sync.go:451-457`, `daemon_apply_interfaces.go:98-109`;
  `PrepareLinkCycle` suppresses/logs command failures through
  a void interface, `daemon_apply_dataplane.go:289-296`,
  `process_linkcycle.go:145-162`): deferred-MAC, pending-XSK
  publication, XSK-liveness probe, link-cycle rebind,
  OnXSKBound, PrepareLinkCycle — all tokened and registered.
  (e) THE TOKEN NAMESPACE CORRECTION (Codex fold-2): the
  #6034 seed is the neighbor-REPLACE generation, a different
  namespace the helper initializes to zero
  (`process_status.go:165-172`, `protocol_status.go:73-84`,
  `lifecycle.rs:184-216`) — the cross-incarnation rejection
  comes from the registration rule (a completion whose
  (token, arm-ID) was never registered in THIS incarnation is
  ignored), with a manager attach re-registering the current
  attempt's outstanding arms. (f) THE DEFERRED-MAC PENDING
  CORRECTION (Codex fold-4, verified the retry is UNBOUNDED —
  every tick until the workers bind,
  `manager_worker_arm_5134.go:18-38`,
  `process_status.go:183-198`): the deferred-MAC debt is
  PENDING (the predicate stays unblessed, fail-closed); the
  nil-dp skip is TERMINAL. (g) The status rendering carries
  the token + pending-set beside lastOK/count (Codex fold-3),
  and the stale "OBSERVED complete" prerequisite is struck
  (Codex m2).
  v56: r55 convergence — the send-boundary protocol completes
  (provider coherence, authority generation, success semantics,
  single-owner lock discipline), the mint is fully enumerated
  and admission-ordered, OnXSKBound self-registers, the
  supersession re-registers live debts, and the seventh arm
  becomes terminal (Codex NEEDS-REVISION 9M/2m, folds 4
  PARTIAL / 1 NOT-FOLDED, structure confirmed; AGY PLAN-READY
  5/5 with 3 fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — the per-attempt pending-set
  reset, IS Codex M6): (a) PROVIDER COHERENCE + SUCCESS
  SEMANTICS (Codex M1, verified: the captured `ss` can be
  replaced by a transport-changing apply,
  `daemon_apply_tail.go:238-255`,
  `daemon_ha_sync.go:658-667,1405-1415`; `QueueConfig` returns
  no result and may no-op or fail, `sync_conn_config.go:234-250`;
  a fabric-0-fails/fabric-1-survives case fires no daemon
  callback, `sync_conn.go:480-498,569-570`, so the epoch does
  not advance and a pre-send claim would suppress the retry):
  the boundary revalidation gains PROVIDER IDENTITY,
  `QueueConfig` gains a success return, and the marker
  publishes only on send-SUCCESS while still locked. (b) THE
  AUTHORITY GENERATION (Codex M2, verified: RG0 transitions do
  not take `configSyncMu`, `daemon_ha.go:438-450`; a sender
  can validate as primary, demote mid-write, and have the
  frame rejected, `daemon_ha_sync.go:544-548`): the marker's
  claim state gains an authority generation invalidated on any
  demotion/re-promotion. (c) THE LOCK-DISCIPLINE (Codex M3,
  verified the literal self-deadlock: `pushConfigToPeer` →
  `markConfigSyncPushed` independently locks `configSyncMu`,
  `daemon_ha_sync.go:355-377,407-414`): ONE locked-send owner;
  the marker helper is lock-ASSUMING. (d) THE CONTENTION BOUND
  (Codex m1, corrected: `syncWriteDeadline` is 2s,
  `sync.go:88`, starting INSIDE `writeFull` after the
  `writeMu` wait, `sync_protocol.go:59-74`): the mutex can be
  held across a writeMu wait plus a 2s write; a §9 contention
  regression pins it. (e) THE COMPLETE ENTRY ENUMERATION +
  ADMISSION-ORDERED MINT (Codex M4, verified: v55 named only
  commitAndApply and undefined "background wrappers";
  `commitConfirmedAndApply`, `syncAndApply`, the rollback
  path, `applyConfig`, and `applyConfigResult` were omitted;
  and a function-entry mint could supersede the running apply
  while waiting on applySem): every entry is named, the mint
  occurs AFTER applySem admission and BEFORE
  preflight/promotion, and the outcome classifies at the
  TERMINAL outer return (a compile error may still be retried
  by `commitWithGenBinding`, `daemon_apply_commit.go:102-125`).
  (f) MANAGER-OWNED SELF-REGISTRATION (Codex M5, verified the
  daemon-side check/set race: the status loop can set
  `xskBoundNotified` and launch the old callback between the
  daemon's check and its `SetOnXSKBound` call,
  `daemon_apply_interfaces.go:61,98-100`, `manager.go:424-433`,
  `maps_sync.go:451-456`): the manager registers the arm
  atomically with the launch decision under its own `m.mu`.
  (g) THE NEXT-MINT SUPERSESSION (Codex M6 = SMR m1, verified:
  manager work remains live outside applySem,
  `process_status.go:150-198`, including the unbounded
  deferred-worker retry): a new mint ATOMICALLY supersedes the
  old token's registration set AND re-registers every
  still-relevant manager debt under the new token (the daemon
  queries the manager's outstanding debt state at the mint
  boundary). (h) THE SEVENTH ARM MADE TERMINAL (Codex M7,
  verified: `syncInterfaceAttachments`' DetachXDP/DetachTC
  failures are merely logged, `manager_compile.go:211-214,
  567-591`, while ApplyConfig returns nil,
  `manager.go:348-357` — a config removing a data interface
  could be stamped converged with the old attachment live):
  the detach failure becomes a RETURNED TERMINAL pipeline
  failure. (i) The done predicate carries the no-pending term
  in the runbook, acceptance, and status inventory (Codex M8);
  the "every non-converged return increments" leftover is
  aligned to terminal-only (Codex M9); and §9 gains the
  send-boundary legs (Codex m2): mismatch-drop-without-claim,
  commit/reconciler serialization, provider replacement,
  dual-fabric send failure, and authority turnover.
  v57: r56 partial — the consistency findings fold (Codex M7:
  the acceptance copy now carries the full send-boundary
  protocol — provider identity, authority generation,
  success-only publication, the lock-assuming helper — and the
  §5.1 inventory gains the authority/provider state and the
  pkg/dataplane/userspace change list, and §6's signature list
  gains QueueConfig's success return and the token parameters;
  Codex M8: §9 gains the v56-mechanism legs — the OnXSKBound
  callback interleave, PrepareLinkCycle registration, the
  completion-vs-next-mint transaction, the slow-poll mint, the
  returned detach failure with errors.Join over ALL detaches,
  and the authority leg extended through re-promotion; Codex
  m1: the contention leg is named; Codex m2: the pending term
  joins the post-reactivation predicate and the rendering
  inventory; Codex m3: the detach conversion collects every
  attempted detach). The r56 M1-M6 MECHANISM-DEPTH findings
  (the apply-level ACK / receiver-acceptance gap, the
  provider-generation linearization, the authority-invalidation
  race with publication, the rollback health fork, the
  callback identity, the debt-transfer transaction) are NOT
  folded — they are put to all three reviewers for an explicit
  engineering ruling in r57, per the convergence-loop
  discipline: ten rounds (r47-r56) have refined the H2
  done-predicate machinery, with each round's fold introducing
  a new mechanism whose own correctness becomes the next
  round's target. The ruling question: (A) CONTINUE folding
  to instantaneous correctness (the current trajectory — the
  ACK and the remaining transactions get designed in); (B)
  SIMPLIFY THE CLAIM — the done-predicate's machinery reduces
  to the converged core (the counter + epoch + coherent
  snapshot + tri-state + the send-boundary protocol + the
  bracket + re-drive), and the instantaneous-correctness
  constructions become named bounded residuals with
  detection-and-recovery (the interval-bracketed double digest
  check and the operator re-drive) — the runbook's established
  admit+bound idiom from r29/r37/r38 — with the apply-level
  ACK named as a follow-up; or (C) SPLIT H2 further. Each
  reviewer rules explicitly.
  v58: the r57 HYBRID ruling folded — Codex ruled (A) with the
  decisive safety argument (verified in code): M5 defeats
  (B)'s safe-direction premise because a stale OnXSKBound
  closure captures configuration A, runs outside applySem, and
  can resume after apply B to restore A's fabric
  parent/addresses (`daemon_apply_interfaces.go:98-109`,
  `maps_sync.go:451-456`, `daemon_ha_fabric.go:41-54,99-148`)
  — a live-kernel-state mutation the digest bracket cannot
  see — and M4's session-clear fork can leave traffic
  forwarding under stale authorization
  (`daemon_policy_invalidate.go:242-280`,
  `daemon_apply_commit.go:645-708`) while text digests and
  applied state read green. AGY ruled (B) ("none found"
  unsafe); SMR ruled (B) and revises to the hybrid on Codex's
  verified evidence. THE HYBRID: (i) the LIVE-STATE classes
  are closed BY CONSTRUCTION — the rollback fork gains
  explicit NEUTRAL/SUCCESS/FAILURE outcome classification
  through the boundary (the stale-timer no-op is NEUTRAL; the
  nil-target teardown, apply, and session-clear failures are
  FAILURE), and the OnXSKBound callback NEVER applies captured
  state — at fire time it takes `applySem` and re-derives the
  deferred-overlay set from the CURRENT config, abandoning on
  mismatch, so a stale closure is a no-op by construction;
  (ii) the CONFIG-TEXT-VISIBLE classes are named bounded
  residuals with detection-and-recovery — (iv) the
  receiver-rejection / dual-primary marker suppression (the
  bracket catches the digest divergence; the operator's
  re-drive recovers; the post-procedure suppression tail is
  the pre-existing #5863 semantics), (v) the
  provider-replacement and authority-invalidation publication
  races (at worst a stale/rejected push → digest divergence →
  re-drive), and (vi) the exactly-once debt-transfer
  transaction (a stranded arm holds the predicate unblessed —
  fail-closed, the safe direction; the single-retoken
  transaction is a precision follow-up); (iii) the named
  FOLLOW-UP ISSUE is the apply-level config-ACK wire message
  (the receiver ACKs acceptance; the sender's marker publishes
  only on the ACK), hardening the #5863 safety net generally
  (`sync.go:38-76` carries no config-ACK type today). The
  r57-ruling question is thereby answered with the only
  position consistent with all verified evidence: (B) alone
  leaves live-state holes (Codex's M4/M5); (A) alone keeps
  folding digest-visible classes that the detection net
  already covers.
  v59: r58 convergence — the dual-primary live-forwarding
  false green is closed, the callback becomes lifecycle-total
  and outcome-truthful, the queued-waiter window is published,
  and the M6 contradiction is resolved by serialization (Codex
  NEEDS-REVISION 4M/1m, folds 2 PARTIAL / 2 NOT-FOLDED /
  1 PARTIAL, structure confirmed; AGY PLAN-READY 5/5 with 4
  fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — the acceptance residual
  enumeration, folded here): (a) THE COMPLEMENTARY-AUTHORITY
  CHECK (Codex M1, verified the live-state false green: a
  receiver-primary rejection during dual-primary leaves BOTH
  nodes holding fully-applied intended text — every digest
  and apply-health field green — while BOTH primary
  transitions enable live forwarding, `daemon_ha.go:273-325`,
  `daemon_ha_sync.go:545-548`): the terminal verification
  requires the RG0 election SETTLED with EXACTLY ONE primary
  matching the intended mastership, read on the cluster
  status surface, in both copies. (b) THE CALLBACK IS
  LIFECYCLE-TOTAL AND OUTCOME-TRUTHFUL (Codex M2, both halves
  verified: shutdown can release applySem before the detached
  callback runs, `daemon_run_shutdown.go:50-64,214-230`; and
  `ensureFabricIPVLAN` ignores the parent-up failure, returns
  nil after void address reconciliation, and only logs
  several failures, `daemon_ha_fabric.go:29-50,78-88,115-147`):
  the callback re-checks the work-item-G `stopping` fence
  AFTER acquiring applySem and abandons on it, and its
  fire-time work reports its outcome INTO the arm's
  registration — a creation/reconciliation failure retires
  the arm FAILED, never converged. (c) THE QUEUED STATE IS
  PUBLISHED AT ENQUEUE (Codex M3, verified the queued-waiter
  window: a DHCP lease change precedes its applyConfig's
  semaphore wait, and the reapply is required to rebuild the
  address-scoped host-inbound enforcement,
  `daemon_dhcp.go:73-90,231-260` — so after the holder
  publishes SUCCESS and before the waiter acquires, every
  field could read green over stale enforcement): an apply
  attempt publishes QUEUED (not converged) at enqueue, BEFORE
  the semaphore wait. (d) THE M6 CONTRADICTION IS RESOLVED BY
  SERIALIZATION (Codex M4, verified the v58 fold both
  deferred and required the single-retoken transaction, and
  the false-green interleave: an arm self-registering between
  the manager snapshot and the supersession could be
  discarded, its completion then ignored — work live with the
  predicate green): registration, completion, AND the
  mint-boundary supersession ALL serialize through the
  manager's `m.mu` — the transaction is part of the plan; the
  residual (vi) stands only for the deeper cross-incarnation
  precision follow-up. (e) §9 gains the hybrid-closure legs
  (Codex m1): the rollback-fork legs and the stale-callback
  legs; and the acceptance copy's residual enumeration gains
  (iv)-(vi) plus the authority check (SMR m1).
  v60: r59 convergence — the authority check verifies the
  ACTUATED state, the callback fence is full-form with deep
  outcome reporting, the QUEUED model gains its ordering and
  retirement rules and its actual §5.1 placement (the third
  honest-fold failure, owned), and residual (vi) is withdrawn
  (Codex NEEDS-REVISION 5M/2m, folds 1 FOLDED / 3 PARTIAL /
  1 NOT-FOLDED, structure confirmed; AGY NEEDS-REVISION 1M —
  the QUEUED-overwrite, IS part of Codex M4; SMR
  PLAN-READY-WITH-NITS 0M/1m — the additive-QUEUED pin, IS
  part of Codex M4): (a) THE ACTUATED-STATE AUTHORITY CHECK
  (Codex M1, verified: `runElection` publishes state before
  the daemon consumes the event, the desired activity is
  cluster-primary OR VRRP-master, so a demoted election state
  can retain rg_active while VRRP is still MASTER, and a
  SetRGActive failure leaves that live until a later retry,
  `election.go:337-395`, `rg_state.go:250-263`,
  `daemon_ha.go:340-371,809-848`; and the status combines
  local and cached-peer snapshots from different instants,
  `status.go:12-25`, `heartbeat_manager.go:306-355`): the
  check requires exactly one node with RG0 ACTIVE AND VRRP
  MASTER — the actuated state — and the term joins the final
  post-reactivation predicate. (b) THE FULL-FORM FENCE + DEEP
  OUTCOME REPORTING (Codex M2, verified: signal-driven
  teardown begins BEFORE `runShutdownSequence` publishes
  `stopping`, and the drain proceeds after its 5s timeout,
  `daemon_run_shutdown.go:50-64,214-230`; and
  `ensureFabricIPVLAN`'s failure suppression is multi-layer,
  `daemon_ha_fabric.go:29-53,72-93,102-148`): the callback
  checks `runCtx.Err()` OR `stopping` after acquiring applySem
  AND again before each mutation; every operation's failure is
  returned and aggregated (`errors.Join`), the existing-link
  acceptance gains the KIND check, and any aggregated failure
  retires the arm FAILED. (c) THE QUEUED MODEL — ACTUALLY
  PLACED, WITH ORDERING AND RETIREMENT (Codex M4 + AGY M1 +
  SMR m1 + Codex fold-3's honest-fold catch — the v59 QUEUED
  fold landed only in the revision-history prose, the THIRD
  such failure this loop, owned): the publication is
  generation-tagged (a lower-generation publication never
  overwrites a higher-generation state — A's trailing SUCCESS
  cannot erase B's QUEUED), the queued state is a per-attempt
  SET, a canceled acquisition retires its entry
  (`daemon_apply_commit.go:172-175`), the queued-to-running
  transition is atomic at admission, and the state lives in
  the process-lifetime snapshot (`store.go:302-319`,
  `daemon.go:1046-1054`) — placed in §5.1, the acceptance
  copy, and §9 this time. (d) RESIDUAL (vi) WITHDRAWN (Codex
  M5, verified the contradiction: an omitted cross-incarnation
  arm's ignored completion was a possible false green): the
  serialized supersession's re-registration is TOTAL — every
  live manager debt re-registers under the new token — so no
  live arm is ever omitted; the transaction is implemented,
  not residual. (e) The §5.1 changed-file inventory gains
  `daemon_apply_interfaces.go` + `daemon_ha_fabric.go` (Codex
  m1), and the acceptance post-reactivation predicate gains
  the no-pending + authority terms (Codex m2).
  v61: r60 convergence — the actuated predicate becomes
  multi-term with per-node reads, the callback gets the
  teardown-serialized lease, the three identities and the
  fieldwise merge are defined, the completion alias covers
  carried-forward arms, and the debt ledger gets its own lock
  (Codex NEEDS-REVISION 7M/4m, folds 1 FOLDED / 3 PARTIAL /
  1 NOT-FOLDED, structure confirmed; AGY NEEDS-REVISION 3M/1m
  — the actuated-state observability IS Codex M1, the
  in-flight registration IS Codex M5, the mint-vs-QUEUED
  identity IS Codex M3, the counter divergence IS part of
  Codex M3; SMR PLAN-READY-WITH-NITS 0M/2m — the two-counter
  relationship IS part of Codex M3, the in-flight retoken rule
  IS Codex M5): (a) THE MULTI-TERM ACTUATED PREDICATE (Codex
  M1 + AGY M1, verified: RG0 normally has NO VRRP instance,
  `vrrp/manager.go:929-936`, `vrrp.go:128-142,170-173` —
  "RG0 ACTIVE AND VRRP MASTER" is not generally observable;
  and for a VRRP-backed RG the demotion resigns VRRP BEFORE
  clearing rg_active, so a failed SetRGActive leaves the
  loser ACTIVE+BACKUP while the winner is ACTIVE+MASTER):
  the check is exactly one node with RG0 rg_active, exactly
  one VRRP MASTER where a VRRP-backed RG applies, BOTH on the
  intended node, and the loser EXPLICITLY INACTIVE — read
  PER-NODE on each node's OWN status surface (the operator
  already reads the peer via its localhost per the r42 fold).
  (b) THE TEARDOWN-SERIALIZED CALLBACK LEASE (Codex M2,
  verified: the netlink mutations are non-contextual calls and
  a signal can arrive after any check, with shutdown
  proceeding after its bounded drain,
  `daemon_run_shutdown.go:50-64,214-230`): the callback is
  included in the shutdown's JOIN SET — the teardown waits
  for in-flight callbacks before the dataplane teardown; the
  callback's body is bounded netlink work; the 5s bound
  remains the safety net. (c) THE THREE IDENTITIES + THE
  FIELDWISE MERGE (Codex M3 + AGY M3 + M4 + AGY m1 + SMR m1):
  the ENQUEUE-RESERVATION SEQUENCE (monotonic, minted at
  enqueue) tags the QUEUED publication; the ADMISSION ATTEMPT
  TOKEN mints at admission and the queued entry MIGRATES to it
  atomically; the seqlock version is a third counter (per
  publication, both sides); and publications merge FIELDWISE
  MONOTONIC — the failure count is a monotonic accumulator
  every terminal failure increments regardless of generation,
  while the per-attempt state fields are generation-guarded.
  (d) THE COMPLETION ALIAS (Codex M5 + AGY M2 + SMR m2): a
  carried-forward registration records the ALIAS
  (old-token, arm-ID) → (new-token, arm-ID), and a completion
  for the aliased old identity retires the carried
  registration — an in-flight arm's completion is never lost
  across a supersession. (e) THE DEBT-LEDGER LOCK (Codex M6,
  verified the contradiction: serializing through `m.mu`
  collides with the short-held rule — the status loop holds
  `m.mu` across `requestLocked`, whose round trip can block
  for 120s, `process_status.go:160-167`,
  `process_control.go:52-56,129-142`): a SEPARATE short-held
  debt-ledger lock serializes registration, completion, and
  the mint-boundary supersession — never held across
  control-socket IPC; the lock order is applySem → ledger
  lock, with `m.mu` never nested with the ledger lock. (f)
  THE TYPE+MODE CHECK (Codex M7): the desired link is
  specifically IPVLAN_MODE_L2 (`daemon_ha_fabric.go:56-62`) —
  a same-parent IPVLAN in L3/L3S mode has the right kind and
  wrong semantics — so acceptance validates type AND mode and
  REPLACES a mismatched link. (g) The minors: the
  `pendingHAStateClear` retry debt joins the arm inventory
  (Codex m1, `manager.go:227-236`, `manager_ha.go:98-151`);
  §9's callback legs gain the early-fence, teardown-join, and
  per-operation aggregation cases (Codex m2); the acceptance
  residual reference aligns to the (vi) withdrawal (Codex m3);
  and the §5.1 inventory gains `daemon_apply.go` for the
  QUEUED wrappers (Codex m4).
  v62: r61 convergence — the acceptance copy gains the full
  actuated predicate, the callback join gets its admission
  gate, the predicate gains the queued-empty term with the
  identity ordering, the aliases collapse at supersession,
  and the ledger nesting gets its canonical order (Codex
  NEEDS-REVISION 5M/3m, folds 2 FOLDED / 3 PARTIAL /
  2 NOT-FOLDED, structure confirmed; AGY PLAN-READY 7/7 with
  3 fresh attacks FAILED — including its own alias-collapse
  analysis matching the pin — structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — the alias-collapse pin, IS
  Codex M4): (a) THE ACCEPTANCE COPY CARRIES THE MULTI-TERM
  ACTUATED PREDICATE (Codex M1 — the formal acceptance had
  only "one election primary" plus an undefined generic
  authority check): exactly one rg_active, exactly one VRRP
  MASTER where applicable, both on the intended node, the
  loser explicitly inactive, read per-node. (b) THE CALLBACK
  JOIN'S LIFECYCLE PROTOCOL (Codex M2, verified: a WaitGroup
  Add from the detached firing path can race shutdown's Wait,
  `maps_sync.go:451-456`, `daemon_run.go:115-119`, and a
  timed-out join would let non-contextual netlink operations
  overlap the teardown, `daemon_ha_fabric.go:23-93,102-148`):
  a closed/admission gate atomically reserves in-flight work
  BEFORE launch under the debt-ledger lock (admission closed
  ⇒ never launches; open ⇒ reserves before launch); the
  shutdown closes admission FIRST, then joins the reserved
  set; the 5s bound is the disposition, with a callback past
  the join abandoning at each fence check. (c) THE
  QUEUED-EMPTY TERM + THE IDENTITY ORDERING (Codex M3): the
  predicate gains "no QUEUED reservation outstanding" (the
  queued set empty, rendered beside the pending set), and the
  identity ordering is defined — the enqueue-reservation
  sequence is the canonical order and the admission token
  INHERITS its reservation's position. (d) THE ALIAS COLLAPSE
  (Codex M4 = SMR m1, verified the transitivity gap with
  indefinitely-live retry debt,
  `manager_worker_arm_5134.go:38-96`): every outstanding alias
  is rewritten to the NEW current token at each supersession
  — resolution is always one step and no chain accumulates.
  (e) THE CANONICAL NESTING ORDER (Codex M5, verified the
  contradiction: the OnXSKBound decision/flag/launch happen
  under `m.mu` today, `maps_sync.go:353,451-456`, and
  `pendingHAStateClear` registration depends on `m.mu`-held
  cluster state and IPC outcomes, `manager_ha.go:78-112,
  139-150`): the readiness decision + flag + registration +
  launch form ONE section taken as `m.mu` THEN ledger lock —
  the canonical nesting — with the reverse forbidden and the
  ledger lock never held across IPC. (f) The minors: the
  aggregation gains `LinkDel` (m1 — discarded today,
  `daemon_ha_fabric.go:52-53`); §9 gains the HA-clear-debt
  legs (m2); and the 120s figure is corrected to the 3s
  small-request deadline / ~67s maximum-snapshot figures (m3,
  `process_control.go:31-56,85-103,129-142`).

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
  PERMANENT recovery invariant ships in the FOLLOW-UP unit (work
  item H, §4 — §4.7 delivery structure: G+H+H2 move together): at
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
RACE-3 audit exposed).** *Delivery: FOLLOW-UP unit with H+H2 (§4.7 —
G must not ship without H: its END-of-PHASE-5 release is post-manager
construction, H's revert is only safe at Load before `d.cluster`
exists).* The recovered commit-confirmed timer can fire
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
- Scope note: small companion fix (~55 LoC + tests —
  gate + fence + defer), packaged as a SEPARATE PREREQUISITE COMMIT
  (both r7 reviewers) so it stays reviewable and bisectable ahead of
  the mechanical `dpCell` conversion — *Delivery (r28 split, §4.7):
  the commit ships in the FOLLOW-UP unit with H+H2, NOT in PR-1 —
  the "same PR/stack" framing predates the split ruling.*

**Work item H — permanent FirstCommit+cluster recovery invariant,
revert-at-Load semantics (r8-REDESIGNED; *Delivery: FOLLOW-UP unit
with G+H2 per §4.7 — the "ships IN this PR" framing below predates
the r28 split ruling*).** The r6
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

**Work item H2 — resolution tombstone + ArmID-keyed removal debt
(*Delivery: FOLLOW-UP unit with G+H per §4.7, per the r28 split
ruling*) (r11
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
  R-kind debts key RECORDS via `onDiskArmID` — NEVER a fresh disk read
  at debt-construction time (a resolution-time READ ERROR must
  still construct the right debt, r15 Codex M4) — while the W-kind
  debt keys the LIVE WINDOW via `armedArmID`/`s.armedRecord` (r21
  Codex M3's consistency repair: the two identities serve the two
  kinds — record-keyed removal vs live-window-keyed restore; the
  v18-v20 blanket "debts key only on `onDiskArmID`" predated the
  re-key model and is corrected here). A resolution keys its
  removal debt from `onDiskArmID` — which names the exact record the
  retry will find in every interleaving: the arm's write succeeded (key
  = the arm's ArmID), failed PRE-rename (the prior on-disk record — the
  one the retry must act on), or failed POST-rename (the visible record,
  which the live-window-keyed W debt then owes to make durable). The nested-arm counterexample
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
  construction. EVERY action in this table — the (a) tombstone+delete,
  the (b) `DeleteConfirm` re-drive, the (c) durable rewrite, AND each
  clear — is gated on the ACTIVE side state machine like every other
  confirm-side action (r28 Codex M1's inventory completion: the (a)
  tombstone and (c) rewrite are `WriteConfirm` producers and take the
  NO-CREATE single-snapshot primitive; (g-absent) proceeds ONLY for
  the (b) barrier — the both-files operator-intent assumption is
  stated in the key-class block). Master's unkeyed version of this
  race destroys a fresh
  pending record's crash-recovery file TODAY; the keyed debt closes it.
- **The W-kind (rewrite) debt keys the LIVE window's DESIRED record
  and re-keys at EVERY arm outcome (r16 Codex M3 + SMR m1 + r20 Codex
  M1, which killed the on-disk-keyed model: transition (iv) "C
  pre-rename → W_B stands" let the retry durably rewrite B while C was
  LIVE — a durable write spent healing a DEAD window, producing a
  stale-drop of B that leaves C recordless, or a re-arm of B's OLD
  deadline for identical content; a nested arm STOPS the prior timer
  and installs the new generation/deadline/timer,
  `store_commit.go:470-524`).** The arm ALSO retains the immutable
  attempted record `s.armedRecord` (r20 Codex m1: the in-memory
  pending state carries no absolute deadline or hash,
  `store.go:168-179` — the restore cannot recompute them), alongside
  `armedArmID`. Arm outcomes: a fully DURABLE arm write → NO W debt
  (the live window's record is durable); a POST-rename failure → W
  keyed to the armed record's ArmID with the record VISIBLE (owed:
  make durable); a PRE-rename failure → W keyed to the armed record
  with the record ABSENT-or-STALE on disk (owed: RESTORE it — below).
  A nested arm SUPERSEDES the prior window: the prior W is stale
  (its window is dead) and the debt re-keys to the NEW live window
  per its outcome — the on-disk dead-window record is consumed by the
  restore's overwrite (a `WriteConfirm` of the live record replaces
  whatever is on disk — the restore IS the supersession), or by the
  R-kind machinery if the window resolved. The W retry re-reads
  confirm.json and runs the FOUR-LEGGED table pinned in the
  debt-kind-split block: (w-a) current record's ArmID == the debt key
  (the live window's record IS on disk) → `WriteConfirm` it durable →
  clear; (w-b) current record DIFFERS (a dead window's record) → the
  restore's `WriteConfirm(s.armedRecord)` overwrites it — the
  restore IS the supersession (dominance D2: the ArmID-mismatch
  overwrite is the POINT, never a write OF the dead record) — and it
  SUBSUMES any R-kind debt keyed to that record (the dead record is
  removed BY REPLACEMENT; the R debt clears once the restore's
  dir-fsync lands); (w-c) record ABSENT → restore
  `s.armedRecord` VERBATIM (the immutable attempted record —
  `Deadline`, `GuardedHash`, `HashBasis`, `FirstCommit`, `PrevTree`,
  `ArmID` — never a recomputation) via a durable `WriteConfirm`;
  if the keyed window has since RESOLVED (in-memory `armedArmID` no
  longer matches), the debt is stale → clear (the resolution's own
  tombstone/deletion subsumes it). Composition with the other two
  debts is ordered, not
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
  error → typed). The W-kind (rewrite) debt — AT MOST ONE, keyed to
  the LIVE window's desired record and re-keyed at every arm outcome
  (r20 Codex M1: a nested arm re-keys it; a dead window's W never
  heals) — runs the FOUR-LEGGED rewrite
  table ((w-a)/(w-b)/(w-c) plus the r23 (w-u) unreadable-slot leg):
  (w-a) current record's ArmID == the key (the live window's
  record is on disk) → `WriteConfirm` it durable → clear;
  (w-b) current record DIFFERS (a dead window's record) → restore
  `s.armedRecord` over it (the restore IS the supersession — the
  ArmID-mismatch overwrite is the POINT) — and the restore SUBSUMES
  any R-kind debt keyed to the dead record (dominance D2: replacement
  is not a write of that record; the dead record is removed BY
  REPLACEMENT and the R debt clears once the restore's dir-fsync
  lands; an R-kind debt still dominates every IDENTITY-PRESERVING
  write of its record, D1); (w-c) record
  ABSENT → restore `s.armedRecord` VERBATIM (the immutable attempted
  record retained at arm — `Deadline`, `GuardedHash`, `HashBasis`,
  `FirstCommit`, `PrevTree`, `ArmID`, r20 Codex m1: the in-memory
  pending state carries no absolute deadline or hash,
  `store.go:168-179`, so the arm retains the attempted record —
  never a recomputation) via a durable `WriteConfirm`;
  if the keyed window has since RESOLVED (in-memory `armedArmID` no
  longer matches), the debt is stale → clear (the resolution's own
  tombstone/deletion subsumes it). EVERY action in this table — the
  (w-a) durable write, the (w-b)/(w-c) restore, AND each clear — is
  gated on the ACTIVE side being readable under the current key
  (r26 Codex M1's generalized laundering guard, stated in full in
  the key-class block below: a healthy confirm slot never outruns an
  unreadable active config; the gate is a no-op for plaintext active
  configs — and the (w-c) absent-slot case is exactly the bypass
  that motivated the generalization, since `ReadConfirm` returns
  `(nil, nil)` without touching the key, `db.go:242-253`).
  (w-u) record UNREADABLE
  NON-KEY-CLASS-PERMANENT (r23 Codex M2, verified the normative tables
  defined only readable match/differ/absent while the global
  taxonomy terminalizes the read failure): restore `s.armedRecord`
  OVER the unreadable slot — the restore's rename needs no read,
  and the write-unverified machine's validation EXEMPTS the
  own-target here (r33 Codex M1: the slot's NON-KEY-CLASS
  PERMANENT unreadability is the exemption's whole point — the
  OPPOSITE side must validate, the own-target never can),
  subject to the key-class gate (KEY-CLASS permanent failures —
  authentication failure, invalid observed key length, the
  mechanical `ConfirmRecordKeyClassError` subtype — and ANY
  missing/unreadable key file BLOCK the write: the debt retains and
  the message is CLASS-SPLIT (r32 Codex m2's reconciliation:
  invalid-LENGTH or byte-MISMATCH → `.configdb/master.key`
  RESTORATION; ENOENT/EACCES/mount-IO → key-state UNVERIFIABLE,
  NO restoration claim) — enforced
  by the r28 NO-CREATE keyed write primitive, so the write FAILS
  CLOSED with `readOrCreateMasterKey` never reached — no fresh key
  is created, and a write under a swapped key cannot launder the
  unreadable-active state because the restore's write consumes the
  SAME key snapshot the gate validated) —
  implementing the confirmed-commit-pre-rename case of the (ii-b)
  eager rule. PRIORITY, STRENGTHENED TO FULL SUPPRESSION (r25 Codex
  M2, verified the kill-shot: an EARLIER post-rename W attempt may
  have left the LIVE record C visible on the slot; a later W restore
  failing PRE-rename then leaves C — NOT the superseded record —
  standing, and routing D to (d-i) would synthesize a tombstone over
  a live window. Concretely: C's config removed `master-password`
  while `s.armedRecord` retains a master-password-bearing `PrevTree`
  — an invalid key length BLOCKS W's encrypted write
  (`db.go:207-217`, `crypto.go:262-270,457-465` — encryption keys off
  the prev tree's master-password leaf) while D's synthesized
  tombstone, built from the current master-password-free tree, is
  PLAINTEXT and SUCCEEDS — tombstoning and deleting the live C; a
  crash then silently loses C's recovery intent): the D-kind debt
  NEVER acts while a LIVE WINDOW EXISTS — ANY W-kind debt pended OR
  `armedArmID != ""` (r26 Codex M2, verified the durable-arm gap in
  the W-only condition: a DURABLE arm creates NO W debt, yet the
  window is live — and if the active-validation rule blocks D's
  (d-iii) moot-clear, D stays alive beside the live window, and a
  later NON-key-class permanent read error would route it to (d-i)
  to synthesized-tombstone the live record): the W debt — or the
  live window itself — holds exclusive
  access to the slot, and the restore handles every slot content
  (unreadable superseded record → (w-u) restore-over; visible live
  C → (w-a) make durable). D acts ONLY when NO live window exists
  (no W debt AND `armedArmID == ""`) AND NO active-persist debt is
  outstanding (`persistDegraded == false`) — the THIRD conjunct
  closes the undurable-replacement outrun (r27 Codex M3, verified:
  SyncApply cancels the live window C BEFORE persisting its
  replacement — `store.go:687-717,738-746` — so a PRE-rename
  failure of the replacement's active write leaves NO W debt and
  `armedArmID == ""`, yet #5473 PRE-rename retention keeps C's
  window record as the ONLY crash-recovery intent for the
  still-on-disk UNCONFIRMED C; an actionable D whose fresh re-read
  turns NON-key-class permanent would (d-i) tombstone+delete that
  record while the active-side gate PASSES — disk active C is
  readable — and a crash before the replacement retry lands then
  boots unconfirmed C with its recovery intent destroyed, a #4577
  violation): while the replacement's persist is outstanding, D is
  inert; once the retry lands the replacement durably, the record
  is genuinely superseded and D's fresh re-read proceeds per the
  (ii-b) eager rule — the
  plain-commit/SyncApply eager rule, where no live window exists and
  the slot provably holds the superseded record. When the pended W
  resolves (restore succeeded → the slot holds the live record → D
  moot; the window resolved → W stale-clears → D re-evaluates the
  slot FRESH via its re-read classification — never on a stale
  phase assumption); a restore FAILURE is
  qualified by PHASE (r24 Codex m1): PRE-rename → the W debt stays
  pended and D stays SUPPRESSED (per the kill-shot rule — the slot
  may hold a live record; there is NO D path while W pends);
  POST-rename → the LIVE record C is
  VISIBLE on the slot → the W debt remains owed (C visible, not
  durable — (w-a) makes it durable next pass) AND any D-kind debt
  remains suppressed (its mandatory re-read would reach (d-iii)
  READABLE anyway — clearing D as moot, since the slot provably holds
  C, not the superseded unreadable record) — phase regressions for
  both legs, including the kill-shot case itself. MERGE semantics
  (r19 Codex m1): for the same record, tombstone-required dominates
  delete-finishing — a removal debt needing tombstone+delete and a
  removal debt needing only the delete-finish merge into the
  tombstone-required action.
  SAME-RECORD DOMINANCE, SCOPED TO IDENTITY-PRESERVING WRITES (r18
  Codex M2 + r19 Codex M1 + r21 Codex M1, which inverted the priority
  for REPLACEMENT writes, verified: R_A's mismatch branch rewrites the
  CURRENT record B — an identity-PRESERVING write that durably restores
  pending-shaped B even with R-before-W same-key ordering; a crash
  before R_B re-arms the resolved window,
  `store_persist.go:149-165,231-253` — while the v21 restore-first
  reading created the WORSE recordless-live-window gap: R_B's
  tombstone→delete lands, then a crash before W_C's restore drops B as
  Resolved with durable active C and NO recovery record — an
  unconfirmed config silently permanent): the rules are TWO:
  (D1) an R-kind debt keyed to the current record K dominates EVERY
  IDENTITY-PRESERVING write of K — no W-kind rewrite keyed K, no
  stale-keyed mismatch rewrite (R_A's branch) — R_K's tombstone write
  IS the universal durability barrier for K, and every stale-keyed
  debt clears once that barrier lands;
  (D2) a LIVE window's RESTORE targeting K's slot is NOT a write of K
  — it is a SUPERSESSION (it replaces the dead record with the live
  window's `s.armedRecord`, a different ArmID/content) — and it
  SUBSUMES the pending R_K: the restore runs FIRST (it removes the
  dead record BY REPLACEMENT, so a live window is NEVER left
  recordless by an ordering gap), and R_K clears once the restore's
  dir-fsync lands (the restore's barrier covers K's removal exactly
  as a tombstone→delete would); if the restore FAILS pre-rename, K's
  record stands and R_K's own tombstone→delete path runs under D1.
  The crash cases collapse to the admitted residual class: crash
  after the restore → C durable, R_K cleared-by-barrier; crash before
  the restore → K intact, BOTH debts owed (R_K retries the
  tombstone→delete, W retries the restore). The guarantee is SCOPED
  precisely (r22 Codex m1): restore-first ORDERING never creates a
  recordless live window by itself — but a restore FAILURE returns K
  to D1, and if R_K's tombstone→delete then SUCCEEDS and a crash
  lands before the next SUCCESSFUL W restore (failed passes do not
  close the gap), K is absent with C's window live and
  recordless: that is the admitted best-effort arm-persistence
  residual (`store_commit.go:548-553` — a live window with no
  recovery record, warned; the exposure is seconds-wide under
  TRANSIENT failure but UNBOUNDED up to the confirm window's own end
  under a deterministic write failure — the crash must land before
  the next SUCCESSFUL W restore, failed passes do not close the
  gap, and the W retry has NO success
  guarantee and dies with the process (`store_commit.go:611-628`;
  `store_persist.go:397-401`), and there is NO post-crash heal),
  not a new class. The retry
  evaluates the live-window restore FIRST, then the current-record
  removal; the guard is a membership check at each debt's turn (no
  sort required). The x16
  regression drives the counter-cases: identity-preserving W-first
  (r18), R_A-first (r19), AND the restore-priority handoff (r21:
  R_B + live W_C → restore-first → no recordless window) with the
  crash between.
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
  DEBT — SCOPED to CONTENT-DEPENDENT debts (r24 Codex M1, verified the
  self-contradiction: (w-u) and (d-i) require REPAIR WRITES after
  permanent read failures while this branch said every such debt
  terminalizes; r25 Codex m1's rationale correction: the
  terminalization applies ONLY to debts whose safe action needs the
  slot's CURRENT CONTENT — the R-kind read-back tombstone. The reason
  is NOT that the payload couldn't be synthesized (it could) but that
  a permanent read error leaves the slot's OCCUPANT unprovable: a
  newer LIVE window's record may stand where R_K's resolved record
  used to, and a blind synthesized tombstone could erase a live
  window's rollback intent — the same mismatch class the D-kind
  suppression rule exists for; auto-erasure would also hide a
  corruption the operator should inspect).
  CONTENT-INDEPENDENT debts are EXEMPT BY CONSTRUCTION: the W-kind
  restore (content = `s.armedRecord`, in memory) and the D-kind
  synthesized tombstone (content = synthesized) need NO read — and
  their whole purpose is to overwrite a provably-superseded
  unreadable record (the (ii-b) eager rule applies only where a newer
  durable config landed AFTER the record's window, so the record is
  stale by construction and repair-and-recover has no value — unlike
  the R-kind terminal case, where a permanent read error leaves the
  slot's occupant UNPROVABLE (a newer LIVE record may stand where the
  resolved record used to — never "the owner is known"), so the
  operator's repair-or-remove decision is the point). The
  exemption is further SCOPED BY FAILURE CLASS (r25 Codex M1,
  verified the laundering scenario: a W debt created under key K,
  then master.key replaced by ANOTHER VALID 32-byte K′ —
  `readOrCreateMasterKey` accepts K′ (`crypto.go:457-465`), the
  restore's `WriteConfirm` rewrites the confirm record under K′ and
  the debt clears — while active.json remains encrypted under K:
  health goes green and the NEXT `Load` fails closed on the ACTIVE
  side, `store_persist.go:26-35`): KEY-CLASS permanent failures —
  authentication failure (indistinguishable between wrong-key and
  corrupt ciphertext) and invalid observed master-key length, the
  mechanical `ConfirmRecordKeyClassError` subtype consumed via
  `errors.As` — do NOT proceed with repair writes at all: the debt
  retains and the
  operator-facing message names `.configdb/master.key` RESTORATION
  (writing under
  a new key would launder the unreadable-active state into a healthy
  confirm slot; master-key IO is NOT in this set — it carries the
  TWO-SIDED classification instead: READ-side TRANSIENT (retain +
  retry per the r17 taxonomy — a missing mount or EACCES is
  recoverable, so the read side never terminalizes and the
  (d-i)/(w-u) paths are never entered on it) and WRITE-side BLOCKED
  (`readOrCreateMasterKey` AUTO-CREATES and persists a fresh key on
  `IsNotExist`, `crypto.go:457-479` — a repair write attempted with
  the key file missing would encrypt under a NEW key and launder
  the state, so any repair WRITE is blocked while the key file is
  missing or unreadable)). And the laundering guard is GENERALIZED (r26 Codex
  M1, verified the absence-path bypass: a pre-rename arm failure
  leaves the slot ABSENT — `ReadConfirm` returns `(nil, nil)` without
  touching the key, `db.go:242-253` — so NO key-class failure is ever
  observed, yet the (w-c) restore then writes C under a swapped K′
  and clears while active.json remains K-encrypted; a
  malformed/too-new slot masks the wrong key the same way): EVERY
  W/D repair action (restore, synthesized tombstone, delete) AND
  every confirm-side clear is gated on the ACTIVE side being readable
  under the current key — a healthy confirm slot must never outrun an
  unreadable active config. The gate is a no-op for plaintext active
  configs (`maybeDecryptTreeJSON` passes non-envelope bodies through
  with no key access, `crypto.go:303-356`); on validation failure the
  action is withheld and the message names the ACTIVE side /
  `.configdb/master.key` (r26 Codex m1's path correction —
  `masterKeyPath()` is `filepath.Join(db.dir, "master.key")` and
  `db.dir` is `<confdir>/.configdb`, `crypto.go:34-35`,
  `store.go:302-305`, NOT `/etc/xpf/master.key`). The discriminator
  is MECHANICAL (r26 Codex M3c): the sentinel family gains a
  `ConfirmRecordKeyClassError` subtype (authentication failure +
  invalid observed key length) consumed via `errors.As` — the
  key-class rule never string-matches. THE SUBTYPE HAS TYPED SOURCES
  (r27 Codex M4, verified the gap: Go's GCM authentication error has
  NO exported typed sentinel — `crypto.go:354-356` today converts it
  to an ordinary wrapped error, invalid key length is a plain
  `fmt.Errorf` at `crypto.go:451-453,460-462`, and `ReadConfirm`
  merely adds `%w` at `db.go:250-253` — so `errors.As` has nothing
  to match): `crypto.go` gains TWO typed source errors —
  `ErrMasterKeyAuth` wrapping the `gcm.Open` failure
  (`crypto.go:354-356`) and `ErrMasterKeyLength` at both length
  gates (`crypto.go:451-453,460-462`) — each wrapped so
  `errors.As(err, &ConfirmRecordKeyClassError)` matches (the
  key-class subtype carries the permanent umbrella: the chain ALSO
  satisfies `errors.As(err, &ConfirmRecordPermanentError)` —
  key-class IS permanent), and `ReadConfirm`'s existing `%w`
  wrapping passes the typed causes through unchanged. Classification
  regressions pin all four boundaries: auth failure → key-class;
  invalid observed length → key-class; missing key file / EACCES
  (master-key IO) → NOT key-class (READ-side TRANSIENT);
  unsupported PRF / too-new envelope format / bad nonce ENCODING or
  length / bad base64 → NOT key-class (NON-key-class permanent —
  these fail BEFORE AEAD: the envelope
  header is unencrypted, `crypto.go:26-32,307,323-326,348-353`, so
  the content is provably unparseable under ANY key — while a
  well-formed TAMPERED nonce reaches `gcm.Open` and IS key-class by
  authentication indistinguishability, `crypto.go:354-356`). `crypto.go`
  JOINS the §5.1 change inventory (its omission was Codex r27's
  fold-partial 3). And master-key IO carries the
  TWO-SIDED classification (r26 SMR m1: READ-side TRANSIENT — retain
  + retry per the r17 taxonomy, a missing mount/EACCES is
  recoverable; WRITE-side BLOCKED — `readOrCreateMasterKey`
  AUTO-CREATES and persists a fresh key on `IsNotExist`,
  `crypto.go:457-479`, so a repair write attempted with the key file
  missing would encrypt under a NEW key and launder the state). The
  sanctioned confirm.json removal under a key-class latch carries the
  same active-side validation. Only NON-key-class permanent failures
  (malformed JSON, zero deadline, nil target, too-new envelope
  format, unsupported PRF — content provably unparseable regardless
  of key) take the repair-write exemption.
  THE GATE IS AN EXECUTABLE THREE-WAY STATE MACHINE (r27 Codex M1,
  verified the under-specification: an error-only predicate accepts
  ABSENT active state — `ReadActiveMeta` returns `(nil, true, nil)`
  for a missing active.json, `db.go:319-330` — and a
  non-nil-tree predicate blocks the sanctioned both-files-removed
  barrier). The predicate is evaluated FRESH under `s.mu` at each
  action time (never a cached result) via `ReadActiveMeta` or
  equivalent: (g-ok) `tree != nil && err == nil` → the active side
  is readable under the current key → PROCEED; (g-absent)
  `tree == nil && err == nil` → the active config is ABSENT →
  PROCEED only for the sanctioned both-files-removed `DeleteConfirm`
  barrier (the operator removed both files — active absence IS the
  operator's intent, and the barrier's unlink is idempotent);
  WITHHOLD every other action (a missing active with a healthy
  confirm slot must never clear or repair — the next `Load`
  re-seeds while the confirm slot outruns it). THE OPERATOR
  PROVENANCE IS AN OPERATIONAL ASSUMPTION (r28 Codex fold-partial 1,
  verified: ENOENT proves no provenance — `db.go:302-330`): outside
  FACTORY RESET (the operator-triggered DB removal at
  `factory_reset.go:252-268` — itself an operator action), the
  store NEVER deletes active.json itself, so a both-files absence
  is BY CONSTRUCTION an operator hand action under the same
  store-owned-file doctrine as the single-xpfd assumption (one
  xpfd per `.configdb/`, no flock — hand edits are the operator's
  intent); and the assumption is SAFE if wrong: the barrier only
  dir-fsyncs an already-absent slot and writes nothing, so a
  mistaken assumption costs at most the clear of a debt whose
  record the operator already deleted by hand — never a write over
  a present record. (g-err) `err != nil`
  → WITHHOLD — retain the debt, NO terminalization, NO write, NO
  clear; the message names the ACTIVE side. The active-read error's
  own transient/permanent class does NOT change the gate's behavior
  (withheld is withheld; the class only enriches the message) —
  EACCES and corrupt-active both withhold and retry next pass.
  PLACEMENT is identical at boot and runtime (r27 Codex M1's
  placement pin, verified `store_persist.go:26-42,113-140,402-465`:
  boot reads active ONCE before recovery, the runtime retry loop
  never reads it today): at BOOT, the gate consumes the SAME
  `ReadActiveMeta` result `Load` already took at
  `store_persist.go:26-35` — no second read — and every
  confirm-recovery repair/clear in the boot sequence is gated on it;
  at RUNTIME, the retry loop / probe continuation takes a FRESH
  `ReadActiveMeta` under `s.mu` immediately before each debt action
  and gates on it. The regression matrix covers all three gate
  states × the FULL non-arm producer set (W (w-a) durable rewrite,
  W (w-b)/(w-c) restore, W (w-u) unreadable-slot restore, R (a)
  tombstone+delete, R (c) mismatch rewrite, D tombstone, D delete,
  confirm-side clear, sanctioned barrier) at BOTH placements.
  AND THE REPAIR WRITE IS NO-CREATE, SINGLE-SNAPSHOT (r27 Codex M2,
  verified the hole: every current `WriteConfirm` reaches
  `readOrCreateMasterKey` through `db.go:207-217` +
  `crypto.go:262-270,457-479` — a check-then-ordinary-write leaves
  the auto-create path live AND races a K→K′ swap between the gate's
  read and the write's own key read): EVERY non-arm `WriteConfirm`
  producer — the enumeration is COMPLETE (r28 Codex M1 + r29 Codex
  m2, verified the v28 list omitted retry-side producers and the
  (w-u) unreadable-slot leg): the W-kind (w-a) durable
  rewrite, the W-kind (w-b)/(w-c) restores, the W-kind (w-u)
  unreadable-slot restore-over, the R-kind (a) MATCH
  tombstone (the read-mutate-write helper — the ONLY read-back
  tombstone producer), the R-kind (c) MISMATCH durable rewrite of
  the current record, and the D-kind synthesized tombstone — uses a
  NO-CREATE keyed
  write primitive — the key is sourced via `readMasterKey` (which
  NEVER creates, `crypto.go:443-455`) and a missing/invalid key file
  FAILS the write with no creation — and the gate's active-side
  validation and the repair write consume ONE key snapshot: the key
  bytes are read ONCE under `s.mu` at action time, the active side
  is validated against them, and the SAME bytes are passed into the
  write's encryption step — a K→K′ swap between check and write is
  impossible by construction. The ORDINARY arm write
  (`writeConfirmState`) deliberately KEEPS `WriteConfirm`'s
  create-on-first-use (the documented #1894 fresh-box design — the
  first encrypted write must create the key); only repair/resolution
  writes are no-create. AND the snapshot alone does NOT prove the
  installed key PATH stayed unchanged across the action (r28 Codex
  M2, verified: `master.key` is an ordinary unlocked filesystem
  path, `crypto.go:443-479`, and the operator is explicitly
  permitted live restoration): two pins close the residual. (i) Key
  remediation is SERIALIZED BY RUNBOOK, with the branch chosen BY
  LIVE-DEBT STATE — NOT latch origin (r29 Codex M1 + r30 Codex M1/M2,
  verified: the stopped-restore loses process-local debt provenance
  — a keep-active confirmation can resolve A in memory while a
  wrong key makes its tombstone read fail and retain R_A
  process-locally, and stopping xpfd abandons that retry,
  `store_persist.go:397-401`; after restoring K and restarting, the
  pending-shaped A still hash-matches and recovery re-arms or
  expired-reverts an ALREADY-CONFIRMED config,
  `store_persist.go:149-165,231-255` — the admitted replay
  residual; AND the BOOT latch is NOT a stable no-live-debts state
  — a confirmed commit during the latch can fail its arm pre-rename
  and create a W debt, so TerminalUnreadable and a nonzero debt
  mask can coexist in one snapshot): ANY live process-local debt
  (`ConfirmDebtKindMask ≠ 0`, whatever the latch origin) forces the
  DEBT-ORIGIN branch → restore the key with xpfd
  RUNNING and WAIT for health/debt clearance (the retry loop
  re-validates under the restored key and the debts heal through
  their own tables) — NEVER stop xpfd mid-debt; only `mask == 0`
  (with or without a latch) permits the BOOT-ORIGIN stopped-restore
  path (restore
  with xpfd stopped, restart, and the latch's boot reconstruction
  re-validates the restored key). The operator-facing message names
  the branch from the live mask — a mixed-state regression pins
  BOOT latch + live W → the running/wait branch rendered, never
  the stop branch.
  AND THE SPLIT-KEY INTERLEAVE IS CLOSED STRUCTURALLY (r30 Codex
  M1, verified: with R_A and persistDegraded both live under the
  original K, installing wrong-but-valid K″ lets the retry loop's
  active-persist heal re-encrypt active.json under K″ —
  `store_persist.go:414-428` heals active FIRST,
  `crypto.go:262-270,457-465` encrypts with the currently installed
  key — after which restoring K makes the ACTIVE side unreadable
  and retaining K″ keeps the CONFIRM side unreadable: no single key
  converges): the config-DB carries an explicit WRITE-UNVERIFIED
  state machine (r30 Codex M1 + r31 Codex M1/M2, verified BOTH
  failure modes of the v31 key-class-predicate version: a
  missing/unreadable key file classifies READ-side TRANSIENT —
  UNVERIFIABLE, NOT key-class — so a latest-failure-class
  predicate REOPENS the gate exactly where the auto-create hazard
  lives, with the active heal then creating K′ or accepting K″
  before the confirm read ever runs; AND the healing path is
  circular under a write-block keyed on the debt's own bit —
  W/R healing itself writes encrypted, so the bit must clear
  BEFORE the write it gates, yet clearing on a non-key outcome
  recreates the first hole): ENTER write-unverified on (i) ANY
  key-class-observed failure (authentication failure or invalid
  observed key length on ANY config-DB read — confirm or active),
  (ii) ANY key-path write-side probe failure (ENOENT / EACCES /
  mount-IO at write time or at the clear-time re-read — the
  UNVERIFIABLE outcomes), (iii) ANY byte-mismatch at the
  clear-time compare. HOLD: while in write-unverified, EVERY
  ENCRYPTED config-DB write is blocked — the active-persist retry
  withholds its encrypted write, every confirm-side repair write
  withholds, and NEW arms/commits are REFUSED at the persistence
  layer with a clear key-remediation error — so
  `readOrCreateMasterKey` can NEVER fire and no file is ever
  re-encrypted under an unverified key; PLAINTEXT writes are
  unaffected (the encryption predicate); the in-memory active tree
  stays the source of truth. EXIT: ONLY a POSITIVE validation —
  a successful key-path read yielding key bytes PLUS a successful
  decrypt-validation of an on-disk encrypted record (confirm or
  active) under those SAME bytes (single snapshot — the no-create
  primitive's discipline) — never on the mere absence of a
  failure and never on a non-key-class outcome. AND THE STATE
  EXIT ITSELF RE-VERIFIES THE KEY IDENTITY (r34 Codex M2,
  verified the state-only false clear: `Save` can ENTER the state
  and start the loop with NO persistence debt at all; a pass
  validates both K-encrypted files, the unlocked key path is then
  swapped to K′ before the exit, and the debt-clear key compare
  at (ii) does not apply — with no debt, clearing the state
  satisfies the loop-exit condition, the loop terminates, and
  health goes GREEN while the installed K′ decrypts neither
  record): the positive-validation exit performs its OWN final
  key-path re-read and EXACT-BYTES compare against the validation
  snapshot immediately before clearing (the same discipline the
  debt clear carries at (ii), generalized to the state) — a
  mismatch RETAINS the state with the byte-mismatch
  classification (restoration-required) and the loop keeps
  probing; a match clears. The x25 legs gain the state-only
  second-swap regression. THE EXIT IS
  ACTION-SCOPED AND CONTINUOUS, NOT A ONE-SHOT GLOBAL CLEAR (r32
  Codex M1a, verified the insufficiency: validating "an" encrypted
  record says nothing about a SECOND on-disk generation — a DB
  can hold active.json under K and a confirm record under K′):
  the state is the ABSENCE of a current positive validation, and
  EVERY gated encrypted write — including the active-persist heal
  — re-performs the FRESH same-snapshot validation IMMEDIATELY
  BEFORE encryption (never inherited from an earlier pass), and
  the validation is SIDE-ASYMMETRIC (r33 Codex M1, verified the
  deadlock: requiring the write's OWN target to validate kills the
  content-INDEPENDENT escape hatch — the (w-u) restore-over and
  the D synthesized tombstone exist precisely to overwrite a
  NON-KEY-CLASS-PERMANENT unreadable slot (too-new envelope,
  unsupported PRF, malformed nonce — content provably unparseable
  under ANY key, `crypto.go:307-356`), and an own-target
  validation requirement could never pass for them while
  CONFIRMED-EMPTY could never fire): the OPPOSITE side's present
  encrypted generations MUST validate under the snapshot
  (the dual of the generalized
  laundering guard: an active write must never outrun an
  unreadable CONFIRM generation, just as a confirm repair must
  never outrun an unreadable active config), while the OWN target
  is validated ONLY when it is supposed to be readable — a
  content-INDEPENDENT repair (the (w-u) restore-over, the D
  synthesized tombstone) is EXEMPT from own-target validation
  exactly when its target's classification is NON-KEY-CLASS
  PERMANENT (the overwrite IS the repair — the exemption is the
  whole point); an own-target that fails KEY-CLASS or IO keeps
  the repair withheld per its own leg's rules. Any opposite-side
  mismatch
  withholds the write and RE-ENTERS the state. A premature exit
  is therefore harmless by construction: the other generation's
  own action re-validates at its action time and re-blocks.
  AND THE EXIT IS MADE TOTAL (r32 Codex M1b + r33 Codex M2,
  verified: after the sanctioned removal of the FINAL unreadable
  record — or on a never-encrypted DB — NO ciphertext remains to
  decrypt-validate against, so a decrypt-only exit is
  unreachable; and a key-path probe failure over an all-plaintext
  DB satisfies BOTH the HOLD and the empty exit): the
  CONFIRMED-EMPTY exit joins the decrypt exit and is AUTHORITATIVE
  BEFORE the key-probe HOLD — the proof is ONE fresh under-`s.mu`
  classification of BOTH files using ONE key byte snapshot
  (active.json AND confirm.json each classified
  encrypted-readable / plaintext / absent /
  unreadable-non-key-class-permanent; the plumbing exposes
  `maybeDecryptTreeJSON`'s envelope-detected bit,
  `crypto.go:306-314`, at BOTH call sites — `ReadActiveMeta`'s
  classification surfacing at `db.go:95-103` and `ReadConfirm`'s
  retained decrypted flag at `db.go:242-253` — so the scan never
  re-reads the key path per file): when the scan proves NO
  encrypted-or-unclassifiable record remains (all plaintext, all
  absent, or every formerly-unreadable record either repaired or
  sanctioned-removed), the state EXITS with
  the removal's mandated data-loss warning already surfaced by
  the sanctioned-removal doctrine — regardless of the key path's
  own state (there is nothing left to protect; the HOLD exists
  for content, not for the key file in the abstract). The
  under-`s.mu` scan also excludes Store-origin arm interleavings
  BY CONSTRUCTION (r33 Codex M2's coverage note: CommitConfirmed,
  SyncApply, and the bootstrap ordinary commit all serialize on
  `s.mu`; SyncApply does not itself arm). The CONFIRMED-EMPTY exit IS
  the irrecoverable-generation path (r32 SMR m1): when the
  on-disk records' key generation is irrecoverably lost (every
  validation fails — and the single-file sanctioned removal is
  itself withheld by (g-err) because active.json does not read
  under the installed key either), the operator's exit is the
  BOTH-FILES removal: the (g-absent) barrier proceeds (it only
  dir-fsyncs an already-absent slot), the DB returns to the
  absent/plaintext posture, the CONFIRMED-EMPTY exit clears the
  state, and the box re-bootstraps — with the explicit sacrifice
  warning (the on-disk config's crash-recovery intent is lost,
  matching master's clobbered-key outcome). THE STATE IS
  OBSERVABLE AND ACTIVELY PROBED (r32 Codex M1b's observability
  clause, verified it was absent from the health aggregate): the
  write-unverified state joins the typed snapshot as a
  NON-SECRET `ConfigWriteUnverified bool` — folded into the
  `ConfigPersistDegraded()` aggregate OR and rendered in /health
  with its own message ("config persistence write-unverified:
  master-key validation outstanding — see journal"; the §6
  repertoire grows accordingly) — and the retry loop ACTIVELY
  probes the key path on every pass while the state holds (the
  loop is kept ALIVE by the outstanding state even with no
  debt/latch/mask — a restored key is detected within one
  backoff interval and the decrypt-exit attempt runs on the same
  pass). The restoration
  flow is then non-circular (r31 Codex M2): the operator restores
  K → the next pass's key-path read succeeds AND the confirm
  re-read (R_A's record) decrypts under K → POSITIVE validation →
  EXIT → R_A's tombstone→delete proceeds under the SAME snapshot
  → healed; wrong-but-valid K″ → the re-read fails authentication
  → the state HOLDS → the active write stays blocked → the files
  never diverge; a MISSING key file → the probe failure HOLDS the
  state → the auto-create can never fire. A FRESH box never
  enters the state (no records exist to fail on, no probe has
  failed), so the #1894 first-encrypted-write auto-create still
  works; a fully-plaintext DB vacuously never enters. The commit
  refusal carries an EARLY Store-level precheck (r31 Codex m1,
  verified the post-promotion hole: CommitConfirmed writes active
  BEFORE promotion and arms AFTER — `store_commit.go:437-524,
  530-553` — and the confirm record's encryption keys off the PREV
  tree's master-password leaf, `crypto.go:262-270` via
  `rec.PrevTree`, so a PLAINTEXT candidate with an encrypted
  PrevTree still produces an encrypted confirm record): at
  commit/confirm entry, if the DB is write-unverified AND the
  commit would produce ANY encrypted write (the candidate's own
  leaf for active.json OR the PREV tree's leaf for the confirm
  record), the commit is refused BEFORE any write with the
  key-remediation error — never discovered post-promotion; a
  regression pins the plaintext-candidate/encrypted-PrevTree
  case. SYNCAPPLY's admission is pinned (r33 Codex m2, verified
  the ambiguity: SyncApply bypasses commit gates and promotes
  in-memory BEFORE its degrade-not-fail persistence attempt,
  `store_commit.go:134-138`, `store.go:687-738`): SyncApply
  PROMOTES in-memory per its own #1799 Option-B contract (the
  in-memory apply MUST stand — refusing it would silently diverge
  the cluster, since the primary is already running the new
  config and is never notified), while its encrypted PERSISTENCE
  attempt is WITHHELD while write-unverified and raises the
  active-persist debt — the in-memory tree stays correct, the
  disk write proceeds once the state exits, and the cluster never
  diverges over a key-remediation window. AND THE EXPORTED
  `Save()` PATH TAKES THE WRITE LOCK (r33 Codex m1, verified:
  `Save()` currently holds `s.mu.RLock()` and calls `writeActive`
  whose contract permits either lock, `store_persist.go:258-274`
  — a failed validation must MUTATE `ConfigWriteUnverified` and
  start/retain the retry loop, which races under the read lock
  and deadlocks on upgrade): `Save()` takes `s.mu.Lock()` (it is
  the operator/API save path, not a hot path), so the
  write-unverified transition and the loop start/retain are
  synchronized with every other mutation; the x25 inventory gains
  the exported-path leg. The retry loop's order stays
  active-heal → resolution-finalize (the #5473 durability
  ordering); the active-write gate evaluates the previous
  pass's confirm-side state, AND — closing the second-swap leg
  (r32 Codex M2, verified: an operator swap to K″ between the
  exit pass and the deferred active write would otherwise
  re-encrypt active.json under unvalidated K″ when the on-disk
  active is PLAINTEXT — the (g-ok) active-side no-op would pass
  while a K-era CONFIRM record stands) — the active heal's write
  consumes the fresh same-snapshot BOTH-SIDES validation above:
  a plaintext active side does not exempt the write while a
  confirm-side encrypted generation exists and fails the
  snapshot's validation —
  one pass of lag after the operator's key restoration, zero
  hazard. Intentional key ROTATION is out of scope: no
  re-encryption tooling exists on master either (a follow-up may
  add it); the gate blocks the accidental split, not a supported
  workflow.
  (ii)
  EVERY debt clear that consumed a key snapshot RE-READS the key
  path at clear time and compares bytes to the snapshot — a
  mismatch (the operator swapped the path mid-action) RETAINS the
  debt with the restoration message instead of clearing: a clear
  never lands on a key generation different from the one the
  validation and the write used. The re-read's own outcome taxonomy
  is pinned (r29 Codex m1 + r30 Codex m1, verified the sole
  keyClass bit could not represent it: byte MISMATCH and
  INVALID-LENGTH are RESTORATION-REQUIRED — the mismatch sets the
  debt's keyClass state EXPLICITLY (the key's identity changed —
  a key-class condition even though it is a comparison outcome,
  not a wrapped crypto failure) and invalid observed length already
  matches `ErrMasterKeyLength` via `errors.As`; EACCES / ENOENT /
  mount-IO / any other read failure → RETAIN the debt and journal
  the EXACT verification error with the message saying key state
  UNVERIFIABLE — NO restoration claim (the operator investigates
  the mount/permissions; the generic confirm-debt text renders,
  never the key-class variant); the
  exact-bytes compare is deliberate (a legitimate same-content key
  rewrite passes), and all three branches carry x23/x24 legs.
  PLAINTEXT repair writes are EXEMPT by
  construction (r27 SMR m1, verified `crypto.go:262-265`:
  `maybeEncryptTreeJSON` returns the body untouched when the
  candidate tree carries no master-password leaf and NEVER calls
  `readOrCreateMasterKey`): the write-block predicate IS the
  encryption predicate — a plaintext W restore / plaintext
  synthesized tombstone / slot DELETE performs no key access at
  all, so the missing-key-file block cannot over-block it; it is
  gated only by the (g-ok)/(g-absent)/(g-err) active-side machine
  above (a no-op read for a plaintext active config).
  Terminal for a content-dependent debt means: the confirm-record
  debt stops retrying (no infinite
  capped-backoff loop) while the singleton retry loop KEEPS healing
  `persistDegraded` — `persistRetryLoop` also owns active-config
  persistence (`store_persist.go:402-465`), so stopping the loop
  outright is unsafe (r16 Codex M4's per-debt correction). WRITE
  failures, on ANY debt kind, NEVER terminalize (r24 Codex M1's
  ownership pin: a failed tombstone/restore/delete write retains the
  debt and retries with capped backoff and degraded health — a
  read-only filesystem loops at 503, the intended loud posture, until
  the operator remediates; the invalid-master-key-length case makes
  BOTH the read and the write fail permanently, and the debt loops
  degraded — loudly — until master.key is repaired). The
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
  FOUR-LEGGED rewrite table — rewrite-durable / supersession
  transitions / restore-or-stale / (w-u) restore-over-unreadable —
  NEVER a tombstone of a live
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
  promptly. (ii-b) SUPERSEDED-WHILE-UNREADABLE is resolved EAGERLY and
  DURABLY at the moment supersession is certain — NO in-memory marker,
  and NOT a bare delete (r20 Codex M2/M3 = SMR M1 for the marker
  proofs; r21 Codex M2 for the happy-path critique: a bare unlink can
  fail pre-unlink or post-unlink-pre-fsync, no ArmID-keyed debt can
  name an unreadable record, and a crash-replayed dirent left the
  binding chain constructible again): the rule is a TWO-STEP
  SYNTHESIZED TOMBSTONE + DELETE, mirroring the R-kind pattern with a
  D-KIND SLOT DEBT (keys the confirm.json SLOT — the record is
  unreadable, so ArmID-keying is impossible):
  (1) `WriteConfirm` a SYNTHESIZED full-field tombstone over the
  unreadable record — `Resolved: true` plus NON-DEGENERATE synthetic
  fields so the #5637 gate passes unmodified (`PrevTree` = a clone of
  the CURRENT active tree; `Deadline` = now + 60 s — pinned, non-zero;
  `GuardedHash` = the canonical hash of the current active tree;
  `HashBasis` = `"canonical-v1"` — pinned to the hash's actual basis,
  never a "current" default; `ArmID` = fresh crypto/rand; `FirstCommit` =
  FALSE — LOAD-BEARING, with the rationale stated precisely (r23
  Codex m2 + r24 Codex M2's oracle correction, verified against the
  recovery code): on the NEW reader the `Resolved` check
  precedes work item H in the total order, so H never sees this
  record. On the OLD (pre-H2) reader, which IGNORES `Resolved`, an
  expired record takes the expired-during-downtime path, which
  assigns `s.active = rec.PrevTree` ALWAYS
  (`store_persist.go:166-172`) — with the synthetic `PrevTree` being
  the current tree, the CONTENT is right either way; the
  `FirstCommit` branch then decides the POSTURE: `FirstCommit=true`
  forces `compiled=nil`, `everCommitted=false`, and a `committed=0`
  marker (`store_persist.go:176-184`), re-classifying the boot into
  FIRST-COMMIT/BOOTSTRAP handling (`ActiveConfig()==nil` +
  `!everCommitted` → bootstrap-from-file import) — breaking the
  committed/runtime posture even though the tree content is
  identical; `FirstCommit=false` takes the else branch
  (`store_persist.go:185-194`): compile `PrevTree` (== the current
  tree), `compiled` set, `everCommitted=true`, `committed=1` — a
  true no-op. The write is the full fsatomic cycle,
  so its dir-fsync doubles as the replacement's durability barrier
  on POST-rename converge paths (same-directory, as r16-r17). A
  replay of this record drops at the Resolved-first recovery check —
  no binding is possible from it. The DOWNGRADE behavior is pinned
  (r22 Codex m2 = SMR m1): an old reader's `json.Unmarshal` IGNORES
  the additive `Resolved` field — it sees a PENDING record with
  `PrevTree` == the then-current tree and a ≤60 s deadline → it
  re-arms and reverts to that tree: CONFIG-STATE NEUTRAL (a revert
  to the running config) but RUNTIME-CHURNING per the corrected
  idempotence premise (AF_XDP re-attach, generation bump, FRR
  reload, possible heartbeat restart — the churn the uniform rule
  exists to prevent, accepted once on a downgrade path),
  self-limiting (the timer fires once; the record is consumed), and
  covered by a downgrade-shape regression scoped precisely (r23
  Codex m2 + r24 Codex M2's oracle): NORMAL content → the old
  reader's legacy-basis compare binds (canonical == legacy for
  normal content) → re-arms → and the assertions are the POSTURE,
  not just the tree: serialized `FirstCommit=false`, `compiled`
  present, `everCommitted=true`, `committed=1` marker, and a
  NON-bootstrap boot class (a `FirstCommit=true` variant of the
  record must instead land in the bootstrap handling above —
  proving the pin is load-bearing); EXCEPTIONAL content
  (where the bases diverge per the earlier rounds' analysis) → the
  old reader's hash check mismatches → stale-drop — both safe, and
  the test asserts each leg.
  (2) `DeleteConfirm` (unlink + dir-fsync barrier).
  Any failure raises the D-kind slot debt, retried by the same
  singleton loop — and the debt is ACTIONABLE only under the full
  three-conjunct precondition (r26 Codex M2 + r27 Codex M3, stated
  at the table head so no leg reads unqualified): NO W-kind debt
  pended AND `armedArmID == ""` AND `persistDegraded == false`
  (no outstanding active-persist debt); while any conjunct fails,
  EVERY D leg below — including the (d-ii)/(d-iii) clears — is
  inert, and each leg's action or clear is additionally gated on
  the (g-ok)/(g-absent)/(g-err) active-side state machine —
  but the retry NEVER re-runs the tombstone blindly
  (r22 Codex M2 = SMR M1, both walked the same hazard independently:
  an arm landing between the debt's raise and its retry installs a
  LIVE window's record on the slot, and an unconditional re-run
  would synthesized-tombstone and delete it — a system-induced
  durable loss of a live unconfirmed window's rollback intent): the
  retry RE-READS the slot and RE-CLASSIFIES: (d-i) the read fails
  NON-KEY-CLASS PERMANENT (the sentinel, NOT the
  `ConfirmRecordKeyClassError` subtype) → the slot provably still
  holds an
  unparseable record → proceed with the synthesized tombstone →
  delete, gated on the ACTIVE side being readable under the current
  key (r26 Codex M1's generalized laundering guard — the
  write-unverified machine's own-target EXEMPTION applies here
  too, r33 Codex M1: the tombstone overwrites the provably-
  unparseable slot precisely because it is NON-KEY-CLASS
  PERMANENT; only the OPPOSITE (active) side must validate — and
  the KEY-CLASS case (authentication failure, invalid observed key
  length, or any missing/unreadable key file) RETAINS with the
  CLASS-SPLIT message (r32 Codex m2: invalid-LENGTH or
  byte-MISMATCH → `.configdb/master.key` RESTORATION;
  ENOENT/EACCES/mount-IO → key-state UNVERIFIABLE, NO restoration
  claim) and NO write:
  the r28 NO-CREATE keyed write primitive fails such a write CLOSED
  with `readOrCreateMasterKey` never reached — no fresh key is
  created to launder the state) (that read does NOT re-terminalize; the tombstone write's
  success is the signal); (d-i') the read fails TRANSIENT-class
  (EACCES, short read, master-key IO — READ-side transient per the
  r17 taxonomy; the WRITE-side block for a missing key file lives
  in (d-i) above) → RETAIN the D-kind debt
  UNTRIED — NO write, NO delete: a transient failure does not prove
  the slot's content (r23 Codex M1 = SMR m1, converged: an arm C may
  have become VISIBLE through a post-rename failure while D pends,
  and a transient error cannot distinguish A-unreadable from
  C-visible — writing on it could tombstone a live C), with a
  dedicated regression; (d-ii) record ABSENT → `DeleteConfirm`
  re-drive (finish the dir-fsync) → clear — the re-drive AND the
  clear gated on the active-side state machine ((g-ok) PROCEED;
  (g-absent) PROCEED — this IS the sanctioned both-files-removed
  barrier; (g-err) WITHHOLD); (d-iii) record READABLE →
  the superseded unreadable record is already GONE (replaced — by an
  arm's overwrite per the confirmed-commit rule, or by operator
  action): the D-kind debt CLEARS as moot — the clear gated on the
  active-side state machine like every confirm-side action ((g-ok)
  PROCEED; (g-absent)/(g-err) WITHHOLD — a withheld clear is exactly
  what the live-window and outstanding-persist conjuncts above keep
  inert) — and the readable record
  follows its normal path (live-window ArmID match → untouched;
  `Resolved` → finish the delete; otherwise → the R-kind /
  seeded-orphan machinery). A successful arm on the slot at ANY
  point likewise SUBSUMES the D-kind debt (the arm's overwrite IS
  the supersession the debt existed to perform) — this is the
  ARM'S OWN action, not a D action (r28 Codex m3: the arm-time
  clearing is not subject to the D precondition or the active
  gate; the arm's own write path is the only gate it needs, and
  the clear rides the arm's barrier). THE BARRIER IS THE
  DURABILITY BARRIER (r30 SMR m1 + r30 Codex m2: the dir-fsync,
  `fsatomic.go:45-79` — NEVER mere rename visibility): on arm
  SUCCESS the record is durable and D clears with it; on a FAILED
  barrier — PRE-rename (slot untouched) or POST-rename (record
  merely VISIBLE, a W debt created) — D SURVIVES, suppressed by
  the resulting W debt, and re-classifies fresh when W resolves;
  and a successful (w-a) durability completion IS the deferred
  barrier (r30 Codex m2, verified the ambiguity: the post-rename
  arm leaves the live record visible-but-undurable and
  `armedArmID` live, so every D clear would otherwise wait for
  window resolution with health degraded): when (w-a)'s
  `WriteConfirm` lands the live record durably, D clears WITH W —
  the supersession is complete, the slot provably holds the
  durable live record; absent such an arm-or-(w-a), D stays inert
  until its fresh re-classification under the full
  three-conjunct precondition.
  The D-kind debt is PROCESS-LOCAL (r22 Codex M3, verified: the retry
  is an unjoined plain goroutine abandoned on exit, BOOT-origin is
  "no timer, no debt", and a pre-tombstone crash persists no D
  provenance — and auto-recreating D at boot would be WRONG, since
  the boot cannot distinguish a superseded unreadable record from a
  genuinely-pending one). Crash cases: after (1) before (2) →
  recovery drops the Resolved record (and the Resolved-first drop
  finishes the deletion); before (1) → the unreadable record stands,
  the latch reconstructs at boot, and remediation is
  OPERATOR-MEDIATED (the BOOT-latch substate path: the operator
  repairs or removes the record per the runbook; the next boot's
  total order classifies the result) — the residual is the
  already-admitted tombstone-write-failure ∧ crash-before-heal
  class, with the heal operator-paced rather than loop-paced for
  this one crash case (an operator repair inside it restores the
  record — for a DEAD (D-target) record NEVER pending-shaped per
  the r38/r39 pin (REMOVAL with the directory fsync, or the
  machinery's own `Resolved: true` synthesized shape), with the
  GuardedHash gate plus the documented operator-error boundary
  governing the live-record shapes).
  The rule applies where supersession is CERTAIN: a PLAIN COMMIT or
  SYNCAPPLY that lands durably while
  the BOOT latch stands has armed NO new window, and the replacement
  supersedes EVERY earlier window by construction. A
  CONFIRMED COMMIT: a successful arm OVERWRITES the record (the
  supersession is the overwrite); a PRE-rename arm failure against an
  unreadable record is handled by the LIVE window's W-kind restore
  (which REPLACES the unreadable record with `s.armedRecord` — the
  restore IS the tombstone-equivalent here; the active B is durable
  and the live window is record-less only until the restore lands —
  master's best-effort arm posture,
  `store_commit.go:548-553`). After the delete/restore, the probe's
  confirmed-absence (or clean-live-record) observation clears the
  latch, and no restart can
  resurrect a superseded record — closing the
  permanent-latch ∧ commit-during-latch ∧ restart-before-repair ∧
  repair ∧ content-match chain that both Codex and this SMR walked
  independently.
  permanent-latch ∧ commit-during-latch ∧ restart-before-repair ∧
  repair ∧ content-match chain that both Codex and this SMR walked
  independently. A CONFIRMED ABSENCE (record
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
  loop-exit condition gains "and no terminal latch set" AND "and
  not write-unverified" (r32/r33: the outstanding WRITE-UNVERIFIED
  state alone keeps the loop alive — the key-path probe runs every
  pass so a restored key is detected within one backoff); the
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
  next boot per the continuation kinds). The OWNERSHIP posture is
  pinned (r24 Codex m3 = SMR m2): confirm.json is STORE-OWNED — a
  repaired record is CLASSIFIED (re-validated through the normal
  total order), never trusted on the operator's say-so; the
  sanctioned remediations are REMOVAL (confirmed absence clears via
  the barrier re-drive — and the offline form carries the
  directory-fsync barrier) or repair-to-a-valid-record followed by
  classification (shape-split per the r38/r39 pin: a LIVE window's
  record repairs pending-shaped; a DEAD superseded record is
  REMOVED, never repaired pending-shaped — the `Resolved: true`
  synthesized shape is the machinery's own, never hand-authored)
  — and an arm or restore overwriting a differing
  record is intentional (the Store owns the slot; the single-Store
  invariant at `daemon.go:1042-1053` covers processes, and this pin
  covers hand edits). THE TWO REMEDIATIONS SPLIT BY RACE SAFETY
  (r34 Codex M1, verified: the classify→overwrite sequence —
  ordinary `ReadConfirm` at `db.go:242-253`, then an unconditional
  atomic replacement at `db.go:207-218` + `fsatomic.go:310-366` —
  is NOT serialized against an operator's in-flight hand repair,
  so D's synthesized tombstone or the (w-u) restore can overwrite
  and delete a record the operator JUST repaired to valid, never
  classifying it): REMOVAL is safe LIVE (the operator's `rm`
  cannot be destructively overwritten — the probe's confirmed
  absence re-drives only the idempotent barrier); repair-to-valid
  FILESYSTEM remediation requires xpfd STOPPED (the same
  offline/serialized posture as the BOOT-origin key-restoration
  branch — the operator repairs the record, restarts, and the
  boot total order classifies it) — WITH THE SAME MANDATORY
  PRECONDITION MADE EXPLICIT (r35 Codex M1 = SMR m1, both
  verified independently: the stopped posture is ONLY safe when
  `ConfirmDebtKindMask == 0` — any LIVE process-local debt
  FORBIDS the stop, since the debts die with the process,
  `store_persist.go:397-401`, and a repaired pending-shaped
  record that hash-matches then takes the expired-revert or a
  future re-arm at the next boot,
  `store_persist.go:149-165,171-255`, rolling back an
  ALREADY-CONFIRMED config — with H able to Load-revert the
  FirstCommit+cluster class on top): with any live debt, the
  operator uses the RUNNING probe/removal path instead (removal
  is the live-safe remediation for the same corrupt record);
  and the operator is warned that the boot classification
  differs by Load outcome — a SUCCESSFUL-active `Load` runs the
  full total order (the repaired record classifies through the
  normal recovery machinery), while an absent/compile-failed
  `Load` only SEEDS the record as an orphan resolved by the
  next commit —
  while the LIVE alternative is
  the probe-mediated removal path. AND THE `mask == 0`
  OBSERVATION IS FENCED AGAINST ITS OWN TOCTOU (r36 Codex M1,
  verified: the mask is derived at snapshot time, and a later
  confirmed commit or an asynchronous HA demotion resolving a
  window — `daemon_ha.go:466-474`, with a failed removal raising
  process-local debt, `store_commit.go:575-608,652-702,780-792` —
  can re-raise debt between the observation and the stop;
  post-restart health is TOO LATE because recovery runs inside
  `Load` before service, `store_persist.go:110-114`, and on-disk
  presence cannot reconstruct process-local debt): the stopped
  remediation runs a PRODUCER-QUIESCE protocol, not a point
  check — (1) the operator ensures NO live commit-confirmed
  window stands (confirm or roll back any armed window first —
  window resolution is operator-paced), (1a) the operator
  QUIESCES AUTOMATION: if any `event-options` policy is
  configured, `deactivate event-options` and commit FIRST —
  on BOTH nodes, each commit required to SUCCEED (r48 Codex M4,
  both parts verified: (i) an operator commit syncs only from
  the RG0 authority and is suppressed when ConfigSync is
  disabled, `daemon_apply_commit.go:578-601`,
  `daemon_ha_sync.go:336-370` — and a retained-policy secondary
  becomes writable on promotion after the authority stops,
  `daemon_ha.go:438-450`, committing locally with
  syncPeer=false, `daemon_apply_tail.go:446-455` — so the
  deactivation must be applied per-node: via the authority's
  sync when enabled, by the operator's own per-node commit when
  not, with each node's own apply observed; (ii) a Store
  promotion can persist before an apply aborts ahead of tail
  step 17, `daemon_apply.go:282-309,404-409`,
  `daemon_apply_tail.go:194-202` — leaving the durable tree
  deactivated while the LIVE engine retains its policies — so
  the quiesce's EFFECTIVENESS is verified, not assumed: the
  deactivate commit's own result must succeed on each node —
  a tail abort surfaces as the #5679 deferred commit error,
  `daemon_apply_dataplane.go:145-159`) —
  the event engine is the ONLY autonomous local commit source
  (r47 Codex M4, verified: it stages and commits independently,
  `engine.go:920-948`, via `commitAndApply` WITHOUT peer sync,
  `daemon_apply_tail.go:446-455` — invisible to the counter and
  the dispatch epoch — and shutdown does not fence it: the
  applyCancel + applySem drain precede the engine's Close,
  `daemon_run_shutdown.go:25-59`, whose lifetime context is
  cancelled only by Close, `engine.go:354-367,583-595`) — with
  the PRE-QUIESCE digest captured first (the true
  pre-procedure intent — the quiesce is itself an
  operator-visible config change, `store_command.go:111-129`,
  `config/inactive.go:5-10`, REVERTED at the procedure's end
  below) — and
  (1b) ONLY THEN the operator CAPTURES the intended-config
  digest + text (r47 Codex M3 = r47 SMR m2, the sharper
  construction verified: capturing T1 while a commit-confirmed
  window is live and then rolling back to T0 at step (1) leaves
  the captured pair stale — CommitConfirmed persists active.json
  with committed=1 BEFORE writing confirm.json,
  `store_commit.go:427-461,503-524`, `db.go:105-116` — and a
  stale-pair restore would Load T1 AS committed,
  `store_persist.go:21-55`, letting the final predicate bless a
  formerly unconfirmed configuration; the capture therefore
  FOLLOWS the window resolution, the automation quiesce, and
  the moratorium's declaration, and any commit that lands
  anyway forces a re-capture OF WHICHEVER BASELINE IT
  INVALIDATES (r49 Codex m2 + r49 SMR m1: a commit landing
  between the pre-quiesce capture and the (1a) quiesce commit
  invalidates the PRE-QUIESCE digest the final re-activation
  verification compares against; a commit landing between (1a)
  and (1b) invalidates the fence-time pair — the rule covers
  BOTH captures)), (2) the operator REFRAINS
  from new commits and FENCES the async producer ENFORCEABLY,
  with the observable join, the peer-side preflight, and the
  ordering PINNED (r38 Codex M1 + r39 Codex M1/M2/M3 + r40 Codex
  M1/M2 + r41 Codex M1/M2/M3, all verified: (i) the SyncApply
  apply flag and queue are PRIVATE — `cluster/sync.go:594-616` —
  and the public status surfaces expose only cumulative/history
  data — `cluster/sync.go:191-228`, `cluster/status.go:340-356` —
  so no observable predicate fences peer-driven syncs TODAY;
  (ii) the private 64-slot channel's consumer invokes
  `syncAndApply(context.Background())` and can block
  INDEFINITELY on `applySem` — `sync_conn_config.go:325-351`,
  `daemon_apply_commit.go:326-335` — so NO time-based wait
  drains the queue; (iii) a queue-length + generation-fence
  indicator has THREE false-idle windows — dequeue precedes flag
  publication (`sync_conn_config.go:325-350`), legacy gen-0
  applies leave the flag zero (`sync_conn_config.go:289-309`,
  `sync_protocol.go:704-712`), and `resetRecvGen` can clear it
  during an apply (`sync_conn_read.go:183-195`,
  `sync_conn_gen.go:340-362`); (iv) `down em0` is NOT a
  universal alternative: config sync uses the configured control
  interface only when both control fields exist and otherwise
  falls back to the fabric, possibly over TWO redundant paths —
  `daemon_ha_sync.go:774-785,820-860`; (v) the peer stop
  abandons the PEER's process-local debts symmetrically, so the
  peer needs the SAME full-state preflight before IT is stopped;
  (vi) the reverse direction has its own TOCTOU — when the
  target is RG0 authority, reconnect/promotion/the reconciler
  can push the current config to the peer BETWEEN the peer's
  check and its stop, raising peer `persistDegraded` on write
  failure, `store.go:687-717,738-746`, and degraded health is
  election-neutral so a crash takeover in the gap stays ungated
  (`cluster/readiness.go:20-24`, `cluster/election.go:427-432`);
  (vii) the restart ORDER matters — a peer restarted before the
  target stops resumes reconnect/reconcile pushes,
  `daemon_ha_sync.go:926-956`, while a peer left stopped after
  the target stops is a full cluster outage): THE OBSERVABLE
  JOIN IS ADDED TO THE PLAN AS AN OUTSTANDING-SYNC
  COUNTER (r41 Codex M1, replacing the gapful queue-length +
  gen-fence pair): a single atomic
  `ConfigSyncOutstanding` counter on EACH node, with TOTAL
  retirement and NODE-LIFETIME ownership (r42 Codex M1/M2 +
  r42 AGY M1 + r42 SMR m1 — all three reviewers independently
  caught the balance gap; severity MAJOR on 2-of-3 because a
  leaked token hangs the mandatory drain forever): the counter
  lives in NODE-LIFETIME state (the daemon scope), NOT on the
  replaceable `SessionSync` stats provider — a received
  transport-changing config replaces the session MID-CALLBACK
  (apply step 20, `daemon_apply_tail.go:238-255`:
  `stopClusterComms`+`startClusterComms`, teardown 5s-capped,
  `daemon_ha_sync.go:1405-1415`, `sync_conn.go:349-385`; the
  manager re-points at the fresh provider,
  `sync_state.go:47-63`, `daemon_ha_sync.go:906-913`) — so a
  provider-scoped counter would false-idle the fresh provider
  while the old apply is still blocked; the status surface reads
  the node-lifetime counter across ALL communication epochs.
  Every received token has EXACTLY ONE retirement owner, with
  the publication order PINNED (r43 Codex M1, verified the Go
  semantics: in `select { case ch <- item: ... }` the send
  completes — and the item becomes RECEIVABLE — before the
  arm's body runs, so an increment placed in the arm body lets
  the consumer dequeue and retire BEFORE the producer
  increments — a transient false zero): the increment is an
  OWNERSHIP RESERVATION taken BEFORE the enqueue attempt, with
  a ROLLBACK decrement on the two no-enqueue dispositions (the
  nil-channel guard and the queue-full `default:` drop arm,
  `sync_conn_read.go:318-331`); a transient false-BUSY between
  reservation and rollback is conservative and safe (the drain
  merely waits longer) — a false-idle is the only forbidden
  direction. DECREMENTED
  DEQUEUE-SCOPED via a per-item `defer` in the consumer
  (`sync_conn_config.go:325-351`) — covering the
  stale-generation skip (`sync_conn_config.go:331-336`), the
  nil-handler skip (`sync_conn_config.go:337-341`), apply
  failure, and panic unwind — with the decrement running only
  AFTER the apply returns, including the applySem-blocked
  duration (`daemon_apply_commit.go:326-335`); and session
  TEARDOWN retires every still-buffered token (the ctx-cancel
  abandonment path, `sync_conn_config.go:325-330`, and
  `SessionSync.Stop`, `sync_conn.go:349-385` — on Stop the
  queue is drained-and-retired so no token leaks across a
  provider replacement), AND the reservation itself is GATED ON
  SESSION LIVENESS (r44 Codex M1, verified: Stop can return
  with readers still alive past the 5s cap —
  `sync_conn.go:349-385` — after the consumer has selected
  ctx.Done, `sync_conn_config.go:325-330`; a surviving reader
  could then reserve+send into the still-open queue AFTER its
  one-shot drain, and no consumer remains to retire it): a
  session-dead flag is published at Stop START (before the
  drain), and a dispatch that observes it takes the DROP path —
  NO reservation, an alarm, re-convergence on the peer's next
  push after comms restart — so no token can be created on a
  dead session; and the liveness CHECK + RESERVATION + ENQUEUE
  are ONE critical section serialized against Stop's
  dead-publication and drain (r45 Codex M1 + r45 AGY M1 + r45
  SMR m1 — all three caught the narrower interleaving: a reader
  observing LIVE, preempted before the send, can otherwise
  enqueue after the drain with no consumer left — under `s.mu`
  or an equivalent lock, with the teardown drain holding the
  same exclusion, so a token is either never created — dead
  observed atomically — or always drained — created before the
  drain's exclusion began).
  The witness+counter observation is NOT claimed
  as an INSTANTANEOUS join (r44 Codex M2, verified): a
  complete, verified, not-yet-dispatched frame can exist
  outside both — a reader paused between verification and
  `handleMessage` (`sync_conn_read.go:84-93`), a legacy/unkeyed
  peer's first frame sitting in the handshake's `pendingFrame`
  (`sync_auth.go:352-369`, processed at `sync_conn.go:122-127`),
  or a WRITER-side failure publishing Down via `handleDisconnect`
  while that conn's reader remains runnable
  (`sync_conn_config.go:234-248`, `sync_conn.go:480-497`) — so
  witness-Down + counter==0 at the (2c) instant can precede a
  late dispatch; the fence's safety is the COMPOSITION, not the
  instant: (2c) drains, (3) RE-READS the counter AND compares
  ONE EXPLICITLY NAMED NODE-LIFETIME MONOTONIC DISPATCH EPOCH
  (r46 Codex M1, verified the provider-scoped candidates are
  unusable: `lastAppliedConfigGen` ignores gen-0 and failed
  applies and resets on bulk re-prime,
  `sync_conn_config.go:275-286,351-395`,
  `sync_conn_gen.go:340-367`; `ConfigsReceived` increments
  before the queue-full/stale/failure disposition,
  `sync_conn_read.go:298-330`, and both are scoped to the
  REPLACEABLE SessionSync, `sync.go:293-301,805-857`,
  `sync_state.go:47-63` — a transport-changing clean apply
  replaces the provider mid-callback,
  `daemon_apply_tail.go:238-255`, permitting an old-(0,0) →
  apply → fresh-(0,0) ABA that ERASES the pulse) — the epoch
  advances WITH the provisional pre-enqueue reservation and
  NEVER ROLLS BACK (r47 Codex M1, verified the publication
  race: an epoch incremented only on a successful reservation
  can publish AFTER a fast consumer applies and retires,
  letting (3) observe the stale epoch with a zero counter — so
  nil/full attempts move the epoch WITHOUT moving the counter:
  a conservative epoch false-positive the re-baseline rule
  already covers), lives in NODE-LIFETIME state beside the
  counter
  (preserved across every SessionSync replacement), and is
  exposed beside the counter on the status surface — against
  the value observed at (2c),
  so a dispatch that lands, applies CLEANLY, and retires
  between (2c) and (3) (the level returning to zero — r45 Codex
  M2's level-vs-sticky-event gap) is still SEEN as an epoch
  change; a stale-skip receipt moves the epoch without state
  change — a CONSERVATIVE false-positive, and the runbook's
  rule is EXPLICIT: re-baseline and repeat the (2c)→(3) pass
  (the peer is stopped, so the epoch settles) — WITH THE
  TERMINATION CLAUSE (r48 Codex m2, verified: in UNKEYED
  deployments a third-party or stale-process ingress keeps
  advancing the never-rolled-back epoch through the same
  counted dispatch path, `sync_admission.go:58-83`,
  `sync_auth.go:321-334`, so the re-baseline loop need not
  terminate): if the epoch STILL advances after the second
  re-baseline, a live ingress source exists — the stopped
  remediation is UNAVAILABLE while pulses continue (fail-closed
  by construction); the operator identifies and fences the
  ingress source (itself an incident) or uses the live removal
  path instead; and a dispatch
  landing
  after (3) is residual (iii)'s admitted local window.
  Because the reservation lives in the
  DISPATCH path (the `syncMsgConfig` case), the counter joins
  EVERY DISPATCHED FRAME (r43 Codex M2, verified the three
  non-registered reader classes): a legacy/unkeyed peer's first frame is
  processed BEFORE connection installation
  (`sync_conn.go:122-127` — `handleMessage` on the pending
  frame ahead of `installConn`), a same-fabric replacement's
  SUPERSEDED reader keeps running and its eventual disconnect
  is ignored as stale (`sync_conn.go:244-267,480-498`), and
  Stop's 5s-capped wait can leave an old reader alive past the
  cap (`sync_conn.go:349-385`) — EVERY one of those readers
  dispatches through the same `handleMessage` switch, so every
  dispatched config frame reserves a token regardless of which
  reader or connection epoch produced it; a reader that never
  completes a frame never affects state (dispatch happens only
  after a complete, verified frame —
  `sync_conn_read.go:28-93`), and in UNKEYED deployments a
  third-party or stale-process ingress (dual-accepted
  unauthenticated, `sync_admission.go:58-83`,
  `sync_auth.go:321-334`) is equally COUNTED — observed, never
  invisible (its effects surface at the re-check; the post-
  re-check window is residual (iii) below) —
  independent of generation numbers and epoch resets, so
  `outstanding == 0` is a true join OVER DISPATCHED FRAMES with
  no false-idle window WITHIN THAT DOMAIN (r45 Codex m1: the
  verified-undispatched residual is handled by the COMPOSITION
  — (2c)'s drain, (3)'s counter re-read AND monotonic-epoch
  comparison, residual (iii) — not by the counter alone);
  the counter is exposed read-only on the cluster status surface
  (gRPC/CLI, BOTH nodes) and read LIVE at check time (a single
  atomic — no joint-protection gap, r41 Codex m1's coherence
  note answered by construction), with the implementation in the
  §5.1 inventory and a coherence regression in §9. THE FENCE
  SEQUENCE IS THEN (r41 Codex M2's ordering): (2a) PEER-SIDE
  PREFLIGHT — on the PEER, verify peer `ConfirmDebtKindMask ==
  0` AND peer `persistDegraded == false` AND peer
  `ConfigSyncOutstanding == 0` — the peer's full state read path
  is PINNED (r41 Codex M3: the peer's own `/health` endpoint on
  its localhost ALREADY carries the debt mask and active-persist
  state per the health-snapshot work, and the cluster-status RPC
  gains the outstanding counter — the operator reads the peer's
  health via the peer's localhost or SSH; the §5.1 inventory
  wires the mask/persist fields into the cluster-status surface
  alongside the counter); if the peer is not clean, the stopped
  path is UNAVAILABLE — use the live removal path instead;
  (2b) STOP THE PEER xpfd (the universal fence — a stopped peer
  cannot push over ANY transport, and NO new inbound frames or
  outbound pushes can initiate after it: outbound pushes require
  a connected peer); (2c) LOCAL OUTSTANDING DRAIN — first witness INGRESS
  QUIESCENCE: the TERMINAL EXIT of every REGISTERED ingress
  reader (r43 Codex m2 + r45 Codex m1 — not literal EOF:
  header-read EOF,
  heartbeat-ack timeout, bad magic, oversized/partial payload,
  auth-trailer failure, cancellation, and ordinary read errors
  are ALL valid terminal exits, `sync_conn_read.go:22-89`, and
  dispatch happens only after complete verification, :90-93),
  observed on the EXISTING sync-peer connection-state surface —
  `IsSyncConnected` (`sync_state.go:66-74`), rendered as the
  sync "Status: Up/Down" line (`status.go:263-267`) — read
  Down (it aggregates both redundant registered sessions, and
  it does NOT register pre-install, superseded, or post-cap
  readers — those are the reservation-pinned counter's domain,
  and the verified-undispatched residual is the composition's,
  per the withdrawal above; bytes the peer
  sent before dying are either fully dispatched — counted — or
  abandoned mid-frame at reader exit, never counted and never
  applied: safe), THEN wait for
  the LOCAL `ConfigSyncOutstanding == 0` (every in-flight
  inbound apply completes, including any applySem-blocked one —
  the counter by construction cannot report idle while an apply
  is blocked, and the reservation-pinned counter joins EVERY
  DISPATCHED frame — pre-install, superseded, and
  post-cap readers the connection-state surface does not
  register (r42 Codex M2 + r43 Codex M2); the
  verified-undispatched residual is NOT the counter's domain —
  it is handled by this composition, per the withdrawal above);
  (3)
  the operator RE-CHECKS THE FULL STATE — `ConfirmDebtKindMask
  == 0` AND `persistDegraded == false` AND
  `ConfigSyncOutstanding == 0` AND the NODE-LIFETIME MONOTONIC
  dispatch epoch (the pinned counter-sibling — advanced WITH
  the provisional pre-enqueue reservation and NEVER rolled
  back, r47 Codex M1, so nil/full attempts are conservative
  epoch false-positives; preserved across SessionSync
  replacements, exposed beside the counter) UNCHANGED since the
  (2c) observation
  (r45 Codex M2 + r46 Codex M1 — the level counter alone misses
  a dispatch
  that lands, applies cleanly, and retires between (2c) and
  (3), and a provider-scoped epoch can ABA-erased the pulse;
  the node-lifetime monotonic epoch cannot)
  (r39 Codex M1 + r41 Codex M2: the
  mask-only gap — a queued apply can promote, cancel the old
  window, and FAIL its active write — `store.go:687-717,738-746`
  — leaving `ActivePersistDegraded` while the old record stands
  as the SOLE crash-recovery intent — and the merely-enqueued or
  applySem-blocked apply has not raised debt yet, which only the
  counter sees), and only then (4)
  stops xpfd and repairs. The ordering after the repair is
  PINNED (r39 Codex M2): START THE LOCAL xpfd first — its
  `Load` classification completes BEFORE cluster comms
  (`daemon_run.go:157-177,393-398` — cluster comms start only
  after Load) — and only then restart the peer. The residual
  after the fence is explicitly ADMITTED in THREE bounded shapes:
  (i) a window whose deadline fires between the re-check and the
  stop (the process-local provenance loss admitted since r29);
  (ii) a post-barrier peer SyncApply raising a process-local
  D-kind debt that the stop abandons (r37 Codex M1) — bounded to
  syncs already in flight BEFORE the peer stop (the peer stop is
  the barrier; nothing new initiates after it); (iii) a
  local→peer push (reconnect/promotion/the reconciler,
  `daemon_ha_sync.go:417-522`; `QueueConfig` writes directly,
  `sync_conn_config.go:230-250`) whose APPLY LANDS between the
  peer preflight's FIRST sub-read and the peer stop (2b) —
  REGARDLESS of
  when the frame was received (r45 Codex M3: a complete frame
  paused pre-dispatch, `sync_conn_read.go:84-93`, or held as
  the handshake's `pendingFrame`, `sync_auth.go:352-369`, can
  be RECEIVED before the preflight yet dispatch after it — the
  residual covers the apply's landing, not the push's
  initiation; and r47 Codex m1: the preflight's reads are SPLIT
  across /health and the cluster-status RPC with no coherent
  snapshot, so a frame can promote, fail persistence, and
  retire BETWEEN the two sub-reads, `store.go:687-746` — the
  window therefore runs from the FIRST sub-read, and the
  post-restart closure handles the outcome) — the peer can promote
  the sync and then FAIL its active write
  (`store.go:687-717,738-746`), raising peer
  `ActivePersistDegraded` that the stop abandons
  (`store_persist.go:397-401`) — r42 Codex M3, with the bound
  RESTATED HONESTLY (r43 Codex M3, both sub-claims verified):
  the outcome SPLITS on the write's failure class — a
  PRE-rename failure leaves the replacement INVISIBLE (the
  peer's persisted active stays the prior config; the in-memory
  promote is lost at the stop), while a POST-rename failure
  (the directory-fsync `*PostRenameSyncError`,
  `fsatomic.go:45-53,66-72`; the plan's own failure-class split
  at :2381-2391) leaves the NEW content VISIBLE with durability
  unproven — the peer's restart `Load` loads the visible
  content (`store_persist.go:21-55,110-114`; bringup applies
  it, `daemon_run_bringup.go:516-520`), an equal-and-applied
  re-push skips `SyncApply` (`daemon_ha_sync.go:550-568`), and
  the abandoned process-local degradation is NOT reconstructed
  (`/health` can be green with durability unproven,
  `api/health.go:65-71`); and convergence is
  AUTHORITY-CONDITIONAL, not unconditional — the reconnect
  re-drive skips until peer-connected AND RG0-authority AND
  30s-stable (`daemon_ha_sync.go:447-465`), and the stale peer
  can preempt under its old priorities
  (`cluster/election.go:172-193`) — so WHEN the authority's
  loaded config has config-sync enabled the cluster converges
  to the RG0 AUTHORITY's config, which MAY be the peer's older
  persisted one: a bounded REGRESSION to a persisted state,
  never a silent divergence; and the DISABLED-SYNC SUBCLASS is
  named (r44 Codex M3, verified: `ConfigSync` defaults false
  unless `configuration-synchronize` exists,
  `compiler_system.go:1872-1874`, `types_chassis.go:113`, and
  the reconciler skips on the sync-disabled gate too,
  `daemon_ha_sync.go:461-465`): if the peer's OLDER loaded
  config has ConfigSync=false and it preempts, the newer node
  fails the AUTHORITY gate while the peer-authority fails the
  SYNC-ENABLED gate — NEITHER side pushes and the divergence
  does NOT self-heal; the post-restart intended-config
  comparison below DETECTS it (the two nodes hold different
  configs, and only one matches the operator's intent), and the
  runbook pins the MANUAL re-convergence action — made
  EXECUTABLE (r45 Codex M5, verified: NO operator-callable
  unconditional push exists — `syncConfigToPeer` enforces RG0
  authority and `pushConfigToPeer` enforces ConfigSync,
  `daemon_ha_sync.go:336-370` — and the intended holder can be
  the READ-ONLY secondary, whose store rejects mutations,
  `store.go:344-354`): the operator captures, BEFORE the fence,
  (α) the CANONICAL DIGEST of the intended (fence-time active)
  config from the cluster-status surface (operator-readable,
  redaction-free — the digest needs no cleartext), and (β) the
  intended config's TEXT — which is the OPERATOR'S OWN
  committed configuration (aside from the
  quiesce's own deactivate/re-activate pair, which is
  operator-visible and reverted at the end — r48 Codex M3; the
  intended config is what the operator committed and holds
  in their config management) — with the IN-BOX fallback being
  the on-disk `.configdb/active.json` — an opaque config-DB
  artifact (a magic-header framing line + a possibly-encrypted
  JSON body, `envelope.go:78-99`, `db.go:445-450` — preserved
  byte-for-byte, r47 Codex m2) — copied off-node by the
  root-held operator, WITH ITS FORMAT CAVEATS NAMED (verified:
  the file is NOT Junos text, so it cannot feed `load
  override` directly, `store_command.go:306-309` — and its body
  is KEY-ENCRYPTED when the config carries a master password,
  `crypto.go:262-285`, keyed by the SOURCE node's own
  independently-random master.key, `crypto.go:457-480`, which a
  DIFFERENT authority cannot AEAD-open,
  `crypto.go:307-356,443-455` — r47 Codex M5: the file-level
  restore is therefore pinned to the ORIGIN NODE when the body
  is encrypted; only the cleartext-body (no master password)
  file is portable across boxes; the operator's config TEXT is
  the primary re-convergence artifact in all cases); the file
  copy is a
  byte-exact RESTORE artifact for the stopped-daemon phase, not
  a text source) — no CLI/gRPC capture surface exists or is
  needed (r46 Codex M3: the
  gRPC/REST/remote-CLI renders are always redacted,
  `grpcapi/server_config.go:347-380`, `api/config.go:304-352`,
  `cmd/cli/show.go:81-120`, and the embedded-TTY cleartext show
  is not instantiated in service mode, `daemon_run.go:601-616`),
  and the recovery
  is an AUTHORITY-SIDE staging procedure: on the RG0 authority
  (never read-only), `load override` (the only full-replace
  mode — override/merge/set, `cmd/cli/main.go:549-590`; no
  `load replace` exists, r46 Codex m2) of the operator's config
  TEXT + `commit` through the STANDARD config
  path — or, when the operator's text source is unavailable,
  the STOPPED-DAEMON file-level restore of the captured
  `active.json` onto the authority (with the directory sync and
  the encryption caveat above) — and when the intended holder
  IS the read-only secondary with an encrypted (non-portable)
  artifact, the choreography is PINNED (r48 Codex M5, verified
  the contradiction: the plan admits the intended holder can be
  the read-only secondary, forbids moving its encrypted
  artifact cross-node, and cannot then mandate restoration
  onto a different authority): restart the INTENDED-CONFIG
  HOLDER first — its `Load` classification completes BEFORE
  cluster comms (`daemon_run.go:157-177,393-398`) — then start
  the peer and LET THE ELECTION SETTLE, and RE-CONVERGE THROUGH
  THE RESULTING AUTHORITY (r49 Codex M3 + r49 AGY M1, both
  verified: restart order does NOT hold authority — a
  higher-effective-priority peer preempts after joining,
  `election.go:172-193`; and with sync enabled the
  reconciliation is authority-gated and stability-delayed,
  `daemon_ha_sync.go:447-465`): the operator reads the
  post-election RG0 state (`show chassis cluster status`),
  installs the intended text with `load override` + `commit`
  on WHICHEVER node holds authority (the operator's text is
  the primary artifact), and lets the normal sync carry it to
  the peer — with the OUTBOUND-RECONCILER JOIN (r50 Codex M3,
  verified the stale-capture construction: the reconciler
  captures the old text and claims the old (epoch ×
  generation) marker WITHOUT applySem serialization,
  `daemon_ha_sync.go:462-497`; a paused reconciler can then
  `QueueConfig` the OLD text with a NEWER wire generation,
  `sync_conn_config.go:222-243`, which the receiver accepts
  and applies, `sync_conn_config.go:254-272,325-395` — AFTER
  the predicate passed — and the claimed marker suppresses the
  later self-heal, `daemon_ha_sync.go:479-484`): the
  re-convergence commit runs AFTER the election settles — the
  join is the interval-bracketed digest check
  below PLUS the reconciler's SEND-BOUNDARY PROTOCOL (r53 Codex
  M1 + r54 Codex M1/M2/M3/m1, all verified: the claim-then-unlock-
  then-send window has no timing bound,
  `daemon_ha_sync.go:462-497`; a re-check alone is not an
  exclusion boundary — `ShowActive` releases the store lock
  before the send, `store_format.go:31-36`, and a commit can
  promote and push B while claimant A is paused, A resuming
  with a newer wire generation,
  `sync_conn_config.go:234-243,267-272,325-395`; a stale drop
  poisons the marker because CLAIMED and PUSHED are the same
  state — the A→B→A-in-one-epoch case, reachable because
  event-engine commits use syncPeer=false,
  `daemon_apply_commit.go:596-599`; the capture's
  `ActiveConfig` gate reads and `ShowActive` text read are
  separate transactions, `daemon_ha_sync.go:462-471`,
  `store_format.go:31-36,55-60`, so an enabled→disabled flip
  can pass a generation-only check; authority can change after
  the gate check, `daemon_ha_sync.go:451-454,544-548`; and the
  captured value is a uint64 FNV hash,
  `daemon_ha_sync.go:381-388,467-472`, while the store's
  ActiveDigest is a SHA-256 string, `store.go:772-779,812-829`):
  under `configSyncMu` HELD FROM VALIDATION THROUGH
  SEND-COMPLETION — with EVERY push path (the reconciler AND
  the commit push) taking the same mutex, so a validated send
  and a commit push serialize and a stale capture can never
  land after a newer one — the reconciler at the send boundary
  (i) revalidates authority + connection epoch/liveness +
  ConfigSync-enabled AND PROVIDER IDENTITY (r55 Codex M1/M2,
  verified: the captured `ss` can be replaced by a
  transport-changing apply, `daemon_apply_tail.go:238-255`,
  `daemon_ha_sync.go:658-667,1405-1415` — an equal
  epoch/liveness does not prove the pointer is current; and
  RG0 transitions do not take `configSyncMu`,
  `daemon_ha.go:438-450`, so a sender can validate as primary,
  demote mid-write, and have the frame rejected,
  `daemon_ha_sync.go:544-548` — the marker's claim state gains
  an AUTHORITY GENERATION, invalidated on any
  demotion/re-promotion), (ii)
  recomputes `configGenerationHash(ShowActive())` — the SAME
  function on the current text, matching the capture's type —
  and drops with an alarm on a mismatch, and (iii) claims the
  marker ONLY NOW and ONLY ON SEND-SUCCESS (r55 Codex M1:
  `QueueConfig` returns no result and may no-op or fail,
  `sync_conn_config.go:234-250` — and a fabric-0-fails/
  fabric-1-survives case fires no daemon callback,
  `sync_conn.go:480-498,569-570`, so the epoch does not
  advance and a pre-send claim would suppress the retry):
  `QueueConfig` gains a success return, the marker publishes
  only on success while still locked, and the send path's
  ownership is EXPLICIT (r55 Codex M3, verified the literal
  self-deadlock: `pushConfigToPeer` calls
  `markConfigSyncPushed`, which independently locks
  `configSyncMu`, `daemon_ha_sync.go:355-377,407-414`): ONE
  locked-send owner, and the marker helper is lock-ASSUMING
  (it never re-locks) —
  with the contention bound pinned (r55 Codex m1, corrected:
  `syncWriteDeadline` is 2s, `sync.go:88`, and it starts
  INSIDE `writeFull` after the `writeMu` wait,
  `sync_protocol.go:59-74` — so the mutex can be held across
  a writeMu wait PLUS a 2s write; a waiting commit retains
  applySem through it — bounded, with a §9 contention
  regression); the ConfigsSent tick and the marker no-op
  remain WITHDRAWN as witnesses (r52 Codex M4: a no-op pass
  never ticks, and the marker is private, `daemon.go:420-424`);
  and the observation ORDER is non-circular: the post-election
  digest read DETECTS the divergence, the re-convergence
  commit follows, and the two bracketing reads FOLLOW the
  re-convergence (one after it, one after one full interval);
  a
  stale pass's old-text push is then OVERWRITTEN by the
  operator's commit push (newer wire generation), and every
  later pass carries the intended text — with sync DISABLED no config flows regardless of
  authority (both push gates closed,
  `daemon_ha_sync.go:336-370,461-465`), so the re-convergence
  is applied per-node — with the FINAL VERIFICATION positioned
  deterministically (r51 Codex M4 + r51 AGY M1, both verified:
  the ConfigsSent tick is NOT a faithful witness — a marker
  no-op pass returns before QueueConfig and never ticks,
  `daemon_ha_sync.go:478-485`,
  `sync_conn_config.go:234-250`, so waiting for a tick can hang
  — and a pass paused after claiming at
  `daemon_ha_sync.go:474-489` can survive a reconnect's epoch
  bump, `daemon_ha_sync.go:51-57`, while ANOTHER pass supplies
  the observed tick, then resume and push the OLD text with a
  later wire generation,
  `sync_conn_config.go:234-243,254-272,325-395`, the claimed
  intended marker suppressing the repair,
  `daemon_ha_sync.go:479-484`): the final predicate runs TWICE
  bracketing ONE FULL reconcile interval (`periodic = 30s`,
  `configSyncReconcileLoop`) — the operator re-reads BOTH
  nodes' digests after the re-convergence, again after one full
  interval, and re-drives the intended text on ANY flip (the
  operator's commit push always carries the newest wire
  generation, so a re-drive overwrites a stale landing); a
  still-flipping state after two intervals is a stuck-lock
  incident — fail-closed, the predicate never blesses — and the precedence rule between the
  restart pins is EXPLICIT: intended-holder-first GOVERNS; the
  plain repair case (holder == local) IS the r39 local-first
  pin's case; and the pin's protection is per-node regardless
  (each node's `Load` completes before its own cluster comms),
  so a peer-first start in this recovery case preserves the
  classification protection on both nodes — and the PER-NODE
  commit paths are made executable (r50 Codex M4, verified both
  dead ends: the read-only secondary rejects mutations,
  `store.go:346-353`, `store_lock.go:9-27`, and only the RG0
  primary is writable — promotion clears the gate,
  `daemon_ha.go:438-475`): a per-node commit on a read-only
  secondary is executed by PROMOTING it first with the
  existing manual-failover request (then restoring the
  intended mastership after the commit); and the terminal
  corner is NAMED: an encrypted-artifact origin that must not
  hold the final authority AND an unavailable operator text is
  RUNBOOK-UNRECOVERABLE — fail-closed; the predicate never
  blesses; the operator rebuilds the other node's
  configuration from their config management / day-0 process —
  then re-verify per the post-restart predicate below
  (the commit re-drives the normal sync where enabled). The operational closure is PINNED
  in the runbook, no new machinery: (α) the stopped-filesystem
  repair step ends with a successful directory `sync` of the
  configdb's PARENT directory on EVERY AFFECTED NODE — BOTH
  nodes, because residual (iii)'s post-rename durability
  failure can belong to the PEER's filesystem (the barrier is
  the resolved target's parent-directory fsync,
  `fsatomic.go:354-366`; the peer can otherwise restart, load
  the visible content, mark it applied, and have equality
  suppress any rewrite, `daemon_apply.go:49-70`,
  `daemon_ha_sync.go:550-568`) — before EITHER restart (r44
  Codex M4); and (β) a POST-RESTART
  VERIFICATION step: after the local-then-peer restart, the
  operator verifies BOTH nodes hold the same intended config —
  compared against the OPERATOR'S intended config (the
  pre-procedure committed state as amended by the repair), NOT
  merely cross-node agreement: if the peer preempted and pushed
  its older persisted config, cross-node agreement alone would
  pass on the OLDER config while the operator's intended newer
  one is silently gone — and the comparison surface is pinned
  (r44 Codex m1 + r45 Codex M5/m3): an OFF-NODE capture of the
  intended config — BOTH the canonical digest AND the COMPLETE
  UNREDACTED artifact (the cleartext Show* SSOT backs HA sync
  and the DR archive, `grpcapi/server_config.go:349-352`) — is
  taken BEFORE the fence, because the show/export/compare
  surfaces REDACT secrets (`grpcapi/server_config.go:347-356`,
  `api/config.go:304-312`) and a secret-only regression would
  compare equal on them, and a digest alone cannot reconstruct
  the text for the manual re-convergence; the digest's
  OPERATOR-READABLE surface is wired onto the same
  cluster-status RPC the counter joins (the §5.1 inventory
  carries it; the prior "grpcapi/cli untouched" scoping is
  amended accordingly); AND the FULL derived persist-health
  state is clean on BOTH nodes — `ConfigPersistDegraded() ==
  false`, the AGGREGATE over ActivePersistDegraded, the confirm
  debt mask, ConfirmRecordState, and ConfigWriteUnverified
  (the x14 state model, :4175-4192 — r44 Codex M5: a
  restart-time push can promote+apply the intended config while
  its disk write fails, `store.go:687-689,738-769`, so the
  config comparison and the individual fields can pass while
  the aggregate is still true, `store_persist.go:342-352`) —
  AND `ActiveApplied() == true` on BOTH nodes (r45 Codex M4,
  verified: SyncApply promotes BEFORE the dataplane apply and a
  nonfatal apply failure deliberately leaves ActiveApplied
  false, `store.go:797-809`, `daemon_apply_commit.go:464-494`,
  while every persistence field and both digests still pass;
  the config-apply health alarm is delayed and diagnostic-only,
  `sync_conn_config.go:369-379`) — EXPOSED operator-readably
  beside the counter/epoch/digest on the cluster-status
  rendering (r46 Codex M2a: ActiveApplied is internal today —
  `health.go:65-84`, `status.go:340-356`; the exposure lands in
  pkg/cluster's rendering and relays through the code-untouched
  grpcapi/cli layers, `server_show_cluster_text.go:66-74`) —
  AND `IsConfirmPending() == false` AND `IsDirty() == false`
  (or the candidate EXPLICITLY discarded) on BOTH nodes (r46
  Codex M2b, verified: both are independent exposed state,
  `store_commit.go:796-800`, `store_lock.go:334-338`, via
  `GetConfigModeStatus`, `grpcapi/server_config.go:98-103`; a
  `LoadOverride` can set dirty without touching
  active/applied/persistence, `store_command.go:304-334`, and a
  healthy recovered confirm window can pass every other field
  yet later roll back). The appliedDigest's TEXT-SCOPED
  semantics leave ONE done-predicate hole, admitted after the
  r46 rebuttal was WITHDRAWN (r47 Codex M2's counterexample
  verified): a failed SAME-TEXT reapply can leave STALE
  enforcement when the enforcement depends on dynamic state,
  not just the text — a DHCP lease change reapplies the same T
  to build address-scoped host-inbound enforcement for the NEW
  address (`daemon_dhcp.go:231-245`), an nft installation
  failure leaves the prior kernel generation covering only its
  former destinations (`daemon_nft.go:262-272`), and the error
  returns without clearing the old digest
  (`daemon_apply_tail.go:83-89,316-327`, `daemon_apply.go:56-70`)
  — ActiveApplied compares H(T) only, so it stays true while
  the new address lacks enforcement. The done predicate
  therefore ALSO requires NO dataplane apply failure since the
  post-restart bringup on EITHER node, with the executable
  shape PINNED (r48 Codex M2, verified the existing surfaces do
  not carry it: the compile health is compile-specific,
  `daemon.go:871-880`, `daemon_health.go:79-125`;
  `ConfigsApplyFailed` covers only SessionSync callbacks,
  `sync.go:110-119`, `sync_conn_config.go:351-379`; the
  DHCP/boot/feeds applies run separate wrappers,
  `daemon_apply.go:49-86`): a PROCESS-LIFETIME apply-failure
  counter + last-apply-outcome flag, initialized BEFORE the
  restarted process's boot apply and instrumented CENTRALLY at
  every full-apply entry (the §5.1 pkg/daemon inventory carries
  it), rendered beside ActiveApplied on the status surface; the
  predicate is failure-count == 0 AND no pending arm
  outstanding (the per-arm-ID registration set for the current
  token) AND last-outcome-success
  (process-lifetime, so no baseline capture is needed), and §9
  gains the sticky same-text regression (a failed same-text
  state-dependent reapply keeps ActiveApplied true while the
  failure count moves) —
  with the disabled-sync subclass's MANUAL re-convergence
  performed first where it fired — AND the
  COMPLEMENTARY-AUTHORITY check (r58 Codex M1, verified the
  live-state false green: a receiver-primary rejection during
  dual-primary leaves BOTH nodes holding fully-applied
  intended text — every digest and apply-health field green —
  while BOTH primary transitions enable live forwarding,
  `daemon_ha.go:273-325`, `daemon_ha_sync.go:545-548`): the
  post-restart verification requires the RG0 election SETTLED
  with EXACTLY ONE primary, matching the intended mastership
  (read on the cluster status surface) —
  before the repair is declared done — with the authority
  check verifying the ACTUATED state as a MULTI-TERM
  predicate, not merely the election state (r59 Codex M1 +
  r60 Codex M1 + r60 AGY M1, all verified: `runElection`
  publishes the new state BEFORE the daemon consumes its
  event, and a demoted election state can retain rg_active
  while VRRP is still MASTER, `election.go:337-395`,
  `rg_state.go:250-263`, `daemon_ha.go:340-371,809-848`;
  RG0 normally has NO VRRP instance, `vrrp/manager.go:929-936`,
  `vrrp.go:128-142,170-173`, so "RG0 ACTIVE AND VRRP MASTER"
  is not generally observable; and for a VRRP-backed RG the
  demotion resigns VRRP BEFORE clearing rg_active, so a failed
  SetRGActive leaves the loser ACTIVE+BACKUP while the winner
  is ACTIVE+MASTER — an "exactly one ACTIVE AND MASTER"
  conjunction can hold despite dual rg_active for arbitrarily
  many failed retries; and the peer's actuated state is not
  on the shared status surface, `status.go:12-25`,
  `heartbeat_manager.go:306-355`, `heartbeat.go:636-641`):
  the check is the MULTI-TERM actuated predicate — exactly
  one node with RG0 rg_active, exactly one VRRP MASTER where
  a VRRP-backed RG applies, BOTH on the intended node, and
  the loser EXPLICITLY INACTIVE — read PER-NODE on each
  node's OWN status surface (the operator already reads the
  peer via its localhost per the r42 fold), and the term
  joins the final post-reactivation predicate as well; and ONLY THEN the
  operator RE-ACTIVATES `event-options` — ON BOTH NODES, each
  commit's own success required, EXACTLY mirroring the quiesce
  (r49 Codex M2, verified: with ConfigSync=false one commit
  cannot update the peer, `daemon_ha_sync.go:336-364`, and the
  Store promotes BEFORE apply, `daemon_apply_commit.go:225-246`,
  so a reactivation apply can abort before the engine's
  reconciliation, `daemon_apply_tail.go:194-202`, leaving the
  digest restored while automation stays empty) — and the
  re-activation is followed by the COMPLETE health/apply
  predicate again (not merely digest equality): the pre-quiesce
  digest match AND the full persist-health aggregate AND
  ActiveApplied AND the apply-failure/last-outcome terms AND
  the no-pending-outstanding term (r56 Codex m2) on
  BOTH nodes — the two-digest discipline: the post-restart
  verification compares against the fence-time (post-quiesce)
  digest; the re-activation re-verifies against the
  pre-procedure digest. The same shape covers a push landing on the
  LOCAL node between the re-check (3) and the local stop (4) —
  from any ingress source, including a stale peer process or,
  in unkeyed deployments, a third party (dual-accepted
  unauthenticated, `sync_admission.go:58-83`,
  `sync_auth.go:321-334`): the reservation-pinned counter SEES
  every dispatch at (2c)/(3), and a push landing after (3) has
  its promote+persist-failure abandoned at (4); its closure is
  the directory barrier on every affected node and the
  intended-digest + full-aggregate + ActiveApplied post-restart
  verification (r45 Codex m2 — NOT next-boot reclassification:
  a post-rename directory-sync failure is not reconstructed at
  boot, per the failure-class split above);
  deterministic closure would require a producer-pause knob
  (new machinery) — per this runbook's established admit+bound
  idiom (r29/r37/r38) the residual is admitted and bounded.
  THE r57 HYBRID RULING'S RESIDUALS (Codex ruled (A), AGY
  ruled (B), SMR ruled (B); the hybrid is adopted on the
  verified evidence: the LIVE-STATE classes — the rollback
  session-clear fork and the OnXSKBound stale closure — are
  closed by construction above because the digest net cannot
  see kernel state; the CONFIG-TEXT-VISIBLE classes are named
  bounded residuals with detection-and-recovery): (iv) the
  receiver-rejection / dual-primary marker suppression (r56
  Codex M1: the receiver rejects a config frame when it
  considers itself primary, `daemon_ha_sync.go:544-548`, and
  a sender whose own authority never transitioned keeps its
  claimed marker, suppressing same-connection retries) — the
  peer's digest then never matches the intent, the
  interval-bracketed double read CATCHES it, and the
  operator's re-drive (the commit push always carries the
  newest wire generation) recovers it; the post-procedure
  silent-suppression tail is the PRE-EXISTING #5863
  safety-net semantics, owned by the named follow-up (below);
  (v) the provider-replacement-after-check and
  authority-invalidation-after-check publication races (r56
  Codex M2/M3) — each produces at worst a stale or rejected
  push, a digest divergence at the bracketing reads, re-drive
  recovery; and (vi) the exactly-once debt-transfer
  transaction (r56 Codex M6) — WITHDRAWN as a residual (r59
  Codex M5, verified the contradiction: a cross-incarnation
  arm omitted from the current registration set is not
  pending and its completion is ignored — a possible false
  green): the serialized supersession's re-registration is
  TOTAL — EVERY live manager debt re-registers under the new
  token (the manager's debt ledger is complete because every
  arm registers at launch) — so no live arm is ever omitted,
  and the transaction is implemented, not residual. THE NAMED FOLLOW-UP ISSUE (seeded at
  implementation): the apply-level config-ACK wire message
  (the receiver ACKs acceptance, the sender's marker publishes
  only on the ACK) — hardening the #5863 safety net generally,
  beyond this runbook (`sync.go:38-76` carries no config-ACK
  type today, `sync_conn_config.go:325-395`). The abandoned-D
  outcome is bounded AND the offline repair shape for it is
  PINNED (r38 Codex M2, verified the conflation: a
  tombstone-SUCCESS/delete-failure leaves a `Resolved:true`
  record — dropped at the Resolved-first check — but a
  tombstone FAILURE leaves the ORIGINAL unreadable pending
  record, and a PENDING-SHAPED offline repair of that DEAD
  record can then BIND at the next boot — legacy-empty or
  same-content `GuardedHash`, `store_persist.go:149-165,171-255`
  — and replay the RESOLVED window through the recovery total
  order): the offline repair of a DEAD (D-target, superseded)
  record is REMOVAL, PREFERRED IN EVERY CASE (r39 Codex M4 = SMR
  m1 = AGY attack-2, all three converged: the `Resolved: true`
  tombstone shape is the MACHINERY's own synthesized form and is
  NOT an operator-authoring instruction — a new reader's
  validation runs BEFORE the Resolved check and requires at
  least a nonzero parseable `Deadline` and non-null `PrevTree`,
  `db.go:254-281`, and the downgrade-old reader IGNORES
  `Resolved` entirely, requiring the FULL synthetic field set —
  current-tree `PrevTree`, bounded deadline, canonical
  hash/basis, fresh `ArmID`, `FirstCommit:false` — an
  unrealistic and unnecessary hand-authoring burden); and the
  offline removal carries the SAME durability barrier as the
  live path (r39 Codex M5, verified: a bare `rm` is an unlink
  WITHOUT the parent-directory fsync — a power loss can replay
  the stale record, `db.go:284-315`; the live path survives via
  the probe's `DeleteConfirm` re-drive, but the stopped path has
  no probe before `Load`): the operator runs the removal WITH
  the directory fsync (`rm` then `sync -f` on the `.configdb/`
  directory — the `DeleteConfirm`-equivalent barrier).
  A pending-shaped repair of a dead record is
  explicitly FORBIDDEN in the runbook. The post-restart
  recovery path is NAMED AND CORRECTED TWICE (r37 Codex M2 + m1
  and r38 Codex M3/M4, all verified): the cases SPLIT on the
  record's deadline at restart — (FUTURE/still-pending) the
  recovered timer re-arms for the record's ORIGINAL REMAINING
  interval — possibly arbitrarily short, NOT a fresh default
  window (`store_persist.go:231-253`) — and the operator
  CONFIRMS AWAY with a BARE `commit` within it (confirmation
  cancels the timer, `store_commit.go:729-748,796-823` — NEVER
  `commit check`, which only validates,
  `cli_config.go:177-185,257-271`, and NEVER manual record
  removal, which does NOT cancel the in-memory timer);
  (EXPIRED/already-reverted) `Load` has ALREADY reverted inside
  the boot (the expired path, `store_persist.go:171-228`) —
  there is NO pending window to confirm, AND A BARE `commit`
  PROBE IS FORBIDDEN (r39 Codex M6, verified the diagnostic is
  false and dangerous: only the explicit `ConfirmCommitAs` path
  returns "no pending confirmed commit",
  `store_commit.go:729-746`; a BARE commit falls through to an
  ORDINARY promotion, `cli_config.go:257-280`,
  `grpcapi/server_config.go:257-282`, `api/config.go:238-256`,
  `store_commit.go:155-225` — and after the expired recovery
  reset the candidate to the reverted tree, that ordinary
  promotion COMMITS THE REVERTED (possibly EMPTY) configuration,
  after which the HA node guard and the active-config predicate
  SUPPRESS the later `xpf.conf` import,
  `bootstrap.go:65-79,237-247`): the operator STAGES the
  intended configuration first (set commands loading the
  intended config) and only then commits — never probes the
  state with a bare commit;
  runtime (`daemon_apply_commit.go:194-205`,
  `cluster_topology_preflight.go:59-97` — the HA runtime is
  boot-only-constructed): the supported recovery is the
  preflight's OWN named path — restart xpfd INTO the clustered
  configuration (the `xpf.conf` boot import re-imports the seed
  and commits it on the normal day-0 path,
  `bootstrapFromFile`), or an offline seed-and-restart. THE
  CONFIG-SHAPE SPLIT IS EXPLICIT (r40 SMR m1): in the H case the
  M6 staged-commit path works ONLY for a NON-clustered intended
  config — a staged CLUSTERED commit is preflight-REJECTED
  (cleanly, BEFORE store promotion, `daemon_apply_commit.go:194-205`,
  with the restart instruction in the error text) — so the
  operator stages+commits only when the intended configuration
  is standalone, and uses the restart/import path when it is
  clustered. The
  deadline's operator surface is PINNED (r38 Codex m1): the
  audit journal carries no deadline field (`journal.go:59-80`)
  and confirm.json may be encrypted (`db.go:199-216`) — the
  remaining interval is read from the startup journald log line
  (`store_persist.go:254-255`). The confirm-away path's
  availability is consistent with the commit refusal by
  construction (re-arm follows a CLEAN `Load` — healthy key
  state, not write-unverified — so the bare `commit` is admitted
  exactly when it is needed).
  As defense-in-depth, every
  content-INDEPENDENT repair write (the (w-u) restore, the D
  synthesized tombstone) RE-VERIFIES the target's classification
  inside the SAME `s.mu` hold immediately before the rename —
  byte-identity/hash of the classified content vs the current
  on-disk content; ANY change aborts the write and re-classifies.
  THE MECHANISM IS PINNED (r35 Codex m1, verified the gap:
  `WriteConfirm` calls the MONOLITHIC `WriteFileDurable`,
  `db.go:207-218`, which runs temp+write+fsync+close before its
  unconditional rename, `fsatomic.go:310-355`, with no staged
  seam): `fsatomic` gains a STAGED variant —
  `WriteFileDurableStaged(path, data, perm, preRename func() error)`
  — exposing a pre-rename hook that runs AFTER the temp-file
  fsync/close and BEFORE the rename; the repair write's
  classification re-verify runs INSIDE that hook (still under the
  same `s.mu` hold), an error from the hook UNLINKS the temp
  (the `fsatomic.go:41-44` discipline — "the temp file is removed
  on every failure path before rename", defer-driven per
  `fsatomic.go:315-321`; crash-leaked `.<base>.tmp-*` temps are
  swept by `NewDB` at open, `db.go:61-68` — never accumulated,
  and a target-unchanged/no-temp regression pins both per
  `fsatomic_test.go:297-347`)
  and re-classifies, and a test seam drives the hook's
  failure path; a post-write read-back is explicitly REJECTED as
  the mechanism (it cannot close the hostile interleave — if the
  operator's repair lands before the daemon's rename, the
  read-back sees only the daemon's own replacement) —
  best-effort against the unlocked filesystem — the stopped
  requirement above is the authoritative closure, since the
  operator's own write can land between the re-verify and the
  rename by the same unlocked mechanics). The KEY-CLASS remediation is operator-correct
  (r25 Codex m2 + r26 Codex m1): when the stall is crypto-class, the journal
  carries the exact cause (`invalid master key length in
  /etc/xpf/.configdb/master.key` / `read master key: ...` / authentication
  failure) and the health DETAIL FIELD carries a key-class indicator
  (from the retained failure's `errors.As` check against
  `ConfirmRecordKeyClassError` OR explicit byte-mismatch
  assignment) so the operator-facing guidance can
  name the real remediation — restore the
  ORIGINAL `.configdb/master.key` (writing or deleting under a NEW key would
  launder the unreadable-active state), never at confirm.json
  blindly — with the explicit warning that removing a record that
  might be a LIVE window's sacrifices its crash recovery (the
  classification, not the operator's say-so, decides). The
  operational single-xpfd assumption is stated (r25 Codex m4:
  `daemon.go:1042-1053` shows one Store per Daemon and the systemd
  unit runs one xpfd, but NO flock/singleton enforcement exists in
  `configstore/store.go:296-319` or `db.go:37-70` — the ownership
  invariant is OPERATIONAL (one xpfd per `.configdb/`), documented
  as an assumption with enforcement a follow-up). Manual
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
  fields (r19 Codex m2, verified three booleans cannot carry the
  promised subtypes) — r28 Codex M3 grows the key-class cause to
  PER-STATE form and r29 Codex M2 makes it PER-DEBT with a DERIVED
  mask (verified: one REMOVAL bit cannot represent coexisting same-
  kind R debts — clearing R_A would erase R_B's live cause — and a
  sticky cause misdirects after the key is revalidated and the
  latest retain is a non-key write failure): each keyed debt carries
  its OWN `keyClass` state = the class of that debt's LATEST
  retained failure (re-evaluated at EVERY raise/retain: set when
  the latest retained failure matches `ConfirmRecordKeyClassError`
  via `errors.As` OR by EXPLICIT assignment at a byte-mismatch
  clear-time verification (r33 Codex fold-partial 4 — the mismatch
  is a key-identity change, a key-class condition even though it
  is a comparison outcome), cleared when it does not — never from
  message
  text); the SNAPSHOT mask is DERIVED at snapshot time as the
  OR-by-kind over LIVE debts (a cleared debt simply drops out of
  the OR — no independent clear rule exists to erase a live
  sibling's cause): `{ActivePersistDegraded bool,
  ConfirmDebtKindMask (bitmask: REMOVAL | REWRITE | SLOT_DELETE),
  ConfirmDebtKeyClassMask (bitmask over the SAME kinds — DERIVED
  OR-by-kind over live debts' per-debt keyClass states),
  ConfirmRecordState enum (OK | TerminalUnreadable |
  RestartRecoveryOwed), ConfirmRecordKeyClass bool (the LATCH-level
  cause — likewise the class of the latch's LATEST retained/
  observed failure, re-evaluated at each latch observation, cleared
  with the latch), ConfigWriteUnverified bool (the r32
  WRITE-UNVERIFIED state — NON-SECRET, observable, actively probed;
  folded into the aggregate)}` — the mask covers the
  removal + rewrite debts (the H2-expanded confirmRemoveDegraded
  category) AND the D-kind slot debt (r22 Codex m3: SLOT_DELETE —
  a synthesized-tombstone record with its delete debt outstanding can
  never read falsely healthy, and the detail field names the live
  kinds; the aggregate `ConfigPersistDegraded()` is the OR of
  `persistDegraded`, every confirm-side debt kind, the latch, and
  the write-unverified state),
  and the enum distinguishes terminal-unreadable from
  readable-but-restart-required — with PRECEDENCE TerminalUnreadable
  > RestartRecoveryOwed > ConfirmDebt > WriteUnverified >
  ActivePersist:
  `api/health.go` renders the terminal confirm-record
  message first ("commit-confirmed recovery record is
  unreadable/corrupt; operator remediation required — see journal"),
  then the DISTINCT restart-recovery-owed message
  ("commit-confirmed recovery record readable again; restart required
  to complete recovery"),
  then a GENERIC confirm-persist message (r19 Codex m4 — the category
  covers BOTH removal and rewrite debts, and a rewrite-only failure
  risks LOSING the live window's recovery record, not resurrecting a
  stale rollback): "commit-confirmed recovery record persistence
  degraded (removal/rewrite/slot-delete not yet durable; retry in
  progress)" with
  the mask rendered as the debt-kind detail field — AND the snapshot
  carries the key-class cause ACROSS the Store→API boundary (r27
  Codex m2 + fold-partial 4, verified the gap: the typed snapshot
  and the `ConfigPersistDegradedStateFn` payload exposed only an
  active flag, a debt mask, and the three-state record enum — no
  key-class bit, so the promised ORIGINAL-key guidance was
  unrenderable; r28 Codex M3 then verified the singular-bool form
  was still wrong: MULTIPLE R debts + a W can coexist, and the boot
  key-class latch carries no debt while terminal precedence would
  have rendered the generic corrupt-record message; r29 Codex M2
  verified the per-kind mask must be DERIVED, not independently
  cleared): the snapshot
  carries the PER-STATE causes — `ConfirmDebtKeyClassMask` (DERIVED
  at snapshot time as the OR-by-kind over each LIVE debt's own
  keyClass state, where each debt's state is the class of its
  LATEST retained failure per `errors.As` against
  `ConfirmRecordKeyClassError` OR explicit assignment at a
  byte-mismatch clear-time verification (r31 Codex m2 — the
  mismatch is a key-identity change, a key-class condition even
  though it is a comparison outcome, not a wrapped crypto
  failure) — a mixed-R regression pins the OR
  semantics: R_A key-class + R_B non-key-class both live → REMOVAL
  bit SET; R_A clears → bit CLEARED, because R_B's latest is
  non-key-class) AND
  `ConfirmRecordKeyClass` (the latch-level cause, likewise the
  latch's LATEST observed failure class, cleared with
  the latch) — and
  `api/health.go` renders the key-class VARIANT of the message for
  the level whose cause bit is set — terminal precedence with
  `ConfirmRecordKeyClass` → "restore the ORIGINAL
  `.configdb/master.key`; removing the record sacrifices crash
  recovery"; confirm-debt precedence with any
  `ConfirmDebtKeyClassMask` bit → "restore the ORIGINAL
  `.configdb/master.key`; writing or deleting under a NEW key would
  launder an unreadable active config" — in place of the generic
  removal/rewrite/slot-delete text, with a health regression pinning
  both variants (key-class set vs clear) at BOTH precedence levels,
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
  (`daemon_run_servers.go:370-374`) are updated to name ALL the
  causes (aggregate semantics — the three r18 causes plus the
  per-state key-class causes AND `ConfigWriteUnverified`), closing
  r17 Codex m2 + r18 Codex M7
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
  early error return (`store_persist.go:141`). The ONE additional
  producer (r22): the SYNTHESIZED tombstone of the (ii-b) eager rule
  — full non-degenerate fields by construction (`PrevTree` = a clone
  of the current active tree, non-zero `Deadline`, canonical
  `GuardedHash`, fresh `ArmID`, `FirstCommit=false` — the last is
  LOAD-BEARING, with the rationale corrected per r24 Codex M2: on
  the NEW reader `Resolved` precedes H in the total order, so H
  never sees this record; the load-bearing case is the OLD reader,
  where `FirstCommit=true` forces `compiled=nil`,
  `everCommitted=false`, `committed=0` → FIRST-COMMIT/BOOTSTRAP
  handling) — used ONLY when the
  on-disk record is UNREADABLE (a read-back is impossible); it is
  not the rejected minimal form, and any replay drops at the
  Resolved-first check before its synthetic fields matter.
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
crypto/envelope/auth/PRF/master-key classes) → split BY CLASS
(r25-r28): NON-KEY-CLASS permanent → PER-DEBT TERMINAL for the
content-dependent R-kind debt (that
debt stops, the singleton loop KEEPS healing `persistDegraded`, health
503, loud journal, pinned remediation (no infinite loop, no loop
outright-stop)); KEY-CLASS permanent (authentication failure,
invalid observed key length — the `ConfirmRecordKeyClassError`
subtype) → RETAIN with the `.configdb/master.key` restoration
message, NO repair write, NO terminalization; content-INDEPENDENT
debts (W restore, D synthesized tombstone) are EXEMPT from
terminalization by construction; (x4c') W-kind LIVE-WINDOW re-key (r16 Codex
M3 + SMR m1 + r20 Codex M1 + r21 Codex M3): the W debt keys the LIVE
window's desired record, never a dead one: arm C lands DURABLY while
W_B pends → B's window died at the re-arm → W_B is stale and the debt
re-keys per C's outcome (durable → no debt; POST-rename → make C
durable; PRE-rename → restore C); the (w-b) restore REPLACES the
on-disk dead record with `s.armedRecord` (the restore IS the
supersession — ArmID-mismatch overwrite is the POINT, not a
violation), subsuming any R-kind debt keyed to the dead record once
the restore's barrier lands; an IDENTITY-PRESERVING rewrite of a
record an R-kind debt keys remains forbidden (dominance D1);
(x4f) same-content re-arm → distinct `ArmID`s (crypto/rand) — no key
collision even with identical `GuardedHash`+`Deadline`; (x5) the
read-mutate-write helper is the ONLY READ-BACK tombstone producer (the
synthesized producer writes ONLY the superseded-UNREADABLE slot) — #5637 gate
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
r17 Codex M5 + r20 Codex m3): a
PERMANENT-class corrupt confirm.json at boot sets the terminal latch at
recovery — health stays 503 ACROSS the restart (no laundering via the
bare return, `store_persist.go:140-144`) — while a TRANSIENT-class boot
read error retries bounded inside `Load` and then FAILS `Load`
(fail-closed, (x13)); remediation keys on the substate: a DEBT-origin
clean read resumes the debt BY KIND in-process; a BOOT-origin clean
read is RESTART-RECOVERY-OWED (the latch HELD, 503 + restart-required
message, until reboot — NOT an in-process clear); a superseded record
is DELETED eagerly at the replacement's durable landing (x18); (x10)
health response (r16 Codex m3): the terminal confirm-record state
renders the DISTINCT message, never "active configuration failed to
persist to disk", and the 503 remains election-neutral (no promotion
gate, crash takeover ungated); (x11) LOAD
SEEDING (r17 Codex M2 + r20 Codex m3): absent-DB / compile-failed /
success `Load`
outcomes ALL seed the three-state identity (Present(ArmID) / Absent /
unreadable — with the unreadable branch SPLIT by class: TRANSIENT →
the bounded-retry-then-fail-closed boot path; PERMANENT → the latch)
— the orphan chain (orphan A + plain commit + B pre-rename arm
failure + B resolution read error) now keys the debt
on A so the retry tombstones it, never preserves it; (x12) PROBE
OBSERVER (r17 Codex M4 + r18/r19 refinements): a terminal-latched debt
keeps the singleton ALIVE probe-only — a DEBT-origin clean read
re-seeds the identity and resumes the debt's retry BY KIND (R-kind:
tombstone→delete; W-kind: rewrite/restore) IN-PROCESS; a BOOT-origin
clean read splits into RESTART-RECOVERY-OWED (latch HELD, 503 +
restart-required message until reboot) or SUPERSEDED-WHILE-UNREADABLE
(resolved EAGERLY and DURABLY at the replacement's landing: plain
commit/SyncApply with the latch standing run the TWO-STEP synthesized
tombstone + delete — the synthetic full-field `Resolved:true` record
passes #5637 and drops at the Resolved-first check on any replay —
with the D-KIND SLOT DEBT on failure (the retry RE-READS and
RE-CLASSIFIES: NON-KEY-CLASS-PERMANENT unreadable → proceed with the
synthesized tombstone → delete, gated on the ACTIVE side readable
under the current key; KEY-CLASS permanent (invalid-LENGTH or
byte-MISMATCH) → RETAIN with the `.configdb/master.key`
restoration message; a missing/unreadable key file
(ENOENT/EACCES/mount-IO) → RETAIN with the key-state UNVERIFIABLE
message (NO restoration claim, r32 Codex m2's class-split);
BOTH with NO write; TRANSIENT-class read failure →
retain UNTRIED, no write/delete — a transient failure cannot prove
the slot's content and must never trigger a tombstone; absent →
`DeleteConfirm` re-drive; READABLE → clear as moot — never
tombstone a readable record; the debt is process-local, crash
remediation operator-mediated);
a confirmed commit's successful arm
overwrites, and its PRE-rename failure is handled by the W-kind
restore REPLACING the unreadable record); an operator
`rm` reactivates the absent-state (`DeleteConfirm` barrier for
R-kind; (w-c) restore-or-stale for W-kind) — only the barrier clears;
the loop still exits when no debt and no latch remain AND the
write-unverified state is clear (the state alone keeps the loop
alive for the key-path probe); (x13) BOOT
FAIL-CLOSED (r17 Codex M5): a TRANSIENT boot `ReadConfirm` failure
retries bounded inside `Load` (initial read + ≤3 retries,
100/200/400 ms, `LoadContext(ctx)`) then FAILS `Load` via
`ErrConfirmStateUnreadable` routed fail-closed (no manager
construction, systemd re-drives)
— an unconfirmed config never stands from a lost read; a
PERMANENT-class boot failure proceeds with the latch + 503;
(x14) TYPED HEALTH CHANNEL (r17 Codex M6/m2 + r18 M7 + r19 m4 +
r20 m2 + r23 m3 + r28 Codex M3): `ConfigPersistDegradedState()` returns
the exact breakdown `{ActivePersistDegraded bool,
ConfirmDebtKindMask (REMOVAL|REWRITE|SLOT_DELETE),
ConfirmDebtKeyClassMask (same kinds — DERIVED OR-by-kind over live
debts' per-debt keyClass states, each the class of that debt's
LATEST retained failure per `errors.As` OR explicit assignment at
a byte-mismatch clear-time verification),
ConfirmRecordState (OK|TerminalUnreadable|RestartRecoveryOwed),
ConfirmRecordKeyClass (the LATCH-level key-class cause — the
latch's LATEST observed failure class, cleared with the latch),
ConfigWriteUnverified (the r32/r33 WRITE-UNVERIFIED state —
NON-SECRET, observable, actively probed)}`;
the aggregate `ConfigPersistDegraded()` is a DERIVED value
(`persistDegraded || mask ≠ 0 || enum ≠ OK || writeUnverified`),
not a snapshot field;
/health renders by precedence TerminalUnreadable > RestartRecoveryOwed >
ConfirmDebt (generic
removal/rewrite/slot-delete message + mask detail, REPLACED by the
key-class variant naming ORIGINAL `.configdb/master.key`
restoration when the rendered level's cause bit is set) >
WriteUnverified > ActivePersist; the
gauge consumes the derived aggregate OR; the
descriptor/option/wiring comments name all the causes; (x15)
TAXONOMY
BOUNDARY (r17 Codex M4 + r25 Codex M1): master-key IO (missing
mount/EACCES) →
TRANSIENT retry (no latch); NON-KEY-CLASS permanent (malformed JSON,
zero deadline, nil target, too-new envelope format, unsupported PRF)
→ PERMANENT latch; KEY-CLASS permanent (authentication failure,
invalid observed key length) → RETAIN with the master.key-restoration
message, NO repair write (no laundering), and EVERY repair action
and clear validates the ACTIVE side is also readable under the
current key; (x16) SAME-RECORD DOMINANCE
(r18 Codex M2 + r19 Codex M1): W_B + R_B coexisting with B's tombstone
failed PRE-rename → R_B runs FIRST (tombstone barrier → delete), W_B
clears as stale — the crash-between-debts leg proves a W_B-first
implementation would durably restore the pending record and re-arm an
already-resolved window; AND the r19 generalization: R_A + R_B
coexisting → R_A's mismatch branch may NOT rewrite current B while
R_B exists (the current-record removal dominates EVERY write of that
record, from W-kind debts AND from stale-keyed mismatch branches) —
the R_A-first crash leg proves B never becomes durable before R_B;
AND the r21 RESTORE-PRIORITY handoff (r21 Codex M1): R_B + live W_C
→ the restore runs FIRST (replacing B with C's `s.armedRecord` — no
recordless live window) and R_B clears once the restore's barrier
lands; a restore failure leaves R_B to its own tombstone→delete under
D1 — the crash cases collapse to the admitted residual class;
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
SUPERSEDED-WHILE-UNREADABLE (resolved EAGERLY at the replacement's
durable landing — plain commit/SyncApply with the latch standing run
the TWO-STEP synthesized tombstone + delete with the process-local
D-kind slot debt (retry re-reads and re-classifies; never tombstones
a readable record); the
restart-before-repair leg proves no replay: permanent-latch ∧
commit-during-latch ∧ restart ∧ repair ∧ content-match ends with the
record long gone); (x20) FAIL-CLOSED ROUTING (r18 Codex M6 = SMR M1 + r19 Codex m3):
`ErrConfirmStateUnreadable` →
`classifyLoadError` fail-closed mapping (`bootstrap_test.go:10-36`
legs), confirm.json-named diagnostic, pinned retry envelope (initial
read + ≤3 retries, 100/200/400 ms, `LoadContext(ctx)`); (x21)
HEALTH SNAPSHOT PRECEDENCE (r18 Codex M7/m5 + r19 Codex m4 + r20
Codex m2 + r23 Codex m3 + r27 Codex m2 + r28 Codex M3): the exact
breakdown
`{ActivePersistDegraded, ConfirmDebtKindMask
(REMOVAL|REWRITE|SLOT_DELETE), ConfirmDebtKeyClassMask (same kinds —
DERIVED OR-by-kind over live debts' per-debt keyClass states, each
the class of that debt's LATEST retained failure per `errors.As`
OR explicit assignment at a byte-mismatch clear-time verification),
ConfirmRecordState
(OK|TerminalUnreadable|RestartRecoveryOwed), ConfirmRecordKeyClass
(the LATCH-level key-class cause — the latch's LATEST observed
failure class, cleared with the latch), ConfigWriteUnverified
(the r32/r33 WRITE-UNVERIFIED state — NON-SECRET, observable,
actively probed)}` —
all causes NON-SECRET, NEVER from message text — with the aggregate
DERIVED (`persistDegraded || mask ≠ 0 || enum ≠ OK ||
writeUnverified`);
/health precedence TerminalUnreadable > RestartRecoveryOwed >
ConfirmDebt (generic removal/rewrite/slot-delete message + mask
detail, REPLACED by the key-class variant naming ORIGINAL
`.configdb/master.key` restoration when the rendered level's cause
bit is set — both variants regression-pinned at both levels) >
WriteUnverified > ActivePersist; the gauge
consumes the derived aggregate OR;
Config → NewServer plumbing
pinned; (x22) D-SUPPRESSION LEGS (r27 Codex m1 + r29 Codex m3,
verified the acceptance gap AND corrected the contradiction: a
successful arm on the slot SUBSUMES D by its own overwrite, so "D
inert beside a durable arm" is the WRONG expectation — the arm
kills D itself): (x22a) ARM-BARRIER CLEARANCE — seed a D-kind slot
debt, land a FULLY DURABLE arm on the slot (no W debt created), and
assert D is CLEARED by the arm's own supersession (riding the arm's
dir-fsync DURABILITY barrier — gate-independent, not a D action;
a FAILED barrier — pre- or post-rename — leaves D standing,
suppressed by the resulting W debt), never acted on by D's
own machinery afterward; AND the deferred-barrier leg (r30 Codex
m2): a post-rename arm failure then a SUCCESSFUL (w-a) durability
completion clears D WITH W (the (w-a) `WriteConfirm` IS the
deferred barrier — the slot provably holds the durable live
record); (x22b) SYNCAPPLY-PRE-RENAME (r27 Codex
M3): D seeded beside durable live C, SyncApply cancels C and its
replacement active write fails PRE-rename — assert D stays
INERT while `persistDegraded` stands (C's record survives per
#5473 — no tombstone/delete runs), then let the replacement retry
land and assert D's fresh re-read proceeds per the (ii-b) eager
rule; the `armedArmID != ""` conjunct stands as DEFENSE-IN-DEPTH
(the arm-supersession is the primary mechanism — any future path
that raises D beside a live window keeps it inert), with a leg
that seeds D beside a live window via test seam and asserts no D
action until the window resolves; the D-regression suite covers
every read classification × the three-conjunct precondition;
(x23) ACTIVE-GATE MATRIX (r27 Codex M1 +
r28 Codex M1's inventory completion + r29 Codex m2's (w-u) leg):
(g-ok)/(g-absent)/(g-err) × (W (w-a) durable rewrite, W (w-b)/(w-c)
restore, W (w-u) unreadable-slot restore-over,
R (a) tombstone+delete, R (c) mismatch rewrite, D
tombstone, D delete,
confirm-side clear, sanctioned both-files-removed barrier) at BOTH
placements (boot — consuming the same `ReadActiveMeta` result
`Load` already took; runtime — a fresh read under `s.mu` at action
time), asserting (g-absent) PROCEEDS only for the barrier and
withholds everything else, and (g-err) withholds + retains with NO
terminalization for both EACCES and corrupt-active; (x24) KEY-CLASS
CLASSIFICATION BOUNDARIES (r27 Codex M4 + r28 Codex m1/m2 + r30
Codex m1's re-read outcome taxonomy): auth failure →
`ConfirmRecordKeyClassError`; invalid observed length → key-class;
missing key file / EACCES → NOT key-class (READ-side TRANSIENT);
unsupported PRF / too-new envelope / bad nonce ENCODING or length /
bad base64 → NOT
key-class (NON-key-class permanent — these fail BEFORE AEAD,
`crypto.go:328-353`), while a well-formed TAMPERED nonce reaches
`gcm.Open` and is KEY-CLASS by authentication indistinguishability
(`crypto.go:354-356`); the COMBINED plaintext-active /
K-encrypted-confirm scenario under a swapped-but-valid K′ asserts
ZERO write/delete (the read-side key-class rule retains; the
no-create primitive is never reached); the CLEAR-TIME re-read
taxonomy (r30 Codex m1): byte-MISMATCH → RETAIN + keyClass set
EXPLICITLY (restoration-required); invalid-length →
restoration-required (via `ErrMasterKeyLength`); EACCES / ENOENT /
mount-IO → RETAIN + journal the exact error with the
key-state-UNVERIFIABLE message (generic text, NO restoration
claim); a legitimate same-content rewrite passes;
PLUS the NO-CREATE write pin
(r27 Codex M2 + r28 Codex M1): an encrypted repair write attempted
with the key
file missing FAILS with no key created (the file stays absent), a
K-swap between gate and write is impossible by construction (one
snapshot), a plaintext repair write proceeds with no key access
at all, and EVERY non-arm `WriteConfirm` producer ((w-a), (w-b)/
(w-c), (w-u), R (a), R (c), D tombstone) takes the primitive;
(x25) WRITE-UNVERIFIED STATE MACHINE (r30 Codex M1 + r31 Codex
M1/M2/m1 — full legs in the formal §9 list): ENTER on any
key-class-observed failure / key-path probe failure / byte-mismatch
→ EVERY encrypted config-DB write blocked (active heal withheld,
repair writes withheld, commits refused EARLY — incl. the
plaintext-candidate/ENCRYPTED-PrevTree case); HOLD through
UNVERIFIABLE classifications; EXIT ONLY on POSITIVE validation
(same-snapshot key-path read + decrypt-validation of an on-disk
encrypted record) — the wrong-K″ split can never form and the
restoration flow is non-circular. This closes the
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

### 4.7 Delivery structure — the r28 SPLIT ruling (2-of-3)

The r28 split rulings: **Codex (B) SPLIT**, **Claude SMR (B) SPLIT**,
**AGY (A) CONVERGE** (recorded verbatim in
`codex-plan-r28.md` / `claude-smr-plan-r28.md` / `agy-plan-r28.md`).
The 2-of-3 majority carries, per `docs/engineering-style.md`
principle 5 (narrow scope) and the hand of the r19-recorded analysis
(H-without-H2 is unsound; the only sound split moves H WITH H2 —
v20 history). The delivery is TWO units:

- **PR-1 (the #2114 deliverable — the titled defect)**: the `d.dp`
  synchronized-accessor core — work item A1 (the atomic publication
  cell + uniform accessor), the 5-site writer conversion (§5.2), the
  per-site snapshot boundaries (§5.3), the full reader conversion
  (134 prod + ~110 test, §5.4), the `CachedStatusProvider` sampler
  narrowing (§4 A1), the canary pair (§5.1 + `pkg/daemon` AST
  canary), docs + tests. This core is complete and self-contained:
  it closes RACE-1 (watcher chain), RACE-2 (bootstrap-exit arm), and
  RACE-3 (recovered confirm timer) at the memory-ordering level and
  regresses nothing — every pre-existing hazard it does NOT address
  stays exactly as exposed as master is today.
- **Follow-up issue (filed at /engineer time; seeded from this
  document)**: "commit-confirmed recovery integrity: startup gate +
  FirstCommit+cluster Load recovery + confirm-record durability" —
  work items **G + H + H2 TOGETHER**, per Codex r28's ordering
  constraint (verified against the plan's own pins): G's gate
  releases recovery at END-of-PHASE-5, AFTER manager construction,
  while H's revert-at-Load is only safe BEFORE `d.cluster` exists —
  landing G without H would convert master's short pre-manager timer
  window into the known post-manager bootstrap-with-live-cluster
  hybrid, and H cannot land alone because its correctness depends on
  H2's durability machinery. The core must therefore NOT ship G:
  G moves with H+H2 into the follow-up, which lands as the NEXT work
  item after the core merges (no hard ordering gate — the core
  introduces no new exposure; the follow-up sequences pre-existing
  defects rather than gating the titled fix).
- **Dissent recorded**: AGY ruled (A) CONVERGE — v28's folds close
  H2, so a single PR avoids administrative overhead for an
  already-validated design. The user makes the final call at manual
  approval: the plan converges PLAN-READY under EITHER structure
  (all three reviewers' verdicts gate the DESIGN, which is
  identical; the split is a packaging recommendation). If the user
  prefers one PR, §4.7 collapses to "ship it all" with no design
  change.

## 5. Concrete design (A1)

### 5.1 New/changed types

- `pkg/daemon/daemon.go`: `dpSlot`, `dpCell atomic.Pointer[dpSlot]`
  replacing `dp`; `dataplane()` / `setDataplane()` (kind-gated); field doc
  comment mirroring the `natPoolAlarm` contract (`daemon.go:211-223`).
  PLUS the work-item-G state: `startupDone chan struct{}`,
  `startupDoneOnce sync.Once`, `startupOK atomic.Bool`, `finishStartup`,
  and the r8 `stopping atomic.Bool` shutdown-admission fence.
  PLUS the work-item-H2 authority/provider state (r56 Codex
  M7's inventory completion): the config-sync marker's claim
  carries the AUTHORITY GENERATION (bumped by the RG0
  transition path, `daemon_ha.go:438-475`) and the PROVIDER
  IDENTITY (the captured `getSessionSync()` result,
  revalidated at the send boundary) — both daemon-scope,
  beside the existing marker fields (`daemon.go:420-424`).
  PLUS the work-item-H2 apply-health state (r48 Codex M2 + r49
  Codex M1 + r50 Codex M1/M2): a PROCESS-LIFETIME
  `applyFailureCount` and a `lastApplyOK` flag, initialized
  BEFORE the restarted process's boot apply and written
  CENTRALLY at the single full-apply entry
  (`applyConfigLocked`, `daemon_apply.go:141-355` — every
  wrapper flows through it: boot,
  `daemon_run_bringup.go:516-520`; DHCP/feeds,
  `daemon_dhcp.go:73-90`, `daemon_feeds.go:26-42`;
  commit/rollback/sync, `daemon_apply_commit.go:246,489,697`) —
  published as ONE COHERENT VERSIONED SNAPSHOT with ONE OWNER
  (r50 Codex M1 + r51 Codex M1/M2, three races verified: (i)
  independent atomics beside the independently-locked
  ActiveApplied tear mid-render, `store.go:797-809`,
  `server_show_cluster_text.go:66-74`; (ii) the store's
  promotion changes ActiveApplied's computed truth BEFORE
  `applyConfigLocked` begins while the `MarkActiveApplied`
  stamps land AFTER the boundary,
  `daemon_apply_commit.go:194-246,277-286,464-475`,
  `store.go:781-809,831-848` — copying ActiveApplied at the
  boundary can read false after success; (iii) a one-load
  reader descheduled before a failed apply resumes and returns
  the captured pre-failure green): the CONFIGSTORE owns the
  converged-state snapshot — a single versioned struct
  (active/appliedDigest state + the apply-health fields),
  where EVERY promotion and EVERY applied-digest/apply-outcome
  stamp publishes the same versioned snapshot, and the read
  side is seqlock-style: read the version, read the snapshot,
  RE-READ the version, retry on change (the show path takes no
  applySem, so the versioned re-read is the linearization
  point), with the WRITE side's double-bump and the
  publication method NAMED (r53 Codex m1 — claimed-folded in
  v53 but never actually written, an honest-fold failure
  repaired here): the writer bumps the version BEFORE and
  AFTER publishing (odd-in-flight / even-stable; the reader
  retries on an odd or changed version), and the daemon
  publishes every apply outcome through the store's
  `NoteApplyOutcome`-shaped boundary method (the single
  publication entry every failure class flows through —
  including pre-promotion compile failures, which never touch
  the store's own commit paths) — and the COMPOSITE readers join the same publication
  (r52 Codex M1, verified: `handleConfigSync`'s #4957 converged
  shortcut reads `ShowActive` and `ActiveApplied` in SEPARATE
  store lock transactions, `daemon_ha_sync.go:544-568`,
  `store_format.go:31-36`, `store.go:803-809` — an A→B
  promotion/apply between those reads combines cached text A
  with ActiveApplied(B)==true, returns success for incoming A,
  and advances the receiver high-water,
  `sync_conn_config.go:319-324,390-395`): the shortcut's
  (text, applied) pair is read from ONE versioned snapshot,
  with the §9 composite-reader leg — with the truth assignment at the
  CONVERGENCE point, not the outer return (r50 Codex M2,
  verified both false-green paths: the mandatory deferred-MAC
  second `ApplyConfig` can fail while merely recording retry
  debt and the commit still succeeds,
  `daemon_apply_dataplane.go:390-402,466-489`,
  `manager_worker_arm_5134.go:10-21`; and a `dp.Start` failure
  clears `d.dp` yet still runs the boot apply whose dataplane
  phase skips nil `d.dp`,
  `daemon_run_bringup.go:493-520`,
  `daemon_apply_dataplane.go:137-163`): `lastApplyOK` reads
  TRUE only when the dataplane phase actually converged — the
  deferred-MAC retry-debt outcome and the nil-dp skip both
  record per their REAL termination shapes (r54 Codex fold-4,
  verified: the deferred-MAC retry is UNBOUNDED — every tick
  until the workers bind, `manager_worker_arm_5134.go:18-38`,
  `process_status.go:183-198` — so the deferred-MAC debt is
  PENDING, holding the predicate unblessed without moving the
  count; the nil-dp skip is TERMINAL — FAILED, count++,
  lastOK false), AND the
  pending-XSK publication deferral records PENDING — NOT
  converged, WITHOUT moving the count — until the deferred
  publication COMPLETES or its retry budget is EXHAUSTED (the
  r53 Codex M4 alignment: a retryable rejection is PENDING;
  only a terminal failure increments), with the lastOK/count
  semantics per the tri-state (r51 Codex M3, verified:
  the userspace compile records the desired snapshot and
  returns nil while explicitly deferring publication,
  `manager_compile.go:230-257,289-298`,
  `manager.go:348-357`, so the daemon treats the phase as
  successful, `daemon_apply_dataplane.go:137-163`, while the
  actual publication happens asynchronously and its rejection
  is merely logged and retried,
  `process_status.go:118-131,183-186` — the deferred
  publication's completion/failure drives lastOK/count), with
  the convergence signal defined as an ATTEMPT-TOKENED multi-arm
  join (r52 Codex M2/M3/m1, all verified: the status loop runs
  OUTSIDE applySem, `process_status.go:150-186`, so an old or
  early completion can stamp lastOK=true during a newer apply;
  and the pending publication is not the only asynchronous
  nil/void outcome — normal Compile publishes and returns nil
  before XSK liveness is resolved,
  `manager_compile.go:338-402`, with the later probe able to
  fail closed while merely logging, `maps_sync.go:461-545`,
  and the link-cycle rebind is a void call whose failure is
  swallowed, `daemon_apply_dataplane.go:390-401`,
  `process_linkcycle.go:184-224`): EVERY asynchronous arm —
  SIX named (r54 Codex M6, verified the inventory was not
  exhaustive: `OnXSKBound` launches a goroutine,
  `maps_sync.go:451-457`, whose critical fabric-IPVLAN failure
  is merely logged, `daemon_apply_interfaces.go:98-109`, and
  `PrepareLinkCycle` suppresses/logs its command failures
  through a void interface, `daemon_apply_dataplane.go:289-296`,
  `process_linkcycle.go:145-162`) — PLUS the seventh, made
  TERMINAL rather than tokened (r55 Codex M7, verified:
  `syncInterfaceAttachments` is a void call,
  `manager_compile.go:211-214`, whose DetachXDP/DetachTC
  failures are merely logged, `:567-591`, while ApplyConfig
  returns nil, `manager.go:348-357` — a config REMOVING a data
  interface could be stamped converged while the old XDP/TC
  attachment remains live: a stale-enforcement failure, so it
  becomes a RETURNED TERMINAL pipeline failure, not an
  asynchronous arm) — deferred-MAC, pending-XSK
  publication, XSK-liveness probe, link-cycle rebind
  (NotifyLinkCycle), the OnXSKBound goroutine, and
  PrepareLinkCycle — PLUS the `pendingHAStateClear` retry debt
  (r60 Codex m1, verified it was missing: explicit asynchronous
  retry debt, `manager.go:227-236`, `manager_ha.go:98-151`,
  `process_status.go:200-207`; its originating apply fails
  terminally, so it is registered as debt without being an
  independent false-green path) — carries the apply's ATTEMPT TOKEN with
  EXACTLY-ONCE PER-ARM REGISTRATION (r54 Codex M5, verified:
  a token plus a scalar pending count is not a join — a
  duplicate completion for arm A decrements twice and falsely
  reports zero while arm B is live, and a daemon-side
  post-return increment can lose an early completion because
  ApplyConfig can process status and launch a callback before
  returning, `manager_compile.go:357-402`,
  `maps_sync.go:451-457`): each arm is a (token, arm-ID)
  registration recorded BEFORE the arm launches — with the
  manager-internal launches SELF-REGISTERED by the manager
  under its own `m.mu` (r55 Codex M5, verified the
  daemon-side check/set race: the status loop can set
  `xskBoundNotified` and launch the old callback between the
  daemon's `XSKBoundNotified` check and its `SetOnXSKBound`
  call, `daemon_apply_interfaces.go:61,98-100`,
  `manager.go:424-433`, `maps_sync.go:451-456` — so the
  daemon-side registration can strand or lose): the manager
  registers the arm atomically with the launch decision,
  the pending
  state is a per-arm-ID set (not a scalar), and a completion
  retires its own registration exactly once — a duplicate or
  unregistered completion is ignored — with
  the token's full lifecycle PINNED (r53 Codex M2 + r54 Codex
  M4, verified the mint point was wrong: commit preflight and
  compile failures return BEFORE `applyConfigLocked`,
  `daemon_apply_commit.go:98-126,194-222,551-575`, so a
  central-entry mint cannot cover them — and
  `commitWithGenBinding` still invokes commitFn after an
  initial compile error): the token is a uint64 monotonic
  per-apply generation (no overflow), MINTED at the OUTER
  apply-attempt entry — EVERY entry enumerated (r55 Codex M4):
  `commitAndApply`, `commitConfirmedAndApply`
  (`daemon_apply_commit.go:527-575`), `syncAndApply`
  (:331-402,489), the rollback path (:697), `applyConfig`, and
  `applyConfigResult` (`daemon_apply.go:50-86`) — and the mint
  is ordered AFTER applySem ADMISSION and BEFORE
  preflight/promotion (a function-entry mint could supersede
  the currently-running apply while still WAITING on the
  semaphore — admission at `daemon_apply_commit.go:172-175,
  528-531,332-335`, `daemon_apply.go:50-51,84-85`), with an
  apply attempt publishing QUEUED at ENQUEUE, BEFORE the
  semaphore wait (r58 Codex M3 + r59 Codex fold-3's
  honest-fold repair — the v59 fold landed only in the
  revision-history prose, never here; the queued-waiter window
  is real: a DHCP lease change precedes its `applyConfig`'s
  semaphore wait and the reapply rebuilds the address-scoped
  host-inbound enforcement, `daemon_dhcp.go:73-90,231-260`),
  with the ORDERING AND RETIREMENT MODEL (r59 Codex M4 +
  r59 AGY M1 + r59 SMR m1, all verified: a running attempt's
  trailing SUCCESS can overwrite a higher-generation waiter's
  QUEUED state; multiple waiters need additive reservations;
  and a canceled acquisition returns directly,
  `daemon_apply_commit.go:172-175`, which could leave QUEUED
  false-red indefinitely), with the THREE IDENTITIES DEFINED
  (r60 Codex M3 + r60 AGY M3, verified the impossibility:
  the attempt token mints at admission while QUEUED publishes
  before admission — an enqueued waiter lacks a minted
  token): (a) the ENQUEUE-RESERVATION SEQUENCE — a monotonic
  counter minted at ENQUEUE — tags the QUEUED publication;
  (b) the ADMISSION ATTEMPT TOKEN mints at admission, and the
  queued entry MIGRATES to it atomically at the
  queued-to-running transition; (c) the seqlock version is a
  THIRD counter, bumped per publication on both sides (the
  read-side retry is on the version only — the three counters
  serve enqueue ordering, attempt identity, and read
  linearization respectively and never alias); and the
  publication merge is FIELDWISE MONOTONIC (r60 Codex M4,
  verified the whole-snapshot hazard: dropping a
  lower-generation terminal FAILURE wholesale would lose the
  failure-count increment, while applying it wholesale could
  erase a higher-generation queued reservation): the failure
  count is a monotonic accumulator that EVERY terminal failure
  increments regardless of generation, while the per-attempt
  state fields are generation-guarded — (i) every publication is tagged
  with its attempt identity and a lower-identity
  publication NEVER overwrites a higher-identity per-attempt
  state (A's SUCCESS cannot erase B's QUEUED); (ii) the queued state is
  a per-attempt SET, not a scalar; (iii) a canceled
  acquisition retires its queued entry (no indefinite
  false-red); (iv) the queued-to-running transition is atomic
  at admission; and (v) the queued state lives in the
  process-lifetime snapshot (a restart constructs a fresh
  Store, `store.go:302-319`, `daemon.go:1046-1054` — nothing
  leaks across incarnations), with the
  outcome classified at the TERMINAL outer return (a compile
  error may still be retried by `commitWithGenBinding`,
  `daemon_apply_commit.go:102-125`), with the ROLLBACK fork's
  outcomes EXPLICIT (r57 Codex M4, verified and accepted: a
  stale-timer return applies nothing,
  `daemon_apply_commit.go:645-649` — NEUTRAL; a nil rollback
  target mutates active state but only LOGS the bootstrap
  teardown failure, `:651-683`, `bootstrap.go:314-320,356-370`
  — FAILURE; and the normal apply and session-clear failures
  are likewise only logged, `:697-708` — FAILURE, and
  load-bearing: a session-clear failure leaves traffic
  forwarding under stale authorization,
  `daemon_policy_invalidate.go:242-280`, invisible to any
  config-text digest): every rollback branch publishes
  NEUTRAL/SUCCESS/FAILURE through the same boundary, with the
  §9 rollback-fork legs (a failed rollback's session-clear
  failure can never read green), OWNED by the daemon and
  PUBLISHED with the configstore's versioned snapshot, THREADED
  through the manager calls that defer (the tokenless
  interfaces at `apply.go:37-40,130-134` gain it), with the
  cross-incarnation discipline CORRECTED (r54 Codex fold-2,
  verified: the #6034 seed updates the manager-neighbor
  REPLACE generation, `process_status.go:165-172`,
  `protocol_status.go:73-84` — a DIFFERENT namespace the
  helper initializes to zero, `lifecycle.rs:184-216` — it
  cannot seed an apply-attempt namespace): the token is
  process-incarnation-scoped, and the registration rule
  (below) is what rejects stale completions — a completion
  whose (token, arm-ID) was never registered in THIS
  incarnation is ignored — with a manager attach RE-REGISTERING
  the current attempt's outstanding arms (any pre-restart
  completion matches no registration), and a
  process-lifetime namespace (the predicate is consulted
  post-restart, where the freshly-minted token series rejects
  every pre-restart completion); and the NEXT-MINT supersession
  is explicit (r55 Codex M6 = r55 SMR m1, verified: manager
  work remains live outside applySem,
  `process_status.go:150-198`, including the unbounded
  deferred-worker retry, so a new attempt must not strand the
  old token's live debts NOR let them block the new
  predicate): a new mint ATOMICALLY supersedes the old token's
  registration set AND re-registers every still-relevant
  manager debt under the new token (the daemon queries the
  manager's outstanding debt state at the mint boundary), so
  the predicate evaluates exactly the current attempt's arms;
  and the supersession is SERIALIZED, not deferred (r58 Codex
  M4, verified the v58 contradiction — the residual called the
  single-retoken transaction a follow-up while §5.1 promised
  atomic supersession — and the false-green interleave: an arm
  self-registering between the manager snapshot and the
  supersession could be discarded, its completion then
  ignored, leaving work live with the predicate green,
  `process_status.go:150-198`, `maps_sync.go:451-456`):
  registration, completion, AND the mint-boundary
  supersession ALL serialize through a SEPARATE SHORT-HELD
  DEBT-LEDGER LOCK (r60 Codex M6, verified the contradiction:
  serializing through `m.mu` collides with the short-held
  ledger rule — the status loop holds `m.mu` across
  `requestLocked`, whose round trip is bounded by the
  three-second small-request deadline (corrected per r61
  Codex m3 — not 120s; the maximum applies to a 64-MiB
  apply_snapshot at roughly 67s under the current cap/formula,
  `process_control.go:31-56,85-103,129-142`): the debt-ledger
  lock is
  never held across control-socket IPC (the status loop takes
  it briefly for debt mutations only), and the lock order is
  applySem → ledger lock, with the ONE permitted nesting being
  `m.mu` → ledger lock for the decision-registration section
  (r61 Codex M5, verified the contradiction: the OnXSKBound
  readiness decision, one-shot flag, and launch happen under
  `m.mu` today, `maps_sync.go:353,451-456`, and the
  `pendingHAStateClear` registration/retirement depends on
  `m.mu`-protected cluster state and IPC outcomes,
  `manager_ha.go:78-112,139-150`): the readiness decision +
  flag + registration + launch form ONE section taken as
  `m.mu` THEN ledger lock — the canonical nesting order —
  with the reverse nesting forbidden, so
  no registration can interleave between the debt snapshot
  and the supersession — the transaction is part of the plan,
  and the re-registration is TOTAL — every live manager debt
  re-registers under the new token, so residual (vi) is
  WITHDRAWN (r59 Codex M5: an omitted arm's ignored completion
  was a possible false green; with total re-registration no
  live arm is ever omitted) — with the COMPLETION ALIAS
  (r60 Codex M5 = r60 AGY M2 = r60 SMR m2, verified: a
  carried-forward registration under token B while the
  in-flight arm completes with its captured token A would
  ignore the completion and pend B forever): a carried-forward
  registration records the ALIAS (old-token, arm-ID) →
  (new-token, arm-ID), and a completion for the aliased old
  identity retires the carried registration — with the alias
  map COLLAPSED AT EACH SUPERSESSION (r61 Codex M4 + r61 SMR
  m1, verified the transitivity gap: after A→B and B→C a
  completion carrying A must resolve through two aliases, and
  retry debt can remain live indefinitely,
  `manager_worker_arm_5134.go:38-96`): every outstanding alias
  is rewritten to the NEW current token at each supersession,
  so resolution is always one step and no chain accumulates —
  so an in-flight
  arm's completion is never lost across a supersession;
  the signal reads CONVERGED
  only when the pipeline AND every arm's completion carry the
  CURRENT attempt token; and the state machine distinguishes
  CONVERGED / PENDING / FAILED — a PENDING arm does NOT
  increment the failure count (the count moves only on a
  terminal failure — an apply pipeline failure or an arm's
  retry budget EXHAUSTED; a retryable rejection is PENDING, not
  FAILED), so a clean completion or a
  success-after-rejection rehabilitates the predicate, while
  the predicate requires count==0 AND no pending arm
  outstanding AND lastOK; and the snapshot CARRIES the pending
  state (r53 Codex M3 = r53 AGY m1 = r53 SMR m2): the current
  attempt token + a pending-arm count (incremented when an arm
  defers, decremented on a token-matching completion),
  rendered beside lastOK/count on the status surface so the
  no-pending-outstanding term is operator-checkable) — so an
  in-flight or
  parked apply reads not-success (the false-green-in-flight
  window, r49 Codex M1: a DHCP/feed reapply can be mid-flight
  with ActiveApplied still true and the count still zero,
  `daemon_dhcp.go:73-90`, `daemon_feeds.go:26-42`,
  `store.go:797-809`), and `applyFailureCount` increments on
  every TERMINAL failure — never on a PENDING arm (r55 Codex
  M9's consistency fix) — covering the DHCP/boot/feeds/sync
  wrappers that the compile-health (`daemon.go:871-880`,
  `daemon_health.go:79-125`) and the SessionSync-only
  `ConfigsApplyFailed` (`sync.go:110-119`) surfaces miss.
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
- `pkg/configstore/crypto.go` (r27 Codex M2/M4 — crypto.go IS
  touched): the TWO typed source errors `ErrMasterKeyAuth` (wrapping
  the `gcm.Open` failure, `crypto.go:354-356`) and
  `ErrMasterKeyLength` (both length gates,
  `crypto.go:451-453,460-462`), each wrapped so
  `errors.As(err, &ConfirmRecordKeyClassError)` matches and the
  chain preserves `ConfirmRecordPermanentError`; and the NO-CREATE
  keyed write primitive for ALL confirm-side repair writes (key
  sourced via `readMasterKey` — never `readOrCreateMasterKey` — a
  missing/invalid key file FAILS the write with no creation; one
  key snapshot under `s.mu` feeds both the gate's active-side
  validation and the write's encryption; plaintext writes exempt by
  construction, `crypto.go:262-265`).
- `pkg/fsatomic` (r35 Codex m1 — the re-verify-before-rename
  mechanism): the STAGED variant
  `WriteFileDurableStaged(path, data, perm, preRename func() error)`
  — temp+write+fsync+close, then the pre-rename hook, then the
  rename; the hook UNLINKS the temp on error (the
  `fsatomic.go:41-44` cleanup discipline, defer-driven per
  `fsatomic.go:315-321`; crash-leaked temps swept by `NewDB` at
  open, with a target-unchanged/no-temp regression per
  `fsatomic_test.go:297-347`); a test seam
  drives the hook's failure path. The monolithic
  `WriteFileDurable` is untouched for all other callers; the
  package comment (`fsatomic.go:1-4`) and
  `pkg/fsatomic/README.md:3-12` (both currently claim exactly two
  writers) are updated for the third (r37 Codex m2).
- `pkg/cluster` (r41 Codex M1/M2/M3 + SMR m1 + r42 Codex M1/M2 +
  r42 AGY M1 + r42 SMR m1 — the observable join): the
  gap-free-over-DISPATCHED-frames (r45 Codex m1 — the
  verified-undispatched residual is the composition's domain,
  not the counter's)
  `ConfigSyncOutstanding` atomic counter in NODE-LIFETIME state
  (daemon scope — NOT the replaceable `SessionSync` provider: a
  transport-changing apply replaces the session mid-callback,
  `daemon_apply_tail.go:238-255`, teardown 5s-capped,
  `daemon_ha_sync.go:1405-1415`, `sync_conn.go:349-385`, and the
  manager re-points at the fresh provider, `sync_state.go:47-63`,
  `daemon_ha_sync.go:906-913`); TOTAL retirement with the
  publication order PINNED (r43 Codex M1) — the increment is an
  OWNERSHIP RESERVATION taken BEFORE the enqueue attempt (a
  `select` send completes — and the item becomes receivable —
  before the arm body runs, so an arm-body increment races the
  consumer's retirement into a transient false zero), with a
  ROLLBACK decrement on the no-enqueue dispositions (the
  nil-channel guard and queue-full drop arm,
  `sync_conn_read.go:318-331`); DECREMENTED
  dequeue-scoped via a per-item `defer` in the consumer (covers
  the stale-generation skip, `sync_conn_config.go:331-336`, the
  nil-handler skip, `sync_conn_config.go:337-341`, apply failure,
  and panic unwind — after the apply returns, including the
  applySem-blocked duration, `daemon_apply_commit.go:326-335`),
  and session TEARDOWN retires every still-buffered token
  (`sync_conn_config.go:325-330`, `sync_conn.go:349-385`), and
  the reservation is GATED ON SESSION LIVENESS (r44 Codex M1):
  a session-dead flag is published at Stop START (before the
  drain); a dispatch that observes it takes the DROP path — no
  reservation, an alarm, re-convergence on the peer's next
  push — so a reader surviving past Stop's 5s cap cannot create
  an unretirable token on the dead session; and the liveness
  CHECK + RESERVATION + ENQUEUE are ONE critical section
  serialized against Stop's dead-publication and drain (r45
  Codex M1 + r45 AGY M1 + r45 SMR m1 — a reader observing LIVE
  and preempted before the send can otherwise enqueue after the
  drain): under `s.mu` or an equivalent lock, the teardown
  drain holding the same exclusion.
  Because the reservation lives in the DISPATCH path, the
  counter joins EVERY DISPATCHED frame (r43 Codex M2): pre-install
  pending frames (`sync_conn.go:122-127`), superseded readers
  (`sync_conn.go:244-267,480-498`), and post-Stop-cap readers
  (`sync_conn.go:349-385`) all dispatch through the same
  `handleMessage` switch and reserve identically; unkeyed
  third-party ingress (`sync_admission.go:58-83`,
  `sync_auth.go:321-334`) is equally counted — observed, never
  invisible. The EXISTING direct-injection tests are migrated
  (r44 Codex m2 + r45 Codex m4, the COMPLETE inventory —
  17 direct `configApplyCh <-` sends across three files:
  `sync_config_gen_test.go:236,237,266,267,293,322,340,357`,
  `sync_config_epoch_sweep_race_6284_test.go:108,163,198`,
  `sync_config_health_6387_test.go:152,207,253,281,330,338` —
  under the unconditional dequeue defer they would UNDERFLOW
  the
  counter): each is routed through the dispatch path or its
  injected items carry an explicit reservation. The
  operator-readable ACTIVE-CONFIG CANONICAL DIGEST is wired
  onto this same cluster-status RPC (r45 Codex m3 — the
  pre-fence capture and the post-restart comparison need an
  executable surface; the prior "pkg/grpcapi and pkg/cli
  untouched" scoping is amended to admit exactly this field);
  the NODE-LIFETIME MONOTONIC DISPATCH EPOCH (r46 Codex M1) —
  advanced in the same critical section WITH the provisional
  pre-enqueue reservation and NEVER rolled back (r47/r48 Codex
  M1 — a nil/full attempt moves the EPOCH without the counter:
  a conservative false-positive the re-baseline rule covers;
  "successful reservation" semantics would publish after a fast
  consumer retires, reopening the false-idle), living in
  node-lifetime state beside the counter
  and PRESERVED across every SessionSync replacement (the
  provider-scoped candidates fail: `lastAppliedConfigGen`
  ignores gen-0 and failed applies and resets on bulk re-prime,
  `sync_conn_config.go:275-286,351-395`,
  `sync_conn_gen.go:340-367`; `ConfigsReceived` increments
  before disposition and is provider-scoped,
  `sync_conn_read.go:298-330`, `sync.go:293-301,805-857` — a
  transport-changing apply's provider swap would ABA-erase a
  pulse, `daemon_apply_tail.go:238-255`) — is exposed beside
  the counter; and the ActiveApplied state (r46 Codex M2a —
  internal today, `store.go:797-809`) is rendered on the same
  status surface, ALONGSIDE the last-apply-outcome + a
  monotonic apply-failure count (r47 Codex M2 — the done
  predicate's no-apply-failure-since-bringup term; the daemon
  tracks the outcome in its health state and pkg/cluster
  renders it) AND the current attempt token + the per-arm-ID
  pending set (r56 Codex m2 — the no-pending-outstanding term
  is operator-checkable only if the surface carries it); the
  rendering lands in pkg/cluster, the
  canonical accessor in pkg/configstore, the injection in
  pkg/daemon, and pkg/grpcapi/pkg/cli stay CODE-untouched as
  relays (`server_show_cluster_text.go:66-74`).
- `pkg/daemon/daemon_apply.go` (r60 Codex m4's inventory
  completion): the QUEUED publication and the admission
  transition live in the direct semaphore-entry wrappers
  (`daemon_apply.go:49-86`).
- `pkg/daemon/daemon_apply_interfaces.go` +
  `pkg/daemon/daemon_ha_fabric.go` (r59 Codex m1's inventory
  completion — the callback work necessarily modifies both):
  the OnXSKBound closure's fire-time re-derivation under
  applySem with the full-fence re-checks, and
  `ensureFabricIPVLAN`'s failures becoming returned/aggregated
  errors (including `LinkDel`, r61 Codex m1) with the
  existing-link type+mode check
  (`daemon_ha_fabric.go:29-53,72-93,102-148`).
- `pkg/dataplane/userspace` (r56 Codex M7's inventory
  completion): the attempt-token threading through the
  deferring calls (`apply.go:37-40,130-134` gain the
  parameter); the manager-side atomic
  install/register/already-bound operation for the OnXSKBound
  arm (`manager.go:424-433`); the short-held debt ledger the
  mint's re-registration query reads (no `m.mu` held across
  control-socket IPC — r56 Codex M6 + r56 AGY M1:
  `process_status.go:150-255` holds `m.mu` across the whole
  poll including IPC with a 2s dial and up to a 120s round
  trip, `process_control.go:34-56,129-142`); and the
  `syncInterfaceAttachments` detach failures becoming a
  returned terminal error with `errors.Join` over ALL
  attempted detaches (`manager_compile.go:211-214,567-591` —
  r56 Codex m3's attempt-all rule). PLUS the OnXSKBound
  callback's BY-CONSTRUCTION staleness closure (r57 Codex M5,
  verified and accepted: the closure CAPTURES the installing
  apply's `deferredOverlays` set,
  `daemon_apply_interfaces.go:98-109`, launches via
  `go m.OnXSKBound()` on a one-shot flag,
  `maps_sync.go:451-456`, and runs OUTSIDE applySem — a stale
  closure resuming after a newer apply can create the OLDER
  apply's fabric IPVLAN overlays,
  `daemon_ha_fabric.go:41-54,99-148`, a live-kernel-state
  mutation the digest net cannot see): the callback NEVER
  applies captured state — at fire time it takes `applySem`
  (serializing against every apply) and re-derives the
  deferred-overlay set from the CURRENT config, abandoning if
  the state it was installed for no longer stands — so a
  stale closure is a no-op by construction, with the §9
  stale-callback leg; AND the callback is lifecycle-total and
  outcome-truthful (r58 Codex M2, both halves verified: (a)
  shutdown can release applySem before the detached callback
  runs, `daemon_run_shutdown.go:50-64,214-230` — so the
  callback re-checks the work-item-G fence — `runCtx.Err()`
  OR `stopping`, the FULL form (r59 Codex M2a, verified:
  signal-driven teardown begins BEFORE `runShutdownSequence`
  publishes `stopping`, and the drain proceeds after its
  five-second timeout, `daemon_run_shutdown.go:50-64,214-230`)
  — AFTER acquiring applySem AND again BEFORE each mutation,
  with the callback TEARDOWN-SERIALIZED (r60 Codex M2,
  verified: the netlink mutations are non-contextual calls,
  `daemon_ha_fabric.go:29-93,102-148`, and a signal can arrive
  after any check, with shutdown proceeding after its bounded
  drain, `daemon_run_shutdown.go:50-64,214-230` — repeated
  atomic loads cannot establish never-mutating): the callback
  is included in the shutdown's JOIN SET with the lifecycle
  protocol PINNED (r61 Codex M2, verified: a WaitGroup Add
  from the detached firing path can race shutdown's Wait —
  `maps_sync.go:451-456`, `daemon_run.go:115-119` — and a
  timed-out join would let non-contextual netlink operations
  overlap the teardown, `daemon_ha_fabric.go:23-93,102-148`):
  a closed/admission gate atomically reserves in-flight work
  BEFORE launch (under the debt-ledger lock: admission closed
  ⇒ the callback never launches; admission open ⇒ the
  registration reserves before launch), the shutdown closes
  admission FIRST and then joins the reserved set, and the
  join's 5s bound is the disposition — a callback still
  in-flight past the bound hits the full fence
  (`runCtx.Err()` OR `stopping`) at each mutation and
  abandons — the teardown waits
  for in-flight callbacks before the dataplane teardown; the
  callback's body is bounded netlink work, and the 5s bound
  remains the safety net),
  never mutating live state during teardown; (b) the callback's
  outcome reporting is DEEP (r59 Codex M2b, verified:
  `ensureFabricIPVLAN` ignores parent-up errors, logs
  MTU/address errors, discards existing-child MTU/up errors,
  calls a void reconciliation that suppresses list/delete/add
  failures, and accepts any existing link type when
  ParentIndex matches, `daemon_ha_fabric.go:29-53,72-93,
  102-148`): every operation's failure is RETURNED and
  aggregated (`errors.Join` over the parent-up, the link
  creation, the address reconciliation, the MTU/up
  operations, AND the mismatched-link deletion — `LinkDel`'s
  error is discarded today, `daemon_ha_fabric.go:52-53`, so a
  failed delete must fail the arm rather than leave the
  mismatched link, r61 Codex m1), the existing-link
  acceptance gains the KIND
  **and MODE** check (r60 Codex M7, verified: the desired link
  is specifically IPVLAN_MODE_L2, `daemon_ha_fabric.go:56-62`
  — a same-parent IPVLAN in L3/L3S mode has the right kind
  and wrong forwarding semantics): a type-or-mode-mismatched
  existing link is REPLACED, and the callback retires the arm
  FAILED on any
  aggregated failure — never converged on a partial or
  wrong-kind reconciliation).
  The counter is
  independent of generation numbers and epoch resets
  (`sync_conn_gen.go:340-362`); exposed read-only on the cluster
  status surface (gRPC/CLI) on BOTH
  nodes and read LIVE (single
  atomic — no joint-protection gap); the cluster-status RPC also
  wires the confirm-side debt mask + active-persist state (the
  peer-side preflight's read path — the peer's own `/health`
  endpoint already carries them per the health-snapshot work; the
  peer's COUNTER is read via the peer's cluster-status RPC, r42
  Codex m1); the LOCAL drain also witnesses INGRESS QUIESCENCE
  FIRST — the TERMINAL EXIT of every REGISTERED ingress reader
  (r45 Codex m1: the surface does not register pre-install,
  superseded, or post-cap readers — those are the counter's
  domain) (EOF, heartbeat-timeout, bad-magic, oversized/partial
  payload,
  auth-trailer failure, cancellation, read errors — r43 Codex
  m2), observed on the EXISTING sync-peer connection-state
  surface (`IsSyncConnected`, `sync_state.go:66-74`, rendered
  `status.go:263-267`; aggregates both redundant sessions — r42
  Codex M2 + r43 SMR m1).
- `pkg/configstore/store_commit.go` + `db.go` + `store.go` +
  `store_persist.go` (r11-r17): the `canonicalConfigHash` binding at
  the sole arm site (`writeConfirmState`); the additive `Resolved` +
  `HashBasis` + `ArmID` fields on `confirmRecord` (per the
  `db.go:200-205` additive-evolution contract — NO envelope bump, none
  exists for confirm.json); the TWO-FIELD in-memory identity
  (`armedArmID` window identity — arm stores, recovery restores,
  resolution clears; `onDiskArmID` known-on-disk identity — updated
  ONLY by write outcomes + the EVERY-outcome `Load` seeding:
  Present(ArmID) / Absent / unreadable — the unreadable branch split
  by class: TRANSIENT → the bounded-retry-then-fail-closed boot
  path; PERMANENT → the latch, with KEY-CLASS retained for
  master.key restoration and NO repair write); the read-mutate-write
  tombstone helper (the ONLY READ-BACK tombstone producer — the
  synthesized producer writes ONLY the superseded-UNREADABLE slot;
  its output always
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
  the typed-error debt SET + retry tables
  (MULTIPLE R-kind removal debts keyed to RECORDS via `onDiskArmID` —
  four-state table: match →
  tombstone→delete, absent → `DeleteConfirm` re-drive, mismatch →
  stale-clear, read error → typed — + AT MOST ONE W-kind rewrite debt
  keyed to the LIVE WINDOW via `armedArmID`/`s.armedRecord` (the
  immutable attempted record retained at arm) and re-keyed at every arm
  outcome — FOUR-LEGGED table (r23's (w-u) unreadable-slot
  restore-over joins the r19 three): match → rewrite durable, differ →
  restore-overwrite SUBSUMING the dead record's R-kind debt on the
  restore's barrier, absent → restore `s.armedRecord` verbatim or
  stale-clear, unreadable NON-KEY-CLASS-PERMANENT → restore-over
  subject to the key-class gate; SAME-RECORD dominance SCOPED: D1 — an R-kind debt
  dominates every IDENTITY-PRESERVING write of its record; D2 — a
  live window's restore is a SUPERSESSION, not a write of that
  record, and subsumes the pending removal; tombstone-required dominates
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
  (resolved EAGERLY and DURABLY at the replacement's landing: a
  TWO-STEP synthesized tombstone — full-field `Resolved:true` record
  passing #5637, dropped at the Resolved-first recovery check on any
  replay — + delete, with the D-KIND SLOT DEBT on failure; confirmed
  commit overwrites or restores over the unreadable record);
  a confirmed absence re-drives the
  `DeleteConfirm` barrier for R-kind / runs (w-c) restore-or-stale
  for W-kind before clearing), the
  TRANSIENT-boot bounded-retry (pinned envelope: initial read + ≤3
  retries, 100/200/400 ms, `LoadContext(ctx)` with `Load()` preserved,
  clock seam) then fail-`Load` with
  the NEW `ErrConfirmStateUnreadable` sentinel routed fail-closed
  through `classifyLoadError`, and the
  typed `ConfigPersistDegradedState()` snapshot accessor returning the
  exact breakdown `{ActivePersistDegraded bool,
  `ConfirmDebtKindMask (REMOVAL|REWRITE|SLOT_DELETE)`,
  `ConfirmDebtKeyClassMask (same kinds — DERIVED OR-by-kind over
  live debts' per-debt keyClass states, each the class of that
  debt's LATEST retained failure per `errors.As` OR explicit
  assignment at a byte-mismatch clear-time verification)`,
  `ConfirmRecordState (OK|TerminalUnreadable|RestartRecoveryOwed)`,
  `ConfirmRecordKeyClass bool` — the LATCH-level key-class cause,
  the latch's LATEST observed failure class, cleared with the
  latch; `ConfigWriteUnverified bool` — the WRITE-UNVERIFIED
  state, folded into the aggregate; all NON-SECRET, never from message
  text (r27 Codex m2 + r28 Codex M3)}`
  with the aggregate `ConfigPersistDegraded()` DERIVED
  (`persistDegraded || mask ≠ 0 || enum ≠ OK || writeUnverified`),
  and precedence
  TerminalUnreadable > RestartRecoveryOwed >
  ConfirmDebt > WriteUnverified > ActivePersist; the
  SyncApply finalize ordering in `store.go`; the hedge-the-cause
  stale-drop diagnostic (`store_persist.go:159-165`).
- `pkg/api` (r16 Codex m3 + r17 Codex M6/m2 + r18 Codex M7/m5 + r19
  Codex m4 — `pkg/api` IS touched):
  the new `ConfigPersistDegradedStateFn` Config FIELD (`server.go`,
  alongside the retained aggregate `ConfigPersistDegradedFn` the gauge
  consumes) wired from the store's typed snapshot;
  `api/health.go` renders the messages by precedence
  (terminal confirm-record > confirm-persist — GENERIC
  removal/rewrite/slot-delete text + a debt-kind detail field,
  REPLACED by the key-class variant naming ORIGINAL
  `.configdb/master.key` restoration when the RENDERED LEVEL's
  key-class cause bit is set — `ConfirmRecordKeyClass` at terminal
  precedence, any `ConfirmDebtKeyClassMask` bit at confirm-debt
  precedence — > write-unverified ("master-key validation
  outstanding") >
  active-persist), plus the
  DISTINCT restart-recovery-owed message for the BOOT-origin substate;
  `metrics.go` keeps the gauge on the aggregate OR (including
  `ConfigWriteUnverified`);
  `metrics_descriptors.go` + the field/wiring comments name all the
  causes (incl. `ConfigWriteUnverified`); a Config → NewServer
  plumbing test pins the wiring.
- `pkg/fwdstatus/sampler.go`: `CachedStatusProvider` interface; `NewSampler`
  + `Sampler.dp` retyped; `sample()` direct call.
- `pkg/dataplane/retirement_boundary_canary_test.go`: matcher extension
  (incl. `*ast.IndexExpr` renderer support).
- `pkg/daemon/daemon_dp_canary_test.go` (new): dpCell-access AST canary.
- `pkg/grpcapi`, `pkg/cli` CODE-untouched (r46 Codex fold-8/m3 —
  they RELAY the cluster manager's formatted status,
  `server_show_cluster_text.go:66-74`; the digest/epoch/
  ActiveApplied exposures land in pkg/configstore (the canonical
  accessor), pkg/daemon (the injection), and pkg/cluster (the
  rendering), so the relay layers need no code change).

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
  the FOLLOW-UP unit (§4.7 — these comments document the recurrence
  work item H terminates; the "same PR" framing predates the r28
  split): `daemon_run_naming.go:200-206` ("one-way ... at most once"),
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
  additive-evolution contract comment (`db.go:200-205` — gains the
  THREE new fields' (`Resolved`, `HashBasis`, `ArmID`) downgrade
  semantics AND the correction that
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
  (active-persist retry pending, confirm-record
  removal/rewrite/slot-delete debt,
  terminal confirm-record corruption, AND the write-unverified
  state — "BOTH" was the r17
  two-cause framing, corrected to three in r18/r19, to per-state
  key-class causes in r27-r29, and to the write-unverified
  aggregate member in r32/r33). The r18 additions
  (Codex m4): the #5473 ordering prose
  at `pkg/configstore/README.md:476-540` gains the failure-phase
  classification (PRE-rename retention vs POST-rename immediate
  barrier); `pkg/api/README.md:30-36` describes the typed
  snapshot's causes (grown past three: the per-state key-class
  causes AND `ConfigWriteUnverified`, not the bare bool); the stale
  single-unkeyed-delete-retry
  comments at `store_commit.go:556-570,667-695,732-735` are reworded
  to the keyed debt-set semantics; the health contract header at
  `pkg/api/health.go:10-16` names all the causes (incl.
  write-unverified); and the
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

**Intentional signature changes**: `fwdstatus.NewSampler`
takes `CachedStatusProvider` instead of `DataPlaneAccessor` (r2 M1);
and the work-item-H2 additions (r56 Codex M7): `QueueConfig`
gains a success return (`sync_conn_config.go:234-250`), and
the exported `ConfigSink`/`LinkController` interfaces gain the
attempt-token parameters (`apply.go:37-40,130-134`).
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
  TEXT repertoire grows by SIX cause-distinct degraded messages —
  terminal-unreadable, restart-recovery-owed, generic confirm-debt,
  the two key-class variants (terminal-latch key-class,
  confirm-debt key-class) naming ORIGINAL `.configdb/master.key`
  restoration, PLUS the write-unverified message (master-key
  validation outstanding) —
  the 503 semantics are unchanged, r18 Codex item-7 + r20 Codex m2 +
  r29 Codex fold-partial 7 + r32 Codex M1b),
  REST simulator fail-closed `ok=false` (#3414).

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
    any stale debt is cleared, SAME-RECORD dominance SCOPED (D1: the
    removal debt keyed to the CURRENT on-disk record dominates every
    IDENTITY-PRESERVING write of that record — W-kind rewrites keyed
    to it AND stale-keyed mismatch branches; its tombstone is the
    universal barrier for that record. D2: a LIVE window's restore is
    a SUPERSESSION, not a write of that record — it replaces the dead
    record with the live window's `s.armedRecord`, runs FIRST, and
    the pending removal clears on the restore's barrier — restore-first
    ORDERING never creates a recordless live window; a restore FAILURE
    returns K to D1, and a subsequent R_K delete + crash before the
    next SUCCESSFUL W restore (failed passes do not close the gap)
    is the admitted best-effort arm-persistence residual
    (`store_commit.go:548-553`, named in the residual set below)), debt-kind-correct actions (R-kind:
    tombstone→delete; W-kind: rewrite/restore the LIVE window's
    retained immutable record — re-keyed at every arm outcome, never
    healing a dead window, never a tombstone of
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
    recovery, kept under a LIVE probe-only observer with the
    DEBT-origin/BOOT-origin continuation split — the BOOT-origin
    substates hold the latch until reboot (restart-recovery-owed) or
    resolve the superseded-unreadable record EAGERLY at the
    replacement's durable landing with a TWO-STEP synthesized
    tombstone + delete and the D-kind slot debt (no in-memory
    marker — restart-before-repair cannot replay what was tombstoned
    and deleted at landing; the synthesized full-field record passes
    #5637 and drops at the Resolved-first check on any replay),
    election-neutral, manual remediation, loudly surfaced
    — never silently cleared), and the restore-failure arm-persistence
    residual (a LIVE window's restore fails, the dead record's R-kind
    delete succeeds, and a crash lands before the next SUCCESSFUL W
    restore — the exposure is seconds-wide under TRANSIENT failure
    but UNBOUNDED (up to the confirm window's own end) under a
    deterministic write failure such as an invalid master key or a
    read-only filesystem, which retries until the operator repairs
    (r25 Codex m3); there is NO post-crash heal either way — the
    process-local W
    debt is gone with the process and the window's crash-recovery file
    is lost outright, materially master's own best-effort
    arm-write-failure posture, `store_commit.go:548-553`), and
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

*Delivery partition (§4.7, r29 Codex m5): items tagged **[CORE]** ship
with PR-1 (the `d.dp` accessor core); items tagged **[FOLLOW-UP]** ship
with the G+H+H2 follow-up issue. Untagged general gates (build, vet,
the full Go/Rust suites, smoke) run for BOTH units.*

1. `go build ./... && go vet ./pkg/daemon/... ./pkg/fwdstatus/...` — the
   field retype makes the compiler enumerate every conversion site.
   (Untagged — runs for BOTH units per the partition header.)
2. New `pkg/daemon/daemon_dp_race_test.go` (under `-race`, `-count=5`)
   — the accessor/race tests are **[CORE]**; the work-item G gate
   tests and work-item H/H2 tests nested below are **[FOLLOW-UP]**:
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
     rewrite fails, A's debt retained); (x4c') W-kind LIVE-WINDOW
     re-key (r16 Codex M3 + SMR m1 + r20 Codex M1 + r21 Codex M3):
     the W debt keys the LIVE window's desired record, never a dead
     one: durable arm C while W_B pends → W_B stale, re-key per C's
     outcome (durable → none; POST-rename → make durable; PRE-rename
     → restore); the (w-b) restore REPLACES the on-disk dead record
     with `s.armedRecord` (ArmID-mismatch overwrite is the POINT —
     the restore IS the supersession), subsuming the dead record's
     R-kind debt once the restore's barrier lands; an
     IDENTITY-PRESERVING rewrite of an R-keyed record stays forbidden
     (dominance D1); (x4d) record absent →
     DeleteConfirm re-driven (dir-fsync); (x4e) transient read error →
     retain+retry; (x4e') PERMANENT read error — full taxonomy (#5637
     parse gates + crypto/envelope/auth/PRF/master-key) → split BY
     CLASS (r25-r28): NON-KEY-CLASS permanent → PER-DEBT
     TERMINAL for the content-dependent R-kind debt (that debt stops,
     the singleton loop KEEPS healing
     `persistDegraded`, health 503, pinned remediation); KEY-CLASS
     permanent (the `ConfirmRecordKeyClassError` subtype) → RETAIN
     with the `.configdb/master.key` restoration message, NO repair
     write, NO terminalization; content-INDEPENDENT debts (W
     restore, D synthesized tombstone) EXEMPT; (x4f)
     same-content re-arm → distinct ArmIDs; (x5) the read-mutate-write
     helper is the ONLY READ-BACK tombstone producer (the synthesized
     producer writes ONLY the superseded-UNREADABLE slot) — #5637 gate passes
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
     debts; (x9) BOOT RECONSTRUCTION (r16 Codex M4 + r17 Codex M5 +
     r20 Codex m3): permanent-class
     corrupt confirm.json at boot → terminal latch set at recovery,
     health 503 ACROSS restart (no laundering); transient-class →
     bounded retry then fail-`Load` per (x13); remediation keys on
     the substate: DEBT-origin resumes BY KIND in-process;
     BOOT-origin is RESTART-RECOVERY-OWED (latch HELD until reboot —
     NOT an in-process clear); a superseded record is DELETED
     eagerly at the durable landing per (x18); (x10) health response (r16
     Codex m3): terminal confirm-record state renders the DISTINCT
     message, and the 503 remains election-neutral (no promotion gate,
     crash takeover ungated); (x11) LOAD SEEDING (r17 Codex M2 + r20
     Codex m3): all
     three `Load` outcomes (absent-DB, compile-failed, success) seed
     the three-state identity (Present(ArmID) / Absent / unreadable —
     the unreadable branch SPLIT by class: TRANSIENT → the
     fail-closed retry path; PERMANENT → the latch); the orphan chain
     (orphan A + plain
     commit + B pre-rename arm failure + B resolution read error)
     keys the debt on A → retry tombstones it, never preserves it;
     (x12) PROBE OBSERVER (r17 Codex M4 + r18/r19 refinements):
     terminal-latched debt keeps
     the singleton ALIVE probe-only — DEBT-origin clean read →
     identity re-seeded + retry resumed BY KIND (R-kind
     tombstone→delete; W-kind rewrite/restore) IN-PROCESS;
     BOOT-origin clean read → RESTART-RECOVERY-OWED (latch held,
     503 + restart-required message until reboot) or
     SUPERSEDED-WHILE-UNREADABLE (resolved EAGERLY at the
     replacement's landing: plain commit/SyncApply with the latch
     standing run the TWO-STEP synthesized tombstone + delete with
     the process-local D-kind slot debt (the retry re-reads and
     re-classifies — NON-KEY-CLASS-PERMANENT unreadable → proceed,
     gated on the ACTIVE side readable under the current key;
     KEY-CLASS permanent (invalid-LENGTH or byte-MISMATCH) → RETAIN
     with the `.configdb/master.key` restoration message; a
     missing/unreadable key file (ENOENT/EACCES/mount-IO) → RETAIN
     with the key-state UNVERIFIABLE message (NO restoration claim);
     BOTH with NO write;
     TRANSIENT-class read failure → retain UNTRIED, no write/delete;
     absent →
     `DeleteConfirm` re-drive, READABLE → clear as moot; never
     tombstones a readable record); confirmed commit's
     successful arm overwrites, PRE-rename failure → the W-kind
     restore REPLACES the unreadable record);
     operator `rm` → absent-state re-drive (`DeleteConfirm` barrier
     for R-kind; (w-c) restore-or-stale for W-kind);
     loop exits only
     with no debt AND no latch AND the write-unverified state
     clear (the state alone keeps the loop alive for the key-path
     probe); (x13) BOOT FAIL-CLOSED (r17 Codex M5):
     TRANSIENT boot `ReadConfirm` failure → bounded retry inside
     `Load` (initial read + ≤3 retries, 100/200/400 ms,
     `LoadContext(ctx)`) → `ErrConfirmStateUnreadable` →
     `classifyLoadError` fail-closed mapping (NOT
     `loadOtherError` — `bootstrap_test.go:10-36` legs); the fatal
     diagnostic names confirm.json; (x14) TYPED HEALTH CHANNEL (r17
     Codex M6/m2 + r18 M7 + r19 m4 + r20 Codex m2 + r23 Codex m3 +
     r28 Codex M3):
     `ConfigPersistDegradedState()` returns the exact
     breakdown `{ActivePersistDegraded bool, ConfirmDebtKindMask
     (REMOVAL|REWRITE|SLOT_DELETE), ConfirmDebtKeyClassMask (same
     kinds — DERIVED OR-by-kind over live debts' per-debt keyClass
     states, each the class of that debt's LATEST retained failure
     per `errors.As` OR explicit byte-mismatch assignment),
     ConfirmRecordState
     (OK|TerminalUnreadable|RestartRecoveryOwed),
     ConfirmRecordKeyClass (the LATCH-level key-class cause — the
     latch's LATEST observed failure class, cleared with the
     latch), ConfigWriteUnverified (the WRITE-UNVERIFIED state,
     folded into the aggregate)}`; the aggregate
     `ConfigPersistDegraded()` is DERIVED
     (`persistDegraded || mask ≠ 0 || enum ≠ OK || writeUnverified`);
     /health renders by precedence TerminalUnreadable >
     RestartRecoveryOwed > ConfirmDebt (generic
     removal/rewrite/slot-delete message + mask detail, REPLACED by
     the key-class variant naming ORIGINAL `.configdb/master.key`
     restoration when the rendered level's cause bit is set) >
     WriteUnverified > ActivePersist;
     the gauge consumes the derived aggregate OR;
     descriptor/option/wiring comments name all the causes; (x15) TAXONOMY BOUNDARY (r17 Codex M4 + r25 Codex M1): master-key
     IO → TRANSIENT retry, no latch; NON-KEY-CLASS permanent
     (malformed JSON, zero deadline, nil target, too-new envelope
     format, unsupported PRF) → PERMANENT latch; KEY-CLASS permanent
     (authentication failure, invalid observed key length) → RETAIN
     with the master.key-restoration message — NO repair write
     (writing under a new key would launder the unreadable-active
     state), and EVERY repair action and clear validates the ACTIVE
     side is also readable under the current key; (x16) SAME-RECORD
     DOMINANCE (r18 Codex M2 + r19 Codex M1): W_B + R_B coexisting
     with B's tombstone
     failed PRE-rename (visible record PENDING-shaped) → the retry
     runs R_B FIRST (tombstone barrier → delete) and clears W_B as
     stale — a W_B-first implementation DURABLY RESTORES the pending
     record and the crash-between-debts leg proves the re-arm hazard
     is closed; AND R_A + R_B coexisting → R_A's mismatch branch may
     NOT rewrite current B while R_B exists (the current-record
     removal dominates EVERY write of that record) — the R_A-first
     crash leg proves B never becomes durable before R_B; AND the
     r21 RESTORE-PRIORITY handoff (r21 Codex M1): R_B + live W_C →
     restore-first (ordering never creates a recordless live window;
     a restore FAILURE returns to D1 and the admitted
     arm-persistence residual), R_B clears on the
     restore's barrier, restore-failure → R_B's tombstone→delete
     under D1; (x17)
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
     SUPERSEDED-WHILE-UNREADABLE (resolved EAGERLY at the
     replacement's landing: plain commit/SyncApply with the latch
     standing run the TWO-STEP synthesized tombstone + delete with
     the D-kind slot debt on failure — no marker, no
     restart-before-repair replay; confirmed commit's successful arm
     overwrites, PRE-rename failure → the W-kind restore replaces
     the unreadable record); (x20) FAIL-CLOSED
     ROUTING (r18 Codex M6 = SMR M1 + r19 Codex m3):
     a transient-exhausted boot
     confirm-read returns `ErrConfirmStateUnreadable`;
     `classifyLoadError` maps it to the fail-closed class (NOT
     `loadOtherError` — `bootstrap_test.go:10-36` legs); the fatal
     diagnostic names confirm.json; the pinned envelope (initial read
     + ≤3 retries, delays 100/200/400 ms, `LoadContext(ctx)` with
     `Load()` preserved, clock seam) is asserted;
     (x21) HEALTH SNAPSHOT PRECEDENCE (r18 Codex M7/m5 + r19 Codex
     m2/m4 + r20 Codex m2 + r23 Codex m3 + r28 Codex M3):
     `ConfigPersistDegradedState()` returns the exact
     breakdown `{ActivePersistDegraded bool, ConfirmDebtKindMask
     (REMOVAL|REWRITE|SLOT_DELETE), ConfirmDebtKeyClassMask (same
     kinds — DERIVED OR-by-kind over live debts' per-debt keyClass
     states, each the class of that debt's LATEST retained failure
     per `errors.As` OR explicit byte-mismatch assignment),
     ConfirmRecordState
     (OK|TerminalUnreadable|RestartRecoveryOwed),
     ConfirmRecordKeyClass (the LATCH-level key-class cause — the
     latch's LATEST observed failure class, cleared with the
     latch), ConfigWriteUnverified (the WRITE-UNVERIFIED state,
     folded into the aggregate)}`; the aggregate
     `ConfigPersistDegraded()` is a DERIVED value
     (`persistDegraded || mask ≠ 0 || enum ≠ OK || writeUnverified`),
     not a snapshot
     field; /health
     renders by precedence TerminalUnreadable > RestartRecoveryOwed
     > ConfirmDebt (generic removal/rewrite/slot-delete message +
     mask detail, REPLACED by the key-class variant naming ORIGINAL
     `.configdb/master.key` restoration when the rendered level's
     cause bit is set)
     > WriteUnverified > ActivePersist; the gauge
     consumes the derived aggregate OR (never healthy-while-gauge-1); the
     Config → NewServer plumbing test pins both callbacks wired;
     (x22) D-SUPPRESSION LEGS (r27 Codex m1 + r29 Codex m3): (x22a)
     ARM-BARRIER CLEARANCE — seed a D-kind slot debt, land a FULLY
     DURABLE arm on the slot (no W debt), assert D is CLEARED by the
     arm's own supersession (riding the arm's dir-fsync DURABILITY
     barrier — gate-independent, not a D action; a FAILED barrier
     leaves D standing, suppressed by the resulting W debt); AND
     the deferred-barrier leg (r30 Codex m2): a post-rename arm
     failure then a SUCCESSFUL (w-a) durability completion clears
     D WITH W; (x22b) SYNCAPPLY-PRE-RENAME (r27 Codex
     M3): D inert while `persistDegraded` stands (C's record
     survives per #5473), D's fresh re-read proceeds once the
     replacement lands; the `armedArmID != ""` conjunct is
     DEFENSE-IN-DEPTH (arm-supersession is the primary mechanism),
     with a test-seam leg seeding D beside a live window and
     asserting no D action until the window resolves;
     (x23) ACTIVE-GATE MATRIX (r27 Codex M1 +
     r28 Codex M1's inventory completion + r29 Codex m2's (w-u)
     leg): (g-ok)/(g-absent)/
     (g-err) × (W (w-a) rewrite, W (w-b)/(w-c) restore, W (w-u)
     unreadable-slot restore-over, R (a)
     tombstone+delete, R (c) mismatch rewrite, D tombstone, D
     delete, confirm-side clear, sanctioned both-files-removed
     barrier) at BOTH placements, asserting (g-absent) PROCEEDS
     only for the barrier and (g-err) withholds + retains with NO
     terminalization (EACCES and corrupt-active legs);
     (x24) KEY-CLASS CLASSIFICATION BOUNDARIES (r27 Codex M4 + r28
     Codex m1/m2 + r30 Codex m1's re-read outcome taxonomy): auth
     failure → key-class; invalid observed
     length → key-class; missing key file / EACCES → NOT key-class
     (READ-side TRANSIENT); unsupported PRF / too-new envelope /
     bad nonce ENCODING or length → NOT key-class (NON-key-class
     permanent — the failures precede AEAD, `crypto.go:328-353`),
     while a well-formed TAMPERED nonce reaches `gcm.Open` and is
     key-class by authentication indistinguishability
     (`crypto.go:354-356`); the CLEAR-TIME re-read taxonomy (r30
     Codex m1): byte-MISMATCH → RETAIN + keyClass set EXPLICITLY
     (restoration-required); invalid-length → restoration-required
     (via `ErrMasterKeyLength`); EACCES / ENOENT / mount-IO →
     RETAIN + journal the exact error with the
     key-state-UNVERIFIABLE message (generic text, NO restoration
     claim); a legitimate same-content rewrite passes; the COMBINED
     plaintext-active /
     K-encrypted-confirm scenario under a swapped-but-valid K′
     asserts ZERO write/delete (the read-side key-class rule
     retains; the no-create primitive is never reached); and the
     NO-CREATE pin: an encrypted repair write with the key file
     missing FAILS with NO key created (the file stays absent),
     one snapshot feeds gate+write, a plaintext repair write
     performs no key access, and EVERY non-arm `WriteConfirm`
     producer ((w-a), (w-b)/(w-c), (w-u), R (a), R (c), D
     tombstone) is
     covered; (x25) WRITE-UNVERIFIED STATE MACHINE (r30 Codex M1 +
     r31 Codex M1/M2/m1): ENTER legs — a key-class-observed
     failure (auth/invalid-length), a key-path probe failure
     (ENOENT/EACCES/mount-IO), a byte-mismatch — EACH blocks every
     encrypted config-DB write (the active-persist heal withholds,
     every repair write withholds, new arms/commits refused) while
     plaintext writes proceed; the SPLIT-KEY leg — wrong-but-valid
     K″ installed while R_A + persistDegraded stand under K → the
     active heal NEVER re-encrypts (the state HOLDS through the
     UNVERIFIABLE classification — it is exited ONLY by POSITIVE
     validation, never by a non-key outcome), the files never
     diverge; the RESTORATION leg — K restored → the same pass's
     key-path read + confirm re-read decrypt-validate under K
     (POSITIVE validation, single snapshot) → the state EXITS →
     R_A's tombstone→delete proceeds same-snapshot (NO circularity
     — the healing write is gated by the state the validation just
     exited, not by the debt's own bit); the EARLY-REFUSAL leg —
     a commit attempted while write-unverified is refused BEFORE
     any write, including the plaintext-candidate/ENCRYPTED-
     PrevTree case (the confirm record's encryption keys off the
     PREV tree's leaf, so the candidate's plaintext shape does not
     exempt it); the pass-N/pass-N+1 transition leg — after the
     state exits on pass N's confirm-side actions, pass N+1's
     active write proceeds under K (one pass of lag, no torn
     state); the SECOND-SWAP leg (r32 Codex M2) — K restored and
     the state exited on pass N, then the operator swaps to K″
     before pass N+1's active write → the write's FRESH
     same-snapshot BOTH-SIDES validation at action time fails (the
     K-era confirm generation does not validate under K″) → the
     write withholds and the state RE-ENTERS — a plaintext active
     side does NOT exempt the write while a confirm-side encrypted
     generation exists; the CONFIRMED-EMPTY exit leg (r32 Codex
     M1b) — after the sanctioned removal of the FINAL unreadable
     record (or on a never-encrypted DB), NO ciphertext remains to
     decrypt-validate: the state EXITS via the confirmed-empty
     transition with the removal's data-loss warning surfaced —
     and the irrecoverable-generation path (r32 SMR m1) exits
     through the BOTH-FILES removal → (g-absent) → the
     absent/plaintext posture → this exit; the OWN-TARGET
     EXEMPTION leg (r33 Codex M1) — a content-INDEPENDENT repair
     ((w-u) restore-over, D synthesized tombstone) runs while its
     NON-KEY-CLASS-PERMANENT unreadable target can never validate:
     only the OPPOSITE side must validate, and the state does NOT
     re-enter on the own-target's permanent unparseability; the
     CONFIRMED-EMPTY proof/priority leg (r33 Codex M2) — ONE fresh
     under-`s.mu` classification of BOTH files using ONE key byte
     snapshot (the envelope-detected bit surfaced at both call
     sites) proves all-plaintext/all-absent and exits
     AUTHORITATIVE BEFORE the key-probe HOLD; the exported-`Save()`
     leg (r33 Codex m1) — `Save()` takes `s.mu.Lock()` (not
     RLock), so the write-unverified transition and the loop
     start/retain are synchronized; the SyncApply-admission leg
     (r33 Codex m2) — SyncApply PROMOTES in-memory per its #1799
     Option-B contract while its encrypted persistence attempt is
     WITHHELD under the state and raises the active-persist debt;
     the state-only second-swap leg (r34 Codex M2) — `Save()`
     ENTERS the state with NO persistence debt, a pass validates
     both files, the key path is swapped to K′ before the exit:
     the exit's OWN final key-path re-read and EXACT-BYTES compare
     against the validation snapshot catches it (mismatch →
     RETAIN with the byte-mismatch classification, the loop keeps
     probing; health never goes green on an unvalidated key);
     the operator-race remediation leg (r34 Codex M1 + r35 Codex
     M1/m1 + r36 Codex M1) — REMOVAL
     is safe LIVE (the probe's confirmed-absence barrier is
     idempotent), repair-to-valid FILESYSTEM remediation requires
     xpfd STOPPED with the MANDATORY `mask == 0` precondition
     EXPLICIT and FENCED (the r36-r42 producer-quiesce protocol:
     (1) no live commit-confirmed window stands, (1a) automation
     is quiesced — if any `event-options` policy is configured,
     `deactivate event-options` and commit FIRST ON BOTH NODES,
     each commit required to SUCCEED (an operator commit syncs
     only from the RG0 authority and is suppressed when
     ConfigSync is disabled, `daemon_apply_commit.go:578-601`,
     `daemon_ha_sync.go:336-370`; a promoted secondary is
     writable, `daemon_ha.go:438-450`; a promotion can persist
     before an apply aborts ahead of tail step 17 leaving the
     durable tree deactivated while the live engine retains its
     policies, `daemon_apply.go:282-309,404-409`,
     `daemon_apply_tail.go:194-202` — so effectiveness is
     verified per node via the commit's own result, the tail
     abort surfacing as the #5679 deferred error,
     `daemon_apply_dataplane.go:145-159` — r48 Codex M4) (the event
     engine is the only autonomous local commit source,
     `engine.go:920-948` via `daemon_apply_tail.go:446-455`
     without peer sync, invisible to the counter/epoch; shutdown
     does not fence it, `daemon_run_shutdown.go:25-59`,
     `engine.go:354-367,583-595` — r47 Codex M4), (1b) ONLY
     THEN capture the intended-config digest + text (capturing
     before the window resolution leaves the pair stale across
     a rollback — `store_commit.go:427-461,503-524`,
     `store_persist.go:21-55` — r47 Codex M3 = r47 SMR m2; any
     commit that lands anyway forces a re-capture OF WHICHEVER
     BASELINE IT INVALIDATES — the pre-quiesce digest OR the
     fence-time pair, r49 Codex m2 + r49 SMR m1), (2) refrain
     from commits and FENCE the async producer ENFORCEABLY with
     the peer-side preflight — PEER full-state clean (peer
     `ConfirmDebtKindMask == 0` AND peer `persistDegraded ==
     false` — read via the peer's own `/health` endpoint per
     r41 Codex M3 — AND peer `ConfigSyncOutstanding == 0` — read
     via the peer's cluster-status RPC, which carries the
     counter per the §5.1 `pkg/cluster` entry, r42 Codex m1; an
     unclean peer makes the stopped path UNAVAILABLE
     — use live removal), then STOP THE PEER xpfd (the universal
     fence over every transport — `down em0` is NOT universal:
     sync falls back to fabric over possibly two paths,
     `daemon_ha_sync.go:774-785,820-860`) — and DRAIN THE LOCAL
     OUTSTANDING COUNTER: witness INGRESS QUIESCENCE FIRST — the
     TERMINAL EXIT of every REGISTERED ingress reader (r45
     Codex m1: pre-install, superseded, and post-cap readers
     are the counter's domain, not this surface's) (EOF,
     heartbeat-timeout, bad-magic, oversized/partial payload,
     auth-trailer failure, cancellation, read errors — dispatch
     happens only after complete verification,
     `sync_conn_read.go:22-93`, r43 Codex m2), observed on the
     existing sync-peer connection-state surface
     (`IsSyncConnected`, `sync_state.go:66-74`,
     `status.go:263-267`), then wait the
     `ConfigSyncOutstanding` atomic — gap-free over DISPATCHED
     frames (the verified-undispatched residual is the
     composition's domain, r45 Codex m1) — to ZERO (node-
     lifetime ownership; total retirement with the publication
     order pinned: the increment is an ownership reservation
     taken BEFORE the enqueue attempt with rollback on the
     nil/full dispositions, the decrement is dequeue-scoped per
     item, teardown retires the still-buffered; the reservation
     lives in the dispatch path so pre-install, superseded, and
     post-cap readers — and unkeyed third-party ingress — are
     all counted; a queue-length +
     gen-fence pair has three false-idle windows: dequeue
     precedes flag publication, gen-0 applies are invisible,
     `resetRecvGen` clears mid-apply),
     (3) RE-CHECK THE FULL STATE —
     `ConfirmDebtKindMask == 0` AND `persistDegraded == false`
     AND `ConfigSyncOutstanding == 0` AND the NODE-LIFETIME
     MONOTONIC dispatch epoch (advanced WITH the provisional
     pre-enqueue reservation, NEVER rolled back — nil/full
     attempts are conservative epoch false-positives, r48 Codex
     M1 — preserved across SessionSync replacements,
     exposed beside the counter — r46 Codex M1: the
     provider-scoped candidates reset or ABA,
     `sync_conn_gen.go:340-367`, `sync_state.go:47-63`,
     `daemon_apply_tail.go:238-255`) UNCHANGED since the
     (2c) observation — with the RE-BASELINE-and-repeat rule
     AND its TERMINATION CLAUSE (a still-advancing epoch after
     the second re-baseline means a live ingress source —
     unkeyed third-party or stale process,
     `sync_admission.go:58-83`, `sync_auth.go:321-334` — and the
     stopped remediation is UNAVAILABLE while pulses continue;
     fence the source or use live removal — r48 Codex m2 +
     r49 Codex m1) (r45 Codex M2 — the level counter alone
     misses a dispatch that lands, applies cleanly, and retires
     between (2c) and (3); the monotonic epoch cannot)
     (a queued apply can leave `ActivePersistDegraded` with the
     old record as the sole crash-recovery intent — a mask-only
     check reads it clean; a merely-enqueued or applySem-blocked
     apply has not raised debt yet, which only the counter
     sees), (4) stop and repair — a debt raised mid-wait
     shows at the re-check; the blind-spot residuals are admitted
     and bounded: a mid-fence window deadline (the r29
     provenance loss) SPLIT by deadline at restart — still-
     pending → CONFIRM AWAY with a BARE `commit` (cancels the
     timer; NEVER `commit check` — it only validates; NEVER
     manual removal — it does not cancel the in-memory timer);
     already-expired → `Load` already reverted, so STAGE the
     intended config and commit it — a BARE `commit` probe is
     FORBIDDEN (it ordinary-promotes the reverted, possibly
     EMPTY, candidate and SUPPRESSES the later `xpf.conf`
     import, `bootstrap.go:65-79,237-247`); the
     FirstCommit+cluster class reverts
     INSIDE `Load` and recovers via the preflight's own named
     path (restart xpfd INTO the clustered configuration / the
     `xpf.conf` boot import — a live CLUSTERED commit is
     rejected with no runtime), and a post-barrier SyncApply
     D-abandonment whose offline repair is REMOVAL with the
     directory fsync (`rm` then `sync -f` on `.configdb/` — a
     bare unlink can replay the stale record after power loss,
     `db.go:284-315`; a DEAD record repaired pending-shaped can
     BIND and replay the resolved window, and the `Resolved:
     true` synthesized shape is the machinery's own, never
     hand-authored), and the r42/r43 residual (iii): a push
     whose APPLY lands between the peer preflight's FIRST
     sub-read and the peer
     stop — REGARDLESS of when the frame was received (a
     complete frame paused pre-dispatch or held as the
     handshake's `pendingFrame` can be received before the
     preflight yet dispatch after it,
     `sync_conn_read.go:84-93`, `sync_auth.go:352-369` — r45
     Codex M3; and the preflight's split /health +
     cluster-status reads are not one coherent snapshot — a
     promote+fail-persist+retire can slip between them,
     `store.go:687-746` — so the window runs from the FIRST
     sub-read, r47 Codex m1 + r48 Codex m1) — (or
     on the LOCAL node between the re-check and the local stop,
     from any ingress source including a stale peer process or,
     in unkeyed deployments, a third party) can promote and
     FAIL its active write — the abandoned degradation splits
     on failure class (PRE-rename: prior persisted active
     intact, promote lost; POST-rename: new content VISIBLE,
     durability unproven, not reconstructed at restart), and
     convergence is AUTHORITY-CONDITIONAL (the re-drive skips
     until peer-connected + RG0-authority + 30s-stable,
     `daemon_ha_sync.go:447-465`; the stale peer can preempt,
     `cluster/election.go:172-193`; and the DISABLED-SYNC
     subclass does not self-heal — `ConfigSync` defaults false,
     `compiler_system.go:1872-1874`, `types_chassis.go:113`; a
     preempting peer whose older config has ConfigSync=false
     leaves NEITHER side pushing, `daemon_ha_sync.go:461-465` —
     detected by the intended-config comparison and closed by
     the pinned MANUAL re-convergence — and when the intended
     holder is the read-only secondary with an encrypted
     (non-portable) artifact, the choreography is pinned:
     restart the INTENDED-CONFIG HOLDER FIRST (its `Load`
     classification completes before cluster comms,
     `daemon_run.go:157-177,393-398`), start the peer, LET THE
     ELECTION SETTLE, and re-converge THROUGH THE RESULTING
     AUTHORITY (restart order does not hold authority — a
     higher-priority peer preempts after joining,
     `election.go:172-193`; with sync enabled the reconciliation
     is authority-gated and stability-delayed,
     `daemon_ha_sync.go:447-465`; with sync disabled no config
     flows and the re-convergence is per-node,
     `daemon_ha_sync.go:336-370,461-465`) — read the
     post-election RG0 state, `load override` + `commit` the
     intended text on whichever node holds authority — with the
     FINAL VERIFICATION running TWICE bracketing ONE FULL
     reconcile interval (`periodic = 30s`,
     `configSyncReconcileLoop`): the ConfigsSent tick is NOT a
     faithful witness (a marker no-op pass returns before
     QueueConfig and never ticks, `daemon_ha_sync.go:478-485`,
     `sync_conn_config.go:234-250`; and a pass paused after
     claiming can survive a reconnect's epoch bump and resume
     later with a newer wire generation,
     `daemon_ha_sync.go:51-57,474-489`,
     `sync_conn_config.go:222-243,254-272,325-395`, the claimed
     marker suppressing repair, `daemon_ha_sync.go:479-484`) —
     the operator re-reads BOTH nodes' digests after the
     re-convergence and again after one full interval,
     re-driving the intended text on ANY flip (the operator's
     commit push carries the newest wire generation); a
     still-flipping state after two intervals is a stuck-lock
     incident — fail-closed (r51 Codex M4 + r51 AGY M1); AND
     the reconciler itself gains the SEND-BOUNDARY PROTOCOL
     (r54 Codex M1/M2/M3/m1 + r56 Codex M7's contract-sync):
     under `configSyncMu`
     HELD FROM VALIDATION THROUGH SEND-COMPLETION with EVERY
     push path taking the same mutex (ONE locked-send owner;
     the marker helper is lock-ASSUMING,
     `daemon_ha_sync.go:355-377,407-414`), the reconciler at the
     boundary (i) revalidates authority + connection
     epoch/liveness + ConfigSync-enabled AND PROVIDER IDENTITY
     (the captured `ss` re-validated as the current provider),
     (ii) recomputes
     `configGenerationHash(ShowActive())` and drops with an
     alarm on a mismatch, and (iii) claims the marker ONLY at
     the send boundary on send-SUCCESS (`QueueConfig` gains a
     success return), with the claim carrying the AUTHORITY
     GENERATION (invalidated on any demotion/re-promotion,
     `daemon_ha.go:438-475`);
     a per-node commit on a read-only secondary is executed by
     PROMOTING it first with the existing manual-failover
     request (promotion clears the read-only gate,
     `daemon_ha.go:438-475`; `store.go:346-353`,
     `store_lock.go:9-27`), then restoring the intended
     mastership; and the terminal corner is NAMED (encrypted
     origin-pinned artifact + no operator text + cross-node
     need): RUNBOOK-UNRECOVERABLE, fail-closed, rebuild from
     config management (r50 Codex M4) — and let
     the normal sync carry it; the intended-holder-first /
     local-first precedence is explicit (the holder governs;
     the plain case IS local-first; each node's Load completes
     before its own comms regardless) — r48 Codex M5 + r49
     Codex M3 + r49 AGY M1) — bounded by the repair
     step's successful directory `sync` of the configdb PARENT
     directory on EVERY AFFECTED NODE — BOTH nodes; the
     post-rename failure can belong to the peer's filesystem,
     `fsatomic.go:354-366` — before either restart, and the
     POST-RESTART VERIFICATION step (both nodes hold the same
     intended config — compared against the OPERATOR'S intended
     config captured BEFORE the fence as BOTH the OFF-NODE
     canonical digest (from the cluster-status surface —
     redaction-free, no cleartext needed) AND the intended
     config's TEXT — the OPERATOR'S OWN committed configuration
     (aside from the quiesce's own operator-visible
     deactivate/re-activate pair, reverted at the end — r48
     Codex M3), with the in-box
     fallback being the on-disk `.configdb/active.json` — an
     opaque config-DB artifact (a magic-header framing line + a
     possibly-encrypted JSON body, `envelope.go:78-99`,
     `db.go:445-450`; preserved byte-for-byte, r47 Codex m2) —
     copied off-node by the root-held operator as a byte-exact
     STOPPED-DAEMON RESTORE artifact (NOT
     Junos text — it cannot feed `load override` directly,
     `store_command.go:306-309` — and when the config carries a
     master password the body is keyed by the SOURCE node's
     independently-random master.key, `crypto.go:262-285,457-480`,
     which a DIFFERENT authority cannot AEAD-open,
     `crypto.go:307-356,443-455` — so the file-level restore is
     pinned to the ORIGIN NODE in the encrypted case and
     portable only when cleartext, r47 Codex M5) —
     no CLI/gRPC capture surface exists or is
     needed (r46 Codex M3: every rendered surface is redacted,
     `grpcapi/server_config.go:347-380`, `api/config.go:304-352`,
     `cmd/cli/show.go:81-120`, and the embedded-TTY cleartext
     show is not instantiated in service mode,
     `daemon_run.go:601-616`), since
     the show/export surfaces redact secrets,
     `grpcapi/server_config.go:347-356`, `api/config.go:304-312`;
     not merely cross-node agreement, which a
     preempting peer's older pushed config would falsely
     satisfy — AND the FULL derived persist-health state
     `ConfigPersistDegraded() == false` on BOTH nodes — the
     aggregate over ActivePersistDegraded, the mask,
     ConfirmRecordState, and ConfigWriteUnverified, since a
     restart-time push can promote+apply while its disk write
     fails, `store.go:687-689,738-769`,
     `store_persist.go:342-352` — AND `ActiveApplied() == true`
     on BOTH nodes (a promote-then-nonfatal-apply-failure
     leaves ActiveApplied false while every persistence field
     and both digests pass, `store.go:797-809`,
     `daemon_apply_commit.go:464-494`; the config-apply health
     alarm is delayed and diagnostic-only,
     `sync_conn_config.go:369-379` — r45 Codex M4; the digest's
     text-scoped semantics leave ONE hole — the r46 rebuttal
     WITHDRAWN per r47 Codex M2's verified counterexample: a
     failed same-text reapply with state-dependent enforcement
     (the DHCP host-inbound build, `daemon_dhcp.go:231-245`;
     nft failure retains the prior kernel generation,
     `daemon_nft.go:262-272`) keeps ActiveApplied true while
     the new address lacks enforcement — so the predicate ALSO
     requires NO dataplane apply failure since the post-restart
     bringup on either node — i.e. failure-count == 0 AND no
     pending arm outstanding (the per-arm-ID registration set
     for the current token) AND
     last-outcome-success read from ONE coherent snapshot (r50
     Codex m1 + M1 — the mid-render entry race is closed by the
     single-snapshot publication, and the truth assignment is
     at the CONVERGENCE point: the deferred-MAC retry-debt
     outcome and the nil-dp boot skip both record NOT-converged,
     `daemon_apply_dataplane.go:390-402,466-489,137-163`,
     `manager_worker_arm_5134.go:10-21`,
     `daemon_run_bringup.go:493-520`) — a PROCESS-LIFETIME failure
     counter + last-outcome flag initialized BEFORE the boot
     apply and instrumented centrally at every full-apply entry
     (the existing surfaces do not carry it: compile health is
     compile-specific, `daemon.go:871-880`,
     `daemon_health.go:79-125`; `ConfigsApplyFailed` is
     SessionSync-only, `sync.go:110-119`; the DHCP/boot/feeds
     applies run separate wrappers, `daemon_apply.go:49-86` —
     r48 Codex M2), rendered beside ActiveApplied) —
     EXPOSED beside the counter/epoch/digest on the
     cluster-status rendering (r46 Codex M2a) — AND
     `IsConfirmPending() == false` AND `IsDirty() == false` (or
     the candidate explicitly discarded) on BOTH nodes (r46
     Codex M2b — `store_commit.go:796-800`,
     `store_lock.go:334-338`, `store_command.go:304-334`) —
     AND the MULTI-TERM ACTUATED authority predicate
     (r61 Codex M1's acceptance alignment): exactly one node
     with RG0 rg_active, exactly one VRRP MASTER where a
     VRRP-backed RG applies, BOTH on the intended node, and
     the loser EXPLICITLY INACTIVE — read PER-NODE on each
     node's OWN status surface (RG0 normally has no VRRP
     instance, `vrrp/manager.go:929-936`; a failed SetRGActive
     can leave the loser ACTIVE+BACKUP while the winner is
     ACTIVE+MASTER, `rg_state.go:250-263`,
     `daemon_ha.go:340-371,809-848`) —
     before the repair is declared
     done; and the residual enumeration includes the r58
     hybrid residuals (iv)-(v) per the normative fence
     section — residual (vi) was WITHDRAWN in v60 (the
     re-registration is total), r60 Codex m3's alignment — and ONLY THEN the operator RE-ACTIVATES
     `event-options` — ON BOTH NODES, each commit's own success
     required, EXACTLY mirroring the quiesce (r49 Codex M2:
     with ConfigSync=false one commit cannot update the peer,
     `daemon_ha_sync.go:336-364`; the Store promotes before
     apply, `daemon_apply_commit.go:225-246`, so a reactivation
     apply can abort before the engine's reconciliation,
     `daemon_apply_tail.go:194-202`) —
     and re-verifies the COMPLETE predicate again (not merely
     digest equality — r50 AGY m1 / r50 Codex fold-2: the
     pre-quiesce digest match AND the full persist-health
     aggregate AND ActiveApplied AND the apply-failure/
     last-outcome terms AND the no-pending-outstanding term
     (r59 Codex m2) AND the authority check on BOTH nodes) against
     the PRE-QUIESCE digest captured before (1a) — the
     two-digest discipline: post-restart verification against
     the fence-time digest, re-activation verification against
     the pre-procedure digest),
     and every
     content-INDEPENDENT repair write
     RE-VERIFIES the target's classification inside the SAME
     `s.mu` hold immediately before the rename via the PINNED
     `WriteFileDurableStaged` pre-rename hook (the hook UNLINKS
     the temp on a classification change per the
     `fsatomic.go:41-44` discipline; a test seam drives the
     failure path — defense-in-depth; the stopped
     requirement is the authoritative closure);
     the JOIN-COHERENCE leg (r41 Codex m1 + SMR m1 + r42 Codex
     m2 + r43 Codex fold-5) — the `ConfigSyncOutstanding`
     counter is read LIVE and
     coherent, with NAMED sub-legs: (a) the framed-blocking-apply
     regression (frame dequeued, apply blocked on `applySem` via
     the test seam) asserts the counter NEVER reads zero until
     the apply returns — the dequeue-before-flag-publication
     window; (b) a LEGACY GEN-0 payload leg — a gen==0 frame is
     counted at receipt and retired after its apply returns,
     closing the gen-0-invisible window
     (`sync_conn_config.go:289-309`); (c) a CONCURRENT
     `resetRecvGen` leg — a bulk-start reset mid-apply
     (`sync_conn_read.go:183-195`, `sync_conn_gen.go:340-362`)
     leaves the counter untouched; (d) a PROVIDER-REPLACEMENT
     leg — a transport-changing apply (`daemon_apply_tail.go:
     238-255`) swaps the `SessionSync` mid-callback and the
     NODE-LIFETIME counter still reports the in-flight token
     until the old apply returns; (e) a RETIREMENT-TOTALITY leg —
     EVERY no-apply and non-registered-reader path leaves the
     counter balanced: the nil-channel guard and queue-full
     drop (reservation rolled back,
     `sync_conn_read.go:318-331`), the stale-generation skip and
     nil-handler skip (dequeue-scoped defer,
     `sync_conn_config.go:331-341`), callback FAILURE and PANIC
     unwind (the same defer), a partial-frame reader exit (no
     dispatch, no token, `sync_conn_read.go:28-93`), the
     pre-install pending-frame dispatch (`sync_conn.go:122-127`)
     and the superseded-reader dispatch
     (`sync_conn.go:244-267,480-498`) — both reserve and retire
     through the same counted path — and
     teardown-with-buffered-items; (f) the PUBLICATION-ORDER leg
     (r43 Codex M1) — a test seam after the channel send
     completes but before the producer's continuation asserts
     the reservation is ALREADY visible (the consumer can
     dequeue at the seam; the counter never reads a false
     zero — and the EPOCH'S advance is
     visible at the same seam, r47 Codex M1); (g) the
     ENQUEUE-AFTER-TEARDOWN leg, rewritten as TWO
     legs (r46 Codex m1 — freezing the reader INSIDE the
     critical section while Stop publishes+drains is impossible
     under the same exclusion; the exclusion prevents that
     interleaving by construction, so the legs test the two
     orderings instead): (g1) READER-WINS — the reader
     completes the serialized check+reserve+enqueue FIRST;
     Stop blocks on the exclusion, then publishes dead and
     drains; the drain retires the token; the counter ends at
     zero; (g2) STOP-WINS — Stop publishes dead and drains
     first; the reader then enters the section, observes dead,
     and takes the DROP path — no reservation, the counter
     stays at zero;
     (h2) the STICKY-APPLY-HEALTH legs (r48 Codex M2 + r49 Codex
     M1): (h2a) the STICKY-FAILURE regression — a failed
     same-text state-dependent reapply (the DHCP host-inbound
     build, `daemon_dhcp.go:231-245`, with the nft failure
     seam, `daemon_nft.go:262-272`) keeps ActiveApplied true
     while `applyFailureCount` moves and `lastApplyOK` reads
     false — the done predicate catches what the digest cannot;
     (h2b) the PARKED-MID-APPLY regression — an apply parked
     past the predicate's read (via the test seam) reads
     `lastApplyOK == false` from ENTRY until its nil return, so
     the predicate can never read green in flight;
     (h2c) the SNAPSHOT-CONTRACT legs (r51 Codex M1/M2/m1): the
     STALE-SNAPSHOT-RETURN leg (a renderer loads the pre-entry
     snapshot, is descheduled through a failed DHCP/feed apply,
     and resumes — the seqlock version re-read forces the
     retry, never returning the captured green), the
     MID-RENDER-ENTRY leg (an apply entering BETWEEN component
     reads is caught by the version change), and the
     single-owner publication order regression (every promotion
     and every stamp publishes the same versioned snapshot);
     (h2d) the PENDING-XSK REJECTION leg (r51 Codex M3/m1 +
     r53 Codex M4): a deferred-publication rejection is PENDING
     — lastOK=false, the count UNMOVED — while its retry
     budget lasts, and the predicate cannot bless until the
     publication completes (only budget exhaustion or an apply
     pipeline failure moves the count);
     (h2e) the OUTBOUND-CLAIMANT legs (r51 Codex M4/m1): the
     paused-claimant / reconnect / commit / release ordering
     (a pass paused after its marker claim survives a reconnect
     epoch bump and resumes with a newer wire generation — the
     interval-bracketed double digest check catches the flip
     and the re-drive overwrites it) and the MARKER-NO-OP
     REJECTION leg (a no-op pass never ticks ConfigsSent, so no
     runbook step may wait on a tick);
     (h2k) the HYBRID-CLOSURE legs (r58 Codex m1): the
     ROLLBACK-FORK legs (every rollback branch publishes its
     NEUTRAL/SUCCESS/FAILURE outcome — a failed rollback's
     session-clear failure never reads green) and the
     STALE-CALLBACK legs (a stale OnXSKBound closure takes
     applySem, re-derives from the current config, and
     abandons on mismatch AND on the FULL fence — `runCtx.Err()`
     OR `stopping`, including the early signal-driven window —
     with the teardown JOIN (a teardown beginning between the
     guard and a mutation is covered by the shutdown's join
     set), and a fire-time operation-by-operation aggregated
     failure (parent-up, creation, address reconciliation,
     MTU/up, and the type+mode mismatch) retires the arm
     FAILED — r60 Codex m2's leg completion);
     (h2j) the v56-MECHANISM legs (r56 Codex M8): the OLD/NEW
     OnXSKBound CALLBACK INTERLEAVE (the manager's atomic
     install/register/already-bound operation can neither
     strand the new registration nor lose an early
     completion), the PrepareLinkCycle registration leg, the
     COMPLETION-VS-NEXT-MINT TRANSACTION leg (a debt completing
     between the manager snapshot and the daemon registration
     cannot strand a new-token registration), the SLOW-POLL
     MINT leg (the mint's debt query never blocks behind
     control-socket IPC — the debt ledger is short-held, r56
     Codex M6 + r56 AGY M1), the RETURNED DETACH-FAILURE leg
     (a stale XDP/TC detach failure fails the pipeline
     terminally, with `errors.Join` collecting EVERY attempted
     detach — never returning on the first error and skipping
     the rest, r56 Codex m3), and the AUTHORITY leg EXTENDED
     through re-promotion + marker-state + retry assertions;
     (h2i) the SEND-BOUNDARY legs (r55 Codex m2): the
     MISMATCH-DROP-WITHOUT-CLAIM leg (a stale capture drops at
     the boundary and the marker stays unclaimed, so a later
     pass for the same generation still pushes), the
     COMMIT/RECONCILER SERIALIZATION leg (a commit push and a
     reconciler send serialize under `configSyncMu` held
     through the send), the PROVIDER-REPLACEMENT leg (a
     transport-changing apply mid-claim is caught by the
     provider-identity revalidation), the DUAL-FABRIC
     SEND-FAILURE leg (a fabric-0 failure with fabric-1
     surviving leaves the marker unpublished and the retry
     unsuppressed), the CONTENTION leg (r56 Codex m1: a blocked
     write holds `configSyncMu` across the untimed `writeMu`
     wait PLUS the 2s `syncWriteDeadline`, `sync.go:88`,
     `sync_protocol.go:59-74`, while a commit push waits —
     asserted bounded), and the AUTHORITY-TURNOVER leg (a demotion
     mid-claim invalidates the authority generation and the
     claim);
     (h2f) the COMPOSITE-READER leg (r52 Codex M1): the #4957
     shortcut's (text, applied) pair is read from ONE versioned
     snapshot — an A→B promotion/apply between the two reads
     can no longer combine text A with ActiveApplied(B) —
     exercised with the high-water advance assertion
     (`sync_conn_config.go:319-324,390-395`);
     (h2l) the HA-CLEAR-DEBT legs (r61 Codex m2): the
     `pendingHAStateClear` debt's registration, supersession,
     alias completion, and ledger serialization (the existing
     tests cover only the boolean debt/retry behavior,
     `hastate_clear_debt_5487_test.go:15-112`,
     `manager_ha_clear_debt_5873_test.go:32-112`);
     (h2g) the ATTEMPT-TOKEN legs (r52 Codex M2/M3): an OLD
     arm's completion arriving during a NEWER apply cannot
     stamp converged (the token mismatch), exercised across the
     deferred-MAC, pending-XSK-publication, XSK-liveness-probe,
     and link-cycle-rebind arms; and the PENDING/FAILED
     distinction leg (r52 Codex m1): a pending arm holds the
     predicate without moving the failure count, a terminal
     failure moves it, and a success-after-rejection
     rehabilitates;
     (h) the PULSE-BETWEEN-READS leg (r45 Codex M2 + r46 Codex
     M1) — a
     dispatch that lands, applies CLEANLY, and retires between
     the (2c) observation and the (3) re-check returns the
     level counter to zero but MOVES the pinned NODE-LIFETIME
     monotonic dispatch epoch (advanced WITH the provisional
     reservation and NEVER rolled back — the leg ALSO asserts a
     nil/full attempt advances the epoch permanently without
     moving the counter, r48 Codex M1; preserved across
     SessionSync replacements):
     the
     regression asserts the epoch comparison at (3) catches the
     pulse the level cannot — including across a
     transport-changing apply's provider swap
     (`daemon_apply_tail.go:238-255`);
     the OBSERVABILITY leg
     (r32 Codex M1b) — `ConfigWriteUnverified` renders in /health
     and folds into the aggregate OR, and the retry loop ACTIVELY
     probes the key path every pass while the state holds (a
     restored key is detected within one backoff);
     and the FRESH-BOX leg — a never-committed box never
     enters the state (the #1894 first-encrypted-write auto-create
     still works).
3. Update `daemon_natpoolalarm_race_test.go` (`writeDPFor` →
   `setDataplane`) and `daemon_forwarding_status_test.go` (rewrite against
   the narrowed adapter: `ProjectsMapStats`/`UsesUserspaceStatusAdapter`
   move to asserting `CachedStatus` per-call probing;
   `UsesCurrentDataplaneAfterSwap` maps onto the narrowed shape with
   `setDataplane` swaps). **[CORE]**
4. Scoped race gate: new `test-race-dp` make target —
   `go test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit' -count=2`
   — invoked from `test-go` (r1/r2: plain `go test ./...` has no race
   teeth; full-repo `-race` stays out of scope). **[CORE]**
5. Canary tests: redesigned matcher self-tests both directions; new
   `daemon_dp_canary_test.go` asserts no direct `dpCell` access outside the
   accessors. **[CORE]**
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

- **The G+H+H2 follow-up unit (§4.7 delivery structure)**: work item G
  (startup-readiness gate), work item H (FirstCommit+cluster recovery
  invariant), and work item H2 (confirm-record durability machinery)
  ship in the named follow-up issue, NOT the #2114 PR — per the r28
  2-of-3 split ruling and Codex's ordering constraint (G-without-H
  would extend the pre-manager timer window into the post-manager
  bootstrap-with-live-cluster hybrid). Their designs remain in this
  document as the follow-up's research seed.
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
  in the G+H+H2 follow-up unit (§4.7) and prevents the
  bootstrap-with-cluster state from persisting
  past the next boot; the lifecycle redesign is a pre-existing policy
  question, not a `d.dp` publication concern.

## 11. Open questions for adversarial review (r40)

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
commit — *in the FOLLOW-UP unit per §4.7 (the "same PR/stack (OQ6)"
framing predates the r28 split ruling)*; work item H REDESIGNED in v9 as a
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
an immediate revert-at-load — the only sound split moves H WITH H2);
r20 additions: the W-kind debt re-keys to the LIVE window at every
arm outcome (a nested arm supersedes — the dead window's W never
heals; the arm retains the immutable attempted record `s.armedRecord`
and the restore is VERBATIM), the SUPERSEDED-WHILE-UNREADABLE marker
replaced by EAGER durable deletion at the replacement's landing
(plain commit/SyncApply with the BOOT latch standing delete the
unreadable record + dir-fsync barrier; confirmed commit overwrites or
deletes on PRE-rename failure — closing the marker-loss /
restart-before-repair / content-match replay chain that Codex M2 and
SMR M1 walked independently, and the marker-scoping hazards of Codex
M3), the health snapshot's enum + debt-kind mask
(`ConfirmRecordState`: OK / TerminalUnreadable / RestartRecoveryOwed)
with the four-level precedence, and the stale-expectation repairs
(x9 substate-keyed remediation, x11 class split, THREE schema
fields); r21 additions: dominance SCOPED (D1 identity-preserving
writes vs D2 live-window restore-as-supersession — the restore runs
FIRST and the pending removal clears on the restore's barrier,
closing the recordless-live-window gap Codex proved against the v21
restore-last reading), the eager supersession as a TWO-STEP
synthesized tombstone + delete with the D-kind slot debt (full-field
`Resolved:true` synthetic record passing #5637 and dropping at the
Resolved-first recovery check on any replay; the confirmed-commit
pre-rename case handled by the W-kind restore replacing the
unreadable record), the two identities split explicitly (R-kind
debts key RECORDS via `onDiskArmID`; the W-kind debt keys the LIVE
WINDOW via `armedArmID`/`s.armedRecord`), both x4c' copies restated
to the live-window re-key + restore-overwrite, the §9 x19 marker
workflow swept, and the health legs carried to the four-level
precedence with the enum + mask; r22 additions: the D-kind retry
RE-READS and RE-CLASSIFIES (NON-KEY-CLASS-PERMANENT unreadable →
proceed, gated on the ACTIVE side readable under the current key;
KEY-CLASS permanent (invalid-LENGTH or byte-MISMATCH) → RETAIN with
the `.configdb/master.key` restoration message; a missing/unreadable
key file (ENOENT/EACCES/mount-IO) → RETAIN with the key-state
UNVERIFIABLE message (NO restoration claim); BOTH with NO write;
TRANSIENT → retain untried (r23 pin); absent →
`DeleteConfirm` re-drive → clear; READABLE → clear as moot — never
tombstone a readable record; a successful arm on the slot clears the
debt as moot), the D-kind debt is PROCESS-LOCAL with
operator-mediated crash remediation (no auto-recreation at boot —
the boot cannot distinguish superseded from genuinely-pending
unreadable records), the remaining R-first table copy rewritten to
D2, all three x12/x19 bare-delete copies and all four "ONLY
tombstone producer" copies swept (read-back producer vs the
synthesized producer for the unreadable slot), the recordless
guarantee SCOPED (restore-first ordering never creates the gap; a
restore failure returns to D1 and the admitted arm-persistence
residual), the synthetic record pinned (`FirstCommit=false`
load-bearing, `Deadline` = now + 60 s, downgrade behavior documented
config-neutral/runtime-churning/self-limiting with a downgrade-shape
regression), and the health mask gains `SLOT_DELETE` with the
aggregate defined as the OR of `persistDegraded`, every confirm-side
debt kind, and the latch; r23 additions: the D-kind retry's read split
completed ((d-i) synthesized tombstone ONLY on a CONFIRMED
NON-KEY-CLASS-PERMANENT slot read failure (the r26 key-class gate);
(d-i') TRANSIENT read failure
RETAINS the debt UNTRIED — no write, no delete — a transient error
cannot distinguish A-unreadable from C-visible), the W-kind table
gains (w-u) with W-before-D priority (unreadable
NON-KEY-CLASS-PERMANENT slot
→ restore `s.armedRecord` over it — key-class and any
missing/unreadable key file BLOCK the write per r26; a successful
restore subsumes D as
moot; a restore failure returns the slot to D's (d-i) path —
SUPERSEDED in r25: a failed W restore RETAINS W and D stays
SUPPRESSED while W pends), the
recordless claim scoped everywhere (restore-first ORDERING never
creates the gap; the restore-failure arm-persistence residual joins
the residual set), the synthetic record completed (`HashBasis` =
`"canonical-v1"`; the downgrade regression scoped to NORMAL content
with the exceptional-content stale-drop leg; the `FirstCommit=false`
rationale corrected to the OLD reader's expired-first-commit
revert-to-EMPTY path), and the health schema unified (the snapshot is
exactly `{ActivePersistDegraded, ConfirmDebtKindMask
(REMOVAL|REWRITE|SLOT_DELETE), ConfirmRecordState
(OK|TerminalUnreadable|RestartRecoveryOwed)}` — r28 grows TWO
NON-SECRET cause fields (`ConfirmDebtKeyClassMask` per-debt +
`ConfirmRecordKeyClass` latch-level) for the key-class message
variant — with the aggregate a
DERIVED value, not a snapshot field); r24 additions: the
permanent-error state machine unified (terminalization SCOPED to
content-dependent debts — the R-kind read-back tombstone;
content-INDEPENDENT debts (W restore, D synthesized tombstone) EXEMPT
— their purpose is to overwrite a provably-superseded unreadable
record; WRITE failures on ANY debt kind NEVER terminalize — retain +
capped-backoff retry + degraded health, the intended loud posture),
the downgrade oracle corrected (recovery assigns `s.active =
rec.PrevTree` ALWAYS; `FirstCommit=true` on the OLD reader forces
`compiled=nil` + `everCommitted=false` + `committed=0` → bootstrap
handling, NOT an empty-tree revert; the regression asserts
`FirstCommit=false` + compiled + `committed=1` + non-bootstrap boot
class), the (w-u) restore failure phase-qualified (PRE-rename → D's
(d-i) — SUPERSEDED in r25: W stays pended and D stays SUPPRESSED;
POST-rename → live C visible, W stays owed, D's re-read
reaches (d-iii) → clear as moot), the residual wording corrected
(the crash must land before the next SUCCESSFUL W restore —
seconds-wide under transient failure, UNBOUNDED up to the confirm
window's end under a deterministic write failure (r25 Codex m3) — NO
post-crash heal; the process-local W debt dies with the process),
the operator-ownership posture pinned (confirm.json is STORE-OWNED;
a repaired record is CLASSIFIED, never trusted; sanctioned
remediations are removal or repair-to-valid-then-classify), and the
remaining schema copies unified (exact three-value breakdown with
the aggregate DERIVED and the four-level precedence); r25 additions:
the exemption scoped BY FAILURE CLASS (KEY-CLASS permanent —
authentication failure + invalid observed key length, the mechanical
`ConfirmRecordKeyClassError` subtype consumed via `errors.As` —
retains with the `.configdb/master.key`-RESTORATION message and NO
repair write, since writing under a new key launders the
unreadable-active state; master-key IO is TWO-SIDED — READ-side
TRANSIENT (retain + retry with the key-state UNVERIFIABLE message,
NO restoration claim) and WRITE-side
BLOCKED since `readOrCreateMasterKey` auto-creates a fresh key on
`IsNotExist`; only
NON-key-class permanent failures take the repair-write exemption;
EVERY repair action and clear validates the ACTIVE side is also
readable under the current key), D FULLY SUPPRESSED while ANY LIVE
WINDOW EXISTS (any W debt pended OR `armedArmID != ""`;
the kill-shot: an earlier post-rename W attempt may
have left LIVE C visible; C's master-password-free config makes D's
synthesized tombstone PLAINTEXT while W's encrypted write is
blocked by an invalid key — D would tombstone and delete live C;
the W debt — or the live window itself — holds exclusive slot
access and D acts ONLY when NO live window exists (the
eager-rule case), re-evaluating the slot FRESH when W
resolves), the R terminalization rationale corrected (the payload
COULD be synthesized — blind action is unsafe because the slot's
occupant is unprovable under a permanent read error, not because
"the owner is known"), the key-class remediation made
operator-correct (journal + ORIGINAL master.key restoration + the
live-record deletion warning), the exposure window stated honestly
(seconds-wide transient, UNBOUNDED up to the confirm window's end
under deterministic write failure, NO post-crash heal), the
Store-ownership invariant stated as OPERATIONAL (one xpfd per
`.configdb/`, no flock — documented assumption, enforcement a
follow-up), and the partial copies repaired (x15 legs split
NON-KEY-CLASS vs KEY-CLASS; both FirstCommit rationale copies
corrected; the generic message names slot-delete; the §5.1 seeding
shorthand names the class split).

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
6. **SPLIT-OR-CONVERGE (r28 RULED; r29 confirms)**: the r28 rulings
   are recorded in §4.7 — Codex (B) SPLIT with the ordering
   constraint (G must move with H+H2: G's END-of-PHASE-5 release is
   post-manager construction while H's revert is only safe at Load
   before `d.cluster` exists, so G-without-H would convert master's
   short pre-manager window into the post-manager
   bootstrap-with-live-cluster hybrid); Claude SMR (B) SPLIT
   (follow-up may trail — the core introduces no new exposure); AGY
   (A) CONVERGE (the v28 folds close H2; one PR avoids the
   overhead). The 2-of-3 majority structure stands in §4.7: PR-1 =
   the `d.dp` core (A1 + conversion + canaries + sampler); follow-up
   = G+H+H2 seeded from this document. Each reviewer: confirm the
   §4.7 structure (or restate your dissent), confirm the design
   closes under EITHER packaging, and return your verdict on the
   current design. The user makes the final packaging call at manual
   approval — the plan converges PLAN-READY when all three verdicts
   gate the DESIGN as ready, whichever packaging they prefer.

---

*Review ledger: see `reviewer-ids.md`. Round docs: `claude-smr-plan-r<N>.md`,
`codex-plan-r<N>.md`, `agy-plan-r<N>.md`.*
