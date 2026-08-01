# #2114 (residual): publish `d.dp` through one synchronized accessor — plan-of-action

- **Status**: DRAFT v78 — r76 folds: Codex M1 + AGY M1's uniform
  registry-access rule (EVERY `m.maps`/`m.programs` access in every
  class in every state goes through the single `m.mu`-scoped
  helper; classification + handle selection are ONE scoped
  operation; population publishes as ONE whole-batch critical
  section — locking the writer never protected unlocked readers),
  Codex M2's L2 narrowing (A3 claims fresh-unarmed admission
  safety + registry-selection race safety in every state — NOT
  current-generation delivery or re-arm linearizability; the
  retained-generation confusion on the bootstrap-recurrence
  Teardown-retain path is master's own racy behavior, named in
  §10 and owned by the follow-up's work item H), the all-or-
  nothing population proof (AGY r76 M2's partial-state premise
  does not exist — every fallible pin step returns before the
  insert loops; Codex's partial-load check PASSes), Codex m1-m3
  (invariant 12 + the §4.7 pointer texts reworded to the two-state
  form; §9 gains the retained blocked-re-Start overlap with every
  class driven + the Detach test's population actor; the fixture
  migration classification redone — injected fixtures are
  retained-unarmed and PROCEED, the XSK fixture is not broken);
  r76 verdicts: Codex PLAN-NEEDS-MAJOR (2M/3m), AGY
  PLAN-NEEDS-MAJOR (2M), Claude SMR PLAN-READY; pending
  convergence review r77
- **Issue**: psaab/xpf#2114 (OPEN; `bug`, `audit`)
- **Branch**: `research/2114-nat-pool-alarm-dp-race` (plan docs only — NO
  production code in `/research`)
- **Base**: origin/master @ `ed6999000`
- **Mode**: `/research` — stops at PLAN-READY. Implementation requires manual
  `/engineer 2114`.
- **Delivery** (r28 split ruling, §4.7; physically executed at v69): TWO
  units — the #2114 PR ships the `d.dp` accessor core (work item A1 +
  the armed-state gate A3 + the full site conversion + canaries +
  sampler narrowing — THIS document); the named follow-up issue ships
  G+H+H2 (startup-readiness gate + FirstCommit+cluster Load recovery +
  confirm-record durability machinery) seeded from `followup-seed.md`
  (extracted verbatim from this document at v69, with the open findings
  against that unit).
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

  v63: r62 convergence — the acceptance predicate is augmented
  not replaced, the admission gate gains its shutdown-only
  owner, the aliases retire with their registrations, and the
  queued-empty term is ACTUALLY placed this time (Codex
  NEEDS-REVISION 3M/2m, folds 2 FOLDED / 3 PARTIAL /
  1 NOT-FOLDED, structure confirmed; AGY PLAN-READY-WITH-NITS
  0M/1m — the rg_active rendering entry, IS Codex m2; SMR
  PLAN-READY-WITH-NITS 0M/1m — the acceptance queued-empty
  term, IS Codex fold-3): (a) THE AUGMENT (Codex M1, verified
  the v62 regression: my M1 fold REPLACED the election-settled
  term in the acceptance copy rather than augmenting it —
  election state publishes before side effects run,
  `election.go:337-395`, so an actuated-only snapshot can
  coexist with an unsettled control state): the acceptance
  carries BOTH the election-settled term AND the actuated
  predicate. (b) THE SHUTDOWN-ONLY CLOSE/JOIN API (Codex M2,
  verified: the only generic lifecycle hooks are Close and
  Teardown, `apply.go:18-23`, and bootstrap calls the REUSABLE
  Teardown and retains the object for re-arm,
  `bootstrap.go:470-475`): the gate closes ONLY on process
  shutdown, via a named close-admission/join call in
  `runShutdownSequence` AHEAD of the subsystem teardown;
  Teardown never closes it; and the disposition is honestly
  bounded to one in-flight netlink call, with the §9
  timeout-inside-mutation leg. (c) THE ALIAS RETIREMENT (Codex
  M3, verified the correctness failure: arm IDs are reusable,
  and a surviving A/X→B/X alias rebased to a later C/X
  registration would let a delayed duplicate A/X completion
  retire the NEW live arm — false green): every reverse alias
  targeting a registration is REMOVED atomically when that
  registration completes or terminally retires, with the §9
  arm-ID-reuse/stale-duplicate regression. (d) THE QUEUED-EMPTY
  TERM ACTUALLY PLACED (Codex fold-3's NOT-FOLDED — the v62
  M3 fold was lost to a scripting failure, the FOURTH
  honest-fold/scripting loss this loop; from here each fold
  edit is one-replacement-per-script with a grep verification
  after each): the normative predicate at :5491 AND the
  acceptance predicate at :8344 both carry "no QUEUED
  reservation outstanding" with the identity ordering. (e)
  The named actuated surfaces (Codex m2 + AGY m1, verified no
  new renderer is needed): `show chassis cluster data-plane
  statistics` renders `rgN active=` per node
  (`status_sections.go:329-335`,
  `server_show_cluster_text.go:138-147`,
  `cmd/cli/show.go:462-477`), and `show security vrrp`
  renders runtime mastership (`cmd/cli/show_security.go:601-625`,
  `server_nat.go:341-367`). (f) The minors: §9 gains the
  LINKDEL INJECTION leg (Codex m1 — the discarded-error path
  at `daemon_ha_fabric.go:52-53` cannot satisfy the test) and
  the second 120s instance is corrected (Codex fold-6's
  catch).
  v64: r63 convergence — the shutdown gate is daemon-scope and
  adds no new wait, the callback gains the manager-epoch
  discipline, the alias purge covers every retirement path,
  the queued-empty term reaches the remaining copies, and the
  join respects the shutdown budget (Codex NEEDS-REVISION
  5M/1m, folds 3 FOLDED / 3 PARTIAL, structure confirmed; AGY
  PLAN-READY 6/6 with 3 fresh attacks FAILED, structure
  confirmed; SMR PLAN-READY-WITH-NITS 0M/1m — the
  arm-ID-reuse leg, IS Codex M3's testing half): (a) THE
  DAEMON-SCOPE GATE WITH NO NEW WAIT (Codex M1 + M5, both
  verified: the v63 text said "a named call" without a name
  or owner, and the existing sequential worst-case waits —
  5s apply drain + 3s aggregator + 3s IPsec join + 2s HA
  clear + 5s session-sync stop — already reach at least 23s
  against `TimeoutStopSec=20`, `test/incus/xpfd.service:11`):
  the gate is DAEMON-SCOPE state (not manager-owned — a
  re-arm failure clears `d.dp`,
  `daemon_run_naming.go:230-235`, which would strand a
  manager-owned gate while reserved work survives); the
  callback HOLDS applySem THROUGH ITS BODY, so the EXISTING
  5s apply drain (`daemon_run_shutdown.go:50-58`) already
  waits for every in-flight callback — the close-admission
  step flips the flag and adds NO new sequential wait. (b)
  THE MANAGER-EPOCH DISCIPLINE (Codex M2, verified the exact
  bootstrap interleaving: epoch A reserves and launches the
  detached callback then stalls; bootstrap Teardown RETAINS
  the manager, `bootstrap.go:470-475`, and Teardown/stopLocked
  reset NEITHER `xskBoundNotified` NOR `OnXSKBound`,
  `manager.go:421-433,478-482`, `process.go:197-267`; epoch B
  restarts the same object, so A's callback can resume with
  the fences open while B never produces its own readiness
  callback, `daemon_apply_interfaces.go:57-77`): the
  reusable-Teardown path RESETS the one-shot flag and CLEARS
  the callback registration state, AND the callback carries
  the manager's lifecycle generation — a fire in a later
  manager epoch abandons by generation mismatch. (c) THE
  ALIAS PURGE ON EVERY RETIREMENT PATH (Codex M3): the
  neutral/cancellation exits (the debt-drop exits for an
  absent helper or an already-armed later apply,
  `manager_worker_arm_5134.go:42-54`) now invoke the
  reverse-alias purge too, and §9 gains the ARM-ID-REUSE leg
  (a delayed duplicate completion against a reused arm ID is
  ignored — the testing half + SMR m1). (d) THE QUEUED-EMPTY
  TERM IN THE REMAINING COPIES (Codex M4): the §5.1
  convergence definition, both post-reactivation summaries,
  and the rendering inventory all carry the term now. (e) The
  absolute wording is rewritten to the bounded form (Codex
  m1): teardown waits up to the five-second bound and may
  overlap ONE already-entered mutation.
  v65: r64 convergence — the shutdown disposition's downstream
  holes are closed, the manager-epoch reset is scoped to
  Teardown, the rendering inventory gains the queued set, and
  the budget arithmetic is corrected (Codex NEEDS-REVISION
  3M/1m, folds 2 FOLDED / 3 PARTIAL, structure confirmed; AGY
  PLAN-READY 5/5 with 2 fresh attacks FAILED, structure
  confirmed; SMR PLAN-READY with 4 documented attacks FAILED):
  (a) THE THREE DOWNSTREAM HOLES (Codex M1, all verified:
  (i) after the drain times out, `stopPolicySchedulerLoop`
  reacquires applySem with `context.Background()` — UNCAPPED —
  `daemon_run_shutdown.go:78`, `daemon_scheduler.go:170-183`;
  (ii) a startup abort invokes shutdown BEFORE `applyCancel`
  initialization, `daemon_run.go:157-197`, skipping the drain
  while phase four can launch the callback,
  `daemon_run_bringup.go:493-520`; (iii) a preemption after
  the callback's fence check but before the netlink call):
  the downstream reacquisition gains a bounded context; the
  admission-gate close is UNCONDITIONAL at every shutdown
  entry, ahead of any conditional drain; and §9 gains the
  preemption-between-check-and-call leg. (b) THE RESET SCOPE
  (Codex M2, verified: `stopLocked` also runs during ordinary
  helper restarts, `process.go:18-33,133`,
  `manager_compile.go:242-249`, `process_status.go:61-70`,
  and a compile restart occurs after the daemon installed the
  callback with no later registration in that apply): the
  reset/generation bump is TEARDOWN-SPECIFIC (never the
  helper-restart paths), precedes `stopLocked`'s early return
  (`process.go:210-216`), and the callback's generation
  comparison occurs AFTER its applySem acquisition; §9 gains
  the Teardown→reset→B-registration→A-generation-rejection
  regression. (c) THE RENDERING INVENTORY GAINS THE QUEUED
  SET (Codex M3). (d) The budget arithmetic is corrected
  (Codex m1): the listed waits total 18s (with up to 6s more
  from Run's defers, `daemon_run.go:100-112`, and a
  pre-existing unbounded `wg.Wait`,
  `daemon_run_shutdown.go:62-64`).
  v66: r65 convergence — the join waits on the reserved set,
  the scheduler timeout gains its safe terminal state, the
  callback fence gains the zeroize latch, and the reset
  taxonomy is stated (Codex NEEDS-REVISION 3M/1m, folds 2
  FOLDED / 2 NOT-FOLDED, structure confirmed; AGY PLAN-READY
  4/4 with 2 fresh attacks FAILED, structure confirmed; SMR
  PLAN-READY-WITH-NITS 0M/1m — the two missing §9 legs,
  folded here): (a) THE JOIN WAITS ON THE RESERVED SET (Codex
  M1, verified: a `go m.OnXSKBound()` goroutine can remain
  UNSCHEDULED while the shutdown acquires/releases applySem
  and start afterward, `maps_sync.go:451-456` — a semaphore
  drain never sees a not-yet-started callback): the
  admission-gate reservation (recorded at launch under the
  ledger lock) is the join state — the shutdown closes
  admission, then waits the reserved set; a not-yet-scheduled
  callback's FIRST act is the fence check (gate closed ⇒
  abandon and retire its reservation), so the reserved set
  always drains — no new sequential wait beyond the
  set-drain's 5s disposition. (b) THE SCHEDULER'S SAFE
  TERMINAL STATE (Codex M2, verified: the acquire error is
  ignored and the release unconditional,
  `daemon_scheduler.go:170-183`, and cancellation cannot
  unblock an update already acquiring with the intentionally
  uncancelled `d.daemonCtx`, leaving `schedulerWg.Wait()`
  unbounded, `daemon_scheduler.go:192-203`,
  `scheduler.go:103-116,207-217`): the bound matches the
  drain's 5s (no new sequential wait), and on expiry the
  scheduler stop is ABANDONED with the process exiting — the
  scheduler's state is in-memory and dies with the process,
  and its mutation path shares the apply machinery's fence.
  (c) THE ZEROIZE LATCH JOINS THE FENCE (Codex M3, verified:
  a successful zeroize releases applySem with `resetting`
  LATCHED before stopping xpfd, `daemon_apply_reset.go:59-89`,
  `server_diag_system_action.go:69-86,186-205`,
  `cli_request_system.go:174-198` — a queued callback could
  acquire after the wipe and mutate netlink from the retained
  pre-wipe configuration): the callback's fence is
  `runCtx.Err()` OR `stopping` OR `resetting`. (d) THE RESET
  TAXONOMY (Codex m1): `Manager.Close` is a third, terminal
  category and `Teardown` has both reusable and terminal
  callers (`manager.go:471-482`, `bootstrap.go:470-475`,
  `daemon_run_shutdown.go:222-229`) — the reset runs on BOTH
  Teardown paths, never on `stopLocked`'s helper-restart
  paths, and `Close` needs no reset (the process is exiting).
  (e) §9 gains the v65 SHUTDOWN legs (SMR m1 + Codex's
  fold-1/fold-2 testing PARTIALs): the
  preemption-between-check-and-call leg, the
  Teardown→reset→B-registration→A-generation-rejection leg,
  and the reserved-set-drain leg.
  v67: r66 convergence — the reservation binds to a defer on
  every exit, the mutation entry serializes against the gate
  closure, and the scheduler abandonment gains its fence and
  terminal latch (Codex NEEDS-REVISION 3M/1m, folds 2 FOLDED
  / 2 PARTIAL / 1 NOT-FOLDED, structure confirmed; AGY
  PLAN-READY 5/5 with fresh attacks FAILED, structure
  confirmed; SMR PLAN-READY with 4 documented attacks FAILED):
  (a) THE DEFER-BOUND RESERVATION + THE HONEST HUNG
  DISPOSITION (Codex M1, verified: a callback hung in a
  non-contextual netlink call cannot run its defer,
  `daemon_ha_fabric.go:23-93,102-148`): the reservation
  retires via a defer on EVERY callback exit path; a callback
  past the bound has at most ONE in-flight netlink call (its
  next mutation abandons at the fence); a never-returning
  call dies with the process at `TimeoutStopSec=20`. (b) THE
  CHECK-THEN-ENTER CRITICAL SECTION (Codex M2, verified:
  repeated atomic loads cannot establish never-mutating — a
  callback preempted after its check until after the timeout
  can resume and enter the call): the fence check and each
  mutation's entry form ONE critical section under the
  ledger lock, so no call STARTS after the gate closes.
  (c) THE SCHEDULER'S FENCE + TERMINAL LATCH (Codex M3, all
  three parts verified: (i) `publishPolicyScheduleState`
  checks only epoch before dataplane mutation,
  `daemon_scheduler.go:192-217,229-241` — it gains the
  three-term fence check; (ii) the abandonment gains a
  TERMINAL LATCH making any later `stopPolicySchedulerLoop`
  call a no-op, answering Run's unconditional defer re-entry,
  `daemon_run.go:89-100`; (iii) the scheduler's mutation
  holds `m.mu` across the snapshot IPC,
  `manager_compile.go:447-453,526-564`, while Close/Teardown
  require the same mutex, `manager.go:471-482` — the
  teardown can wait behind ONE in-flight scheduler snapshot,
  bounded by the control-request deadline, and the fence
  prevents NEW mutations). (d) The zeroize consistency (Codex
  m1): the two-term "full" references now read the three-term
  form, and §9 gains the ZEROIZE CALLBACK leg.
  v68: r67 convergence — the critical section is
  check-plus-mark with the syscall outside the lock, the
  scheduler's mutations get the same discipline plus the
  observed latch, and the teardown's m.mu wait is honestly
  bounded (Codex NEEDS-REVISION 4M/3m, folds 4 PARTIAL,
  structure confirmed; AGY PLAN-READY with its attack-1
  reading (the section covers check+registration, the syscall
  outside) adopted; SMR PLAN-READY-WITH-NITS 0M/1m — the
  section-hold bound, resolved per AGY's reading): (a) THE
  CHECK-PLUS-MARK SECTION (Codex M1, verified the
  unbounded-hold hazard: the netlink calls are synchronous
  and non-contextual, `daemon_ha_fabric.go:23-148`, so
  holding the ledger through the CALL would block the gate
  closure, the join, and the mint): the section covers the
  fence check + the entry MARK only (microseconds); the
  netlink syscall executes OUTSIDE the lock; and the mark
  establishes the call's precedence — a callback whose
  section completed before the close legitimately entered,
  and one arriving after sees the closed gate and abandons.
  (b) THE SCHEDULER'S CHECK+MARK DISCIPLINE (Codex M2,
  verified: `publishPolicyScheduleState` checks state then
  makes two separate dataplane calls,
  `daemon_scheduler.go:205-215,220-241`, and the userspace
  seed releases `m.mu` before `UpdatePolicyScheduleState`
  reacquires it, `manager_compile.go:153-160,447-453`): each
  scheduler mutation's entry is marked atomically with its
  fence check under the ledger lock — the same discipline as
  the callback. (c) THE OBSERVED LATCH (Codex M3, verified:
  `schedulerCancel`/`schedulerWg`/`schedulerStopped` are
  applySem-guarded, `daemon.go:334-346`, and an
  already-admitted apply can resume after ApplyConfig and
  start another scheduler generation,
  `daemon_apply_dataplane.go:133-165`,
  `daemon_scheduler.go:140-157`): the latch is set under
  applySem and OBSERVED by `startPolicySchedulerLoopLocked`
  (a start after the latch is a no-op). (d) THE HONEST
  m.mu WAIT BOUND (Codex M4, verified:
  `UpdatePolicyScheduleState` holds `m.mu` across rebuild
  work, optional preliminary IPC, and apply_snapshot,
  `manager_compile.go:450-564`, with JSON marshaling before
  any socket deadline, `process_control.go:106-142`, and the
  snapshot deadline alone reaching ~67s versus
  `TimeoutStopSec=20`): the wait is at most ONE in-flight
  snapshot, bounded by the snapshot deadline, and the
  pathological >20s case is SIGKILL-bounded — named. (e) The
  minors: the acceptance's two-term "FULL fence" reference
  gains the three-term form (Codex m1); the §5.1 daemon
  inventory gains the admission flag + reserved set +
  scheduler latch (Codex m2); §9 gains the SCHEDULER LATCH
  leg; and the post-reactivation "COMPLETE" predicate gains
  `IsConfirmPending` + `IsDirty` (Codex m3 — the event
  engine mutates the candidate before invoking commitFn,
  `engine.go:899-930,948`, so the abbreviated rerun could
  false-green). v69: the r28 split ruling EXECUTED at the
  document level — work items G+H+H2 (the FOLLOW-UP unit,
  ~5,170 lines: §4 A1 work items, §5.1 follow-up bullets,
  §6 H2 signatures, §7 invariant 12, §8 follow-up risk
  text, §9 [FOLLOW-UP] legs) moved VERBATIM to
  `followup-seed.md`, which opens with the unit's open
  reviewer findings (Codex r60-r67: every MAJOR across
  those rounds was in this unit's machinery — Codex's own
  per-round structure confirmations kept PR-1 intact).
  This document is now the PR-1-only plan-of-action; all
  remaining G/H/H2 mentions are pointers to the seed or
  historical revision record. v70 @ `dd14047a6` (r68: work
  item A3 armed-state gate added after Codex proved the
  cell cannot order the backend's own post-publication
  mutations — watcher `SetRGActive` vs `Start`'s `m.maps`
  population; plus four minors). v71: r69 folds — A3's
  universal typed-error form was falsified (non-error
  signatures; test-pinned mapless counter-clear contracts)
  and redesigned as the four-class method-by-method
  contract; the teardown proof retracted (false cilium
  premise) with the shutdown link-map race named as a
  residual; the publish-after-`Start` rejection re-founded
  on corrected premises; test respecs + comment sweep. v70: r68 folds — Codex M1
  (the first PR-1-surface MAJOR since the split, verified:
  the watcher calls `d.dp.HA().SetRGActive` at
  `daemon_ha.go:297` in the pre-`Start` window while
  `Start` populates the plain Go map `m.maps` at
  `loader_userspace_shim.go:185-190` and `UpdateRGActive`
  reads it at `maps_fabric.go:38` with no shared lock — a
  fatal concurrent-map read/write on master today; the
  cell closes the interface tear but cannot order the
  backend's own post-publication mutations) folded as
  work item A3 (armed-state method gate: `loaded` →
  `atomic.Bool` + every exported maps-touching method
  gates on it, with the two-layer RACE-1/RACE-2 closure
  rewording); Codex m1 (the pure Store-vs-Load cell leg
  of the confirm-timer test restored as [CORE]); Codex
  m2 / SMR m1 (the narrowed `forwardingStatusDataplane()`
  keeps the `d == nil ||` guard leg); Codex m3 (the
  fwdstatus README:33 + sampler.go:48 wording and the
  `errors`-import deletion join the inventory); Codex m4
  (the §7 shutdown-admission invariant and the §6
  health-message growth parenthetical were follow-up
  residue — moved to the seed). v72 (r70: the partition
  completed — class-2 widened to any signature with
  byte-for-byte missing-map outcomes, class-3 expanded to
  all required-side-effect hybrids, the AST matrix made
  the totality net; gate placement, class-4 corrections,
  exact-schedule residual, narrowed-not-closed wording,
  comment sweep). v73 (r71: class-2 gains its
  synchronization rule; the partition gains categories
  L/F/G + the escape-first precedence rule — total and
  exclusive against the 157-method inventory; the class-3
  raw-helper nested-call rule; residual writer inventory
  + the honest XDPLinks hazard; the m.mu comment sweep;
  the attach-family arming-order invariant). v74 (r72: the
  no-op stubs assigned; direct-access + delegation rule; the
  matrix oracle honestly scoped; the `xdpEntryProg` trio
  synchronized (a real Start-overlap race found inside
  category F); the detaches reclassified to category G;
  the VlanSubInterfaces residual; test-oracle wording;
  the ErrDataplaneNotArmed declaration contract). v75 (r73:
  the trio locked-helper scheme (the v74 text deadlocked);
  the :632 swap write scoped; SwapToUserspaceXDPShimEntryProgram
  assigned class 1; DetachXDP's mixed classification; the
  dedicated XDP test seam; totality wording; inventory
  alignment; the VlanSubInterfaces adjudication). v76 (r74:
  the DetachXDP retained-claim correction (no gate on the
  cleanup path; class-3-like internal); the direct :632
  test pinning; label hygiene (trio single-homed in G;
  DetachXDP's single label); the fixture migration; the
  status-loop premise correction; AGY accepted the VLAN
  adjudication). v77 (r75: the two-state gate predicate —
  the fresh-vs-retained conflation fix; the lock-ownership
  test assertion; the named Detach leg + error-order
  qualification; the fixture migration mechanism +
  inventory; the SMR m1 withdrawal). v78 (r76: the uniform
  registry-access rule + whole-batch publication; the L2
  narrowing (admission + registry-selection safety only;
  the retained-generation confusion named to §10, owned by
  follow-up H); the all-or-nothing population proof;
  invariant-12/pointer rewording; the retained re-Start
  overlap leg; the fixture classification redo).

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
    the startup-readiness gate (work item G — FOLLOW-UP unit,
    `followup-seed.md`; §4.7).
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
  item H — `followup-seed.md`; §4.7 delivery structure: G+H+H2 move
  together): at
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

**Work items G + H + H2 — MOVED to `followup-seed.md` (v69 extraction,
§4.7).** The startup-readiness gate (G), the permanent
FirstCommit+cluster recovery invariant (H), and the confirm-record
durability machinery (H2 — resolution tombstone, ArmID-keyed removal
debt, shutdown-admission fence, scheduler latch, debt ledger,
apply-health snapshot, authority/provider pinning) are the FOLLOW-UP
unit per the r28 split ruling. Their full design text (~3,250 lines,
verbatim from plan v68 @ `f9d0b3eb7`) now lives in
`followup-seed.md` in this directory, which also carries the open
reviewer findings against that unit. PR-1 (this document) neither
ships nor depends on G/H/H2: every hazard they address is
pre-existing on master and not worsened by PR-1 (§4.7). Where PR-1's classification text references the gate
or the recovery guard for reachability scoping (§5.2/§5.3/§5.4), the
classification stands with a pointer to the seed.

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
  assertion at :113 is deleted). 3 files touched in the fwdstatus
  change proper: `sampler.go`, `sampler_test.go` (the
  `countingAccessor` fake already has `CachedStatus`), and the
  daemon adapter file — PLUS `pkg/fwdstatus/README.md` (§5.5) and
  the `daemon_forwarding_status_test.go` rewrite (§9 item 3), both
  named here so the inventory is complete (r69 Codex m4). `Build`
  untouched.
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
  (nil iff `d == nil || d.opts.NoDataplane` — r68 Codex m2 + SMR m1:
  the current constructor explicitly accepts a nil receiver at
  `daemon_forwarding_status.go:123-125`; the guard leg is preserved);
  `IsLoaded`/`GetMapStats`/`Status` leave
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
  idiom cannot express negation). The now-unused `errors` import at
  `daemon_forwarding_status.go:3` leaves with the deleted helpers (r68
  Codex m3).

**Work item A3 — armed-state backend admission gate (r68 Codex M1;
contract redesigned at v71 per r69 Codex M1/M2 — both code-verified:
the universal typed-error form broke non-error signatures and the
test-pinned mapless counter-clear contracts, and the teardown proof
rested on a false cilium/ebpf premise).** The cell closes the interface tear; it cannot order
mutations the backend performs on ITSELF after publication. The
verified race, live on master today: the cluster watcher starts at
`daemon_run_bringup.go:203` (the election inside `UpdateConfig` at
:181 / `election.go:443` synchronously enqueues the initial
transition), the publication Store lands at `:469`, and `Start`
remains later at `:493`; the watcher's handler chain can therefore
load the coherent-but-starting backend and call
`d.dp.HA().SetRGActive` (`daemon_ha.go:297`), which reads the plain
Go map `m.maps` at `maps_fabric.go:38` while `Start` writes it at
`loader_userspace_shim.go:185-190` — no shared lock, a fatal
concurrent-map read/write. Bootstrap has the same shape:
request-time `IsLoaded` reads `loaded` unsynchronized
(`loader.go:457`) against the arm's `:164` write. These hazards
pre-date PR-1 and PR-1 does not worsen them — but the plan's
unqualified "closes the watcher chain at the memory-ordering level"
claim was wrong, and the nil-or-full-slot test cannot detect this
class. The fold:

- `pkg/dataplane/loader.go`: `loaded bool` → `loaded atomic.Bool`
  (:36 declaration; `:164` Store(true) — already the LAST step of
  the load, sequenced after all map population; `:458`, `:490`,
  `:1082` become Load; Store(false) at `Close()`'s ENTRY (:1206),
  before the link-handle closes).
- **THE CONTRACT — a TOTAL, EXCLUSIVE partition of the exported
  `*Manager` surface (r69 Codex M1; completed v72 per r70 Codex M1;
  categorized v73 per r71 Codex M1/M2/M3 — all three verified against
  the full 157-method inventory: apply.go 8, compiler.go 1, loader.go
  26, counters 11, fabric 8, filter 10, flow 2, mirror 2, NAT 30,
  policy 17, screen 8, session 18, stale 15, stats 1)**. Classification
  is by the method's DIRECT START-STATE access (r72 Codex M1 —
  "touches" means DIRECT access; a method that only DELEGATES into
  an already-classed internal is classed by that delegation target,
  so L's `LoadUserspaceShim` populating `m.maps` inside the arming
  path and F's `ApplyConfig` delegating to `Compile` do not collide
  with the access predicates), in this precedence order
  (r71 Codex M2 — the precedence is what makes the classes disjoint):
  a method that ESCAPES a Start-state reference is class 4; else a
  method touching Start-state with required pre-error Go-side side
  effects is class 3; else a method touching Start-state whose pre-arm
  outcome is master's missing-map outcome is class 2 (any signature);
  else a method touching Start-state is class 1; methods touching only
  `m.mu`-protected Go state are category G; lifecycle and facade
  methods are categories L/F. The §9 matrix test assigns every
  exported method to exactly one class via a generated AST inventory
  — an unassigned or double-assigned method fails the test. The
  oracle split is stated honestly (r72 Codex M1): the AST manifest
  enforces TOTALITY mechanically; the per-class OUTCOMES are
  enforced by the runtime tests (the blocked-Start overlap drives
  ALL entries per class, not representatives); each label's
  CORRECTNESS (escaping-reference / side-effect / neutral-outcome
  properties) comes from the handwritten access audit reviewed in
  the PR — the matrix cannot prove semantic disjointness, and the
  plan no longer claims it can.
  - **Class 1 — fallible map-required methods, no required pre-gate
    side effects** (e.g. `maps_fabric.go` `UpdateRGActive` :38,
    `UpdateFabricFwd` :30; the attach family `AttachXDP`/`AttachTC` —
    NOT the detaches, r72 Codex M3): acquire-load `m.loaded` BEFORE THE FIRST
    Start-state access; pre-arm return the typed `ErrDataplaneNotArmed`
    — contract specified (r72 Codex m3): declared in `pkg/dataplane`
    as `var ErrDataplaneNotArmed = errors.New("dataplane not armed")`,
    wrapped with `%w` at each gate site, `errors.Is`-compatible.
    Pure validation that touches NO Start-populated state may precede
    the gate (r70 Codex m1 — `AddTxPort` validates the ifindex at
    `loader.go:982-991` before any map access, and
    `constants_test.go:187-220` pins the capacity/remediation error's
    precedence on an unarmed manager). Population sequenced-before the
    release-Store of `loaded=true` gives the happens-before edge: a
    method observing `true` sees a fully-populated `m.maps`; a method
    during population observes `false` and never touches the map.
    **THE UNIFORM REGISTRY-ACCESS RULE (r76 Codex M1 + AGY r76 M1 —
    the retained-proceed race fix):** EVERY `m.maps`/`m.programs`
    access in EVERY class in EVERY state goes through the single
    `m.mu`-scoped registry helper — classification AND handle
    selection happen as ONE scoped operation under the lock (the
    gate outcome and the handle copy are atomic), and the
    population publishes as ONE whole-batch critical section (the
    program assignment plus both insert loops,
    `loader_userspace_shim.go:183-190`, under a single `m.mu`
    hold) — without whole-batch publication the first insertion
    would flip fresh→retained while population is still partial
    (verified all-or-nothing otherwise: every fallible pin step
    returns before the insert loops, so no partial state exists
    OUTSIDE the batch; r76 Codex's partial-load check PASSes this
    and AGY r76 M2's partial-state premise does not exist on
    current code). Locking the writer never protected unlocked
    readers; this rule is uniform so no reader is unlocked.
    **THE GATE PREDICATE IS TWO-STATE (r75 Codex M1 — the fresh-vs-
    retained conflation fix):** `Close` sets `loaded=false` but
    clears NEITHER `m.maps` NOR `m.programs` (`loader.go:1206-1218` —
    the hitless-restart posture: pinned maps keep forwarding and the
    retained Manager keeps them live), and bootstrap retains the
    Manager for re-arm (`bootstrap.go:470`). The gate fires ONLY on
    the FRESH-unarmed state (`loaded==false` AND `m.maps` empty,
    checked under `m.mu`) — exactly where master returns the
    map-not-found errors the typed error replaces. On the
    RETAINED-unarmed state (`loaded==false`, maps present) every
    class proceeds EXACTLY as master: retained reads report the
    retained state (`SessionCount` counts it, `maps_session.go:326`;
    `GetMapStats` reports it, `maps_stats.go:69`), retained
    mutations reach the live retained maps (the never-throttled
    watchdog timestamp write, `manager_ha.go:807-815` — suppressing
    it would trip the BPF ~2s stale window while the pinned
    dataplane still forwards), and class-4 getters return the
    retained handles. Suppressing stale handles might be a
    defensible policy — it is NOT preservation, and A3 does not
    adopt it. The /engineer pass runs the two-state audit per class
    (fresh-neutral vs retained-proceed, with caller retry/side-
    effect analysis) and the §9 matrix gains retained-state
    coverage: seed maps+programs with `loaded=false`, assert
    master's retained behavior per class.
  - **Class 2 — neutral-outcome methods, ANY signature, WITH the
    synchronization rule (r71 Codex M1 — v72 specified the outcomes
    but not the synchronization, leaving 22 best-fit class-2 lookups
    racing Start)**: acquire-load `m.loaded` before the first
    Start-state access; on `false` return master's missing-map outcome
    BYTE-FOR-BYTE (`IsLoaded` false — no, `IsLoaded` IS the gate read,
    category G below; `SessionCount` (0,0) `dataplane.go:299`;
    `GetMapStats` empty :415; the error-signature no-ops' nil:
    `ClearSessionCounts` `maps_screen.go:57-75`, `ClearStaticNATEntries`
    `maps_nat.go:258-286`, `UpdatePolicyScheduleState`
    `maps_policy.go:244-255` — the #3780 deliberate nil that keeps the
    scheduler self-heal from spinning). A gated class-2 method performs
    NO lookup until population is complete, so it needs NO `m.mu`
    (r71's note: `ClearStaticNATEntries` must not hold `m.mu` across
    iteration — with the gate it never looks up mid-population, and
    its post-gate iteration uses the library handle, which is
    library-safe). Class-2 methods join the §9 blocked-Start overlap
    test — a nonconcurrent matrix cannot distinguish a correct neutral
    gate from today's ungated lookup.
  - **Class 3 — hybrids with required pre-error Go-side side
    effects**: `ClearNATRuleCounters` (`maps_nat.go:395`),
    `ClearGlobalCounters` (`maps_counters.go:176`),
    `ClearZoneCounters` (`maps_counters.go:227` — #3643),
    `ClearAllCounters` (`maps_counters.go:245`): UNGATED — the pinned
    pre-arm behavior IS the contract (`manager_nat_test.go:320`,
    `manager_counters_test.go:509-565`, `zonecounters.go:7-18`).
    Their `m.maps` lookups move under `m.mu` via SCOPED lookup locking
    (lock the lookup, copy the `*ebpf.Map` handle, release BEFORE any
    BPF iteration/update — verified shape per r71; never whole-method
    locking: the offset helpers take `m.mu` internally and
    `sync.Mutex` is non-reentrant), and `Start`'s population insert
    loops (`loader_userspace_shim.go:185-190` — assignment loops only;
    collection construction and pinning stay outside) take `m.mu`.
    **The nested-call rule (r71 Codex M3)**: class-3 hybrids compose
    through INTERNAL raw helpers, never through the public gated
    methods — `ClearAllCounters` calls `clearInterfaceCountersRaw`-
    style internals, so its pinned legacy error text
    ("interface_counters map not found", tolerated by
    `manager_counters_test.go:552`) survives instead of being replaced
    by `ErrDataplaneNotArmed`. Per-method classification cannot catch
    nested-call composition; the matrix test asserts the raw-helper
    shape for every class-3 method with internal calls.
  - **Class 4 — escaping getters of Start-populated state**: `Map`
    (:1151), `Program` (:1156), `NewEventSource` (:1161 — returns
    `(nil, ErrDataplaneNotArmed)`, honoring its `(EventSource, error)`
    signature): gated; callers use the returned references
    per-operation (verified: no long-lived `*ebpf.Map` caching), so a
    post-gate-true reference is fully constructed. (Precedence:
    `Map`/`Program` also match the broad class-2 neutral-nil
    predicate, and `NewEventSource` matches class 1 — the
    escape-first precedence rule resolves them to class 4, r71 Codex
    M2.)
  - **Category L — lifecycle** (r71 Codex M2's missing category):
    `Load` (retired sentinel), `LoadUserspaceShim`, `Start`,
    `CompileUserspaceShim`, `Close`, `Teardown` — the arming/teardown
    path itself, ungated BY CONSTRUCTION (they define armedness; the
    attach flow runs strictly post-Store(true), SMR r71 m1 —
    `LoadUserspaceShim` never attaches; the attach flow is
    CompileUserspaceShim-driven, post-Load — and the §9 matrix's
    pre-arm attach assertion doubles as the reorder tripwire). The
    retired-path no-op stubs `StartFIBSync`/`NotifyLinkCycle`/
    `SyncFabricState` (`maps_fabric.go:72-76` — r72 Codex M1's three
    unassigned methods) touch NO shared state and join category L
    as documented no-ops.
  - **Category F — facade/domain accessors**: `Link`, `HA`,
    `Sessions`, `SessionDeltas`, `Telemetry`, `ApplyConfig` (its
    multi-target delegation orders per-target in sequence, r73
    Codex m1: `Compile`'s inner classing, then `LastApplyResult`'s
    facade read), `LastApplyResult`, `LastCompileResult` — return
    construction-time handles/results or drive their own
    sub-locking; each is verified at /engineer to touch no
    unsynchronized Start-populated state (any that does is classed
    by the access rules instead — the matrix enforces). (The
    `xdpEntryProg` trio's single home is category G under the
    locked-helper scheme — removed from this listing, r74 Codex
    m1.)
  - **Category G — ungated Go-state helpers** (r71 Codex M2's second
    missing category): the offset readers/setters/clears across
    `maps_counters.go` / `maps_nat.go:365` / `maps_screen.go:88`
    (including `IncrementGlobalCounter`) — they touch only
    `m.mu`-protected Go state, never `m.maps`/`m.programs`; several
    are readers that legitimately return POPULATED values on an
    unarmed manager (pinned by `zone_flood_counters_hide_test.go:61`)
    — that is their contract, preserved. `IsLoaded` is the gate read
    itself (resolving the v72 double-listing, r71 Codex M2), and
    `Mode()` lives on `userspace.Manager` (`manager.go:437`), NOT the
    root Manager — the v72 text's placement is corrected here.
    `GetPersistentNAT` (:1146 — `New()`-allocated at :89-100 with its
    own `sync.RWMutex`, `persistent_nat.go:51-65`; pre-Start
    test-pinned at `server_show_nat_test.go:15-20`),
    `XDPLinks`/`TCLinks` (:1195/:1199 — `New()`-created), AND
    `DetachTC` (:1131 — reads only the construction-created link
    map, nil on empty) are category G. `DetachXDP` (:639) is the
    MIXED case (r73 Codex M1): its absent-link early return reads
    only the construction link map (category-G nil preserved), but
    the nonempty path delegates to `setXDPAttachedFlag` (:650),
    which reads Start-populated `m.maps` (:700 `iface_zone_map`,
    :730 `vlan_iface_map`) — reachable on re-arm because `Close`
    clears NEITHER `xdpLinks` NOR `m.maps` NOR `xdpFlagClaims`
    (`loader.go:1206`) and bootstrap retains the Manager for
    re-arm (`bootstrap.go:470`). The v75 class-2 gate on this
    path was WRONG (r74 Codex M1): `setXDPAttachedFlag(false)`
    performs REQUIRED Go-side work — it discovers the retained
    claims (:711) and deletes the detaching ifindex from
    `xdpFlagClaims` (:777) — and on the retained re-arm state
    `m.maps` is still populated, so master RUNS the cleanup while
    a `loaded`-gate would skip it, leaving stale claims a later
    `SetZone` consumes into a spurious re-flag (:851/:865). v76:
    NO `loaded` gate on this path — the delegation target is a
    class-3-LIKE internal: the claim cleanup always runs, and its
    `m.maps` lookups take scoped `m.mu` sections (the class-3
    mechanism). `DetachXDP`'s single manifest label is category G
    (its direct access is the construction link map) with the
    class-3-like delegation target named (r74 Codex m1's
    single-label rule), and §9 gains the specified Detach leg: a
    package-local fake embedding `link.Link` (overriding
    `Unpin`/`Close`), seeding `xdpLinks` AND `xdpFlagClaims`,
    asserting the cleanup runs and no race fires. the `XDPLinks` raw-map hazard is
    named honestly (r71 Codex m1): the 1 Hz status path ranges it at
    `maps_sync.go:943` while Compile can mutate it before taking the
    userspace `m.mu` — pre-existing, not worsened by PR-1, §10.
  - **The `xdpEntryProg` trio + the swap writer SYNCHRONIZED (r72
    Codex M2; the lock SHAPE fixed at v75 per r73 Codex M2 / AGY
    r73 / SMR r73 m1 — three independent reports of the same
    defect):** the plain `m.xdpEntryProg` field is read/written at
    `loader.go:106/:109/:115` (the trio), `:632` (the omitted
    `swapXDPEntryProg` write), and initialized at `:97` —
    `LoadUserspaceShim` writes it during Start (`:154`, before the
    `:164` Store), a recovered-rollback Compile calls the selector
    pre-`m.mu` (RACE-3's window), and the 1 Hz status path reads it
    (`maps_sync.go:481`, `:947`). The v74 "all three accessors
    lock" text would DEADLOCK: `UsingUserspaceXDPShimEntryProgram`
    (:118-120) CALLS `XDPEntryProgram`, and `sync.Mutex` is
    non-reentrant. v75 specifies the locked-helper scheme: an
    internal `xdpEntryProgramLocked()` raw helper; each public
    accessor takes `m.mu` ONCE and delegates (`Using...` locks once
    and calls the helper, never the public getter);
    `swapXDPEntryProg`'s SHIM-FIELD accesses move under scoped
    `m.mu` sections (r74 Codex M2's precision): the `:609`
    `m.programs` lookup, the `:613` already-selected check (via
    the locked helper), and the `:632` write each take `m.mu`
    around the ACCESS only — never whole-method locking (that
    would recurse through the getter and hold the mutex across
    the `:618-628` link-update loop; the loop's `xdpLinks` range
    is serialized by the OUTER userspace `m.mu` against
    Compile-driven attaches — the swap is invoked from the
    liveness-restore path, `maps_sync.go:490-540`, under that
    outer lock). With the field `m.mu`-protected, the trio's home
    is category G (resolving the F/G double-match, r73 Codex m1 —
    the §4 category-F text no longer lists the trio).
    The trio joins the §9 blocked-Start overlap set, the
    `loader.go:49` `m.mu` comment names the field (§5.5 aligned),
    and the §9 XDP seam (below) proves the synchronization. This
    closes the selector write/write + status-read races — the last
    piece of the RACE-3 L2 closure.
- **`loaded` mechanics**: `atomic.Bool` (:36 declaration; `:164`
  Store(true) — already the LAST step of the load, sequenced after
  all map population; `:458`, `:490`, `:1082` become Load; the
  Store(false) moves to `Close()`'s ENTRY (:1206 — AGY r69: new
  entrants gate out BEFORE link-handle teardown begins; honestly an
  admission bit, NOT a lease — it cannot drain an operation that
  already observed true).
- **Master-today in-window outcomes, preserved-or-improved
  precisely** (v72 wording after r70 Codex M1 falsified v71's
  "only pre-arm successes" claim): the pre-arm outcomes on master
  are (i) the class-3 hybrids' pinned side-effect-plus-success/
  later-error behavior — preserved by construction; (ii) the
  class-2 neutral outcomes INCLUDING the error-signature no-ops'
  nil returns — preserved byte-for-byte; (iii) the class-1
  outcomes (map-not-found error or the fatal concurrent-map
  throw) — these become the one clean typed error, the only
  intentional behavior change; (iv) the class-4 getters'
  nil-return — preserved, with the typed error added where the
  signature carries one. A pre-arm initial-election `SetRGActive`
  now returns the typed error instead of racing; the desired state
  was already recorded (`daemon_ha.go:290-291`, before the call)
  and is retried unconditionally by the reconcile loop
  (`reconcileRGStateLoop` runs immediately on startup and every 2s
  with `needsApply = tr.Changed || s.NeedsApply()`,
  `daemon_ha.go:604,:809`) — no lost transition.
- **Teardown is explicitly OUT of the claim (r69 Codex M2)**: v70's
  invariant text overclaimed a teardown proof on a WRONG library
  premise — cilium/ebpf documents "It is not safe to close a map
  which is used by other goroutines" (`map.go:273`). The
  pre-existing shutdown-window race stands named, not hidden, with
  the schedule described exactly (r70 Codex m3): shutdown's
  `stopPolicySchedulerLoop` performs an UNBOUNDED applySem
  acquisition (`daemon_scheduler.go:170-183`) that waits out an
  in-flight apply holder, so the surviving interleaving is
  LATE/ALREADY-NEW admission after the semaphore is released — a
  fresh attach writing the Go link maps (the live userspace path's
  `AttachXDP` fresh insertion `loader.go:575` and detach deletion
  `:661`; `:1124` is the TC path the userspace shim does not
  invoke) while `Close` ranges them (:1206-1216). Pre-existing on
  master, not worsened by PR-1, outside the RACE-1/2/3 publication
  windows; full lifecycle exclusion (lease/refcount + drain) is a
  dataplane-lifecycle follow-up (§10), not #2114.
- **Alternative considered and not adopted (r69 Codex m2 — v70's
  replay premise was FALSE and is corrected)**: a pending-owner +
  publish-after-`Start` design (the bootstrap exit retains the
  constructed owner in a daemon-side pending field and publishes
  only after a successful `Start`) is VIABLE — the missed-transition
  concern v70 cited does not exist (desired state is recorded and
  retried, above). Not adopted because: (a) the admission gate
  standardizes the in-window failure mode at the BACKEND boundary
  for every present and future caller — including the bootstrap-arm
  window's request-time callers — with no per-caller audit, while
  pending-owner protects only cell readers; (b) pending-owner adds a
  SECOND lifecycle channel (cell + pending field, with its own
  clear-on-failure/observability rules) to get wrong; (c) the gate
  is purely additive where publish-after-`Start` rewires the boot
  sequence. Recorded as the documented alternative.
- The RACE-1/RACE-2 closure claims stay the two precise layers
  everywhere they appear: **(L1)** the interface tear — closed by
  the cell; **(L2)** narrowed to its defensible form (r76 Codex
  M2): (i) FRESH-unarmed admission safety (the typed error where
  master returned map-not-found), and (ii) REGISTRY-SELECTION
  race safety in every state (the uniform `m.mu` registry rule +
  whole-batch publication). A3 does NOT claim current-generation
  delivery, re-arm linearizability, or teardown/lifetime safety:
  on the bootstrap-recurrence path (`bootstrap.go:470` —
  Teardown-RETAINs the Manager, `Cleanup` removes the pin tree,
  `loader.go:1221-1235`), the retained handles reference DEAD
  unpinned kernel objects, a re-`Start` creates FRESH maps
  (`loadOrCreatePinnedShimMap`, `loader_userspace_shim.go:602`),
  and a retained-proceed method can mutate the obsolete object —
  a mutation that never reaches the live generation. That hazard
  is master's own racy behavior on the recurrence path — the
  EXACT recurrence the follow-up unit's work item H terminates
  (`followup-seed.md`) — PR-1 neither creates nor worsens it, and
  "preserve master" is explicitly NOT claimed as an oracle for a
  path whose master behavior is already racy (r76 Codex M2's
  phrasing adopted). §10 carries it.

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
  cell + uniform accessor), work item A3 (the armed-state backend
  method gate, r68 Codex M1, §4 A1), the 5-site writer conversion
  (§5.2), the per-site snapshot boundaries (§5.3), the full reader
  conversion (134 prod + ~110 test, §5.4), the `CachedStatusProvider`
  sampler narrowing (§4 A1), the canary pair (§5.1 + `pkg/daemon` AST
  canary), docs + tests. This core is complete and self-contained:
  it closes RACE-1 (watcher chain), RACE-2 (bootstrap-exit arm), and
  RACE-3 (recovered confirm timer) at BOTH layers — (L1) the
  interface tear, by the cell; (L2) method-level admission safety
  against a published-but-unarmed backend, by A3's contract — and
  regresses nothing: no pre-existing hazard is WORSENED, and two
  pre-existing windows are NARROWED without closure being claimed
  (r70 Codex m3 — the `Close()`-entry Store(false) narrows new
  admission at teardown; the population `m.mu` narrows the
  lookup-vs-population window; the §10 residuals remain open).
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

**v69 — the split EXECUTED at the document level.** The follow-up
unit's design text (~5,170 lines: the §4 A1 work items G/H/H2, the
§5.1 follow-up bullets, the §6 H2 signature additions, §7 invariant
12's H/H2 content, the §8 follow-up risk text, and §9's [FOLLOW-UP]
test legs) moved VERBATIM to `followup-seed.md`, which opens with
the unit's open reviewer findings: Codex returned NEEDS-REVISION
every round from r60 through r67 and every one of those MAJORs was
in this unit's shutdown-admission / durability machinery — Codex's
own per-round structure confirmations kept PR-1 intact throughout
("PR-1 remains the synchronized d.dp core and G+H+H2 remain together
in the follow-up", r65/r67). The verdict surface for #2114's
PLAN-READY is therefore PR-1 ONLY: this document neither ships nor
depends on G/H/H2 — every hazard they address is pre-existing on
master and not worsened by PR-1. The
follow-up issue (filed at /engineer-2114 time) re-runs /research
convergence on the seed before any implementation of G/H/H2.
## 5. Concrete design (A1)

### 5.1 New/changed types

- `pkg/daemon/daemon.go`: `dpSlot`, `dpCell atomic.Pointer[dpSlot]`
  replacing `dp`; `dataplane()` / `setDataplane()` (kind-gated); field doc
  comment mirroring the `natPoolAlarm` contract (`daemon.go:211-223`).
  FOLLOW-UP unit (G+H+H2) daemon state — the work-item-G
  startup-outcome state, the H2 shutdown-admission state (admission
  flag + reserved set + scheduler abandoned-stop latch), the H2
  authority/provider state, and the H2 apply-health versioned-snapshot
  state — moved verbatim to `followup-seed.md` §5.1-mirror at v69.
- `pkg/daemon/daemon_forwarding_status.go`: single-method sampler-only
  adapter (§4 A1); `userspaceDataplaneStatus()` removed;
  `userspaceCachedStatusProbe` retained; `forwardingStatusDataplane()`
  returns `fwdstatus.CachedStatusProvider`, nil iff `d == nil ||
  d.opts.NoDataplane` (the nil-receiver guard leg preserved, r68
  Codex m2 + SMR m1);
  the §4 A1 deletion inventory (`var _` assertion, userspace wrapper,
  `userspaceStatusProbe`, the unused `errors` import) executed.
- `pkg/dataplane` (r68 Codex M1; the v73 categorized partition per
  r69/r70/r71 Codex M1/M2/M3 — work item A3, the armed-state
  admission gate): `loader.go` `loaded` → `atomic.Bool` (:36, :164,
  :458, :490, :1082; Store(false) at `Close()` ENTRY :1206); the
  total, exclusive partition of all 157 exported methods (§4 A1) by
  Start-state access with the escape-first precedence rule: class-1
  fallible map-required (gate before the first Start-state access;
  pure validation may precede); class-2 neutral-outcome ANY
  signature WITH the acquire-load rule (class-2 joins the
  blocked-Start overlap); class-3 required-side-effect hybrids
  UNGATED with scoped `m.mu` lookup locking, population loops under
  `m.mu`, and the raw-helper nested-call rule; class-4 escaping
  getters gated; category L lifecycle (ungated by construction;
  the attach family is class-1 with the arming-order invariant);
  category F facade accessors; category G ungated Go-state helpers
  (offset family, `IsLoaded`; `GetPersistentNAT`; `Mode()`'s home
  corrected to `userspace.Manager`); the `xdpEntryProg` locked-
  helper scheme (trio + the `swapXDPEntryProg` :632 write under a
  scoped section, never whole-method); `DetachXDP`'s mixed shape
  (category-G absent-link nil + the class-3-LIKE delegation target —
  scoped `m.mu` lookups, cleanup always runs, no `loaded` gate;
  v76 corrected the v75 text's stale class-2 reference here, r75
  Codex m1);
  `SwapToUserspaceXDPShimEntryProgram` (:604) is class 1 (its
  pre-arm "XDP program not found" becomes the typed error — the
  intended class-1 change; AGY r73's omitted-method catch).
- FOLLOW-UP unit (G+H+H2) package touches — `daemon_apply_commit.go`,
  `daemon_run.go`/`daemon_run_shutdown.go`, `pkg/configstore`
  (`store_persist.go`, `crypto.go`, `store_commit.go`/`db.go`/`store.go`),
  `pkg/fsatomic`, `pkg/cluster`, `daemon_apply.go`,
  `daemon_apply_interfaces.go` + `maps_sync.go`, `pkg/dataplane/userspace`,
  `pkg/api` — moved verbatim to `followup-seed.md` §5.1-mirror at v69.
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
(work item G — FOLLOW-UP, `followup-seed.md`) all timer dispatch is
ordered after startup, collapsing
those rows back to plain APPLY-serialized, with the atomic cell as the
uniform defense. (The NAT start gate `daemon_natpoolalarm.go:101` is
APPLY-class but lives on the bootstrap-EXIT path, not the rollback apply
path — not timer-reachable.) "RACE-2 reaches only standalone/bootstrap"
and the exclusion statements are current-version claims; the legacy
cross-upgrade path is handled by work item H (FOLLOW-UP,
`followup-seed.md`). Everything not labeled
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
| `daemon_run_shutdown.go` 161,167,173 | HA-only rg_active clear (requires cluster config) | CONCURRENT | unreachable via exclusion (current-version; legacy path guarded by work item H — FOLLOW-UP, `followup-seed.md`) |
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
  the FOLLOW-UP unit (§4.7, `followup-seed.md` — these comments document
  the recurrence work item H terminates; the "same PR" framing predates
  the r28 split): `daemon_run_naming.go:200-206` ("one-way ... at most once"),
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
- `pkg/fwdstatus/README.md:33` (the stale `DataPlaneAccessor.CachedStatus()`
  wording rekeys to `CachedStatusProvider`) and the `sampler.go:48`
  "failed `Status()` call" comment (reworded for the narrowed direct
  call) — r68 Codex m3 inventory completion.
- `pkg/dataplane/README.md` (or the loader's doc comment): the armed-state
  admission contract (work item A3) — the four-class pre-arm outcomes.
- The `m.mu` contract comment at `loader.go:49` (r71 Codex m2,
  aligned with §4 at v75 per r73 Codex m2): today it names only
  the offset state; it is updated to name the offset state, the
  `m.maps`/`m.programs` population + scoped class-3 lookups, AND
  the `xdpEntryProg` field.
- Stale source comments describing direct `d.dp` access or the
  plain-interface race (r69 Codex m4 + r70 Codex m4 — the census
  subtracts comments, so these need the explicit sweep):
  `daemon_run.go:373`, `daemon_ha_sync.go:297`,
  `daemon_natpoolalarm_race_test.go:11`, plus the r70 additions
  `daemon_ha_sync.go:1117-1124`, `bootstrap.go:324-330`,
  `daemon_natpoolalarm.go:98-110`. The /engineer pass greps for
  residual `d\.dp` comment prose after the conversion and justifies
  or rewords each hit.
- Recovery-contract docs for work item H's third outcome (FOLLOW-UP —
  `followup-seed.md`; r9 Codex m2,
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
takes `CachedStatusProvider` instead of `DataPlaneAccessor` (r2 M1).
(The work-item-H2 signature additions — `QueueConfig`'s success return
and the `ConfigSink`/`LinkController` attempt-token parameters — are
FOLLOW-UP; `followup-seed.md` §6-mirror.)
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
- `applyResult()`, the health endpoint's 200/503 CONTRACT (unchanged by
  PR-1; the H2 health-message additions that previously grew this bullet
  are FOLLOW-UP — moved to `followup-seed.md` §6-mirror at v70, r68
  Codex m4), REST simulator fail-closed `ok=false` (#3414).
- Pre-arm backend calls (work item A3, the v73 partition + the v77
  two-state predicate — §4 A1): the gate fires ONLY on the
  FRESH-unarmed state (`loaded==false` AND maps empty) — there,
  class-1 methods return the typed `ErrDataplaneNotArmed` instead of
  master's "map not found" error or the fatal concurrent-map throw
  (the ONLY intentional behavior change, now precisely scoped; the
  class-3 raw-helper composition rule keeps even the legacy error
  TEXTS stable, r71 Codex M3); class-2 keep master's missing-map
  outcome byte-for-byte; class-3 keep their test-pinned
  side-effect-plus-PINNED-OUTCOME behavior; class-4 return nil (+
  the typed error where the signature carries one). On the
  RETAINED-unarmed state every class proceeds EXACTLY as master
  (r75 Codex M1 — retained reads report retained state, retained
  mutations reach the live pinned maps; suppression would be a
  policy change, not preservation). Post-arm behavior
  bit-identical; no signature changes.

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
11. **[FOLLOW-UP — moved to the seed at v70 (r68 Codex m4)]**: the
    shutdown-admission guard invariant is work-item-G content; it moved
    verbatim to `followup-seed.md` §7-mirror.
12. **Armed-state admission (work item A3, r68 Codex M1; scoped r69
    Codex M2; two-state r75/r76)**: `loaded` is an `atomic.Bool`;
    its Store(true) is the LAST step of the whole-batch population
    critical section (`loader.go:164`). The invariant, stated
    exactly (r76 Codex m1's corrections): (i) a method gated on the
    FRESH state (`loaded==false` AND the registry empty — one
    scoped `m.mu` operation with the handle selection) never
    touches Start-populated state; (ii) a method observing true
    sees a fully-populated registry; (iii) a retained-state method
    proceeds against the retained registry UNDER the uniform
    registry rule — master's exact behavior. NO lifetime or
    teardown exclusion is claimed — the Store(false) at `Close()`'s
    entry (:1206) gates new FRESH-state entrants (retained-state
    methods proceed per the two-state rule, = master) and cannot
    drain an in-flight operation; the pre-existing shutdown-window
    link-map race (`Close`'s :1206-1216 range vs the live userspace
    path's link-map writers — pinned-link reuse insertion :534,
    fresh insertion :575, detach deletion :661 — admitted late
    after the scheduler stop's unbounded applySem acquisition
    releases, `daemon_scheduler.go:170-183`, a late confirm
    rollback acquiring with `context.Background()`,
    `daemon_apply_commit.go:629`) stands as a named residual (§10);
    cilium/ebpf documents close-in-use as unsafe (`map.go:273`).
13. **#4577 confirm contract (r8/r10/r11/r12/r13/r14/r15)**: an
    unconfirmed config must NEVER stand, and a CONFIRMED config must
    never be rolled back. Work item H's revert-at-Load (FOLLOW-UP —
    `followup-seed.md` §7-mirror) honors the first half for the
    FirstCommit+cluster class, and work item H2's tombstone/debt
    machinery enforces the removal linearization; both designs and
    their documented irreducible residuals moved verbatim to the
    seed at v69. PR-1 itself changes NO confirm-record semantics.

## 8. Risk assessment

| Class | Rating | Assessment |
|---|---|---|
| Behavioral regression | **MED** | Large but mechanical diff; compiler-enforced completeness + regenerated §5.4 table + the new dpCell canary. Real risks: (a) a §5.3 snapshot-boundary mistake; (b) canary redesign errors (mitigated by both-direction self-tests); (c) the fwdstatus narrowing touching `NewSampler` (contained: 1 prod caller + 2 test sites; full-suite gate); (d) [FOLLOW-UP — seed] work item H narrows commit-confirmed recovery semantics for the FirstCommit+cluster class (revert-at-Load vs re-arm); the follow-up unit's risks are assessed in `followup-seed.md`; (e) the A3 enumerate-and-gate audit could miss an exported maps-touching method — mitigated by the pre-arm method-matrix test and the blocked-Start -race regression (§9), and bounded by the failure shape (a missed gate reproduces master's map-not-found error, never a NEW failure mode). |
| Lifetime / borrow | **LOW** | Immutable slots; captured references keep backends alive exactly as today. No FFI/Rust interaction. |
| Performance regression | **LOW** | One atomic load + indirection per control-plane read (1 Hz sampler, request rate, watchdog 2/s, HA ≤15/s). One small allocation per Store, ≤5/lifetime. No per-packet Go code. |
| Architectural mismatch | **LOW** | #2116 `atomic.Pointer` precedent; daemon atomics-for-publication idiom; no dataplane-lifecycle redesign (Option B rejected); canary redesign extends the existing boundary-guard pattern. Work items G+H (FOLLOW-UP — `followup-seed.md`) carry a deliberate lifecycle change (startup-outcome gating of the rollback executor + the shutdown-admission fence) and a narrowed recovery semantic; their full risk assessment lives in the seed. PR-1 itself adds no lifecycle change. |

## 9. Test plan

*Delivery partition (§4.7, r29 Codex m5): items tagged **[CORE]** ship
with PR-1 (the `d.dp` accessor core); items tagged **[FOLLOW-UP]** ship
with the G+H+H2 follow-up issue — those legs moved verbatim to
`followup-seed.md` §9-mirror at v69. Untagged general gates (build,
vet, the full Go/Rust suites, smoke) run for BOTH units.*

1. `go build ./... && go vet ./pkg/daemon/... ./pkg/fwdstatus/...` — the
   field retype makes the compiler enumerate every conversion site.
   (Untagged — runs for BOTH units per the partition header.)
2. New `pkg/daemon/daemon_dp_race_test.go` (under `-race`, `-count=5`)
   — the accessor/race tests are **[CORE]**; the work-item G gate
   tests and work-item H/H2 tests are **[FOLLOW-UP]** (moved verbatim
   to `followup-seed.md` §9-mirror at v69 — pointer below):
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
     PLUS the construction-contract legs (r69 Codex m3 — a
     nonnil-fake-only start cannot catch retention of the
     nil-at-construction early return): nil receiver → nil;
     `NoDataplane` → nil; initially-empty cell → NON-nil adapter
     whose per-call probe reports ok=false until a userspace backend
     publishes.
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
   - `TestDataplaneCell_ConfirmTimerStoreVsApplyReader` (r68 Codex m1 —
     the pure cell leg of the confirm-timer test has NO G/H/H2
     dependency and stays [CORE]): two-sided gate — a
     `setDataplane(dp)` publication gated immediately before the store
     vs an applySem-holding reader gated immediately before its
     `d.dataplane()` load; shared release; no channel between the pair.
   - **[FOLLOW-UP] legs moved (v69)**: the work-item-G gate tests
     (`TestDataplaneCell_ConfirmTimerVsBootPublication`), the work-item-H
     recovery-guard tests (i)-(x), and the work-item-H2 test legs
     (tombstone/debt/fence/join/scheduler-latch/zeroize/apply-health)
     moved verbatim to `followup-seed.md` §9-mirror. They run with the
     follow-up issue's implementation, not PR-1.
3. Update `daemon_natpoolalarm_race_test.go` (`writeDPFor` →
   `setDataplane`) and `daemon_forwarding_status_test.go` (rewrite against
   the narrowed adapter: `ProjectsMapStats`/`UsesUserspaceStatusAdapter`
   move to asserting `CachedStatus` per-call probing;
   `UsesCurrentDataplaneAfterSwap` maps onto the narrowed shape with
   `setDataplane` swaps). **[CORE]**
4. Scoped race gate: new `test-race-dp` make target —
   `go test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit' -count=2`
   plus `go test -race ./pkg/dataplane/ -run 'ArmedGate|PreArm' -count=2`
   (r68 Codex M1 — the A3 gate legs) — invoked from `test-go` (r1/r2:
   plain `go test ./...` has no race teeth; full-repo `-race` stays
   out of scope). **[CORE]**
4a. A3 armed-gate tests (`pkg/dataplane`, r68 Codex M1 / r69 Codex m1 /
   r71 Codex M1-M3 — respecified): the root `Manager.Start` invokes
   the retired Load path (`apply.go:208`); real shim population runs
   through the userspace manager + the privileged loader
   (`loader.go:152`, `loader_userspace_shim.go:95`), so the test drives
   a SYNTHETIC per-manager loader seam (test-only var) with FIXED
   entered/resume barriers around a population write, then overlaps
   gated-method readers and the population writer for real — a mere
   pause-after-write would order the readers and need not trigger
   `-race`: (i) `TestManager_ArmedGate_BlockedStart` — class-1/class-4
   calls during the held window return `ErrDataplaneNotArmed`/nil,
   class-2 calls — ALL 22 named entries, not representatives (r72
   Codex) — return their exact neutral values (r71 Codex M1 — a
   nonconcurrent matrix cannot distinguish a correct neutral gate
   from today's ungated lookup), class-3 calls perform their pinned
   side effects AND return their pinned outcomes (success OR the
   legacy later error — r72 Codex m2 wording correction), and the
   synchronized `xdpEntryProg` trio joins the overlap set (r72
   Codex M2) — and the XDP field gets its DEDICATED two-sided seam
   (r73 Codex M3): real Start writes the selector at `loader.go:154`
   BEFORE the population barrier, so a population-only barrier
   orders the selector write before the accessor calls and the test
   would pass even with unsynchronized access — the synthetic
   loader gains a second entered/resume barrier around the `:154`
   selector write, with the getter, predicate, and swap (`:632`)
   driven concurrently across it — and the `:632` lock is pinned
   DIRECTLY (r74 Codex M2): a blocked Start leaves the public Swap
   at its class-1 gate, a direct private swap exits at the `:609`
   absent-program check or the `:613` already-selected check, so a
   missing `:632` lock could silent-green — the test therefore
   drives a DIRECT `swapXDPEntryProg` call with a seeded DISTINCT
   test-only program (seed `m.programs["test_prog"]` and
   `xdpEntryProg="other"` so both early exits fail and `:632`
   executes), raced against the getter across the seam — AND the
   test asserts lock OWNERSHIP, not just branch execution (r75
   Codex M2: a mutant dropping only the `:632` lock still passes
   the race schedule, because the getter's unlock synchronizes-
   before the swap's earlier `:609`/`:613` sections — the read
   happens-before the mutant write): the `:632` critical section
   contains a test hook that HOLDS the section while a getter
   attempts, and the test asserts the getter BLOCKS until release
   (or fails an in-section `TryLock`); no fatal fault; (ii)
   `TestManager_PreArmMethodMatrix` — every exported `*Manager`
   method is ASSIGNED to exactly one v75 class/category by the
   generated AST inventory — the manifest asserts TOTALITY (one
   label per method, matching §4's honest oracle scoping; r73 Codex
   m1's wording fix) — and the class-3 raw-helper composition shape
   is asserted (r71 Codex M3 — `ClearAllCounters` composes through
   internal raw helpers, preserving its pinned legacy error text).
   PLUS the RETAINED-state coverage the §4 contract promised (r76
   Codex m2 — the v77 text promised it but §9 never gained it):
   `TestManager_ArmedGate_RetainedReStartOverlap` — a retained
   fixture (seed maps+programs, `loaded=false`) driven through a
   blocked re-`Start` whose whole-batch critical section holds a
   hook, with EVERY class's methods driven across the seam: fresh
   methods gate, retained methods proceed under the registry rule,
   no fatal fault, and the whole-batch boundary proven (no partial
   registry is observable). The named Detach test's "race-free"
   gains its concurrent population actor (the same blocked
   re-`Start` seam).
   The fixture-migration classification is REDONE under the
   two-state rule (r76 Codex m3 — v77's prescription was stale):
   `injectShimMap` modifies only `maps`, never `loaded`
   (`manager_testhelpers_test.go:22`), so an injected fixture is
   RETAINED-unarmed — and under the two-state predicate it
   PROCEEDS. The XSK fixture
   (`xdp_shim_decouple_test.go:32,:321,:41` — it already injects
   ctrl/binding maps before the Swap call) is retained-unarmed and
   the gate does NOT break it. Only fixtures asserting
   `loaded==true` semantics (armed assertions) need the armed
   synthetic fixture (an in-package `pkg/dataplane` helper for the
   root tests; the userspace tests keep the reflect/unsafe
   pattern); the /engineer pass re-derives the true migration set
   from the two-state classification instead of the stale ~30
   estimate (most injected fixtures proceed unchanged). The Detach leg gets its named test
   (r75 Codex m2): `TestManager_ArmedGate_DetachRetainedClaims`
   (matching the race target's `-run` pattern) — the fake
   `link.Link` embed, `xdpLinks`+`xdpFlagClaims` seeded, cleanup
   asserted race-free — with the error-order qualification:
   "cleanup always runs" means UNLESS a discovery failure returns
   first (the `vlan_iface_map` lookup :730 and `iface_zone_map`
   iteration :747 error paths preserve claims and the link for
   retry — claims are never deleted before those failures).
   **[CORE]**
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
  bootstrap-with-live-cluster hybrid). Their designs live in
  `followup-seed.md` (extracted verbatim from this document at v69,
  with the open reviewer findings against that unit — the seed is
  NOT converged and gates its own /research rounds under the
  follow-up issue).
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
- **Pre-existing retained-generation confusion on the bootstrap-
  recurrence path (r76 Codex M2 — named, owned by the follow-up's
  work item H)**: `bootstrap.go:470` Teardown-retains the Manager;
  `Cleanup` removes the pin tree (`loader.go:1221-1235`); the
  retained `m.maps`/`m.programs` handles reference dead unpinned
  kernel objects while re-`Start` creates fresh ones. A retained-
  proceed method can mutate the obsolete object (the mutation never
  reaches the live generation) and multi-map readers can report a
  mixed old/new generation. Master has this exact behavior today
  with NO gate at all; the recurrence itself is what work item H
  terminates (`followup-seed.md`), and the generation/
  linearizability redesign rides with it. A3's registry rule keeps
  the Go-level access race-free in the meantime; it deliberately
  does NOT claim generation correctness here.
- **Pre-existing shutdown-window link-map race (r69 Codex M2,
  exact-schedule r70 Codex m3 — named, not fixed)**: shutdown's
  `stopPolicySchedulerLoop` performs an UNBOUNDED applySem
  acquisition (`daemon_scheduler.go:170-183`) that waits out an
  in-flight apply holder, so the surviving interleaving is
  LATE/ALREADY-NEW admission after the semaphore is released — a
  fresh attach writing the Go link maps (pinned-link reuse insertion
  `loader.go:534` — reachable because userspace Compile ignores
  pin-removal errors before `CompileUserspaceShim`,
  `manager_compile.go:168` — fresh insertion `:575`, detach deletion
  `:661`; `:1124` is the TC path the userspace shim does not invoke)
  while `Close` ranges them (:1206-1216); cilium/ebpf documents
  close-in-use as unsafe (`map.go:273`). The related raw-`XDPLinks`
  exposure is named honestly (r71 Codex m1): the 1 Hz status path
  ranges it at `maps_sync.go:943` while Compile can mutate it before
  taking the userspace `m.mu` — pre-existing, not worsened by PR-1.
  The adjacent exported `VlanSubInterfaces` Go-map race joins it
  (r72 Codex m1; inventory completed at v75 per r73 Codex m3 — also
  read during the swap path at `loader.go:622` and written by the
  legacy Compile at `compiler.go:441`): the status helper reads it
  at `maps_sync.go:950` while `CompileUserspaceShim` writes it
  (`loader.go:201`) before acquiring the userspace `m.mu`
  (`manager_compile.go:213`) — pre-existing, not worsened by PR-1.
  **The r73 reviewer-split adjudication**: AGY r73 ruled this MUST
  join A3 (a fatal map crash on the 1 Hz status path; folding the
  trio while residual-izing this field is unprincipled); Codex r73
  ruled residual-ization CONSISTENT and r74 RE-CONFIRMED the
  conclusion while correcting one premise (r74 Codex m3): the
  status loop does NOT start only after a successful Compile —
  `clearHelperHAStateWithDebtEnsureRetryLocked` starts it before
  propagating two Compile failures (`manager_ha.go:115`,
  `manager_compile.go:276,:378`) — but EVERY loop-start path is
  still after `bpfShim.CompileUserspaceShim` has returned, and
  `Start` only delegates to `Load` (`manager.go:370`), so this
  remains a POST-arm Compile-vs-status race with NO Start-window
  overlap, outside A3's pre-arm L2 scope.
  Ruling: the residual STAYS (Codex's scoping is the principled
  line — A3's claim is the pre-arm window), AND the hazard gets the
  explicit disposition AGY's severity assessment demands: it is a
  fatal-crash-class pre-existing race fixable by a one-field `m.mu`
  guard, named here as the FIRST cheap-follow-up candidate after
  PR-1 (filed with the follow-up issue at /engineer time), not
  silently dropped. AGY's r74 re-review rules on this adjudication
  explicitly. Full lifecycle exclusion
  (lease/refcount + drain) is a dataplane-lifecycle redesign — a
  follow-up candidate, NOT #2114. PR-1's A3 adoption of the
  `Close()`-entry Store(false) narrows the entrant window but
  deliberately claims no drain.
- **Broader cluster-runtime lifecycle question (follow-up issue, filed at
  /engineer time)**: should `enterBootstrapMode` stop cluster comms when
  `d.cluster != nil`? The permanent recovery invariant (work item H — `followup-seed.md`)
  ships in the G+H+H2 follow-up unit (§4.7) and prevents the
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
   overhead). The 2-of-3 majority structure stands in §4.7 and was EXECUTED at the
   document level at v69: PR-1 = the `d.dp` core (A1 + conversion +
   canaries + sampler — THIS document); follow-up = G+H+H2, extracted
   verbatim to `followup-seed.md` with its open findings. Each
   reviewer: confirm the extraction is faithful (no PR-1 content
   lost, no follow-up dependency smuggled into PR-1), and return
   your verdict on the PR-1 design ONLY — the follow-up seed is
   explicitly out of this verdict's scope and gates its own
   convergence under the follow-up issue. The plan converges
   PLAN-READY when all three verdicts gate the PR-1 design as
   ready.

7. **r68-r76 resolution (for the record)**: Codex r68 M1 (armed-state
   admission gate) folded as work item A3; r69-r75 falsified each
   intermediate form, and r76 caught the last two structural defects
   (locking the writer never protected unlocked readers — the uniform
   registry rule + whole-batch publication; "retained" conflated
   live-pinned with torn-down generations — the L2 claim narrowed to
   admission + registry-selection safety, with the generation hazard
   named to §10 and owned by the follow-up's work item H). AGY r76's
   partial-state premise was falsified by the all-or-nothing
   population proof (both reviewers see this). Each reviewer: verify
   the uniform registry rule covers every class in every state, the
   whole-batch boundary, and the narrowed L2 wording.

---

*Review ledger: see `reviewer-ids.md`. Round docs: `claude-smr-plan-r<N>.md`,
`codex-plan-r<N>.md`, `agy-plan-r<N>.md`.*
