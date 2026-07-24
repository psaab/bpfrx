# #2114 (residual): publish `d.dp` through one synchronized accessor — plan-of-action

- **Status**: DRAFT v13 — r12 findings folded (Codex NEEDS-REVISION
  4M/1m; AGY NEEDS-REVISION 2 remediations; Claude SMR
  PLAN-READY-WITH-NITS 0M/2m); pending convergence review r13
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
legacy records get faithful-to-their-build semantics (their pre-existing
divergence exposure is unchanged, not amplified). Tests:
upgrade-in-window (legacy raw-hash record with invalid UTF-8 → legacy
compare BINDS → no spurious stale-drop; recovery proceeds to its normal
outcome) and downgrade-shape (a canonical-basis record unmarshalled by a
reader that ignores `HashBasis` — JSON fixture asserting the additive
field is inert).
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

**Work item H2 — resolution tombstone (r11 Codex M1 + r12 Codex M1/M2/M3,
Claude SMR m1/m2, AGY Attacks 1/2 — all verified; in scope because H's
correctness depends on resolution identity).** Every confirm path
resolves a pending window by DELETING confirm.json
(`resolveConfirmRemovalLocked`, `store_commit.go:575-590`) WITHOUT
changing active content — so after a failed durable removal (retry debt
retained, `:596-608`, which itself documents "a restart before the
background retry heals could resurrect a stale rollback"), the lingering
record's GuardedHash STILL MATCHES the active tree: recovery cannot
distinguish "window pending" from "window RESOLVED but deletion failed".
On master TODAY, recovery re-arms such a record and the timer later
rolls back an ALREADY-CONFIRMED config (`ConfirmPendingOnDemotion`,
`:777-792`, exists precisely to prevent the #4378 standby divergence —
a crash in the retry window reopens it). For FirstCommit+cluster
records, work item H would instead revert the confirmed config AT LOAD
— immediate divergence. Fix (configstore, ~55 LoC + tests), with the
r12-hardened mechanics:

- **Additive schema fields — DECIDED, not deferred (r12 Codex M3 =
  Claude SMR m1 = AGY Attack 1).** `Resolved bool` and `HashBasis
  string` are ADDITIVE JSON fields on `confirmRecord`, per the
  `WriteConfirm` contract comment itself: "No #1917 compatibility
  envelope is used — the file is transient recovery state, not a
  committed config, and confirmRecord evolves via additive JSON fields"
  (`db.go:200-205`). The v12 claim that the schema change "rides the
  existing envelope versioning" was FALSE — `wrapEnvelope` covers only
  `active.json` (`db.go:450`); the real format floor
  (`EnvelopeFormatVersion`/`EnvelopeMinReaderVersion`,
  `envelope.go:111-123`) does not govern confirm.json. Downgrade
  semantics (documented, accepted): an old reader's `json.Unmarshal`
  silently IGNORES the unknown fields — `Resolved` → it re-arms a
  resolved record (bounded by the new build's retry loop converging the
  deletion; no worse than today's delete-failure window); `HashBasis` →
  it compares on its own legacy basis (faithful to its build).
- **Tombstone write = READ-MUTATE-WRITE, full record (r12 Claude SMR m2
  = AGY Attack 2).** The tombstone is the EXISTING record read back,
  `Resolved` set, rewritten via the same `WriteConfirm` fsatomic path —
  preserving `Deadline`/`PrevTree`/`Gen`/`GuardedHash`/`HashBasis`, so
  the #5637 degenerate-record gate (`db.go:275-281`: zero deadline or
  nil PrevTree → parse error) passes UNMODIFIED. A minimal
  `{"resolved":true}` tombstone is explicitly REJECTED: it trips #5637
  and wedges recovery at the early error return
  (`store_persist.go:141`), tombstone never honored, record never
  cleaned. `fsatomic.WriteFileDurable` (temp+fsync+rename) makes the
  sequence crash-atomic: either the original record (pending) or the
  complete tombstone (resolved), never a torn file.
- **Linearization order — durable tombstone FIRST (r12 Codex M1).**
  Master resolves in memory first — `cancelPendingConfirmTimerLocked`
  (`store_commit.go:717-726`) stops the timer, bumps `confirmGen`, and
  NILS the in-memory record content — then deletes durably; a crash
  between leaves a matching pending-shaped record that recovery
  re-arms. v13 pins the order: (1) READ-MUTATE-WRITE the tombstone
  durably — THE resolution linearization point; (2) in-memory
  resolution (timer stop + confirmGen bump + state clear — still
  covering the in-flight callback race, `:717-726` +
  `PromoteRollback`'s gen check `:860`); (3) best-effort delete with
  retry. Tombstone-write FAILURE: proceed with the in-memory resolution
  and retain retry debt (re-driving tombstone→delete) — making the
  confirm itself durability-gated would invert a disk failure into a
  rollback of a confirmed config, which is strictly worse. The
  irreducible residual (write-failure AND crash before retry heals)
  re-arms a resolved window — documented, bounded by the retry loop,
  and strictly smaller than today's window (which spans the entire
  deletion, not just the tombstone write).
- **Generation-safe removal debt (r12 Codex M2 — verified
  PRE-EXISTING).** `confirmRemoveDegraded` is an UNKEYED bool and the
  retry (`store_persist.go:439-444`) removes WHATEVER confirm.json
  exists: a resolved-A/delete-failed → arm-B sequence lets the retry
  destroy B's genuinely-pending crash-recovery record on master TODAY
  (a crash in B's window then strands the unconfirmed config). The
  in-memory nil'ing at `:717-726` additionally means the retry cannot
  distinguish stale A from fresh B by content. Fix: the ARM path
  SUPERSEDES the debt — `writeConfirmState` clears
  `confirmRemoveDegraded` with a journal note, because the overwrite
  satisfies the debt by construction (A's record no longer exists once
  B's is written — the debt "A must not be recovered" is moot).
  Regression: delete-failure(A) → arm(B) → retry fires → B's record
  INTACT → restart → B re-arms normally.
- **Recovery total order (AGY r12, verified)**: ReadConfirm parse gate
  → `rec.Resolved` check (tombstone → drop) → GuardedHash mismatch
  (stale → drop) → expired (existing revert) → work item H (unexpired
  FirstCommit+cluster → revert-at-Load) → re-arm.

Regressions: (x1) demotion-confirm + injected deletion failure +
restart → recovery drops the tombstoned record (no re-arm, no H, no
rollback of the confirmed config; the #4378
`commit_confirm_demote_4378_test.go:5-17,50-72` divergence stays
closed); (x2) crash BETWEEN arm and tombstone → genuinely pending →
normal re-arm; (x3) tombstone-write failure → in-memory resolution
proceeds, retry converges tombstone→delete, health degraded until
healed; (x4) delete-failure(A) → arm(B) → retry → B's record intact →
restart re-arms B (generation-safe debt); (x5) minimal tombstone
rejected by construction — the read-mutate-write helper is the ONLY
tombstone producer (assert its output passes the #5637 gate). This
closes the master's re-arm-after-confirmed residual for ALL record
classes, not just H's.

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
- `pkg/configstore/store_commit.go` + `db.go` (r11/r12): the
  `canonicalConfigHash` binding at the sole arm site
  (`writeConfirmState`); the additive `Resolved` + `HashBasis` fields
  on `confirmRecord` (per the `db.go:200-205` additive-evolution
  contract — NO envelope bump, none exists for confirm.json); the
  read-mutate-write tombstone helper (the ONLY tombstone producer —
  its output always passes the #5637 gate); the
  tombstone-first resolution ordering; the arm-path
  `confirmRemoveDegraded` supersession.
- `pkg/fwdstatus/sampler.go`: `CachedStatusProvider` interface; `NewSampler`
  + `Sampler.dp` retyped; `sample()` direct call.
- `pkg/dataplane/retirement_boundary_canary_test.go`: matcher extension
  (incl. `*ast.IndexExpr` renderer support).
- `pkg/daemon/daemon_dp_canary_test.go` (new): dpCell-access AST canary.
- `pkg/grpcapi`, `pkg/cli`, `pkg/api` untouched.

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
  `HashBasis` discriminator, and the tombstone (r11/r12) updates the
  `confirmRecord` struct doc (`db.go:161-168`), the `WriteConfirm`
  additive-evolution contract comment (`db.go:200-205` — gains the two
  new fields' downgrade semantics), and the
  `resolveConfirmRemovalLocked` / `noteConfirmRemoveFailureLocked`
  comments (`store_commit.go:575-608`) for the tombstone-first
  linearization + arm-superseded debt semantics.
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
- `applyResult()`, health endpoint, REST simulator fail-closed `ok=false`
  (#3414).

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
12. **#4577 confirm contract (r8/r10/r11/r12)**: an unconfirmed config
    must NEVER stand, and a CONFIRMED config must never be rolled back.
    Work item H's revert-at-Load honors the first half for the
    FirstCommit+cluster class by resolving the window EARLY (revert
    before manager construction) rather than by keeping the config; the
    operator's remaining confirm window is sacrificed for this narrow
    hybrid-generating class, loudly and on purpose. Expired records keep
    the existing expired-branch behavior bit-for-bit. The second half is
    enforced by THREE mechanisms with pinned linearization: the
    versioned canonical binding (no live record is stale-dropped over a
    serialization or basis-transition divergence), the resolution
    tombstone (the DURABLE tombstone write is the resolution
    linearization point — a resolved window is never re-armed or
    reverted after it lands), and the generation-safe removal debt (a
    new arm supersedes the prior debt by overwrite — the retry never
    acts on a record it did not resolve). The irreducible residual —
    tombstone-write failure AND crash before retry — re-arms a resolved
    window, is bounded by the retry loop, and is strictly smaller than
    today's whole-deletion window; making confirm durability-gated
    would invert a disk failure into a rollback and is rejected.

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
     (x) RESOLUTION-TOMBSTONE regressions (r11/r12): (x1)
     demotion-confirm + injected confirm.json deletion failure +
     restart → recovery drops the TOMBSTONED record (no re-arm, no H,
     no rollback of the confirmed config — the #4378 divergence stays
     closed); (x2) crash BETWEEN arm and tombstone → genuinely pending
     → normal re-arm; (x3) tombstone-write failure → in-memory
     resolution proceeds, retry converges tombstone→delete, health
     degraded until healed; (x4) delete-failure(A) → arm(B) → retry →
     B's record INTACT (debt superseded at arm) → restart re-arms B;
     (x5) the read-mutate-write helper is the ONLY tombstone producer —
     assert its output passes the #5637 degenerate gate unmodified;
     (x6) HASH-BASIS versioning: upgrade-in-window (legacy raw-hash
     record with invalid UTF-8 → legacy-basis compare BINDS, no
     spurious stale-drop) + downgrade-shape (additive `HashBasis` inert
     under a reader that ignores it).
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

## 11. Open questions for adversarial review (r13)

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
`writeConfirmState`).

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
