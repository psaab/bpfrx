# Codex hostile plan-review — round 10 (plan v10 @ `b4f1c6548`)

Reviewer: Codex (companion task `task-mrykb2ts-9b11zc`, session
`019f92d2-71cc-7061-8907-47af35e317d1`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications recorded in plan v11.

---

Fold verification:

1. PARTIAL — The signal-driven arm holds: Run derives the signal context at pkg/daemon/daemon_run.go:86, and gRPC/HTTP teardown starts only after that context's Done closes at pkg/grpcapi/server.go:486-493 and pkg/api/listener.go:64-93, so runCtx.Err() is guaranteed non-nil for PHASE-5/6 signals. The interactive arm remains under-specified because v10 requires stopping only before the drain at docs/research/2114-nat-pool-alarm-dp-race/plan.md:412-430, while shutdown begins earlier with applyCancel at pkg/daemon/daemon_run_shutdown.go:25-36.

2. FOLDED — The five-second limit and possible post-timeout overlap are honestly admitted at docs/research/2114-nat-pool-alarm-dp-race/plan.md:931-950 and pkg/daemon/daemon_run_shutdown.go:50-58. No bounded WaitGroup-style join improves this: the rollback is deliberately non-cancellable at pkg/daemon/daemon_apply_commit.go:693-698; absolute exclusion requires either an unbounded wait or cancellable/recoverable apply semantics. The "not worsened" wording still needs narrowing, below.

3. PARTIAL — s.compiled is authoritative: Load assigns it before recovery at pkg/configstore/store_persist.go:81-113, ActiveConfig returns it at pkg/configstore/store_format.go:55-60, and cluster construction reads it at pkg/daemon/daemon_run_bringup.go:161-164. Compile failure returns before recovery and boots without a cluster at pkg/configstore/store_persist.go:82-108 and pkg/daemon/daemon_run_bringup.go:287-301,352-370. However, pre-recovery hash mutation can bypass H, and H's own nil compiled result can be replaced by bootstrapFromFile before PHASE 3.

4. PARTIAL — Test leg 3 drives the real shutdown function, but it proves only publication before the drain at docs/research/2114-nat-pool-alarm-dp-race/plan.md:1076-1083. Since applyCancel precedes that drain at pkg/daemon/daemon_run_shutdown.go:35-53, the test does not prove the stronger ordering actually required.

5. FOLDED — The source "Two outcomes" contract and README prose are both scheduled at docs/research/2114-nat-pool-alarm-dp-race/plan.md:870-875, matching pkg/configstore/store_persist.go:127-135 and pkg/configstore/README.md:417-449.

6. FOLDED — The monotonic, unsupported-second-Run lifecycle is documented at docs/research/2114-nat-pool-alarm-dp-race/plan.md:436-443, and production constructs one runner and invokes Run once at cmd/xpfd/main.go:490-507.

New findings:

MAJOR — Interactive shutdown still allows a rollback to be admitted after shutdown begins. A conforming implementation can place stopping.Store(true) after d.applyCancel() but immediately before the drain, satisfying plan.md:427-431 and the proposed actual-path test. Interactive CLI exit leaves runCtx uncancelled at pkg/daemon/daemon_run.go:741-756; a timer scheduled between applyCancel and the Store can therefore acquire applySem, observe both guards false, and begin non-cancellable rollback work. If it exceeds five seconds, teardown proceeds over it. Require stopping.Store(true) as the first action in runShutdownSequence, before pkg/daemon/daemon_run_shutdown.go:35, and have the test's injected applyCancel assert that stopping is already true.

MAJOR — A valid same-generation confirm record can be misclassified as stale before Work H runs. Load mutates the raw tree through retired-dataplane rewriting and sanitization at pkg/configstore/store_persist.go:65-75, then compares GuardedHash against the mutated tree at :159-165. In v10's recurrence state, a strict FirstCommit cluster candidate can also contain an inactive retired leaf: inactive nodes are pruned before validation at pkg/config/compiler.go:2257-2268, while CommitConfirmed persists and hashes the raw candidate at pkg/configstore/store_commit.go:407-410,437,543-549. On reboot, rewriteRetiredDataplaneType deletes that leaf without checking Node.Inactive at pkg/configstore/dataplane_retire.go:184-224, changing the Format hash. Recovery deletes the record as stale and returns before H, silently retaining the unconfirmed cluster config. Capture the on-disk hash before all Load migrations, use that for generation binding, and add this recurrence regression.

MAJOR — H's revert can be undone later in the same boot. The proposed guard sets s.compiled=nil at docs/research/2114-nat-pool-alarm-dp-race/plan.md:562-566 and returns a successful Load. PHASE 1 then sees ActiveConfig()==nil with no compile-failure flag and invokes bootstrapFromFile at pkg/daemon/daemon_run_bringup.go:313-334, per pkg/daemon/bootstrap.go:65-79. That path reads xpf.conf and performs a permanent plain commit at pkg/daemon/daemon_apply_commit.go:14-61; PHASE 3 constructs a cluster from this replacement compiled config at pkg/daemon/daemon_run_bringup.go:161-164. If xpf.conf contains the same unconfirmed cluster configuration, H has effectively made it permanent, violating plan invariant 12 at plan.md:951-957. Recovery needs an explicit outcome that suppresses bootstrap-file import for this boot, plus a full loadAndBootstrapConfig regression.

MINOR — The runCtx fixture migration is incomplete. The proposed expression calls d.runCtx.Err() at plan.md:420, but plan.md:484-497 initializes only startupDone/startupOK. The bare executor fixtures at pkg/daemon/rollback_resync_test.go:31,81, pkg/daemon/bootstrap_rollback_test.go:24,74, and pkg/daemon/rollback_serialize_test.go:71,150,201,247 will reach a nil context.Context and panic. Initialize runCtx with context.Background(), make the guard explicitly nil-safe, or reuse the nil-safe applyCancelCtx at pkg/daemon/daemon_apply.go:118-125.

MINOR — Production runCtx binding is not fail-on-revert tested. Leg 2 manually injects a cancellable field at plan.md:1074-1076, while the existing test only verifies startupSignalContext itself at pkg/daemon/startup_signal_5807_test.go:16-42. Neither catches Run omitting the assignment or storing the raw parent from pkg/daemon/daemon_run.go:70 instead of the signal child created at :86.

MINOR — "Does not worsen the IN-FLIGHT class" is too categorical at plan.md:944-947. The gate delays an early-fired timer until END-of-PHASE-5 at plan.md:390-397,452-453, whereas master acquires immediately at pkg/daemon/daemon_apply_commit.go:629-631. This can shift work that master might have completed during startup next to a later signal, increasing overlap likelihood. It does not lengthen the admitted body or enlarge the existing worst case; state that narrower claim.

MINOR — The recovery documentation sweep still misses pkg/configstore/db.go:161-168, which promises that every future-deadline record is re-armed. Work H introduces a future-deadline FirstCommit+cluster exception, but plan.md:870-875 schedules only store_persist.go and the README.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v11)

All findings code-verified before folding; M3 adjudicated differently than
proposed, with the reasoning recorded in the plan:

- M1 (first-statement Store) VERIFIED — `runShutdownSequence` opens with
  `if d.applyCancel != nil { d.applyCancel(); ...drain }`
  (`daemon_run_shutdown.go:34-58`); "before the drain" admits a
  placement after applyCancel with an interactive-exit window. Folded:
  Store as FIRST statement; injected-applyCancel ordering assertion.
- M2 (hash-mutation stale-drop) VERIFIED — Load mutates before recovery
  (`store_persist.go:65` retire rewrite, `:75-82` sanitize); recovery
  hashes the MUTATED `s.active` (:159); commit hashed the RAW promoted
  tree (`store_commit.go:543-549`); `isRetiredDataplaneLeaf` has NO
  Inactive check (`dataplane_retire.go:215-224`); the compiler prunes
  inactive pre-validation (`config/compiler.go:2257-2268`). A
  pre-existing master #4577 violation for every record class; bypasses H
  in the recurrence state. Folded: pre-migration hash capture for the
  binding (migrations still drive compile); regression (viii);
  #5835 binding comment update.
- M3 (bootstrapFromFile undo) VERIFIED AS INTERACTION, ADJUDICATED AS
  DOCUMENTED-CONSISTENCY — H's end state is bit-identical to the expired
  path; master's expired path hits the same `shouldBootstrapFromFile`
  import (`bootstrap.go:77-79`, `bringup:313-334`); the daemon never
  writes DB state to the seed file (writes go to `.configdb/`); on an HA
  node the boot class resolves NORMAL via the node-id guard
  (`bootstrap.go:243-245`) — no hybrid is possible post-guard, which is
  the guard's actual safety goal. Suppression would strand the node and
  diverge from #4577's own expired path — REJECTED, stated openly for
  reviewer overrule; parity regression (ix) added.
- m1 (nil runCtx panic) VERIFIED (also AGY f1) — folded: nil-safe guard
  + `runCtx: context.Background()` in fixtures + `runCtxOrBackground()`
  helper (mirrors `applyCancelCtx`, `daemon_apply.go:118-125`).
- m2 (runCtx binding test) VERIFIED — folded: leg 3b signal-child
  wiring assertion.
- m3 ("not worsened" too categorical) VERIFIED — folded: narrowed claim
  (no longer body, no larger worst case; admission timing shift can
  increase overlap likelihood — stated openly).
- m4 (db.go docs) VERIFIED — `db.go:161-168` confirmRecord doc promises
  unconditional re-arm; folded into §5.5.

AGY r10 findings folded in the same pass: f1 = Codex m1; f2 (unbounded
Acquire wedge) VERIFIED — folded as cancellable
`Acquire(runCtxOrBackground())` with error check + test leg 2b; f3
(post-Run `stop()` cancels runCtx) — document-only lifecycle note, folded
into the single-use contract comment.

Verdict recorded: **NEEDS-REVISION (3 MAJOR, 4 MINOR)**.
