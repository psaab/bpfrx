# AGY hostile plan-review — round 10 (plan v10 @ `b4f1c6548`)

Reviewer: AGY (`agy --print-timeout 9m --add-dir <worktree> --print`, from
trusted workspace `/home/ps/git/bpfrx`; read-only). Verbatim output below;
orchestrator fold adjudications recorded in plan v11.

---

### (A) Fold Verification

1. **Double guard under every interleaving**: **FOLDED**
   - **Signal during PHASE 5 vs END-of-PHASE-5 `finishStartup(true)` publish**: `finishStartup(true)` closes `d.startupDone` and sets `startupOK=true`. Any gated executor unblocks, acquires `d.applySem`, and evaluates `d.stopping.Load() || d.runCtx.Err() != nil`. Context cancellation via signal is synchronous, so `d.runCtx.Err() != nil` evaluates to `true` even if `d.runShutdownSequence` has not yet published `stopping=true`.
   - **Interactive CLI exit without ctx cancellation (daemon_run.go:741-748)**: On `shell.Run()` exit, `ctx` is not cancelled, but `Run()` proceeds directly to `runShutdownSequence` (daemon_run.go:756), which publishes `stopping=true` before its `applySem` drain. Any timer released by `finishStartup(true)` sees `d.stopping.Load() == true` under `applySem` and abandons.
   - **Steady-state timer during shutdown**: Evaluates `stopping=true` or `runCtx.Err() != nil` under `applySem` and abandons.

2. **Honest in-flight bound ("not worsened vs master")**: **FOLDED**
   - On master today (daemon_run_shutdown.go:50-58), shutdown drains `applySem` for up to `applyCloseoutDrainTimeout` (5s). If an apply/rollback is already in flight, shutdown waits up to 5s and then proceeds to teardown regardless. Work Item G adds an entry fence (`stopping` / `runCtx.Err()`) under `applySem`, eliminating new rollbacks from entering during/after shutdown. In-flight rollbacks exceeding 5s overlap teardown exactly as on master today.

3. **Compiled-topology predicate**: **FOLDED**
   - `s.compiled` at store_persist.go:111 is the exact pointer returned by `d.store.ActiveConfig()` (store_format.go:56), which PHASE 3 bringup uses to construct `d.cluster` (daemon_run_bringup.go:162).
   - On the `loadCompileFailed` path (store_persist.go:108), `s.compiled` is `nil` and `recoverPendingConfirmLocked` is skipped via early return. `daemon_run_bringup.go:287` catches `loadCompileFailed`, leaves `d.cluster` as `nil`, and enters bootstrap mode safely without starting cluster managers.

---

### (B) Fresh Attacks & (C) Reviewer Attack

#### Finding 1 (MINOR): `d.runCtx.Err()` nil-interface panic hazard on uninitialized `Daemon` test fixtures
- **Evidence**: plan.md:420, plan.md:484-496
- **Impact**: In Go, `context.Context` is an interface. Invoking `.Err()` on a `nil` interface panics. The plan's pseudocode snippet specifies:
  `if d.stopping.Load() || d.runCtx.Err() != nil {`
  Existing test fixtures that construct bare `&Daemon{...}` structs without running `Run()` (such as `rollback_resync_test.go:31,81`, `bootstrap_rollback_test.go:24,74`, `rollback_serialize_test.go:71,150`) do not initialize `d.runCtx`. Calling `executeConfirmedRollback` on those fixtures will panic unless the guard checks `d.runCtx != nil` or `runCtx` is populated in test constructors.
- **Resolution**: Update the pseudocode guard to `d.stopping.Load() || (d.runCtx != nil && d.runCtx.Err() != nil)` (or explicitly list `d.runCtx = context.Background()` in the test-fixture migration inventory).

#### Finding 2 (MINOR): Unbounded `d.applySem.Acquire(context.Background(), 1)` wait during teardown of a wedged apply
- **Evidence**: daemon_apply_commit.go:630, daemon_run_shutdown.go:50-58, plan.md:390-397
- **Impact**: If an in-flight apply is wedged and `runShutdownSequence` times out after its 5s `applyCloseoutDrainTimeout`, shutdown continues while the wedged apply holds `d.applySem`. A confirm timer firing afterwards calls `_ = d.applySem.Acquire(context.Background(), 1)` and blocks indefinitely before reaching the `stopping`/`runCtx` check.
- **Resolution**: While bounded at the OS level by systemd `TimeoutStopSec=20s`, passing `d.runCtx` (if non-nil) to `applySem.Acquire` or checking `d.runCtx.Err() != nil` / `d.stopping.Load()` both before AND after `Acquire` avoids parking the executor goroutine on a wedged semaphore during teardown.

#### Finding 3 (MINOR): Post-`Run()` context cancellation behavior on re-used Daemon instances in tests
- **Evidence**: daemon_run.go:63,86-87, plan.md:407-425
- **Impact**: `startupSignalContext` returns a cancel function `stop` that is deferred at `Run` entry (`defer stop()`). When `Run()` returns, `stop()` cancels `runCtx`. Any subsequent call to `executeConfirmedRollback` on that same `Daemon` instance will observe `d.runCtx.Err() == context.Canceled` and abandon. Production creates one `Daemon` per process lifetime, so this is correct; test helpers that re-use a `Daemon` across multiple test phases after `Run()` completes should be aware of this lifecycle boundary.

---

### Verdict

**PLAN-READY-WITH-NITS**

---

## Orchestrator note

f1 verified (nil-interface panic — also Codex m1); f2 verified (the
parked-executor wedge — folded as the cancellable
`Acquire(runCtxOrBackground())` + error check + test leg 2b; the
before-AND-after check option was subsumed by the cancellable Acquire,
which is strictly stronger); f3 verified as a lifecycle observation —
document-only, folded into the single-use contract comment (the
post-`Run()` cancelled-`runCtx` behavior is CORRECT for production and
only a test-hygiene note). AGY's interleaving analysis in (A) is sound
design reasoning; its claim in item 1 that the interactive path was fully
covered was refuted by Codex's M1 in the same round (applyCancel precedes
the drain), which the v11 first-statement placement closes.
