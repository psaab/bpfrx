# Claude SMR hostile plan-review — round 11 (plan v11 @ `a89504f6b`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r11 verifies
the v11 folds of the r10 findings (mine + Codex's + AGY's) against
worktree code and mounts fresh attacks on the v11 delta. All line numbers
re-verified (origin/master `ed6999000` + plan-doc-only branch; plan items
are unimplemented — verification is of claims ABOUT code).

## A. Fold verification (r10 findings → v11)

1. **Codex M1 → first-statement Store** — v11 pins
   `stopping.Store(true)` as the FIRST statement of `runShutdownSequence`,
   before `d.applyCancel()` (`daemon_run_shutdown.go:34-35`), with the
   actual-path test's injected `applyCancel` asserting the flag is
   already raised. The interactive-exit admission window (no ctx
   cancellation, `daemon_run.go:741-748`) is now closed by construction:
   every entry into the shutdown sequence raises the flag before ANY
   other shutdown action. FOLDED.
2. **Codex M2 → pre-migration hash capture** — verified the full chain:
   `journalConfigHash = sha256(tree.Format())`
   (`store_persist.go:334-341`); DB persistence is
   `json.MarshalIndent(tree)` (`db.go:435-457`), NOT `Format()` — so the
   commit-vs-Load hash equivalence rests on
   `Format(jsonRoundTrip(tree)) == Format(tree)`. That round trip is
   shape-stable (Keys/Children are order-preserving slices; the Inactive
   bool marshals losslessly; the file-level encryption wrapper is
   transparent to tree shape) — and EMPIRICALLY proven by the passing
   #5835/#4577 recovery tests on master (ordinary records bind correctly
   across restarts today). The only divergence sources are the Load-time
   MIGRATIONS — the retire rewrite (`store_persist.go:65`) and the
   sanitize pass (:75-82) — which is exactly what v11's pre-migration
   capture removes from the binding. The migrated tree still drives
   compile (the guard's `s.compiled` predicate is unaffected).
   `isRetiredDataplaneLeaf`'s missing Inactive check re-verified
   (`dataplane_retire.go:215-224`). FOLDED. Bonus: the fix closes the
   stale-drop for EVERY record class, not just H's — a genuine master
   #4577 defect dies here.
3. **Codex M3 → adjudicated documented-consistency** — my own r10
   adjudication; re-verified the load-bearing links this round: the
   daemon never writes DB state to `xpf.conf` (all config writes go to
   `.configdb/` via `fsatomic.WriteFileDurable`,
   `db.go:216,290,458`); `shouldBootstrapFromFile(false, false)` is true
   (`bootstrap.go:77-79`) so BOTH the expired path and the guard path
   reach the same import; the HA-node boot class resolves NORMAL via the
   node-id guard BEFORE the everCommitted check
   (`bootstrap.go:243-245`) — no bootstrap-mode hybrid can arise
   post-guard. The guard's safety goal (no live-cluster-runtime +
   bootstrap-mode rollback) is achieved regardless of what the seed
   re-establishes. FOLDED as documented; suppression remains rejected.
4. **AGY f2 → cancellable Acquire** — v11:
   `Acquire(d.runCtxOrBackground(), 1)` with the error CHECKED and the
   `defer Release` AFTER the error check (no release-without-acquire).
   `x/sync/semaphore.Weighted.Acquire` returns `ctx.Err()` on
   cancellation — prompt. Test leg 2b parks the executor behind a held
   semaphore and cancels. FOLDED.
5. **Codex m1 / AGY f1 → nil-safe guard + fixtures** — v11:
   `(d.runCtx != nil && d.runCtx.Err() != nil)`; fixtures init
   `runCtx: context.Background()`; `runCtxOrBackground()` mirrors
   `applyCancelCtx` (`daemon_apply.go:118-125`). FOLDED.
6. **Codex m2 → signal-child wiring leg** — leg 3b asserts the stored
   context is the child derived at `daemon_run.go:86`. FOLDED.
7. **Codex m3 → narrowed claim** — invariant 11 now admits the
   admission-timing shift openly (likelihood up; body length and worst
   case unchanged). Accurate. FOLDED.
8. **Codex m4 → db.go docs** — `db.go:161-168` + the #5835 binding
   comment (`store_commit.go:543-548`) join the sweep. FOLDED.

## B. Fresh attacks on the v11 delta (all MOUNTED, all FAILED — plan survives)

**Attack 1 — gate wait cancellability.** The `<-d.startupDone` wait is
NOT context-cancellable: a waiter parks there on a failed startup until
the publish. But v9/v10 already guarantees the publish on EVERY exit
path (both real failure returns inside `runStartupOrAbort`, PLUS the
Run-scoped `defer d.finishStartup(false)` for panic/unwind — verified
the defer ordering: defers run during panic unwinding, `sync.Once`
idempotent). A process-fatal exit kills the waiter with the process. No
leak class remains. FAILED.

**Attack 2 — abort-path first-statement Store vs the failure publish.**
`runStartupOrAbort`'s teardown IS `runShutdownSequence`, so the abort
path now publishes `stopping` at teardown start. The v9 ordering pin
(publish `finishStartup(false)` BEFORE `teardown(err)`) means gate
waiters abandon at the `startupOK` check before the guard matters; a
waiter racing past that check into `Acquire(runCtxOrBackground())` hits
the cancelled signal context (the abort path is signal-driven — ctx is
already cancelled) and abandons. No harmful interleaving. FAILED.

**Attack 3 — other `journalConfigHash(s.active)` consumers.** Grepped:
the only correctness consumer of the binding is recovery's :159 check;
journal-entry `ConfigHash` fields are audit logging, not binding. The
fix threads a dedicated pre-migration variable — no collateral change
to journal content. FAILED.

**Attack 4 — shared revert helper vs `s.candidate` at Load.** The
expired branch's candidate reset is guarded `if s.candidate != nil`
(`store_persist.go:208-211`); at Load the candidate is nil
(EnterConfigure creates it later), so the shared helper's candidate
step is a no-op on both paths. FAILED.

## C. Findings

None. Zero MAJOR, zero MINOR. This is the first round I can find no
defect in the plan delta — but note the review history: r8-r10 each
found REAL holes (shutdown fence, #4577 semantics, recurrence, fence
timing, raw-scan predicate, hash-binding, placement), and this READY
verdict rests on those folds being verified, not on the plan having
been sound earlier. The M3 adjudication (documented-consistency, not
suppression) is mine and is recorded openly in the plan for Codex/AGY
to overrule with a concrete counterexample.

## Verdict

**PLAN-READY** — conditional on no reviewer producing a concrete
counterexample to the M3 adjudication or a new break in the v11 delta.
