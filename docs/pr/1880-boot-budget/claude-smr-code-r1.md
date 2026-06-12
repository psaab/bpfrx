# PR #1883 — Claude SMR hostile code review, round 1

Scope reviewed at c6f08ab4a298 (incl. Codex code-r1 + AGY code-r1
fixes). I am the implementation author; this pass deliberately attacks
my own weakest joints rather than re-narrating the diff.

## Attacks attempted

1. **Deadlock hunt.** Lock order is reloadMu → retryMu everywhere
   (commitManagedSection holds reloadMu and calls
   noteReloadOutcomeLocked → ensureRetryLocked/signalRetryCancel which
   take only retryMu; the retry goroutine takes reloadMu in
   retryReloadOnce and retryMu only after releasing it, in
   clearEpisodeIfMine at exit). signalRetryCancel never blocks on the
   goroutine — cancellation is signal-only; the only blocking join is
   Stop()'s retryWG.Wait(), which runs without any manager lock held.
   No cycle found.
2. **Two-retries-interleaved.** A cancelled-but-draining episode can
   coexist with its replacement, but BOTH exec under reloadMu, and the
   drainer's first action under the lock is ctx.Err() → exit; its
   self-clean is identity-guarded (clearEpisodeIfMine). The drainer can
   never exec, never clears the new episode's fields, and is reaped by
   retryWG. Verified by TestSuccessCancelsRetryEpisode (exact exec
   count) under -race.
3. **Stop() vs in-flight commit.** Codex M1 fix: disable under retryMu
   before Wait. Attack: commit already PAST the disable check with an
   Add done — then Wait covers it (Add happened-before Wait via
   retryMu). Commit not yet at the check — observes disabled, no
   spawn. No Add-after-Wait interleaving remains.
4. **Re-arm guard recursion/duplication (my H1 fix).** The deferred
   re-arm runs while reloadMu is still held (LIFO before the unlock)
   and ensureRetryLocked is idempotent on a live episode — at most one
   episode results even when noteReloadOutcomeLocked already ensured.
   Hard-failure path pinned by TestHardFailureReArmsRetry.
5. **Sentinel misuse.** ErrFRRReloadDegraded is returned ONLY from the
   fallback-success path; double failure returns the vtysh error
   (asserted non-degraded in TestReloadFallbackErrorPropagated). The
   double-%w keeps ENOENT classification live through the sentinel
   (TestPytoolsMissingClassification).
6. **Gauge visibility.** Codex M2 fix moves emission before the dp
   gate; nil-DP canary added (TestFRRReloadDegradedGauge), descriptor
   coverage canary extended. Emitted-but-undeclared (#1635 class)
   covered by the pedantic-registry test.
7. **Harness semantics.** Phase 4 wall-clock loop cannot busy-spin
   (wait_for_instance sleeps 1s on failure); budget message reports
   true elapsed. sysrq exec bound: live evidence shows timeout alone
   is insufficient (incus exec forwards SIGTERM to the dead session)
   and -k's SIGKILL fired correctly in validation run 1; bash's
   "Killed" notice suppressed at all three sites (incl.
   test-double-failover.sh, whose unbounded execs were the same latent
   hang). Residual divergence: test-double-failover's Phase-4
   iteration-counted wait — follow-up, not this PR's converged scope.
8. **Behavioral parity for existing callers.** ApplyFull/Clear callers:
   applyFRRConfig (warn-and-continue, now degraded-aware) and xpfd
   cleanup (one-shot, loud log, exit 0). Clear() returning errors is a
   contract change ONLY for cleanup, which handles it. grep found no
   other callers.

## Verdict

MERGE-READY from the SMR seat, contingent on: (a) Codex + AGY
round-2 confirmation of their fix resolutions, (b) the second
consecutive first-run-after-deploy failover pass (run 1: 14/14,
exit 0, 23.0 Gbps).
