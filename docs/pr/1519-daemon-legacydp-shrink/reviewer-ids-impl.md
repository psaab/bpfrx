# #1519 capstone-delete — reviewer task/job IDs

Tracks all Codex and AGY plan-review + code-review rounds for the
capstone-delete branch (`refactor/1519-daemon-legacydp-shrink-impl`).

Distinct from `reviewer-ids.md` which tracks the round-1 PLAN-KILL'd
shrink branch (`refactor/1519-daemon-legacydp-shrink`).

## Plan review

### Round 1 (plan-impl v1)

- Codex: task `bvbk382ym` → PLAN-NEEDS-MINOR (3 findings: 1×P2,
  2×P3). P2 = fictional `conntrack.PersistentNATProvider` /
  `conntrack.SessionCountPublisher` references in row 1 of the
  migration matrix (correct surface is `conntrack.NewGC(d.dp,
  interval)` against the exported `RuntimeDomainProvider` at
  `pkg/conntrack/gc.go:45`; the persistent/sessionCount probes are
  intentionally package-private lowercase names internal to gc.go).
  P3a = cliRuntime described as a strict superset of
  `dataplane.RuntimeDataPlane`; reality per `pkg/cli/runtime.go:11`
  is a strict SUBSET of `dataplane.DataPlane`. P3b = flake loop
  `for i in 1..5` is a single-literal-token no-op in bash. All
  three addressed in plan-impl v1.1.
- AGY: `review-mpm1pdkv-g1sycf` → PLAN-READY (no findings). AGY
  performed hostile-verification against the live codebase + the
  in-flight `refactor/1516-grpcapi-migration @ 0436f386` branch
  and ratified the v1.1 plan. Key confirmations: 16 call sites +
  1 function deletion count via direct grep; dead-code at
  `daemon_scheduler.go:159-161` (both backends satisfy
  `policyScheduleStateUpdater`); telemetry-after-Stop safety via
  walked trace (`d.cluster.Stop()` → `sessionSync.Stop()` →
  `logFinalStats` → `dp.Close/Teardown`, with bpfShim teardown
  only inside `manager.Close()`/`Teardown()`); all five probe
  shapes satisfied by both backends. §10 open questions ratified:
  Q1=hybrid (promote cliRuntime to public, keep api/grpc probes
  daemon-local), Q2=grpcDataPlane locked-in from #1554 branch
  inspection, Q3=both canaries, Q4=keep fibSyncStarter,
  Q5=telemetry safe, Q6=rebase risk small, Q7=smoke load OK.
- Date: 2026-05-25 (Codex), 2026-05-26 (AGY)

### Round 2 (plan-impl v1.2 — locked, not redispatched)

Per repo policy when both reviewers PLAN-READY at round-1, the
plan is locked and we proceed to code when #1554 closes. v1.2
folds in the AGY-confirmed grpcDataPlane shape and AGY's §10
ratifications. No round-2 dispatch.

## Code review

(Populated post-implementation, after #1516/PR #1554 closes and impl
branch is rebased + pushed.)
