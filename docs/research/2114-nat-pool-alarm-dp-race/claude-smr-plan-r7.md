# Claude SMR — HOSTILE plan review r7 — #2114 residual

Reviewer: Claude (kimi-k3, in-conversation SMR pass).
Plan under review: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` v7 @
`5de29ed7d`. External r7 inputs: Codex NEEDS-REVISION (2 MAJOR, 4 MINOR);
AGY PLAN-READY-WITH-NITS (0 MAJOR, 1 MINOR).

**VERDICT: NEEDS-REVISION** (2 MAJOR, 3 MINOR). The redesigned gate's
production semantics now pass both reviewers' checks; what remains is test
determinism, the OQ7 scope fork, and mechanical consistency. I adjudicate
the OQ7 fork FOR Codex (ship the narrow recovery guard in this PR) — see
M2. Both reviewers also independently caught the `startupDone` double-close
(AGY r7 nit = Codex r7 MINOR 4a), which alone forces v8.

## MAJOR

### M1. Gate tests: determinism + hermeticity gaps (Codex r7 M1 — all verified)
- **Gate-entry barrier missing**: test (a)'s applySem-freedom assertion
  passes a wrong acquire-then-wait implementation if the contender happens
  to run first. The executor needs a test-only entry signal (a hook
  incremented/signalled immediately before the `<-startupDone` wait) so
  the test knows the executor is AT the gate before contending.
- **Failure-leg coverage is manual, not production**: closing
  `startupDone` with OK=false by hand proves executor abandonment, not
  that PRODUCTION closes it on the plain-phase-error and signal-abort
  paths. Existing tests drive `runStartupOrAbort` directly
  (`startup_signal_5807_test.go:131`) — the failure publish must live
  where those paths reach it (inside `runStartupOrAbort`'s failure
  handling or its wrapper, Once-guarded), and the tests must drive BOTH
  real paths.
- **"Assert NO dispatch" is impossible as specced**: `fireConfirmTimer`
  invokes the executor directly (`store_commit.go:819-820`); the gate is
  INSIDE the executor. The observable is executor-ENTRY (the hook) plus
  no `PromoteRollback`/apply side effects while gated.
- **Hermeticity**: a phase hook cannot conjure a fake dataplane —
  `buildRuntimeDataPlane` hard-codes userspace (`daemon_run.go:53-60`) and
  phase 4 overwrites `d.dp` (`daemon_run_bringup.go:421`); persisted custom
  backend names are rejected (`compiler_validate_strict.go:199`). The plan
  needs a per-Daemon backend-factory seam (test-only var substituted by
  `buildRuntimeDataPlane`). And test (c) should orchestrate the REAL phase
  functions (config-load with stubbed store → manager-init →
  dataplane-setup with the factory seam + `linkDir` override) rather than a
  full host-mutating `Run` — plus a late-manager milestone assertion
  (`snmpBootReady` etc.) so a close placed right after phase 4 cannot pass.

### M2. OQ7 adjudication: ship the NARROW recovery guard in THIS PR (side with Codex over AGY)
The fork: AGY r7 says deferring legacy-coexistence hardening is safe
because the atomic cell covers every reader; Codex r7 says the cell fixes
field tearing only, not the UNSAFE live-topology hybrid itself (HA
election/watchers/VRRP live while the dataplane is torn down into
bootstrap) — which the repo's own preflight classifies as unsafe
(`cluster_topology_preflight.go:27`). Codex is right on the merits:
memory-safety is the floor, not the ceiling, and this review cycle has
overturned every "safe by deferral" claim once the evidence deepened.
The NARROW guard is small and cleanly testable at the configstore seam:
**at confirm-record recovery, if `rec.FirstCommit` AND the recovered
active config has `Chassis.Cluster != nil`, resolve the window as expired
(keep the active config, remove the record, loud log) instead of re-arming
a rollback into bootstrap-with-cluster** — matching the preflight's own
"topology transitions are boot-only" philosophy. Tests: (i) legacy
empty-`GuardedHash` record → guard fires; (ii) matching nonempty-hash
record (rollout-interval) → guard fires; (iii) standalone `FirstCommit`
record → rollback proceeds unchanged. The BROADER cluster-runtime
lifecycle question (should `enterBootstrapMode` stop cluster comms when
`d.cluster != nil`) stays a follow-up. With the guard shipped, the §2
coexistence documentation becomes historical-but-guarded rather than
accepted.

## MINOR

### m1. Double-close guard (AGY r7 nit = Codex r7 MINOR 4a — independent collision)
Literal `defer close(startupDone)` plus the success close panics on normal
shutdown. Specify `d.finishStartup(ok bool)` — a `sync.Once`-guarded
outcome publisher: `once.Do(func() { if ok { startupOK.Store(true) };
close(startupDone) })`, called at the linearization point with `true` and
from the failure paths with `false`.

### m2. Linearization overclaim + final point (Codex r7 MINOR 4b)
v7's "no apply concurrent with server construction" is false for the
before-exposure point (a rollback promoted before gRPC snapshots
`ActiveConfig` at `daemon_run_servers.go:216` runs exactly that race).
Move the linearization to the END of PHASE 5 (after `startGRPCServer`,
before PHASE 6): the dispatched rollback is then EXACTLY equivalent to a
remote commit arriving at first contact — the only point with zero new
concurrency semantics. The timer's rollback simply waits a few
milliseconds longer.

### m3. Mechanical consistency (Codex r7 MINORs 1-3, verified)
- Preamble: narrow "every APPLY-class reader" to "every apply-PIPELINE
  reader (`applyConfigLocked` and its callees)" — the NAT gate
  (`daemon_natpoolalarm.go:101`) lives on the exit path, not the rollback
  apply path; its row stays APPLY/BOOT-SYNC with a note.
- `bootstrap.go:472,473` row gains the `(pre-gate)` qualifier.
- The "RACE-2 reaches only standalone/bootstrap" and "unreachable via
  exclusion" statements get current-version qualifiers (with the guard
  shipped, the legacy scenario is prevented going forward).
- Citations: executor dispatch `store_commit.go:819-820`; recovered nil
  assignment `store_persist.go:239-240`; preflight call
  `daemon_apply_commit.go:558`.
- Fixture migration adds `rollback_serialize_test.go:71,150,201,247`.

## Disposition required for v8

1. `finishStartup(ok)` Once-guarded publisher; failure publish reachable
   from BOTH real failure paths (m1, M1).
2. Linearization moved to end-of-PHASE-5 (m2).
3. Gate tests: entry hook, dual real-path failure coverage, executor-entry
   + no-side-effects assertion, backend-factory seam, phase-level
   orchestration + late-manager milestone (M1).
4. Narrow recovery guard (`FirstCommit` && cluster active config →
   resolve-as-expired before manager construction) + three tests, IN this
   PR (M2); broader cluster-lifecycle work stays follow-up.
5. Mechanical fixes (m3).
