# Claude SMR — HOSTILE plan review r4 — #2114 residual

Reviewer: Claude (kimi-k3, in-conversation SMR pass).
Plan under review: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` v4 @
`e9ac48db1`. External r4 inputs: Codex NEEDS-REVISION (1 MAJOR + 5 MINOR;
fold ledger M1 FOLDED, M2/M3 PARTIAL, MINORs 1/2 FOLDED, 3 PARTIAL); AGY
**PLAN-READY** (all folds verified, no new findings).

**VERDICT: NEEDS-REVISION** (1 BLOCKER, 2 MAJOR, 3 MINOR). Codex's r4 major
is real and I verified both chains end-to-end before folding; it does not
change the architecture (A1 covers all three races), only the plan's
completeness claims and the test matrix. Convergence remains close: AGY is
PLAN-READY, Codex's remaining items are completeness/precision, none
architectural.

## BLOCKER

### B1. RACE-3: the recovered commit-confirmed rollback timer races the boot publication (Codex r4 M1 chain B — verified)
Verified end-to-end:
1. `executeConfirmedRollback` is registered at daemon init, BEFORE any
   startup phase (`daemon_run.go:129-135`).
2. Phase-1 `Store.Load` re-arms a pending commit-confirmed timer for the
   remaining window — arbitrarily short (`store_persist.go:231-238`).
3. The timer goroutine invokes the executor without `s.mu`
   (`store_commit.go:815`); the executor takes `d.applySem`
   (`daemon_apply_commit.go:629-631`) and runs the rollback: first-commit
   rollback reads `d.dp` at `bootstrap.go:472-473`; a non-nil rollback
   enters `applyConfigLocked` and reads `d.dp` at
   `daemon_apply_dataplane.go:98` and onward.
4. The boot writers (`daemon_run_bringup.go:448,464,469,497`) do NOT hold
   applySem — phase 3 runs straight-line on the Run goroutine.
So on ANY restart inside a commit-confirmed window, the recovered timer can
fire during phase 3 and read `d.dp` concurrently with the boot assignment —
a third structural race, reachable with zero operator exoticism (operator
issues `commit confirmed`, reboots within the window). Not covered by the
watcher-chain (RACE-1) or bootstrap-exit (RACE-2) framings. A1 fixes it
(atomic publication is unconditional); the plan must document RACE-3 and
add a timer-shape regression (same two-sided gate: gate the boot
`setDataplane(dp)` publication against a rollback-shape `d.dataplane()`
read — or drive the REAL `executeConfirmedRollback` with a gated
PromoteRollback — design freedom noted for /engineer).

## MAJOR

### M1. `daemon_ha_userspace_readiness.go:202` is RACE-1-exposed via the watcher (Codex r4 M1 chain A — verified)
Promotion in the watcher handler calls `removeBlackholeRoutes`
(`daemon_ha.go:310`, demotion equivalent `:359-360` → `:1064-1066`), which
calls `userspaceDataplaneActive()` (`daemon_ha.go:1124`), which reads
`d.dp` at `daemon_ha_userspace_readiness.go:202`. The readiness `:202` row
must leave the "uniformity" bucket and join the RACE-1 set
(`:297,299,337,348,362,367` + `:202`). `:230,:233` stay uniformity.

### M2. Residual table/prose inconsistencies (Codex r4 M2 — all verified)
- `plan.md:105` still says "128 readers" — must be 129.
- §2 RACE-2 enumeration still lists `daemon_run_shutdown.go:161` — the
  HA-only clear is exclusion-unreachable; only `:214` belongs.
- Stream rows: `:122` is mixed standalone/HA (standalone launch
  `daemon_run.go:369`, cluster launch `daemon_ha_sync.go:1176`);
  `:67,:235,:259` are HA-context (`:67` capture-once at goroutine start in
  either launch context; `:235` PER-CALLBACK — not capture-once — in the
  full-resync path; `:259` capture-once in the HA fallback loop). §5.3
  rule 6 must drop `:235` (it belongs under per-invocation, rule 7).
- Callback registration guard cite is `daemon_run.go:284`, not `:288`.

## MINOR

### m1. Teardown quiescence rule needs teeth (Codex r4 MINOR 1)
A stopped counter over a short window does not prove the 1 s loop exited.
Spec: the fake `ProcReader` records entries under a mutex (synchronized
counter), returns a successful stat so the sample completes, and after
`cancel(ctx)` the test requires a sustained quiescence of ≥2×
`SampleInterval` (≥2.5 s margin) with zero new `ReadSelfStat` calls —
bounded, so the test cannot hang.

### m2. Typed-nil test matrix must cover every guarded kind (Codex r4 MINOR 3)
The guard switches over Chan/Func/Map/Pointer/Slice/UnsafePointer; the
matrix lists pointer/value/named-slice. Make it table-driven over all
nillable kinds (typed-nil named map, chan, func, slice, pointer) plus the
value-receiver success case, or the "all shapes" invariant text
(`plan.md:478`) overclaims.

### m3. Comment sweep still incomplete (Codex r4 MINOR 5 — verified)
Add: `daemon_apply_commit.go:156` ("one-way"), `daemon_natpoolalarm.go:88`
("exactly once" vs discard-and-rearm at `:118-126`),
`cluster_topology_preflight.go:59` (second stale `daemon_run.go:1868`
cite).

## Disposition required for v5

1. Document RACE-3 (§2) with the four-link evidence chain + add the
   timer-shape `-race` regression (B1).
2. Move readiness `:202` into the RACE-1 set; split the readiness row (M1).
3. Fix the four prose/table residuals (M2).
4. Teardown quiescence spec; typed-nil matrix over all kinds; three more
   comment-sweep entries (m1-m3).

Architecture unchanged. With these folded my r5 verdict is PLAN-READY.
