# Claude SMR — HOSTILE plan review r2 — #2114 residual

Reviewer: Claude (kimi-k3, in-conversation SMR pass).
Plan under review: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` v2 @
`61568128f`. External r2 inputs: Codex NEEDS-REVISION (6 MAJOR, 3 MINOR);
AGY PLAN-READY-WITH-NITS (1 MAJOR, 2 MINOR, all four of its r1 findings
FOLDED).

**VERDICT: NEEDS-REVISION** (2 BLOCKER, 3 MAJOR, 3 MINOR) — all fixable by
editing, none architectural. A1 still stands; v2's remaining defects are
precision defects, three of them regressions INTRODUCED by v2's own folds
(the over-broad "class D eliminated" swing, the reflect-guard panic, the
non-deterministic test spec).

Independently verified every load-bearing claim from both external reviews
against source before folding anything (line cites below). Where Codex and
AGY disagree (twice), I adjudicate with code evidence.

## BLOCKER

### B1. The typed-nil guard as drafted panics at Store time (Codex r2 M1 = AGY r2 M1 — two-reviewer collision)
`reflect.ValueOf(dp).IsNil()` panics for non-nillable concrete kinds
(struct values). `RuntimeDataPlane` (`pkg/dataplane/apply.go:18`) has no
pointer-only constraint and the registry (`dataplane.go:152,215`) returns
arbitrary constructor results unchecked; a value-type test fake would crash
the daemon. v3 must kind-gate:
```go
if dp == nil { d.dpCell.Store(nil); return }
if v := reflect.ValueOf(dp); v.Kind() == reflect.Pointer && v.IsNil() {
    d.dpCell.Store(nil); return
}
```
plus unit tests for BOTH a typed-nil pointer fake and a value-receiver fake.
Verdict on both reviews: VALID, fold verbatim.

### B2. The bootstrap+live-cluster recurrence (v2 §2/§5.4) is UNREACHABLE — Codex r2 M5 is right; v2 over-corrected
I verified Codex's four-link proof end-to-end:
1. compile-failed boot ⇒ `ActiveConfig() == nil` (`daemon_run_bringup.go:287`);
2. `d.cluster` constructed EXACTLY ONCE, at boot, only from a non-nil active
   cluster config (`daemon_run_bringup.go:164`; documented
   `cluster_topology_preflight.go:117`);
3. standalone↔cluster topology transitions are REJECTED at commit
   (`daemon_apply_commit.go:551-557` `clusterTopologyCommitPreflight`) and a
   peer SyncApply that would transition returns BEFORE `applyConfigLocked`
   (`daemon_apply_commit.go:364-379`);
4. `enterBootstrapMode` fires only for a nil rollback target
   (`daemon_apply_commit.go:650-652`) — the never-committed path, which
   cannot follow a config that had a live cluster runtime.
So a live cluster runtime and bootstrap mode are mutually exclusive — but
NOT for v1's stated reason (nodeID⇒normal, which IS false: compile-failed HA
nodes bootstrap). The correct invariant is the four-link one above.
Consequence for v3: restore a precise class distinction — HA background
readers (`daemon_ha*.go`, fabric, `daemon_health.go:141`) race RACE-1 (boot
publication) but CANNOT race RACE-2 (the bootstrap-exit writer). The uniform
conversion is unchanged (RACE-1 alone reaches them, and uniformity is the
issue's requirement #1), but the plan's race-reachability narrative must be
exact. AGY's r1 MAJOR remains credited (it killed the false nodeID proof);
its reachability scenario does not survive the preflight evidence. I own the
v2 adjudication error — I upheld AGY's scenario without finding the
preflight links.

## MAJOR

### M1. Structural sampler-only (Codex r2 M2) beats comment-level (AGY r2 Q3) — side with Codex
The disagreement: AGY says a doc comment + test pin suffices; Codex demands
the adapter be unable to satisfy `Build`. Verified facts: the sampler only
ever calls `CachedStatus` (`sampler.go:113-125`); `DataPlaneAccessor`
requires only `IsLoaded`+`GetMapStats` (`builder.go:35-41`); `Build` keys
`isUserspace` on `Status()` PRESENCE (`builder.go:116-123`) and maps a
Status error to `StateUnknown` (:219); `NewSampler` has exactly ONE
production caller (`daemon_run.go:595`) and two test callers
(`sampler_test.go:69,106`). Resolution: narrow `NewSampler` to a
`CachedStatusProvider` interface (`CachedStatus() (userspace.ProcessStatus,
bool)` — sampler.go already imports userspace), drop the per-tick type
assertion in `sample()`, and reduce the daemon adapter to the single
`CachedStatus` method probing per call. The adapter then structurally CANNOT
satisfy `DataPlaneAccessor`/`Build` — misuse is a compile error, matching
this repo's compile-time-invariant discipline (engineering-style.md). Cost:
one interface + signature change in `pkg/fwdstatus` (revises v2's
"pkg/fwdstatus untouched" claim — accepted, it is 3 files: sampler.go,
sampler_test.go, daemon_forwarding_status.go); `IsLoaded`/`GetMapStats`/
`Status` leave the daemon adapter (no production callers — verified; the
existing daemon-side tests get rewritten against the narrowed shape);
`userspaceDataplaneStatus()` helper becomes dead and is removed,
`userspaceDataplaneCachedStatus()` retained. `Build`, grpcapi, cli untouched.

### M2. Real-sampler determinism via the synchronous prime (Codex r2 M3)
`Sampler.Start` runs `s.sample(time.Now())` SYNCHRONOUSLY before launching
the loop (`sampler.go:64-67`). v3 must specify the exact barrier: blocking
fake `CachedStatus` (entered-channel + release-channel), start the REAL
sampler, wait for the priming sample to enter the fake, run
`armBootstrapExitDataplane` with the failing Start, release, cancel, join —
a deterministic sampler-tick-vs-writer overlap with zero new seams. Barrier
the direct status/probe reader loops the same way. VALID, fold.

### M3. Audit table: my head-truncated grep under-enumerated (Codex r2 M4)
Root cause confirmed: my r1 evidence grep was piped through `head -80`; the
v2 table silently inherited the truncation. The untruncated per-file totals
(128 greppable production lines incl. comments; pattern
`'d\.dp\b|a\.daemon\.dp\b'`) show the v2 table omitted:
`daemon_apply_dataplane.go:397,459,463,482,485,497,501,505`;
`daemon_ha.go:842,1531,1545`; `daemon_ha_sync.go:1165,1297`;
`daemon_run_naming.go:231`; and listed `:458` (the `deferSetter` type decl)
where the selector is `:459`. v3 regenerates the table from the untruncated
grep with exact counts (also correcting "5 W + ~159 reads" — the 159 figure
includes the 5 writes and comment lines).

## MINOR

### m1. Transition test start-state (Codex r2 MINOR 1)
Old `forwardingStatusDataplane()` returns nil immediately when `d.dp == nil`
at construction (`daemon_forwarding_status.go:123-125`) — starting the test
at nil fails old code for the wrong reason. With the M1 narrowing the point
is moot for `Status` (adapter no longer has one), but the probing test still
starts `readyProbeOnlyFake → userspaceFake → nil` to prove per-call
capability adaptation. Fold.

### m2. Option D rejection must use valid arguments (Codex r2 MINOR 2)
`dpOwner == nil && !dpPresent` DOES represent never-constructed, and the
tear argument assumed violating D's own invariant. Reject D on its real
weaknesses: two-word state (flag-then-load ordering discipline required of
every reader with no compiler help; identity lost for post-clear
introspection — `%T` logging, final-stats-on-shutdown); A1 carries
identity+presence in one atomic word; D's only edge (no per-store
allocation) is noise at ≤5 stores/lifetime. Fold.

### m3. Docs/comment sweep additions (Codex r2 MINOR 3 + AGY r2 MINOR 1/2)
Add: `pkg/daemon/README.md:936` live `d.dp.ApplyConfig` reference; stale
"one-way"/"at most once" bootstrap-exit comments at
`daemon_run_naming.go:200-206`, `bootstrap.go:284-289`,
`daemon_apply.go:213-220` (contradict the rollback recurrence the plan now
tests — reword, don't redesign); canary `canaryExprString` needs
`*ast.IndexExpr`/`*ast.IndexListExpr` support for the generic
(`retirement_boundary_canary_test.go:3352-3360`); name the new canary test
file `pkg/daemon/daemon_dp_canary_test.go`. Smoke gates must cite the
engineering-style.md:93-103 specifics (CoS re-apply after cluster deploy,
`iperf3 -P 16 -t 30 -p 5203` → 172.16.80.200, ≥23 Gbit/s no-regression,
ping 0% loss, HA loss/convergence criteria, explicit `make test`). Fold all.

## Disposition required for v3

1. Kind-gated typed-nil guard + both fake-shape tests (B1).
2. Rewrite the race-reachability narrative with the four-link
   bootstrap/cluster mutual-exclusion proof (B2); audit table notes HA
   readers as RACE-1-reachable / RACE-2-unreachable; `daemon_health.go:141`
   reclassified accordingly (still converted).
3. Adopt the narrowed `CachedStatusProvider` sampler interface +
   single-method daemon adapter (M1); revise the "pkg/fwdstatus untouched"
   out-of-scope line to the 3-file change; update §5.1/§6/§9/§10.
4. Deterministic real-sampler barrier per M2.
5. Regenerate the audit table untruncated with exact counts (M3).
6. m1-m3 folds (test start-state, Option D text, docs/comment/canary/smoke
   specifics).
