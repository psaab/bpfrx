# #1519 daemon legacyDP() shrink + delete — capstone implementation plan v1

**Status:** PLAN — drafted in Phase A while waiting on #1516 (PR #1554
at 0436f386) to merge. #1517 closed via PR #1549. #1518 closed via PR
#1551. This plan is distinct from the round-1 PLAN-KILL'd v2 shrink
plan at `plan.md`; this is the **capstone-delete plan** that runs once
#1516 closes.

## Issue

https://github.com/psaab/xpf/issues/1519 — eBPF retirement: shrink and
delete daemon `legacyDP()` accessor (sub-#1451 S4).

Parent #1451 (eBPF retirement migration scope); umbrella #1373; this
PR also closes the S4 acceptance criterion of #1451 once landed.

## Sibling state @ plan time

- #1516 — OPEN, PR #1554 at 0436f386 (MERGEABLE, Copilot reviewed,
  no further reviewer findings). Capstone implementation **waits**
  for #1554 to merge to master before the impl branch is rebased and
  the code changes begin.
- #1517 — CLOSED via PR #1549. `pkg/cli` now exposes `cliRuntime` (a
  strict superset of `dataplane.RuntimeDataPlane`, including
  `IsLoaded`, `IterateSessions(V6)`, `GetMapStats`,
  `GetPersistentNAT`, `ClearAllCounters`, `ClearAllSessions`, etc.)
  declared in `pkg/cli/runtime.go`. `cli.New(...)` already takes
  `cliRuntime`, **not** `dataplane.DataPlane`. Daemon side at
  `daemon_run.go:882` still passes `d.legacyDP()` because the
  daemon-side narrowing was deferred to this issue.
- #1518 — CLOSED via PR #1551. `pkg/cluster` now exposes
  `clusterRuntime` (Sessions/Telemetry) declared in
  `pkg/cluster/runtime.go`, plus `SetRuntime(rt clusterRuntime)` and
  a deprecated `SetDataPlane(dp dataplane.DataPlane)` alias kept for
  one release cycle. Daemon side at `daemon_ha_sync.go:741` already
  calls `d.sessionSync.SetRuntime(d.dp)`. The remaining `legacyDP()`
  calls in `daemon_ha_sync.go` (lines 271, 281, 700) are for
  userspace event-stream typed probes, not the SessionSync seam.

## Audit @ rebase target (origin/master, expected post-#1516 close)

`grep -n legacyDP pkg/daemon/*.go` on `1f39f79d` (current master):

```
pkg/daemon/daemon.go:345-356               function definition + comment
pkg/daemon/daemon_forwarding_status.go:20  IsLoaded() probe
pkg/daemon/daemon_forwarding_status.go:28  GetMapStats() probe
pkg/daemon/daemon_forwarding_status.go:56  Status() typed probe
pkg/daemon/daemon_forwarding_status.go:70  forwardingStatusDataplane()
pkg/daemon/daemon_gc.go:16                 persistent-NAT + session-count
pkg/daemon/daemon_scheduler.go:159         dead-code fallback (#1519 v2)
pkg/daemon/daemon_run.go:310               post-Start Seed* (eBPF only)
pkg/daemon/daemon_run.go:365               StartFIBSync (no-op everywhere)
pkg/daemon/daemon_run.go:710               api.Config{DP: ...}
pkg/daemon/daemon_run.go:796               grpcapi.Config{DP: ...}
pkg/daemon/daemon_run.go:882               cli.New(... dp ...)
pkg/daemon/daemon_run.go:1076              logFinalStats(lp)
pkg/daemon/daemon_ha_sync.go:271           event-stream exporter probe
pkg/daemon/daemon_ha_sync.go:281           %T log of legacyDP() type
pkg/daemon/daemon_ha_sync.go:700           event-stream provider probe
```

That is 16 call expressions plus the function definition. The plan
also folds in the comment at `daemon_ha_sync.go:739` referring to
#1518 (now landed) and the docstring at `daemon.go:345-348`.

## 1. Migration matrix

Each row lists current text + target. All migrations preserve
nil-tolerance: type assertions remain `if x, ok := y.(T); ok &&
x != nil { ... }` where today's code nil-checks.

| # | Site | Current | Target |
|---|---|---|---|
| 1 | `daemon_gc.go:16` | `if lp := d.legacyDP(); lp != nil { ... NewGCWithDomains(..., lp, lp, ...) }` | Pass `d.dp` directly as the persistent-NAT + session-count provider via type assertion; both eBPF Manager and userspace LegacyDataPlaneAdapter satisfy `conntrack.PersistentNATProvider` and `conntrack.SessionCountPublisher` via the existing legacy interface. Verify with named probes declared in `pkg/conntrack/runtime.go` (existing) or local probes in `pkg/daemon`. |
| 2 | `daemon_scheduler.go:159-161` | `if lp := d.legacyDP(); lp != nil { lp.UpdatePolicyScheduleState(...) }` | **Delete dead fallback.** Both backends already satisfy the local `policyScheduleStateUpdater` probe at line 14, asserted on `d.dp` at line 155. Independently verified in v2 plan; AGY round-1 ratified. |
| 3 | `daemon_forwarding_status.go:20` | `dp := a.daemon.legacyDP(); return dp != nil && dp.IsLoaded()` | New local probe `dataplaneReadyProbe interface { IsLoaded() bool }` declared in `pkg/daemon/runtime_probes.go` (new file). Assert against `a.daemon.dp`. |
| 4 | `daemon_forwarding_status.go:28-32` | `dp := a.daemon.legacyDP(); ... dp.GetMapStats()` | Swap to `a.daemon.dp.Telemetry().MapStats()` — covered by `dataplane.Telemetry.MapStats()` (apply.go:154). |
| 5 | `daemon_forwarding_status.go:56-63` | `dp := d.legacyDP(); provider, ok := dp.(interface{ Status()... })` | Assert on `d.dp` directly; userspace `LegacyDataPlaneAdapter` exposes `Status()` natively (legacy_dataplane.go:350). |
| 6 | `daemon_forwarding_status.go:66-81` | `dp := d.legacyDP()`; if dp implements `Status()` wrap with userspace variant | Use `dataplaneReadyProbe` for the IsLoaded gate; type-assert `Status()` on `d.dp`. |
| 7 | `daemon_run.go:310-317` | `if lp := d.legacyDP(); lp != nil { lp.SeedNATPortCounters(); lp.SeedSessionIDCounter(nodeID) }` | New local probe `natSeeder interface { SeedNATPortCounters(); SeedSessionIDCounter(int) }` in `pkg/daemon/runtime_probes.go`. eBPF Manager satisfies natively (maps.go:1589, 1611); userspace `LegacyDataPlaneAdapter` inherits via embedded bpfShim. Assert on `d.dp`. |
| 8 | `daemon_run.go:365-367` | `if lp := d.legacyDP(); lp != nil { lp.StartFIBSync(ctx) }` | New local probe `fibSyncStarter interface { StartFIBSync(context.Context) }` in `pkg/daemon/runtime_probes.go`. Documented no-op on all in-tree backends but kept under the probe for forward compatibility (DPDK had a real one before #1527; future backends may need it). Assert on `d.dp`. |
| 9 | `daemon_run.go:710` (api.Config.DP) | `api.Config{DP: d.legacyDP()}` | `api.Config.DP` is already typed `apiRuntimeDataPlane` at `pkg/api/server.go:49`. The interface (`pkg/api/handlers.go:28`) includes IsLoaded, IterateSessions, IterateSessionsV6, ClearAllSessions, Read*, ClearAllCounters, GetMapStats. Both backends satisfy via embedded shim. **Solution:** assert on `d.dp` to `apiRuntimeDataPlane` via a daemon-local probe `apiDataPlaneProbe = apiRuntimeDataPlane` (Go allows interface satisfaction at call site without daemon importing the package-private interface — instead, daemon declares its own matching probe locally and asserts on `d.dp`). Pass the asserted value. **Alternative:** add a public typed accessor in `pkg/api` matching the structural set. The local probe is preferred (no public surface widening). |
| 10 | `daemon_run.go:796` (grpcapi.Config.DP) | `grpcapi.Config{DP: d.legacyDP()}` | **Blocked by #1516 (PR #1554) at plan time.** Once #1554 merges, `grpcapi.Config.DP` will be a narrow typed surface (mirroring api/cli pattern). Migration: assert `d.dp` to the new typed surface (a daemon-local matching probe). If the grpcapi field stays typed as `dataplane.DataPlane` after #1554 merges, fail loud and reopen #1516 — that contradicts the sub-#1451 S1 acceptance criteria. |
| 11 | `daemon_run.go:882` (cli.New) | `cli.New(d.store, d.legacyDP(), ...)` | Assert `d.dp` to `cliRuntime` via a daemon-local matching probe declared in `pkg/daemon/runtime_probes.go`. Both backends satisfy `cliRuntime` (#1517 explicitly designed it so). Pass the asserted value to `cli.New`. |
| 12 | `daemon_run.go:1076-1078` | `if lp := d.legacyDP(); lp != nil { logFinalStats(lp) }` | Change `logFinalStats` signature to `logFinalStats(ready dataplaneReadyProbe, tel dataplane.Telemetry)`. Call from teardown as `logFinalStats(d.dp, d.dp.Telemetry())`. Implementation reads `tel.GlobalCounter(idx)` instead of `dp.ReadGlobalCounter(idx)`. |
| 13 | `daemon_ha_sync.go:271` | `if exporter, ok := d.legacyDP().(userspaceEventStreamExporter); ok` | Assert on `d.dp` directly. `userspaceEventStreamExporter` is a local typed probe (daemon_ha_userspace.go:49); userspace `LegacyDataPlaneAdapter` satisfies it via the `ExportAllSessionsViaEventStream()` method at legacy_dataplane.go:422. |
| 14 | `daemon_ha_sync.go:281` | `"dp_type", fmt.Sprintf("%T", d.legacyDP())` | Replace with `"dp_type", fmt.Sprintf("%T", d.dp)`. Functionally identical (same concrete type); avoids the legacy round-trip. |
| 15 | `daemon_ha_sync.go:700` | `if provider, ok := d.legacyDP().(userspaceEventStreamProvider); ok` | Assert on `d.dp` directly (mirror of #13). |
| 16 | `daemon_ha_sync.go:739` (comment only) | `// legacyDP() cast is no longer required at this seam (#1518).` | Update comment: drop the historical reference; #1518 has shipped, no follow-up needed. |
| 17 | `daemon.go:345-356` | `legacyDP()` definition + 12-line docstring | **Delete the function.** All callers have migrated. |

## 2. New file: `pkg/daemon/runtime_probes.go`

Local typed-probe declarations for the post-shrink daemon. All
interfaces are package-private (lowercase identifier) to keep them
out of the daemon's public surface.

```go
package daemon

import (
    "context"

    "github.com/psaab/xpf/pkg/cli"
    "github.com/psaab/xpf/pkg/dataplane"
)

// dataplaneReadyProbe is the minimal lifecycle probe used by daemon
// internals to gate operations on a started dataplane. Both the legacy
// eBPF Manager and the userspace LegacyDataPlaneAdapter implement it.
type dataplaneReadyProbe interface {
    IsLoaded() bool
}

// natSeeder is satisfied by backends that prime BPF NAT-port and
// session-ID maps after Start. The legacy eBPF Manager satisfies it
// directly; the userspace adapter inherits via the embedded bpfShim.
type natSeeder interface {
    SeedNATPortCounters()
    SeedSessionIDCounter(int)
}

// fibSyncStarter is satisfied by backends that maintain a userspace
// FIB. Both in-tree backends document StartFIBSync as a no-op (the
// kernel-side bpf_fib_lookup handles FIB resolution); the probe is
// retained for forward compatibility.
type fibSyncStarter interface {
    StartFIBSync(context.Context)
}

// apiDataPlane mirrors pkg/api/handlers.go's apiRuntimeDataPlane so
// daemon can construct an api.Config without legacyDP(). Structural
// typing: any value satisfying both surfaces is implicitly assignable
// to api.Config.DP.
type apiDataPlane interface {
    IsLoaded() bool
    IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error
    IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
    ClearAllSessions() (int, int, error)

    ReadGlobalCounter(uint32) (uint64, error)
    ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error)
    ReadZoneCounters(uint16, int) (dataplane.CounterValue, error)
    ReadPolicyCounters(uint32) (dataplane.CounterValue, error)
    ReadFilterConfig(uint32) (dataplane.FilterConfig, error)
    ReadFilterCounters(uint32) (dataplane.CounterValue, error)
    ReadNATRuleCounter(uint32) (dataplane.CounterValue, error)
    ReadNATPortCounter(uint32) (uint64, error)
    ClearAllCounters() error
    GetMapStats() []dataplane.MapStats
}

// grpcDataPlane mirrors the (post-#1516) grpcapi.Config.DP surface.
// The exact set is finalized after #1554 merges; this probe is
// committed alongside the migrated call site so the daemon's local
// shape matches the downstream contract.
type grpcDataPlane interface {
    // ... finalized after #1516 ships, mirrors grpcapi.Config.DP type.
}

// cliDataPlane mirrors pkg/cli/runtime.go's cliRuntime so daemon can
// construct cli.New without legacyDP().
type cliDataPlane = cli.CLIRuntime // OR re-declare as local matching surface
```

Open question for plan review: do we (a) re-declare matching local
probes in `pkg/daemon`, or (b) import `pkg/cli.CLIRuntime` (rename
from cliRuntime to public) and `pkg/api.RuntimeDataPlane` (rename
from apiRuntimeDataPlane) and use them directly? Option (a) keeps
each package's typed surface private but duplicates the declaration;
Option (b) widens the consumer's public surface but is DRY.

**Recommended:** option (a) for `pkg/api` and `pkg/grpcapi` (the daemon
declares matching local probes that compile-time-check satisfy each
public surface via `var _ apiRuntimeDataPlane = (dataplaneSink)(nil)`
asserted in `runtime_probes_test.go`). For `pkg/cli`, since the
cliRuntime already names the daemon as its only in-tree caller (line
3-9 of pkg/cli/runtime.go), promote `cliRuntime` to `CLIRuntime`
(public) and have the daemon import it. This avoids duplicating a
24-line interface declaration.

**Codex/AGY: rule on option (a) vs (b) per package.**

## 3. Compile-time assertions

Add to `pkg/daemon/runtime_probes_test.go`:

```go
package daemon

import (
    "testing"

    "github.com/psaab/xpf/pkg/api"
    "github.com/psaab/xpf/pkg/cli"
    "github.com/psaab/xpf/pkg/dataplane"
    dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
    "github.com/psaab/xpf/pkg/grpcapi"
)

func TestProbesSatisfiedByBackends(t *testing.T) {
    var _ dataplaneReadyProbe = (*dataplane.Manager)(nil)
    var _ dataplaneReadyProbe = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
    var _ natSeeder = (*dataplane.Manager)(nil)
    var _ natSeeder = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
    var _ fibSyncStarter = (*dataplane.Manager)(nil)
    var _ fibSyncStarter = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
    var _ apiDataPlane = (*dataplane.Manager)(nil)
    var _ apiDataPlane = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
    var _ grpcDataPlane = (*dataplane.Manager)(nil)
    var _ grpcDataPlane = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
    var _ cli.CLIRuntime = (*dataplane.Manager)(nil) // if option (b) taken
    var _ cli.CLIRuntime = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
    // Downstream consumer compile-time check that local matches public:
    var _ api.RuntimeDataPlane = (apiDataPlane)(nil) // if api surface promoted
}
```

If these compile, the migration is sound by Go's structural typing.

## 4. Canary: forbid future reintroduction of `legacyDP()`

**Approach 1 (recommended):** extend the existing
`retirement_boundary_canary_test.go` allowlist at line 49:

  - Drop the `pkg/daemon/daemon.go` entry's
    "exposes legacyDP for unmigrated callers" rationale; replace with
    something narrower (e.g. "daemon owns RuntimeDataPlane; no legacy
    accessor remains") or remove the file from the allowlist if it
    no longer imports `pkg/dataplane`.
  - Drop the `pkg/daemon/daemon_run.go` "passes legacyDP to unmigrated
    services" rationale; replace with a narrower rationale tied to
    the remaining call sites at that file. (Most of the remaining
    refs are to the dataplane.* type names, not the accessor itself.)

**Approach 2 (additional canary):** new file
`pkg/daemon/legacy_dataplane_canary_test.go`:

```go
package daemon

import (
    "go/parser"
    "go/token"
    "path/filepath"
    "strings"
    "testing"
)

// TestLegacyDPAccessorRemoved enforces that the (*Daemon).legacyDP()
// accessor stays deleted after #1519. Future reintroduction must
// either (a) re-justify by adding a new sub-issue or (b) update this
// canary with a rationale.
func TestLegacyDPAccessorRemoved(t *testing.T) {
    fset := token.NewFileSet()
    files, err := filepath.Glob("*.go")
    if err != nil { t.Fatal(err) }
    for _, f := range files {
        if strings.HasSuffix(f, "_test.go") { continue }
        node, err := parser.ParseFile(fset, f, nil, parser.AllErrors)
        if err != nil { t.Fatal(err) }
        // Walk for FuncDecl named legacyDP with *Daemon receiver,
        // or CallExpr selector .legacyDP(...). Fail with a precise
        // file:line message naming #1519.
    }
}
```

The AST walker is the production-grade canary; the allowlist is the
boundary check. Both should be updated.

**Recommended:** Approach 1 + Approach 2. Both close the loop.

## 5. Implementation step-by-step

After #1516 (PR #1554) closes:

1. Rebase `refactor/1519-daemon-legacydp-shrink-impl` onto current
   `origin/master`. Confirm `grep -n legacyDP pkg/daemon/*.go` still
   matches the 17-line count from this audit, OR re-audit and update
   this plan if `daemon_run.go` line numbers shifted.

2. Inspect the merged #1554 grpcapi narrowing. Document the exact
   `grpcapi.Config.DP` type that ships. Update §2 `grpcDataPlane`
   probe to match.

3. Create `pkg/daemon/runtime_probes.go` with all five typed probes
   (`dataplaneReadyProbe`, `natSeeder`, `fibSyncStarter`,
   `apiDataPlane`, `grpcDataPlane`, plus the cli reference if option
   (b) is taken).

4. Create `pkg/daemon/runtime_probes_test.go` with the
   compile-time assertions from §3. **If any var-decl fails to
   compile, fix the corresponding probe definition; do not skip
   any backend.**

5. Apply migrations #1-#16 from §1 in order. Each migration is a
   self-contained edit; commit after #5 (forwarding_status batch),
   #8 (run.go top-half batch), #12 (run.go logFinalStats), #16
   (ha_sync batch) for clean review-ability.

6. Apply migration #17: delete `(*Daemon).legacyDP()` and its
   docstring from `pkg/daemon/daemon.go`. Run `go vet ./pkg/daemon/...`
   and `go build ./...` — must compile.

7. Update `pkg/dataplane/retirement_boundary_canary_test.go`
   allowlist per §4 Approach 1.

8. Add `pkg/daemon/legacy_dataplane_canary_test.go` per §4 Approach 2.

9. Run `make test` (focus `./pkg/daemon/...`,
   `./pkg/conntrack/...`, `./pkg/cluster/...`, `./pkg/api/...`,
   `./pkg/grpcapi/...`, `./pkg/cli/...`).

10. 5× flake loop: `for i in 1 2 3 4 5; do GOCACHE=/dev/shm/gocache
    go test ./pkg/daemon/... -count=1 || exit 1; done`. Must be
    100% pass.

11. Push branch; open PR with body containing `Closes #1519`. Tag
    @copilot via `gh pr edit --add-reviewer Copilot` (the formal
    `copilot-pull-request-reviewer` route, not the conversational
    swe-agent).

12. Wait for Copilot review + dispatch Codex + AGY hostile + my own
    SMR (3 lenses: HA/daemon-lifecycle, CPU arch / atomic memory
    semantics, SW design patterns).

13. On 4-of-4 MERGE-READY on identical SHA, post AWAITING-SMOKE
    marker per CLAUDE.md. STOP.

## 6. Risk / value framing

**Architectural value:** legacy BPF-shaped surface removed from the
daemon's public API. #1451 S4 (the capstone) lands. #1373 retirement
boundary advances one step closer to source-removal phase (#1476).

**Runtime impact:** zero. All migrations are type-level. Behavior
preserved: every `legacyDP() != nil ?` check becomes a structurally
identical `d.dp.(T)` type assertion guarded by the same nil/ok.

**Correctness risk:** medium-low. The 5 typed probes need to match
each backend's method set exactly; the compile-time assertions in §3
catch any drift at build time. The HA-adjacent migrations (#13-#15)
touch event-stream wiring on the userspace side; smoke + failover
test catch regressions.

**Test surface:** `make test` (Go unit), 5× flake on `./pkg/daemon`,
`make test-failover` (mandatory per issue body for HA-adjacent
accessor changes), 30-cell smoke matrix (v4+v6 × push+reverse ×
CoS-off+CoS-on per CLAUDE.md).

**Worst-case behavior delta:** a control-path bug in session sync,
GC, or HA event streaming. Caught by either the type-system probes
(at build) or the failover test (at smoke).

## 7. Invariants to preserve

- **Nil-tolerance contract:** `legacyDP()` returns nil when `d.dp` is
  nil OR when concrete type doesn't satisfy DataPlane. Each migrated
  site preserves this via `if probe, ok := d.dp.(X); ok && probe !=
  nil { ... }`. Skipping the `probe != nil` check is safe IF the type
  assertion guarantees a non-nil interface value, but for defensive
  style keep both.

- **`logFinalStats` ordering:** runs after `d.cluster.Stop()` and
  `d.sessionSync.Stop()`, before `d.dp.Close()`/`Teardown()`.
  Telemetry must still be valid at that point. **Verify** the
  userspace `Telemetry()` provider doesn't go nil after Stop. Check
  `pkg/dataplane/userspace/legacy_dataplane.go:121` and follow the
  `Telemetry()` call: it returns `dataplane.NewDataPlaneTelemetry(a)`
  which dispatches to `ReadGlobalCounter` on the adapter. The
  adapter's `ReadGlobalCounter` is inherited from the embedded
  bpfShim; bpfShim teardown happens in `dp.Close()/Teardown()`
  which runs **after** `logFinalStats`. Safe.

- **`SeedNATPortCounters` / `SeedSessionIDCounter`:** only the legacy
  eBPF backend currently uses these (userspace doesn't read the BPF
  NAT maps for forwarding decisions, but the embedded bpfShim still
  has the methods). The new `natSeeder` probe must succeed on both.
  Verified by `var _ natSeeder = (*LegacyDataPlaneAdapter)(nil)`.

- **`StartFIBSync` no-op:** documented at maps.go:2021 (eBPF) and
  comment at daemon_run.go:359-364 (userspace). The probe call site
  preserves the existing "call if probe satisfies, else skip"
  behavior.

- **`UpdatePolicyScheduleState` fallback:** v2 plan + AGY round-1
  confirmed dead. Both backends satisfy
  `policyScheduleStateUpdater` (asserted on line 155). Migration #2
  deletes the dead branch.

- **`event-stream` typed probes (`userspaceEventStreamExporter` /
  `userspaceEventStreamProvider`):** declared in
  `daemon_ha_userspace.go`; satisfied by `LegacyDataPlaneAdapter`'s
  `ExportAllSessionsViaEventStream()` (line 422) and `EventStream()`
  (line 414). Assertion on `d.dp` is equivalent.

- **`api.Config.DP` field type:** must be assignable from the value
  returned by `d.dp.(apiDataPlane)`. Since `apiDataPlane` and
  `apiRuntimeDataPlane` are structurally identical (Go interface
  satisfaction is duck-typed), any value satisfying the former
  satisfies the latter. The compile-time assertion `var _
  api.RuntimeDataPlane = (apiDataPlane)(nil)` would only work if the
  api package promotes `apiRuntimeDataPlane` to `RuntimeDataPlane`
  (public). If we keep it package-private, we cannot directly assert
  cross-package; we rely on Go structural typing at the assignment
  site. **The assignment will fail to compile if the two surfaces
  drift**, which is a satisfactory canary.

- **`cliRuntime` package visibility:** `pkg/cli/runtime.go:28` keeps
  `cliRuntime` package-private. To pass a typed value from the
  daemon, the daemon either (a) declares a matching local probe (no
  cross-package import needed; Go duck-types at the call site), or
  (b) the cli package promotes `cliRuntime` to public. Plan §2
  recommends (b) — promote `CLIRuntime` since the daemon is the only
  in-tree caller and the surface is already documented as a stable
  contract.

## 8. Test plan

| Gate | Command |
|------|---------|
| Compile | `go build ./...` |
| Vet | `go vet ./...` |
| Unit | `make test` |
| Focus | `GOCACHE=/dev/shm/gocache go test ./pkg/daemon/... ./pkg/conntrack/... ./pkg/cluster/... ./pkg/api/... ./pkg/grpcapi/... ./pkg/cli/... -count=1` |
| Flake | `for i in 1..5; do go test ./pkg/daemon/... -count=1 || exit 1; done` |
| Boundary canary | `go test ./pkg/dataplane -run TestRetirementBoundary -count=1` |
| Legacy-DP canary | `go test ./pkg/daemon -run TestLegacyDPAccessorRemoved -count=1` (new) |
| Failover | `make test-failover` (mandatory per issue body) |
| Smoke | Loss userspace cluster, v4+v6 × push+reverse × CoS-off+CoS-on |

## 9. Out of scope

- Deleting `LegacyDataPlaneAdapter` — owned by a later #1451 phase.
- Migrating `pkg/conntrack/runtime.go` `RuntimeDomainProvider` shape
  — already in place from #1507.
- Any change to `dataplane.RuntimeDataPlane` shape (#1381 follow-up
  if needed).
- Removing the `cluster.SessionSync.SetDataPlane` deprecated alias
  — kept for one release cycle per #1518's commitment.

## 10. Open questions for plan review

1. **Probe-redeclaration vs public promotion (per package).** §2
   recommends option (b) for `pkg/cli` (promote cliRuntime →
   CLIRuntime) and option (a) for `pkg/api` and `pkg/grpcapi`
   (daemon-local matching probes). Is this split defensible, or
   should all three be treated uniformly?

2. **#1554 grpcapi shape uncertainty.** This plan commits before
   #1554 merges. If #1554 lands with a grpcapi probe shape that
   differs from the cli/api pattern, the plan's `grpcDataPlane`
   probe is incorrect. Mitigation: §5 step 2 explicitly inspects
   the merged #1554 shape and updates §2 before any daemon edit.
   Sufficient?

3. **Canary belt-and-braces.** §4 proposes both extending the
   existing allowlist AND a new AST canary. Is one of them
   sufficient on its own? AST canaries cost ~50ms per run but
   catch regressions the allowlist would miss.

4. **`fibSyncStarter` retention vs deletion.** v2 plan §6 noted
   `StartFIBSync` is documented no-op everywhere. The probe-based
   migration keeps the call site at zero runtime cost; deleting it
   entirely is also defensible. Vote?

5. **Telemetry-after-Stop ordering.** §7 reasons that
   `d.dp.Telemetry()` is safe in `logFinalStats` because the
   adapter's underlying bpfShim doesn't get torn down until
   `dp.Close()`/`Teardown()` which runs after. Verify by walking
   the userspace adapter's Telemetry call chain.

6. **Rebase risk vs #1554.** This plan rebases onto post-#1554
   master. If #1554 doesn't change line numbers in
   `pkg/daemon/daemon_run.go`, the call-site coordinates in §1 hold.
   If it does (it shouldn't — #1516's daemon-side comment says
   "preserves the daemon-side call expression"), §5 step 1 re-audits.

7. **Smoke-runner load.** The capstone PR triggers the full 30-cell
   matrix plus `make test-failover`. Acceptable given the
   architectural milestone, or should we batch with other
   in-flight #1451 work?

## 11. AGY hallucination guard

AGY round-1 on v2 PLAN-KILL ratified all key claims:
- dead-code at `daemon_scheduler.go:159-161`
- telemetry-after-Stop safety
- typed-probe shapes for dataplaneReadyProbe / natSeeder /
  fibSyncStarter
- #1520 and #1521 not unblocked by partial shrink

Carry those ratifications forward as priors; if AGY round-1-impl
contradicts any without quoting verbatim file:line evidence, treat
as hallucination.

## 12. Reviewer disposition expected

Both reviewers were favorable to Option B (PLAN-KILL pending
siblings) in round-1; the capstone-delete plan is the work they
ratified for the post-sibling timeline. Expected verdicts:

- **Codex:** PLAN-NEEDS-MINOR or PLAN-READY. Likely nits: probe
  visibility (§10 Q1), fibSyncStarter retention (§10 Q4), AST canary
  scope (§10 Q3).
- **AGY:** PLAN-NEEDS-MINOR or PLAN-READY. Likely nits: telemetry-
  after-Stop walked trace (§10 Q5), apiDataPlane structural-typing
  assertion at call site vs cross-package (§7 last bullet), rebase
  risk vs #1554 (§10 Q6).

PLAN-KILL is unlikely barring a new architectural blocker discovered
between v2 round-1 (which ratified the capstone path) and #1554
merge.
