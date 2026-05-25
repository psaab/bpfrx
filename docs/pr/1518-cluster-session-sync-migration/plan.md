# #1518 Plan — Migrate pkg/cluster Session-Sync Off Legacy dataplane.DataPlane

**Status:** DRAFT v1 — pending hostile plan review (Codex + Antigravity)

## Issue framing

Sub-#1451 step S3 of the eBPF retirement (#1373). `pkg/cluster/sync.go`
currently exposes `NewSessionSync`, `NewDualSessionSync`, and
`SetDataPlane` whose signatures take `dataplane.DataPlane` — the wide
legacy BPF-shaped interface. The internals of `SessionSync` no longer
need that full surface: a prior step already split the stored fields
into `s.sessions dataplane.SessionStore` and `s.telemetry
dataplane.Telemetry`, populated via `SetRuntimeDomains(...)` from
`dataplane.SessionStoreOf/TelemetryOf(dp)`.

What still couples the cluster package to the legacy shape is only the
**boundary**: the public constructor and setter parameter types. This
step removes that residual coupling so the HA hot path no longer names
`dataplane.DataPlane` at all, then renames `SetDataPlane` to
`SetRuntime` (with a one-release alias).

This unblocks #1476 (drop the legacy `DataPlane` interface from the
daemon shrink set per `docs/pr/1451-migration-scope/scope.md` once all
S1-S5 land).

## Honest scope / value framing

- **No runtime behavior change.** Pure type-narrowing at a single
  package boundary plus a constructor rename.
- **Win:** removes the last cluster→legacy-DP type dependency. Lets
  the userspace runtime feed `SessionSync` without going through the
  `legacyDP()` cast in `daemon_ha_sync.go:718`. Keeps eBPF and
  userspace dataplanes symmetric at this seam.
- **Cost:** small surface change but ~80 test call-sites in
  `pkg/cluster/sync_test.go` plus two daemon call-sites and three
  daemon-test call-sites.
- **Risk if wrong:** This touches HA session-sync wiring. A subtle
  miswire (e.g. passing nil where Sessions are needed, or losing the
  type assertion against `userspaceEventStreamProvider` next to the
  setter) silently kills bulk sync, GC delete propagation, or fabric
  forwarding.

If reviewers conclude the type-narrowing churn is too small to justify
the test-surface change, **PLAN-KILL is an acceptable verdict** — the
two-cycle alias and the existing `SessionStoreOf` adapter mean the
boundary is already neutral at runtime; the rename is the principal
deliverable.

## What is already shipped / partially migrated

`SessionSync` already stores the narrow domain interfaces:

- `pkg/cluster/sync.go:153` `sessions dataplane.SessionStore`
- `pkg/cluster/sync.go:154` `telemetry dataplane.Telemetry`
- `pkg/cluster/sync.go:405` `SetRuntimeDomains(sessions, telemetry)` —
  backend-neutral domain setter
- `pkg/cluster/sync.go:393` `SetDataPlane(dp dataplane.DataPlane)` —
  the legacy-shaped setter; today it adapts via
  `dataplane.SessionStoreOf(dp)` + `TelemetryOf(dp)` and calls
  `SetRuntimeDomains`.

All the actual hot paths inside the cluster package already use
`s.sessions.*` / `s.telemetry.*` (see `sync.go:570`, `sync_bulk.go:121,
160`, `sync_conn.go:34, 49, 64, 74, 330, 384, 385, 399, 417, 447,
448`). There is **no remaining hot-path use** of `dataplane.DataPlane`
inside the cluster package. The boundary is the only thing left.

## Concrete design

### 1. New `pkg/cluster/runtime.go`

```go
package cluster

import "github.com/psaab/xpf/pkg/dataplane"

// clusterRuntime is the backend-neutral runtime surface required by
// SessionSync. It captures exactly the domains the HA hot path needs
// (session-store install/delete/iterate + telemetry counters used by
// the sweep). Both pkg/dataplane.Manager (legacy eBPF) and
// pkg/dataplane/userspace.Manager satisfy it via their existing
// Sessions()/Telemetry() methods.
type clusterRuntime interface {
    Sessions() dataplane.SessionStore
    Telemetry() dataplane.Telemetry
}
```

Notes:
- Lower-case (package-private) interface name. The constructors are
  public; the type bound is satisfied structurally.
- Identical method set to the relevant slice of
  `dataplane.RuntimeDataPlane` so any current/future runtime that
  implements `RuntimeDataPlane` satisfies `clusterRuntime` for free.
- Does **not** include `SessionDeltas()` because today's sweep reaches
  it via `s.sessions.SessionDeltas()` (see `sync_conn.go:330`),
  consistent with how the rest of the hot path uses `s.sessions`.

### 2. Constructor signatures

```go
func NewSessionSync(localAddr, peerAddr string, rt clusterRuntime) *SessionSync
func NewDualSessionSync(local, peer, local1, peer1 string, rt clusterRuntime) *SessionSync
```

Both constructors call `s.SetRuntime(rt)` instead of
`s.SetDataPlane(dp)`.

### 3. New `SetRuntime` + deprecated `SetDataPlane` alias

```go
// SetRuntime sets the backend-neutral runtime used by SessionSync.
// Passing nil clears both domains.
func (s *SessionSync) SetRuntime(rt clusterRuntime) {
    if rt == nil {
        s.SetRuntimeDomains(nil, nil)
        return
    }
    s.SetRuntimeDomains(rt.Sessions(), rt.Telemetry())
}

// Deprecated: use SetRuntime. Kept for one release cycle for any
// out-of-tree caller still passing dataplane.DataPlane. The legacy
// dataplane satisfies clusterRuntime via Manager.Sessions()/Telemetry().
func (s *SessionSync) SetDataPlane(dp dataplane.DataPlane) {
    if dp == nil {
        s.SetRuntimeDomains(nil, nil)
        return
    }
    s.SetRuntimeDomains(dataplane.SessionStoreOf(dp), dataplane.TelemetryOf(dp))
}
```

`SessionStoreOf` already handles the case where a `DataPlane`
implementation also exposes `Sessions()`/`Telemetry()` directly
(`apply.go:65`), so the alias does not regress behavior versus the
new path.

### 4. Daemon fan-out

- `pkg/daemon/daemon_ha_sync.go:525, 527` — pass `nil` for the runtime
  at construction time (unchanged) because the daemon wires the
  runtime later via `SetRuntime` (kept asynchronous, see lines
  693-731).
- `pkg/daemon/daemon_ha_sync.go:718` — change
  `d.sessionSync.SetDataPlane(d.legacyDP())` to
  `d.sessionSync.SetRuntime(d.dp)`. `d.dp` is already typed
  `dataplane.RuntimeDataPlane`; both the legacy `*dataplane.Manager`
  and the userspace `*userspace.Manager` implement
  `Sessions()/Telemetry()`.
- Keep the existing `legacyDP()` callers nearby (event-stream
  provider type assertion at line 682, exporter at line 271). Those
  are **not** session-sync wiring; they are userspace-specific
  capability probes. **Do not touch them in this PR** — they are
  owned by #1520/#1521.

### 5. Test fan-out

- `pkg/cluster/sync_test.go` — 80 call-sites. Half pass `nil`
  (continues to compile under the new signature). The other half pass
  `*mockSweepDP` which today embeds `dataplane.DataPlane`. Two options:
  - **(a)** Add `Sessions()` / `Telemetry()` methods to `mockSweepDP`
    that return `dataplane.SessionStoreOf(m)` / `TelemetryOf(m)`. Then
    `*mockSweepDP` satisfies `clusterRuntime` directly.
  - **(b)** Continue using the deprecated `SetDataPlane` path in
    tests during the alias window.
  Chosen approach: **(a)**. It exercises the real production path,
  keeps the deprecated alias's only purpose being out-of-tree callers,
  and avoids accidentally regressing if the alias is removed.
- `pkg/daemon/daemon_apply_runtime_test.go:30`,
  `pkg/daemon/session_sync_readiness_test.go:152` — pass `nil`
  (continues to compile under the new signature).
- `TestSetDataPlane` at `sync_test.go:505` is renamed to
  `TestSetRuntime` and tests `SetRuntime`. A small `TestSetDataPlane`
  is kept for the alias surface so the deprecation window is covered.

## Public API preservation

| Identifier | Before | After |
|---|---|---|
| `NewSessionSync(localAddr, peerAddr string, dp dataplane.DataPlane)` | takes `dataplane.DataPlane` | takes `clusterRuntime` |
| `NewDualSessionSync(local, peer, local1, peer1 string, dp dataplane.DataPlane)` | same | same |
| `SetDataPlane(dp dataplane.DataPlane)` | active API | deprecated alias, kept one cycle |
| `SetRuntime(rt clusterRuntime)` | not present | new primary setter |
| `SetRuntimeDomains(sessions, telemetry)` | active | unchanged |

The exported function names of `NewSessionSync`,
`NewDualSessionSync`, and `SetDataPlane` are preserved per the issue
("keep an alias for one release cycle if any external caller exists").
Only the parameter type of the constructors changes; existing callers
passing `dataplane.DataPlane` will fail to compile and need a one-line
fix at the boundary. This is acceptable because all in-tree callers
already pass `nil` at construction.

## Hidden invariants the change must preserve

1. **Construction is decoupled from runtime wiring.** The daemon
   constructs `SessionSync` early (`daemon_ha_sync.go:525-528`), but
   only attaches the runtime later in a retry loop (line 718). The new
   `SetRuntime` must accept `nil` and clear both domains, matching the
   existing `SetDataPlane(nil)` contract.
2. **`s.sessions == nil` and `s.telemetry == nil` guards.** Code paths
   like `sweepIntervals()` (`sync_conn.go:328`),
   `syncSweep()` (`sync_conn.go:369-379`), and the bulk reconcile
   (`sync.go:570`) all check for nil. Preserve nil-tolerance through
   the new setter.
3. **Adapter equivalence with the legacy boundary.** Today,
   `SetDataPlane(legacyDP)` calls `SessionStoreOf(legacyDP)` and
   `TelemetryOf(legacyDP)`. The new `SetRuntime(d.dp)` calls
   `d.dp.Sessions()` and `d.dp.Telemetry()`. For the legacy manager
   these return identical implementations (both reach the same
   `dataPlaneSessionStore`); for the userspace manager they reach the
   in-process userspace session store. Verify by reading
   `apply.go:225-237` and `userspace/manager.go:209, 220`.
4. **`writeMu` serialization.** Unchanged — this PR does not touch
   any conn.Write path.
5. **GC delete-callback hooks.** Unchanged — `daemon_run.go:333-344`
   already calls `d.sessionSync.QueueDeleteV4/V6`, which has no
   dataplane dependency. The dataplane is only consulted on receive
   (`sync_conn.go:34-79`), which already routes through
   `s.sessions.PutClusterSyncedV4/V6` etc.
6. **Ring-buffer SESSION_OPEN forward-sync.** `daemon_run.go:367-408`
   already uses `d.dp.Sessions().GetV4/V6` directly. Unchanged.
7. **Sweep profiler detection.** `sweepIntervalsForDataPlane` at
   `sync_conn.go:336` does `dp.(sessionSyncSweepProfiler)` against the
   `SessionDeltaSource` returned by `s.sessions.SessionDeltas()`. That
   contract is independent of the boundary type and stays intact.
8. **Compile-time interface conformance.** The plan does **not** add
   any `var _ clusterRuntime = (*dataplane.Manager)(nil)` assertion in
   `pkg/cluster` because that would create an upward dependency from
   `cluster` to `dataplane`'s concrete Manager type. Conformance is
   instead asserted at the daemon call-site by the compiler at line
   718 (assigning `d.dp` to a `clusterRuntime` parameter).

## Risk assessment

| Class | Level | Justification |
|---|---|---|
| Behavioral regression | LOW | No runtime path changes. Boundary uses identical accessors (`Sessions()`/`Telemetry()`) that the legacy adapter already returns. |
| Lifetime / borrow-checker | N/A | Pure Go interface change. |
| Performance regression | LOW | One fewer indirection on the runtime wire-up (skip the `SessionStoreOf`/`TelemetryOf` switch table in the hot setter). Construction-time only; no per-packet effect. |
| Architectural mismatch (#946 Phase 2 / #961 dead-end pattern) | LOW | The narrow interface already exists in production (`SetRuntimeDomains`). This PR just changes the constructor parameter type to match the steady-state design. |
| HA hot path — failover timing | LOW | No changes to VRRP, RETH, sync hold, heartbeat. Same `writeMu` serialization; same `IsLocalPrimary` gating; same fabric forwarding glue. |
| HA hot path — session reconciliation | LOW | `ReconcileClusterBulk` is invoked the same way (`sync.go:570`) and still goes through `s.sessions`. |
| Test surface | MED | 80 call-sites in `sync_test.go`. Risk is mechanical churn, not semantic regression. The chosen approach (a) makes `*mockSweepDP` implement `clusterRuntime` via two new methods so we only touch `mockSweepDP` itself, not every call-site. |
| Deprecation alias drift | LOW | `SetDataPlane(nil)` and `SetRuntime(nil)` both call `SetRuntimeDomains(nil, nil)`; behavior identical. |

## Test plan

1. `go build ./...` clean.
2. `go test ./pkg/cluster/...` green (full suite, ~640 tests).
3. `go test ./pkg/daemon/...` green.
4. Full Go suite: `make test` (30 packages).
5. Named-test 5× flake check on:
   - `TestSetRuntime` (new)
   - `TestSetDataPlane` (alias coverage)
   - One representative bulk-sync test (e.g. `TestSyncSweepV4`).
6. **`make test-failover` on the local regression cluster** with
   `CLUSTER_ENV=` (see CLAUDE.md HA section). This is the explicit
   requirement on cluster/VRRP/session-sync/failover changes.
7. Smoke matrix on the **loss userspace cluster** per the standard
   triple-review skill:
   - Pass A (CoS off): v4 + v6 × push + reverse single-stream; v4
     + v6 multi-stream `-P 12 -R`.
   - Pass B (CoS on): per-class smoke 5201-5206 × v4+v6 × push+rev.
8. After Pass A on the loss userspace cluster, trigger at least
   one cluster failover cycle (`request chassis cluster failover
   redundancy-group 1`) and verify:
   - Bulk session sync replays primary→secondary,
   - `show chassis cluster status` reports symmetric state,
   - `show chassis cluster information` shows no fabric/sync error
     counters incrementing.

## Out of scope (explicitly)

- Removing `dataplane.SessionStoreOf` / `TelemetryOf`. Other migration
  steps (e.g. #1519 daemon-legacydp-shrink) need them.
- Removing the `userspaceEventStreamProvider` / `userspaceEventStreamExporter`
  type assertions at `daemon_ha_sync.go:271, 682`. Those are owned by
  #1520 (userspace boot extraction) and #1521 (maps sync decouple).
- Renaming `SetRuntimeDomains`. Keeping it gives test code a direct
  knob.
- Touching `cmd/cli/`, `pkg/grpcapi/`, or anything outside
  `pkg/cluster/`, `pkg/daemon/`. Sibling agents on #1516/#1517 own
  those.
- Removing the `legacyDP()` helper at `daemon.go:348`. Other
  call-sites still need it during the staged retirement.

## Open questions for adversarial plan review

1. **Is the deprecated `SetDataPlane` alias actually necessary?** The
   issue body says "keep an alias for one release cycle if any
   external caller exists." Are there any out-of-tree consumers of
   `cluster.NewSessionSync`/`SetDataPlane`? If not, removing the alias
   immediately is simpler and avoids the `dataplane.DataPlane`
   parameter type lingering. **Argue for or against keeping the
   alias.**
2. **Should `clusterRuntime` be exported (capital `R` `Runtime`)?**
   Lower-case keeps the interface package-private which prevents
   accidental dependence; capital makes mocking from external test
   code easier. Pick one with reasoning.
3. **`mockSweepDP` migration approach.** Plan picks option (a) — make
   the mock implement `clusterRuntime` directly. Is option (b) — keep
   tests on the deprecated `SetDataPlane` alias path — safer because
   it exercises the alias too? Or does (a) better future-proof when
   the alias is deleted?
4. **`SetRuntime(nil)` semantics.** The plan clears both domains on
   nil. Is there any code path in the daemon that could re-wire
   midway and expect partial domains? Audit `sessionSync.SetRuntime`
   call sites for re-entrancy.
5. **`d.dp` typing at the call-site.** `d.dp` is
   `dataplane.RuntimeDataPlane`. Are there any concrete dataplane
   implementations registered through the boot path that do **not**
   implement `Sessions()` and `Telemetry()` returning non-nil values?
   If a backend can return nil from `Sessions()`, the new path
   silently disables session sync — whereas the old path went through
   `SessionStoreOf` which returns a no-op store wrapper. **Worked
   trace: walk both userspace.Manager.Sessions() and the legacy
   dataplane.Manager.Sessions() and confirm neither returns nil during
   normal operation.**
6. **`make test-failover` runs on the local regression cluster (not
   the loss userspace cluster).** That cluster runs the **legacy
   eBPF** dataplane. After this PR, the legacy boundary at line 718
   becomes `SetRuntime(d.dp)`. Is the legacy `dataplane.Manager`
   guaranteed to be the type of `d.dp` on that cluster? If `d.dp` is
   constructed differently in either cluster (e.g. the regression
   cluster wraps it in `LegacyDataPlaneAdapter`), the call-site swap
   could route to a different `Sessions()` implementation. Walk
   `pkg/daemon/dataplane_setup*.go` (or equivalent) for both branches.
7. **Architectural mismatch check.** Does this fit the
   #1451 migration scope's promise to remove `dataplane.DataPlane`
   from `pkg/cluster/`? If a later step depends on `cluster.SessionSync`
   exposing a wider runtime (e.g. `LinkController` for fabric address
   reconciliation), then `clusterRuntime` is too narrow and we'll add
   methods to it later. Confirm or rebut.
