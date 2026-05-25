# #1516 plan — migrate `pkg/grpcapi` off legacy `dataplane.DataPlane`

**Status:** v2 — folds AGY round-1 PLAN-NEEDS-MAJOR finding on
userspace cursor pagination plus the omitted canary/docs touchpoint.
Codex round-1 retry pending (`task-mplca3od-d7w9gy`).

## 1. Issue framing

Issue #1516 asks: stop exposing the full `dataplane.DataPlane`
interface across `pkg/grpcapi`. Replace `Config.DP` and `Server.dp`
with a narrow, package-local `grpcRuntime` interface declared in a
new `pkg/grpcapi/runtime.go`, sized to exactly the methods the gRPC
server actually consumes. Fold the existing inline
`s.dp.(interface{...})` provider-probe type assertions into named
provider interfaces declared in the same file. The daemon continues
to pass the same `*userspace.LegacyDataPlaneAdapter` (or the legacy
eBPF dataplane during regression runs) into the new typed field
without any boot-side rewiring.

This is sub-issue S1 of #1451 — the eBPF retirement decomposition.
The migration target and pattern come directly from
`docs/pr/1451-migration-scope/scope.md` and the already-shipped
`pkg/api` precedent (`apiRuntimeDataPlane` in
`pkg/api/handlers.go:28`).

## 2. Honest scope / value framing

This is **boundary tightening, not behavioral change**. The win
is purely structural:

- Removes one of the two large remaining direct importers of
  `dataplane.DataPlane` (the other is `pkg/cli`, sub-issue #1517).
- Lets future deletions of legacy interface methods compile-fail at
  the `pkg/grpcapi/runtime.go` boundary rather than scatter across
  ~15 handler files.
- Makes the userspace-specific provider extensions
  (`Status`, `SetForwardingArmed`, `SetQueueState`,
  `SetBindingState`, `InjectPacket`) explicit named interfaces
  rather than inline anonymous type assertions, so they can be
  evolved independently of the legacy shape.

No measurable runtime impact at all — the same concrete type is
still passed in, the same methods are still called, the call graph
is identical. The dispatch path goes through a Go interface today
and still goes through a Go interface tomorrow; the only thing
that changes is the static type the gRPC server sees.

*If reviewers conclude the structural win is too small to justify
the churn, or that the methodology violates a constraint not visible
in the scope doc, PLAN-KILL is an acceptable verdict.*

## 3. What's already shipped / partially done

- **`pkg/api`** — `apiRuntimeDataPlane` in `pkg/api/handlers.go:28`
  (10-method subset). Canonical pattern for this migration.
- **`pkg/fwdstatus`** — `DataPlaneAccessor` in `builder.go:35`.
- **`pkg/monitoriface`** — `RuntimeDataPlane` in `monitor.go:30`.
- **`pkg/conntrack`** — `NewGC(provider RuntimeDomainProvider, …)`
  with no `DataPlane` parameter on either constructor.
- The daemon already exposes the legacy interface via
  `Daemon.legacyDP() dataplane.DataPlane`
  (`pkg/daemon/daemon.go:348`); the userspace backend already
  bridges through `pkg/dataplane/userspace/legacy_dataplane.go`.
  No daemon-side rewiring is needed for this step beyond changing
  the field type on `grpcapi.Config.DP`.

## 4. Concrete design

### 4.1 New file `pkg/grpcapi/runtime.go`

Declares one main runtime interface plus four named provider
interfaces.

```go
package grpcapi

import (
    "github.com/psaab/xpf/pkg/dataplane"
    dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// grpcRuntime is the gRPC server's domain-specific dataplane
// surface. Listed exactly to the methods the gRPC handlers
// consume on master @ fcd53beb. Narrower than
// dataplane.DataPlane; intentionally not exported.
type grpcRuntime interface {
    // Liveness probe — guards every counter / iter call site.
    IsLoaded() bool

    // Counters (read).
    ReadGlobalCounter(index uint32) (uint64, error)
    ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
    ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
    ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error)
    ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
    ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error)
    ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error)
    ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)

    // Counters (clear) — diag/clear paths.
    ClearPolicyCounters() error
    ClearFilterCounters() error
    ClearNATRuleCounters() error
    ClearAllCounters() error

    // Session store (read).
    IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
    IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
    GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error)
    GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
    SessionCount() (v4, v6 int)

    // Session store (clear / delete) — `clear security flow session ...`.
    ClearAllSessions() (v4 int, v6 int, err error)
    DeleteSession(key dataplane.SessionKey) error
    DeleteSessionV6(key dataplane.SessionKeyV6) error
    DeleteDNATEntry(key dataplane.DNATKey) error
    DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

    // NAT bindings / system buffers.
    GetPersistentNAT() *dataplane.PersistentNATTable
    GetMapStats() []dataplane.MapStats
}

// sessionCursorIterator: optional cursor-based iteration; consumed via
// type assertion in server_sessions.go:getSessionsCursor. Userspace
// adapter implements it; legacy eBPF does not. Falls through to
// legacy full-table scan when absent.
type sessionCursorIterator interface {
    IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
    IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// userspaceStatusProvider: probe for the userspace-specific Status()
// call. Used by:
//   - userspaceDataplaneStatus() in server.go
//   - forwardingStatusDataplane() in server_show_forwarding.go
//   - server_show.go "buffers" / "buffers-detail" topics
type userspaceStatusProvider interface {
    Status() (dpuserspace.ProcessStatus, error)
}

// userspaceControlProvider: superset of statusProvider used by the
// diag/control path (queue/binding admin, forwarding-armed, inject).
// Used by userspaceDataplaneControl() in server.go.
type userspaceControlProvider interface {
    userspaceStatusProvider
    SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
    SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
    SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
    InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}
```

### 4.2 `server.go` edits

```go
type Config struct {
    Store     *configstore.Store
    DP        grpcRuntime   // was dataplane.DataPlane
    ...
}

type Server struct {
    pb.UnimplementedBpfrxServiceServer
    store *configstore.Store
    dp    grpcRuntime       // was dataplane.DataPlane
    ...
}

func (s *Server) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
    provider, ok := s.dp.(userspaceStatusProvider)
    if !ok {
        return dpuserspace.ProcessStatus{}, fmt.Errorf("userspace status unavailable")
    }
    return provider.Status()
}

func (s *Server) userspaceDataplaneControl() (userspaceControlProvider, error) {
    provider, ok := s.dp.(userspaceControlProvider)
    if !ok {
        return nil, fmt.Errorf("userspace dataplane control unavailable")
    }
    return provider, nil
}
```

### 4.3 Inline `interface{…}` consolidations

- `server_show_forwarding.go:68` `s.dp.(interface { Status() … })`
  → `s.dp.(userspaceStatusProvider)`.
- `server_show.go:1730` and `:1786` `s.dp.(interface { Status() … })`
  → `s.dp.(userspaceStatusProvider)`.
- `server_sessions.go:46` keep the local `sessionIteratorFrom`
  declaration but rename to `sessionCursorIterator` and move it into
  `pkg/grpcapi/runtime.go` so the cursor-iteration provider is in
  one place with the others. The type assertion at
  `server_sessions.go:56` becomes `s.dp.(sessionCursorIterator)`.

### 4.4 Daemon wiring (no change required)

`pkg/daemon/daemon_run.go:763` already does `DP: d.legacyDP()`.
`d.legacyDP()` returns `dataplane.DataPlane` — the concrete adapter
type satisfies `grpcRuntime` plus the optional providers because
`dataplane.DataPlane` is a strict superset of `grpcRuntime`'s method
set. No daemon-side edit is needed. (Compile will catch it if I'm
wrong about the superset claim.)

### 4.5 Userspace cursor-pagination repair (AGY r1 finding)

AGY r1 found that the cursor pagination type assertion at
`server_sessions.go:56` silently fails under the userspace dataplane
because `LegacyDataPlaneAdapter` embeds the `dataplane.DataPlane`
interface, not the concrete `*dataplane.Manager`. `IterateSessionsFrom`
and `IterateSessionsV6From` are concrete methods on `*Manager` that
are NOT part of the `dataplane.DataPlane` interface, so Go's method
promotion does not lift them onto `LegacyDataPlaneAdapter`. Today the
gRPC server's cursor pagination handler in
`server_sessions.go:getSessionsCursor` already falls through to the
legacy full-table scan when the assertion fails — under userspace
this is the silent default.

For boundary tightening to be honest, this fallback should be
visible-or-fixed. The plan now ships the fix: add
`IterateSessionsFrom` and `IterateSessionsV6From` as delegation
methods on `LegacyDataPlaneAdapter`, asserting the embedded
`a.DataPlane` against the cursor-iterator interface and forwarding
to `bpfShim`. If the embedded interface field is non-nil and the
underlying concrete value is `*dataplane.Manager`, the assertion
succeeds and the cursor path runs as designed. If it does not (e.g.
the userspace manager is constructed without a bpfShim, as in some
unit tests), the method returns a typed error and `getSessionsCursor`
still falls through to `getSessionsLegacy`.

The added methods are paint-by-numbers delegation; they do not
introduce any new dataplane behavior. They are intentionally scoped
to this sub-issue because the alternative (extending the
`dataplane.DataPlane` interface) widens the very surface #1516 is
narrowing.

## 5. Public API preservation

- `grpcapi.Config` and `grpcapi.NewServer(addr, cfg)` keep the same
  exported names and the same positional fields. The only API change
  is the **declared type** of `Config.DP`. Existing callers
  (`pkg/daemon/daemon_run.go` only) compile unchanged because the
  concrete value passed in (`d.legacyDP()`) satisfies the narrower
  interface.
- gRPC wire surface (`proto/xpf/v1`) — untouched.
- `grpcapi.Server` is opaque to external callers (its fields are
  unexported); the change to `dp` field type is invisible.

## 6. Hidden invariants the change must preserve

1. **Liveness gating.** Every counter/iter call site that today
   reads `if s.dp == nil || !s.dp.IsLoaded() { ... }` keeps that
   exact gate. The new `grpcRuntime` interface intentionally
   exposes `IsLoaded()` so the nil-guard pattern compiles
   unchanged.

2. **Provider-probe semantics.** Today's anonymous
   `interface{ Status() (ProcessStatus, error) }` type assertion
   matches the userspace adapter at runtime. The named
   `userspaceStatusProvider` interface in the new file MUST have
   exactly the same method signature so the assertion result is
   identical. (Go interface satisfaction is structural; renaming the
   interface doesn't change which concrete types satisfy it as long
   as the method set is identical.)

3. **Cursor-iteration fallback.** `getSessionsCursor` falls through
   to `getSessionsLegacy` when the type assertion fails. The
   userspace adapter must continue to satisfy the renamed
   `sessionCursorIterator`; verify by grep against
   `pkg/dataplane/userspace/legacy_dataplane.go`.

4. **Clear-counter side effects.** `ClearAllCounters`,
   `ClearPolicyCounters`, `ClearFilterCounters`,
   `ClearNATRuleCounters`, and `ClearAllSessions` all mutate
   dataplane state. They are reached via `clear` RPCs through
   `server_diag.go`, `server_cluster.go`, `server_sessions.go`. The
   migration does not move these methods or alter their semantics;
   it only changes the static type they're called on.

5. **DeleteDNATEntry / DeleteSession ordering.** In
   `server_sessions.go` around line 740–820 the filtered-clear
   path issues `DeleteSession` then `DeleteDNATEntry` per matched
   entry. The ordering is preserved because the migration is
   signature-only.

## 7. Risk assessment

| Class | Risk | Notes |
|---|---|---|
| Behavioral regression | LOW | No runtime path changes; signature-only. |
| Lifetime / borrow-checker | N/A | Go, no lifetimes. |
| Performance regression | LOW | Same interface dispatch (one method-table indirection); narrower interfaces can in principle be marginally faster but the win is unmeasurable. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | LOW | This isn't an architecture change — it's a boundary tightening that already shipped in three sibling packages with identical shape. The wrong-target pattern is paint-by-numbers, not invention. |

The only non-trivial risk is **method-set drift between the issue
body and master**. The issue body lists `ReadNATPortCounter` and
`Compile` as consumed via `s.dp`, but `grep -rn` on master @
fcd53beb finds neither. The new interface lists what the code
actually uses today; if reviewers want a strict superset of "what
the issue body says," that's a different design and they can ask
me to add the two stale methods. I'd argue against — an unused
method on the interface defeats the boundary's purpose.

## 8. Test plan

- `make build` — package compiles, no Go vet warnings.
- `make test ./pkg/grpcapi/...` — full `pkg/grpcapi` test suite
  green. (Issue acceptance.)
- `make test ./pkg/api/... ./pkg/cli/... ./pkg/daemon/... ./pkg/conntrack/...`
  — adjacent packages still build because nothing outside `pkg/grpcapi`
  imports `grpcapi.grpcRuntime`.
- `make test` — full Go suite to confirm no incidental breakage.
- 5× named-test flake check on `TestSessionsCursorIteration` and
  `TestForwardingStatusAdapter` (the two test files that pin the
  provider-probe behavior, per `server_sessions_test.go` and
  `server_show_forwarding_adapter_test.go`).
- Deploy on `loss:xpf-userspace-fw0/fw1`.
- **Pass A (CoS disabled):** v4 + v6 × push + reverse on port
  5201, plus 12-stream `-R` reproducer on v4 and v6.
- **Pass B (CoS enabled):** per-class 5201-5206 × v4 + v6 ×
  push + reverse = 24 measurements.
- Manual gRPC-surface validation from the remote CLI on the loss
  cluster:
  - `show security flow session` — exercises
    `IterateSessions{,V6}` + `GetSessionV4/V6`.
  - `show security flow statistics` — exercises
    `ReadGlobalCounter`.
  - `clear security flow session all` — exercises
    `ClearAllSessions`.
  - `show system buffers` — exercises the
    `userspaceStatusProvider` and `GetMapStats` fallback.
  - `show chassis forwarding` — exercises the
    `userspaceStatusProvider` path in
    `forwardingStatusDataplane()`.

## 9. Out of scope (explicitly)

- `pkg/cli` migration (sub-issue #1517).
- `pkg/cluster` session-sync migration (sub-issue #1518).
- Removing `Daemon.legacyDP()` accessor (sub-issue #1519).
- `pkg/dataplane.New()` boot-path extraction (sub-issue #1520).
- `pkg/dataplane/userspace/maps_sync.go` BPF map name decoupling
  (sub-issue #1521).
- Splitting `grpcRuntime` into multiple smaller domain interfaces
  (counter-reader, session-store-clear, diag-clear) within
  `pkg/grpcapi`. The scope doc mentions this as a possible follow-up
  if S1 itself feels too large; I'm not doing it here because the
  whole-package interface is what already shipped for `pkg/api`.

## 10. Open questions for adversarial review

Each of these is a legitimate basis to vote PLAN-KILL.

1. **Is one whole-package `grpcRuntime` interface the right shape,
   or should it be split into named sub-interfaces by domain
   (counters, session-store, NAT bindings, diag-clear) so the
   coupling is even narrower?** Codex/AGY should walk
   `server_show_*.go` files and decide whether the sub-interface
   split would make handler signatures more honest (a show handler
   doesn't need clear methods).

2. **Stale-method handling.** The issue body lists
   `ReadNATPortCounter` and `Compile` as consumed via `s.dp` but
   master doesn't actually use them. Should the new interface
   include them anyway for forward compatibility, or drop them
   because the boundary's job is to reflect actual coupling?

3. **`sessionCursorIterator` placement.** It's used only inside
   `server_sessions.go`. Moving it to `runtime.go` consolidates it
   with the other provider interfaces but may obscure its
   single-call-site relationship. Keep it local, move it global, or
   inline-define both at every call site?

4. **`userspaceControlProvider` shape.** The control interface
   includes five methods that are called from a single handler each
   (queue/binding state, forwarding-armed, inject). Is it cleaner
   to define five micro-interfaces (one per control method) or one
   superset like the plan shows?

5. **Boundary regression canary.** `pkg/dataplane/userspace/manager_coupling_test.go`
   uses an AST-walking canary to enforce the eBPF/userspace
   boundary. Should this PR add a similar canary for
   `pkg/grpcapi/runtime.go` to prevent a future regression that
   re-imports `dataplane.DataPlane` into `grpcapi.Config.DP`? I am
   not adding one in this PR because it's a meta-concern that
   applies equally to every #1451 sub-issue; if you think it should
   land here, justify why this sub-issue is the right place rather
   than #1476.

6. **Architectural mismatch risk.** Is there any reason this
   tightening is the wrong move — e.g. an in-flight change that
   wants the gRPC server to stay coupled to the full interface, or
   a future plan where the legacy `DataPlane` shape is the only
   thing that survives and the domain interfaces get deleted?

7. **Test coverage adequacy.** Existing `server_sessions_test.go`
   and `server_show_forwarding_adapter_test.go` test the
   provider-probe behavior with concrete fakes. Is that sufficient
   coverage, or should the PR add explicit "fake satisfies
   `grpcRuntime`" compile-time assertions in test code?

## References

- `docs/pr/1451-migration-scope/scope.md` — sub-issue boundary
  definition.
- `pkg/api/handlers.go:28` — `apiRuntimeDataPlane` precedent.
- `pkg/fwdstatus/builder.go:35` — `DataPlaneAccessor` precedent.
- `pkg/monitoriface/monitor.go:30` — `RuntimeDataPlane` precedent.
- `pkg/conntrack` — `RuntimeDomainProvider` precedent.

Refs: #1516, #1451, #1373.
