# #1520 Plan: Extract Userspace Boot Path From Legacy `dataplane.New()`

**Status:** v4 — addresses AGY round-2 CRITICAL (existing AST canary
collision) and Codex round-3 stragglers. v3 addressed Codex
round-2 PLAN-NEEDS-MAJOR (9 findings).

v4 changes:
- §4.2: pin helper location to `pkg/daemon/daemon_run.go` and
  document the load-bearing
  `dataplane.NewRuntimeDataPlane(dpType)` reference required by
  `retirement_boundary_canary_test.go::TestDaemonRuntimeEntryPointUsesRuntimeDataPlane`.
- §4.3: rename "rollback / test seam" → "compatibility / test
  seam" (Codex round-3 finding 8).
- §8.5: drop the stale `Boot(BootOptions{})` reference (Codex
  round-3 finding 7).

v3 changes were: Changes from v1/v2:

- Drop premature `BootOptions{}` — use no-arg `Boot()` (finding 7).
- Drop the parse-text canary that targets a literal filename
  (findings 4 and 6) and replace with behavioral canaries on the
  daemon helper.
- Add behavioral test for `buildRuntimeDataPlane("")` AND
  `buildRuntimeDataPlane(TypeUserspace)` returning the adapter and
  for both producing the same concrete type (finding 5).
- §6 now requires that BOTH empty default and explicit
  `TypeUserspace` route through `Boot()` (finding 2).
- Strike the "structured config gate" wording — §4.4 is documentation
  only; the rollback gate is the existing `dataplane-type` config
  knob (finding 3).
- Call the registry path a "compatibility/test seam," not "rollback"
  (finding 8) — rollback is `dataplane-type ebpf` through
  `NewRuntimeDataPlane()`, not through the userspace registry.
- Sharpen the structural value statement (finding 1): the
  enforceable delta is that `pkg/daemon` no longer compiles against
  the registry indirection for the userspace path. Future #1521
  threads typed options through the new `Boot()` signature; today
  there is no opt struct.
- #1521 coordination: this slice does NOT add `BootOptions`, so
  there is no API surface for #1521 to extend yet (finding 9).
  Semantic coordination is now stated explicitly in §7.

**Scope (one line):** sub-#1451 S5; provide a userspace-native
constructor that does not require the legacy `dataplane.New()`
registry round-trip for daemon startup, while keeping the explicit
retained AF_XDP XDP-shim subset of the legacy `dataplane.Manager`
that the userspace runtime intentionally still uses.

If reviewers conclude the extraction does not meaningfully reduce
coupling — e.g., because the surviving `bpfShim` field still ties
the userspace runtime to the legacy Manager type by AST canary —
PLAN-KILL is an acceptable verdict.

## 1. Issue framing

`pkg/dataplane/userspace/manager.go` constructs the userspace
backend through `dataplane.RegisterRuntimeBackend(TypeUserspace, …)`
in an `init()`, and daemon startup reaches the userspace runtime
through `dataplane.NewRuntimeDataPlane(dpType)` which:

1. routes empty default (`EffectiveType("")` → `"userspace"`) to
   the userspace registry constructor;
2. calls the registry closure, which calls `userspace.New()`;
3. wraps the result in `*LegacyDataPlaneAdapter` for legacy callers.

`userspace.New()` in turn calls `dataplane.New()` to build a full
legacy `*dataplane.Manager`, then calls
`SelectUserspaceXDPShimEntryProgram()` to retarget the XDP entry
program for future attachments. The userspace runtime only uses a
narrow subset of that Manager — the retained AF_XDP XDP-shim
loader (`LoadUserspaceShim`/`CompileUserspaceShim`), the shared
shim/session maps (`userspace_ctrl`, `userspace_bindings`,
`userspace_xsk_map`, `sessions`, `sessions_v6`, `fib_gen_map`,
…), and a handful of HA/fabric/counter helpers — but the registry
indirection and the `New()`-shaped construction hide that.

The acceptance criteria from #1520 say:

> - A new `userspace.Boot()` (or equivalent) constructs the
>   userspace manager without going through
>   `dataplane.New(TypeUserspace)`.
> - The `xdp_main_prog` / `xdp_userspace_prog` swap path either
>   moves into the dedicated userspace-XDP shim (per #1473) or is
>   documented as the explicit retained fallback with a structured
>   config gate.
> - Backend registration via `RegisterBackend(TypeUserspace, …)`
>   either remains for the rollback path (`dataplane-type ebpf`) or
>   is documented as removed in coordination with #1474.

#1474 is closed; explicit `dataplane-type ebpf` is the only
remaining rollback. #1473 is still open and #1493/#1494 already
landed (loader split + canary).

## 2. Honest scope / value framing

This is **not** a performance change. The retained `bpfShim` field
in `userspace.Manager` is intentionally kept under an AST canary
(`TestUserspaceManagerDoesNotEmbedLegacyDataPlane`) that requires
the field to remain — see
`pkg/dataplane/userspace/manager_coupling_test.go:53`:

```go
if !hasExplicitBPFShim {
    t.Fatal("userspace Manager must keep an explicit bpfShim field for userspace XDP maps")
}
```

So the structural value of #1520 is **not** to remove the typed
`*dataplane.Manager` field from `userspace.Manager`. It is to:

1. give the **construction call chain** in `cmd/xpfd/main.go` →
   `pkg/daemon/daemon_run.go` a userspace-native entry point that
   does not require `dataplane.NewRuntimeDataPlane(TypeUserspace)`
   to detour through the legacy registry, while still resolving the
   default (empty `dataplane-type`) the same way at the
   configuration layer;
2. give the codebase a single named seam — `userspace.Boot()` — for
   future #1521 (maps-name decoupling) and #1473 (XDP shim split)
   to thread their narrower types through, rather than each one
   re-deriving the construction chain;
3. classify the `dataplane-type ebpf` rollback path explicitly so
   the legacy `dataplane.New()` constructor and the
   `xdp_main_prog`/`xdp_userspace_prog` swap stay clearly fenced off
   to that one branch.

If reviewers feel that adding `userspace.Boot()` is a thin rename
of `userspace.New()` plus a tiny daemon wiring change, **that is
exactly the scope this slice intends**. We are not chasing a Manager
type split here; the canary explicitly forbids it. #1520 is a
construction-chain seam, not an internal Manager split.

The Manager-shape split — moving `bpfShim` to a typed
`UserspaceXDPShimLoader` that only owns the XDP shim
programs/maps — is intentionally **out of scope** for this slice
because it touches six files (`manager.go`, `manager_ha.go`,
`maps_sync.go`, `policycounters.go`, `process.go`,
`legacy_dataplane.go`) and overlaps with the in-flight #1521
maps_sync rename. Doing it here would collide with the sibling
agent's work and require re-running the smoke matrix twice.

## 3. What's already shipped

- **#1494** (PR merged): canary that keeps the retained userspace
  shim boundary stable.
- **#1493** (closed): userspace shim loader split. The current code
  already has `LoadUserspaceShim()` and `CompileUserspaceShim()`
  that bypass `loadAllObjects()`. `userspace.Manager.Load()` calls
  `bpfShim.LoadUserspaceShim()`, not the legacy `Load()`.
- **#1474** (closed): omitted `dataplane-type` already resolves to
  userspace via `EffectiveType("")`.
- **#1381** (closed for blocking interface split): `RuntimeDataPlane`
  interface exists; `userspace.Manager` implements it.
- **Existing AST canary** in
  `pkg/dataplane/userspace/manager_coupling_test.go` enforces:
  - `Manager` does not embed `dataplane.DataPlane`;
  - `Manager` keeps a typed `bpfShim *dataplane.Manager` field
    (load-bearing — do not remove);
  - `*Manager` does NOT implement `dataplane.DataPlane`;
  - `*Manager` DOES implement `dataplane.RuntimeDataPlane`;
  - `NewRuntimeDataPlane(TypeUserspace)` returns
    `*LegacyDataPlaneAdapter` (the legacy-compatibility wrapper).

The existing factory path is at `pkg/dataplane/dataplane.go:173`:

```go
func NewRuntimeDataPlane(dpType string) (RuntimeDataPlane, error) {
    dpType = EffectiveType(dpType)
    switch dpType {
    case TypeEBPF:
        return New(), nil
    case TypeDPDK:
        return nil, ErrDPDKBackendRetired
    default:
        if ctor, ok := runtimeBackendRegistry[dpType]; ok {
            return ctor(), nil
        }
        ...
    }
}
```

And the registry side at `pkg/dataplane/userspace/manager.go:60`:

```go
func init() {
    dataplane.RegisterRuntimeBackend(dataplane.TypeUserspace, func() dataplane.RuntimeDataPlane {
        return NewLegacyDataPlaneAdapter(New())
    })
}
```

## 4. Concrete design

### 4.1 Add `userspace.Boot()` as the userspace-native constructor

In `pkg/dataplane/userspace/manager.go`, add:

```go
// Boot constructs the userspace AF_XDP runtime and returns it as a
// dataplane.RuntimeDataPlane wrapped in the legacy-compatible adapter.
//
// Daemon startup MUST prefer Boot() over dataplane.NewRuntimeDataPlane(
// TypeUserspace) for the default and explicit userspace selections.
// The legacy registry path is retained for the explicit
// `dataplane-type ebpf` rollback only, because that branch deliberately
// resolves through dataplane.New() and the legacy program loader.
//
// The returned value still implements dataplane.DataPlane via the
// adapter, so unmigrated callers (pkg/cli, pkg/api, pkg/conntrack,
// pkg/fwdstatus) continue to compile until #1451 finishes the surface
// shrink. When #1521 / #1473 need to thread additional construction
// configuration in, they should add a typed options argument here —
// not pre-emptively. See Claude SMR review feedback rejecting empty
// `BootOptions{}` as premature YAGNI.
func Boot() dataplane.RuntimeDataPlane {
    return NewLegacyDataPlaneAdapter(New())
}
```

This is intentionally close to a typed rename. The new value is in
the **call site** — daemon startup no longer needs to consult the
runtime backend registry for the userspace path.

### 4.2 Daemon startup chooses Boot() for userspace, registry for legacy

The helper `buildRuntimeDataPlane()` **MUST** live inside
`pkg/daemon/daemon_run.go` and the helper body **MUST** contain the
literal call `dataplane.NewRuntimeDataPlane(dpType)` for the
non-userspace fall-through. This is load-bearing: the existing AST
canary
`pkg/dataplane/retirement_boundary_canary_test.go::TestDaemonRuntimeEntryPointUsesRuntimeDataPlane`
parses `pkg/daemon/daemon_run.go` and fails if
`dataplane.NewRuntimeDataPlane` is no longer referenced in that file
(see `hasDaemonRuntimeConstructorCall` at
`retirement_boundary_canary_test.go:3366`). Splitting the helper
into a new file or replacing the legacy-path call with a different
constructor would trigger
`t.Fatal("daemon runtime startup no longer calls dataplane.NewRuntimeDataPlane")`.

In `pkg/daemon/daemon_run.go`, replace:

```go
dpType := ""
if cfg := d.store.ActiveConfig(); cfg != nil {
    dpType = cfg.System.DataplaneType
}
dp, err := dataplane.NewRuntimeDataPlane(dpType)
```

with:

```go
dpType := ""
if cfg := d.store.ActiveConfig(); cfg != nil {
    dpType = cfg.System.DataplaneType
}
dp, err := buildRuntimeDataPlane(dpType)
```

and add the helper inside `pkg/daemon/daemon_run.go`:

```go
// buildRuntimeDataPlane selects the userspace-native Boot() path for
// the default and explicit userspace selections, and falls through to
// dataplane.NewRuntimeDataPlane only for the explicit legacy eBPF
// rollback (and the retired-DPDK error case). Keeping the legacy
// branch routed through the dataplane factory preserves the
// ErrDPDKBackendRetired sentinel handling unchanged AND preserves
// the existing retirement_boundary_canary_test.go AST canary that
// requires daemon_run.go to reference dataplane.NewRuntimeDataPlane.
//
// This helper MUST stay in daemon_run.go for the AST canary above.
// Do not split into pkg/daemon/dataplane_boot.go.
func buildRuntimeDataPlane(dpType string) (dataplane.RuntimeDataPlane, error) {
    switch dataplane.EffectiveType(dpType) {
    case dataplane.TypeUserspace:
        return userspace.Boot(), nil
    default:
        return dataplane.NewRuntimeDataPlane(dpType)
    }
}
```

### 4.3 Keep the runtime backend registration as the compatibility / test seam

The `init()` in `pkg/dataplane/userspace/manager.go` continues to
register a userspace runtime backend so that
`dataplane.NewRuntimeDataPlane("userspace")` still works for
callers (tests, future operator surfaces) that go through the
registry. The registry path stays a thin alias for the canonical
`userspace.Boot()` constructor:

```go
func init() {
    dataplane.RegisterRuntimeBackend(dataplane.TypeUserspace, func() dataplane.RuntimeDataPlane {
        return Boot()
    })
}
```

This satisfies #1520 acceptance criterion 3 ("Backend registration
… either remains for the rollback path"): registration remains, and
its presence is documented in code as the **compatibility/test
seam**, not the canonical daemon startup path and not the operator
rollback path. The operator rollback path is
`dataplane-type ebpf` which goes through
`dataplane.NewRuntimeDataPlane()` → `New()` (legacy
`*dataplane.Manager`) and never touches the userspace registry
entry.

### 4.4 `xdp_main_prog` / `xdp_userspace_prog` swap path documentation

Add a short doc paragraph in
`docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md`
under a new "Userspace boot path classification" section, and a
shorter pointer comment at
`pkg/dataplane/loader.go:100` (above
`SelectUserspaceXDPShimEntryProgram`) that:

- `xdp_main_prog` is the legacy entry program used **only** by the
  explicit `dataplane-type ebpf` rollback;
- `xdp_userspace_prog` is the retained AF_XDP shim entry that
  userspace.Boot() selects via `bpfShim.SelectUserspaceXDPShimEntryProgram()`;
- the userspace boot path never calls
  `bpfShim.Load()` (which would invoke `loadAllObjects()` and load
  the legacy XDP/TC tail-call objects); it calls
  `bpfShim.LoadUserspaceShim()` exclusively;
- the swap-back path in
  `pkg/dataplane/userspace/maps_sync.go` calls
  `bpfShim.SwapToUserspaceXDPShimEntryProgram()` defensively after
  a link cycle. This is operationally observable in
  `show system buffers` and userspace status but is **not** a new
  config gate — the only operator-facing dataplane gate is the
  existing `set system dataplane-type {ebpf|userspace}` knob. The
  swap NEVER goes the other direction in normal userspace startup.

This documentation satisfies #1520 acceptance criterion 2
("documented as the explicit retained fallback with a structured
config gate"): the structured gate is the existing
`dataplane-type` knob, not a new flag introduced by this slice.

### 4.5 New AST canary: `Boot()` is the daemon entry point

Add behavioral canary tests in two places:

In `pkg/dataplane/userspace/userspace_boot_canary_test.go`:

- asserts behavior of `Boot()`: returns a value that
  - implements `dataplane.RuntimeDataPlane`,
  - implements `dataplane.DataPlane` (adapter identity preserved),
  - is concretely `*LegacyDataPlaneAdapter`,
  - has the same concrete type as
    `dataplane.NewRuntimeDataPlane(dataplane.TypeUserspace)`.
- the existing registry canary
  `TestUserspaceBackendRegistryReturnsRuntimeAdapterForLegacyCallers`
  is kept and continues to assert
  `dataplane.NewRuntimeDataPlane(TypeUserspace)` returns the same
  shape.

In `pkg/daemon/dataplane_boot_test.go` (new test file in the
daemon package so the helper is directly exercised):

- `TestBuildRuntimeDataPlaneDefaultUsesUserspaceBoot` asserts that
  `buildRuntimeDataPlane("")` returns the userspace adapter (same
  concrete type as `userspace.Boot()`).
- `TestBuildRuntimeDataPlaneUserspaceUsesUserspaceBoot` asserts the
  same for `buildRuntimeDataPlane(dataplane.TypeUserspace)`.
- `TestBuildRuntimeDataPlaneEBPFRoutesToLegacyManager` asserts
  `buildRuntimeDataPlane(dataplane.TypeEBPF)` returns the legacy
  `*dataplane.Manager` shape (NOT `*LegacyDataPlaneAdapter`).
- `TestBuildRuntimeDataPlaneDPDKReturnsRetired` asserts
  `buildRuntimeDataPlane(dataplane.TypeDPDK)` propagates
  `ErrDPDKBackendRetired` unchanged.

No file is parsed for a literal text reference — the canary that
v2 proposed against `pkg/daemon/daemon_run.go` is dropped per
Codex round-2 finding 4/6 (brittle text-shape check that breaks
under a future file rename without any behavioral regression).

## 5. Public API preservation

- `userspace.New()`: unchanged signature and behavior. It remains
  the lower-level constructor (returns `*Manager`).
- `userspace.NewLegacyDataPlaneAdapter(*Manager) *LegacyDataPlaneAdapter`:
  unchanged. Still used by `Boot()`.
- `dataplane.NewRuntimeDataPlane(string) (RuntimeDataPlane, error)`:
  unchanged signature and behavior.
- `dataplane.NewDataPlane(string) (DataPlane, error)`: unchanged.
- AST canaries in
  `pkg/dataplane/userspace/manager_coupling_test.go`: must remain
  green. The `bpfShim *dataplane.Manager` field stays.
- The runtime backend registry still has a userspace entry.

## 6. Hidden invariants the change must preserve

0. **Default routing.** Both `dpType == ""` and
   `dpType == TypeUserspace` MUST route through `userspace.Boot()`,
   not through `dataplane.NewRuntimeDataPlane()`. The daemon
   helper resolves the empty default itself via
   `dataplane.EffectiveType()` and dispatches accordingly. This
   is the load-bearing structural delta of #1520.

1. **Side-effect ordering on startup.** `userspace.New()` calls
   `bpfShim.SelectUserspaceXDPShimEntryProgram()` BEFORE returning.
   Daemon then calls `d.dp.Start(ctx)` which calls
   `Manager.Load()` → `bpfShim.LoadUserspaceShim()` → which
   re-selects the userspace entry program inside `LoadUserspaceShim`.
   Both call sites must continue to hold. `Boot()` must not skip
   the pre-Load entry-program selection because `Compile()` may run
   before `Load()` in some non-default code paths.

2. **`init()` ordering.** The `RegisterRuntimeBackend` call must
   still run at package init time. `Boot()` must be safe to call
   either before or after the registry init runs (no shared
   mutable state).

3. **Adapter identity.** The daemon `legacyDP()` helper depends on
   the runtime dp being type-assertable to `dataplane.DataPlane`.
   `*LegacyDataPlaneAdapter` satisfies that. `Boot()` MUST return
   the adapter, not the bare `*Manager`. (Without the adapter,
   `legacyDP()` returns nil and CLI / API status paths silently
   degrade.)

4. **No stray legacy-loader hop.** `Boot()` must not call
   `bpfShim.Load()` or invoke the legacy `loadAllObjects()` path
   transitively. The retained shim loader path must remain the only
   load call.

5. **HA fabric forwarding.** `manager.go:276,283` still call
   `bpfShim.UpdateFabricFwd`/`UpdateFabricFwd1` directly through
   the kept `bpfShim` field. `Boot()` must preserve the `bpfShim`
   identity and not introduce a different Manager instance for
   fabric forwarding vs. the rest of the userspace runtime.

6. **Rollback path.** `dataplane-type ebpf` still constructs a
   bare `*dataplane.Manager` (legacy) via the
   `dataplane.NewRuntimeDataPlane` → `New()` switch case. The
   daemon wrapper must continue to route TypeEBPF through
   `dataplane.NewRuntimeDataPlane`, not through `userspace.Boot()`.

7. **DPDK retirement sentinel.** `dataplane-type dpdk` still
   returns `ErrDPDKBackendRetired`. The daemon wrapper MUST
   propagate that sentinel unchanged so the existing
   `errors.Is(err, dataplane.ErrDPDKBackendRetired)` branch in
   `daemon_run.go` keeps working.

## 7. Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression risk | LOW | `Boot()` is a thin constructor wrapping `New()` + `LegacyDataPlaneAdapter`. Daemon wrapper preserves all existing sentinel error handling. |
| Lifetime / borrow-checker risk | N/A | Go; no borrow checker concerns. |
| Performance regression risk | NONE | Boot() runs once at daemon startup. No hot-path change. |
| Architectural mismatch risk | MEDIUM | The AST canary forbids removing the `bpfShim` field. If reviewers want the slice to also peel `bpfShim` off into a smaller type, they should PLAN-KILL this slice and open a new issue that updates the canary. This slice deliberately does NOT touch the Manager shape. |
| Sibling-PR collision risk | LOW | Touches `pkg/dataplane/userspace/manager.go` (init + new Boot), `pkg/daemon/daemon_run.go` (one call-site change + new helper inline), and adds `pkg/dataplane/userspace/userspace_boot_canary_test.go` + `pkg/daemon/dataplane_boot_test.go`. #1521 touches `pkg/dataplane/userspace/maps_sync.go`. No file overlap. Semantic coordination: #1521 does NOT consume any new exported type from this slice. This slice does NOT add a `BootOptions` API for #1521 to extend. Future #1521 / #1473 may add a typed options argument to `Boot()` at that time. |

## 8. Test plan

1. **Build clean.** `make build` succeeds.
2. **Cargo unaffected.** `cd userspace-dp && cargo build --release`
   succeeds (no Rust changes — sanity check only).
3. **Existing AST canaries green.**
   `go test ./pkg/dataplane/userspace/... -run TestUserspaceManager`
   passes — the existing
   `TestUserspaceManagerDoesNotEmbedLegacyDataPlane`,
   `TestUserspaceManagerRuntimeContractDoesNotExposeLegacyDataPlane`,
   and
   `TestUserspaceBackendRegistryReturnsRuntimeAdapterForLegacyCallers`
   must continue to pass.
4. **New canary.** Behavioral tests in
   `pkg/daemon/dataplane_boot_test.go` pass (default, userspace,
   ebpf, dpdk routes — see §4.5).
5. **Boot() return-shape canary.** `TestUserspaceBootReturnsAdapter`
   asserts `Boot()` returns `*LegacyDataPlaneAdapter` and that the
   adapter still implements both `dataplane.DataPlane` and
   `dataplane.RuntimeDataPlane`.
6. **Rollback path canary.** `TestBuildRuntimeDataPlaneRoutesEBPFThroughLegacyFactory`
   asserts the daemon helper still routes `dataplane-type ebpf`
   through the legacy factory and returns the legacy
   `*dataplane.Manager` (not `*LegacyDataPlaneAdapter`).
7. **DPDK sentinel canary.**
   `TestBuildRuntimeDataPlaneDPDKReturnsRetired` asserts the helper
   still propagates `ErrDPDKBackendRetired` unchanged.
8. **5×flake** for the new canaries.
9. **Full Go suite.** `make test`.
10. **Loss userspace cluster smoke matrix (mandatory):**
    - `make cluster-deploy` (deploys loss:xpf-userspace-fw0/fw1).
    - Pass A (CoS disabled): v4+v6 × push+reverse single-stream
      baseline (8 cells) and 12-stream `-R` reproducer on v4 + v6.
    - Pass B (CoS enabled): per-class smoke ports 5201-5206 ×
      v4+v6 × push+reverse (24 cells).
11. **Link-cycle smoke.** Run the cluster's link-cycle path
    (the PR #1513 test infrastructure) and confirm userspace
    rebinds XSK sockets cleanly after a kernel link DOWN/UP.

## 9. Out of scope (explicitly)

The following are deferred to other slices and MUST NOT be
attempted in this PR:

- Renaming `bpfShim` or moving it to a smaller typed loader. The
  AST canary forbids removing the field, and a rename would
  require updating six files plus the canary in one go. Defer to
  a future "Manager shape split" issue if one is opened.
- Moving `userspace_ctrl`/`userspace_bindings`/`userspace_xsk_map`
  map name lookups off `bpfShim.Map(...)`. That's #1521's scope.
- Splitting the retained AF_XDP XDP shim from the legacy
  `xdp_main` fallback at the Rust shim level. That's #1473's scope.
- Removing the runtime backend registration. Acceptance criterion
  3 explicitly allows keeping registration as the rollback /
  test seam.
- Touching the legacy `dataplane.NewDataPlane` switch case for
  TypeEBPF. The eBPF rollback path stays exactly as it is.
- Adding a new config flag. No new operator surface in this
  slice; no Junos CLI change.

## 10. Open questions for adversarial review

1. **Is `userspace.Boot()` meaningfully different from
   `userspace.New()` + `NewLegacyDataPlaneAdapter(...)`?** If
   reviewers feel the constructor is just a typed rename without
   architectural value, PLAN-KILL the slice and add a doc comment
   to the existing registry init instead. The slice's value is
   the daemon wrapper that fences the legacy registry off to the
   rollback branch.

2. **Should the daemon wrapper be in `pkg/daemon/` or moved into
   `pkg/dataplane/` as a factory that knows about backend
   selection?** Putting the wrapper at the daemon layer keeps
   `pkg/dataplane/` free of daemon-only construction policy.
   Putting it in `pkg/dataplane/` centralizes the registry / Boot
   choice but couples the dataplane package to userspace
   selection policy. The plan picks the daemon-layer wrapper.
   Reviewers may prefer otherwise.

3. **Does the new daemon wrapper change `ErrDPDKBackendRetired`
   handling at all?** It must not — the daemon already has a
   `errors.Is(err, dataplane.ErrDPDKBackendRetired)` branch. The
   wrapper for TypeUserspace cannot produce that error (Boot()
   doesn't fail). For TypeEBPF and TypeDPDK and other types, the
   wrapper falls through to `dataplane.NewRuntimeDataPlane()`
   which returns the sentinel unchanged. Reviewers should verify
   this is preserved end-to-end.

4. **Is the new AST canary brittle?** RESOLVED in v3: the
   text-shape canary on `daemon_run.go` is dropped. The new tests
   are behavioral — they call `buildRuntimeDataPlane()` directly
   and assert returned types — and are stable across file
   renames.

5. **Is the BootOptions struct premature future-proofing?**
   RESOLVED in v3: `Boot()` takes no arguments. Future slices that
   need to thread options can add them at that point.

6. **#1521 collision.** #1521 is decoupling `maps_sync.go` from
   hard-coded BPF map name string literals. #1520 does not touch
   `maps_sync.go`. There is no file overlap. Reviewers should
   verify by walking the diff that no `maps_sync.go` line is
   touched.

7. **Does the `RegisterRuntimeBackend` rollback path stay
   reachable?** A test must call
   `dataplane.NewRuntimeDataPlane(dataplane.TypeUserspace)` and
   confirm it still returns `*LegacyDataPlaneAdapter`. If `Boot`
   replaces the registry constructor body, the test must still
   pass.

## 11. Reviewer note

Reviewers are encouraged to treat PLAN-KILL as a real option. The
methodology has used it before to stop slices whose architectural
premise was wrong (#946 Phase 2, #961 PacketContext). #1520's
premise is bounded — give the daemon a userspace-native
construction seam and fence the legacy factory off to the
rollback branch — but if reviewers conclude the seam adds no
structural value over a doc comment, PLAN-KILL is correct.
