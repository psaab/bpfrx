# #1547 — Split `pkg/frr/frr.go` (Plan v3)

**Status:** DRAFT v3 — addresses round 2 findings from
Codex (PLAN-NEEDS-MAJOR) and Gemini (PLAN-KILL on reload bypass).

## Review history

- **Round 1** (plan v1, commit `f9713e65`)
  - Codex `task-mpn2tga9-k9tqob`: PLAN-NEEDS-MAJOR — defer of
    vtyshExecutor, wrong grouping for `ifaceNetwork`,
    `ApplyFull` inline blocks left in orchestrator, README
    will go stale.
  - Gemini `task-mpn2twzv-dyoeha`: PLAN-KILL — false cohesion
    claim in `policy_render.go`, AC#3 cannot be deferred.
- **Round 2** (plan v2, commit `71370dc7`)
  - Codex `task-mpn3es2s-6o96p3`: PLAN-NEEDS-MAJOR —
    zero-value Manager panic on `var m frr.Manager`;
    parsing methods in `status_parse.go` must also route
    through the executor; stale v1 text in plan contradicts
    v2; no fake-executor tests required by plan; ECMP block
    in `ApplyFull` not addressed (Gemini also flagged this).
  - Gemini `task-mpn3fedx-8nv5ky`: PLAN-KILL — single-method
    `exec(cmd)` executor signature does not cover `m.reload()`,
    which itself shells out to `systemctl reload frr` (with
    context timeout) and falls back to `vtysh -f m.frrConf`.
    AC#3 is therefore still not satisfied: `ApplyFull` cannot
    be mocked in tests because `reload()` still escapes the
    executor.

## What v3 changes vs v2

1. **Broader `frrExecutor` interface** (renamed from
   `vtyshExecutor` to reflect coverage of the systemctl + vtysh
   reload path too). Three methods, all private to the
   package:
   ```go
   type frrExecutor interface {
       // Vtysh "-c" one-shot command. Used by ExecVtysh and all
       // status query methods (parsed + raw).
       Vtysh(command string) (string, error)
       // systemctl reload frr with caller-supplied context for
       // the 15s timeout invariant.
       SystemctlReload(ctx context.Context) error
       // vtysh -f <conf> fallback when systemctl reload fails.
       VtyshLoad(ctx context.Context, conf string) ([]byte, error)
   }
   ```
   `realExecutor` (private) wraps `exec.Command` /
   `exec.CommandContext` for each method. The bodies are
   byte-identical to the existing call sites
   (`pkg/frr/frr.go:1056-1075` for reload,
   `pkg/frr/frr.go:1597-1605` for vtysh).
2. **Zero-value-safe accessor.** `Manager` gains an unexported
   helper `func (m *Manager) executor() frrExecutor` that
   returns `m.exec` if non-nil, otherwise the package-default
   `realExecutor{}`. Every internal call site uses
   `m.executor().Vtysh(...)` / `.SystemctlReload(ctx)` /
   `.VtyshLoad(ctx, conf)`. This preserves the existing
   contract that `var m frr.Manager; m.ExecVtysh(...)` does
   not panic on a literal `Manager`.
3. **All vtysh-shelling paths route through the executor**:
   - Public `Manager.ExecVtysh` and all raw `Get*` methods
     in `vtysh.go`.
   - Parsed methods in `status_parse.go` (`GetRIPRoutes`,
     `GetISISAdjacency`, `GetOSPFNeighbors`,
     `GetBGPSummary`, `GetBGPRoutes`, `GetRouteDetailJSON`)
     also call `m.executor().Vtysh(...)`. The parsers stay
     in `status_parse.go`; only the exec call changes.
   - `Manager.reload` in `manager.go` uses
     `m.executor().SystemctlReload(ctx)` and
     `m.executor().VtyshLoad(ctx, m.frrConf)`. The 15s
     `context.WithTimeout(context.Background(), 15*time.Second)`
     timeout stays in `reload()` exactly as today; only the
     `exec.Command*` calls become method calls on the executor.
4. **`ApplyFull` becomes pure ordering glue.** Per Codex
   finding 4 (round 1) and Gemini ECMP finding (round 2),
   every inline rendering and policy-resolution block moves
   to a named helper in `config_render.go`:
   - `renderGenerateRoutes(b *strings.Builder, fc *FullConfig)`
   - `renderDHCPDefaults(b *strings.Builder, fc *FullConfig)`
   - `renderBackupRouter(b *strings.Builder, fc *FullConfig)`
   - `renderClusterModeDefaults(b *strings.Builder, fc *FullConfig)`
   - `resolveECMP(fc *FullConfig) int` — returns the
     `ecmpMaxPaths` value and **also mutates
     `fc.ConsistentHash`** as today (this side-effect is
     documented in the function doc comment because it's
     unusual).
5. **File grouping unchanged from v2.** Exactly 5 sibling
   `.go` files per user mandate: `manager.go`,
   `config_render.go`, `vtysh.go`, `status_parse.go`,
   `policy_render.go`. `policy_render.go` is documented in
   its file-header doc comment as "protocols + policy
   rendering". The user override on the 5-file count is the
   adjudicated answer; reviewers are not invited to
   re-litigate.
6. **README updated** to reflect the new layout (entry-point
   list maps `Manager` to `manager.go`; the status-query
   bullet maps to `status_parse.go` and `vtysh.go`).
7. **Fake-executor tests added.** New `frr_executor_test.go`
   (or appended to `frr_test.go` — pick whichever keeps
   diffs cleanest) exercises:
   - `Manager.ExecVtysh` with an injected fake (asserts
     command string forwarded).
   - One parsed method (`Manager.GetRIPRoutes`) with a
     fake that returns a canned vtysh response.
   - `Manager.reload` happy path (systemctl succeeds) and
     fallback path (systemctl fails, vtysh -f succeeds)
     with a fake executor.

## Issue framing

`pkg/frr/frr.go` is 1606 LOC and mixes four responsibilities:

1. **Config rendering** — managed-section, interface
   settings, static-route emission, per-VRF rendering,
   `Apply`/`ApplyFull` orchestration, `writeManagedSection`,
   `reload`.
2. **Vtysh execution** — `vtyshCmd`, `ExecVtysh`, and thin
   per-feature raw-output shells.
3. **Status parsing** — `Get*` methods that parse vtysh
   output into typed `*Entry`/`*Neighbor`/`*Route` values.
4. **Protocol + policy rendering** — `generateProtocols`
   (OSPF/OSPFv3/BGP/RIP/ISIS), `generatePolicyOptions`
   (prefix-lists, route-maps, communities),
   `resolveRedistribute`, BFD profile dedup,
   `ifaceNetwork`.

Issue acceptance criteria:

1. Existing FRR output remains byte-for-byte identical for
   current fixtures.
2. Route-map / prefix-list rendering has focused tests.
3. vtysh command execution is behind a narrow interface for
   tests.
4. `go test ./pkg/frr/...` passes.

This plan covers AC1 (regression oracle is the existing
`frr_test.go`), AC3 (via the `frrExecutor` interface), and
AC4 (build + test gate). AC2 is partially covered: the
existing rendering tests already lock prefix-list and
route-map output byte-for-byte; introducing brand-new
isolated tests for these is a deferred follow-up (the
existing tests are not torn down, just renamed by call
graph).

## Honest scope/value framing

Pure code motion within `package frr` plus one new private
interface and zero-value-safe accessor. Public API and
rendered output unchanged.

Wins:
- Future merge conflicts scoped to the file that owns the
  affected concern.
- vtysh-shelling can be faked for tests (AC#3), enabling
  test coverage of `reload()` and `ApplyFull` that today
  requires a real `vtysh` binary on the test host.
- Adding a new protocol drops into `policy_render.go`
  without touching manager lifecycle.

No perf gain. No correctness change.

*If reviewers conclude the structural+testability win is
too small to justify the churn, PLAN-KILL is acceptable.*

## What's already shipped

- `pkg/frr/README.md` documents the existing module
  contract; v3 plan updates it.
- `pkg/frr/frr_test.go` (2311 LOC) is the byte-for-byte
  regression oracle.
- The 15s FRR reload context timeout is a documented
  shutdown-correctness invariant
  (CLAUDE.md / docs/engineering-style.md).

## Concrete design

All files live at `pkg/frr/` and remain in `package frr`.

### `pkg/frr/manager.go`

Owns package-level types and the `Manager` lifecycle:

- `Manager` struct (with the new unexported
  `exec frrExecutor` field).
- `New() *Manager` — initializes `frrConf` and `exec` to
  the real implementation.
- `markerBegin` / `markerEnd` / `DefaultFRRConf` constants.
- `InstanceConfig`, `DHCPRoute`, `FullConfig` types.
- `Apply`, `ApplyWithInstances`, `ApplyFull`, `Clear`,
  `writeManagedSection`, `reload`.
- `(*Manager).executor()` accessor (returns `m.exec` or
  `realExecutor{}` if nil).
- `ApplyFull` becomes pure ordering glue: every inline
  rendering and policy-resolution block delegates to a
  named helper in `config_render.go`. Comment block at the
  top of `ApplyFull` lists the emission order as a contract.

### `pkg/frr/config_render.go`

Non-protocol config rendering helpers:

- `generateInterfaceSettings` (interface-block bandwidth +
  point-to-point hints).
- `generateStaticRoute` (per-prefix `ip route` / `ipv6 route`
  emission with RETH name translation and IPv6 next-hop
  interface resolution).
- New named extractors:
  - `renderGenerateRoutes(b, fc)` — emits one blackhole
    static per `GenerateRoute`, picking v4 vs v6 by `:`.
  - `renderDHCPDefaults(b, fc)` — computes
    `hasV4Default`/`hasV6Default` from `fc.StaticRoutes`
    and `fc.Inet6StaticRoutes`, then iterates
    `fc.DHCPRoutes` to emit AD-200 defaults that don't
    collide with explicit static defaults.
  - `renderBackupRouter(b, fc)` — emits AD-250 default.
  - `renderClusterModeDefaults(b, fc)` — emits the dual-AF
    blackhole AD-250 defaults.
  - `resolveECMP(fc) int` — computes `ecmpMaxPaths` and
    mutates `fc.ConsistentHash` (documented side-effect).

### `pkg/frr/policy_render.go`

**Protocols + policy rendering** (per the file header doc
comment — name kept for the user 5-file mandate):

- `generateProtocols` (OSPF, OSPFv3, BGP, RIP, ISIS).
- `generatePolicyOptions` (prefix-lists, route-maps,
  communities).
- `resolveRedistribute`, `knownRedistProtocols`.
- `bfdProfile`, `bfdProfileName`.
- `ifaceNetwork` (called from OSPF rendering at the
  original `frr.go:689` site).

### `pkg/frr/vtysh.go`

Vtysh execution surface and the `frrExecutor` interface:

- `frrExecutor` interface (Vtysh / SystemctlReload /
  VtyshLoad) — see "What v3 changes" section.
- `realExecutor` struct (zero-field, methods do the
  `exec.Command*` calls byte-identical to today).
- `Manager.ExecVtysh` and all raw `Get*` methods that
  used to call `vtyshCmd` now call
  `m.executor().Vtysh(...)`.

### `pkg/frr/status_parse.go`

Parsing helpers and their public types:

- `RIPRouteEntry` + `Manager.GetRIPRoutes`.
- `ISISAdjacency` + `Manager.GetISISAdjacency`.
- `OSPFNeighbor` + `Manager.GetOSPFNeighbors`.
- `BGPPeerSummary` + `Manager.GetBGPSummary`.
- `BGPRoute` + `Manager.GetBGPRoutes`.
- `FRRRouteDetail`, `FRRNextHop`, `frrRouteJSON`,
  `frrNextHopJSON`.
- `Manager.GetRouteDetailJSON`, `parseRouteJSON`,
  `FormatRouteDetail`.

All `Get*` methods that shell out call
`m.executor().Vtysh(...)` so they can be faked in tests.

## Public API preservation

Every exported identifier on `frr.Manager`, every exported
package type, every exported package function keeps its
exact signature and exact package path `pkg/frr`. External
callers (`pkg/daemon`, `pkg/grpcapi`, `pkg/api`,
`cmd/xpfd`) see zero import-path change.

The only behavioural change is:

- `var m frr.Manager; m.ExecVtysh(...)` continues to work
  (zero-value-safe via `m.executor()`).
- `frr.New()` continues to be the canonical constructor and
  pre-populates `m.exec` with the real implementation.

## Hidden invariants the change must preserve

1. **15s FRR reload context timeout** in `Manager.reload`.
   `ctx, cancel := context.WithTimeout(context.Background(),
   15*time.Second)` stays in `reload()` byte-identical;
   only the `exec.Command*` lines move into
   `realExecutor.SystemctlReload` /
   `realExecutor.VtyshLoad`. The ctx is passed through.
2. **Managed-section markers** (`markerBegin` /
   `markerEnd`): `writeManagedSection` does a literal
   substring strip-and-replace; constants stay in
   `manager.go`.
3. **ApplyFull emission order**: global statics →
   generate-routes → inet6 statics → DHCP-learned defaults
   → backup-router → cluster-mode blackhole → per-VRF
   statics → policy-options → interface-settings → global
   protocols → per-VRF protocols. Preserved verbatim. A
   doc comment at the top of `ApplyFull` records the order
   as a contract.
4. **BFD profile dedup** in `generateProtocols` stays
   adjacent to `bfdProfile` / `bfdProfileName` in
   `policy_render.go`.
5. **slog calls** stay at their exact lines (one-time
   events at FRR-write and reload sites).
6. **Byte-for-byte rendered output** — `frr_test.go` is
   the regression oracle.
7. **Zero-value `Manager` does not panic** —
   `m.executor()` returns `realExecutor{}` when
   `m.exec == nil`. Test verifies.
8. **ECMP side-effect**: `resolveECMP(fc)` mutates
   `fc.ConsistentHash`. Documented in the function
   doc comment so future readers understand the
   non-pure nature.

## Risk assessment

| Risk class | Level | Reasoning |
|---|---|---|
| Behavioral regression | LOW | Pure code motion + new executor indirection that preserves zero-value behavior. `frr_test.go` is the byte-for-byte regression oracle. |
| Lifetime / borrow-checker | N/A | Go. |
| Performance regression | NONE | Control plane only. The executor indirection is one interface dispatch per vtysh call (negligible). |
| Architectural mismatch | LOW | 5-file shape is the adjudicated user override. The executor interface satisfies issue AC#3. |
| Test-environment regression | LOW | Existing `frr_test.go` already runs with `_ = m.ApplyFull(fc)` (swallowing vtysh errors when the binary is absent). New fake-executor tests run without a vtysh binary. |

## Test plan

- `go build ./...` clean.
- `go test ./pkg/frr/...` — all existing tests pass with
  no rendered-output change.
- `go test ./...` — 30+ packages all green.
- New fake-executor tests:
  - `TestExecVtyshUsesExecutor` — injects fake, asserts
    command string forwarded and result returned.
  - `TestGetRIPRoutesUsesExecutor` — injects fake that
    returns a canned `show ip rip` output, asserts parse.
  - `TestReloadUsesSystemctlThenVtyshLoad` — fake fails
    systemctl, succeeds VtyshLoad; asserts fallback is
    taken. Verifies the 15s context is passed.
  - `TestZeroValueManagerExecVtyshNoPanic` — zero-value
    `frr.Manager{}` calls `ExecVtysh` and either returns a
    real result or an exec error (no panic).
- `gofmt -d pkg/frr/*.go` clean.
- No deploy / smoke required (control-plane refactor; per
  batch-merge mandate, post-batch smoke covers it).

## Out of scope (explicitly)

- Carving out sub-packages — explicitly forbidden by user
  rules.
- Renaming any exported identifier.
- Restructuring `frr_test.go` (regression oracle stays
  intact).
- Splitting `policy_render.go` into a separate
  `protocols_render.go` — explicitly held back by user
  5-file mandate.
- Broadening the `frrExecutor` interface beyond what
  current callers need (e.g. streaming output, custom
  args) — defer to a follow-up when a concrete caller
  requires it.

## Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is the `frrExecutor` interface scoped correctly?**
   Three methods cover the vtysh-c, systemctl-reload, and
   vtysh-f-fallback call sites. Anything else in `pkg/frr`
   shell out today? (Audit: only `vtyshCmd` and the two
   `exec.CommandContext` calls in `reload()` shell out.)
2. **Does the zero-value executor accessor introduce a
   data race?** No — the field is initialized in `New()`
   and never re-assigned. Tests that inject a fake do so
   on a fresh `Manager` before any concurrent access.
3. **Does `resolveECMP` mutating `fc.ConsistentHash`
   surprise any caller?** Today the mutation happens
   inline in `ApplyFull`. Hoisting it preserves the
   behavior; the doc comment makes the side-effect
   explicit. Reviewer should confirm no caller of
   `ApplyFull` reads `fc.ConsistentHash` mid-call.
4. **Should `realExecutor.Vtysh` take a `context.Context`
   too, for symmetry with `SystemctlReload` /
   `VtyshLoad`?** Today `vtyshCmd` does not use a context.
   Adding one is an API change for the interface; can be
   done in a follow-up if needed.
5. **Are the new tests sufficient to claim AC#3 is met?**
   Four tests (ExecVtysh, GetRIPRoutes, reload happy +
   fallback, zero-value safe) cover the executor's three
   methods plus the accessor. Reviewer may demand more
   coverage (e.g. per-protocol parsed Get*).
6. **Does any caller of `ApplyFull` rely on the inline
   structure of the function (e.g. via test that monkeys
   the internals)?** Audit of `frr_test.go` shows tests
   only assert rendered output, not internal call order.
   Safe.
