# #1547 — Split `pkg/frr/frr.go` (Plan v2)

**Status:** DRAFT v2 — addresses Codex PLAN-NEEDS-MAJOR and Gemini
PLAN-KILL feedback from round 1.

## Round 1 outcomes

- **Codex** (task `task-mpn2tga9-k9tqob`): PLAN-NEEDS-MAJOR.
  Demands (1) vtyshExecutor interface in the same PR to satisfy
  issue acceptance criterion 3; (2) `generateProtocols` moved
  out of `policy_render.go` into a separate
  `protocols_render.go`; (3) `ifaceNetwork` is actually called
  from protocol rendering (line 689), not interface settings —
  must move with protocols; (4) `ApplyFull` inline render
  blocks extracted into named helpers; (5) README will go stale
  and must be updated.
- **Gemini** (task `task-mpn2twzv-dyoeha`): PLAN-KILL. Same two
  blocking demands: (1) the cohesion claim that
  `generateProtocols` and `generatePolicyOptions` share helpers
  is **factually false** — `resolveRedistribute` and the BFD
  profile dedup are only used by protocol rendering;
  (2) vtyshExecutor interface is an issue acceptance criterion
  and cannot be unilaterally deferred.

## What v2 changes

1. **`vtyshExecutor` interface added in this PR.** A narrow
   private interface
   (`type vtyshExecutor interface { exec(cmd string) (string,
   error) }`) is introduced in `vtysh.go`. The `Manager` gains a
   `vtysh vtyshExecutor` field initialized in `New()` to the
   real `exec.Command` implementation; tests can inject a fake.
   All public `Get*` methods and `ExecVtysh` route through
   `m.vtysh.exec(cmd)` instead of the bare `vtyshCmd` free
   function. This satisfies issue acceptance criterion 3.
2. **File-grouping decision held to the user's mandate.** The
   user's standing rule for this PR is **exactly five sibling
   `.go` files**: `manager.go`, `config_render.go`, `vtysh.go`,
   `status_parse.go`, `policy_render.go`. Both reviewers asked
   for a sixth file (`protocols_render.go`). The user override
   wins. To address the cohesion concern, `policy_render.go`
   becomes "**protocols + policy rendering**" — it owns
   `generateProtocols`, `generatePolicyOptions`,
   `resolveRedistribute`, `knownRedistProtocols`,
   `bfdProfile`, `bfdProfileName`, and `ifaceNetwork`. The file
   name stays `policy_render.go` to honor the user's literal
   list; the file header doc comment documents the actual
   contents. If a future reviewer still considers this a
   blocker after reading the user's standing rule, that is a
   user-arbitration question and not a plan-revision one.
3. **`ifaceNetwork` correctly placed.** Per Codex's
   line-evidence at frr.go:689, `ifaceNetwork` is called from
   OSPF rendering inside `generateProtocols`, not from
   `generateInterfaceSettings`. Moves to `policy_render.go`
   with the rest of protocol rendering.
4. **Inline `ApplyFull` rendering blocks extracted to named
   helpers in `config_render.go`.** Per Codex finding 4. New
   helpers: `renderGenerateRoutes(b, fc)`,
   `renderDHCPDefaults(b, fc)`, `renderBackupRouter(b, fc)`,
   `renderClusterModeDefaults(b, fc)`. These are pure code
   motion — call sites in `ApplyFull` become single function
   calls. `ApplyFull` becomes the ordering glue and nothing
   more.
5. **README updated.** Entry-point list and file-location
   citations updated to the new layout.

## Issue framing

`pkg/frr/frr.go` is 1606 LOC and mixes four distinct responsibilities:

1. **Config rendering** — managed-section rendering, interface settings,
   static-route emission, per-VRF rendering, top-level `Apply`/`ApplyFull`
   orchestration, `writeManagedSection`, `reload`.
2. **Vtysh execution** — `vtyshCmd`, `ExecVtysh`, and the thin per-feature
   shells that wrap raw vtysh shell-outs (`GetBFDPeers`, `GetRouteMapList`,
   `GetISISAdjacencyDetail`, `GetISISDatabase`, `GetISISRoutes`,
   `GetOSPFNeighborDetail`, `GetOSPFDatabase`, `GetOSPFInterface`,
   `GetOSPFRoutes`, `GetBGPNeighborReceivedRoutes`,
   `GetBGPNeighborAdvertisedRoutes`, `GetBGPNeighborDetail`).
3. **Status parsing** — `GetRIPRoutes`, `GetISISAdjacency`,
   `GetOSPFNeighbors`, `GetBGPSummary`, `GetBGPRoutes`,
   `GetRouteDetailJSON`, `parseRouteJSON`, `FormatRouteDetail`, the
   `frrRouteJSON`/`frrNextHopJSON` decode types, and the public
   `RIPRouteEntry`/`ISISAdjacency`/`OSPFNeighbor`/`BGPPeerSummary`/
   `BGPRoute`/`FRRRouteDetail`/`FRRNextHop` types.
4. **Protocol + policy rendering** — `generateProtocols` (OSPF, OSPFv3,
   BGP, RIP, ISIS, BFD profile dedup), `generatePolicyOptions`
   (prefix-lists, route-maps, communities), `resolveRedistribute`,
   `knownRedistProtocols`, `bfdProfile`/`bfdProfileName`,
   `ifaceNetwork`.

The issue's "preferred shape" calls for sub-packages
(`pkg/frr/render/`, `pkg/frr/protocols/`, `pkg/frr/policy/`,
`pkg/frr/vtysh/`, `pkg/frr/status/`, `pkg/frr/routes/`). The user's
standing rules explicitly **forbid** that: the split must use
**sibling `.go` files inside `pkg/frr/`** — no sub-packages, no
filename prefixes (i.e. NOT `frr_config_render.go`).

## Honest scope/value framing

This is **pure code motion** within a single Go package. It does not
change the FRR rendering output, the vtysh execution surface, or the
public API of `frr.Manager`. The win is purely structural:

- Future merge conflicts on `frr.go` get scoped to the file that
  owns the affected concern.
- The status-parse JSON/text helpers can be unit-tested in isolation
  without dragging the rendering globals.
- Adding a new protocol (e.g. EIGRP, BGP-EVPN) drops into
  `policy_render.go` or a new file without touching the manager
  lifecycle.

No perf gain. No correctness change. *If reviewers conclude the
structural win is too small to justify the churn, PLAN-KILL is an
acceptable verdict.* The user has, however, set this as a standing
mandate for #1547 alongside the larger refactor program.

## What's already shipped

- `pkg/frr/README.md` documents the existing module contract; it
  does not need to change because the file *layout* changes are
  internal to the package.
- `pkg/frr/frr_test.go` (2311 LOC) covers rendering, parsing, and
  vtysh-shape tests; moving the implementation to sibling files
  must not change a single test outcome.
- The 15s FRR reload context timeout in `m.reload()` is a known
  shutdown-correctness invariant — it must move verbatim with
  `Manager.reload` to whatever file owns `Manager`.

## Concrete design

All files live at `pkg/frr/` and remain in `package frr`. No
sub-packages, no `frr_` prefixes.

### `pkg/frr/manager.go`

Owns the package-level types and the `Manager` lifecycle:

- `Manager` struct (now with the `vtysh vtyshExecutor` field)
  + `New()` constructor (initializes `vtysh` to the real
  exec.Command-backed implementation).
- `markerBegin` / `markerEnd` / `DefaultFRRConf` constants.
- `InstanceConfig`, `DHCPRoute`, `FullConfig` types.
- `Apply`, `ApplyWithInstances`, `ApplyFull`, `Clear`,
  `writeManagedSection`, `reload` (with the 15s context
  timeout preserved verbatim).
- Top-level orchestration in `ApplyFull` that now delegates
  every inline render block to a named helper in
  `config_render.go`.

### `pkg/frr/config_render.go`

Holds the non-protocol config rendering helpers:

- `generateInterfaceSettings` (interface-block bandwidth +
  point-to-point hints).
- `generateStaticRoute` (per-prefix `ip route` / `ipv6 route`
  emission with RETH name translation and IPv6 next-hop
  interface resolution).
- New named extractors that subsume the inline `ApplyFull`
  rendering blocks: `renderGenerateRoutes(b *strings.Builder,
  fc *FullConfig)`, `renderDHCPDefaults`, `renderBackupRouter`,
  `renderClusterModeDefaults`. Each one is a pure builder-write
  that preserves the existing emission order and exact byte
  output. Calls in `ApplyFull` become single-line invocations.

### `pkg/frr/policy_render.go`

Holds **protocol + policy rendering** (despite the name — see
v2 file-grouping note above for why the name stays
`policy_render.go`):

- `generateProtocols` (OSPF, OSPFv3, BGP, RIP, ISIS).
- `generatePolicyOptions` (prefix-lists, route-maps,
  communities).
- `resolveRedistribute`, `knownRedistProtocols` map (used
  inside `generateProtocols`).
- `bfdProfile`, `bfdProfileName` (BFD profile dedup used inside
  `generateProtocols`).
- `ifaceNetwork` (used inside OSPF rendering at the original
  frr.go:689 call site).

The file header doc comment will document that this is the
"protocol + policy" rendering file. The user's literal file
list is honored; the misleading "policy_render" name is
documented in code.

### `pkg/frr/vtysh.go`

Holds the vtysh execution surface (no parsing):

- `vtyshExecutor` private interface with one method
  `exec(command string) (string, error)`.
- `realVtyshExecutor` private concrete type whose `exec`
  shells out via `exec.Command("vtysh", "-c", command)` —
  this is the byte-identical body of the existing `vtyshCmd`
  free function, just moved behind the interface.
- `Manager.ExecVtysh` (public) and all `GetBFDPeers`,
  `GetRouteMapList`, `GetISISAdjacencyDetail`,
  `GetISISDatabase`, `GetISISRoutes`, `GetOSPFNeighborDetail`,
  `GetOSPFDatabase`, `GetOSPFInterface`, `GetOSPFRoutes`,
  `GetBGPNeighborReceivedRoutes`,
  `GetBGPNeighborAdvertisedRoutes`, `GetBGPNeighborDetail` —
  all routed through `m.vtysh.exec(...)`.

### `pkg/frr/status_parse.go`

Holds the parsing helpers and their public types:

- `RIPRouteEntry` + `Manager.GetRIPRoutes`.
- `ISISAdjacency` + `Manager.GetISISAdjacency`.
- `OSPFNeighbor` + `Manager.GetOSPFNeighbors`.
- `BGPPeerSummary` + `Manager.GetBGPSummary`.
- `BGPRoute` + `Manager.GetBGPRoutes`.
- `FRRRouteDetail`, `FRRNextHop`, `frrRouteJSON`, `frrNextHopJSON`.
- `Manager.GetRouteDetailJSON`, `parseRouteJSON`,
  `FormatRouteDetail`.

## Public API preservation

Every exported identifier on `frr.Manager`, every exported package
type, every exported package function MUST keep its exact signature
and exact package path (`pkg/frr`). The split is **file-level**, not
**package-level**. External callers (`pkg/daemon`, `pkg/grpcapi`,
`pkg/api`, `cmd/xpfd`) see zero import-path change.

Concretely:

- `frr.New()`
- `(*frr.Manager).Apply` / `.ApplyWithInstances` / `.ApplyFull` /
  `.Clear` / `.ExecVtysh` / `.GetBFDPeers` / `.GetRouteMapList` /
  all `GetISIS*` / all `GetOSPF*` / all `GetBGP*` /
  `.GetRIPRoutes` / `.GetRouteDetailJSON`
- `frr.DefaultFRRConf`
- `frr.InstanceConfig` / `frr.DHCPRoute` / `frr.FullConfig`
- `frr.RIPRouteEntry` / `frr.ISISAdjacency` / `frr.OSPFNeighbor` /
  `frr.BGPPeerSummary` / `frr.BGPRoute` / `frr.FRRRouteDetail` /
  `frr.FRRNextHop`
- `frr.FormatRouteDetail`

## Hidden invariants the change must preserve

1. **15s FRR reload context timeout** in `Manager.reload`. This is
   the project's documented shutdown safety net to prevent hanging
   on `systemctl reload frr`. Must move byte-identical into
   `manager.go`.
2. **Managed-section markers** (`markerBegin` / `markerEnd`):
   `writeManagedSection` does a literal substring strip-and-replace
   on the on-disk `/etc/frr/frr.conf`. The marker constants must
   stay reachable from `writeManagedSection` (they live in
   `manager.go` alongside it).
3. **ApplyFull orchestration order** — current order is:
   global statics → generate-routes → inet6 statics → DHCP-learned
   defaults → backup-router → cluster-mode blackhole → per-VRF
   statics → policy-options → interface-settings → global
   protocols → per-VRF protocols. The order matters for FRR
   parsing (interface settings before OSPF cost auto-derivation).
   The split must preserve this order verbatim.
4. **BFD profile dedup** in `generateProtocols` — keep adjacent
   to `bfdProfile`/`bfdProfileName` in `policy_render.go`.
5. **slog.Info calls** at FRR-write and reload sites stay where
   they are (one-time events, not hot path — per project logging
   rules).
6. **Byte-for-byte rendered output** — the issue's first
   acceptance criterion is "Existing FRR output remains
   byte-for-byte identical for current fixtures." The 2311-LOC
   `frr_test.go` is the regression oracle.

## Risk assessment

| Risk class | Level | Reasoning |
|---|---|---|
| Behavioral regression | LOW | Pure code motion; no logic change. `frr_test.go` is the byte-for-byte regression oracle. |
| Lifetime / borrow-checker | N/A | Go, not Rust. Method receivers move with their methods. |
| Performance regression | NONE | Control plane only. FRR reload runs at config-commit time. |
| Architectural mismatch | LOW | The issue's "preferred shape" was sub-packages; user override mandates sibling files. The risk is reviewer disagreement with the user-chosen shape, not architectural impossibility. |

## Test plan

- `go build ./...` clean.
- `go test ./pkg/frr/...` — all existing tests pass with no change.
- `go test ./...` — 30+ packages all green (downstream callers
  unaffected).
- Diff-check: `gofmt -d pkg/frr/*.go` clean.
- No deploy / smoke required because:
  - Control-plane-only change with zero behavior delta.
  - The change does not touch the dataplane, HA, VRRP, session
    sync, or any code path under load.
  - Test suite covers rendered output byte-for-byte.
  - However, per the user's standing batch-merge mandate for
    refactor-chain PRs, the post-batch smoke will exercise this
    change as part of the next comprehensive smoke.

## Out of scope (explicitly)

- Carving out sub-packages (`pkg/frr/render/`, etc.) — explicitly
  forbidden by user rules.
- Renaming any exported identifier.
- Restructuring `frr_test.go` (the regression oracle stays intact;
  follow-up issue can split it after the source split lands).
- Adding new interfaces (`type Renderer interface`, etc.) — the
  issue mentions "vtysh command execution is behind a narrow
  interface for tests" but introducing an interface here is a
  behavioral surface change, not pure code motion. Defer to a
  follow-up if/when test mocking actually needs it.
- Touching `pkg/frr/README.md` — module contract is unchanged.

## Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is sibling-file split sufficient value over a sub-package
   split?** The issue *prefers* sub-packages. The user overrides
   with sibling files. If you (the reviewer) think sibling files
   inside `package frr` deliver too little structural separation
   to justify the churn relative to the eventual ideal,
   PLAN-KILL is fair.
2. **Does `policy_render.go` hold the right grouping?** Should
   `generateProtocols` (which is large and protocol-heavy) live
   in its own `protocols_render.go`, with `policy_render.go`
   carrying only `generatePolicyOptions`? The shared
   `resolveRedistribute` + BFD-dedup pulls them together, but the
   2-file alternative is a viable shape.
3. **Should the inline static-route / DHCP-route / generate-route
   / backup-router / cluster-mode rendering blocks in `ApplyFull`
   be hoisted into named helpers in `config_render.go`?** Doing
   so makes the manager method shorter but adds named helpers
   that exist only for one caller. Status quo is also defensible.
4. **Does keeping the public `*RouteEntry` / `*Neighbor` / etc.
   types in `status_parse.go` create import-cycle hazards?** They
   are package-level exports; no import-cycle risk inside the
   package. But if a downstream caller imports a type from
   `pkg/frr` *expecting* it to live with the manager (e.g. via
   IDE jump-to-definition), this is a small ergonomic change.
5. **Is the 15s context timeout in `Manager.reload` actually
   safe to move?** It is. But verify the move is byte-identical
   and no caller does `m.reload()` from a goroutine that would
   now race with the file move. (None do — it's only called from
   `ApplyFull`.)
6. **Should we introduce a `vtyshExecutor` interface in
   `vtysh.go`?** The issue says yes ("vtysh command execution is
   behind a narrow interface for tests"). The plan defers this
   to a follow-up because introducing an interface is behavioral
   surface change, not code motion. Reviewer may push back on
   that deferral.
7. **Are we sure no currently-private helper becomes
   `cross-file-private`-broken?** All Go package-private names
   stay package-private; sibling files in the same package share
   the namespace. No risk, but the reviewer should confirm by
   reading the call graph.
