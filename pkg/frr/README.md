# pkg/frr

FRR (FRRouting) integration. Generates a managed section inside
`/etc/frr/frr.conf` from the typed config (static routes, OSPF, BGP,
ISIS, RIP, BFD profiles, multi-VRF instances) and queries protocol state
via `vtysh`.

This package is the only place in the codebase that's allowed to touch
kernel routes — and it doesn't, directly. It writes config and reloads
FRR, which then owns the kernel route table.

## File layout

The package is split across five sibling `.go` files (no sub-packages,
no filename prefixes):

| File | Owns |
|---|---|
| `manager.go` | `Manager` struct + lifecycle (`New`, `Apply`, `ApplyFull`, `Clear`, `writeManagedSection`, `reload`), top-level types (`InstanceConfig`, `DHCPRoute`, `FullConfig`), package constants, and the zero-value-safe `executor()` accessor. |
| `config_render.go` | Non-protocol config rendering: `generateInterfaceSettings`, `generateStaticRoute` (+ `generateStaticRouteInTable`, the table-suffix variant for `instance-type forwarding` instances, #1827 PR-2), named `ApplyFull` extractors (`renderGenerateRoutes`, `renderDHCPDefaults`, `renderBackupRouter`, `renderPreferredRoutes` — the #1827 ip-monitoring overlay as distance-1 statics, emission step 7 — `renderClusterModeDefaults`), and `resolveECMP` (which has a documented side effect: mutates `fc.ConsistentHash`). |
| `policy_render.go` | **Protocols + policy rendering** (despite the filename — `generateProtocols` for OSPF/OSPFv3/BGP/RIP/ISIS, `generatePolicyOptions` for prefix-lists/route-maps/communities, `resolveRedistribute`, BFD profile dedup). OSPFv2 area membership is rendered per-interface as `ip ospf area <id>` under `interface <name>` (matching the OSPFv3 idiom), never as a global `network <prefix> area` statement — see #1712. |
| `vtysh.go` | `frrExecutor` interface (Vtysh / SystemctlReload / VtyshLoad), `realExecutor` (production exec.Command implementation), `ExecVtysh`, and all raw-output Get* shells (`GetBFDPeers`, `GetRouteMapList`, `GetISIS*Detail`/`Database`/`Routes`, `GetOSPF*Detail`/`Database`/`Interface`/`Routes`, `GetBGPNeighbor*`). |
| `status_parse.go` | Parsed Get* methods + their public types (`RIPRouteEntry`, `ISISAdjacency`, `OSPFNeighbor`, `BGPPeerSummary`, `BGPRoute`, `FRRRouteDetail`, `FRRNextHop`) + `parseRouteJSON`, `FormatRouteDetail`. |

## Entry points

- `Manager` — `manager.go`.
- `New() *Manager` — `manager.go`. Defaults to `/etc/frr/frr.conf` and
  to a real `os/exec`-backed `frrExecutor`.
- `ApplyFull(fc *FullConfig) error` — `manager.go`. Apply full config
  (idempotent diff against on-disk).
- `FullConfig`, `InstanceConfig`, `DHCPRoute` — `manager.go`.
- State queries: raw-text shells in `vtysh.go`, parsed `Get*` methods
  in `status_parse.go`. All shell-outs route through `m.executor()`
  so they can be faked in tests (see `executor_test.go`).

## Callers

`pkg/daemon` (lifecycle), `pkg/grpcapi` (show commands).

`FullConfig.PreferredRoutes` (#1827) carries the ip-monitoring
effective-route overlay; the daemon's `assembleFRRConfig` is the sole
`FullConfig` constructor for both the full apply path and the
routes-only actuator, so an operator commit can never wipe an active
failover route. The `ApplyFull` emission-order contract comment lists
the overlay as step 7.

## Dependencies

`pkg/config` only.

## Managed-section markers

`! BEGIN BPFRX MANAGED CONFIG` … `! END BPFRX MANAGED CONFIG`. User-edited
content **outside** the markers is preserved across `ApplyFull`. Don't
move or rename the markers — they're literal strings.

## Gotchas

- Static routes have RETH names (`reth0`) but FRR wants the physical
  member name in cluster mode. The package translates via `RethMap` from
  the typed config.
- `InstanceConfig` has two rendering modes (#1827 PR-2):
  `VRFName != ""` renders `vrf <name>` (virtual-router instances);
  `VRFName == ""` with `TableID > 0` renders `table <id>`
  (`instance-type forwarding` instances — no VRF device exists, and the
  table must match the FBF/PBR `ip rule` target and the dataplane's
  `<ri>.inet.0`). `renderPreferredRoutes` resolves an overlay entry's
  instance via `InstanceConfig.Name`; legacy callers that never set
  `Name` keep the historical `vrf-<name>` rendering.
- IPv6 next-hops without an explicit interface require `IPv6NextHopInterfaces`
  for link-local resolution — link-local addresses alone are ambiguous to
  FRR.
- In cluster mode the package emits a blackhole default at admin distance
  250 so traffic to the active fabric peer survives a brief
  active/active overlap.
- `vtysh -c` is run synchronously in batch mode for state queries. There
  is no streaming; long output is buffered.
- All `vtysh` and `systemctl` shell-outs route through the package-private
  `frrExecutor` interface. Tests inject a fake; production uses
  `realExecutor{}` (which `exec.Command`s the real binary). A zero-value
  `Manager{}` is tolerated via the `executor()` accessor — useful for
  same-package literals.
- `Manager.reload()` enforces a 15-second `context.WithTimeout` around
  the entire reload (systemctl + vtysh -f fallback). This is the inner
  shutdown-correctness invariant; the systemd unit's `TimeoutStopSec=20`
  is the outer safety net.
