# pkg/frr

FRR (FRRouting) integration. Generates a managed section inside
`/etc/frr/frr.conf` from the typed config (static routes, OSPF, BGP,
ISIS, RIP, BFD profiles, multi-VRF instances) and queries protocol state
via `vtysh`.

This package is the only place in the codebase that's allowed to touch
kernel routes — and it doesn't, directly. It writes config and reloads
FRR, which then owns the kernel route table.

`frr.conf` is DurableState (#1894): `atomicWriteFile` delegates to
`fsatomic.WriteFileDurable` with `WithPreserveExisting` +
`WithResolveSymlinks` (the #1883 mode/owner/symlink semantics were
lifted into that package), gaining the parent-dir fsync the local
writer lacked. The file carries operator content outside the managed
section, so it must survive power loss.

## File layout

The package is split across five sibling `.go` files (no sub-packages,
no filename prefixes):

| File | Owns |
|---|---|
| `manager.go` | `Manager` struct + lifecycle (`New`, `ApplyFull`, `Clear`, `writeManagedSection`, `reload`), top-level types (`InstanceConfig`, `DHCPRoute`, `FullConfig`), package constants, and the zero-value-safe `executor()` accessor. The legacy `Apply`/`ApplyWithInstances` partial constructors were deleted (#1827 AGY F1, PR #1843): they bypassed `assembleFRRConfig` and would have wiped an active failover overlay. |
| `config_render.go` | Non-protocol config rendering: `generateInterfaceSettings`, `generateStaticRoute` (+ `generateStaticRouteInTable`, the table-suffix variant for `instance-type forwarding` instances, #1827 PR-2), named `ApplyFull` extractors (`renderGenerateRoutes`, `renderDHCPDefaults`, `renderBackupRouter`, `renderPreferredRoutes` — the #1827 ip-monitoring overlay as distance-1 statics, emission step 7 — `renderClusterModeDefaults`), and `resolveECMP` (which has a documented side effect: mutates `fc.ConsistentHash`). |
| `policy_render.go` | **Protocols + policy rendering** (despite the filename — `generateProtocols` for OSPF/OSPFv3/BGP/RIP/ISIS, `generatePolicyOptions` for prefix-lists/route-maps/communities, `resolveRedistribute`, BFD profile dedup). OSPFv2 area membership is rendered per-interface as `ip ospf area <id>` under `interface <name>` (matching the OSPFv3 idiom), never as a global `network <prefix> area` statement — see #1712. **Route-filter match-types** (the `from route-filter <prefix> <match-type>` switch in `generatePolicyOptions`) render to FRR prefix-list entries as: `exact` → bare prefix (no `le`/`ge`); `orlonger` → default `le 32`/`le 128` (`le == prefix-len` on a `/32`/`/128` is FRR-VALID — only `ge`/`le` *strictly less than* the prefix length is rejected); `longer` → `ge <plen+1> le max`; `upto /N` → bare `le N` (NO `ge`), with `upto /N == prefix-len` — and any `upto` on a max-length host prefix (`/32`/`/128`) — rendering as **exact** (bare prefix, no `le`/`ge`), since a max-length prefix has no more-specifics (#2072). For `longer`, a max-length prefix (`/32`/`/128`) has no strictly-more-specific routes at all — the empty set — so the entry is **skipped entirely** rather than emitting the FRR-invalid `ge <plen+1> le max` (e.g. `ge 33 le 32`, which fails FRR's YANG range `0..32` and `ge > le`); the boundary skips ONLY `plen == max`, so `/31 longer` still emits the valid `ge 32 le 32` (#2103). When a term's route-filters are ALL skipped (or all malformed), the renderer emits no prefix-list lines AND suppresses the `match … prefix-list` line (a materialised empty prefix-list is FRR `PREFIX_PERMIT`/match-ALL, so the list must never be created; a non-existent list referenced by a surviving `match` would be wrong too) — the term keeps its other `from`/`then` clauses with no route-filter condition; the `match`-line address family is derived from the first *emitted* entry, not `RouteFilters[0]` (#2103/#2105). The `ge` value used in a rendered line is ALWAYS strictly greater than the prefix length, and `le` is ALWAYS >= the prefix length (never strictly less — `orlonger`/`upto` may emit `le == prefix-len`, which is FRR-valid), and a rejected line can fail the whole `frr-reload` (`frr-reload.py` applies the add-batch via a single `vtysh -f` and exits non-zero on any `CMD_WARNING_CONFIG_FAILED`) — that is why `longer` uses `plen+1`/skips at max, and `upto` emits a bare `le N`. `upto` lengths < prefix-len, 0/unset (the compiler rejects `upto /0` so 0 means unset), or > family-max degrade safely to a valid `le family-max` (orlonger-equivalent superset) when the prefix is not max-length, never an invalid line. The **route-filter prefix is CIDR-validated at commit** (`ValidateRouteFilterArg` keyValidator, `pkg/config`): a malformed prefix is rejected at commit/commit-check (strict) but tolerated on load/HA-sync (lenient, #1960); the renderer carries a belt-and-suspenders skip for any malformed prefix that reaches it via the lenient path (#2105). `prefix-length-range` and `through` are admitted as commit keywords but not yet rendered (a separate gap — see #2072 follow-up). |
| `vtysh.go` | `frrExecutor` interface (Vtysh / FrrReloadPy / VtyshLoad), `realExecutor` (production exec.Command implementation), `ExecVtysh`, and all raw-output Get* shells (`GetBFDPeers`, `GetRouteMapList`, `GetISIS*Detail`/`Database`/`Routes`, `GetOSPF*Detail`/`Database`/`Interface`/`Routes`, `GetBGPNeighbor*`). |
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
- All `vtysh` and `frr-reload.py` shell-outs route through the
  package-private `frrExecutor` interface. Tests inject a fake;
  production uses `realExecutor{}` (which `exec.Command`s the real
  binary). A zero-value `Manager{}` is tolerated via the `executor()`
  accessor — useful for same-package literals.
- Reload mechanism (#1880): the primary reload is a DIRECT bounded
  `/usr/lib/frr/frr-reload.py --reload <frr.conf>` — NEVER
  `systemctl reload frr`. On FRR 10.6 the unit's ExecReload
  (frrinit.sh reload) unconditionally restarts watchfrr, the
  Type=forking unit's MainPID, so every systemd-mediated reload cancels
  its own job, parks frr.service in `stop-sigterm` for 2 minutes, and
  ends with systemd SIGKILLing all FRR daemons. The direct invocation
  keeps the unit state untouched and restores stale-config REMOVAL on
  commit (the systemctl branch had been 100%-failing, so every reload
  silently ran the additive fallback).
- Each reload leg gets its OWN 15-second `context.WithTimeout`: the
  primary and, when it fails (any cause, including timeout), a FRESH
  context for the additive `vtysh -f` fallback. The real executor runs
  frr-reload.py in its own process group and SIGKILLs the group on
  cancel (`Setpgid` + `cmd.Cancel`), so no child `vtysh` writer can
  survive a timeout and race the fallback. Worst case on the apply
  path: ≤40s (2×15s + up to two 5s WaitDelay windows; an apply also
  waits at most one teardown window behind a pre-cancelled in-flight
  retry, ≤45s total).
- Degraded mode: fallback success returns `ErrFRRReloadDegraded`
  (wrapping the primary cause). A single-flight in-manager retry loop
  re-runs the primary at 15s/30s/60s then every 5min until a full diff
  converges (`frr.conf` on disk is the SSOT; a newer apply supersedes
  and a fully-successful reload cancels the episode). All reloads —
  applies AND the retry — serialize under `reloadMu`; `confGen` guards
  against a stale success clearing the state. The condition is exported
  via `Manager.ReloadDegraded()` → `xpf_frr_reload_degraded` (0/1
  gauge). `frr-pythontools` missing is classified explicitly
  (warn-once, slow-cadence retry). `Manager.Stop()` (wired into daemon
  shutdown) cancels in-flight process groups and reaps the retry
  goroutine; `DisableDegradedRetry()` is the one-shot (`xpfd cleanup`)
  configuration.
