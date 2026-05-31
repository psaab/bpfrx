# pkg/routing

Manages static routes, GRE tunnels, VRFs, XFRM interfaces, and tunnel
keepalive probes via netlink. Tracks link state for monitored
interfaces and exposes per-tunnel up/down state via `KeepaliveState`
for weight-based failover.

This package owns netlink object lifecycles. FRR (`pkg/frr`) owns the
kernel route table; this package owns the *interfaces* routes hang off
of.

## Structure (#1698 domain split)

`Manager` (`routing.go`) is a thin **façade**: it owns the single
`*netlink.Handle` and delegates every public method to an unexported
per-domain manager. Each domain owns its own sub-state + its own lock
and depends on a narrow netlink-facing ops interface (`vrfOps`,
`routeLister`, `linkOps`, `ruleOps`) rather than the concrete handle,
which makes each domain unit-testable with a fake (see `rules_test.go`'s
`fakeRuleOps` and `routing_test.go`'s `fakeVRFOps`).

| File | Domain | Owns |
|------|--------|------|
| `routing.go` | `Manager` façade | sole `*netlink.Handle`, domain refs |
| `vrf.go` | `vrfManager` | VRF lifecycle + `BindInterfaceToVRF`; own `mu` + tracked set |
| `routes.go` | `routeReader` | kernel routing-table reads (`routeLister`) |
| `routeformat.go` | free fns | Junos `show route` formatters |
| `tunnel.go` | `tunnelManager` | GRE/IPIP tunnels + keepalive goroutines; own `mu` |
| `xfrm.go` | `xfrmManager` | XFRM/IPsec interface lifecycle; own `mu` |
| `rules.go` | `nextTableManager` / `ribGroupManager` / `pbrManager` | policy-routing ip-rule reconcilers (`ruleOps`, stateless) |
| `bond.go` | `bondManager` | bond device lifecycle; own `mu` |
| `reth.go` | `rethManager` | stale `reth*` bond cleanup |
| `monitor.go` | `monitorManager` | interface-monitor HA signal; own `mu` |

The tunnel domain depends on the VRF domain (`tunnelManager.vrfBinder`)
to bind tunnel interfaces to a routing-instance VRF;
`BindInterfaceToVRF` takes no lock, so there is no lock-ordering cycle.

## Entry points

All public methods remain on `*Manager` with unchanged signatures and
delegate to the owning domain. Exported types:

- `Manager` — `routing.go` (façade).
- `VRFSpec` — `vrf.go`.
- `KeepaliveState` — `tunnel.go`. Per-tunnel probe status.
- `TunnelStatus` — `tunnel.go`.
- `RouteEntry`, `TableRoutes` — `routes.go`.
- `PBRRule` — `rules.go`.
- `InterfaceMonitorStatus` — `monitor.go`.
- `New() (*Manager, error)` — `routing.go`.

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

`pkg/config` only.

## ip-rule priorities

- `100–199`: next-table inter-VRF leaking (static routes with
  `next-table` directive). `nextTableRulePriority` in `rules.go`.
- `31000–31999`: PBR (firewall-filter `routing-instance` action).
  `pbrRulePriority` in `rules.go`.
- `33000–33099`: rib-group inter-VRF leaking (`from all lookup
  <table>`).
- main table at `32766`. The next-table range sits **before** main
  (lower priority value = higher priority). PBR sits before main as
  well; rib-group sits after.

## Gotchas

- #848 / #1698: each interface domain (`tunnelManager`, `xfrmManager`,
  `bondManager`) now has its own lock instead of one shared `ifaceMu`.
  The split is safe because no operation crossed those domains under one
  lock; keepalives belong to the tunnel domain. Long-running reads
  (`GetTunnelStatus`) snapshot under the tunnel lock and iterate the
  copy lock-free.
- `vrfManager` holds its own lock for the entire netlink reconciliation;
  `ReconcileVRFs` isn't re-entrant.
- `Manager.Close()` is not safe to call concurrently with the public
  apply/read methods (single-threaded-shutdown contract; no daemon
  caller of `Close` today).
- Keepalive runner goroutines drain on the `done` channel before the
  netlink handle is closed. Closing the handle while a goroutine still
  holds it would be a use-after-close.
- Static routes go through `pkg/frr`, not this package. The "next-table"
  and "rib-group" leaking modes go through `ip rule` (here), not FRR.
- RPM probes that need VRF binding use `SO_BINDTODEVICE` on the VRF
  device, not on the destination interface.
