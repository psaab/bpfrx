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
| `probe_pin.go` | `probePinManager` | RPM probe next-hop pin reconciler (#1827): fwmark rules in band 50-99 + pinned host routes in reserved tables 7000-7049 (`probePinOps`, stateless) |
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

- `50–99`: RPM probe next-hop pins (`fwmark <mark> lookup <table>`,
  #1827). Constants live in `pkg/config` (`ProbeRulePriorityBase`,
  `ProbeTableBase` 7000-7049, `ProbeFwmarkBase` 0x1000) because
  `pkg/config` commit validation, this package, and `pkg/rpm` all
  consume them. Cleared on daemon startup (`ClearProbePins`) so a
  crashed daemon never leaks pins.
- `100–199`: next-table inter-VRF leaking (static routes with
  `next-table` directive). `nextTableRulePriority` in `rules.go`.
- `31000–31999`: PBR (firewall-filter `routing-instance` action).
  `pbrRulePriority` in `rules.go`.
- `33000–33099`: rib-group inter-VRF leaking (`from all lookup
  <table>`).
- main table at `32766`. The next-table range sits **before** main
  (lower priority value = higher priority). PBR sits before main as
  well; rib-group sits after.

## Tunnel reconcile-in-place (#1884)

`tunnelManager.Apply` reconciles instead of clear-all +
delete-and-recreate: an untouched tunnel keeps its netdev (stable
ifindex — no FRR route churn, no userspace-dp TUN-reader death per
commit, see #1881/#1887), tunnels removed from config are deleted via a
set-diff against the previous DESIRED set (`ownedNames`, retained on a
failed delete for retry), and a device is recreated only when the
existing kernel link is genuinely incompatible:

- **Anchors** (production userspace path): reuse requires TUN mode +
  `NO_PI` (the Rust reader opens `IFF_TUN|IFF_NO_PI`) + persistent.
  MTU ownership: `tc.MTU > 0` (config) is reconciled on every reuse
  (the compiler MTU stage restores ZONED interfaces only); `tc.MTU ==
  0` is written exactly once when ADOPTING a device this manager did
  not own at the last apply (restart adoption; wireguard→gre same-name
  flip repair — the WG-reduced MTU must not leak into the userspace
  snapshot's live-MTU reads).
- **Legacy non-anchor** (standalone-CLI only): compare-then-decide on
  the config-driven attrs (type/family, endpoints, defaulted TTL,
  keys, ip6tnl proto); kernel-populated fields (PMtu, Tos, flags,
  encap-limit — mutated by the post-create `encaplimit none` exec) are
  deliberately NOT compared. Real changes delete+recreate; the
  encaplimit exec runs only on (re)create.
- **Addresses**: symmetric reconcile; stale LINK-LOCAL addresses are
  deleted only if recorded in `appliedAddrs` (a configured fe80 we
  applied), never the kernel's autoconf fe80; failed LL deletes stay
  tracked for retry. The WG branch uses the same helper with the nil
  sentinel (blanket LL skip — pre-existing WG semantics).
- **VRF claims** (`appliedRI`): written ONLY from a successful
  `BindInterfaceToVRF` or a direct observation that the link's master
  is `vrf-<RIListMember>` (a step-0a routing-instance interface-list
  bind) — never from intent. `TunnelConfig.RIListMember` (populated by
  `collectAppliedTunnels` with the exact step-0a name normalization)
  vetoes unbinding when the config list-binds the tunnel. Unbind on
  config-wants-none is identity-gated: only when the current master IS
  the claimed RI's `vrf-` device; transient errors retain the claim
  for retry.
- **Keepalives** (legacy branch only — anchors never probe): runners
  are reconciled by normalized identity `(remote, interval,
  retry<=0→3)` and survive unrelated applies; `LinkSetUp` is SKIPPED
  when a retained runner holds the tunnel down (the down-transition in
  `keepaliveLoop` is gated on `state.Up`, so re-upping would strand
  the link admin UP).

`Clear()`/`ClearTunnels` keep delete-everything semantics and reset the
reconcile state. Restart residuals (documented): anchors/addresses/RI
claims orphaned while the daemon was down are adopted as-is, not
retroactively diffed.

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
