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
| `xfrm.go` | `xfrmManager` | XFRM/IPsec interface lifecycle; own `mu` + tracked `name→if_id` set. `Apply` reconciles **differentially** against the tracked set (keep unchanged / create new / delete removed / recreate on `if_id` change) — it does NOT clear-all-then-rebuild, so an unrelated config commit leaves active xfrmi interfaces untouched (#2546). Refuses to create either of two distinct devices that derive the same `if_id` — fail-closed collision guard (#2909) |
| `rules.go` | `nextTableManager` / `ribGroupManager` / `pbrManager` | policy-routing ip-rule reconcilers (`ruleOps`, stateless) |
| `probe_pin.go` | `probePinManager` | RPM probe next-hop pin reconciler (#1827): fwmark rules in band 50-99 + pinned host routes in reserved tables 7000-7049 (`probePinOps`, stateless). `Apply` returns per-test install failures (keyed by TestKey) and rolls back the fwmark rule when the pinned route fails (best-effort — a failed rollback is swept by the next band clear; the pin reports failed either way); callers thread the failed map into `pkg/rpm` so affected tests hold state instead of probing unpinned (#1895) |
| `bond.go` | `bondManager` | bond device lifecycle; own `mu` |
| `reth.go` | `rethManager` | stale `reth*` bond cleanup |
| `monitor.go` | `monitorManager` | interface-monitor HA signal; own `mu`. Link health via `linkAttrsUp` reads kernel **operstate** (`OperUp` → up; `OperUnknown` → admin-flag fallback; `OperDown`/lower-layer-down → down), **not** `IFF_UP` — admin-up-but-carrier-down (cable pulled) must report DOWN so HA fails over (#2070). Mirrors `pkg/vrrp.linkAttrsUp` and `pkg/cluster/monitor.go` |

The tunnel domain depends on the VRF domain (`tunnelManager.vrfBinder`)
to bind tunnel interfaces to a routing-instance VRF;
`BindInterfaceToVRF` takes no lock, so there is no lock-ordering cycle.

### XFRM interface reconcile (#2546)

`xfrmManager.Apply` is called by `pkg/daemon` on **every** config commit
(not only IPsec changes) so xfrmi devices for deleted VPNs are torn
down. It therefore reconciles the desired xfrmi set (`name→if_id`
derived from each VPN's `bind-interface` via
`config.XFRMIfNameAndID`) against the tracked set instead of clearing
all and rebuilding:

- **keep** an interface untouched when it is still desired with the same
  `if_id` — no `LinkDel`/`LinkAdd`, so active tunnel traffic and routing
  bound to the interface survive an unrelated commit;
- **create** a newly-desired interface (also adopts a kernel link that
  outlived in-memory tracking, e.g. across a daemon restart);
- **delete** an interface whose VPN was removed;
- **recreate** (delete+create) an interface whose name is unchanged but
  whose desired `if_id` differs — `Ifid` is set at xfrmi creation and is
  not mutable in place.

A no-op commit (identical VPN set) issues zero `LinkDel` and zero
`LinkAdd`. `Clear()` (shutdown / full teardown) still deletes every
tracked interface.

#### `if_id` collision guard (#2909)

The kernel keys the SA↔xfrmi binding on the XFRM `if_id`, so the `if_id`
**must be unique per distinct xfrmi device**. `config.XFRMIfNameAndID`
can derive a colliding id for two *distinct* `bind-interface` values: a
bare `st0` and an explicit `st0.0` both resolve to `if_id 1` (the unit
defaults to 0 when there is no `.N` suffix) under *different* device
names (`st0` vs `st0.0`). Programming both would either `EEXIST` or,
worse, silently route both VPNs' SAs through one device — leaking
traffic between VPNs that are supposed to be isolated.

`Apply` therefore detects when two distinct desired device names map to
the same `if_id` and **refuses to create either** colliding device
(fail-closed: no transit for the ambiguous pair beats a cross-VPN leak).
If one half of the colliding pair was already created by an earlier
commit, it is torn down on the commit that introduces the alias.
Non-colliding interfaces in the same commit are created normally. The
proper long-term fix is a commit-time rejection of an ambiguous
secure-tunnel `bind-interface` in the config compiler / `pkg/ipsec`
(separate lane, #2885); this routing guard is the last line of defense
so a config that slips through never programs colliding kernel state.

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
  `pbrRulePriority` in `rules.go`. **Kernel FBF support matrix (#3730):**
  `BuildPBRRules` mirrors only the term `from` predicates an `ip rule` can
  express — source/destination address + prefix-list, DSCP (non-zero),
  `protocol` (`FRA_IP_PROTO`), `source-port` (`FRA_SPORT_RANGE`) and
  `destination-port` (`FRA_DPORT_RANGE`); multi-value protocol/port sets
  expand to one rule per value and a port range maps to a single `[lo,hi]`
  range. A term carrying any predicate an `ip rule` cannot represent —
  `source-port-except` / `destination-port-except`, `tcp-flags`,
  `icmp-type` / `icmp-code`, `is-fragment`, `flexible-match-range`, a
  DSCP-0 match, a non-empty address `except` set, an unknown protocol /
  unparseable port, or any unresolved `from` leaf — FAILS CLOSED:
  `buildPBRFromFilter` (via `pbrTermL4`) drops the whole term and records a
  degraded build error. Honoring the address/protocol/port half while
  silently dropping the rest would WIDEN the match and steer traffic the
  operator constrained away (the #3730 over-steer); dropping the term is
  the fail-safe under-steer (steered traffic falls back to the main table)
  and the userspace filter path still enforces the term exactly. The
  degraded error is returned to the daemon (`daemon_apply.go` step 3d) and
  logged; the buildable rules are still installed.
- `33000–33099`: rib-group inter-VRF leaking (`from all lookup
  <table>`). `ribGroupManager.Apply` only installs a leak rule when an
  instance's `interface-routes` rib-group imports a rib that resolves to
  a real table *different* from the instance's own source table.
  `resolveRibTable` returns `(tableID, ok)`; an **unknown / undefined**
  import-rib (typo, non-existent instance, garbage — `ok == false`) is
  skipped with a warning and never sets `needsLeak`, so it cannot install
  a phantom `from all lookup <sourceTable>` rule — and nothing is ever
  installed into table 0 from an unresolved name (#2226). The family
  suffix is matched **exactly**: `resolveRibTable` (via
  `ribInstanceFromName`) resolves only `inet.0` / `inet6.0` (main table)
  and `<instance>.inet.0` / `<instance>.inet6.0` (an instance with a
  non-empty prefix). A malformed family token whose prefix happens to be
  a defined instance — `<instance>.inetX.0`, `.inetfoo.0`, `.inet60.0`,
  or trailing garbage like `.inet.0.x` — returns `ok == false` and is
  rejected, not silently mapped onto the instance table (#2253). The
  earlier loose `.inet` substring match accepted those. The matching
  commit-time gate `validateRibGroupImportRibReferencesStrict`
  (`pkg/config`) mirrors the same exact-suffix matcher and hard-rejects
  the dangling/malformed import-rib before apply; both sides MUST stay in
  lockstep so the commit gate and the runtime applier agree on what
  resolves. This runtime guard is the defense-in-depth backstop for the
  tolerant load / peer-sync path.
- main table at `32766`. The next-table range sits **before** main
  (lower priority value = higher priority). PBR sits before main as
  well; rib-group sits after.

### clear()/Apply error contract (#2273)

Each reconciler's `Apply` is clear-then-re-add: `clear()` removes every
rule in the manager's own priority window, then `Apply` re-installs the
desired set. `clear()` walks `[AF_INET, AF_INET6]`, calling `RuleList`
(a per-family netlink dump) on each. The error handling is:

- **Per-family `RuleList` failures are best-effort but observable.** A
  family whose dump fails is skipped (its in-window rules are left in
  place that pass), but the failure is **aggregated and returned**
  (`errors.Join`, wrapped with the family) rather than swallowed. Every
  family whose dump succeeds is still cleaned. Before #2273 a transient
  `AF_INET` dump failure orphaned the IPv4 rules in the window for that
  pass and `clear()` returned `nil`, so the caller never learned — a
  brief, unobservable self-healing window (the rules are re-cleared on
  the next commit once the transient clears).
- **`Apply` logs-and-continues; it does NOT abort on a `clear()` error.**
  The clear error is captured, logged at WARN, and the desired rules are
  still re-added (forward progress on the common path is preserved,
  including the empty-config early returns). `Apply` then **returns the
  clear error** so `pkg/daemon` (`daemon_apply.go` steps 3b–3d) observes
  it. The daemon currently logs Apply errors at WARN and continues; the
  change makes the failure visible (and lets a future caller retry)
  without changing the daemon's apply sequencing. `RuleDel` failures on
  individual rules remain debug-logged and do not fail `Apply` — a stale
  rule that survives one delete is swept by the next pass and re-add uses
  `NLM_F_CREATE|NLM_F_EXCL`, so a still-desired rule stays correct.

## Tunnel reconcile-in-place (#1884)

`tunnelManager.Apply` reconciles instead of clear-all +
delete-and-recreate: an untouched tunnel keeps its netdev (stable
ifindex — no FRR route churn, no userspace-dp TUN-reader death per
commit, see #1881/#1887), tunnels removed from config are deleted via a
set-diff against the previous DESIRED set (`ownedNames`, retained on a
failed delete OR a TRANSIENT `LinkByName` lookup error for retry — a
genuine not-found drops tracking; a transient error must not orphan a
live link with stale addresses, #1919 r2), and a device is recreated only
when the existing kernel link is genuinely incompatible:

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
  tracked for retry. On an `AddrList` enumeration failure the reconcile
  deletes nothing AND preserves the prior applied LINK-LOCAL ownership
  (so a configured fe80 mid-removal is not silently re-classified as
  foreign and leaked on a later WG prune — #1919 r1 Codex MAJOR); the
  configured-address AddrAdd pass still runs (idempotent on EEXIST).
- **WireGuard removal address prune** (`wgConfigured`, #1919): WG `wgN`
  TUNs are persistent (#1432 S2a) — they are deliberately excluded from
  the `ownedNames` removal diff so the link is NEVER torn on reload
  (tearing it flaps the device + live peer). But that exclusion meant a
  WG tunnel REMOVED from config never had its addresses reconciled away
  (the per-tunnel apply loop only reconciles still-configured WG). `Apply`
  now keeps a WG-only `wgConfigured` set; a name that disappears from it
  has `pruneAppliedAddrsLocked` delete every present non-link-local
  address (manager owns the device's non-LL set, same as steady-state
  reconcile) plus configured/applied link-locals, while KEEPING the link.
  The helper returns `(failed, retry)`; the name is retained for retry
  when an `AddrDel` failed OR `AddrList` itself failed (cannot prove
  clean) — decoupled from `len(failed)` so an empty applied set with a
  transient list failure still retries (it does NOT reuse
  `reconcileLinkAddrsLocked`, whose return only records failed LL
  deletes). A transient `LinkByName` error (vs `isLinkNotFound`) also
  retains for retry; a genuine not-found drops tracking. Residuals
  deferred to #1434: removal while the daemon was DOWN is not pruned
  (only tracked-applied addresses prune), and VRF membership is not
  unbound (WG binds VRF directly, no `appliedRI` claim).
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
  are reconciled by normalized identity `(remote, source, interval,
  retry<=0→3)` and survive unrelated applies; `LinkSetUp` is SKIPPED
  when a retained runner holds the tunnel down (the down-transition in
  `keepaliveLoop` is gated on `state.Up`, so re-upping would strand
  the link admin UP). A change to the tunnel SOURCE restarts the runner
  (#1918 §5c): the source is the probe bind address.

## Keepalive liveness probing (`tunnel_keepalive.go`, #1918)

The keepalive performs a **real ICMP echo round-trip** — it is a
liveness check, not a route-existence check. (The pre-#1918 `probeICMP`
opened a socket and returned `true` without sending anything, so a dead
peer behind a valid route read up forever and the fail-safe
`LinkSetDown` was unreachable.)

- **Mechanism**: unprivileged datagram ICMP (`udp4`/`udp6` via
  `golang.org/x/net/icmp`), the same mechanism as the tested
  `pkg/cluster/monitor.go` precedent. Requires `net.ipv4.ping_group_range`
  to admit the daemon gid (or `CAP_NET_RAW`); when it does not, the probe
  is **ProbeUnsupported** and the link is HELD (never torn down — see
  hold-on-unknown).
- **Reply match**: `Seq` + a per-probe random **Data-nonce** — NOT the
  ICMP ID. Datagram ("ping") sockets rewrite the outbound id to the
  socket source port, so id is advisory only.
- **Probe target / table**: the underlay `Destination`, routed in the
  GLOBAL/underlay FIB (no `SO_BINDTODEVICE` to an overlay VRF) — exactly
  where the tunnel's encapsulated packets resolve.
- **Source bind**: the probe binds the tunnel's local `Source` IP so the
  echo egresses from, and the reply returns to, the tunnel endpoint
  (multi-homed / policy-routed correctness). Empty source → wildcard.
- **Typed result** (`ProbeResult`): `ProbeAlive | ProbeDead |
  ProbeUnsupported`. The old `bool` erased "could not probe".
- **Hold-on-unknown** (Axis C): on `ProbeUnsupported` the loop does NOT
  change `Failures` and does NOT transition the link; it holds the prior
  `Up` and reports `KeepaliveUp == nil` with `KeepaliveInfo = "unknown
  (...)"`. Structural causes (missing `ping_group_range`/cap, bound
  source not local) hold indefinitely with a one-shot `slog.Warn`;
  transient causes (FD/memory exhaustion, unrecognized errno) hold but
  escalate to `slog.Error` after `MaxRetries` consecutive unknown ticks
  so a real peer death is never silently masked. Tearing the link down
  because the daemon cannot probe would be a self-inflicted outage.
- **Commit-after-success / lock scope** (Axis D): the tick classifies the
  probe and computes the transition INTENT under `state.mu`, releases the
  lock, performs the single `LinkSetUp`/`LinkSetDown` OUTSIDE the lock,
  and commits `state.Up` ONLY if the netlink op succeeded. A
  `LinkByName`/`LinkSet*` error leaves `Up` unchanged so the transition
  retries next tick (never a lost or half-applied transition), and a
  racing `GetStatus` never blocks behind a slow netlink op nor observes
  an uncommitted `Up`.
- **Recreate safety**: `applyKernelTunnelLocked` cancels + DRAINS the
  existing keepalive runner BEFORE it deletes/recreates the kernel link
  (drain-before-recreate), so no stale runner can issue a `LinkSet*`
  against a recreated link that reused the ifindex. A per-tunnel
  `linkGen` (`*atomic.Uint64`, read LOCK-FREE by the runner — it never
  takes `t.mu`) is the defense-in-depth backstop; the runner drops any
  transition whose captured generation no longer matches.

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
