# pkg/ipmon

`services ip-monitoring` engine (#1827 PR-1b): Junos-parity
probe-driven preferred-route failover. A policy matches one RPM probe;
while ANY test of that probe is FAILED, the policy's preferred routes
are injected (at route preference 1 — Static/1, beating static AD 5 and
DHCP AD 200); on recovery they are withdrawn (after the optional
`hold-down`, an extension beyond Junos that damps recovery flaps).

## The single decision point

`ActiveOverlay()` is the engine's **effective-route overlay**: the set
of currently-injected routes after winner resolution — per
(routing-instance, prefix) the lowest `preferred-metric` wins,
tie-break lexicographic policy name. Both consumers read the SAME
overlay, so kernel and dataplane agree by construction:

1. **FRR** — `frr.FullConfig.PreferredRoutes`, rendered as distance-1
   statics in the managed section (emission step 7), assembled by the
   daemon's `assembleFRRConfig` for BOTH the full apply path and the
   routes-only actuator.
2. **Dataplane snapshot** — `buildRouteSnapshots` overlay parameter;
   an overlay winner replaces the ENTIRE (table, family, prefix) entry
   set (never merges next-hops — no ECMP half-override), published via
   `userspace.Manager.PublishRouteOverlaySnapshot`.

## Actuation

Coalesced: dirty bit + bounded debounce (1 s) + minimum
inter-actuation throttle (3 s); at most one actuation in flight (the
single run-loop goroutine); the actuator snapshots the overlay at run
time (last-writer-wins). `Apply` marks dirty only when the effective
overlay actually changed (Codex PR #1843 MED) — overlay-neutral
commits never schedule a routes-only FRR reload, and the actuator
bumps the FIB generation only when `PublishRouteOverlaySnapshot`
reports a REAL publish (duplicate-skips do not churn established-flow
route caches). A sustained per-cycle flapper with hold-down 0
produces at most one frr-reload + one snapshot push per throttle window
— bounded and observable via `xpf_ipmon_policy_transitions_total`.

The daemon actuator (`pkg/daemon/daemon_ipmon.go`) runs under the SAME
apply semaphore as operator commits and bumps the FIB generation ONLY
after a successful snapshot publish (ordering is load-bearing — see
`actuateRouteOverlayLocked`).

### Consistency + autonomous self-heal (#3757)

The actuator returns a `bool`; the engine clears its dirty bit **only
after** the actuator reports a fully consistent, converged actuation.
Any consumer failure keeps the state dirty and the run loop retries
autonomously on the next sweep, throttle-paced (at most one
frr-reload + snapshot per throttle window), until it converges — no
future config change is required to recover.

- **Hard FRR reload error (H1):** the FRR manager contract guarantees
  *nothing converged* — the kernel FIB still holds the previous routes
  — so the actuator **aborts before publishing** the userspace
  snapshot. Publishing on top would split the FIB (kernel on the old
  route, dataplane on the failover route). Both FIBs stay on the last
  consistent state and the retry re-applies once FRR recovers. A
  **degraded** reload (#1880, additive `vtysh -f` applied) is *not* a
  hard error: the new routes are live in the kernel, so the matching
  snapshot publish keeps the two FIBs in agreement while the FRR
  manager's own retry converges stale-config removal.
- **Snapshot publish error (H2):** no FIB-generation bump, state stays
  dirty, retried on the next sweep.
- **Unconfirmed FIB-generation bump (H3):** `pendingFIBBump` is armed
  *and* the actuation reports failure, so the bump retries on the next
  autonomous sweep (not only on a future unrelated actuation).
- **Dirty cleared only on success (M1):** the run loop snapshots a
  `dirtyGen` before actuating and clears `dirtySince` only when the
  actuation converged AND no newer change landed meanwhile
  (last-writer-wins preserved).

## HA

Overlay is runtime state, never config: it does not sync to the peer
and re-derives from fresh probe results within seconds of a takeover.
`SetPublishEnabled(false)` (standby) makes `ActiveOverlay` return nil —
the config baseline — while the state machine keeps tracking
underneath. Primary-only probing/publication scope is computed in
`pkg/daemon` (`filterRPMForHAGating`, `ipmonPublishAllowed`).

## DHCP-tracked next-hops (#1844)

An interface-typed preferred route (`next-hop ge-0/0/3.0`, compiled to
`PreferredRoute.NextHopInterface` — the Linux DHCP lease key) is
resolved to the unit's DHCP-learned gateway **inside the engine,
before winner selection**, via the injected `NextHopResolver`: an
unresolvable winner (no lease) is skipped so a resolvable losing
candidate can win the prefix — resolving after selection would get
this wrong by construction. Resolved entries carry the gateway in
`RouteOverlayEntry.NextHop` (plus the lease key in
`NextHopInterface`), so FRR render and the snapshot builder are
unchanged. Skipped candidates surface as
`PolicyStatus.UnresolvedRoutes` (shown by `FormatStatus` and exported
as `xpf_ipmon_unresolved_next_hops`).

`NotifyNextHopChange` is the DHCP gateway-change trigger (wired to
`dhcp.New`'s `onGatewayChange` hook): it marks the overlay dirty only
when a currently FAILED policy has an interface-typed route, and
enters the SAME dirty→debounce→throttle queue as probe transitions —
no second actuation path, no full apply.

**Lock order (one-way, load-bearing):** `Engine.mu → dhcp.Manager.mu`.
The resolver (called under `Engine.mu`) takes `dhcp.mu` via
`LeaseFor`; `pkg/dhcp` fires the hook strictly OUTSIDE `dhcp.mu`, so
the hook's bounded blocking on `Engine.mu` can never deadlock. The
resolver must never call back into the engine.

Withdrawal: a removed lease record (client stopped, unit
deconfigured) fires the hook → resolver returns `!ok` → next actuation
withdraws the route. A failed re-acquisition keeps the last-known
gateway (record persists until replaced) — deliberate parity with the
FRR DHCP default route; see the RFC 2131 coupling rule in
`pkg/dhcp/README.md`.

## Entry points

- `Engine`, `New(actuate func() bool)`, `Start/Stop` — `ipmon.go`.
  The actuator returns `true` on a consistent, converged actuation and
  `false` to keep the state dirty for an autonomous retry (#3757).
- `Apply(cfg, results)` — install committed policies, preserving FAIL
  state for surviving (name, probe) pairs.
- `HandleTransition(rpm.Transition)` — the sensor input (wired to
  `rpm.Manager.SetTransitionCallback`).
- `SetNextHopResolver(NextHopResolver)` (before `Start`) and
  `NotifyNextHopChange()` — the #1844 DHCP next-hop seam (above).
- `ActiveOverlay() []config.RouteOverlayEntry`.
- `Status() []PolicyStatus`, `FormatStatus` (`display.go`) — shared by
  the local CLI and gRPC `show services ip-monitoring status`.

## Callers

`pkg/daemon` (engine lifecycle + actuator + next-hop resolver),
`pkg/cli`, `pkg/grpcapi`, `pkg/api` (metrics).

## Dependencies

`pkg/config`, `pkg/rpm`.
