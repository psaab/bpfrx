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

## HA

Overlay is runtime state, never config: it does not sync to the peer
and re-derives from fresh probe results within seconds of a takeover.
`SetPublishEnabled(false)` (standby) makes `ActiveOverlay` return nil —
the config baseline — while the state machine keeps tracking
underneath. Primary-only probing/publication scope is computed in
`pkg/daemon` (`filterRPMForHAGating`, `ipmonPublishAllowed`).

## Entry points

- `Engine`, `New(actuate func())`, `Start/Stop` — `ipmon.go`.
- `Apply(cfg, results)` — install committed policies, preserving FAIL
  state for surviving (name, probe) pairs.
- `HandleTransition(rpm.Transition)` — the sensor input (wired to
  `rpm.Manager.SetTransitionCallback`).
- `ActiveOverlay() []config.RouteOverlayEntry`.
- `Status() []PolicyStatus`, `FormatStatus` (`display.go`) — shared by
  the local CLI and gRPC `show services ip-monitoring status`.

## Callers

`pkg/daemon` (engine lifecycle + actuator), `pkg/cli`, `pkg/grpcapi`,
`pkg/api` (metrics).

## Dependencies

`pkg/config`, `pkg/rpm`.
