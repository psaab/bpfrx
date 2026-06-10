# pkg/rpm

Real-time Performance Monitoring probes (ICMP echo, TCP connect, HTTP
GET). Tracks RTT and jitter, emits events for the event-options engine,
fires per-test pass/fail transitions for the ip-monitoring engine, and
pins probes to devices/next-hops via `SO_BINDTODEVICE` / `SO_MARK`.

## Entry points

- `Manager` — `rpm.go`.
- `ProbeResult` — `rpm.go`. Per-test metrics (RTT, jitter,
  success/fail counters).
- `Event` — `rpm.go`. `test_failed`, `probe_failed`, `test_completed`.
- `Transition` — `rpm.go`. Per-test pass/fail status transition with a
  current-state results snapshot (#1827 — sensor input for
  `pkg/ipmon`).
- `New()` — `rpm.go`.
- `Apply(ctx context.Context, cfg *config.RPMConfig)` — `rpm.go`.
- `StopAll()` — `rpm.go`.
- `Results()` — `rpm.go`.
- `SetEventCallback(fn)` — `rpm.go`.
- `SetTransitionCallback(fn)` — `rpm.go` (#1827).
- `SetRethMap(map[string]string)` — `rpm.go` (#1827). RETH → physical
  member translation for `destination-interface` resolution.

## Callers

`pkg/daemon`, `pkg/eventengine`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`, `pkg/routing` (probe pin mark assignment),
`golang.org/x/net/icmp`.

## Gotchas

- **icmp-ping sends a real ICMP echo since #1827** (raw socket, id/seq
  matching, 3 s timeout). The pre-#1827 prober never put a packet on
  the wire (raw-IP dial + UDP connect fallback — a route-existence
  check), so icmp-ping tests that "always passed" can now fail and can
  now trigger event-options policies. Release-noted behavior change.
- **Setup errors hold state** (AGY PR #1843 F2): a raw-socket open
  failure (capability/permission) is `ErrProbeSetup` — the probe loop
  holds the test's current state (no counters, no status change, no
  events, no Transition), logs a rate-limited Warn, and ip-monitoring
  never actuates routes off an environment error. Send/receive/timeout
  errors stay genuine path failures.
- The raw-socket seam is injectable (`icmpListenFunc` in `icmp.go`) so
  prober logic is unit-testable without privileges.
- `destination-interface` takes precedence over the routing-instance
  VRF device for `SO_BINDTODEVICE`; otherwise VRF binding uses
  `vrf-<ri-name>` — not the destination interface itself.
- Next-hop-pinned tests (`next-hop` leaf) set `SO_MARK` with the fwmark
  derived from `routing.BuildProbePins` — the SAME deterministic
  assignment pkg/routing programs as fwmark rules, so socket mark and
  kernel rule cannot drift.
- Events expose both the test owner (probe name) and the test name so
  event-options policies can match on either via `attributes-match`.
- A consecutive-failure counter discriminates transient blips from
  sustained failures; `test_failed` only fires when the threshold is
  crossed, not on every individual missed probe.
