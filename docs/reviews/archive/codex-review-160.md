# Codex review 160 - ip-monitoring route overlay actuator audit

## 1. Base commit reviewed

- Base: `579768f06`
- Output: `/tmp/codex-review-160.md`
- Agent: `codex`
- Audit mode: quota campaign, not best-findings pass.

## 2. Duplicate suppression summary

I read the prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` corpus plus the relevant repo docs/history for `ipmon`, `ip-monitoring`, `preferred-route`, `PublishRouteOverlaySnapshot`, `pendingFIBBump`, `lowestDataRG`, `xpf_ipmon`, and link-local static routes.

Covered or closed and not duplicated here:

- #1827/#1843: baseline `services ip-monitoring` preferred-route overlay, commit-riding overlay filtering, and duplicate-publish skip.
- #1844/#1851: DHCP-tracked IPv4 next-hop interface support, unresolved candidate skip before winner selection, `pendingFIBBump` retry on a later actuation, and `xpf_ipmon_unresolved_next_hops`.
- #1895: probe-pin false PASS on failed kernel pin programming and autonomous pin retry.
- #2452/#2542: configured static-route IPv6 link-local next-hop interface inference. The new finding below is narrower: ip-monitoring `PreferredRoutes` are not included in the inference input.
- #2492/#2494/#2496/#2558: RPM bad source-address, link-local zone, HTTP scheme, and undefined routing-instance validation.
- #2527: RPM per-cycle transition coalescing.

## 3. Explicit module checklist

1. `pkg/ipmon/ipmon.go`: engine lifecycle, dirty/throttle loop, policy FSM, overlay computation, DHCP resolver seam.
2. `pkg/ipmon/display.go`: CLI/gRPC status rendering.
3. `pkg/daemon/daemon_ipmon.go`: actuator ordering, FRR/snapshot/FIB consumers, HA gate.
4. `pkg/daemon/daemon_rpm.go`: RPM HA gating scope and RG mapping.
5. `pkg/daemon/daemon_apply.go`: full apply overlay handoff and FRR integration.
6. `pkg/daemon/daemon_run.go`: startup/shutdown lifecycle and IPv6 next-hop inference.
7. `pkg/frr/config_render.go`: preferred-route FRR static rendering.
8. `pkg/dataplane/userspace/routes.go`: userspace route snapshot overlay replacement.
9. `pkg/dataplane/userspace/manager.go`: route overlay partial publish and hash skip.
10. `pkg/api/metrics_system.go`: ip-monitoring metrics truthfulness.
11. `pkg/config/compiler_services.go`: parser/validator limits for preferred routes.
12. `docs/multi-wan.md`, `pkg/ipmon/README.md`, `pkg/daemon/README.md`: documented operational contract.

## 4. Module-by-module inspection log

- `pkg/ipmon`: found lifecycle/idempotence issues, stale-state hazards, lock contention, and actuator failure retry gaps. No new hot-path endian/cache-line issue; this is Go control-plane state, not packet hot path.
- `pkg/daemon` actuator: found the strongest correctness risks. The comments state a single decision point, but FRR, snapshot publish, and FIB invalidation fail independently.
- `pkg/frr`: found an overlay-specific link-local inference gap; static-route gap is closed, preferred-route input is not.
- `pkg/dataplane/userspace`: found route overlay snapshot publish updates desired cache before successful publication, and duplicate-skip semantics hide whether an earlier publication failed.
- `pkg/api`: found metrics named as applied state but sourced from desired state.
- `pkg/config`: numeric and IPv6 link-local preferred-route validation gaps remain. Basic family and RI validation are present.
- Docs: existing docs honestly mention lowest-data-RG publication coarseness; I still list it as low-confidence/known limitation because it is vSRX parity relevant and should have a first-class issue if not already open.

## 5. High confidence findings

### H1. FRR reload failure does not stop dataplane overlay publish, splitting kernel FRR and userspace FIB

- Severity: High
- Confidence: High
- Labels: `bug`, `routing`, `ip-monitoring`, `dataplane-consistency`

Evidence:

```go
// pkg/daemon/daemon_ipmon.go:161-176
func (d *Daemon) applyFRRConfig(fc *frr.FullConfig) {
    if d.frr == nil {
        return
    }
    if err := d.frr.ApplyFull(fc); err != nil {
        if errors.Is(err, frr.ErrFRRReloadDegraded) {
            slog.Warn("FRR reload degraded: additive vtysh -f applied; stale-config removal deferred to the in-manager retry", "err", err)
        } else {
            slog.Warn("failed to apply FRR config", "err", err)
        }
    }
}
```

```go
// pkg/daemon/daemon_ipmon.go:224-241
func (d *Daemon) actuateRouteOverlayLocked(cfg *config.Config) {
    overlay := d.ipmonActiveOverlay()
    d.applyFRRConfig(d.assembleFRRConfig(cfg, overlay))
    pub, ok := d.dp.(routeOverlayPublisher)
    if !ok {
        return
    }
    published, err := pub.PublishRouteOverlaySnapshot(cfg, overlay, schedulerState)
```

Runtime trace:

1. RPM transition marks policy failed.
2. `ipmon.run` fires the route-only actuator.
3. `d.applyFRRConfig` calls `FRR.ApplyFull`; it returns a non-degraded error.
4. `applyFRRConfig` logs only and returns no error.
5. `actuateRouteOverlayLocked` continues and publishes the userspace snapshot with the failover overlay.
6. Userspace forwards new flows to the failover next-hop while FRR/kernel still holds old routes.

Why it matters:

This breaks the stated "FRR and dataplane agree by construction" invariant. A security appliance cannot have kernel routing, dynamic routing, and userspace forwarding disagree after an uplink failure.

Fix direction:

Make FRR actuation return a status. Treat hard `ApplyFull` errors as an unapplied consumer and keep a durable pending route-overlay convergence state. Either fail closed by skipping snapshot/FIB until FRR applies, or explicitly model degraded FRR as a separate state with metrics and retry.

### H2. Snapshot publish failure consumes the dirty event and has no autonomous retry

- Severity: High
- Confidence: High
- Labels: `bug`, `ip-monitoring`, `userspace-dataplane`, `availability`

Evidence:

```go
// pkg/ipmon/ipmon.go:529-545
if !e.dirtySince.IsZero() &&
    now.Sub(e.dirtySince) >= e.debounce &&
    now.Sub(e.lastActuation) >= e.throttle {
    fire = true
    e.dirtySince = time.Time{}
    e.lastActuation = now
}
...
if fire && e.actuate != nil {
    e.actuate()
}
```

```go
// pkg/daemon/daemon_ipmon.go:240-248
published, err := pub.PublishRouteOverlaySnapshot(cfg, overlay, schedulerState)
if err != nil {
    slog.Warn("ip-monitoring: route overlay snapshot publish failed - NOT bumping FIB generation",
        "err", err)
    return
}
```

Runtime trace:

1. Policy enters FAIL and marks `dirtySince`.
2. Run loop fires and clears `dirtySince` before invoking the actuator.
3. FRR may already apply the overlay.
4. `PublishRouteOverlaySnapshot` returns a transient control-socket error.
5. Actuator returns without re-marking dirty, without scheduling retry, and without `pendingFIBBump`.
6. No more RPM transitions occur because the policy remains failed.
7. Dataplane stays on the old route until an unrelated commit, lease change, or transition occurs.

Why it matters:

This is a silent partial failover. The overlay can be active in FRR but missing in the userspace dataplane, which is exactly the path the feature was built to synchronize.

Fix direction:

Make the actuator report failure to the engine, or move pending convergence state into the daemon. A failed publish should requeue after throttle/backoff and expose `xpf_ipmon_actuator_pending{consumer="snapshot"}`.

### H3. FIB-generation bump failure is retried only on a future unrelated actuation

- Severity: High
- Confidence: High
- Labels: `bug`, `ip-monitoring`, `flow-cache`, `dataplane-consistency`

Evidence:

```go
// pkg/daemon/daemon_ipmon.go:257-268
if _, err := pub.BumpFIBGeneration(); err != nil {
    d.pendingFIBBump = true
    slog.Warn("ip-monitoring: FIB generation bump unconfirmed - will retry on next actuation",
        "err", err)
    return
}
d.pendingFIBBump = false
```

```go
// pkg/daemon/daemon_ipmon_test.go:259-285
// Actuation 1: publish OK, bump fails -> pending.
d.actuateRouteOverlayLocked(&config.Config{})
...
// Actuation 2: duplicate publish (hash-skip) + bump still failing ->
// the bump IS retried and stays pending.
d.actuateRouteOverlayLocked(&config.Config{})
```

Runtime trace:

1. Overlay snapshot publish succeeds.
2. `BumpFIBGeneration` control message fails.
3. `pendingFIBBump` is set.
4. No timer or kick is scheduled by the daemon.
5. Existing flows keep cached old egress routes indefinitely.
6. The test demonstrates retry only by manually invoking a second actuation; production has no equivalent self-retry if the policy remains stable.

Why it matters:

Established flows are the expensive case during failover. A successful snapshot without a confirmed FIB bump can leave long-lived flows pinned to the dead path forever.

Fix direction:

Add an autonomous retry loop keyed to `pendingFIBBump`, with bounded backoff and stop-context cancellation. Treat confirmed bump as a separate convergence consumer, not a side effect of future overlay transitions.

### H4. `actuateRouteOverlay` can block daemon shutdown forever on `applySem.Acquire(context.Background())`

- Severity: High
- Confidence: High
- Labels: `bug`, `lifecycle`, `ip-monitoring`, `shutdown`

Evidence:

```go
// pkg/daemon/daemon_ipmon.go:202-209
func (d *Daemon) actuateRouteOverlay() {
    _ = d.applySem.Acquire(context.Background(), 1)
    defer d.applySem.Release(1)
```

```go
// pkg/daemon/daemon_run.go:1695-1699
// Stop the ip-monitoring engine (after RPM so no transitions
// arrive during teardown).
if d.ipmon != nil {
    d.ipmon.Stop()
}
```

```go
// pkg/ipmon/ipmon.go:541-559
if fire && e.actuate != nil {
    e.actuate()
}
...
case <-e.stop:
    return
```

Runtime trace:

1. `ipmon.run` fires while another apply holds `applySem`.
2. The actuator blocks in `Acquire(context.Background(), 1)`.
3. The daemon begins shutdown and calls `d.ipmon.Stop()`.
4. `Stop` closes `e.stop` and waits for `done`.
5. The run loop cannot observe `e.stop` because it is blocked inside `e.actuate()`.
6. Shutdown hangs until the unrelated apply releases the semaphore, possibly forever if that apply is wedged.

Why it matters:

Control-plane shutdown/restart is part of failover recovery. An unbounded wait inside an optional route-overlay actuator can wedge the daemon.

Fix direction:

Use daemon context in `Acquire`, make actuator cancellable, and have `Stop`/shutdown bound wait time. Consider dropping or rescheduling route-only actuation if shutdown has begun.

### H5. IPv6 link-local ip-monitoring preferred routes are not included in FRR interface inference

- Severity: High
- Confidence: High
- Labels: `bug`, `ipv6`, `ip-monitoring`, `frr`, `vsrx-parity`

Evidence:

```go
// pkg/frr/config_render.go:301-306
sr := &config.StaticRoute{
    Destination: entry.Destination,
    Preference:  1,
    NextHops:    []config.NextHopEntry{{Address: entry.NextHop}},
}
b.WriteString(m.generateStaticRouteInTable(sr, vrfName, tableID, fc.RethMap, fc.IPv6NextHopInterfaces))
```

```go
// pkg/daemon/daemon_run.go:2097-2105
addRoutes := func(vrfName string, routes []*config.StaticRoute) {
    candidates := connectedByVRF[vrfName]
    for _, sr := range routes {
        for _, nh := range sr.NextHops {
            if nh.Interface != "" || nh.Address == "" || !strings.Contains(nh.Address, ":") {
                continue
            }
            setResolved(vrfName, nh.Address, resolve(candidates, nh.Address))
```

```go
// pkg/daemon/daemon_run.go:2145-2154
addRoutes("", cfg.RoutingOptions.StaticRoutes)
addRoutes("", cfg.RoutingOptions.Inet6StaticRoutes)
for _, ri := range cfg.RoutingInstances {
    ...
    addRoutes(vrfName, ri.StaticRoutes)
    addRoutes(vrfName, ri.Inet6StaticRoutes)
}
```

Runtime trace:

1. Operator configures `services ip-monitoring ... preferred-route route ::/0 next-hop fe80::1`.
2. Validation accepts literal IPv6 next-hop if family matches.
3. `inferIPv6StaticNextHopInterfaces` resolves only addresses that appear in configured static route next-hops.
4. The ip-monitoring overlay `PreferredRoutes` are not passed to `addRoutes`.
5. `renderPreferredRoutes` builds a `StaticRoute` with only `Address: fe80::1`.
6. `generateStaticRouteInTable` looks up `IPv6NextHopInterfaces[vrf][fe80::1]`; the key is absent unless an unrelated static route mentions the same gateway.
7. FRR receives `ipv6 route ::/0 fe80::1 1`, which the repo docs state FRR rejects without a trailing interface.

Why it matters:

IPv6 WAN gateways are commonly link-local. vSRX supports next-hop interface qualification; xpf's ip-monitoring overlay can fail exactly when the failover route is needed.

Fix direction:

Either reject literal link-local `preferred-route next-hop` unless an interface qualifier exists, or extend `PreferredRoute` / `RouteOverlayEntry` with explicit next-hop interface for IPv6 literals and feed overlay entries into the inference map before rendering.

### H6. `PublishRouteOverlaySnapshot` mutates the cached desired overlay before publication succeeds

- Severity: High
- Confidence: High
- Labels: `bug`, `userspace-dataplane`, `state-consistency`

Evidence:

```go
// pkg/dataplane/userspace/manager.go:929-935
func (m *Manager) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (published bool, err error) {
    m.mu.Lock()
    defer m.mu.Unlock()

    m.routeOverlay = cloneRouteOverlay(overlay)
```

```go
// pkg/dataplane/userspace/manager.go:984-989
if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
    return false, fmt.Errorf("publish route overlay snapshot: %w", err)
}
m.logWgEndpointSetTransitionLocked(&publishSnap, "route-overlay")
m.generation = nextGeneration
m.lastSnapshot = &next
```

Runtime trace:

1. Route overlay publish starts with a new failover route.
2. Manager immediately sets `m.routeOverlay` to the new desired overlay.
3. The helper `apply_snapshot` request fails.
4. Function returns an error before updating `lastSnapshot`.
5. A later full apply calls `SetRouteOverlay`/snapshot build paths that read the cached overlay as if it were the last successful dynamic overlay.
6. Observability cannot distinguish cached-desired from helper-applied state.

Why it matters:

This increases the blast radius of transient helper failures. Internal state says "new overlay" before the dataplane accepted it.

Fix direction:

Split desired overlay from applied overlay. Update applied overlay only after successful `apply_snapshot`; keep pending desired state with explicit retry/metrics.

### H7. `Status`/`FormatStatus` reports PASS for unknown or absent RPM data

- Severity: High
- Confidence: High
- Labels: `bug`, `observability`, `ip-monitoring`, `vsrx-parity`

Evidence:

```go
// pkg/ipmon/ipmon.go:418-424
for test, failed := range e.failedTests[st.cfg.MatchRPMProbe] {
    if failed {
        ps.FailingTests = append(ps.FailingTests, test)
    }
}
sort.Strings(ps.FailingTests)
```

```go
// pkg/ipmon/display.go:16-27
state := "PASS"
if ps.Failed {
    state = "FAIL"
}
...
if len(ps.FailingTests) == 0 {
    fmt.Fprintf(w, "    %-22s %-15s %-16s %s\n", ps.Probe, "*", "-", "PASS")
}
```

Runtime trace:

1. Policy is configured but RPM has not produced a result yet, or the probe set is gated off/unknown.
2. `e.failedTests[probe]` is nil or contains no failed entries.
3. `PolicyStatus.Failed` remains false and `FailingTests` is empty.
4. CLI/gRPC prints `Status: PASS` and test row `PASS`.

Why it matters:

Unknown health is not pass. Operators reading `show services ip-monitoring status` can assume failover protection is active and healthy when no probe result exists.

Fix direction:

Track per-test known state and expose `UNKNOWN`/`HELD` separately from PASS. The RPM result model already has setup-error/hold concepts; carry them through to ipmon status.

### H8. `xpf_ipmon_routes_applied` is desired overlay count, not applied-route count

- Severity: High
- Confidence: High
- Labels: `bug`, `metrics`, `observability`, `ip-monitoring`

Evidence:

```go
// pkg/api/metrics_system.go:176-196
routesApplied := 0
for _, ps := range c.srv.ipmonStatusFn() {
    ...
    routesApplied += len(ps.Routes)
}
ch <- prometheus.MustNewConstMetric(c.ipmonRoutesApplied,
    prometheus.GaugeValue, float64(routesApplied))
```

```go
// pkg/api/metrics_descriptors.go:530-533
ipmonRoutesApplied: prometheus.NewDesc(
    "xpf_ipmon_routes_applied",
    "Number of ip-monitoring preferred routes currently applied "+
        "(after winner resolution, #1827).",
```

Runtime trace:

1. Policy fails and `Status()` computes a route in `ps.Routes`.
2. FRR reload fails, snapshot publish fails, or FIB bump fails.
3. Metric still increments from `len(ps.Routes)`.
4. Alerting sees routes "currently applied" even when one or more consumers never applied them.

Why it matters:

This hides exactly the failover failure modes that need alerts.

Fix direction:

Rename to desired overlay routes, or add consumer-specific applied gauges: `xpf_ipmon_overlay_desired`, `xpf_ipmon_overlay_frr_applied`, `xpf_ipmon_overlay_snapshot_applied`, `xpf_ipmon_fib_bump_pending`.

### H9. Engine lifecycle is not idempotent; double `Start` can panic by closing `done` twice

- Severity: High
- Confidence: High
- Labels: `bug`, `lifecycle`, `test-gap`

Evidence:

```go
// pkg/ipmon/ipmon.go:184-197
func (e *Engine) Start() {
    go e.run()
}

func (e *Engine) Stop() {
    ...
    close(e.stop)
    <-e.done
}
```

```go
// pkg/ipmon/ipmon.go:517-520
func (e *Engine) run() {
    defer close(e.done)
    timer := time.NewTimer(time.Hour)
```

Runtime trace:

1. A future hot-reload, test, or lifecycle refactor calls `Start` twice on the same engine.
2. Two goroutines enter `run`.
3. `Stop` closes `e.stop`.
4. Both goroutines return and both defer `close(e.done)`.
5. The second close panics.

Why it matters:

The daemon currently starts once, but this is an exported engine API and the exact lifecycle style has caused repeated regressions in this repo.

Fix direction:

Add `sync.Once` or explicit state under lock. Make `Start` return an error on double start and make `Stop` safe before start and after stop.

### H10. `Stop` before `Start` deadlocks forever

- Severity: High
- Confidence: High
- Labels: `bug`, `lifecycle`

Evidence:

```go
// pkg/ipmon/ipmon.go:189-198
func (e *Engine) Stop() {
    select {
    case <-e.stop:
        return // already stopped
    default:
    }
    close(e.stop)
    <-e.done
}
```

Runtime trace:

1. A constructed engine is stopped as part of error cleanup before `Start`.
2. `Stop` closes `e.stop`.
3. No run loop exists to close `e.done`.
4. Caller blocks forever.

Why it matters:

Constructor/startup error unwinds are common around netlink, DHCP, dataplane, and cluster wiring. A safe engine should not require the caller to remember an external started flag.

Fix direction:

Track lifecycle state. If not started, close both stop/done or return without waiting.

## 6. Medium confidence findings

### M1. Failed actuator clears the dirty bit before any consumer confirms success

- Severity: Medium
- Confidence: Medium
- Labels: `bug`, `ip-monitoring`, `retry`

Evidence:

```go
// pkg/ipmon/ipmon.go:531-537
if !e.dirtySince.IsZero() &&
    now.Sub(e.dirtySince) >= e.debounce &&
    now.Sub(e.lastActuation) >= e.throttle {
    fire = true
    e.dirtySince = time.Time{}
    e.lastActuation = now
}
```

Runtime trace:

1. Dirty bit represents unapplied desired state.
2. Engine clears it before the actuator starts.
3. Actuator has no return value.
4. Any failure path becomes invisible to the scheduler.

Why it matters:

This is the root cause behind H2/H3 and makes retries a bolt-on instead of part of the state machine.

Fix direction:

Track `dirty` until an actuator success ack. If actuator returns per-consumer results, clear only the consumers that converged.

### M2. Multi-RG HA publication gate keys all overlays to the lowest data RG

- Severity: Medium
- Confidence: Medium
- Labels: `feature-gap`, `ha`, `ip-monitoring`, `vsrx-parity`

Evidence:

```go
// pkg/daemon/daemon_ipmon.go:291-299
func (d *Daemon) ipmonPublishAllowed(cfg *config.Config) bool {
    if d.cluster == nil || cfg == nil || cfg.Chassis.Cluster == nil {
        return true
    }
    return d.cluster.IsLocalPrimary(lowestDataRG(cfg))
}
```

```md
docs/multi-wan.md:486-490
Overlay publication follows the same gate. Known v1 coarseness: the
publication gate keys on primaryship of the LOWEST data RG only - in
a multi-data-RG cluster with split primaryship, per-policy/per-RETH
publication gating is not yet differentiated
```

Runtime trace:

1. RG1 primary is node A; RG2 primary is node B.
2. An ip-monitoring policy controls a route for an RG2 uplink.
3. On node B, `ipmonPublishAllowed` checks `lowestDataRG`, which is RG1.
4. Node B suppresses all overlay publication even though it owns RG2.

Why it matters:

vSRX deployments can split RG ownership. A coarse global gate turns per-RG failover into wrong-node behavior.

Fix direction:

Compute publish eligibility per policy/route from the matched probe's gating RG or the route's egress/RETH ownership, not a node-wide boolean.

### M3. RPM probe gating can still default referenced probes to the wrong RG when no RETH/source binding exists

- Severity: Medium
- Confidence: Medium
- Labels: `feature-gap`, `ha`, `rpm`, `ip-monitoring`, `vsrx-parity`

Evidence:

```go
// pkg/daemon/daemon_rpm.go:133-165
defaultRG := lowestDataRG(cfg)
...
rgID, inScope := defaultRG, false
if referenced[probeName] {
    inScope = true
}
...
if inScope {
    gated[probeName] = rgID
}
```

Runtime trace:

1. An RPM probe is referenced by an ip-monitoring policy but does not have `destination-interface` or a VIP source-address.
2. `referenced[probeName]` makes it gated.
3. No test updates `rgID`.
4. The probe is gated by `lowestDataRG`, even if the preferred route targets another RG's uplink.

Why it matters:

This is a hidden default. It can suppress the probe on the actual owner node in split-RG deployments.

Fix direction:

Require explicit RG binding for HA-gated ip-monitoring probes, or derive the RG from the policy's preferred-route egress interface/routing-instance.

### M4. `NotifyNextHopChange` schedules baseline actuation even while publication is HA-gated off

- Severity: Medium
- Confidence: Medium
- Labels: `performance`, `ha`, `ip-monitoring`

Evidence:

```go
// pkg/ipmon/ipmon.go:157-180
func (e *Engine) NotifyNextHopChange() {
    e.mu.Lock()
    relevant := false
    for _, st := range e.policies {
        if !st.failed {
            continue
        }
        ...
    }
    if relevant {
        e.markDirtyLocked(true)
    }
```

```go
// pkg/ipmon/ipmon.go:310-313
func (e *Engine) computeOverlayLocked() ([]config.RouteOverlayEntry, map[string][]string) {
    if !e.publishEnabled {
        return nil, nil
    }
```

Runtime trace:

1. Standby node has `publishEnabled=false`.
2. A DHCP gateway change occurs on a failed interface-typed policy.
3. `NotifyNextHopChange` marks dirty without checking publication gate.
4. Actuator fires and publishes/re-renders the baseline (`nil` overlay), possibly repeatedly on a standby.

Why it matters:

This is avoidable control-plane churn in HA, under the same failure conditions where DHCP may be flapping.

Fix direction:

When gated off, record that a next-hop changed but avoid route-only actuation until gate opens, or make the actuator cheap no-op if current and target overlays are both nil.

### M5. DHCP resolver is called under `Engine.mu`, so a slow DHCP manager blocks transitions and status

- Severity: Medium
- Confidence: Medium
- Labels: `performance`, `lock-contention`, `ip-monitoring`

Evidence:

```go
// pkg/ipmon/ipmon.go:74-80
// Called under Engine.mu during overlay computation; the implementation may
// take its own lock (dhcp.Manager.mu) but must NEVER call back into
// the engine - the lock order Engine.mu -> dhcp.mu is one-way.
type NextHopResolver func(leaseIface string) (gw string, ok bool)
```

```go
// pkg/ipmon/ipmon.go:331-335
if pr.NextHopInterface != "" {
    gw, ok := "", false
    if e.resolveNextHop != nil {
        gw, ok = e.resolveNextHop(pr.NextHopInterface)
    }
```

Runtime trace:

1. `Status`, `ActiveOverlay`, `Apply`, or `run` computes overlay.
2. Engine holds `Engine.mu`.
3. Resolver calls into DHCP manager and may wait on `dhcp.mu`.
4. RPM transitions and other ipmon status calls block behind `Engine.mu`.

Why it matters:

Failover control-plane paths should avoid nested locks over external subsystems. A DHCP stall should not block RPM transition ingestion.

Fix direction:

Snapshot lease gateways into an ipmon-owned map on DHCP hook, or call resolver outside `Engine.mu` and feed immutable resolved gateway data into the winner computation.

### M6. Full apply computes overlay before and after policy swap, potentially doing resolver work twice under apply lock

- Severity: Medium
- Confidence: Medium
- Labels: `performance`, `commit-latency`, `ip-monitoring`

Evidence:

```go
// pkg/ipmon/ipmon.go:204-231
e.mu.Lock()
overlayBefore := e.activeOverlayLocked()
...
changed := e.evaluateLocked(e.now())
if !changed && !slices.Equal(overlayBefore, e.activeOverlayLocked()) {
    changed = true
}
```

Runtime trace:

1. Operator commit calls `reconcileIPMon` under the daemon apply path.
2. Engine computes current overlay, resolving DHCP interface next-hops.
3. It swaps policies, evaluates, then computes overlay again.
4. Each computation may take `dhcp.mu`.

Why it matters:

Commit latency grows with policies/routes and DHCP lock contention, and it happens under the daemon's serialized apply path.

Fix direction:

Compute a cheap structural overlay fingerprint that uses cached resolved gateways, or make the resolver snapshot explicit once per apply.

### M7. Hold-down duration changes do not reset an already pending recovery timer

- Severity: Medium
- Confidence: Medium
- Labels: `bug`, `ip-monitoring`, `config-change`

Evidence:

```go
// pkg/ipmon/ipmon.go:217-223
if prev, ok := e.policies[name]; ok && prev.cfg.MatchRPMProbe == pol.MatchRPMProbe {
    st.failed = prev.failed
    st.since = prev.since
    st.pendingRecoveryAt = prev.pendingRecoveryAt
    st.transitions = prev.transitions
}
```

```go
// pkg/ipmon/ipmon.go:479-489
case !anyFailed && st.failed:
    hold := time.Duration(st.cfg.HoldDownSecs) * time.Second
    if hold > 0 {
        if st.pendingRecoveryAt.IsZero() {
            st.pendingRecoveryAt = now.Add(hold)
            ...
        }
        if now.Before(st.pendingRecoveryAt) {
            continue
        }
```

Runtime trace:

1. Policy is failed, then probes recover and a 300s hold-down starts.
2. Operator changes hold-down to 10s, same policy name and same RPM probe.
3. `Apply` preserves the old `pendingRecoveryAt`.
4. Recovery still waits for the old deadline.

Why it matters:

Operator intent during incident response is ignored. Lowering hold-down should shorten recovery; raising it should extend the pending hold.

Fix direction:

Preserve pending recovery only if hold-down value is unchanged; otherwise recompute from now or from original recovery start with a stored start timestamp.

### M8. `seedResultsLocked(nil)` preserves stale fail state for package/API callers

- Severity: Medium
- Confidence: Medium
- Labels: `bug`, `api-contract`, `ip-monitoring`

Evidence:

```go
// pkg/ipmon/ipmon.go:436-452
func (e *Engine) seedResultsLocked(results []*rpm.ProbeResult) {
    if results == nil {
        return
    }
    fresh := make(map[string]map[string]bool)
    ...
    e.failedTests = fresh
}
```

Runtime trace:

1. Engine previously saw probe `WAN/t` fail.
2. Caller applies a new policy config with `results=nil`.
3. `seedResultsLocked` returns and leaves the old `failedTests` map intact.
4. A survivor policy matching `WAN` can stay failed using stale results.

Why it matters:

The daemon usually has an RPM manager, but the exported engine API and tests use nil. This is a footgun for future callers and startup/error paths.

Fix direction:

Define nil results semantics explicitly. If nil means unknown, clear to unknown and status should show UNKNOWN; if nil means preserve, rename the method or require a separate `ApplyPreserveResults`.

### M9. Unresolved route status omits routing-instance, policy route next-hop-interface, and metric

- Severity: Medium
- Confidence: Medium
- Labels: `observability`, `ip-monitoring`, `operator-ux`

Evidence:

```go
// pkg/ipmon/ipmon.go:339-343
if unresolved == nil {
    unresolved = make(map[string][]string)
}
unresolved[name] = append(unresolved[name], dest)
```

```go
// pkg/ipmon/display.go:50-52
for _, dest := range ps.UnresolvedRoutes {
    fmt.Fprintf(w, "    %-17s next-hop unresolved (no DHCP gateway) - skipped\n", dest)
}
```

Runtime trace:

1. Two policies or two routing-instances have unresolved `0.0.0.0/0` candidates.
2. `Status` records only the destination prefix per policy.
3. Display omits the routing-instance, interface lease key, metric, and candidate next-hop.

Why it matters:

Operators cannot tell which DHCP unit is missing or which RI lost failover. This slows incident recovery.

Fix direction:

Replace `[]string` with a typed unresolved route struct carrying RI, destination, next-hop-interface, metric, and reason.

### M10. Losing failed policies hide their route actions in status

- Severity: Medium
- Confidence: Medium
- Labels: `observability`, `ip-monitoring`, `vsrx-parity`

Evidence:

```go
// pkg/ipmon/ipmon.go:392-416
overlay, unresolved := e.computeOverlayLocked()
byPolicy := make(map[string][]config.RouteOverlayEntry)
for _, entry := range overlay {
    byPolicy[entry.Policy] = append(byPolicy[entry.Policy], entry)
}
...
Routes: byPolicy[name],
```

Runtime trace:

1. Policy A and policy B are both failed for the same prefix.
2. Policy A wins by lower preferred metric or lexicographic tie-break.
3. Policy B remains failed but has no `Routes` in `Status`.
4. CLI shows B failed with `(none applied)`, not "suppressed by A".

Why it matters:

This looks like an unresolved/buggy failover route rather than a deterministic winner decision.

Fix direction:

Expose candidate routes and result state: APPLIED, SUPPRESSED_BY_POLICY, UNRESOLVED, GATED.

## 7. Low confidence findings and design smells

### L1. No metric exposes actuator failures or pending convergence consumers

- Severity: Low
- Confidence: Low
- Labels: `observability`, `ip-monitoring`

Evidence:

```go
// pkg/api/metrics_descriptors.go:517-545
ipmonPolicyFailed
ipmonPolicyTransitions
ipmonRoutesApplied
ipmonUnresolvedNextHops
```

Runtime trace:

1. FRR fails, snapshot publish fails, or FIB bump is pending.
2. Only logs record the condition.
3. Metrics expose desired policy state and desired route count, not consumer convergence.

Fix direction:

Add counters/gauges for FRR apply errors, snapshot publish errors, pending FIB bump, last successful route-overlay actuation age, and per-consumer applied generation.

### L2. `PreferredMetric` is an unbounded `int`

- Severity: Low
- Confidence: Low
- Labels: `validation`, `ip-monitoring`

Evidence:

```go
// pkg/config/compiler_services.go:855-862
setMetric := func(v string) error {
    n, err := strconv.Atoi(v)
    if err != nil || n < 0 {
        return fmt.Errorf(...)
    }
    r.PreferredMetric = n
```

Runtime trace:

1. Operator commits an extremely large metric within Go `int` range.
2. Engine uses it for ordering only.
3. Display/tests carry it without an operational bound.

Why it matters:

This is less severe because the injected FRR route preference is fixed at 1. Still, Junos-like config surfaces should have explicit ranges and schema/CLI completion should document them.

Fix direction:

Pick a bounded range matching schema validators and docs, or document unbounded in-memory tie-break semantics.

### L3. `SetNextHopResolver` is exported but intentionally racy after `Start`

- Severity: Low
- Confidence: Low
- Labels: `api-contract`, `race`, `ip-monitoring`

Evidence:

```go
// pkg/ipmon/ipmon.go:140-145
// Must be called before Start() - the field is read by the
// run-loop goroutine without further synchronization.
func (e *Engine) SetNextHopResolver(r NextHopResolver) {
    e.resolveNextHop = r
}
```

Runtime trace:

1. Future code changes resolver after engine start.
2. Run loop/status concurrently reads `resolveNextHop`.
3. Go race detector catches a data race, or production gets undefined behavior.

Fix direction:

Set resolver only through constructor, or guard it under `Engine.mu`/atomic value and make hot-swaps safe.

### L4. `FormatStatus` uses wall-clock `time.Until` rather than engine clock

- Severity: Low
- Confidence: Low
- Labels: `observability`, `test-gap`

Evidence:

```go
// pkg/ipmon/display.go:56-58
if !ps.PendingRecoveryAt.IsZero() {
    fmt.Fprintf(w, "  Recovery hold-down expires in %s\n",
        time.Until(ps.PendingRecoveryAt).Round(time.Second))
}
```

Runtime trace:

1. Engine tests can inject `e.now`.
2. Display always uses real wall clock.
3. NTP jumps or tests with fake clocks can show negative/incorrect hold-down remaining.

Fix direction:

Carry computed remaining duration in `PolicyStatus`, or inject a clock into the renderer for tests.

### L5. Route-only actuator docs promise one decision point but code has no transaction record

- Severity: Low
- Confidence: Low
- Labels: `modularity`, `refactor`, `ip-monitoring`

Evidence:

```go
// pkg/ipmon/ipmon.go:11-17
// The single decision point is the engine's effective-route overlay
// ...
// Both consumers (the FRR managed-section render and the userspace snapshot
// builder) read the same overlay, so kernel and dataplane agree by
// construction.
```

Runtime trace:

1. One overlay value is computed.
2. Three stateful consumers apply it in sequence.
3. There is no `RouteOverlayTransaction` object with per-consumer state.

Fix direction:

Introduce `ipmon/actuator` or `routeoverlay/*.go` package with an explicit transaction model: desired generation, FRR generation, snapshot generation, FIB generation, retry policy, metrics, and reconciliation.

### L6. `Apply` preserves policy state by `(name, probe)` only, not by route-action semantic revision

- Severity: Low
- Confidence: Low
- Labels: `ip-monitoring`, `config-change`, `test-gap`

Evidence:

```go
// pkg/ipmon/ipmon.go:217-223
if prev, ok := e.policies[name]; ok && prev.cfg.MatchRPMProbe == pol.MatchRPMProbe {
    st.failed = prev.failed
    st.since = prev.since
    st.pendingRecoveryAt = prev.pendingRecoveryAt
    st.transitions = prev.transitions
}
```

Runtime trace:

1. Policy name and probe are unchanged.
2. Operator changes preferred-route set or hold-down.
3. Failure state, since, pending recovery, and transition count are preserved.

Why it matters:

Some preservation is intentional, but state like pending recovery may no longer be semantically attached to the new route-action set.

Fix direction:

Store a semantic revision hash for the fields that should reset timers/counters independently from probe identity.

### L7. No status field tells whether publication is HA-gated off

- Severity: Low
- Confidence: Low
- Labels: `observability`, `ha`, `ip-monitoring`

Evidence:

```go
// pkg/ipmon/ipmon.go:407-416
ps := PolicyStatus{
    Name:              name,
    Probe:             st.cfg.MatchRPMProbe,
    Failed:            st.failed,
    ...
    Routes:            byPolicy[name],
```

Runtime trace:

1. Node is standby and `publishEnabled=false`.
2. Policy is failed internally.
3. `computeOverlayLocked` returns nil.
4. Status shows failed policy and `(none applied)`, but not "standby gate".

Fix direction:

Add `PublicationGate` / `GatedReason` to `PolicyStatus`, render it, and emit a gauge.

### L8. Userspace route overlay replaces next-hop list with bare `entry.NextHop`, so no interface scope can ever reach the helper

- Severity: Low
- Confidence: Low
- Labels: `ipv6`, `dataplane`, `route-snapshot`, `vsrx-parity`

Evidence:

```go
// pkg/dataplane/userspace/routes.go:173-178
replaced[key{table, family, dest}] = RouteSnapshot{
    Table:       table,
    Family:      family,
    Destination: dest,
    NextHops:    []string{entry.NextHop},
}
```

Runtime trace:

1. Future work adds IPv6 link-local preferred-route support with explicit interface.
2. `RouteOverlayEntry` currently has no field to carry literal next-hop interface.
3. Userspace snapshot can only encode address string.

Why it matters:

The Go FRR side has interface-aware static routes. The helper route snapshot representation may need an `addr@iface` convention for overlay routes too.

Fix direction:

Define an interface-scoped next-hop representation for overlay entries before claiming IPv6 link-local preferred-route parity.

### L9. Standalone engine has no bounded actuator timeout

- Severity: Low
- Confidence: Low
- Labels: `lifecycle`, `performance`

Evidence:

```go
// pkg/ipmon/ipmon.go:541-545
if fire && e.actuate != nil {
    e.actuate()
}
```

Runtime trace:

1. Actuator blocks on FRR reload, control socket, or semaphore.
2. Engine cannot process stop, hold-down expiry, or subsequent dirty events.

Fix direction:

Use an actuator interface that accepts context and returns status; bound control-plane blocking.

### L10. No integration test proves a stable failed policy self-recovers from one transient publish/bump failure

- Severity: Low
- Confidence: Low
- Labels: `test-gap`, `ip-monitoring`

Evidence:

```go
// pkg/daemon/daemon_ipmon_test.go:259-285
// retry is exercised by manually calling actuateRouteOverlayLocked again
d.actuateRouteOverlayLocked(&config.Config{})
...
d.actuateRouteOverlayLocked(&config.Config{})
```

Runtime trace:

1. Unit test calls the actuator repeatedly.
2. Production only calls it from the engine when dirty/throttle conditions fire.
3. No test drives `Engine.run` through a stable failed state plus one transient actuator failure.

Fix direction:

Add an integration test with fake clock or short debounce/throttle proving self-retry without an extra RPM transition.

### L11. `RouteOverlayEntry.NextHopInterface` is described as consumer-ignored, which blocks richer parity

- Severity: Low
- Confidence: Low
- Labels: `modularity`, `route-overlay`

Evidence:

```go
// pkg/config/types_system.go:647-653
// NextHopInterface records the DHCP lease key the NextHop was
// resolved from when the owning PreferredRoute is interface-typed
// (#1844); "" for literal next-hops. FRR/snapshot consumers read
// NextHop only - this field exists so FilterOverlayForConfig can
// match an interface-typed entry against the incoming config
```

Runtime trace:

1. Current consumers are intentionally blind to interface data.
2. Literal IPv6 link-local and future route-action features need interface scoping.

Fix direction:

Promote overlay next-hop to a typed struct `{address, interface, lease_key, source}` and have FRR/snapshot consumers consume the same struct.

### L12. `docs/multi-wan.md` omits `xpf_ipmon_unresolved_next_hops` in the observability quick list

- Severity: Low
- Confidence: Low
- Labels: `docs`, `observability`

Evidence:

```md
docs/multi-wan.md:472-475
- Prometheus: `xpf_ipmon_policy_failed{policy}`,
  `xpf_ipmon_policy_transitions_total{policy}`,
  `xpf_ipmon_routes_applied`.
```

Runtime trace:

1. Operator follows the quick observability list.
2. DHCP-tracked next-hop unresolved state is the most important failure mode for DHCP backup uplinks.
3. The quick list omits it; it appears later in prose.

Fix direction:

Add `xpf_ipmon_unresolved_next_hops` and any new convergence metrics to the quick list.

## 8. Suggested issue split

1. Route-overlay actuator convergence transaction: FRR, snapshot publish, FIB bump retries and per-consumer metrics. Covers H1, H2, H3, M1, L1, L5, L9, L10.
2. Make ipmon engine lifecycle idempotent and cancellable. Covers H4, H9, H10.
3. Add IPv6 link-local/interface-scoped preferred-route overlay support or fail-closed validation. Covers H5, L8, L11.
4. Fix ip-monitoring status truth model: UNKNOWN/HELD/GATED/SUPPRESSED and richer unresolved details. Covers H7, M9, M10, L7.
5. Rename or split `xpf_ipmon_routes_applied` into desired vs applied/converged metrics. Covers H8 and L12.
6. Per-RG ip-monitoring HA publication/probe gating. Covers M2 and M3; label `vsrx-parity`.
7. Remove DHCP resolver calls from under `Engine.mu` and reduce apply-path resolver work. Covers M5 and M6.
8. Reset or recompute hold-down pending timers on semantic config changes. Covers M7 and L6.
9. Define nil-results semantics for `Engine.Apply`. Covers M8.
10. Bound preferred-metric and document schema semantics. Covers L2.
11. Make `SetNextHopResolver` safe or constructor-only. Covers L3.
12. Make hold-down display clock-testable. Covers L4.
