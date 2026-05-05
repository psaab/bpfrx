---
status: REVISED v5 — Codex round-4 PLAN-NEEDS-MAJOR; 5 more holes plugged (atomic-PR constraint added)
issue: #1197
phase: Plan + fix design
prior:
  - v1 commit 2709752f — fixed second loop only; missed 5 things
  - v2 commit f6e7070a — addressed Codex round-1 5 findings (incremental defense)
  - v3 commit 867bd363 — kernel-as-authority redesign per user feedback
  - v4 commit 4bcb7947 — Codex round-3 4 substantive holes
  - v5 (this) — Codex round-4 found 5 more holes; addressing now
---

## 1. Issue framing (unchanged)

Issue #1197: xpfd preinstalls stale neighbor MAC into kernel ARP
every 15s. When peer MAC changes, kernel briefly learns fresh MAC
via normal ARP, then xpfd reverts. Self-heals only via xpfd
restart.

## 2. Design shift from v2 to v3

User feedback rejected the v2 incremental-defense approach in favor
of the principled redesign:

> "Shouldn't we be listening for neighbor advertisements and
> updating those when it changes to what we have cached? Also
> shouldn't we doing a neighbor solicit when our view of the
> world expires. We shouldn't be caching the mac forever if we
> haven't heard from it for a while. We should actually
> pre-emptively send our an NS before we expire the entry to
> make sure it's still there."

This is RFC 4861 NUD discipline applied to the snapshot:
- **Listen** on netlink for kernel ARP/NDP changes (RTM_NEWNEIGH/
  RTM_DELNEIGH).
- **Don't cache forever** — entries have a TTL; expire when the
  kernel stops confirming them.
- **Proactively probe** before an entry is too cold via NS/ARP,
  give the kernel a chance to confirm it's still valid.
- **Trust the kernel** as the source of truth on the current MAC.
  Stop pushing snapshot-MAC into kernel ARP.

The current design fights the kernel's NUD machinery. The right
design is to compose with it.

## 3. Inverted authority model

### Current (broken) data flow

```
xpfd snapshot (Go memory)  →  kernel ARP (push every 15s, NeighSet)
xpfd snapshot (Go memory)  →  userspace-dp state.neighbors (publish on regen)
```

Snapshot is treated as authoritative; pushed both ways.

### v3 data flow

```
Kernel ARP/NDP ← (kernel runs RFC 4861 NUD: REACHABLE→STALE→DELAY→PROBE)
Kernel ARP → xpfd snapshot ← listen on RTM_NEWNEIGH/DELNEIGH
xpfd snapshot → userspace-dp state.neighbors (publish on change)
xpfd → kernel: send proactive NS/ARP via resolveNeighbors
              for next-hops we actively care about
```

Kernel is authoritative; xpfd is a listener + proactive prober.

## 4. Existing infrastructure to leverage

### Netlink neighbor subscription
`pkg/daemon/daemon_ha_fabric.go:809` — `netlink.NeighSubscribe`
already exists, narrowly scoped to fabric peer IPs. We extend
or parallel this for all monitored neighbors.

### Proactive probing
`pkg/daemon/daemon_neighbor.go:117` — `resolveNeighbors` already
sends ARP / IPv6 NS for known next-hops, NAT destinations, address-
book hosts. Called from:
- `daemon_health.go:84` (health check)
- `daemon_ha_vip.go:174` (VRRP master transition)
- `daemon_apply.go:807` (after config apply)
- `daemon_neighbor.go:430,451` (config commit + DHCP refresh)

We add a periodic timer that calls `resolveNeighbors` (or its
inner equivalent) so kernel-side entries stay warm.

### Snapshot regeneration
`pkg/dataplane/userspace/manager.go:421` — `BumpFIBGeneration`
already rebuilds snapshot via `buildNeighborSnapshots(cfg)` and
publishes via `update_neighbors`. The new netlink listener
triggers this on neighbor change.

## 5. Concrete v3 design

### 5.1 Phase 1: stop the bug

Two minimum changes that stop the connectivity-breaking behavior:

**A) Remove the snapshot-driven NeighSet loop entirely.**
`pkg/daemon/daemon_neighbor.go:78-101` — delete this loop. It
unconditionally overwrites kernel ARP with stale snapshot MAC.
The replacement: nothing at the kernel-write level; we listen
instead.

**B) Make the kernel-list NeighSet loop state-preserving.**
`pkg/daemon/daemon_neighbor.go:33-74` — read kernel ARP, but
only re-NeighSet entries that are ALREADY REACHABLE. Don't
promote STALE/DELAY/PROBE → REACHABLE. (The whole loop is
arguably useless once we listen, but minimal-fix says preserve
the "keep REACHABLE timer warm" behavior.)

Actually — simpler: **delete the entire `preinstallSnapshotNeighbors`
function**. The kernel manages its own ARP. We don't touch it.
The function's stated purpose (keep standby warm for failover) is
already covered by:
- `resolveNeighbors` at activation (sends ARP/NS to populate kernel)
- The new netlink listener that keeps snapshot fresh
- The new periodic probe timer

The 15s preinstall tick disappears entirely.

### 5.2 Phase 2: listen for changes — **CORRECTED per Codex round-3**

Codex round-3 caught two issues with v3 listener:

1. **Filter scope wrong.** `buildNeighborSnapshots` publishes
   ALL kernel neighbors on configured forwarding/fabric
   interfaces (`snapshot.go:1758-1850`). Filter must align with
   that — not narrowed to next-hops only.

2. **Subscription is lossy.** Multicast can drop; not every NUD
   transition is notified. Need `NeighSubscribeWithOptions` with
   `ListExisting: true` (initial dump), error-callback resubscribe,
   debounce, periodic safety reconciliation.

3. **Event handling can't be MAC-only.** RTM_DELNEIGH must trigger
   immediate snapshot eviction. State changes to FAILED/INCOMPLETE
   may also matter. Avoid publish-churn on harmless REACHABLE↔STALE
   transitions via forwarding-effective diff.

Corrected design:

```go
// neighborListener runs the netlink RTM_NEWNEIGH/DELNEIGH event
// loop. Triggers snapshot regen when a monitored neighbor's
// forwarding-effective state changes.
func (d *Daemon) neighborListener(ctx context.Context) {
    var (
        regenDebounce = make(chan struct{}, 1)
        debounceMs    = 100 * time.Millisecond
    )
    // Debounce coalesces bursts (e.g., GARP storm during failover)
    go d.regenDebouncer(ctx, regenDebounce, debounceMs)

    // Periodic safety reconciliation: catches lost multicast events
    safetyTick := time.NewTicker(60 * time.Second)
    defer safetyTick.Stop()

    for {
        if !d.runOneSubscription(ctx, regenDebounce, safetyTick) {
            return // ctx done
        }
        // Subscription closed; resubscribe after backoff.
        select {
        case <-ctx.Done():
            return
        case <-time.After(2 * time.Second):
        }
    }
}

// runOneSubscription owns ONE NeighSubscribe lifetime. Returns
// true to keep retrying (resubscribe), false on ctx done.
//
// Codex round-4: the previous v4 sketch had a `break` inside a
// `select` that exited the select, not the inner loop, so a
// closed updates channel could spin and double-close `done`.
// This helper makes the lifetime explicit: subscription opened,
// loop runs to first error/close, then helper returns and outer
// loop reopens.
func (d *Daemon) runOneSubscription(
    ctx context.Context,
    regenDebounce chan struct{},
    safetyTick *time.Ticker) bool {

    updates := make(chan netlink.NeighUpdate, 1024)
    done := make(chan struct{})
    opts := netlink.NeighSubscribeOptions{
        ListExisting:      true,
        ErrorCallback:     func(err error) {
            slog.Warn("neighbor listener netlink err", "err", err)
        },
        ReceiveBufferSize: 1 << 20, // 1 MB; channel size != socket buf
    }
    if err := netlink.NeighSubscribeWithOptions(updates, done,
                                                opts); err != nil {
        slog.Warn("neighbor subscribe failed", "err", err)
        return true // try again after backoff
    }
    defer close(done) // always close on return; no double-close path

    for {
        select {
        case <-ctx.Done():
            return false
        case <-safetyTick.C:
            d.triggerRegen(regenDebounce)
        case u, ok := <-updates:
            if !ok {
                return true // subscription closed; resubscribe
            }
            if !d.isMonitoredNeighbor(u.LinkIndex) {
                continue
            }
            if d.shouldTriggerRegen(u) {
                d.triggerRegen(regenDebounce)
            }
        }
    }
}

// isMonitoredNeighbor returns true if linkIndex belongs to an
// interface enumerated by buildNeighborSnapshots. Codex round-4
// caught: that snapshot iterates all configured base interfaces
// AND units (snapshot.go:1768-1787), not an informal "forwarding/
// fabric" subset. To stay aligned, EXPORT the enumeration as
// a public helper and reuse it here.
//
// Plan: refactor buildNeighborSnapshots' interface enumeration
// into a shared helper:
//
//   func MonitoredInterfaceLinkIndexes(cfg *config.Config)
//                                         map[int]struct{}
//
// Both buildNeighborSnapshots and isMonitoredNeighbor call this
// helper, so the listener's filter is GUARANTEED to match the
// snapshot's keyspace. Drift is impossible.
func (d *Daemon) isMonitoredNeighbor(linkIndex int) bool {
    cfg := d.store.ActiveConfig()
    if cfg == nil { return false }
    monitored := userspace.MonitoredInterfaceLinkIndexes(cfg)
    _, ok := monitored[linkIndex]
    return ok
}

// shouldTriggerRegen filters out forwarding-irrelevant churn.
// Codex round-4: userspace forwarding (forwarding/mod.rs:45)
// treats every state EXCEPT failed/incomplete as usable. So
// new entries in DELAY/PROBE/NOARP with a valid MAC also need
// to trigger. Same-MAC state churn (REACHABLE↔STALE etc.) is
// the only ignored case.
//
// "Usable" set (must match userspace-dp's neighbor.rs treatment):
//   NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT | NUD_NOARP
const usableNUD = netlink.NUD_REACHABLE | netlink.NUD_STALE |
                  netlink.NUD_DELAY | netlink.NUD_PROBE |
                  netlink.NUD_PERMANENT | netlink.NUD_NOARP

func (d *Daemon) shouldTriggerRegen(u netlink.NeighUpdate) bool {
    switch u.Type {
    case syscall.RTM_DELNEIGH:
        // Kernel evicted entry; snapshot must drop it immediately.
        return true
    case syscall.RTM_NEWNEIGH:
        existing := d.dp.LookupSnapshotNeighbor(u.LinkIndex, u.IP)
        hasMAC := u.HardwareAddr != nil && len(u.HardwareAddr) > 0
        usable := u.State&usableNUD != 0
        unusable := u.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0

        if existing == nil {
            // New usable entry with valid MAC → snapshot must learn it.
            return hasMAC && usable
        }
        // Existing snapshot has this entry.
        // 1. MAC change → always trigger (the bug-class case).
        if hasMAC && !bytes.Equal(existing.MAC, u.HardwareAddr) {
            return true
        }
        // 2. Transition to unusable → snapshot must drop entry.
        if unusable {
            return true
        }
        // 3. Same MAC, same usable category → harmless aging churn.
        return false
    }
    return false
}

// regenDebouncer coalesces regen requests so a burst of events
// (e.g., GARP storm during failover) results in one regen.
func (d *Daemon) regenDebouncer(ctx context.Context, ch chan struct{},
                                 delay time.Duration) {
    var pending bool
    var timer *time.Timer
    for {
        select {
        case <-ctx.Done():
            return
        case <-ch:
            if !pending {
                pending = true
                timer = time.AfterFunc(delay, func() {
                    pending = false
                    if d.dp != nil {
                        d.dp.RegenerateNeighborSnapshot()
                    }
                })
            }
            _ = timer
        }
    }
}

func (d *Daemon) triggerRegen(ch chan struct{}) {
    select { case ch <- struct{}{}: default: }
}
```

This requires a new `Manager.LookupSnapshotNeighbor(ifindex, ip)`
method (cheap O(1) read of in-memory snapshot map).

### 5.3 Phase 3: proactive expiry + reprobe — **CORRECTED per Codex round-3 + round-4**

Codex round-3 caught: `resolveNeighborsInner` at
`daemon_neighbor.go:323-334` skips entries already in
`NUD_REACHABLE|NUD_STALE|NUD_PERMANENT`. Idle STALE entries
**never get re-probed by this path**.

Codex round-4 added: `forceProbeNeighbors` is right shape but
**`collectMonitoredNeighbors` was undefined**, and the force
path **must also fire on RG takeover** (not only the 15s tick).
And **target prioritization** is needed: probe
STALE/PROBE/DELAY first, then on-link/next-hops, then rest —
to avoid a 256-target ARP storm at startup.

Defining `collectMonitoredNeighbors` precisely:

```go
// collectMonitoredNeighbors returns the union of:
//   1. Current snapshot keys (every neighbor xpfd has published
//      to userspace-dp), so we re-validate everything we've told
//      the data plane is reachable.
//   2. Configured next-hops, NAT destinations, address-book hosts
//      (the resolveNeighbors target set), so we keep priming
//      entries the kernel may have aged out.
//   3. Fabric peer IPs (from monitorFabricState).
//
// Returned in PRIORITY ORDER:
//   tier 1: snapshot keys with kernel state in {STALE, PROBE,
//           DELAY, FAILED, INCOMPLETE} — these are the ones at
//           risk of forwarding to dead address
//   tier 2: configured next-hops + fabric peers (highest-impact
//           targets that must not go cold)
//   tier 3: snapshot REACHABLE + remaining configured targets
//
// Truncate at the configured cap (default 256). Log skipped count.
func (d *Daemon) collectMonitoredNeighbors(
    cfg *config.Config) []probeTarget {
    // Implementation: iterate active snapshot first via
    // dp.SnapshotNeighbors() to learn (ifindex, IP, current
    // kernel state via NeighList lookup). Then add configured
    // targets via the existing addByIP/addByName helpers in
    // resolveNeighborsInner. Sort into tier order, truncate.
    // ...
}

// forceProbeNeighbors sends ARP/NS probes for monitored targets
// REGARDLESS of NUD state (no skip-STALE). Distinct from
// resolveNeighborsInner which only fills missing/INCOMPLETE/FAILED
// entries — that semantics is right for activation priming, but
// wrong for steady-state staleness reconciliation.
func (d *Daemon) forceProbeNeighbors(cfg *config.Config) {
    targets := d.collectMonitoredNeighbors(cfg)
    cap := d.neighborProbeMaxTargets // default 256
    if len(targets) > cap {
        slog.Warn("neighbor probe truncated",
                  "total", len(targets), "cap", cap)
        targets = targets[:cap]
    }
    for _, t := range targets {
        link, err := netlink.LinkByIndex(t.linkIndex)
        if err != nil { continue }
        ifName := link.Attrs().Name
        go func(ip net.IP, iface string) {
            if ip.To4() == nil {
                _ = cluster.SendNDSolicitationFromInterface(iface, ip)
            }
            sendICMPProbe(iface, ip)
        }(t.neighborIP, ifName)
    }
}
```

**RG takeover must call forceProbeNeighbors too.** Currently
`daemon_ha_vip.go:174` calls `resolveNeighbors` (skip-stale) on
VRRP MASTER. Change that call to `forceProbeNeighbors` so a
takeover with stale snapshot entries gets re-validated, not
left alone.

This is the periodic cadence (default 15s, tunable) that drives
proactive reprobing. Replies → kernel ARP update → RTM_NEWNEIGH
→ our listener → snapshot regen → userspace-dp update.

**Cardinality concern (Codex finding #4):** address-book hosts
can be much larger than the 5-10 next-hops estimate. Add a
configurable cap (`neighbor-probe-max-targets`, default 256;
log target count each tick).

### 5.4 Phase 4: snapshot regeneration with forwarding-effective diff

Codex round-4 caught: v4 plan's `shouldTriggerRegen` filters
event-loop churn correctly, but **`RegenerateNeighborSnapshot`
itself uses `neighborsEqual` (snapshot.go:160) which compares
RAW state**. So the 60s safety tick + `BumpFIBGeneration` can
still publish on REACHABLE↔STALE churn — the buggy publish
happens at the manager level, not the listener level.

Add a manager-level **forwarding-effective equality**:

```go
// neighborsEqualForwarding compares snapshot entries on what
// matters for forwarding decisions:
//   - (Ifindex, IP, Family) key
//   - MAC
//   - Usable bit (state ∈ {REACHABLE, STALE, DELAY, PROBE,
//     PERMANENT, NOARP} → usable; FAILED/INCOMPLETE → unusable)
//
// Raw state (REACHABLE vs STALE) is NOT compared — both are
// usable and aging churn shouldn't trigger publish.
func neighborsEqualForwarding(a, b []NeighborSnapshot) bool {
    // Build map<key, (mac, usable)> for both, compare.
}
```

Use this in `RegenerateNeighborSnapshot` and the
`BumpFIBGeneration`-driven path so ONLY forwarding-relevant
changes publish.

`Manager.RegenerateNeighborSnapshot()` becomes:

```go
// RegenerateNeighborSnapshot rebuilds neighbors[] from kernel
// ARP/NDP via buildNeighborSnapshots, diffs forwarding-effectively,
// and publishes update_neighbors only on real changes.
func (m *Manager) RegenerateNeighborSnapshot() {
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
        return
    }
    newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
    if neighborsEqualForwarding(m.lastSnapshot.Neighbors,
                                 newNeighbors) {
        return // no forwarding-relevant change
    }
    m.lastSnapshot.Neighbors = newNeighbors
    m.lastSnapshot.Generation = m.generation
    m.publishUpdateNeighbors(newNeighbors)
}
```

Called from:
- `neighborListener` debouncer (event-driven primary path)
- `BumpFIBGeneration` (continues to call this on FIB regen;
  forwarding-effective diff prevents churn)
- `forceProbeNeighbors` completion (after probes have had time
  to land; bound by the 100ms debounce)

## 6. What gets deleted / changed

### Deleted
- `pkg/daemon/daemon_neighbor.go:24-105` — entire
  `preinstallSnapshotNeighbors` function
- The 15s timer at `daemon_neighbor.go:468` that calls it (or
  repurposed to call `resolveNeighborsInner` instead)

### Added
- `pkg/daemon/daemon_neighbor.go` — `neighborListener`,
  `handleNeighUpdate`, `isMonitoredNeighbor`, `probeNeighbor`,
  `snapshotDisagreesOrMissing` helpers
- `pkg/dataplane/userspace/manager.go` —
  `RegenerateNeighborSnapshot()` public method

### Changed
- `pkg/daemon/daemon.go` (or wherever the periodic loop is wired)
  — start `neighborListener` goroutine at daemon init; replace
  preinstall tick with probe tick

## 7. HA / failover considerations

**Failover path (RG transition: standby → active):**
- VRRP MASTER event fires `becomeMaster` (which already calls
  `resolveNeighbors`)
- `resolveNeighbors` sends ARP/NS for all next-hops
- Kernel updates ARP table on replies
- RTM_NEWNEIGH fires for each → our listener updates snapshot
- userspace-dp state.neighbors is fresh BEFORE first packet
  forwarded by new active

**No regression risk** — the activation-time priming is preserved
(it's how the standby gets warm in the first place; it always was
the actual mechanism, not the periodic preinstall which was just
masking the bug).

**Standby cold-cache concern:** while standby, no traffic forces
kernel ARP entries. The kernel may evict over time. When standby
becomes active, `resolveNeighbors` re-sends probes. First-packet
delay is bounded by ARP RTT (~ms) — same as today.

If we want to keep standby warmer, the periodic probe timer (5.3)
runs on standby too — sends NS/ARP, kernel resolves, entries stay
warm. Net effect: standby's kernel ARP is fresher under v3 than
under v1+v2.

## 8. Risk assessment v3

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Removes a buggy path; activation primer + listener cover the use cases |
| HA correctness | LOW | Activation-time `resolveNeighbors` already exists and is the actual mechanism; periodic probe optional |
| Performance regression | NEGLIGIBLE | One netlink subscription; periodic probe sends ~5-10 ARP/NS every 15s; vs current 99-entry NeighSet every 15s |
| Architectural mismatch | LOW | Aligns with kernel NUD; stops fighting it |
| Test coverage | MEDIUM | Need unit tests for listener filter + snapshot regen path; existing `resolveNeighbors` tests cover probe |

## 9. Phased ship plan

**PR 1 (this):** v5 atomic ship — Codex round-4 explicit:
*"One PR is fine only if delete + listener + force-probe + regen
diff ship atomically. Do not ship deletion alone."* So PR1
contains the complete replacement of the broken mechanism:

- **Delete** `preinstallSnapshotNeighbors` (and its 15s tick at
  `daemon_neighbor.go:468`). Stop the bug source.
- **Add** `neighborListener` with:
  - `NeighSubscribeWithOptions{ListExisting:true,
    ErrorCallback:...}` for initial dump + resubscribe loop
  - **Broad filter** matching `buildNeighborSnapshots` keyspace
    (any configured forwarding/fabric interface), NOT narrowed to
    "static next-hops"
  - **Forwarding-effective diff** in `shouldTriggerRegen` —
    ignore REACHABLE↔STALE↔DELAY↔PROBE on same MAC; trigger on
    MAC change, RTM_DELNEIGH, FAILED/INCOMPLETE
  - 100ms debounce coalescer
  - 60s safety reconciliation tick
- **Add** `Manager.RegenerateNeighborSnapshot()` (event-driven
  regen API)
- **Add** `Manager.LookupSnapshotNeighbor(ifindex, ip)` (O(1)
  cheap read for diff)
- **Add** `forceProbeNeighbors(cfg)` — sibling of
  `resolveNeighborsInner` that does NOT skip STALE entries.
  Called periodically (15s, configurable) to drive proactive
  re-validation of all monitored neighbors.
- **Tunable cap** `neighbor-probe-max-targets` (default 256) +
  log target count each tick.
- **Replace** the 15s preinstall tick with the new force-probe
  tick (NOT the existing skip-stale `resolveNeighborsInner`,
  per Codex finding #1).

**PR 2 (follow-up if needed):** TTL-based expiry on snapshot
entries. If kernel entries age out (RTM_DELNEIGH), our snapshot
follows. If we don't hear about an entry for >T, drop it from
snapshot. Forces re-resolution on next packet via the userspace-
dp's existing dynamic_neighbors fallback path.

**PR 3 (follow-up if needed):** explicit takeover-context
preinstall. If failover diagnostics show measurable first-packet
delay despite the new design, add a `preinstallOnTakeover()` that
fires only on RG_active transition (not periodic).

## 10. Test plan

**Unit (pkg/daemon):**
- `TestNeighborListenerUpdatesSnapshotOnMACChange`: install handler,
  inject RTM_NEWNEIGH with new MAC, assert
  `RegenerateNeighborSnapshot` called.
- `TestNeighborListenerIgnoresUnmonitored`: inject for an IP not
  in monitored set; assert no regen.
- `TestNeighborListenerHandlesDelNeigh`: inject RTM_DELNEIGH;
  assert proactive probe fired.

**Unit (pkg/dataplane/userspace):**
- `TestRegenerateNeighborSnapshotPublishesOnChange`
- `TestRegenerateNeighborSnapshotIdempotent`

**Cargo build clean** + cargo tests pass.
**Go test full suite:** zero regressions.

**Manual repro on loss userspace cluster:**
1. Deploy v3 build.
2. `ip neigh replace 172.16.80.200 lladdr <fake_mac> dev
   ge-0-0-2.80 nud reachable` on fw0.
3. Wait 30s.
4. Verify: kernel ARP shows REAL MAC (kernel re-resolved); xpfd
   snapshot has REAL MAC; cluster-host → 172.16.80.200 ping works.
5. Verify journal: RTM_NEWNEIGH events seen, snapshot regen
   triggered.

**Smoke matrix on loss userspace cluster:**
- Full 30-cell smoke (v4+v6, push+reverse, CoS-off+CoS-on,
  per-class 5201-5206) — confirms throughput preserved.
- Failover test: trigger RG1 failover; verify TCP survives;
  verify standby's kernel ARP is fresh (not stale + reverted).

## 11. Open questions for adversarial review v4

1. Is `forceProbeNeighbors` (no skip-STALE) at 15s cadence safe
   in terms of ARP/NS traffic on the wire? Cap protects against
   pathological large address-books, but normal case may still
   be 50-100 probes/min on a busy WAN-side interface.

2. Is the `shouldTriggerRegen` filter sufficient, or are there
   forwarding-effective state transitions it misses?
   Specifically: does NUD_NOARP need any handling
   (loopback/dummy entries)?

3. Is the 60s safety reconciliation tick the right cadence, or
   should it be tighter (10s) to bound staleness if multicast
   loses many events in a row?

4. Does the dynamic-neighbor fallback in
   `userspace-dp/src/afxdp/forwarding/mod.rs:1464` actually
   contain the kernel-learned data, or is it independent of
   netlink? If independent, even a perfect Go-side fix won't
   reach the data plane — Phase 1 needs to verify the
   `update_neighbors` publish path is end-to-end correct.

5. Is "delete `preinstallSnapshotNeighbors` entirely" safe in
   one PR, or should it be progressive (first reduce blast
   radius, then add listener, then delete)? The argument for
   one PR: removing the buggy code is the actual fix; the new
   listener is the replacement. Argument for progressive: less
   blast radius if the listener has bugs.

## 12. Verdict request

PLAN-READY → implement v3 phase 1.
PLAN-NEEDS-MINOR → tweak rationale/code, then implement.
PLAN-NEEDS-MAJOR → still wrong; revise.
PLAN-KILL → premise wrong; redesign.
