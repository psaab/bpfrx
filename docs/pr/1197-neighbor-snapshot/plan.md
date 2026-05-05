---
status: REVISED v3 — kernel-as-authority redesign per user feedback
issue: #1197
phase: Plan + fix design
prior:
  - v1 commit 2709752f — fixed second loop only; missed 5 things
  - v2 commit f6e7070a — addressed Codex round-1 5 findings (incremental defense)
  - v3 (this) — user feedback: redesign to event-driven + proactive-probe
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

### 5.2 Phase 2: listen for changes

Add a general neighbor netlink subscriber in `pkg/daemon/`:

```go
// neighborListener subscribes to RTM_NEWNEIGH/DELNEIGH for all
// interfaces, filters to neighbors we care about (next-hops in
// the active config), and triggers snapshot regeneration when a
// monitored neighbor's MAC changes.
func (d *Daemon) neighborListener(ctx context.Context) {
    updates := make(chan netlink.NeighUpdate, 256)
    done := make(chan struct{})
    if err := netlink.NeighSubscribe(updates, done); err != nil {
        slog.Warn("neighbor listener subscribe failed", "err", err)
        return
    }
    defer close(done)

    for {
        select {
        case <-ctx.Done():
            return
        case u, ok := <-updates:
            if !ok {
                return
            }
            d.handleNeighUpdate(u)
        }
    }
}

func (d *Daemon) handleNeighUpdate(u netlink.NeighUpdate) {
    // Filter: only react to neighbors on configured interfaces
    // for IPs we monitor (next-hops, address-book, NAT dests).
    if !d.isMonitoredNeighbor(u.IP, u.LinkIndex) {
        return
    }

    // For each event type:
    switch u.Type {
    case syscall.RTM_NEWNEIGH:
        // Kernel learned/updated a MAC. If our snapshot disagrees
        // (or doesn't have it), regen the snapshot and publish.
        if d.snapshotDisagreesOrMissing(u.IP, u.LinkIndex,
                                        u.HardwareAddr) {
            d.dp.RegenerateNeighborSnapshot()
        }
    case syscall.RTM_DELNEIGH:
        // Kernel evicted entry. Trigger a proactive probe to
        // re-resolve, then regen snapshot when reply arrives
        // (which will fire RTM_NEWNEIGH).
        go d.probeNeighbor(u.IP, u.LinkIndex)
    }
}
```

### 5.3 Phase 3: proactive expiry + reprobe

Add a periodic resolver timer (15s or 30s; tunable) that calls
`resolveNeighborsInner(cfg, false)` for all known next-hops. The
existing function:
- Iterates next-hops, address-book hosts, NAT destinations
- Sends ARP / IPv6 NS via raw socket (already implemented)
- Doesn't block on replies (false flag)

The kernel handles the rest. Replies come back via normal NDISC
processing → kernel updates ARP → RTM_NEWNEIGH fires → our
listener regenerates snapshot.

This replaces the 15s preinstall tick with a 15s probe tick. The
probe is proactive (kernel may have valid REACHABLE; probe
re-confirms) and harmless (kernel won't update ARP unless reply
differs from existing).

### 5.4 Phase 4: snapshot regeneration is event-driven

`Manager.RegenerateNeighborSnapshot()` (new public method on
`pkg/dataplane/userspace/manager.go`) becomes the single entry
point for "kernel changed; tell userspace-dp."

It's called from:
- `handleNeighUpdate` (RTM_NEWNEIGH for monitored IP, MAC differs)
- `BumpFIBGeneration` (already calls `buildNeighborSnapshots`;
  preserve)
- `resolveNeighbors` completion (after probe, snapshot may have
  refreshed)

The function:
- Calls `buildNeighborSnapshots(cfg)` to rebuild from kernel
- Diffs against `lastSnapshot.Neighbors`
- If different: updates `lastSnapshot.Neighbors`, publishes
  `update_neighbors` to userspace-dp.

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

**PR 1 (this):** v3 minimum viable
- Delete `preinstallSnapshotNeighbors` (and its 15s tick)
- Add `neighborListener` (RTM_NEWNEIGH → regenerate snapshot)
- Add `Manager.RegenerateNeighborSnapshot()`
- Replace 15s preinstall tick with 15s `resolveNeighborsInner`
  call (existing function; new caller)

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

## 11. Open questions for adversarial review v3

1. Is removing `preinstallSnapshotNeighbors` entirely safe? The
   function's stated purpose is "keep standby warm for failover."
   The argument is: standby gets warm via activation-time
   `resolveNeighbors`, and the new periodic probe keeps it warmer
   over time. Verifies via failover test.

2. Is RTM_NEWNEIGH from `netlink.NeighSubscribe` reliable enough
   that we can stop pushing snapshot to kernel? The existing
   subscription in `daemon_ha_fabric.go:809` is already trusted
   for fabric peer monitoring; expanding the trust is a small
   step, but worth flagging.

3. Is the `isMonitoredNeighbor` filter scope correct? Initial
   scope: any IP that appears as a static-route next-hop in the
   active config; any address-book host; any NAT destination;
   any fabric peer; any VRRP virtual router. Should this be
   broader (all configured interface peers) or narrower
   (next-hops only)?

4. Does the periodic `resolveNeighborsInner` probe at 15s tick
   create unwanted ARP/NS traffic? At 5-10 next-hops × 15s ticks
   = ~40 NS/ARP per minute. Compare to broadcast ARP cost.

5. Should `RegenerateNeighborSnapshot` debounce? RTM_NEWNEIGH
   may fire in bursts (e.g., during VRRP failover when many
   peers all GARP at once). A 100ms debounce would coalesce
   bursts.

## 12. Verdict request

PLAN-READY → implement v3 phase 1.
PLAN-NEEDS-MINOR → tweak rationale/code, then implement.
PLAN-NEEDS-MAJOR → still wrong; revise.
PLAN-KILL → premise wrong; redesign.
