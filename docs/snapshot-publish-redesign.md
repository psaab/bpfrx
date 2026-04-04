# Snapshot Publish Redesign

## 1. Problem Statement

The userspace dataplane control socket is a serialized bottleneck. Every
operation — snapshot publish, session install, status poll, HA state sync,
forwarding state sync — goes through a single Unix socket using a 2-second
dial timeout and a 3-second post-connect I/O deadline in
`requestDetailedLocked()` (`pkg/dataplane/userspace/manager.go:2418`).

Observed symptoms during OSPF/BGP convergence on an HA cluster:

- **5,213 RST suppression reinstalls** during a single boot — each triggered by
  `syncInterfaceNATAddressMapsLocked()` which runs on every `Compile()` path
- **42-second barrier ack delays** during manual failover — peer barrier in
  `prepareUserspaceRGDemotionWithTimeout()` (`pkg/daemon/daemon_ha.go:1169`)
  waits for all queued session deltas to drain, but session installs from
  `SetClusterSyncedSessionV4()` (`pkg/dataplane/userspace/manager_ha.go:542`)
  are starved by continuous snapshot publishes
- **Dozens of full snapshot rebuilds per second** during FRR route convergence —
  each `BumpFIBGeneration()` (`manager.go:378`) calls `buildSnapshot()` which
  reads all kernel routes/neighbors and serializes the entire config

Root cause: every `Compile()` call triggers `BumpFIBGeneration()` which rebuilds
and publishes a complete snapshot (config + route snapshots from config + kernel
neighbors + policies + NAT rules). During OSPF convergence, `applyConfig()`
fires continuously (route changes → FRR reload → recompile), holding the control
socket mutex and blocking HA session installs.

## 2. Current Architecture

### What triggers Compile() and snapshot publish

| Trigger | Call site | Frequency |
|---------|-----------|-----------|
| Config commit | `pkg/daemon/daemon.go` `d.dp.Compile(cfg)` | On commit only |
| RETH MAC deferred re-compile | `pkg/daemon/daemon.go` | Once per MAC set |
| HA RG activation/demotion | `pkg/dataplane/userspace/manager_ha.go` `BumpFIBGeneration()` | Per RG transition |
| Compile tail (eBPF inner) | `pkg/dataplane/compiler.go` `BumpFIBGeneration()` | Every Compile() |
| DHCP lease change | `pkg/daemon/daemon.go` `d.applyConfig()` | Per lease |
| Config sync from peer | `pkg/daemon/daemon_ha.go` `d.applyConfig()` | Per peer push |
| Status poll catch-up | `pkg/dataplane/userspace/manager.go` `syncSnapshotLocked()` | 1/s poll |

### What a snapshot contains

`buildSnapshot()` (`manager.go:723`) assembles everything into one blob:

- **Config state**: zones, policies, NAT rules, screens, filters, policers,
  flow export, address books — changes only on commit
- **FIB state**: `buildRouteSnapshots()` derives routes from config static routes
  and connected interface prefixes (NOT kernel routing tables);
  `buildNeighborSnapshots()` reads kernel ARP/NDP via `netlink.NeighList` —
  changes on every route event / neighbor state change
- **Interface state**: ifindex mappings, fabric config, tunnel endpoints
- **HA state**: redundancy group inventory

The entire snapshot is JSON-encoded and sent over the control socket as a
single `apply_snapshot` request (`manager.go:310`).

### Control socket serialization

`requestDetailedLocked()` (`manager.go:2418`) dials the Unix socket, writes
the JSON request, reads the JSON response, and closes the connection — all
under `m.mu.Lock()`. Every caller blocks:

- `SetClusterSyncedSessionV4()` — session install from HA sync (line 558)
- `syncHAStateLocked()` — HA state update
- `syncDesiredForwardingStateLocked()` — forwarding state
- Status poll (1/s) — `manager.go:3816`
- Snapshot publish — `manager.go:2490`

A single snapshot publish that takes 50ms blocks all session installs for that
duration. During route convergence, back-to-back publishes can hold the socket
for seconds.

### HA config sync today

Config sync is commit-time only: `pushConfigToPeer()` (`daemon_ha.go:1194`)
sends the active config text via `QueueConfig()` (`sync.go:1043`), and the
receiver applies it via `handleConfigSync()` (`daemon_ha.go:1215`). This part
is already correctly scoped — config sync is not the contention source.

## 3. Proposed Design: Separate Config State from FIB State

### Config snapshots (commit-time only)

Config state changes only when the user commits. Split the snapshot into two
message types:

**ConfigSnapshot** — pushed on `Compile()` only when config content changes:
- Zones, security policies, NAT rules, screen profiles
- Interface assignments, VLAN config, address books
- Filters, policers, flow export config
- Scheduler and QoS configuration

This is the expensive part of `buildSnapshot()` but changes infrequently.

### FIB deltas (route/neighbor events)

Instead of rebuilding the entire snapshot on every route change, send
lightweight delta messages:

```go
type FIBDelta struct {
    Operation   string // "add" | "delete"
    Family      int    // AF_INET | AF_INET6
    Prefix      string // CIDR notation
    NextHop     string // next-hop IP (empty for connected)
    IfIndex     uint32
    MAC         [6]byte // resolved neighbor MAC (if known)
    Table       uint32  // routing table ID
    VRF         string  // VRF name (empty for main)
}
```

New control message type: `"fib_delta"` — a batch of adds/deletes that the
Rust helper applies incrementally to its route table. No full snapshot rebuild.

**Neighbor deltas** follow the same pattern:
```go
type NeighborDelta struct {
    Operation string // "add" | "delete" | "update"
    Family    int
    IP        string
    MAC       [6]byte
    IfIndex   uint32
    State     int    // NUD_REACHABLE, NUD_STALE, etc.
}
```

### Where to split

In `BumpFIBGeneration()` (`manager.go:378`), replace the full snapshot rebuild:

```go
// Before (current):
snap := buildSnapshot(m.lastSnapshot.Config, m.cfg, m.generation, newGen)
m.syncSnapshotLocked()  // full snapshot over control socket

// After (proposed):
deltas := computeFIBDeltas(m.lastRoutes, currentRoutes)
m.syncFIBDeltasLocked(deltas)  // lightweight batch over control socket
m.lastRoutes = currentRoutes
```

The Rust helper maintains its own route table and applies deltas
incrementally. No JSON serialization of the full config on every route change.

**FIB generation propagation**: The `fib_delta` message must include the new
`fib_generation` value. The Rust helper updates `last_fib_generation` on each
delta batch, and workers refresh `validation.fib_generation` from it. This is
critical: flow-cache validation depends on FIB generation to invalidate stale
entries after route and HA changes. Without advancing the generation on deltas,
pre-transition cache entries survive route changes.

### HA config sync (unchanged)

Config sync is already commit-time only (`pushConfigToPeer()`). No changes
needed. The FIB delta path is local-only — each node resolves its own routes
from FRR and applies deltas to its own Rust helper.

## 4. Control Socket Priority

Session installs from HA sync must not be blocked by snapshot publishes.
Three options, in order of implementation preference:

### Option A: Content-hash deduplication (Phase 1, no protocol change)

Before publishing a snapshot, hash the serialized content. Skip if unchanged.
This eliminates the most common case: `BumpFIBGeneration()` where routes
haven't actually changed (FRR convergence sends multiple notifications for
the same final state).

### Option B: Separate session channel

Add a second Unix socket (`control-sessions.sock`) dedicated to session
install/delete operations. The Rust helper listens on both sockets. Session
operations never compete with snapshot publishes.

**Go-side locking change required**: `SetClusterSyncedSessionV4()` and
snapshot publish are both serialized under `Manager.mu` before either
request reaches the Unix socket. Moving only the transport to a second
socket doesn't help if the Go lock still serializes both. The session
install path must use a separate mutex (e.g., `sessionMu`) that does not
contend with the snapshot publish path's `mu`. The BPF map update
(`m.inner.SetSessionV4`) can stay under `mu`; only the Rust helper
control socket call needs the split.

Requires: Rust helper changes to accept a second listener, Go side to
maintain two connections and split the locking model.

### Option C: Async snapshot publish

Make `syncSnapshotLocked()` non-blocking: write the snapshot to a staging
file and send a short `"load_snapshot"` message with the file path. The Rust
helper reads the file asynchronously. The control socket is held only for
the notification, not for the full payload transfer.

**Recommendation**: Option A first (quick win), then Option B for sustained
improvement.

## 5. Migration Plan

### Phase 1: Content-hash deduplication (quick win)

Scope: `pkg/dataplane/userspace/manager.go`

- Hash the **stable content** of the snapshot (routes, neighbors, interface
  state) *before* `buildSnapshot()` stamps generation/timestamp fields.
  `buildSnapshot()` sets `Generation` and `GeneratedAt` on every call, making
  the full serialized payload unique even when nothing meaningful changed.
  The hash must cover only the fields that affect forwarding behavior:
  route set, neighbor set, interface config, NAT rules.
- Store the hash; skip `buildSnapshot()` + publish entirely if unchanged.
  Increment `FIBGeneration` in the BPF map (the eBPF pipeline needs it)
  but do NOT rebuild or publish the userspace snapshot.
- Covers the common case where `BumpFIBGeneration()` fires repeatedly
  during convergence but the route table hasn't changed yet.
- No protocol changes, no Rust changes.

Expected: eliminates 80%+ of redundant publishes during convergence.

### Phase 2: FIB deltas

Scope: `manager.go`, `manager_ha.go`, Rust helper

- Add `FIBDelta`/`NeighborDelta` structs and `"fib_delta"` control message
- Track last-published route/neighbor sets in the Manager
- `BumpFIBGeneration()` computes and sends deltas instead of full rebuild
- Rust helper implements `apply_fib_deltas()` to update its routing table
- Full snapshot still sent on `Compile()` — deltas only for inter-compile
  FIB changes

Expected: snapshot publish drops from ~50ms to <1ms for route updates.

### Phase 3: Separate session channel

Scope: `manager.go`, `manager_ha.go`, Rust helper

- Add `control-sessions.sock` listener in Rust helper
- `syncSessionV4Locked()` / `syncSessionV6Locked()` use the session socket
- Snapshot publishes and session installs run on independent sockets
- Barrier acks are no longer blocked by in-flight snapshot publishes

Expected: barrier ack latency drops from 42s to <5s.

### Phase 4: Async snapshot publish (if needed)

Only if Phase 1-3 don't fully resolve contention:

- Write snapshot to tmpfs file
- Send `"load_snapshot"` message with path (< 100 bytes on socket)
- Rust helper `mmap`s and processes asynchronously
- Control socket held for <1ms per publish

## 6. Impact

| Metric | Current | After Phase 1 | After Phase 3 |
|--------|---------|---------------|---------------|
| Barrier ack latency | 42s | ~15s | <5s |
| Snapshot publishes during OSPF convergence | dozens/s | ~2-3 | ~2-3 |
| Control socket hold time (FIB bump) | ~50ms | 0ms (skipped) | 0ms |
| Session install latency during convergence | blocked | reduced | unblocked |
| RST suppression reinstalls per boot | 5,213 | ~50 | ~50 |
| CPU from `buildSnapshot()` during convergence | saturated | near zero | near zero |

### Risk

- Phase 1 is zero-risk (additive check, existing code path unchanged)
- Phase 2 requires Rust helper changes but is backward-compatible (fall back
  to full snapshot if helper doesn't support deltas)
- Phase 3 requires coordinated Go + Rust changes but is isolated to the
  session install path
