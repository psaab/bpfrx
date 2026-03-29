# Session Sync Architecture

## Overview

bpfrx HA clusters synchronize stateful firewall sessions between two nodes so
that a new primary can continue forwarding established flows after an RG move
or peer loss. Session sync rides a custom TCP protocol over the fabric link
(`fab0` / `fab1`).

The current implementation has four distinct pieces:

1. **Bulk sync** — cold transfer of the full owned session set on first
   connection after disconnect and when a different fabric transport becomes
   active.
2. **Incremental sweep** — periodic scan of kernel session maps for new or
   changed sessions.
3. **Userspace deltas** — low-latency event drain from the AF_XDP helper for
   userspace-managed sessions.
4. **Demotion handoff** — an explicit quiesce / republish / barrier sequence
   used before graceful failover, so demotion does not race the sync stream.

The older mental model of "bulk once, then background sweep" is incomplete.
Current failover safety depends on sender-side bulk acknowledgement,
barrier-based demotion ordering, and filtered userspace delta replication.

## Session Representation

### BPF Maps

Sessions live in two BPF hash maps:

- `sessions_v4` — IPv4 sessions
- `sessions_v6` — IPv6 sessions

Each logical session has two entries:

- forward entry: `IsReverse = 0`
- reverse entry: `IsReverse = 1`

Only forward entries are sent on the wire. The receiver recreates the reverse
entry locally.

### Session Value

The session value includes state, policy, timestamps, counters, NAT fields,
reverse key, and a cached forwarding result (`FibIfindex`, MACs, VLAN,
generation).

### Userspace Mirror

When the userspace dataplane is active, cluster-synced forward sessions are
installed into both places:

- the kernel/BPF session maps
- the Rust helper session table via the userspace manager RPC path

`SetClusterSyncedSessionV4()` / `SetClusterSyncedSessionV6()` do both. Before
install, they clear the cached FIB result so the receiving node recomputes
node-local forwarding.

That is only one direction of the userspace integration. Locally-created
userspace sessions do **not** flow back through `SetClusterSyncedSession*`.
They are exported through:

- background `DrainSessionDeltas(...)`
- explicit `ExportOwnerRGSessions(...)` during demotion prep

## Wire Protocol

### Transport

Session sync uses TCP over the fabric overlays:

- `fab0` — primary fabric
- `fab1` — optional secondary fabric

Sockets are bound to `vrf-mgmt` with `SO_BINDTODEVICE`. One deterministic side
initiates per fabric. `TCP_NODELAY` is enabled.

### Header

```
[0:4]   Magic "BPSY"
[4]     Type (uint8)
[5:8]   Reserved
[8:12]  Payload length (uint32, little-endian)
```

### Message Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| 1 | SessionV4 | Primary -> Secondary | Incremental IPv4 add/update |
| 2 | SessionV6 | Primary -> Secondary | Incremental IPv6 add/update |
| 3 | DeleteV4 | Primary -> Secondary | IPv4 delete |
| 4 | DeleteV6 | Primary -> Secondary | IPv6 delete |
| 5 | BulkStart | Primary -> Secondary | Start of bulk transfer |
| 6 | BulkEnd | Primary -> Secondary | End of bulk transfer |
| 7 | Heartbeat | Bidirectional | Keepalive |
| 8 | Config | Primary -> Secondary | Full config text |
| 9 | IPsecSA | Primary -> Secondary | IPsec connection names |
| 10 | Failover | Bidirectional | Remote failover request |
| 11 | Fence | Bidirectional | Peer fencing |
| 12 | ClockSync | Bidirectional | Monotonic clock exchange |
| 13 | Barrier | Primary -> Secondary | Ordered demotion marker |
| 14 | BarrierAck | Secondary -> Primary | Barrier acknowledgement |
| 15 | BulkAck | Secondary -> Primary | Bulk acknowledgement |

## Bulk Sync

### When It Triggers

Bulk sync is started when:

- the first session-sync connection appears after a total disconnect
- a different fabric connection becomes the active transport

On first connection after disconnect, the transport setup order is:

1. flush the delete journal
2. fire `OnPeerConnected`
3. start `BulkSync()`

That order matters because reconnect readiness and retry state are reset before
the new bulk is sent.

### Send Side

`BulkSync()`:

1. allocates a new monotonically increasing epoch
2. sends `BulkStart(epoch)`
3. iterates `sessions_v4` / `sessions_v6`
4. skips reverse entries
5. skips sessions not owned by this node for the ingress zone
6. sends forward entries only
7. sends `BulkEnd(epoch)`
8. records `pendingBulkAckEpoch` and waits for peer acknowledgement

The sender now treats outbound bulk acknowledgement as first-class state. A
bulk transfer is not considered fully primed until the peer returns `BulkAck`
for the current epoch.

### Receive Side

On `BulkStart` the receiver:

- snapshots zone ownership for stale-session reconciliation
- resets the per-bulk receive tracking maps
- marks bulk in progress

For each received session it:

1. decodes key/value
2. tracks the forward key in the current bulk receive set
3. rebases timestamps into local monotonic time
4. clears cached FIB resolution
5. installs the forward entry through `SetClusterSyncedSession*`
6. creates and installs the reverse entry locally
7. recreates any SNAT `dnat_table` entry locally

On `BulkEnd` the receiver:

1. verifies the epoch
2. reconciles stale sessions using the frozen ownership snapshot
3. sends `BulkAck(epoch)`
4. fires `OnBulkSyncReceived`

### Stale Session Reconciliation

After a bulk completes, the receiver deletes sessions that are still present
locally but were not refreshed by the peer for zones that the frozen snapshot
says are peer-owned.

Important detail: zones missing from the frozen snapshot are conservatively kept
instead of deleted.

## Sync Readiness and Bulk Priming

This is the biggest place where older descriptions are wrong or incomplete.
There are now two distinct readiness signals:

- `syncBulkPrimed` — we received the peer's current-generation bulk
- `syncPeerBulkPrimed` — the peer acknowledged our current-generation bulk with
  `BulkAck`

They are not the same thing.

### Connection Lifecycle

On peer connect:

- `syncBulkPrimed = false`
- `syncPeerBulkPrimed = false`
- cluster sync readiness is forced false
- a guarded readiness timeout is armed
- a bulk-prime retry loop starts

On bulk receive:

- `syncBulkPrimed = true`
- the readiness timeout is stopped
- VRRP sync hold is released
- cluster sync readiness becomes true

On bulk ack receive:

- `syncPeerBulkPrimed = true`

On disconnect:

- both primed flags are cleared
- cluster sync readiness is forced false
- the readiness timeout is invalidated with a generation guard so a stale timer
  callback cannot flip readiness back to true after disconnect

### Bulk-Prime Retry Loop

After reconnect, the daemon retries `BulkSync()` if the peer never acknowledges
our current-generation bulk.

Important current behavior:

- retries stop once `syncPeerBulkPrimed` becomes true
- retries are deferred while the current bulk is still waiting for `BulkAck`
- retries are also deferred while inbound sync progress is still advancing
- retries stop if the connection is replaced or disconnected

This exists because failover admission now depends on the standby having both
sides of the current-generation baseline, not just having received one bulk.

## Incremental Sweep and Delete Journal

### Background Sweep

A background sweep periodically scans the kernel session maps for forward
entries whose `Created` or `LastSeen` timestamps moved since the previous sweep.
Only sessions owned by the local node for the ingress zone are sent.

The sweep is deliberately separate from userspace deltas. It is still the only
way the kernel conntrack path exports incremental session creation.

### Delete Journal

Delete messages are queued immediately from conntrack GC callbacks. If the peer
is disconnected, deletes are journaled in a bounded ring.

The journal is replayed when the next first-post-disconnect connection comes up,
before `OnPeerConnected` and before the fresh bulk starts.

## Userspace Session Integration

### Delta Drain

The Go daemon periodically drains helper-originated session deltas via
`DrainSessionDeltas(...)`.

These deltas are **not** blindly mirrored. Current filtering is:

- `local_delivery` is never synced to the peer
- stale-owner `FabricRedirect` deltas from non-fabric ingress are allowed even
  if the local node is no longer owner, because the peer still needs the
  forward-wire alias to receive redirected traffic
- if a delta carries `OwnerRGID`, ownership is checked with `IsPrimaryForRGFn`
- otherwise the fallback is `ShouldSyncZone(ingressZone)`

For stale-owner fabric redirects, the daemon also synthesizes forward-wire alias
session keys on the sync stream so the new owner can materialize the translated
forward tuple it will receive over the fabric.

### Export During Demotion Prep

`ExportOwnerRGSessions(rgIDs, 0)` is used during graceful demotion prep to dump
all userspace sessions owned by the demoting RGs. This is not the same thing as
the steady-state delta drain. It is an explicit republish step used to reduce
handoff loss.

## Clock Synchronization

At connection setup, both sides exchange monotonic timestamps with `ClockSync`.
The receiver computes a local offset and rebases received session timestamps
into the local monotonic clock domain before install.

That keeps session expiry behavior consistent across nodes even though the two
systems have different boot times and independent monotonic clocks.

## Failover Session Handling

### Promotion

When a node becomes primary for an RG:

- synced sessions for newly-owned zones become locally authoritative
- GC delete callbacks become active for those zones
- userspace session state for the newly-owned RG is refreshed or promoted as
  needed for local forwarding
- direct-mode failover also relies on post-transition re-announcements to move
  LAN-side ownership quickly

### Graceful Demotion

Graceful demotion is now an explicit staged protocol, not just "send a barrier
and hope the queue is empty".

Current sequence:

1. Require `syncPeerBulkPrimed` for the current connection
2. Wait for any previous demotion barriers to be acknowledged
3. Repeatedly wait for the sync stream to go idle (`WaitForIdle`) and then send
   a probe barrier (`WaitForPeerBarrier`) until quiescence is proven or the
   timeout expires
4. Pause background incremental sync with `PauseIncrementalSync(...)`
5. Export userspace sessions owned by the demoting RGs
6. Drain recent userspace deltas while incremental sync is paused
7. Send a final ordered barrier and wait for peer acknowledgement
8. Call helper `PrepareRGDemotion(...)`
9. Resume incremental sync

Manual failover uses the same demotion-prep path, but wraps some failures as
retryable admission errors instead of proceeding unsafely.

## Invariants

1. Only forward entries are sent on the wire.
2. Reverse entries are recreated locally by the receiver.
3. Received sessions always have cached FIB resolution cleared before install.
4. Timestamps are rebased into the receiver's monotonic clock domain.
5. Session ownership filtering happens before incremental sync or userspace
   delta replication.
6. `local_delivery` sessions are helper-local and are not valid HA sync state.
7. Graceful demotion is ordered against the session-sync stream with explicit
   quiescence and barriers.

## What Earlier Versions Missed

The previous version of this document was materially incomplete in a few places:

- it treated readiness as "bulk received" and omitted sender-side `BulkAck`
  readiness
- it did not describe the bulk-prime retry loop or pending-bulk-ack tracking
- it simplified userspace delta sync as an unfiltered mirror of helper events
- it did not explain the explicit demotion-prep pause / export / drain /
  barrier protocol
- it implied userspace mirroring happened only through `SetClusterSyncedSession*`
  and omitted the helper-originated delta/export paths

## Known Limitations

### Sweep Latency

Kernel-originated session creation is still exported by periodic sweep, not by a
real-time event stream. Short-lived sessions can be missed between sweeps.

### No Real-Time BPF Session Event Stream

There is still no cheap real-time BPF event feed for full session state. The
current design intentionally uses periodic sweep for kernel sessions and keeps
the lower-latency userspace delta path scoped to the AF_XDP helper.

### Delete Journal Overflow

The delete journal is bounded. Extended disconnects with high churn can evict
old deletes. The next bulk reconciliation eventually cleans this up, but not
immediately.

### Counter Divergence

Counters are not kept perfectly current by incremental sync. Session state is
more important than exact byte/packet counters for failover.

### Failover Quality Still Depends on Dataplane Behavior

Correct session-sync admission does not guarantee zero-loss failover. The recent
userspace failover work showed that post-admission dataplane behavior can still
collapse if redirected traffic, queue selection, or translated alias handling is
wrong.

## Key Files

| File | Purpose |
|------|---------|
| `pkg/cluster/sync.go` | Wire protocol, bulk sync, barriers, retry state |
| `pkg/cluster/sync_test.go` | Session sync protocol tests |
| `pkg/daemon/daemon.go` | Readiness, retry, userspace delta filtering, demotion prep |
| `pkg/conntrack/gc.go` | GC delete callbacks |
| `pkg/dataplane/types.go` | Session key/value definitions |
| `pkg/dataplane/userspace/manager.go` | Userspace session install, helper RPCs |
| `userspace-dp/src/session.rs` | Rust session table |
| `userspace-dp/src/afxdp/session_glue.rs` | Userspace session promotion / refresh / export |
