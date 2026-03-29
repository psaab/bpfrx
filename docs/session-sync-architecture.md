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

When a management VRF (`vrf-mgmt`) is configured, sockets are bound to it with
`SO_BINDTODEVICE`; otherwise they use the default routing table. One
deterministic side initiates per fabric. `TCP_NODELAY` is enabled.

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

### Event Stream (Primary Path)

The Rust helper pushes session events over a persistent binary-framed Unix
socket (`/run/bpfrx/userspace-dp-events.sock`). Events (SessionOpen,
SessionClose, SessionUpdate) carry sequence numbers for reliable delivery.
The daemon reads events, applies ownership filtering, and queues them to the
peer sync stream. Ack frames flow back for replay buffer management. Pause,
Resume, and DrainRequest frames support demotion-prep integration.

When the event stream is disconnected (helper restart, startup race), the
daemon automatically falls back to RPC polling.

### Delta Drain (Fallback Path)

The Go daemon can poll helper-originated session deltas via
`DrainSessionDeltas(...)` as a fallback when the event stream is unavailable.

These deltas are **not** blindly mirrored. Filtering in
`shouldSyncUserspaceDelta()`:

- `local_delivery` disposition is never synced to the peer
- `FabricRedirect` with `!FabricIngress`: always synced even if the local node
  is no longer owner, because the peer needs the forward-wire alias to receive
  redirected traffic. The daemon also synthesizes forward-wire alias session
  keys via `userspaceForwardWireAliasFromDeltaV4/V6` so the new owner can
  materialize the translated forward tuple it will receive over the fabric.
- if the delta carries `OwnerRGID`, ownership is checked with `IsPrimaryForRGFn`
- otherwise the fallback is `ShouldSyncZone(ingressZone)`

The filtering fields on `SessionDeltaInfo` are `FabricRedirect` and
`FabricIngress` (boolean flags), not a single combined field.

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

Current sequence (`prepareUserspaceRGDemotionWithTimeout()`):

1. Acquire demotion prep gate (`acquireUserspaceRGDemotionPrep`) — prevents
   duplicate concurrent preps for the same RG. On failure, the gate is released
   via `releaseUserspaceRGDemotionPrep` so retries are not blocked.
2. Require `syncPeerBulkPrimed` for the current connection
3. Wait for any previous demotion barriers to be acknowledged
   (`WaitForPeerBarriersDrained`)
4. Repeatedly wait for the sync stream to go idle (`WaitForIdle`) and then send
   a probe barrier (`WaitForPeerBarrier`) until quiescence is proven or the
   timeout expires
5. Pause background incremental sweep with `PauseIncrementalSync(...)` — this
   is a depth-counted pause that only stops the periodic sweep goroutine. GC
   delete callbacks continue to run and queue delete messages normally.
6. Export userspace sessions owned by the demoting RGs
   (`ExportOwnerRGSessions`)
7. Drain recent userspace deltas while sweep is paused
8. Send a final ordered barrier and wait for peer acknowledgement
9. Call helper `PrepareRGDemotion(...)` which marks demoted sessions as synced
   in the shared session maps
10. Resume incremental sync

Manual failover uses the same demotion-prep path via
`prepareUserspaceManualFailover()`, but wraps failures as
`RetryablePreFailoverError` for transient conditions (previous barrier pending,
peer not quiescent, barrier ack timeout). The cluster state machine can retry
admission on retryable errors instead of proceeding unsafely.

## Implementation Details

### Incremental Sync Pause/Resume

`PauseIncrementalSync(reason)` / `ResumeIncrementalSync(reason)` provide a
depth-counted pause mechanism. Multiple callers can pause independently; the
sweep only resumes when all callers have resumed. This is used during demotion
prep to stop the sweep without affecting GC delete callbacks or explicit sync
producers.

### Bulk-Prime Retry Loop

After reconnect, `startSessionSyncPrimeRetry()` retries `BulkSync()` at
increasing intervals (10s, 20s, 40s) if the peer never acknowledges our
bulk with `BulkAck`. Retries are deferred while:

- a pending bulk ack is still young (< 35s since BulkEnd was sent)
- inbound sync progress is still advancing (`syncPrimeProgressObserved`)
- the connection was replaced or disconnected

Retries stop once `syncPeerBulkPrimed` becomes true.

### Readiness Timeout Generation Guard

`armSyncReadyTimer()` captures a generation counter when the timer is armed.
The timeout callback checks that the generation is still current AND the sync
transport is still connected before releasing readiness. `stopSyncReadyTimer()`
increments the generation, invalidating any in-flight callback. This prevents
a stale timer from flipping readiness back to true after a disconnect in a
tight race.

### Barrier Ordering

`WaitForPeerBarrier()` enqueues the barrier message onto `sendCh` (the same
buffered channel used by `sendLoop` for all sync messages) rather than writing
directly to the socket. This preserves strict FIFO ordering — the barrier
cannot overtake messages that `sendLoop` has dequeued but not yet written.

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

## Revision History

This document has been corrected through multiple passes:

- v1: Basic bulk + sweep description. Missing sender-side ack tracking,
  demotion protocol, userspace delta filtering.
- v2 (PR #264): Added two-readiness-signal model, bulk-prime retry loop,
  explicit demotion-prep sequence, userspace delta filtering details.
- v3 (current): Corrected delta filtering field names (`FabricRedirect` +
  `FabricIngress`, not a combined field). Clarified that `PauseIncrementalSync`
  only pauses the sweep — GC delete callbacks are never suppressed. Added
  manual failover retry admission logic, depth-counted pause mechanism,
  readiness generation guard, barrier ordering via sendCh.

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
