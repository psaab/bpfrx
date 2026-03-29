# Session Sync Architecture

## Overview

bpfrx HA clusters synchronize stateful firewall sessions between two nodes so that on failover, the new primary can continue forwarding established flows without requiring TCP re-establishment. Sessions are synced over TCP on the fabric link (fab0/fab1 IPVLAN overlays) using a custom binary protocol.

Three sync mechanisms operate concurrently:

1. **Bulk sync** — cold transfer of the entire session table on startup/reconnect
2. **Incremental sweep** — periodic scan for new/changed sessions during steady state
3. **Userspace deltas** — low-latency session event drain from the Rust AF_XDP helper

## Session Representation

### BPF Maps

Sessions live in two BPF hash maps:

- `sessions_v4` — IPv4 sessions (key: 16 bytes, value: 160+ bytes)
- `sessions_v6` — IPv6 sessions (key: 40 bytes, value: 256+ bytes)

Each logical session has **two entries**: a forward entry (`IsReverse=0`) and a reverse entry (`IsReverse=1`). The forward entry uses the original 5-tuple as its key; the reverse entry uses the swapped (reply-direction) 5-tuple with swapped zones. The forward entry stores a `ReverseKey` field that points to its paired reverse entry.

### Session Key (IPv4, 16 bytes)

```
SrcIP [4]byte, DstIP [4]byte, SrcPort uint16, DstPort uint16, Protocol uint8, Pad [3]byte
```

### Session Value (160+ bytes)

State, Flags, TCPState, IsReverse, SessionID, Created/LastSeen timestamps (monotonic), Timeout, PolicyID, IngressZone, EgressZone, NAT fields (SrcIP/DstIP/SrcPort/DstPort), packet/byte counters, ReverseKey, ALG/Log/App metadata, and a FIB cache (Ifindex, VlanID, Dmac, Smac, Generation).

### Userspace Mirror

When the userspace dataplane is active, sessions are also mirrored to the Rust AF_XDP helper's in-process `SessionTable`. The Go daemon calls `SetClusterSyncedSessionV4()` which writes to both the BPF map and the userspace helper via a Unix socket RPC.

## Wire Protocol

### Transport

TCP on the fabric link. Each node has one or two fabric interfaces:

- **fab0** (primary fabric) — IPVLAN L2 overlay on ge-X-0-0
- **fab1** (secondary fabric, optional) — IPVLAN L2 overlay on ge-X-0-0

Sockets are bound to `vrf-mgmt` via `SO_BINDTODEVICE`. One deterministic TCP initiator per fabric (lower IP address initiates). `TCP_NODELAY` is enabled for latency.

### Header (12 bytes)

```
[0:4]   Magic "BPSY"
[4]     Type (uint8)
[5:8]   Reserved
[8:12]  Payload length (uint32, little-endian)
```

### Message Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| 1 | SessionV4 | Primary → Secondary | Incremental IPv4 session add/update |
| 2 | SessionV6 | Primary → Secondary | Incremental IPv6 session add/update |
| 3 | DeleteV4 | Primary → Secondary | IPv4 session deletion |
| 4 | DeleteV6 | Primary → Secondary | IPv6 session deletion |
| 5 | BulkStart | Primary → Secondary | Marks start of bulk transfer (carries epoch) |
| 6 | BulkEnd | Primary → Secondary | Marks end of bulk transfer (carries epoch) |
| 7 | Heartbeat | Bidirectional | Keepalive |
| 8 | Config | Primary → Secondary | Full configuration text |
| 9 | IPsecSA | Primary → Secondary | IPsec connection names |
| 10 | Failover | Bidirectional | Remote failover request |
| 11 | Fence | Bidirectional | Peer fencing (disable all RGs) |
| 12 | ClockSync | Bidirectional | Monotonic clock exchange |
| 13 | Barrier | Primary → Secondary | Ordered sync marker (for demotion handoff) |
| 14 | BarrierAck | Secondary → Primary | Barrier acknowledgement |
| 15 | BulkAck | Secondary → Primary | Bulk transfer acknowledgement (carries epoch) |

### Session Encoding

IPv4 sessions are serialized as 176 bytes (16 key + 160 value), IPv6 as ~512 bytes. All multi-byte fields are little-endian.

## Bulk Sync (Cold Transfer)

### When It Triggers

- First connection after a total disconnect (both fab0 and fab1 were down)
- New active fabric transport connected

### Send Side (`BulkSync()`)

1. Assign a monotonically increasing epoch number
2. Send `BulkStart` marker with epoch
3. Iterate all sessions in `sessions_v4` and `sessions_v6`:
   - Skip reverse entries (`IsReverse != 0`)
   - Skip sessions where this node is NOT primary for the ingress zone (`ShouldSyncZone()`)
   - Encode and send each forward entry
4. Send `BulkEnd` marker with matching epoch
5. Track epoch as pending, await `BulkAck` from peer

Only forward entries are sent. The receiver creates reverse entries locally.

### Receive Side

**On BulkStart**: Snapshot zone ownership (which zones this node is primary for), initialize tracking maps for received sessions, set `bulkInProgress = true`.

**Per session message**:

1. Decode payload into session key/value
2. Track received key in `bulkRecvV4`/`bulkRecvV6` map
3. Rebase timestamps to local monotonic clock domain
4. **Clear FIB cache** — forces fresh `bpf_fib_lookup` on next packet (node-local forwarding paths differ)
5. Install forward entry in BPF map via `SetClusterSyncedSessionV4()`
6. Create and install reverse entry (copy forward, set `IsReverse=1`, swap zones)
7. Create `dnat_table` entry for SNAT sessions (maps `(Protocol, NATSrcIP, NATSrcPort)` → `(OrigSrcIP, OrigSrcPort)`)

**On BulkEnd**: Verify epoch, run stale session reconciliation, send `BulkAck`, trigger `OnBulkSyncReceived()` callback (releases VRRP sync hold on the secondary).

### Stale Session Reconciliation

After bulk transfer, the receiver deletes local sessions in peer-owned zones that were NOT refreshed during the bulk:

1. Use the frozen zone ownership snapshot from BulkStart time
2. Iterate all local forward sessions
3. For each session in a peer-owned zone: if the session key was NOT in the bulk receive set, delete it (forward + reverse + dnat_table)
4. Zones missing from the snapshot are conservatively kept (not deleted)

This prevents stale sessions from a previous primary from lingering on the new secondary.

## Incremental Sweep (Steady State)

### Background Sweep

A background goroutine runs at configurable intervals:

- **Active interval**: 1s (default), 15s (userspace DP override)
- **Idle interval**: 10s (default), 60s (userspace DP override)

Each sweep:

1. Check if any sessions were created or closed since last sweep (compare global counters)
2. If no changes, skip the scan entirely (fast path)
3. Iterate session maps for entries where `Created >= lastSweepTime` or `LastSeen >= lastSweepTime`
4. For each qualifying forward entry in a locally-primary zone, encode and queue via buffered channel
5. If the send channel (4096 entries) is full, set a backfill flag to replay the window on next sweep

### GC Delete Callbacks

When the conntrack garbage collector expires a session, it invokes a callback:

```go
gc.OnDeleteV4 = func(key dataplane.SessionKey) {
    if d.cluster != nil && d.cluster.IsLocalPrimaryAny() && d.sessionSync != nil {
        d.sessionSync.QueueDeleteV4(key)
    }
}
```

Delete messages are queued immediately. If the peer is disconnected, deletes go into a ring journal (10,000 entries, oldest evicted on overflow). On reconnect, the journal is replayed before normal sync resumes.

### Send Queue

All incremental messages (session adds, deletes) are enqueued onto a buffered channel (4096 entries). A dedicated `sendLoop` goroutine drains the channel and writes to the TCP connection under `writeMu` serialization.

## Userspace Session Deltas

When the userspace AF_XDP dataplane is active, sessions are managed by the Rust helper in addition to BPF maps. The helper maintains its own `SessionTable` and produces session events (opens/closes) as deltas.

### Delta Drain

The Go daemon periodically calls `DrainSessionDeltas(max)` via Unix socket RPC to the Rust helper. This returns a batch of recent session events:

```go
type SessionDeltaInfo struct {
    Kind       string  // "open" or "close"
    Protocol   uint8
    SrcIP      string
    DstIP      string
    SrcPort    uint16
    DstPort    uint16
    // ... NAT, zone, resolution fields
    FabricRedirect bool
}
```

These deltas are forwarded to the peer via the same sync TCP stream.

### Failover Export

During demotion prep, `ExportOwnerRGSessions(rgIDs, max)` dumps all sessions owned by the demoting RGs. This allows the new primary to have complete session state before promotion, reducing the window where synced sessions might be stale.

## Clock Synchronization

At connection setup, both nodes exchange monotonic timestamps via `ClockSync` messages:

```
Peer sends: its monotonic seconds
Local computes: offset = local_mono - peer_mono
```

All received session timestamps (Created, LastSeen) are rebased: `local_ts = peer_ts + offset`. This ensures GC timeouts work correctly — a session created 30s ago on the peer should still have 30s of life remaining locally, regardless of when each node booted.

## Failover Session Handling

### On Promotion (Secondary → Primary)

1. Zone ownership flips — zones previously synced to this node are now locally authoritative
2. GC delete callbacks activate (`IsLocalPrimaryAny()` now returns true)
3. Userspace exports all sessions in newly-owned RGs for sync to peer
4. Synced sessions get their egress resolution refreshed (`refresh_live_reverse_sessions_for_owner_rgs`) since forwarding paths may differ

### On Demotion (Primary → Secondary)

Staged handoff with barrier:

1. **Pause** incremental sync (stop background sweeps)
2. **Wait for quiescence** — ensure no active sync traffic in flight
3. **Drain** remaining userspace session deltas
4. **Barrier** — send ordered marker to peer, wait for acknowledgement
5. **Resume** incremental sync after demotion complete

The barrier ensures the peer has processed all session updates before the demotion takes effect. Without this, the new primary could miss sessions that were in the send queue at demotion time.

## Invariants

1. **Forward entries only on wire** — only `IsReverse=0` sessions are synced. Reverse entries are created by the receiver.
2. **Zone ownership filtering** — sessions are only synced by the node that is primary for the session's ingress zone.
3. **FIB cache invalidation** — always cleared on reception. Each node has different interfaces, MACs, and ARP tables.
4. **Clock domain translation** — all timestamps rebased to local monotonic clock for correct GC behavior.
5. **Dual-entry deletion** — when deleting a synced session, both forward and reverse entries are removed, plus any dnat_table entry.

## Known Limitations

### Sweep Latency

The sweep-based incremental sync has inherent latency — up to 1s between session creation in BPF and sync to the peer. Short-lived sessions (DNS queries, ICMP pings) may complete and be GC'd before the sweep picks them up. The userspace delta path is lower latency (drained on demand via RPC) but only covers the userspace dataplane, not the eBPF conntrack.

### No Real-Time Session Event Stream from BPF

BPF has no efficient mechanism to notify userspace of individual session creates in real time. The BPF ring buffer is used for logging events but not for session sync — the overhead of copying full session values through the ring buffer at high session rates would be prohibitive. The sweep approach trades latency for throughput.

### Delete Journal Overflow

The delete journal is bounded at 10,000 entries. During extended disconnects with high session churn, deletes can be lost. The next bulk sync reconciliation will clean up stale sessions, but there's a window where the peer retains expired sessions.

### Counter Divergence

Packet/byte counters are synced during bulk but not during incremental updates (only timestamps and state are meaningful for failover). After failover, counter values reflect the primary's last bulk, not real-time counts.

## Key Files

| File | Purpose |
|------|---------|
| `pkg/cluster/sync.go` | Session sync protocol, bulk/incremental/barrier, wire encoding |
| `pkg/cluster/sync_test.go` | Sync protocol tests |
| `pkg/daemon/daemon.go` | Daemon integration: GC callbacks, sweep startup, sync readiness |
| `pkg/conntrack/gc.go` | Session garbage collection with delete callbacks |
| `pkg/dataplane/types.go` | SessionKey, SessionValue, BPF map structures |
| `pkg/dataplane/userspace/manager.go` | Userspace DP session mirror, delta drain, export |
| `userspace-dp/src/session.rs` | Rust session table |
| `userspace-dp/src/afxdp/session_glue.rs` | Rust session install/demotion/refresh |
