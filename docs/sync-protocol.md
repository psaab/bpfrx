# Cluster Session Sync Protocol (RTO)

Reference for `pkg/cluster/sync.go` and `pkg/conntrack/gc.go`.

## Transport

- **Protocol:** TCP on port 4785 over the fabric link
- **Addressing:** `localAddr` = `:4785`, `peerAddr` = `<fabric-peer-ip>:4785`
- **Dual connection model:** Both nodes run accept + connect loops simultaneously
  - `acceptLoop`: Listens for incoming peer connections
  - `connectLoop`: Retries outbound connection every 5s (3s dial timeout) when disconnected
  - Whichever connects first wins; new connection replaces any existing one
- **Keepalive:** 30s read deadline; on timeout, sends `syncMsgHeartbeat` and continues
- **Send channel:** Buffered `chan []byte` (4096 entries), non-blocking send; overflow increments `Errors` counter and drops the message
- **Payload limit:** 16MB maximum per message (for config sync)
- **Disconnect handling:** Any I/O error closes the connection and sets `Connected = false`

## Wire Format

Every message is a 12-byte header followed by a variable-length payload:

```
Offset  Size  Field      Description
0       4     Magic      "BPSY" (0x42, 0x50, 0x53, 0x59)
4       1     Type       Message type (1-9)
5       3     Pad        Reserved, zero
8       4     Length     Payload length in bytes (little-endian uint32)
12      N     Payload    Type-specific data
```

All multi-byte integers in the wire format are **little-endian**, matching the native byte order of x86 systems and BPF maps.

## Message Types

| Type | Name             | Direction        | Payload Size        | Purpose |
|------|------------------|------------------|---------------------|---------|
| 1    | SessionV4        | Primary→Secondary | 120 bytes           | Create/update IPv4 session |
| 2    | SessionV6        | Primary→Secondary | ~196 bytes          | Create/update IPv6 session |
| 3    | DeleteV4         | Primary→Secondary | 16 bytes            | Delete IPv4 session |
| 4    | DeleteV6         | Primary→Secondary | 40 bytes            | Delete IPv6 session |
| 5    | BulkStart        | Primary→Secondary | 0                   | Marks start of bulk transfer |
| 6    | BulkEnd          | Primary→Secondary | 0                   | Marks end of bulk transfer |
| 7    | Heartbeat        | Bidirectional     | 0                   | Keepalive (sent on 30s idle) |
| 8    | Config           | Primary→Secondary | Variable (UTF-8)    | Full config text |
| 9    | IPsecSA          | Primary→Secondary | Variable (UTF-8)    | Newline-separated connection names |

## Session V4 Payload Layout (120 bytes)

```
Offset  Size  Field
── Key (16 bytes) ──────────────────────
0       4     SrcIP           [4]byte (network order)
4       4     DstIP           [4]byte (network order)
8       2     SrcPort         uint16 LE
10      2     DstPort         uint16 LE
12      1     Protocol        uint8
13      3     Pad             -
── Value (104 bytes) ───────────────────
16      1     State           uint8 (0=new, 1=established, 2=closing)
17      1     Flags           uint8 (SNAT/DNAT/StaticNAT bits)
18      1     TCPState        uint8
19      1     IsReverse       uint8 (always 0 for synced entries)
20      4     Pad0            -
24      8     Created         uint64 LE (monotonic seconds)
32      8     LastSeen        uint64 LE (monotonic seconds)
40      4     Timeout         uint32 LE (seconds)
44      4     PolicyID        uint32 LE
48      2     IngressZone     uint16 LE
50      2     EgressZone      uint16 LE
52      4     NATSrcIP        uint32 LE (NativeEndian IP bytes)
56      4     NATDstIP        uint32 LE
60      2     NATSrcPort      uint16 LE
62      2     NATDstPort      uint16 LE
64      8     FwdPackets      uint64 LE
72      8     FwdBytes        uint64 LE
80      8     RevPackets      uint64 LE
88      8     RevBytes        uint64 LE
── Reverse Key (16 bytes) ──────────────
96      4     RevSrcIP        [4]byte
100     4     RevDstIP        [4]byte
104     2     RevSrcPort      uint16 LE
106     2     RevDstPort      uint16 LE
108     1     RevProtocol     uint8
109     3     Pad             -
── Trailer (8 bytes) ───────────────────
112     1     ALGType         uint8
113     1     LogFlags        uint8
114     2     Pad1            -
116     4     (unused)        -
```

## Session V6 Payload Layout (~196 bytes)

Same structure as V4 but with 16-byte IPs:

```
── Key (40 bytes): SrcIP[16] + DstIP[16] + SrcPort[2] + DstPort[2] + Protocol[1] + Pad[3]
── Value: Same fields as V4, except NATSrcIP/NATDstIP are [16]byte and ReverseKey uses 16-byte IPs
```

## Delete V4 Payload (16 bytes)

```
Offset  Size  Field
0       4     SrcIP         [4]byte
4       4     DstIP         [4]byte
8       2     SrcPort       uint16 LE
10      2     DstPort       uint16 LE
12      1     Protocol      uint8
13      3     (implicit)    -
```

## Delete V6 Payload (40 bytes)

```
Offset  Size  Field
0       16    SrcIP         [16]byte
16      16    DstIP         [16]byte
32      2     SrcPort       uint16 LE
34      2     DstPort       uint16 LE
36      1     Protocol      uint8
37      3     (implicit)    -
```

## Config Payload (Variable)

Raw UTF-8 text of the full Junos-format configuration. Sent as-is after `commitConfig()` on the primary. The secondary's `OnConfigReceived` callback invokes `load override` + commit to apply it.

## IPsec SA Payload (Variable)

Newline-separated (`\n`) list of strongSwan connection names (e.g., `vpn-gw1\nvpn-gw2`). On failover, the new primary calls `swanctl --initiate` for each name.

## Sync Algorithms

### 1. Initial Bulk Sync (on TCP connect)

Triggered once when the `connectLoop` successfully dials the peer:

```
connectLoop() establishes TCP connection
  → BulkSync()
    → writeMsg(BulkStart, nil)           // signal start
    → IterateSessions(all v4)            // send every v4 session as SessionV4
    → IterateSessionsV6(all v6)          // send every v6 session as SessionV6
    → writeMsg(BulkEnd, nil)             // signal complete
```

Both forward and reverse entries are sent during bulk sync. The receiver calls `SetSessionV4/V6` to install each session directly into the BPF map.

### 2. Periodic Sync Sweep (1s interval, new sessions)

`StartSyncSweep()` launches a goroutine with a 1-second ticker:

```
syncSweep():
  if !IsPrimaryFn() → skip
  if !Connected     → skip
  threshold = lastSweepTime
  now = CLOCK_MONOTONIC seconds

  for each v4 session where IsReverse==0 && Created >= threshold:
    QueueSessionV4(key, val) → sendCh

  for each v6 session where IsReverse==0 && Created >= threshold:
    QueueSessionV6(key, val) → sendCh

  lastSweepTime = now
```

Key properties:
- **Forward-only:** Only sends IsReverse==0 entries; the receiver creates both forward and reverse via `SetSessionV4/V6`
- **Monotonic clock:** `Created` timestamps come from `bpf_ktime_get_ns()/1e9`, which matches `CLOCK_MONOTONIC`
- **Non-blocking send:** Messages dropped silently if sendCh is full (4096 buffer)
- **Primary-only:** Skips when not primary for redundancy group 0

### 3. GC Delete Callbacks (expired session cleanup)

Wired in `daemon.go` after GC creation:

```
gc.OnDeleteV4 = func(key SessionKey) {
    if isPrimary && sessionSync != nil {
        sessionSync.QueueDeleteV4(key)
    }
}
```

The conntrack GC (`sweep()` in gc.go) runs every 10 seconds:
1. Iterates all sessions, checks `LastSeen + Timeout < now`
2. Builds `toDelete` slice as pairs: `[fwd, rev, fwd, rev, ...]`
3. After each successful `DeleteSession(key)`, fires callback for forward entries only (`i%2 == 0`)
4. The callback queues a DeleteV4/V6 message to the peer

The peer receives the delete and calls `DeleteSession(key)` to remove the forward entry from its BPF map. The peer's own GC handles cleaning up any orphaned reverse entries.

### 4. Ring Buffer Callback (near-real-time, <1ms)

Registered on the BPF ring buffer event reader in `daemon.go`:

```
er.AddCallback(func(rec EventRecord, raw []byte) {
    if rec.Type != "SESSION_OPEN" → skip
    if !isPrimary || !isConnected → skip

    Parse 5-tuple from raw event bytes:
      v4: SrcIP raw[8:12], DstIP raw[24:28]
      v6: SrcIP raw[8:24], DstIP raw[24:40]
      Ports raw[40:44] (BigEndian), Protocol raw[53], AF raw[55]

    Lookup full session from BPF map via GetSessionV4/V6(key)
    If found and IsReverse==0:
      QueueSessionV4/V6(key, val) → sendCh
})
```

This is **additive** to the periodic sweep — it provides sub-millisecond sync for logged sessions. Sessions that don't generate ring buffer events are caught by the 1s sweep.

## Receiver-Side Processing

`handleMessage()` dispatches by type:

| Type | Action |
|------|--------|
| SessionV4/V6 | `decodeSessionPayload()` → `dp.SetSessionV4/V6()` → installs in BPF map |
| DeleteV4/V6 | Parse 5-tuple from payload → `dp.DeleteSession/V6()` → removes from BPF map |
| BulkStart/End | Log markers only |
| Heartbeat | No-op (resets read deadline) |
| Config | `OnConfigReceived` callback (runs in goroutine) |
| IPsecSA | Store names, call `OnIPsecSAReceived` |

## Statistics (SyncStats)

All counters are `atomic.Uint64` / `atomic.Bool`, lock-free:

| Counter | Meaning |
|---------|---------|
| SessionsSent | Sessions queued to sendCh |
| SessionsReceived | Session messages received from peer |
| SessionsInstalled | Sessions successfully written to BPF map |
| DeletesSent | Delete messages queued |
| DeletesReceived | Delete messages received |
| BulkSyncs | Completed bulk sync operations |
| ConfigsSent/Received | Config sync messages |
| IPsecSASent/Received | IPsec SA list messages |
| Errors | Send failures, channel overflows, bad magic |
| Connected | Peer TCP connection active |

## Timing Summary

| Event | Interval | Latency |
|-------|----------|---------|
| Bulk sync | Once on connect | Seconds (depends on table size) |
| Periodic sweep | 1 second | 0-1s for new sessions |
| Ring buffer callback | Per SESSION_OPEN event | <1ms |
| GC delete propagation | 10 second GC interval | 0-10s |
| Heartbeat | 30s idle timeout | - |
| Connect retry | 5 seconds | - |

## Data Flow Diagram

```
Primary Node                              Secondary Node
─────────────                             ──────────────
BPF creates session
  │
  ├─ Ring buffer event ──→ Callback ─┐
  │                                  │
  ├─ 1s sweep ticker ──→ syncSweep ──┤
  │                                  ├──→ sendCh ──→ TCP ──→ receiveLoop
  │                                  │                         │
  │  GC expires session              │                    handleMessage
  │    │                             │                         │
  │    └── OnDeleteV4/V6 ───────────┘                    SetSessionV4/V6
  │                                                      DeleteSession
  │                                                           │
  │                                                      BPF map updated
```
