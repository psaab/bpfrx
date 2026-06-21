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
| 1    | SessionV4        | Primary→Secondary | length-gated        | Create/update IPv4 session |
| 2    | SessionV6        | Primary→Secondary | length-gated        | Create/update IPv6 session |
| 3    | DeleteV4         | Primary→Secondary | 16 or 24 bytes      | Delete IPv4 session |
| 4    | DeleteV6         | Primary→Secondary | 40 or 48 bytes      | Delete IPv6 session |
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

## Install-Generation Guard (#2170)

To stop a deferred/journaled delete from killing a same-5-tuple replacement
session, every **session** and **delete** message carries a length-gated
trailing `Generation uint64` (LE):

- **Session V4/V6**: 8 bytes appended after the existing last field (`FibGen`).
  An old decoder stops after `FibGen` and ignores it (`if off+8 <= len(payload)`
  block in `decodeSession*Payload`); a new decoder reading an old, shorter
  payload sees `Generation == 0`.
- **Delete V4**: 16 → 24 bytes; **Delete V6**: 40 → 48 bytes. The generation is
  the trailing 8 bytes after the 5-tuple block. The handler's `len(payload) >=
  16/40` check already tolerates the longer payload; the generation is read
  only when `len(payload) >= 24/48`.

**Semantics (sender, `pkg/cluster`):** a single process-wide strictly-monotonic
counter (seeded from `CLOCK_MONOTONIC` nanos) stamps every install send
(`QueueSession*`, sweep, bulk) and is recorded per wire key. A delete echoes the
exact generation last stamped for that key and evicts the record, so the
delete's generation is always same-domain as the entry the receiver stored.
Generations are only ever compared per-`(sender,key)` — never across keys — so a
single sender-local counter suffices.

**Semantics (receiver, `pkg/cluster`):** `SessionSync` keeps the authoritative
per-key stored generation in its own map (the BPF C conntrack struct stays
generation-free). The apply layer:

- **Delete guard** (`deleteClusterSynced*`): apply a delete only if its
  generation is **not strictly older** than the stored entry's. `delete < stored`
  with both non-zero → refuse (`DeletesStaleIgnored++`), short-circuiting BOTH
  the BPF map delete and the helper. Equality applies (the delete of the very
  session installed); `gen == 0` on either side falls back to today's
  unconditional delete (rolling-upgrade safe).
- **Install guard** (`installClusterSynced*`): refuse to overwrite a stored
  entry with a strictly-older-generation install (`InstallsStaleIgnored++`) so
  the per-key stored generation never regresses (closes the delayed-stale-install
  variant).

The userspace helper mirrors the same field on its in-memory
`SyncedSessionEntry` (via `SessionSyncRequest.generation`) and enforces the
same guard in `upsert_synced_session` / `delete_synced_session_gen` as a
belt-and-suspenders for helper-originated deletes; the Go cluster apply layer is
authoritative. A mixed-version cluster degrades to exact pre-#2170 behavior for
any pair where either end lacks a generation.

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
| SessionV4/V6 | Decode → install forward → create reverse → create dnat_table (SNAT) |
| DeleteV4/V6 | Lookup → delete reverse → delete dnat_table (SNAT) → delete forward |
| BulkStart/End | Log markers; BulkEnd triggers `OnBulkSyncReceived` (releases VRRP sync hold) |
| Heartbeat | No-op (resets read deadline) |
| Config | `OnConfigReceived` callback (runs in goroutine) |
| IPsecSA | Store names, call `OnIPsecSAReceived` |

### Session Reconstruction on Receiver

Forward-only sweep entries are reconstructed into full conntrack state:
1. **Forward entry:** Install as-is via `SetSessionV4/V6(key, val)`
2. **Reverse entry:** If `IsReverse==0 && ReverseKey.Protocol != 0`: copy val, set `IsReverse=1`, set `ReverseKey = original key`, install at `val.ReverseKey`
3. **dnat_table (SNAT only):** If `Flags & SessFlagSNAT && !(Flags & SessFlagStaticNAT)`: create `{Protocol, NATSrcIP, NATSrcPort} → {SrcIP, SrcPort}`

### FIB Cache (Not Synced — By Design)
- `fib_ifindex`, `fib_dmac`, `fib_smac`, `fib_gen` are zeroed in synced sessions
- Interface indices and MACs differ between nodes; zero forces fresh `bpf_fib_lookup`
- **Userspace-dataplane exception (#1873):** when
  `LogFlagUserspaceTunnelEndpoint` is set, `fib_gen` carries the
  session's `tunnel_endpoint_id` across the cluster as a bare LE u16.
  Ids are content-derived (`config.StableTunnelEndpointID` — a frozen
  FNV-1a fold of the unit-qualified tunnel interface name), so both
  nodes compute identical ids from identical config and the value is
  portable by construction. The receiving node resolves it against its
  own snapshot (`sessionSyncTunnelEndpointLocked`); an unknown id
  degrades that synced session to NoRoute until configs converge.

### Known Issues
- **NO_NEIGH after failover (FIXED, `0080cbc`):** Cold ARP cache on takeover previously caused `bpf_fib_lookup` rc=7 and mis-forward behavior. This was fixed in HA sync hardening.
- **Monotonic clock skew (FIXED, `0080cbc`):** Remote timestamps in synced sessions previously caused premature GC expiry; this was fixed in receiver-side handling.

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
