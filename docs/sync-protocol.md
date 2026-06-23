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
(`QueueSession*`, sweep, bulk) and is recorded per wire key. A delete draws a
**fresh, strictly-greater** generation from the same counter (`takeDeleteGenV4/V6`
→ `nextInstallGen`) rather than echoing the install's stamp, and evicts the
sender record. A delete therefore always out-ranks the install it cancels — the
property that lets the receiver order a reordered delete/install pair (see #2221
below). A key never installed in this boot (no stamp recorded) yields `gen == 0`
(legacy unconditional delete). Generations are only ever compared
per-`(sender,key)` — never across keys — so a single sender-local counter
suffices.

**Semantics (receiver, `pkg/cluster`):** `SessionSync` keeps the authoritative
per-key stored generation in its own map (the BPF C conntrack struct stays
generation-free). The apply layer:

- **Delete guard** (`deleteClusterSynced*`): apply a delete only if its
  generation is **not strictly older** than the stored entry's. `delete < stored`
  with both non-zero → refuse (`DeletesStaleIgnored++`), short-circuiting BOTH
  the BPF map delete and the helper. Equality applies (the delete of the very
  session installed); `gen == 0` on either side falls back to today's
  unconditional delete (rolling-upgrade safe). On an applied **non-zero** delete
  the stored generation is **upgraded to the delete generation as a TOMBSTONE**
  (not evicted), so a reordered older install of the cancelled session is refused
  by the install guard (#2221). A `gen == 0` delete evicts (no tombstone).
- **Install guard** (`installClusterSynced*`): refuse to overwrite a stored
  entry (live OR a delete tombstone) with a strictly-older-generation install
  (`incoming < stored` → `InstallsStaleIgnored++`) so the per-key stored
  generation never regresses (closes the delayed-stale-install variant AND the
  reordered-install-after-delete residual).

The userspace helper mirrors the same field on its in-memory
`SyncedSessionEntry` (via `SessionSyncRequest.generation`) and enforces the
same guard in `upsert_synced_session` / `delete_synced_session_gen` as a
belt-and-suspenders for helper-originated deletes; the Go cluster apply layer is
authoritative. A mixed-version cluster degrades to exact pre-#2170 behavior for
any pair where either end lacks a generation.

### Generation is sync-only — it MUST NOT inflate the BPF map (#2360)

The install `Generation` lives in three places: the in-memory `SessionValue` /
`SessionValueV6` (Go) and `SyncedSessionEntry` (Rust), and the sync wire (the
length-gated trailing 8 bytes above). It is deliberately **absent** from the BPF
C conntrack struct (`struct session_value` / `struct session_value_v6` in
`bpf/headers/xpf_conntrack.h`), so the kernel-visible `sessions` / `sessions_v6`
HASH maps are 128 / 176 bytes per value — the same layout the Rust helper
mirrors as `BpfSessionValueV4` / `BpfSessionValueV6` (size-asserted at
`userspace-dp/src/afxdp/bpf_map_tests.rs`).

Because `SessionValue` carries the extra trailing `Generation uint64`, it is
136 / 184 bytes — 8 bytes larger than the on-map layout. The Go map
registration therefore must use the dedicated on-map ABI types
`bpfSessionValue` / `bpfSessionValueV6` (`pkg/dataplane/bpf_session_value.go`),
which mirror the C struct exactly without `Generation`, and all map I/O
(`SetSessionV4/V6`, `GetSessionV4/V6`, iterate/batch in
`pkg/dataplane/maps_session.go`) projects through `toBPF()` / `sessionValue()`
at the boundary. Registering at `sizeOf[SessionValue]` instead would make the
kernel `value_size` 8 bytes larger than the Rust helper's lookup buffer, so a
`bpf_map_lookup_elem` would copy `value_size` bytes into the smaller buffer — an
8-byte out-of-bounds write (latent because the trailing bytes are usually zero).
The parity guards `TestSessionMapRegisteredAtConntrackABISize` /
`TestBPFSessionValueMatchesConntrackABI` (Go) and the Rust size asserts pin the
128 / 176 contract on both sides. **A new sync-only field must be added to the
sync codec and the in-memory structs — never to the on-map ABI types.**

### Generation-map bounds and overflow (#2198 F1)

Both the sender echo maps (`genSentV4/V6`) and the receiver stored-generation
maps (`recvGenV4/V6`) are bounded by `genGuardMapCap` (200000) so a churning
workload cannot grow them without limit. Sender entries are evicted on the
matching delete. Receiver entries are evicted on a `gen == 0` (legacy) delete
but a non-zero delete **records a tombstone in place** (#2221, see below); the
cap (via `putGenBounded`) plus the bulk-barrier `resetRecvGen` keep the
receiver map bounded under steady churn, and the cap is also the safety valve
for keys whose delete never arrives (e.g. a dropped close delta).

On overflow the map is **never cleared**. A map at cap updates an EXISTING key
in place (its stored generation is never dropped) and **skip-records** a NEW
key, incrementing `GenMapOverflow`. A skipped key degrades to gen-0
(unconditional install / unconditional delete), which is safe: gen-0 never
causes a wrongful delete of a *different* live incarnation — it only forgoes the
stale-delete protection for that one new key. Clearing the whole map would drop
the stored generation of every live key, disabling the guard for a churn window
and re-opening the exact #2170 hazard (a stale delete killing a live
re-established session).

### Cross-boot generation regression and the bulk re-prime reset (#2198 F2)

The sender `genCounter` is seeded from `CLOCK_MONOTONIC` nanos, which is
boot-relative and **resets at OS reboot**. After a reboot this node's counter
can come up LOWER than a generation the peer stored from its previous boot, so a
post-reboot same-5-tuple re-install would carry a lower generation and the
peer's install guard would refuse it as stale (a stale-RETAIN — the inverse of
#2170), and the cold-start bulk re-prime would silently fail to land.

This is handled on the **receiver** side: when a (reconnecting, possibly
rebooted) peer begins its bulk transfer (`syncMsgBulkStart`), the receiver
resets its per-key stored generations (`resetRecvGen`). The bulk re-prime — the
authoritative live set — then lands unconditionally and re-records each key's
fresh generation, so the install guard accepts it. This is safe against opening
a stale-delete window: deletes are only acted on after the bulk completes
(`reconcileStaleSessions` at `BulkEnd`), and the re-prime re-establishes the
live set before any such delete; a delete that arrives mid-bulk for a
not-yet-re-recorded key falls back to gen-0 (unconditional), the legacy-safe
behavior. No persisted cross-boot high-water mark is required.

### Apply-sequence atomicity (#2198 F3)

The receiver apply sequence — install guard check, dataplane `PutClusterSynced`,
`recordInstalledGen` (and the delete path's `deleteGenGuard`) — does not hold
`recvGenMu` across the whole sequence; each helper takes the mutex
independently. This is safe because the receiver apply path for a given peer is
single-threaded: messages are decoded and dispatched serially within one
`receiveLoop` goroutine over the single ACTIVE fabric connection (conn0
preferred; conn1 only when conn0 is down). No two installs/deletes for the same
key are ever applied concurrently, so the per-key stored generation cannot be
interleaved between the guard read and the record write. Holding `recvGenMu`
across the dataplane `Put` would serialize unrelated keys under dataplane I/O
for no benefit the single-active-fabric invariant doesn't already provide.

### Same-generation install/delete reorder (#2221, residual of #2170)

The #2170 guard assumes per-key generations are strictly monotonic so a stale
(older-generation) delete is refused. The **residual** hazard is WITHIN a single
generation domain: the gen-stamp and the `sendCh` enqueue are not atomic, and two
producer goroutines mutate the same key — the 1s sweep re-stamps a LIVE session
to generation `N` and queues an install carrying `N`, while the userspace
delta-drain takes the close and (pre-fix) echoed that same `N` on the delete. The
delete can then win the `sendCh` enqueue race and be sent BEFORE the install. The
receiver applies `delete(N)` then `install(N)`. Because the guards refuse only a
*strictly-older* operation, an equal-`N` install after an equal-`N` delete was
re-applied — the standby resurrected a session the master had already closed
(the stale-RETAIN inverse of #2170, this time triggered by reorder rather than a
journaled replay).

The fix makes convergence **order-independent (last-writer-wins per key)** with
two composed changes:

1. **Sender** — a delete draws a FRESH generation strictly greater than the
   install it cancels (`takeDeleteGenV4/V6` → `nextInstallGen`, see above)
   instead of echoing it. A delete therefore always out-ranks its install.
2. **Receiver** — an applied non-zero delete records the delete generation as a
   **tombstone** in `recvGenV4/V6` (it does not evict). A reordered install of
   the cancelled session carries the OLDER install generation, so the install
   guard (`incoming < stored`) refuses it (`InstallsStaleIgnored++`) and the
   standby stays GONE — matching the master. A genuinely newer incarnation,
   re-established and re-stamped by a later sweep, carries a strictly-greater
   generation than the tombstone and still installs.

Both reorder directions, and the in-order close, converge to the master's final
state: GONE when the master deleted last, PRESENT when a strictly-newer install
arrived last. The tombstone is bounded by `genGuardMapCap` and cleared by the
bulk barrier (`resetRecvGen`), which also handles the cross-boot generation
regression (#2198 F2) so a tombstone never blocks a legitimate cold-start
re-prime. Regression coverage: `TestSameGenReorderDeleteThenInstallConverges{V4,
V6}` (drives the real sender enqueue + receiver apply in wire order),
`TestReorderedInstallRefusedByTombstoneV4`,
`TestReestablishAfterDeleteAppliesV4`, and
`TestDeleteGenerationStrictlyGreaterThanInstall{V4,V6}` in
`pkg/cluster/sync_gen_guard_test.go`.

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
