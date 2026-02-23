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
| SessionV4/V6 | `decodeSessionPayload()` → install forward entry → create reverse entry → create dnat_table entry (SNAT) |
| DeleteV4/V6 | Parse 5-tuple → lookup session → delete reverse entry → delete dnat_table entry (SNAT) → delete forward entry |
| BulkStart/End | Log markers; BulkEnd triggers `OnBulkSyncReceived` callback (releases VRRP sync hold) |
| Heartbeat | No-op (resets read deadline) |
| Config | `OnConfigReceived` callback (runs in goroutine) |
| IPsecSA | Store names, call `OnIPsecSAReceived` |

### Receiver-Side Session Reconstruction

The periodic sweep sends **forward-only** entries (IsReverse==0). The receiver must reconstruct the full conntrack state from each forward entry:

1. **Install forward entry:** `SetSessionV4/V6(key, val)` writes the forward session to the BPF map.

2. **Create reverse entry:** If `val.IsReverse == 0 && val.ReverseKey.Protocol != 0`:
   - Copy forward value → set `IsReverse = 1` → set `ReverseKey = original key`
   - Install via `SetSessionV4/V6(val.ReverseKey, revVal)`
   - Without this, return traffic finds no conntrack match → goes to policy as new connection → dropped

3. **Create dnat_table entry (SNAT only):** If the forward session has `SNAT` flag set (and NOT `StaticNAT`):
   - Build `DNATKey{Protocol, DstIP=val.NATSrcIP, DstPort=val.NATSrcPort}`
   - Build `DNATValue{NewDstIP=key.SrcIP, NewDstPort=key.SrcPort}`
   - Install via `SetDNATEntry(dnatKey, dnatVal)`
   - `xdp_zone` uses dnat_table to rewrite dst IP back to the real client before conntrack lookup on return traffic
   - Without this, return traffic uses the SNAT'd dst IP for conntrack lookup → miss → RST or drop

For **delete messages**, the receiver performs cleanup in reverse order:
1. Look up the forward session to get the ReverseKey and NAT fields
2. Delete the reverse entry (`DeleteSession(val.ReverseKey)`)
3. Delete the dnat_table entry (SNAT sessions only)
4. Delete the forward entry

### FIB Cache (Not Synced — By Design)

Session FIB cache fields (`fib_ifindex`, `fib_dmac`, `fib_smac`, `fib_gen`) are **zeroed** in synced sessions. This is correct behavior:
- Interface indices differ between cluster nodes (enp6s0 may be ifindex 3 on node0 but 5 on node1)
- MAC addresses differ between nodes
- Zero `fib_ifindex` forces a fresh `bpf_fib_lookup` on the first packet, populating the local FIB cache

### Data Dependencies by Session Type

| Session Type | Forward Entry | Reverse Entry | dnat_table Entry | Notes |
|-------------|:---:|:---:|:---:|-------|
| Plain (no NAT) | Yes | Yes | No | Return traffic matches reverse entry directly |
| SNAT (interface/pool) | Yes | Yes | Yes | Return traffic needs dnat_table for pre-routing dst rewrite |
| DNAT | Yes | Yes | No | DNAT rules exist in config; dnat_table populated from config, not sessions |
| Static NAT (1:1) | Yes | Yes | No | Static NAT entries exist in config; bidirectional mapping from config |
| NAT64 | Yes | Yes | No | NAT64 translation handled by xdp_nat64 program |

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
  │    └── OnDeleteV4/V6 ───────────┘                         │
  │                                                     ┌─────┴──────┐
  │                                                     │ SessionV4/V6│
  │                                                     ├────────────┤
  │                                                     │ 1. Install  │
  │                                                     │    forward  │
  │                                                     │ 2. Create   │
  │                                                     │    reverse  │
  │                                                     │ 3. Create   │
  │                                                     │    dnat_tbl │
  │                                                     │    (SNAT)   │
  │                                                     └─────┬──────┘
  │                                                           │
  │                                                      BPF map updated
```

## Known Issues and Fixes

### FIXED: Forward-only session sync (missing reverse entries)

**Symptom:** After VRRP failover, return traffic on the takeover node had no conntrack match. Packets went through policy evaluation as new connections and were dropped (deny-by-default) or created conflicting sessions.

**Root cause:** The periodic sync sweep sent only forward entries (`IsReverse==0`), but `handleMessage()` installed them directly without creating the corresponding reverse entry. Only bulk sync sent both forward and reverse entries.

**Fix:** `handleMessage()` now creates a reverse entry from each forward entry: copies the forward value, sets `IsReverse=1`, sets `ReverseKey = original forward key`, and installs via `SetSessionV4/V6(val.ReverseKey, revVal)`.

### FIXED: Missing dnat_table entries for SNAT sessions

**Symptom:** After failover, SNAT return traffic (server→firewall) was not being de-NAT'd correctly. The takeover node's `xdp_zone` couldn't find the dnat_table entry needed to rewrite the dst IP back to the original client. Conntrack lookup used the wrong (SNAT'd) dst IP → miss → new connection → kernel RST.

**Root cause:** SNAT sessions need dnat_table entries on the takeover node for pre-routing dst rewrite. The sync protocol only sent session entries; dnat_table entries (which are derived from sessions, not config) were never synced.

**Fix:** `handleMessage()` now creates a dnat_table entry for each forward SNAT session (Flags has `SessFlagSNAT` set, `SessFlagStaticNAT` not set). The entry maps `{Protocol, NATSrcIP, NATSrcPort} → {SrcIP, SrcPort}` from the forward session.

### IN PROGRESS: NO_NEIGH drops synced SNAT sessions after failover

**Symptom:** After VRRP failover, the takeover node has no ARP/NDP entries for next hops that were only used by the previous primary. `bpf_fib_lookup` returns `BPF_FIB_LKUP_RET_NO_NEIGH` (rc=7) → XDP_PASS with un-NAT'd packet → kernel sends RST (local dst) or forwards with wrong source IP.

**Root cause:** ARP/NDP caches are per-node. When the primary sends SNAT'd traffic, only the primary has ARP entries for the next hop. The secondary never sends traffic to those destinations, so its ARP cache is cold.

**Proposed fix:** Proactive ARP/NDP warmup after VRRP MASTER transition:
- On becoming MASTER, iterate synced sessions with SNAT flag
- Extract unique next-hop IPs from session NAT fields
- Send ICMP echo (ping) to each next hop to trigger ARP resolution
- Consider `BPF_FIB_LOOKUP_SKIP_NEIGH` flag for graceful degradation

### IN PROGRESS: Monotonic clock skew in GC

**Symptom:** Synced sessions carry the remote node's monotonic timestamps (`Created`, `LastSeen`). If the local node has been running longer than the remote, `LastSeen + Timeout < local_now` evaluates true immediately → premature session expiry within seconds of sync.

**Root cause:** `CLOCK_MONOTONIC` timestamps are relative to each node's boot time. Node A reboots (low monotonic time), syncs sessions to Node B (high monotonic time). Node B's GC sees sessions with low `LastSeen` → expires them.

**Proposed fix:** Set `LastSeen = local monotonic time` when installing synced sessions in `handleMessage()`. This ensures GC on the local node uses the local clock for expiry decisions. The `Created` timestamp remains original for auditing/display purposes.

## Test Plan: Session Sync Failover

### Prerequisites

- Two-node cluster: bpfrx-fw0 (node 0, priority 200), bpfrx-fw1 (node 1, priority 100)
- cluster-lan-host (10.0.60.102) as traffic source via RETH LAN VIP (10.0.60.1)
- External host or WAN-reachable iperf server for SNAT testing
- Heartbeat link: 10.99.0.0/30, Fabric link: 10.99.1.0/30
- WAN RETH VIP: 172.16.50.10, LAN RETH VIP: 10.0.60.1

### Test Cases

#### 1. Basic SNAT failover (TCP)

```bash
# On external host: start iperf3 server
iperf3 -s

# On cluster-lan-host: start TCP flow through firewall
incus exec cluster-lan-host -- iperf3 -c <external-host> -t 120 -C bbr

# Verify sessions synced to fw1
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security flow session

# Trigger failover: stop fw0
incus exec bpfrx-fw0 -- systemctl stop bpfrxd
# OR: incus stop bpfrx-fw0

# Verify on fw1:
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show vrrp summary        # MASTER state
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security flow session # sessions present
```

**Pass criteria:**
- fw1 becomes MASTER within 3.5s (master-down timer)
- iperf throughput resumes within 5s
- No RSTs sent by fw1 kernel (`ss -s` shows no resets)
- Session counters continue increasing on fw1

#### 2. SNAT failover (UDP)

```bash
# Same setup as TCP but with UDP
incus exec cluster-lan-host -- iperf3 -c <external-host> -t 120 -u -b 100M
```

**Pass criteria:**
- UDP should be more resilient (no RSTs, no TCP connection state)
- Flow resumes within 3.5s of failover
- Packet loss limited to failover window only

#### 3. DNAT failover

```bash
# Set up DNAT rule: external:8080 → internal:80
# Start HTTP server on cluster-lan-host
incus exec cluster-lan-host -- python3 -m http.server 80

# From external host, connect to DNAT VIP
curl -v http://172.16.50.10:8080/

# With long-running connection (iperf or curl --no-buffer)
# Stop fw0 → verify connection survives on fw1
```

**Pass criteria:**
- DNAT sessions synced including NATDstIP/NATDstPort
- After failover, fw1 has both forward+reverse entries and dnat_table entries from config
- New connections to DNAT VIP work through fw1

#### 4. Preemption with sync hold

```bash
# Start with both nodes running, fw0 is MASTER (priority 200)
# Stop fw0 → fw1 becomes MASTER
incus exec bpfrx-fw0 -- systemctl stop bpfrxd

# Establish sessions through fw1
incus exec cluster-lan-host -- iperf3 -c <external-host> -t 120

# Start fw0 → verify sync hold delays preemption
incus exec bpfrx-fw0 -- systemctl start bpfrxd

# Watch fw0 logs for sync hold
incus exec bpfrx-fw0 -- journalctl -u bpfrxd -f
# Should see: "vrrp: sync hold active" then "vrrp: sync hold released"
```

**Pass criteria:**
- fw0 starts with `preempt=false` (sync hold active)
- fw0 receives bulk sync from fw1 before becoming MASTER
- "sync hold released" log appears after BulkEnd received (or 30s timeout)
- Existing sessions survive fw0's preemption of fw1
- No traffic interruption during preemption

#### 5. GC doesn't kill synced sessions

```bash
# Sync sessions from fw0 to fw1 (verify with show sessions on fw1)
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security flow session

# Wait 30+ seconds (multiple GC cycles — GC runs every 10s)
sleep 35

# Verify sessions still exist on fw1
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security flow session

# Trigger failover → sessions should still work
incus exec bpfrx-fw0 -- systemctl stop bpfrxd

# Verify traffic still flows
incus exec cluster-lan-host -- ping -c 3 <external-host>
```

**Pass criteria:**
- Synced sessions survive 3+ GC cycles (30s) without expiry
- After failover, sessions are usable (not garbage collected)
- Note: requires monotonic clock fix (task #2) to pass reliably

#### 6. ARP warmup after failover

```bash
# Flush fw1's ARP cache before test
incus exec bpfrx-fw1 -- ip neigh flush all

# Establish SNAT sessions through fw0
incus exec cluster-lan-host -- iperf3 -c <external-host> -t 120

# Trigger failover
incus exec bpfrx-fw0 -- systemctl stop bpfrxd

# Check ARP entries populated quickly
incus exec bpfrx-fw1 -- ip neigh show

# Check flow stats for NO_NEIGH drops
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security flow statistics
```

**Pass criteria:**
- ARP entries populated within 1s of becoming MASTER
- No NO_NEIGH drops visible in flow stats
- Note: requires NO_NEIGH fix (task #1) to pass

### Verification Commands

```bash
# Check sessions on peer
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security flow session

# Check VRRP status
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show vrrp summary

# Check sync stats
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show chassis cluster information

# Check flow stats (includes NO_NEIGH counter)
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security flow statistics

# Check ARP cache
incus exec bpfrx-fw1 -- ip neigh show

# Check kernel RSTs (ss -s shows TCP reset counts)
incus exec bpfrx-fw1 -- ss -s

# Follow daemon logs during failover
incus exec bpfrx-fw1 -- journalctl -u bpfrxd -f

# Check dnat_table entries on fw1
incus exec bpfrx-fw1 -- /opt/bpfrx/bpfrxd show security nat source summary
```
