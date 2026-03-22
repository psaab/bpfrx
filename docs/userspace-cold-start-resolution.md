# Userspace Dataplane: Cold Start & Neighbor Resolution

**Date:** 2026-03-22
**Commits:** `e0c01ac` through `2f818e8`

## Problem Statement

After daemon restart or when encountering a new destination host, the
userspace AF_XDP dataplane could not establish new TCP connections.
The first SYN packet hit `MissingNeighbor` (no ARP/NDP entry for the
egress next-hop) and was either dropped or reinjected to the kernel
slow-path TUN, resulting in:

- **Infinite timeout** for new TCP connections (initial state)
- **~1.2s delay** after adding slow-path reinject (TCP SYN retransmit)
- **~2ms delay** after all fixes (buffer-and-retry with ICMP probe)

## Root Causes

### 1. Zero-Copy Fill Ring Bootstrap

**Problem:** After XSK socket bind in zero-copy mode, the mlx5 driver
runs NAPI during channel activation to post fill ring entries as
hardware WQEs. If the fill ring was empty at bind time,
`xsk_buff_alloc_batch()` failed and the driver never retried — leaving
the hardware RQ with zero WQEs forever.

**Fix:** Prime the fill ring BEFORE the `xsk_bind()` call, not after.
(`8a05d52`)

```
// Before: prime_fill_ring_offsets(&mut device, &offsets) called AFTER bind
// After:  prime_fill_ring_offsets(&mut device, &offsets) called BEFORE bind
```

**Verification:** `rx_xsk_buff_alloc_err` counter stopped incrementing
on daemon restart.

### 2. Heartbeat Gating Deadlock

**Problem:** The `xsk_rx_confirmed` flag gated heartbeat writes on
receiving at least one XSK packet. But without heartbeat, the XDP shim
did `XDP_PASS` (kernel forwarding), so no XSK packets ever arrived —
a deadlock. With the pre-bind fill ring prime fixing the underlying WQE
issue, the gate was unnecessary.

**Fix:** Remove `xsk_rx_confirmed` gating entirely. All queues write
heartbeat immediately after the grace period. (`161053a`)

### 3. XDP_PASS on Zero-Copy Breaks VLAN ARP Demux

**Problem:** On mlx5 in zero-copy mode, `XDP_PASS` for non-IP traffic
(ARP replies) doesn't properly deliver through VLAN demux. The ARP
reply arrives on the parent interface (`ge-0-0-2`), the XDP shim
returns `XDP_PASS`, but the zero-copy-to-SKB conversion path skips
the VLAN tag processing needed to steer the packet to `ge-0-0-2.80`.
The kernel sees the ARP reply but can't match it to the VLAN
sub-interface, leaving neighbor entries stuck in `INCOMPLETE` state.

This also affected `cpumap_or_pass` — cpumap redirect for ARP replies
doesn't trigger the kernel's L2 ARP state machine either.

**Impact:** The kernel could never resolve ARP/NDP for hosts on VLAN
sub-interfaces while the XDP shim was attached to the parent.

**Fix:** Use `XDP_PASS` for non-IP (not cpumap). While XDP_PASS has
the VLAN demux issue, the ICMP socket probe (below) bypasses it
entirely by using the kernel's own ARP/NDP stack. (`87a60a3`, `8211f35`)

### 4. AF_PACKET `send_raw_frame` Silently Drops on VLAN Sub-Interfaces

**Problem:** The helper sent ARP requests via `AF_PACKET SOCK_RAW` on
VLAN sub-interfaces (e.g., `ge-0-0-2.80`). The `send()` syscall
returned success (42 bytes sent) but the frame never reached the wire.
The kernel accepted the frame into the socket buffer but the VLAN
sub-interface egress path dropped it — likely due to TX VLAN offload
expecting the tag in descriptor metadata, not in the frame payload.

**Diagnosis:**
- `tcpdump -i ge-0-0-2.80` showed 0 ARP packets from the helper
- `tcpdump -i ge-0-0-2` (parent) also showed 0
- Python `socket.AF_PACKET` with `bind()` + `send()` worked (different
  kernel code path than `sendto()` with `sll_ifindex`)
- The `sll_protocol` field was set incorrectly: `(proto as i32).to_be()`
  byte-swaps all 4 bytes instead of just the lower 16 bits

**Multiple attempted fixes (all failed for VLAN):**
1. `sendto()` with `sll_ifindex` — frame silently dropped
2. `bind()` + `send()` — frame accepted but never transmitted
3. `bind()` + `sendto()` with explicit `sockaddr_ll` — same
4. Insert 802.1Q tag + send on parent interface — TX offload strips tag
5. Netlink `RTM_NEWNEIGH` with `NUD_INCOMPLETE` — kernel sends ARP but
   reply doesn't survive XDP_PASS VLAN demux

**Working fix:** ICMP socket probe (see below).

### 5. ICMP SOCK_DGRAM `sendto()` Silently Fails

**Problem:** The `trigger_kernel_arp_probe()` function used
`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` to send an ICMP echo
request. The `socket()` call succeeded but `sendto()` returned
`EINVAL` silently (return value not checked). The code then closed
the socket without falling through to the `SOCK_RAW` fallback.

Same issue for IPv6: `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)`.

**Fix:** Use `SOCK_RAW` directly for both IPv4 and IPv6. Set
`IPV6_CHECKSUM` sockopt for ICMPv6 auto-checksum. (`fd53f19`, `2f818e8`)

```rust
// IPv4: SOCK_RAW IPPROTO_ICMP + SO_BINDTODEVICE
let fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name);
sendto(fd, icmp_echo, target_addr);

// IPv6: SOCK_RAW IPPROTO_ICMPV6 + SO_BINDTODEVICE + IPV6_CHECKSUM
let fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name);
setsockopt(fd, IPPROTO_ICMPV6, IPV6_CHECKSUM, &2); // offset 2
sendto(fd, icmpv6_echo, target_addr);
```

### 6. Buffer Retry Not Running on Empty RX

**Problem:** The `retry_pending_neigh()` function only ran at the end
of `poll_binding()`, after RX packet processing. When no new packets
arrived (the common case during cold ARP — the SYN was buffered and
no other traffic), `poll_binding()` returned early at the
`available == 0` check without ever checking the pending buffer.

The buffered SYN sat idle until the TCP retransmit (~1s) generated a
new packet, waking the RX path. This caused the classic "1.2s TCP
black hole" — the ARP resolved in ~5ms but the retry didn't fire
for another ~1195ms.

**Fix:** Call `retry_pending_neigh()` on the `available == 0` early
return path, before `counters.flush()`. This runs the retry on every
1ms poll cycle (interrupt mode), catching the netlink event within
1ms of ARP resolution. (`293b818`)

```rust
if available == 0 {
    maybe_wake_rx(binding, false, now_ns);
    retry_pending_neigh(...);  // NEW — check buffered packets
    counters.flush(&binding.live);
    return did_work;
}
```

### 7. No Session Created on MissingNeighbor

**Problem:** When a TCP SYN hit `MissingNeighbor`, the session was
never created. The SYN was buffered and later forwarded (after ARP
resolved), but the SYN-ACK from the target had no matching forward
session. The SYN-ACK went through session miss → policy check, and
with default-deny policy for WAN→LAN, it was dropped.

**Fix:** Create the session immediately on `MissingNeighbor`, before
buffering the packet. The session stores the NAT decision so the
SYN-ACK's reverse lookup finds it via `install_reverse_session_from_forward_match`. (`9584447`)

## Architecture: Cold Start Flow (Final)

```
1. SYN arrives on ge-0-0-1 → XDP shim → XSK → helper RX
2. Session miss → policy permit → SNAT → FIB lookup
3. FIB: next-hop 172.16.80.200 on ge-0-0-2.80
4. Neighbor lookup: not in dynamic_neighbors → MissingNeighbor

5. CREATE SESSION (NAT decision stored for reverse SYN-ACK lookup)
6. ICMP PROBE: socket(SOCK_RAW, IPPROTO_ICMP) + SO_BINDTODEVICE
   → kernel sends ICMP echo → triggers ARP on ge-0-0-2.80
   → ARP reply arrives → kernel learns neighbor → RTM_NEWNEIGH
7. BUFFER PACKET: hold UMEM frame in pending_neigh queue

8. Netlink monitor thread: recv() → RTM_NEWNEIGH → update dynamic_neighbors
9. Worker poll (1ms): rx.available() == 0 → retry_pending_neigh()
   → neighbor found in dynamic_neighbors → rewrite frame → XSK TX
10. SYN reaches 172.16.80.200 → SYN-ACK comes back
11. SYN-ACK: session hit (forward NAT match) → reverse session created
    → forwarded to cluster-host via XSK TX
12. ACK: session hit → TCP established → data flows at line rate
```

**Total cold latency: ~2ms** (ARP/NDP roundtrip + netlink + retry)

## Performance Results

| Metric | Before | After |
|--------|--------|-------|
| Cold TCP connect (after ARP flush) | Infinite timeout | ~2ms |
| Cold iperf3 IPv4 (8 streams, 5s) | 0 Gbps (timeout) | 20.1 Gbps |
| Cold iperf3 IPv6 (8 streams, 5s) | 0 Gbps (broken) | 20.0 Gbps |
| Warm iperf3 (8 streams, 10s) | 23+ Gbps | 23+ Gbps |
| Fill ring bootstrap | Failed (0/12 queues) | 12/12 queues |
| Neighbor resolution | 1-5s (Go snapshot) | ~2ms (netlink event) |

## Files Changed

| File | Changes |
|------|---------|
| `userspace-dp/src/afxdp.rs` | Buffer-and-retry, ICMP probe, netlink monitor, session-on-miss, retry on empty RX |
| `userspace-dp/src/afxdp/bind.rs` | Pre-bind fill ring prime, SO_BUSY_POLL tuning |
| `userspace-dp/src/main.rs` | Global busy_poll sysctls |
| `userspace-xdp/src/lib.rs` | XDP_PASS for non-IP, heartbeat gating removal |
| `pkg/dataplane/userspace/manager.go` | Kernel address sync, NAPI bootstrap after rebind, VLAN sub XDP skip |
| `pkg/dataplane/compiler.go` | Skip XDP on VLAN sub-interfaces |
| `pkg/dataplane/loader.go` | VlanSubInterfaces tracking |
| `pkg/daemon/daemon.go` | Session sync timeout tuning |

## Key Learnings

1. **mlx5 zero-copy XDP_PASS breaks VLAN demux** — the ZC-to-SKB
   conversion path doesn't call `vlan_do_receive()`. ARP/NDP replies
   on VLAN interfaces must be resolved through the kernel's own stack
   (ICMP socket probe), not through XDP_PASS.

2. **AF_PACKET on VLAN sub-interfaces is unreliable** — `send()` and
   `sendto()` report success but frames are silently dropped. The
   kernel's VLAN egress path with TX offload expects the tag in
   descriptor metadata, not in the frame payload.

3. **SOCK_DGRAM IPPROTO_ICMP sendto() fails with EINVAL** — despite
   the socket creation succeeding. Always use SOCK_RAW for ICMP/ICMPv6
   probes. Set `IPV6_CHECKSUM` for ICMPv6 auto-checksum.

4. **Buffer retry must run on empty RX polls** — the XSK poll loop's
   early return on `available == 0` skips end-of-batch processing.
   Buffered packets sit idle until the next RX packet arrives (~1s for
   TCP retransmit). Checking the buffer on every poll wake (1ms) is
   critical for sub-10ms cold start.

5. **Create sessions on MissingNeighbor** — without the forward session,
   the reverse direction (SYN-ACK) can't find the NAT match and gets
   policy-denied. The session must exist before the SYN-ACK arrives.
