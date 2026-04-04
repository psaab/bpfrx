# Fabric Bridge Tuning Plan

## Current State

The HA cluster uses two virtio bridges between VMs on the `loss` hypervisor:

| Bridge | Purpose | VMs | VM interface | MTU |
|--------|---------|-----|-------------|-----|
| bpu-hb0 | Heartbeat + session sync | fw0 em0, fw1 em0 | enp6s0 | 1500 |
| bpu-fab0 | Fabric forwarding | fw0 ge-0-0-0, fw1 ge-7-0-0 | enp7s0 | 1500 |

Session sync TCP runs on em0 (heartbeat bridge), not the fabric parent.
Fabric forwarding (XSK packet redirect) runs on ge-X-0-0 (fabric bridge).

### Observed symptoms

- TCP sync connection: 18ms RTT spikes, 6+ retransmissions, cwnd=10
- Barrier ack latency: ~12s for 200-300 sessions
- Fabric forwarding throughput: 3.5 Gbps (CPU 95% idle — bridge-limited)

### Bridge configuration issues found

1. **MTU mismatch**: ge-0-0-0 inside VM has MTU 9000, but host bridge
   `bpu-fab0` has MTU 1500. Fabric-forwarded packets >1500 bytes are
   silently dropped by the bridge. TCP MSS clamping limits TCP to 1448,
   but non-TCP transit (UDP, ICMP) can exceed this.

2. **Unnecessary bridge features**: Both bridges have VLAN filtering
   (`vlan_filtering 1`) and multicast snooping (`mcast_snooping 1`)
   enabled. These add per-packet overhead on what is a simple
   point-to-point link between two VMs.

3. **TX ring 256**: QEMU default virtio TX ring is 256 entries (max).
   RX ring was already increased to 1024 via `raw.qemu rx_queue_size=1024`.
   TX ring can also be increased with `tx_queue_size`.

4. **Bridge MAC learning**: Bridges do MAC learning + flooding for unknown
   destinations. With exactly two ports (one per VM), this is wasted
   work. Static FDB entries or `learning off` eliminates the overhead.

5. **Single TX queue on bridge device**: The bridge device itself has
   `numtxqueues=1 numrxqueues=1` even though the virtio NICs have 6
   combined queues. This serializes bridge forwarding.

## Tuning Plan

### Phase 1: Bridge-level tuning (hypervisor config, no code changes)

Apply to both `bpu-hb0` and `bpu-fab0`:

```bash
# MTU 9000 on fabric bridge (match VM-side MTU)
ip link set bpu-fab0 mtu 9000

# Disable VLAN filtering (point-to-point, no VLANs needed)
ip link set bpu-fab0 type bridge vlan_filtering 0

# Disable multicast snooping (two ports, no benefit)
ip link set bpu-fab0 type bridge mcast_snooping 0

# Disable MAC learning (static point-to-point)
bridge link set dev <vm0-port> learning off
bridge link set dev <vm1-port> learning off

# Disable STP (already off, confirm)
ip link set bpu-fab0 type bridge stp_state 0

# Reduce aging time (faster FDB convergence on VM restart)
ip link set bpu-fab0 type bridge ageing_time 10
```

For `bpu-hb0` (heartbeat/sync), same tuning but MTU stays at 1500
(sync traffic is small packets).

### Phase 2: TX ring increase (QEMU config)

```
raw.qemu: -global virtio-net-pci.rx_queue_size=1024 -global virtio-net-pci.tx_queue_size=1024
```

This increases the TX ring from 256 to 1024, matching the RX ring.
Requires VM stop/start (hot-plug doesn't change ring sizes).

**Note**: `tx_queue_size` was added in QEMU 2.10 and requires the
virtio-net device to support it. Verify with:
```bash
incus exec <vm> -- ethtool -g <iface>  # check TX max
```

### Phase 3: TCP sync tuning (code change in Go daemon)

Set socket options on the session sync TCP connection:

```go
// In sync.go dial path:
conn.(*net.TCPConn).SetNoDelay(true)     // disable Nagle for barrier latency
conn.(*net.TCPConn).SetWriteBuffer(256 * 1024)  // 256KB send buffer
conn.(*net.TCPConn).SetReadBuffer(256 * 1024)   // 256KB recv buffer
```

TCP_NODELAY is critical for barrier messages: without it, small barrier
messages (20 bytes) can be delayed up to 200ms by Nagle's algorithm
waiting to coalesce with other data.

### Phase 4: Replace bridge with macvtap or veth pair (incus config)

The bridge device adds per-packet overhead:
- FDB lookup per frame
- SKB clone for flooding
- qdisc processing

For a point-to-point link between exactly two VMs, a direct connection
eliminates all bridge overhead:

**Option A: veth pair** — create a veth pair, assign one end to each VM.
No bridge, no MAC learning, no flooding. Requires incus raw device config.

**Option B: macvtap bridge mode** — each VM gets a macvtap device on a
shared parent. Lower overhead than a full bridge but still has some
MAC-level processing.

**Option C: DPDK vhost-user** — eliminates kernel networking entirely for
the fabric path. Requires significant code changes but achieves near line
rate VM-to-VM throughput.

Recommendation: start with veth pair (Option A) — simplest, biggest
impact, no code changes beyond incus config.

## Phase 5: Dedicated fabric sync (future)

Move session sync from the heartbeat bridge to the fabric bridge:
- Fabric bridge gets MTU 9000 (Phase 1) → larger TCP segments
- Fabric parent has XDP for fast-path packet processing
- Consolidates all inter-VM traffic on one high-performance link

This requires changing the sync connection dial address from the
em0 (heartbeat) address to the fabric overlay address. Currently blocked
by the fabric overlay DOWN bug.

## Expected Impact

| Change | Barrier latency | Fabric throughput |
|--------|-----------------|-------------------|
| Current | ~12s | 3.5 Gbps |
| Phase 1 (bridge tuning) | ~8s | 5-7 Gbps |
| Phase 2 (TX ring 1024) | ~6s | 7-10 Gbps |
| Phase 3 (TCP_NODELAY) | ~3s | — |
| Phase 4 (veth pair) | ~2s | 10-15 Gbps |

Phase 3 (TCP_NODELAY) likely has the biggest single impact on barrier
latency since Nagle coalescing directly delays small control messages.

## Quick Wins (can apply immediately)

1. `ip link set bpu-fab0 mtu 9000` on the hypervisor
2. Disable VLAN filtering + mcast snooping on both bridges
3. Add TCP_NODELAY to the sync connection
