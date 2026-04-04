# Fabric Forwarding Performance Optimizations

## Current State (2026-04-04)

| Path | -P1 | -P8 |
|------|-----|-----|
| Direct (all RGs same node) | 7.8 Gbps | 23.0 Gbps |
| Fabric (split-RG) | 2.0 Gbps | 3.5 Gbps |

## Architecture: How Fabric Redirect Actually Works

Fabric redirect runs entirely through the **userspace dataplane (XSK)**, not the
eBPF pipeline. Verified with live test: 1,058,580 XSK RX packets on fw0 during a
5-second -P1 fabric test at 1.7 Gbps.

1. **Packet arrives on ingress interface** (e.g. ge-0-0-1 on fw0, LAN side).
   The XDP shim redirects the packet to the XSK AF_XDP socket.

2. **Rust helper processes the packet**: session lookup in the flow cache or
   BPF session map. The session resolves to a `FabricRedirect` disposition
   (the session's owner RG is active on the peer node, not this one).

3. **Rust helper rewrites MACs and applies NAT** (`apply_nat_on_fabric=true`):
   source/destination MAC rewrite for the fabric link, plus full NAT
   transformation (SNAT/DNAT IP + port rewrite). NAT uses
   `recompute_l4_checksum_ipv4` — a **full L4 checksum recompute** that walks
   the entire payload. This is O(payload length) per packet.

4. **TX out fabric parent** (e.g. ge-0-0-0): copy-mode XSK → kernel
   `__xsk_generic_xmit` → SKB allocation → virtio TX. This is NOT zero-copy —
   the generic XSK path allocates an `sk_buff` and copies the frame.

5. **Peer receives on fabric parent** (e.g. ge-7-0-0 on fw1): XDP shim →
   XSK redirect → Rust helper processes with the synced session → forwards
   out the egress interface (e.g. ge-7-0-2, WAN).

### Key insight

The fabric path goes through the Rust userspace dataplane on BOTH nodes.
The full L4 checksum recompute (`recompute_l4_checksum_ipv4`, 3.6% in the
profile) is a real cost on the fabric path — it runs on every fabric-redirected
packet, not just the direct path. Replacing it with incremental checksum
updates would reduce per-packet CPU cost from O(payload) to O(1).

## Fabric NAT Flow (via Userspace Dataplane)

### Outbound: Client -> Server (split-RG: fw0=LAN, fw1=WAN)

```
Client 10.0.61.102:43446 -> 172.16.80.200:5201

1. Arrives on ge-0-0-1 (fw0, LAN)
2. XDP shim -> XSK redirect -> Rust worker
3. Session lookup -> FabricRedirect (RG1/WAN owned by fw1)
4. Rust helper: rewrite MACs for fabric link
   + apply_nat_on_fabric=true -> SNAT (src 10.0.61.102 -> 172.16.80.8)
   + recompute_l4_checksum_ipv4 (full payload walk)
5. TX out ge-0-0-0 (fabric parent, copy-mode XSK -> SKB -> virtio TX)
6. Arrives at fw1 ge-7-0-0 (fabric parent)
7. XDP shim -> XSK redirect -> Rust worker
8. Session lookup -> Forward (RG1/WAN is local)
9. Forwards out ge-7-0-2 (WAN) with src=172.16.80.8:43446
```

### Return: Server -> Client

```
Server 172.16.80.200:5201 -> 172.16.80.8:43446

1. Arrives on ge-7-0-2 (fw1, WAN)
2. XDP shim -> XSK redirect -> Rust worker
3. Session lookup -> FabricRedirect (RG2/LAN owned by fw0)
4. Rust helper: rewrite MACs for fabric link
   + apply_nat_on_fabric=true -> un-SNAT (dst 172.16.80.8 -> 10.0.61.102)
   + recompute_l4_checksum_ipv4 (full payload walk)
5. TX out ge-7-0-0 (fabric parent, copy-mode XSK -> SKB -> virtio TX)
6. Arrives at fw0 ge-0-0-0 (fabric parent)
7. XDP shim -> XSK redirect -> Rust worker
8. Session lookup -> Forward (RG2/LAN is local)
9. Forwards out ge-0-0-1 (LAN) with dst=10.0.61.102:43446
```

### NAT is applied by the Rust userspace DP, with full checksum recompute

- **Outbound**: NAT applied on fw0 (the sending node) before fabric TX
- **Return**: NAT applied on fw1 (the sending node) before fabric TX
- Full L4 checksum recompute — O(payload) per packet
- This is the primary CPU-side optimization target for fabric throughput

## Actual Bottleneck: Virtio Bridge Throughput

The fabric path runs at 3.5 Gbps with CPUs mostly idle (~2% peak in profiles).
This is NOT a CPU bottleneck — it's the virtio-net bridge throughput between VMs.

### Contributing factors

1. **Copy-mode XSK on virtio**: The fabric parent uses generic/copy-mode XSK
   (`__xsk_generic_xmit`). Every TX frame allocates an `sk_buff` and copies
   data — there is no zero-copy DMA path on virtio-net.

2. **Virtio TX ring size**: Limited to 256 entries (TX max on QEMU). At high pps,
   the ring fills and the VM must wait for completions before sending more.

3. **Bridge forwarding overhead**: The local bridge between VMs adds per-packet
   overhead for MAC learning, flooding, and sk_buff management.

4. **VM configuration**: vhost-net, NUMA pinning, multiqueue alignment, and CPU
   model settings affect VM-to-VM throughput.

## Optimization Plan

### Phase 1: VM-Level Tuning [LOW effort, potentially HIGH impact]

These are configuration changes, no code required:

1. **Verify vhost-net is active** on the host for both VMs
2. **Pin both VMs to same NUMA node** (`numactl` or libvirt/incus XML)
3. **Set CPU model to `host`** to expose AVX/AES-NI instructions
4. **Increase virtio TX ring** if QEMU supports it (currently 256 max)
5. **Test with MTU 9000** on the bridge itself (not just the VM interfaces)
6. **Disable GSO/LRO inside guest** on the fabric parent (can cause overhead
   in pure-virtual paths)

Expected improvement: 2-3x if the current limit is configuration, not hardware.

### Phase 2: Incremental L4 Checksum in Rust Helper [MEDIUM effort, HIGH impact]

Replace `recompute_l4_checksum_ipv4` with incremental checksum updates in
`build_forwarded_frame_into_from_frame` for fabric-redirected packets:

1. **Incremental NAT checksum**: Instead of walking the full payload, compute
   the checksum delta from the changed fields (src/dst IP, src/dst port) and
   apply it to the existing checksum. This is O(1) instead of O(payload).
   Implementation challenge: `enforce_expected_ports` also modifies checksums,
   so all adjustments must be done in a single pass:
   - Capture pre-NAT IPs and ports
   - Apply NAT (`apply_nat_ipv4`)
   - Apply port enforcement (`enforce_expected_ports`)
   - Compute combined incremental delta for IPs + ports
   - Write final checksum once

2. **Impact estimate**: At 1.7 Gbps with 1M+ packets in 5 seconds, the full
   payload walk is ~200k packets/sec * O(1460 bytes). Incremental updates
   reduce this to O(12 bytes) per packet — ~100x less work per packet.

### Phase 3: Flow Cache HA Validity Check [COMPLETED — PR #432]

The `cached_flow_decision_valid()` per-packet HA check (1.3% CPU on the direct
path) has been replaced by an inline lease-expiry check in the flow cache stamp.
The `owner_rg_lease_until` field in each flow cache entry is compared against
the current timestamp — O(1) with no BTreeMap lookup. Same correctness
guarantees, better cache locality.

### Phase 4: Reduce Virtio Copy Overhead [LOW effort]

Profile and micro-optimize the copy-mode XSK TX path:

1. **Profile `__xsk_generic_xmit`** during fabric -P8 to find hot spots
2. **Batch TX submissions**: Ensure the Rust helper batches multiple frames
   per `sendto()` syscall to amortize kernel entry/exit overhead
3. **Investigate `XDP_ZEROCOPY`**: Check if virtio-net supports zerocopy mode
   in newer kernels (unlikely on QEMU/KVM, but worth checking)

## Profile Data (Split-RG -P8)

### System-wide (mostly idle)
```
2.0%  pv_native_safe_halt       — CPU idle
1.7%  __irqentry_text_start     — interrupt handling
1.4%  scanobject                — Go GC (daemon, not dataplane)
1.2%  __raw_callee_save_spin    — kernel spinlock
1.2%  worker_loop               — Rust worker (mostly idle)
1.2%  mlx5e_napi_poll           — NIC polling
1.1%  mlx5e_poll_xdpsq_cq      — XDP TX completion
```

The CPU is ~95% idle during fabric forwarding at 3.5 Gbps. The bottleneck is
the virtio bridge path (TX ring, copy-mode XSK overhead), not CPU processing.

### Direct Path -P8 (23 Gbps, for comparison)
```
15.9%  poll_binding              — packet processing
10.3%  enqueue_pending_forwards   — frame build + segmentation
 2.0%  parse_session_flow         — packet parsing
 1.5%  drain_pending_tx           — TX completions
 1.3%  cached_flow_decision_valid — HA check (per-packet) [now replaced by inline lease check]
 1.2%  target_index               — binding lookup
```

## Completed Optimizations

- [x] Virtio RX ring 256->1024 (`raw.qemu rx_queue_size=1024`)
- [x] FabricRedirect flow cache cacheable
- [x] Cache BPF map FDs outside worker loop
- [x] Barrier pause/drain for prompt failover
- [x] Forward session push to workers on RG activation
- [x] Fabric link preservation in shared_forwarding across snapshots
- [x] Flow cache HA validity: `owner_rg_lease_until` inline check replaces `cached_flow_decision_valid()` BTreeMap lookup (PR #432)
