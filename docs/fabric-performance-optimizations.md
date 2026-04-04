# Fabric Forwarding Performance Optimizations

## Current State (2026-04-04)

| Path | -P1 | -P8 |
|------|-----|-----|
| Direct (all RGs same node) | 7.8 Gbps | 23.1 Gbps |
| Fabric (split-RG) | 2.0 Gbps | 4.0 Gbps |

The fabric path is **5.8x slower** than direct at -P8.

## Root Cause: Generic XDP + Copy-Mode XSK on Virtio Fabric

The fabric parent interface (ge-0-0-0/ge-7-0-0) is virtio-net which only
supports generic XDP (no driver-mode). This means:
- **TX**: Every packet goes through `__xsk_generic_xmit` which allocates a
  full `sk_buff`, copies data, and calls `start_xmit` (9.4% CPU on fw0)
- **RX**: Copy-mode XSK copies every frame from kernel to UMEM (11.3% CPU on fw1)

The eBPF pipeline avoids this entirely by using `bpf_redirect_map` for fabric
redirect — zero-copy XDP-to-XDP redirect at the driver level.

## Fabric NAT Flow

NAT is applied at the fabric sender (`apply_nat_on_fabric=true`):
- **Outbound**: fw0 SNATs before fabric TX → fw1 sees post-NAT → forwards to WAN
- **Return**: fw1 un-SNATs before fabric TX → fw0 sees post-un-NAT → forwards to LAN
- No re-NAT on the receiving peer — it just forwards

This means full L4 checksum recompute happens on BOTH fabric crossings (3.6% CPU each).

`apply_nat_on_fabric=false` is broken because the receiving peer's fabric-ingress
path doesn't re-apply NAT from the synced session's stored NAT decision. The packet
would leave the WAN with the client's private IP as source, breaking return routing.

## Optimizations (Priority Order)

### 1. XDP Shim Fabric Redirect [HIGH — eliminates ~20% kernel overhead]

**Impact**: Eliminates all kernel copy/alloc overhead on both nodes
**Effort**: Medium (XDP shim + BPF map changes)

Teach the XDP shim to detect fabric-destined packets and use `bpf_redirect_map`
directly at the XDP level, bypassing XSK entirely:

1. Rust helper writes fabric redirect entries to a new `USERSPACE_FABRIC_REDIRECT`
   BPF map: `{forward_key} → {fabric_ifindex, dst_mac, src_mac, nat_rewrite}`
2. XDP shim checks the map BEFORE redirecting to XSK
3. If match found: rewrite MACs, apply NAT, `bpf_redirect_map(fabric_ifindex)` → zero-copy
4. If no match: redirect to XSK as before (normal userspace processing)

**Benefit**: Fabric packets never enter userspace — same performance as eBPF pipeline.
Requires the shim to do NAT rewrite in BPF (IP/port/checksum), which the eBPF pipeline
already implements.

### 2. Incremental L4 Checksum for Non-Segmented Fabric TX [MEDIUM — saves 3.6%]

**Impact**: Reduces checksum overhead from O(packet_size) to O(1) for MTU-sized packets
**Effort**: Low (code change in segmentation path)

Currently `segment_forwarded_tcp_frames_into_prepared()` always calls
`recompute_l4_checksum_ipv4()` which sums the entire L4 payload (~1460 bytes).
For single-segment packets (no actual TSO segmentation), use incremental adjustment:

```rust
// Instead of full recompute:
recompute_l4_checksum_ipv4(packet, ip_header_len, meta.protocol, false);

// Use incremental for single-segment non-segmented packets:
if segment_count == 1 {
    adjust_l4_checksum_incremental(packet, l4_csum_delta, ttl_delta);
}
```

The `l4_csum_delta` is already precomputed for NAT changes. TTL decrement is a
constant delta. This turns an O(1460) operation into O(1).

### 3. Cross-Binding In-Place Rewrite [MEDIUM — saves ~7%]

**Impact**: Avoids full frame copy + segmentation path for cross-interface forwarding
**Effort**: Medium (requires UMEM architecture change)

Currently the in-place fast path (`apply_rewrite_descriptor`) only works when
the ingress and egress bindings are on the same interface (hairpin). For fabric
redirect, ingress is MLX5 (LAN) and egress is virtio (fabric) — different
bindings with different UMEMs.

Option A: Modify in-place to rewrite the frame in the ingress UMEM, then copy
only the rewritten frame to the egress UMEM (avoiding re-parse + re-checksum).

Option B: Share UMEM across bindings so in-place rewrite works cross-binding.

### 4. Fabric-Ingress XDP_PASS to eBPF Pipeline [LOW — alternative to #1]

**Impact**: Eliminates copy-mode XSK RX overhead on the receiving side only
**Effort**: Low (XDP shim change)

For packets arriving ON the fabric parent, have the XDP shim `XDP_PASS` to the
kernel instead of redirecting to XSK. The eBPF pipeline already handles
fabric-ingress correctly (xdp_zone → conntrack → nat → forward).

Less impactful than #1 because only fixes the RX side and still goes through
the kernel eBPF pipeline (which is fast but not zero-copy).

### 5. Fix apply_nat_on_fabric=false [MEDIUM — enables deferred NAT]

**Impact**: Eliminates NAT + checksum on fabric sender, defers to receiver
**Effort**: Medium (fix fabric-ingress NAT application path)

When fabric-ingress packets arrive, the current code skips zone policy and goes
directly to forwarding. It needs to also apply the session's stored NAT decision
before forwarding to the egress interface. This requires:

1. Look up session by pre-NAT key (already works)
2. Extract NAT rewrite from session decision
3. Apply NAT rewrite to the packet before forwarding

If implemented, `apply_nat_on_fabric=false` would save the 3.6% checksum on
BOTH fabric directions (7.2% total), but the receiver would incur the same
cost. Net benefit: zero for checksum, but reduces fabric TX bandwidth
(smaller packets if ports change, and avoids double-touching the frame).

### 6. Virtio Ring Size Optimization [DONE]

**Status**: Implemented via `raw.qemu='-global virtio-net-pci.rx_queue_size=1024'`
**Impact**: Eliminates burst drops (was 4193 drops / 36M packets)

Increased virtio RX ring from 256 to 1024 entries. This absorbs the initial burst
when a high-throughput stream transitions to the fabric path during failover.

## Profile Data (Split-RG -P8)

### fw0 (sends to fabric)
```
 8.2%  poll_binding              — packet processing
 6.4%  memmove (libc)            — kernel XSK copy
 4.2%  __xsk_generic_xmit        — kernel generic XDP TX (SKB alloc!)
 3.6%  recompute_l4_checksum_ipv4 — full L4 checksum per fabric packet
 3.5%  enqueue_pending_forwards   — frame build + segmentation
 1.7%  slab_update_freelist      — kernel slab allocator (SKB)
 1.6%  virtqueue_add_outbuf      — virtio TX ring
 1.4%  start_xmit                — virtio TX kick
 1.3%  kmem_cache_alloc_node     — kernel alloc
 1.3%  __alloc_skb               — SKB allocation
 1.2%  apply_nat_ipv4            — NAT rewrite
```

### fw1 (receives from fabric)
```
10.2%  poll_binding              — packet processing
 7.3%  memmove (libc)            — copy-mode XSK RX
 4.4%  enqueue_pending_forwards   — frame build + TX
 4.0%  memcpy_orig               — kernel copy
 1.9%  worker_loop               — loop overhead
 1.4%  __skb_flow_dissect        — generic XDP flow parsing
 1.1%  receive_buf               — virtio RX
 0.9%  do_xdp_generic            — generic XDP processing
 0.9%  __xsk_generic_xmit        — fabric TX back (return path)
 0.8%  xp_alloc                  — XSK frame allocation
```
