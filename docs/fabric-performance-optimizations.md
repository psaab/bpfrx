# Fabric Forwarding Performance Optimizations

## Current State (2026-04-04)

| Path | -P1 | -P8 |
|------|-----|-----|
| Direct (all RGs same node) | 7.8 Gbps | 23.0 Gbps |
| Fabric (split-RG) | 2.0 Gbps | 3.5 Gbps |

## Architecture: How Fabric Redirect Works Today

In strict userspace mode, steady-state fabric transit stays on the AF_XDP
dataplane. It does not rely on `PASS_TO_KERNEL` to bounce transit packets back
into the eBPF forwarding pipeline.

1. The XDP shim classifies packets and redirects transit session hits and
   misses to AF_XDP/userspace.
2. `PASS_TO_KERNEL` is reserved for local-delivery or explicit fallback cases:
   peer-synced local-delivery sessions, ESP, non-native GRE, NDP, and similar
   control-plane traffic.
3. The userspace helper resolves policy, NAT, routing, and HA ownership. If the
   result is `FabricRedirect`, the helper builds the fabric frame itself and
   transmits it through AF_XDP TX.
4. `publish_live_session_entry()` keeps subsequent transit packets on the
   userspace dataplane, so the hot path is flow cache plus `RewriteDescriptor`,
   not `PASS_TO_KERNEL`.
5. `apply_nat_on_fabric` decides whether the userspace helper should NAT the
   packet before fabric TX or preserve the original tuple for later handling on
   the owner side.

### Key implications

- Fabric NAT performance is still a userspace dataplane problem.
- The generic builders and segmentation path still pay real checksum work when
  the descriptor fast path cannot be used.
- Plans that assume "write `PASS_TO_KERNEL` earlier" are solving the wrong path
  for strict userspace fabric transit.

## Where the NAT Cost Still Lives

- `build_forwarded_frame_into_from_frame()` still falls back to
  `recompute_l4_checksum_ipv4` for IPv4 NAT plus port-enforcement cases on the
  generic path.
- `segment_forwarded_tcp_frames_from_frame()` has to rebuild TCP checksums per
  segment.
- Cache hits still do a per-packet HA validation after `FlowCache::lookup()`
  has already checked config generation, FIB generation, RG epoch, and RG lease
  expiry.
- Cache hits still recompute the fabric target binding lookup even though the
  descriptor structure already has space to cache it.

## Optimization Plan

### Phase 1: VM-Level Tuning [LOW effort, potentially HIGH impact]

These are configuration changes, no code required:

1. Verify `vhost-net` is active on the host for both VMs.
2. Pin both VMs to the same NUMA node.
3. Set CPU model to `host` to expose AVX/AES-NI instructions.
4. Increase the virtio TX ring if QEMU supports it.
5. Test MTU 9000 on the bridge itself, not just on the VM interfaces.
6. Disable GSO/LRO inside the guest on the fabric parent if they are adding
   overhead in the pure-virtual path.

Expected improvement: 2-3x if the current ceiling is configuration, not
hardware.

### Phase 2: Tighten the Userspace Fabric/NAT Fast Path [MEDIUM effort]

1. Honor cached `apply_nat_on_fabric` decisions on `FabricRedirect` hits.
   Cached self-target and cross-binding hits must reuse the stored decision
   instead of forcing NAT back on.
2. Replace the generic IPv4 full recompute path with a combined incremental
   NAT plus expected-port checksum update in
   `build_forwarded_frame_into_from_frame()`.
3. Populate `RewriteDescriptor.target_binding_index` for cacheable fabric flows
   so hot hits can skip `fabric_target_index()` while config and FIB generation
   still match.
4. Measure how often `apply_rewrite_descriptor()` falls back to the generic
   builder because of port repair or cross-binding conditions, then widen
   descriptor coverage only where that fallback rate justifies the added code.

### Phase 3: Reduce Duplicate HA Validation on Cache Hits [MEDIUM effort]

1. `FlowCache::lookup()` already rejects stale entries using config generation,
   FIB generation, RG epoch, and RG lease-until. The remaining
   `cached_flow_decision_valid()` call is a second HA walk on every hit.
2. Prove which resolution fields can still change outside the lookup stamp. If
   none of them matter on a cache hit, make the lookup stamp authoritative and
   remove the extra HA check.
3. If full removal is not safe, flatten the hot
   `enforce_ha_resolution_snapshot()` path and carry owner-RG lookup data
   alongside the descriptor.

### Phase 4: Re-profile After Fast-Path Cleanup [LOW effort]

1. Re-run split-RG perf after the Phase 2 and 3 userspace fixes.
2. Determine whether the remaining ceiling is virtio bridge throughput, TX
   completion pressure, binding lookup, or segmentation.
3. Only then decide whether more eBPF-side or VM-side work is worth it.

## Profile Data (Split-RG -P8)

### System-wide (mostly idle)

```
2.0%  pv_native_safe_halt       — CPU idle
1.7%  __irqentry_text_start     — interrupt handling
1.4%  scanobject                — Go GC (daemon, not dataplane)
1.2%  __raw_callee_save_spin    — kernel spinlock
1.2%  worker_loop               — Rust worker (mostly idle)
1.2%  mlx5e_napi_poll           — NIC polling
1.1%  mlx5e_poll_xdpsq_cq       — XDP TX completion
```

The split-RG ceiling still looks dominated by virtualization and queueing, not
raw CPU exhaustion. That said, the userspace path still has real NAT and
cache-hit overhead worth removing before treating the VM ceiling as final.

### Direct Path -P8 (23 Gbps, for comparison)

```
15.9%  poll_binding              — packet processing
10.3%  enqueue_pending_forwards  — frame build + segmentation
 2.0%  parse_session_flow        — packet parsing
 1.5%  drain_pending_tx          — TX completions
 1.3%  cached_flow_decision_valid — HA check (per-packet)
 1.2%  target_index              — binding lookup
```

## Completed Optimizations

- [x] Virtio RX ring 256→1024 (`raw.qemu rx_queue_size=1024`)
- [x] FabricRedirect flow cache cacheable
- [x] Cache BPF map FDs outside worker loop
- [x] Flow-cache stamp invalidation via config generation, FIB generation, RG
  epoch, and RG lease
- [x] Forward session push to workers on RG activation
- [x] Fabric link preservation in shared_forwarding across snapshots
