# Fabric Forwarding Performance Optimizations

## Current State (2026-04-04)

| Path | -P1 | -P8 |
|------|-----|-----|
| Direct (all RGs same node) | 7.8 Gbps | 23.0 Gbps |
| Fabric (split-RG) | 2.0 Gbps | 3.5 Gbps |

## Architecture: How Fabric Redirect Actually Works

The userspace dataplane and eBPF pipeline cooperate for fabric redirect:

1. **Session demotion**: When an RG is demoted on a node, the Rust helper writes
   `PASS_TO_KERNEL` entries in the `USERSPACE_SESSIONS` BPF map for those sessions.

2. **XDP shim fallback**: On the next packet for that session, the XDP shim
   (`xdp_userspace_prog`) finds the `PASS_TO_KERNEL` entry and calls
   `fallback_to_main()` — a BPF tail call into the eBPF pipeline's `xdp_main_prog`.

3. **eBPF pipeline processing**: The full eBPF pipeline runs:
   `xdp_main → xdp_zone → xdp_conntrack → xdp_nat → xdp_forward`

4. **Fabric redirect in xdp_zone**: `try_fabric_redirect()` rewrites Ethernet
   MACs and calls `bpf_redirect_map(&tx_ports, fabric_ifindex, 0)` — zero-copy
   XDP redirect to the fabric parent interface.

5. **NAT in xdp_nat**: The eBPF pipeline applies NAT using **incremental checksum
   updates** (`csum_update` BPF helpers), NOT full L4 recompute. This is O(1).

### Key insight

The fabric path is already zero-copy XDP redirect with incremental NAT checksums.
The userspace DP's `recompute_l4_checksum_ipv4` (3.6% in the profile) only applies
to the DIRECT forwarding path (all RGs same node), NOT the fabric path. Fabric
packets never enter userspace — they go through the eBPF pipeline via tail call.

## Fabric NAT Flow (via eBPF Pipeline)

### Outbound: Client → Server (split-RG: fw0=LAN, fw1=WAN)

```
Client 10.0.61.102:43446 → 172.16.80.200:5201

1. Arrives on ge-0-0-1 (fw0, LAN)
2. XDP shim → PASS_TO_KERNEL (RG1 demoted)
3. Tail call → eBPF xdp_main
4. xdp_zone: try_fabric_redirect → rewrite MACs → bpf_redirect_map(ge-0-0-0)
   NOTE: NAT is NOT applied here — the packet crosses fabric with original IPs.
   xdp_zone sends to fabric BEFORE xdp_nat runs (fabric redirect short-circuits).
5. Arrives at fw1 ge-7-0-0 (fabric parent)
6. XDP shim → PASS_TO_KERNEL or XSK redirect
7. fw1 processes → conntrack finds synced session → xdp_nat applies SNAT
8. Forwards out ge-7-0-2 (WAN) with src=172.16.80.8:43446
```

### Return: Server → Client

```
Server 172.16.80.200:5201 → 172.16.80.8:43446

1. Arrives on ge-7-0-2 (fw1, WAN)
2. fw1 conntrack → reverse session → xdp_nat applies un-SNAT (dst→10.0.61.102)
3. xdp_zone: egress is reth1 (RG2 on fw0) → try_fabric_redirect
4. bpf_redirect_map(ge-7-0-0) → zero-copy to fw0
5. Arrives at fw0 ge-0-0-0 (fabric parent)
6. fw0 eBPF pipeline → conntrack → forwards to ge-0-0-1 (LAN)
7. Client receives dst=10.0.61.102:43446
```

### NAT is applied by the eBPF pipeline, NOT the userspace DP

- **Outbound**: NAT happens on fw1 (the WAN owner) after receiving from fabric
- **Return**: NAT happens on fw1 before fabric redirect to fw0
- Incremental checksum updates — O(1) per packet
- No `recompute_l4_checksum_ipv4` involved for fabric traffic

## Why apply_nat_on_fabric Exists (and When It Matters)

The `apply_nat_on_fabric` flag in the userspace DP only matters for packets that
go through the XSK path (NOT `PASS_TO_KERNEL`). This happens when:

- A NEW session is created that resolves to `FabricRedirect` (before the
  `PASS_TO_KERNEL` BPF map entry is written)
- The XDP shim redirects to XSK (no BPF map entry yet)
- The Rust helper processes the packet and routes it via fabric XSK TX

In this transient case, the userspace DP applies NAT before fabric TX and
uses full L4 checksum recompute. But this only affects the first few packets
of a new session — once the `PASS_TO_KERNEL` entry is written, subsequent
packets go through the eBPF pipeline.

## Actual Bottleneck: Virtio Bridge Throughput

The fabric path runs at 3.5 Gbps with CPUs mostly idle (~2% peak in profiles).
This is NOT a CPU bottleneck — it's the virtio-net bridge throughput between VMs.

### Contributing factors

1. **Generic XDP on virtio**: The fabric parent uses generic XDP (no driver-mode
   support). `bpf_redirect_map` on generic XDP still creates an sk_buff and copies
   data — it's NOT true zero-copy like native/driver XDP redirect.

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

### Phase 2: Reduce Transient XSK Path Overhead [MEDIUM effort]

For the first few packets of new fabric-redirect sessions that go through XSK
before the `PASS_TO_KERNEL` entry is written:

1. **Write `PASS_TO_KERNEL` entry immediately** when a session resolves to
   `FabricRedirect` — don't wait for the next control socket sync. This
   minimizes the window where packets go through the slow XSK path.

2. **Incremental L4 checksum in `build_forwarded_frame_into_from_frame`** —
   replace `recompute_l4_checksum_ipv4` with incremental adjustment for
   the transient XSK packets. Implementation challenge: `enforce_expected_ports`
   also modifies checksums, so all adjustments must be done in a single pass:
   - Capture pre-NAT IPs and ports
   - Apply NAT (`apply_nat_ipv4`)
   - Apply port enforcement (`enforce_expected_ports`)
   - Compute combined incremental delta for IPs + ports
   - Write final checksum once

### Phase 3: Reduce `cached_flow_decision_valid` Overhead [MEDIUM effort]

The per-packet HA check on flow cache hits costs 1.3% CPU on the direct path.
Can't remove it (breaks fabric redirect), but can optimize:

1. **Epoch-based short-circuit**: Track a `last_ha_transition_epoch` counter that
   increments on every RG demotion/activation. Workers cache this locally. If the
   cached epoch matches the global one, skip the full BTreeMap HA check — the state
   hasn't changed since the cache entry was created.

2. **Inline the hot path**: The common case is `owner_rg_id > 0`, RG found in
   ha_state, `is_forwarding_active` returns true. Profile the branch prediction
   and ensure the happy path has no function call overhead.

### Phase 4: Reduce eBPF Pipeline NAT Overhead [LOW effort]

The eBPF pipeline's NAT already uses incremental checksums, but can be profiled
for micro-optimizations:

1. **Profile `xdp_nat.c`** during fabric -P8 to find hot spots
2. **Reduce map lookups**: Cache `fabric_fwd_info` in per-CPU scratch to avoid
   repeated `bpf_map_lookup_elem` calls (already partially implemented via
   `fabric_ingress_match` caching)
3. **Skip conntrack for fabric-ingress**: Packets arriving from fabric were
   already conntrack'd by the sender — the receiver could skip re-lookup

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
the virtio bridge path (TX ring, generic XDP overhead), not CPU processing.

### Direct Path -P8 (23 Gbps, for comparison)
```
15.9%  poll_binding              — packet processing
10.3%  enqueue_pending_forwards   — frame build + segmentation
 2.0%  parse_session_flow         — packet parsing
 1.5%  drain_pending_tx           — TX completions
 1.3%  cached_flow_decision_valid — HA check (per-packet)
 1.2%  target_index               — binding lookup
```

## Completed Optimizations

- [x] Virtio RX ring 256→1024 (`raw.qemu rx_queue_size=1024`)
- [x] FabricRedirect flow cache cacheable
- [x] Cache BPF map FDs outside worker loop
- [x] Barrier pause/drain for prompt failover
- [x] Forward session push to workers on RG activation
- [x] Fabric link preservation in shared_forwarding across snapshots
