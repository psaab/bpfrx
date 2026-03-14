# Shared UMEM Implementation Plan (#205)

## Problem

Cross-interface AF_XDP forwarding copies each 1500-byte frame between
separate UMEM regions (11.5% CPU at 20 Gbps). This is the primary
remaining bottleneck preventing the userspace dataplane from reaching
native XDP line rate (22 Gbps on 25G mlx5).

## Goal

Eliminate cross-UMEM memcpy by sharing a single UMEM region across all
AF_XDP bindings within the same worker thread. Frames received on one
binding can be rewritten in-place and submitted directly to another
binding's TX ring without any copy.

## Current Architecture

```
Worker 0
  ├── Binding A (ge-0-0-1 queue 0)
  │     ├── WorkerUmem A  (own MmapArea, own Umem)
  │     ├── Socket A       (own FD)
  │     ├── Fill/Completion rings A
  │     └── RX/TX rings A
  └── Binding B (ge-0-0-2 queue 0)
        ├── WorkerUmem B  (own MmapArea, own Umem)
        ├── Socket B       (own FD)
        ├── Fill/Completion rings B
        └── RX/TX rings B

Forward A→B: copy frame from UMEM-A to UMEM-B (memcpy ~1500 bytes)
```

## Target Architecture

```
Worker 0
  ├── SharedUmem (one MmapArea, one Umem)
  ├── Binding A (ge-0-0-1 queue 0)
  │     ├── Socket A (with_shared → same UMEM FD)
  │     ├── Fill/Completion rings A (per-socket)
  │     └── RX/TX rings A
  └── Binding B (ge-0-0-2 queue 0)
        ├── Socket B (with_shared → same UMEM FD)
        ├── Fill/Completion rings B (per-socket)
        └── RX/TX rings B

Forward A→B: rewrite frame in-place at same offset, submit to TX-B (zero copy)
```

## Implementation Steps

### Step 1: Create shared UMEM in worker_loop (not BindingWorker)

Move UMEM creation from `BindingWorker::create()` to the worker thread
startup in `worker_loop()`. All bindings in the worker share one UMEM.

```rust
// In worker_loop(), before creating bindings:
let total_frames_per_binding = binding_frame_count(ring_entries);
let total_shared_frames = total_frames_per_binding * (binding_plans.len() as u32);
let shared_umem = WorkerUmem::new(total_shared_frames)?;

// Global free frame pool for this worker
let mut free_frames: VecDeque<u64> = VecDeque::with_capacity(total_shared_frames as usize);
for idx in 0..total_shared_frames {
    if let Some(frame) = shared_umem.umem.frame(BufIdx(idx)) {
        free_frames.push_back(frame.offset);
    }
}
```

### Step 2: Change BindingWorker::create to accept shared UMEM

New signature:

```rust
fn create_shared(
    binding: &BindingStatus,
    shared_umem: &WorkerUmem,   // borrowed, owned by worker
    is_first: bool,             // first binding creates the "owner" socket
    ring_entries: u32,
    initial_fill: &mut VecDeque<u64>,  // take frames from shared pool
    initial_tx: &mut VecDeque<u64>,    // take TX frames from shared pool
    ...
) -> Result<Self, ...>
```

- First binding: `Socket::new(info)` then register UMEM
- Subsequent bindings: `Socket::with_shared(info, &shared_umem.umem)`
- Each binding takes its share of frames from the global pool for fill ring

### Step 3: Unify frame management

Remove per-binding `free_tx_frames` and `pending_fill_frames`. Replace
with a worker-level shared pool.

```rust
struct WorkerFramePool {
    free: VecDeque<u64>,          // frames not in any ring
    fill_deficit: [u32; MAX_BINDINGS],  // how many fill frames each binding needs
}
```

After each poll cycle:
1. Reap TX completions from each binding → return offsets to `free`
2. Reap fill frames needed → distribute from `free` to binding fill rings
3. Process RX → forward frames in-place (no allocation needed)

### Step 4: Enable in-place rewrite for all same-worker bindings

Change the forwarding decision:

```rust
// OLD:
let can_rewrite_in_place = target_binding.slot == ingress_slot;

// NEW: All bindings in same worker share UMEM → always in-place
let can_rewrite_in_place = true;  // within same worker, always shared UMEM
```

When `rewrite_forwarded_frame_in_place` succeeds:
- Submit the same frame offset to target binding's TX ring
- Mark frame as "in flight" (don't return to fill ring yet)
- On TX completion, return to shared free pool
- From free pool, replenish source binding's fill ring

### Step 5: Handle the copy fallback path

`rewrite_forwarded_frame_in_place` can fail when the Ethernet header
size changes (14→18 for VLAN insert, or 18→14 for VLAN strip). In this
case, the payload needs to be shifted within the frame (memmove, not
cross-UMEM copy).

The in-place function already handles this with `copy_within()`:
```rust
if eth_len != l3 {
    frame.copy_within(l3..l3 + payload_len, eth_len);
}
```

This is a 4-byte shift of the payload, vastly cheaper than a full
1500-byte cross-UMEM copy. So even the "fallback" is near-zero-copy.

The remaining fallback (build_forwarded_frame_from_frame → Vec<u8>)
should only trigger when in-place rewrite fails for other reasons
(malformed frames, etc.). This path can allocate from the shared free
pool instead of per-binding free_tx_frames.

### Step 6: Frame accounting and leak detection

Current per-binding accounting:
```
total = pending_fill + fill_ring + rx_ring + free_tx + outstanding_tx
        + in_flight_recycles + scratch + prepared_tx
```

New worker-level accounting:
```
total = shared_pool.free
        + sum(binding.fill_ring_pending)
        + sum(binding.rx_avail)
        + sum(binding.outstanding_tx)
        + sum(binding.in_flight_forwards)
        + sum(binding.prepared_tx)
```

The invariant `total == shared_umem.total_frames` must hold.

### Step 7: Fill ring rebalancing

Each binding's fill ring needs frames to receive packets. After TX
completions return frames to the shared pool, distribute them:

```rust
fn rebalance_fill_rings(
    bindings: &mut [BindingWorker],
    pool: &mut WorkerFramePool,
) {
    // Round-robin distribute free frames to bindings that need fill
    let per_binding_target = pool.total / bindings.len();
    for binding in bindings {
        let deficit = per_binding_target - binding.fill_ring_count();
        let give = deficit.min(pool.free.len());
        for _ in 0..give {
            if let Some(offset) = pool.free.pop_front() {
                binding.submit_fill(offset);
            }
        }
    }
}
```

## Performance Impact Estimate

- memcpy (AVX-512 1500B copy): 11.5% CPU → eliminated
- `build_forwarded_frame_into_from_frame`: 1.64% CPU → replaced by in-place (0.3%)
- Net CPU savings: ~12.8%
- Expected throughput: 20 Gbps / (1 - 0.128) ≈ 23 Gbps (exceeds 22 Gbps target)

## Risk Mitigation

1. **xdpilone shared socket support**: Already uses `Socket::with_shared()`
   — the API exists and is used (shared_owner=true). Need to verify it
   works when multiple sockets share one UMEM across different interfaces.

2. **Fill ring starvation**: If one direction has burst traffic, it could
   drain the shared pool and starve the other binding's fill ring. The
   rebalance logic must ensure minimum fill frames per binding.

3. **Frame leak**: Shared accounting is harder to debug. Keep per-binding
   tracking of "frames I donated to the pool" for leak detection.

4. **VLAN header size change**: In-place rewrite handles this via
   `copy_within()` (4-byte shift). Verified this already works in
   `rewrite_forwarded_frame_in_place`.

5. **Segmentation (TSO)**: Segmented frames create multiple TX descriptors
   from one RX frame. This needs special handling — the source frame
   cannot be returned to fill ring until ALL segments are transmitted.
   Current code already handles this via `in_flight_forward_recycles`.

## Files Modified

| File | Change |
|------|--------|
| `userspace-dp/src/afxdp.rs` | Shared UMEM creation, frame pool, in-place forwarding |

## Result: NOT FEASIBLE (2026-03-14)

**Shared UMEM across different NICs does not support zero-copy mode.**

The loss cluster has two Mellanox ConnectX-5 NICs on separate PCI buses:
- ge-0-0-1: `0000:08:00.0` (mlx5_core)
- ge-0-0-2: `0000:09:00.0` (mlx5_core)

AF_XDP zero-copy requires the NIC driver to DMA-map the UMEM pages. When
two sockets share one UMEM but bind to different physical NICs, the second
socket's `bind()` fails with `EINVAL` because the mlx5 driver cannot map
pages already DMA-mapped by a different device. The fallback is copy mode
for the second socket, which means:

- First socket: zero-copy (no memcpy on RX/TX)
- Second socket: copy mode (kernel copies every frame into/out of UMEM)

This is **worse** than the original per-binding UMEM approach where both
sockets run in zero-copy mode with a single user-space memcpy for cross-
interface forwarding.

### What would make this work

Shared UMEM zero-copy works when all sockets bind to the **same NIC**
(same PCI device, different queues). This applies to:
- Multi-queue on a single NIC (RSS distribution)
- VLAN sub-interfaces on the same physical port

For cross-NIC forwarding, the memcpy is unavoidable at the AF_XDP level.
The remaining optimization path is to make the existing memcpy cheaper
(e.g., page flipping, io_uring registered buffers, or batched copies
with prefetch).

### Changes reverted

The implementation in `userspace-dp/src/afxdp.rs` was reverted to the
per-binding UMEM approach. This plan document is retained for reference.

## Original Testing Plan

1. `cargo build --release` — compiles
2. Deploy to loss cluster: `loss:bpfrx-userspace-fw0` + `loss:bpfrx-userspace-fw1`
3. Forward throughput: `iperf3 -c 172.16.80.200 -P 8 -t 10` from `loss:cluster-userspace-host`
4. Reverse throughput: same with `-R`
5. Profile: `perf record -a -g --freq=997` — verify memcpy eliminated
6. Verify frame accounting: no FRAME_LEAK in debug output
7. HA failover: verify sessions survive failover
