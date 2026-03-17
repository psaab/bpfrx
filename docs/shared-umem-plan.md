# Shared UMEM Implementation Plan (#205)

Status: In Progress

## Problem

Cross-interface AF_XDP forwarding still copies each frame between
separate UMEM allocations. On current `master`, the steady-state hot
transit path is not the copy-path fallback; it is the direct TX builder
itself. The measured profile on a live transit run shows:

- `bpfrx_userspace_dp::afxdp::poll_binding` about `17.6%`
- `__memmove_evex_unaligned_erms` about `16.7%`
- `bpfrx_userspace_dp::afxdp::frame::enqueue_pending_forwards` about `5.8%`

Helper counters on the same run showed:

- `Direct TX packets`: climbing rapidly
- `Copy-path TX packets`: `0`
- `Slow path injected`: `0`

So the remaining copy bottleneck is the full-payload copy inside the
direct path in `build_forwarded_frame_into_from_frame()`:

```rust
out.get_mut(eth_len..frame_len)?.copy_from_slice(payload);
```

This is the primary remaining bottleneck preventing the userspace
dataplane from reaching native XDP line rate on transit traffic.

## Goal

Eliminate the direct-path cross-UMEM payload copy where that is safe.
The viable target is no longer "all bindings in a worker share one
UMEM". The viable target is:

- same-device shared UMEM only
- `mlx5_core` only
- no cross-NIC shared UMEM
- no `virtio_net` shared UMEM

Frames received on one binding can then be rewritten in-place and
submitted directly to another binding's TX ring without any copy, but
only when both bindings share the same physical device and the same UMEM
allocation.

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
  ├── SharedUmem group for mlx5 device 0000:08:00.0
  ├── Binding A (ge-0-0-1 queue 0, same device)
  │     ├── Socket A (with_shared → shared UMEM FD)
  │     ├── Fill/Completion rings A (per-socket)
  │     └── RX/TX rings A
  └── Binding B (same physical device / queue or sub-interface)
        ├── Socket B (with_shared → shared UMEM FD)
        ├── Fill/Completion rings B (per-socket)
        └── RX/TX rings B

Forward A→B: rewrite frame in-place at same offset, submit to TX-B (zero copy)

Bindings on different physical devices keep private UMEM and still copy.
```

## Implementation Steps

### Step 1: Identify safe shared-UMEM groups

At worker startup, group bindings by `(driver, device_path)`.

- only `mlx5_core` with a non-empty device path is eligible
- only groups with two or more bindings are candidates
- `virtio_net` is always excluded
- different PCI devices are always excluded

### Step 2: Create one UMEM pool per eligible device group

Create a `WorkerUmemPool` per eligible group, not per worker. Each pool owns:

- one `WorkerUmem`
- one `VecDeque<u64>` of free frame offsets

Bindings with no eligible group still allocate a private pool and behave exactly
like current `master`.

### Step 3: Pass the chosen UMEM pool into `BindingWorker::create()`

`BindingWorker::create()` now accepts:

- the `WorkerUmem` to use
- a mutable frame pool for reserved TX and initial fill offsets
- a `shared_umem` flag for diagnostics

This preserves current bind/open behavior while moving UMEM ownership out of the
binding constructor.

### Step 4: Widen in-place rewrite eligibility to same-allocation forwards

The forwarding predicate changes from "same binding only" to "same UMEM allocation":

```rust
let can_rewrite_in_place =
    target_binding.umem.allocation_ptr() == ingress_binding.umem.allocation_ptr();
```

This keeps the optimization narrow:

- same-binding hairpin still works
- same-device shared-UMEM bindings can now rewrite in place
- cross-device forwards still take the existing direct builder copy path

### Step 5: Keep current recycle and ownership semantics

This prototype does not attempt a full worker-global frame rebalance rewrite.
It keeps the existing prepared-TX recycle model and only changes how eligible
bindings source their offsets up front. That makes the prototype materially safer
than the older "share everything in the worker" plan.

### Step 6: Validate the safe boundary

The prototype is only acceptable if:

- it compiles and unit-tests cleanly
- `virtio_net` behavior is unchanged
- cross-NIC `mlx5` behavior is unchanged
- same-allocation forwards can use the in-place path
- no bind strategy regressions are introduced

## Performance Impact Estimate

- For eligible same-device paths, this should eliminate the direct-path payload
  copy that currently shows up as about `16.7%` `memmove`.
- For the current HA lab's cross-NIC transit path, this should not be expected
  to improve throughput by itself.
- The right expectation is structural correctness first, then targeted same-device
  performance gains where the topology actually permits shared UMEM.

## Risk Mitigation

1. **xdpilone shared socket support**: Already uses `Socket::with_shared()`
   — the API exists and is used (shared_owner=true). Need to verify it
   works when multiple sockets share one UMEM across bindings on the same
   physical device.

2. **Scope control**: Do not silently widen this to `virtio_net` or cross-NIC
   `mlx5`. Those are known bad directions in this environment.

3. **Frame leak**: Shared accounting is harder to debug. Keep the existing
   per-binding recycle semantics until the same-device path is proven.

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
| `userspace-dp/src/afxdp.rs` | `WorkerUmem` ownership model, grouped UMEM pool creation, tests |
| `userspace-dp/src/afxdp/bind.rs` | driver/device grouping helpers, UMEM accessor updates |
| `userspace-dp/src/afxdp/frame.rs` | same-allocation in-place forwarding predicate |
| `userspace-dp/src/afxdp/tx.rs` | UMEM accessor updates for shared allocation support |

## Result: Broad Cross-NIC Shared UMEM Is Not Feasible (2026-03-14)

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
(e.g., page flipping, io_uring registered buffers, or batched copies).

## Current Prototype Status (2026-03-17)

The safe reintegration path is now started in the code on the prototype
branch, but live validation exposed two important limits:

- the current HA lab does not have a proof topology for this prototype
- the current implementation is not yet deployable on the HA lab because
  shared UMEM still uses the wrong AF_XDP queue ownership contract

### Narrow scope

- group bindings by `(driver, device_path)`
- only create a shared group for same-device `mlx5_core`
- keep `virtio_net` on private UMEM
- keep cross-NIC traffic on private UMEM

### Current prototype shape

1. `BindingWorker::create()` no longer unconditionally allocates its own
   UMEM.
2. Worker startup can create a `WorkerUmemPool` for eligible same-device
   groups.
3. Bindings in the same eligible group clone the same `WorkerUmem`
   allocation and draw offsets from the same frame pool.
4. In-place rewrite eligibility is widened from "same binding only" to
   "same UMEM allocation".

### What this can and cannot improve

This prototype can improve:

- same-NIC transit between bindings on the same `mlx5` device
- same-device VLAN/sub-interface forwarding
- any worker-local forward where ingress and egress share the same UMEM

This prototype will not, by itself, fix the current HA lab's main
cross-NIC transit bottleneck, because the hot path there still crosses
different physical devices and therefore still requires a copy.

### What live validation actually proved

On the current HA lab:

- `ge-0-0-1`/`ge-7-0-1` and `ge-0-0-2`/`ge-7-0-2` are different physical
  `mlx5` PCI devices
- the WAN50 -> WAN80 path on the active owner already collapses to the
  existing in-place hairpin behavior on `master`
- that means WAN50 -> WAN80 is only a no-regression check, not proof
  that the new same-allocation cross-binding path is exercised

So the current lab can answer:

- did the prototype regress an existing same-device-ish path?

It cannot answer:

- did the prototype materially improve a true same-device cross-binding
  forward path?

### Current implementation gap

The current prototype shares one `WorkerUmem` across multiple bindings in
the same `(driver, device_path)` group, but still opens per-binding AF_XDP
ring ownership the same way as private UMEM bindings.

In live deployment this caused the second queue on the shared group to fail
with:

- `configure AF_XDP rings: create fq/cq: Device or resource busy`

That means the next implementation step is not more performance work. It is
correct AF_XDP shared-UMEM bring-up:

1. establish the right FQ/CQ ownership model for one shared UMEM
2. bind secondary queues/sockets against that owner correctly
3. only then retry same-device throughput validation

### Success criteria for the prototype

- compile and unit-test cleanly on current `master`
- preserve current per-binding bind strategy behavior for non-shared paths
- no change for `virtio_net`
- no change for cross-NIC traffic
- no AF_XDP bind regressions on multi-queue `mlx5`
- same-allocation forwards use the in-place rewrite path instead of the
  direct builder copy path

## Original Testing Plan

1. `cargo build --release` — compiles
2. Deploy to loss cluster: `loss:bpfrx-userspace-fw0` + `loss:bpfrx-userspace-fw1`
3. Forward throughput: `iperf3 -c 172.16.80.200 -P 8 -t 10` from `loss:cluster-userspace-host`
4. Reverse throughput: same with `-R`
5. Profile: `perf record -a -g --freq=997` — verify memcpy eliminated
6. Verify frame accounting: no FRAME_LEAK in debug output
7. HA failover: verify sessions survive failover
