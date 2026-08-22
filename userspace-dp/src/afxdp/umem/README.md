# userspace-dp/src/afxdp/umem/

UMEM (User-space Memory) management — the per-binding shared-memory
region where AF_XDP zero-copy frames live. Owns the `mmap` region,
wraps the crate-local `Umem` type from `xsk_ffi` (a libxdp-backed
drop-in for xdpilone), and tracks frame budgets per binding.

> #6436: the per-binding runtime-state cluster that historically
> lived here (`BindingLiveState`, the redirect TX inbox, the latency
> histogram primitives, the HA session-delta fallback buffer, and the
> snapshot/debug-state/profile renderers) moved to
> `../binding_state/`. This module is now only the memory region.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `WorkerUmem` / `WorkerUmemInner` / `WorkerUmemPool` — Rc-shared UMEM handle held by the owner worker, plus the free-frame pool. |
| `mmap.rs` | `MmapArea` — the raw `mmap` region. |
| `mmap_tests.rs` | Co-located mmap unit tests. |
| `tests/` | Co-located UMEM unit tests: `mod.rs` + `drop_order.rs` + `mmap_area.rs`. The binding-state concern tests moved to `../binding_state/tests/` in #6436 (the #4667 per-concern split maps 1:1 onto the new location). |

## Where it sits

- Constructed once per binding by the worker before AF_XDP socket
  bind.
- Consumed by `tx/` (frame submit), `frame/` (byte mutation), and
  the AF_XDP rings in `xsk_ffi`.

## Notable invariants

- **UMEM ownership is per-queue.** A flow that hashes to queue N is
  *physically tied* to worker N — there is no cross-worker
  descriptor sharing. This is the reason every "rebalance flows
  across workers" design has been plan-killed; see
  `docs/per-5-tuple/state.md` for the formal ceiling.
- **`WorkerUmemInner` field order is load-bearing (#5192).** `umem`
  is declared BEFORE `area` because Rust destroys struct fields in
  declaration order, and `xsk_ffi::Umem::new` is `unsafe` on the
  precondition that the mmap'd area outlives the `Umem`. Declared the
  other way round, `munmap` runs while the libxdp UMEM object is still
  registered against those pages — a latent use-after-free whose only
  defence is that `xsk_umem__delete` in the linked libxdp happens not
  to read the user area, which is an unpinned external library's
  implementation detail rather than an invariant this repo controls.
  Rust has no compile-time drop-order assertion, so the order is
  pinned by observation: both destructors record into
  `crate::drop_order_probe` under `cfg(test)` and
  `tests/drop_order.rs` asserts `[Umem, MmapArea]`. Swapping the two
  declarations back reds it.
- `Rc<WorkerUmemInner>` (not `Arc`) is intentional — UMEM ownership
  doesn't cross thread boundaries within the worker. The cross-binding
  redirect path in `cos/cross_binding.rs` *copies* frames into the
  destination binding's UMEM rather than sharing.
- `WorkerUmem::new_for_test` is hermetic test scaffolding paired with
  the in-memory ring fixtures in `xsk_ffi.rs`. It exists so CoS and TX
  unit tests can exercise worker-owned drain paths without creating
  kernel AF_XDP sockets; production UMEM construction remains
  `WorkerUmem::new`.
- In **zero-copy mode on mlx5**, an `XDP_PASS` action permanently
  consumes a fill-ring frame: the kernel holds the UMEM buffer in
  an SKB and never returns it. Sustained traffic drains all 12K+ RX
  frames within seconds. The mitigation (#209): the XDP shim
  replaces every `XDP_PASS` path with a cpumap redirect
  (`USERSPACE_CPUMAP`), which frees the XSK frame immediately while
  still delivering the packet to the kernel stack. Bind flags try
  zero-copy first and fall back to copy mode if the driver doesn't
  support it; copy mode is unaffected because `XDP_PASS` there
  operates on kernel DMA buffers, not UMEM frames.
