# Triage Result — ps-review-040 A1 Batch 6

Base of review: `03a92b49` (STALE). Re-verified against origin/master
`59d8186d5` via `git show origin/master:<path>`. Main checkout NOT used.

Batch 6 = 1 substantive finding + ~70 module "negative results".

## Finding 1 — UB via shared-to-mutable pointer cast in `ReadRx` (Medium, memory-safety)
Extra scrutiny applied per instruction (memory-safety finding).

- SYMBOL-EXISTS: **YES**, on current origin/master:
  - `userspace-dp/src/xsk_ffi.rs:865-866` — `pub struct ReadRx<'a> { ring: &'a XskRingCons, .. }` (SHARED ref).
  - `xsk_ffi.rs:759-766` — `RingRx::receive(&mut self)` builds `ReadRx { ring: &*self.ring, .. }`.
  - `xsk_ffi.rs:894` — `release()`: `self.ring as *const XskRingCons as *mut XskRingCons` then `bridge_xsk_ring_cons_release(ring_ptr, ..)`.
  - `xsk_ffi.rs:903-911` — `Drop::drop()`: same const-cast for `bridge_xsk_ring_cons_release` / `bridge_xsk_ring_cons_cancel`.
  - `XskRingCons` (xsk_ffi.rs:29-39) is plain `#[repr(C)]`, **no `UnsafeCell`.**
  (Review quoted lines 890-896/901-913; drifted a few lines under the stale base
  but the code is unchanged in substance.)
- ALREADY-FIXED: **No.** The const-cast writes are still present verbatim.
- REAL+MATERIAL: **YES.**
  - Writing through a `*mut` derived from a `&T` with no `UnsafeCell` is UB under
    Rust's aliasing model (Stacked/Tree Borrows); the bridge mutates `cached_cons`
    and the shared `*consumer`. Miri flags it; LTO/opt may miscompile.
  - **Reachable in production**: `RingRx::receive` is NOT `cfg(test)` — it is the
    real per-poll RX drain path. (`new_for_test`/`push_for_test` are the only
    cfg(test) members.)
  - The in-code "exclusive logical access" safety comment does not make the cast
    sound — soundness is a property of the reference *type*, not runtime exclusivity.
  - Fix is trivial and already demonstrated by the sibling completion-ring reader
    `ReadComplete` (xsk_ffi.rs:1033-1074), which holds `ring: &'a mut XskRingCons`
    and calls the release bridge with NO cast; `WriteTx` likewise holds `&'a mut`.
    `ReadRx` is the sole ring reader holding a shared ref. `receive` already takes
    `&mut self`, so a `&mut` reborrow is available.
  - Not a retired-eBPF path; not bench-only.
- DEDUP: Not tracked by any open issue. Nearest neighbor #4976 (afxdp libxdp ABK
  mirror ABI check) is a different concern (layout coupling, not UB write). Not a dup.
- **VERDICT: FILED #4997** (labels `bug`, `security`).

## Negative results (~70 modules)
Sweep of main/policy/prefix/protocol/screen/server/session/slowpath/state_writer/
tcp_flags/xsk_ffi_tests + tests/*. No defects asserted; nothing to file.

## Counts (Batch 6)
- Filed: 1 (#4997)
- Dup: 0
- Already-fixed: 0
- Not-material: 0
