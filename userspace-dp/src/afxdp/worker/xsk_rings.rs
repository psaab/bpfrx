//! #959 Phase 11 — extracts the three XSK kernel-ring handles
//! (`device`, `rx`, `tx`) out of `BindingWorker` into a dedicated
//! `WorkerXskRings` sub-struct.
//!
//! These are the per-binding handles to the kernel AF_XDP socket
//! rings:
//!
//! - `device` — the `DeviceQueue` that owns the underlying XSK file
//!   descriptor and the fill / completion ring pair (kernel-side
//!   pacing).
//! - `rx` — the RX ring (`RingRx`); `available()` / `receive()` /
//!   `as_raw_fd()` are the hot-path entry points.
//! - `tx` — the TX ring (`RingTx`); `transmit()` writes descriptors,
//!   `needs_wakeup()` + `as_raw_fd()` drive the sendto kick.
//!
//! Pure structural extraction: ring objects, bind ordering, FD
//! lifetimes, and access semantics are all unchanged from master
//! pre-Phase-11. Field names preserved so `binding.xsk.rx` keeps
//! the same grep-friendly suffix as the original `binding.rx`.
//!
//! Phase 11 is the last #959 BindingWorker decomposition phase —
//! it was held back as the highest-risk because of the snapshot-
//! mirror name collisions on `off.rx` / `off.tx` (XDP socket ring
//! offsets in `bpf_map.rs`) and `telemetry.dbg.rx` / `.tx`
//! (in-loop diagnostic counters in `poll_descriptor.rs`). Both
//! disambiguate by alias prefix (`off.` and `dbg.` vs the
//! `binding`/`b`/`sb`/`target_binding` aliases used for the
//! BindingWorker rings) so the rewrite is purely mechanical.

use super::*;

/// Per-binding XSK ring handles. See module-level docs.
///
/// **Intentionally NOT `Default`** — the rings are constructed
/// from `open_binding_worker_rings()` which performs the kernel
/// `bpf()`/`mmap()` system calls; a default-derived value would
/// hold dangling FDs.
pub(crate) struct WorkerXskRings {
    pub(crate) device: crate::xsk_ffi::DeviceQueue,
    pub(crate) rx: crate::xsk_ffi::RingRx,
    pub(crate) tx: crate::xsk_ffi::RingTx,
}
