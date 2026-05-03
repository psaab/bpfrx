//! #959 Phase 7 — extracts the per-binding TX pipeline state out of
//! `BindingWorker` into a dedicated `WorkerTxPipeline` sub-struct.
//! #959 Phase 10 — adds `outstanding_tx` to this same sub-struct
//! (was held back from Phase 7 to avoid collision with the
//! `BindingStatus.outstanding_tx` snapshot mirror; the type-level
//! disambiguation now keeps the two distinct).
//!
//! These eight fields hold the per-binding TX pipeline buffers and
//! the per-frame submit-timestamp sidecar:
//!
//! - `free_tx_frames` — UMEM frame addresses available for TX.
//! - `pending_tx_prepared` — TX-ready requests awaiting ring submit.
//! - `pending_tx_local` — local-TX requests awaiting ring submit.
//! - `max_pending_tx` — TX backpressure threshold (configured once).
//! - `outstanding_tx` — transient gauge of in-flight TX descriptors
//!   (incremented when a TX ring descriptor is inserted, decremented
//!   when the completion ring is reaped — `sendto` is the wake/kick,
//!   not the increment site). Mirrored to
//!   `BindingLiveState.debug_outstanding_tx` once per debug tick so
//!   the snapshot reader sees a recent value (#802).
//! - `pending_fill_frames` — fill-ring back-pressure queue.
//! - `in_flight_prepared_recycles` — completion-time recycle map.
//! - `tx_submit_ns` — per-UMEM-frame submit timestamp sidecar
//!   (#812). Pre-allocated to total UMEM frames at construction;
//!   never grown. `Box<[u64]>` (not `Vec<u64>`) at the type level
//!   so any future `push` attempt fails to compile.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-7/10. Field names preserved so
//! `binding.tx_pipeline.free_tx_frames` keeps the same grep-friendly
//! suffix as the original `binding.free_tx_frames`.

use super::*;

/// Per-binding TX pipeline state. See module-level docs.
///
/// **Intentionally NOT `Default`** — `tx_submit_ns` must be sized
/// to `total_frames` at construction, not zero-length. Construction
/// goes through the explicit literal in `BindingWorker::create`
/// which receives `total_frames` from the BindingPlan.
pub(crate) struct WorkerTxPipeline {
    pub(crate) free_tx_frames: VecDeque<u64>,
    pub(crate) pending_tx_prepared: VecDeque<PreparedTxRequest>,
    pub(crate) pending_tx_local: VecDeque<TxRequest>,
    pub(crate) max_pending_tx: usize,
    /// Transient gauge of in-flight TX descriptors — incremented
    /// when a TX ring descriptor is inserted (the
    /// `saturating_add(inserted)` sites in tx/transmit.rs and the
    /// CoS direct-submit paths in cos/queue_service/service.rs),
    /// decremented when the completion ring is reaped
    /// (saturating_sub in tx/rings.rs). `sendto` is the wake/kick
    /// of the kernel TX path, NOT the increment site. Mirrored once
    /// per debug tick to `BindingLiveState.debug_outstanding_tx`
    /// for the snapshot reader (#802). NOT a counter — a
    /// saturating gauge of in-flight work.
    pub(crate) outstanding_tx: u32,
    pub(crate) pending_fill_frames: VecDeque<u64>,
    pub(crate) in_flight_prepared_recycles: FastMap<u64, PreparedTxRecycle>,
    /// #812 per-UMEM-frame submit timestamp sidecar. Indexed by
    /// `offset >> UMEM_FRAME_SHIFT`. Pre-allocated to total UMEM
    /// frames at `BindingWorker::create` so the hot-path stamp
    /// write is a single store — NO allocation, NO grow.
    /// `Box<[u64]>` (not `Vec<u64>`) at the type level so any
    /// future `push` attempt fails to compile (Rust round-1 MED-1).
    /// Unstamped slots hold `TX_SIDECAR_UNSTAMPED` (`u64::MAX`); the
    /// reap path skips the histogram increment for these to avoid
    /// biasing the tail toward bucket 0 (plan §5.4).
    pub(crate) tx_submit_ns: Box<[u64]>,
}
