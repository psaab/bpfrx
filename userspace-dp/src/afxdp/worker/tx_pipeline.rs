//! #959 Phase 7 — extracts the per-binding TX pipeline state out of
//! `BindingWorker` into a dedicated `WorkerTxPipeline` sub-struct.
//!
//! These seven fields hold the per-binding TX pipeline buffers and
//! the per-frame submit-timestamp sidecar:
//!
//! - `free_tx_frames` — UMEM frame addresses available for TX.
//! - `pending_tx_prepared` — TX-ready requests awaiting ring submit.
//! - `pending_tx_local` — local-TX requests awaiting ring submit.
//! - `max_pending_tx` — TX backpressure threshold (configured once).
//! - `pending_fill_frames` — fill-ring back-pressure queue.
//! - `in_flight_prepared_recycles` — completion-time recycle map.
//! - `tx_submit_ns` — per-UMEM-frame submit timestamp sidecar
//!   (#812). Pre-allocated to total UMEM frames at construction;
//!   never grown. `Box<[u64]>` (not `Vec<u64>`) at the type level
//!   so any future `push` attempt fails to compile.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-7. Field names preserved so
//! `binding.tx_pipeline.free_tx_frames` keeps the same grep-friendly
//! suffix as the original `binding.free_tx_frames`.
//!
//! NOT IN THIS PHASE: `outstanding_tx` (collides with the
//! `BindingStatus.outstanding_tx` snapshot mirror; deferred to a
//! tiny followup phase that handles the type disambiguation).

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
