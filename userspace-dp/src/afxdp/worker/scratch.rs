//! #959 Phase 2 — extracts the per-binding `scratch_*` reusable
//! buffers out of `BindingWorker` into a dedicated `WorkerScratch`
//! sub-struct.
//!
//! These vectors are pre-allocated once and reused every poll cycle
//! to avoid per-packet allocations. They're cleared at the start of
//! each cycle and pushed-to as the descriptor loop produces work for
//! the TX submit / fill / recycle / cross-binding handoff stages.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-2. Field names preserved so the
//! `binding.scratch.scratch_X` access pattern keeps the same
//! grep-friendly suffix as the original `binding.scratch_X`.
//! (Rust's default `repr(Rust)` does not guarantee layout, so this
//! says nothing about field ordering or struct size.)

use super::*;

/// Per-binding reusable scratch buffers cleared each poll cycle.
///
/// Naming preserves the historical `scratch_*` prefix inside the
/// struct so callers find the same field name with `.scratch.` in
/// front: `binding.scratch.scratch_recycle` (was
/// `binding.scratch_recycle`).
#[derive(Default)]
pub(crate) struct WorkerScratch {
    pub(crate) scratch_recycle: Vec<u64>,
    pub(crate) scratch_forwards: Vec<PendingForwardRequest>,
    pub(crate) scratch_fill: Vec<u64>,
    pub(crate) scratch_prepared_tx: Vec<PreparedTxRequest>,
    pub(crate) scratch_local_tx: Vec<(u64, TxRequest)>,
    pub(crate) scratch_exact_prepared_tx: Vec<ExactPreparedScratchTxRequest>,
    pub(crate) scratch_exact_local_tx: Vec<ExactLocalScratchTxRequest>,
    pub(crate) scratch_completed_offsets: Vec<u64>,
    pub(crate) scratch_post_recycles: Vec<(u32, u64)>,
    /// Flow cache fast-path: cross-binding in-place rewrites
    /// deferred until after the RX batch (the borrow checker
    /// prevents mutable access to two bindings simultaneously
    /// inside the RX loop). Reserved for the cross-binding
    /// fast-path; not yet wired (hence `#[allow(dead_code)]`).
    #[allow(dead_code)]
    pub(crate) scratch_cross_binding_tx: Vec<(usize, PreparedTxRequest)>,
    pub(crate) scratch_rst_teardowns: Vec<(SessionKey, NatDecision)>,
}
