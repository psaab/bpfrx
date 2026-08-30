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
///
/// **Intentionally NOT `Default`.** Codex round-1 review on
/// PR #1168 flagged that a `#[derive(Default)]` would silently
/// produce zero-capacity Vecs on accidental
/// `WorkerScratch::default()` calls, regressing the no-allocation-
/// on-hot-path contract. The only legal construction path is the
/// explicit literal in `BindingWorker::create` which carries the
/// per-Vec `with_capacity` hints.
pub(crate) struct WorkerScratch {
    pub(crate) scratch_recycle: Vec<u64>,
    pub(crate) scratch_forwards: Vec<PendingForwardRequest>,
    pub(crate) scratch_fill: Vec<u64>,
    pub(crate) scratch_prepared_tx: Vec<PreparedTxRequest>,
    pub(crate) scratch_local_tx: Vec<(u64, TxRequest)>,
    /// #5157: identity of the local-TX items that `transmit_batch`
    /// actually committed, as ORIGINAL-`pending` positions (0-based, in
    /// the order the caller built its per-item sidecars). Filled fresh
    /// on every `transmit_batch` call (cleared at entry). Needed because
    /// the mirror-reserve back-pressure drops a `mirror_clone` request
    /// mid-batch via `continue` — a NON-prefix / interior removal — so
    /// the committed set is no longer a prefix of the input. Only
    /// `submit_local` reads it (to charge flow-bucket / sojourn
    /// accounting to the correct flow); other `transmit_batch` callers
    /// ignore it.
    pub(crate) scratch_committed_orig_idx: Vec<u16>,
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
    /// #7212: forward + reverse keys of every session this poll pass REVOKED
    /// because a static interface INPUT filter now denies it.
    ///
    /// Deferred rather than evicted inline for the same borrow-checker reason as
    /// `scratch_cross_binding_tx`: the eviction has to run on EVERY binding of
    /// this worker (a session does not carry the ingress ifindex the flow cache
    /// is keyed on, and the two directions of one flow can be cached on
    /// different bindings), and the RX loop holds `&mut BindingWorker` for one
    /// binding only. `worker/lifecycle.rs` drains it under the
    /// `left`/`current`/`right` split borrow, in the SAME tick, before any
    /// further packet is processed.
    ///
    /// Bounded by the revocation rate — one push per direction per revoked
    /// session, and a session is revoked at most once because the teardown
    /// removes it — so this is not a per-packet allocation site. Drained and
    /// returned to the binding each pass, keeping its capacity.
    pub(crate) scratch_filter_revoked_keys: Vec<SessionKey>,
}
