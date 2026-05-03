//! #959 Phase 3 — extracts the per-binding `cos_*` CoS-engine state
//! out of `BindingWorker` into a dedicated `WorkerCos` sub-struct.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-3. Field names preserved so the
//! `binding.cos.cos_X` access pattern keeps the same grep-friendly
//! suffix as the original `binding.cos_X`.
//!
//! Filename is `cos_state.rs`, not `cos.rs`, because the
//! `worker::cos` module already exists (it holds the worker-side
//! CoS runtime helpers). This module exclusively defines the data-
//! holding sub-struct.

use super::*;

/// Per-binding CoS scheduling state. Owned by the worker that owns
/// this binding.
///
/// **Intentionally NOT `Default`.** A `WorkerCos::default()` would
/// silently produce empty `FastMap`s and a zero `cos_interface_rr`,
/// which is also the legitimate construction state — but going
/// through `Default` would lose the FastMap's hashing properties
/// (rebuilding from scratch with default builder). The only legal
/// construction path is the explicit literal in
/// `BindingWorker::create`. Same rule as `WorkerScratch`.
pub(crate) struct WorkerCos {
    pub(crate) cos_fast_interfaces: FastMap<i32, WorkerCoSInterfaceFastPath>,
    pub(crate) cos_interfaces: FastMap<i32, CoSInterfaceRuntime>,
    pub(crate) cos_interface_order: Vec<i32>,
    pub(crate) cos_interface_rr: usize,
    pub(crate) cos_nonempty_interfaces: usize,
}
