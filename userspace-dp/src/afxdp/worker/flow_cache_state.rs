//! #959 Phase 9 — extracts the per-binding flow-cache state out of
//! `BindingWorker` into a dedicated `WorkerFlowCacheState` sub-struct.
//!
//! Two fields:
//! - `flow_cache` — per-worker flow lookup cache (the `FlowCache`
//!   data structure from `super::*`).
//! - `flow_cache_session_touch` — count of session touches modulo
//!   the periodic-refresh threshold; the 64-touch boundary triggers
//!   a session-table refresh in the descriptor loop.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-9. Field names preserved.
//!
//! Filename is `flow_cache_state.rs` because `flow_cache.rs` is
//! taken by the `FlowCache` data structure itself (in
//! `userspace-dp/src/flow_cache.rs`).

use super::*;

/// Per-binding flow-cache state. Owned by the worker that owns this
/// binding.
///
/// **Intentionally NOT `Default`** — for consistency with the other
/// #959 sub-structs. `FlowCache::new()` is the canonical
/// construction; the explicit literal in `BindingWorker::create`
/// uses it.
pub(crate) struct WorkerFlowCacheState {
    pub(crate) flow_cache: FlowCache,
    pub(crate) flow_cache_session_touch: u64,
}
