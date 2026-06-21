//! #959 Phase 9 — extracts the per-binding flow-cache state out of
//! `BindingWorker` into a dedicated `WorkerFlowCacheState` sub-struct.
//!
//! One field:
//! - `flow_cache` — per-worker flow lookup cache (the `FlowCache`
//!   data structure from `super::*`).
//!
//! #2220 removed the former `flow_cache_session_touch` counter: it was
//! a binding-GLOBAL modulo-64 sampler that, by design, refreshed only
//! the flow whose cache hit happened to land on a global multiple of
//! 64, so a low-rate flow co-resident with a saturating flow could be
//! reaped while still actively forwarding. The flow-cache fast path now
//! calls `SessionTable::touch_if_stale`, a per-session time-threshold
//! keepalive that needs no worker-local counter.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-9. Field names preserved.
//!
//! Filename is `flow_cache_state.rs` because `flow_cache.rs` is
//! taken by the `FlowCache` data structure itself (in
//! `userspace-dp/src/afxdp/flow_cache.rs`).

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
}
