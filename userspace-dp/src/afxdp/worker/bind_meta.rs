//! #959 Phase 8 — extracts the per-binding registration / identity
//! metadata out of `BindingWorker` into a dedicated `WorkerBindMeta`
//! sub-struct.
//!
//! Three fields:
//! - `bind_time_ns` — monotonic timestamp when this binding was
//!   created. Used by heartbeat-gating logic.
//! - `bind_mode` — copy vs zero-copy XSK bind mode (set after
//!   bind succeeds).
//! - `xsk_rx_confirmed` — flips true once the XSK RX ring has
//!   delivered at least one packet, proving the NIC's XSK receive
//!   queue is active for this binding.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-8. Field names preserved.

use super::*;

/// Per-binding registration / identity metadata. Set at binding
/// construction and during the bind-mode transition. Never reset
/// after the binding is bound.
///
/// **Intentionally NOT `Default`** — `bind_time_ns` must be
/// initialized to the actual monotonic-now sample from
/// `BindingWorker::create`. Default would seed with 0 and break
/// any heartbeat-gating logic that checks
/// `now_ns - bind_time_ns < grace_period`.
pub(crate) struct WorkerBindMeta {
    pub(crate) bind_time_ns: u64,
    pub(crate) bind_mode: XskBindMode,
    pub(crate) xsk_rx_confirmed: bool,
}
