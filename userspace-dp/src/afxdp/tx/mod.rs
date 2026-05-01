use super::*;

// #984 P2a: TX latency-histogram + completion-sidecar helpers
// extracted to sibling module `tx/stats.rs`. The re-export below is
// load-bearing: `umem.rs::tests` (umem.rs:950+) reaches the three fns
// through `crate::afxdp::tx::{stamp_submits,
// record_tx_completions_with_stamp, record_kick_latency}` and that
// path resolves through this `pub(in crate::afxdp) use`.
pub(super) mod stats;
pub(in crate::afxdp) use stats::stamp_submits;
// `record_kick_latency` and `record_tx_completions_with_stamp` are
// reached only by `umem.rs::tests` via `crate::afxdp::tx::*` (see
// umem.rs:966/1077/1124/1188 — all `#[cfg(test)]`). Production callers
// inside `tx/rings.rs` import them directly from `super::stats::*`.
#[cfg(test)]
pub(in crate::afxdp) use stats::{record_kick_latency, record_tx_completions_with_stamp};

// #984 P2b: XSK kernel-ring discipline (TX completion drain, fill ring
// submit, RX/TX kernel wake) extracted to sibling module `tx/rings.rs`.
// External callers (cos/queue_service.rs uses reap_tx_completions and
// maybe_wake_tx; afxdp.rs / frame_tx.rs use drain_pending_fill and
// maybe_wake_rx) reach the moved fns through these re-exports at the
// same `crate::afxdp::tx::*` paths they used pre-move.
pub(super) mod rings;
pub(in crate::afxdp) use rings::{maybe_wake_tx, reap_tx_completions};
pub(super) use rings::{drain_pending_fill, maybe_wake_rx};

// #984 P2c: TX-ring submit + per-frame recycle cluster (transmit_batch,
// transmit_prepared_queue, recycle_*, TxError) extracted to sibling
// module `tx/transmit.rs`. External callers (cos/queue_service.rs
// imports recycle_cancelled_prepared_offset, remember_prepared_recycle,
// transmit_batch, transmit_prepared_queue, TxError;
// cos/cross_binding.rs and worker.rs:1974 import recycle_prepared_immediately)
// reach the moved items via the re-export below.
pub(super) mod transmit;
pub(in crate::afxdp) use transmit::{
    recycle_cancelled_prepared_offset, recycle_prepared_immediately,
    remember_prepared_recycle, transmit_batch, transmit_prepared_queue, TxError,
};
// transmit_prepared_batch is sibling-internal (only caller in tx/mod.rs);
// this private import keeps it available within this module.
use transmit::transmit_prepared_batch;

// #984 P2c2: drain dispatch + queue-bound + pending-queue helpers
// extracted to sibling module `tx/drain.rs`. cos/queue_service.rs
// imports the 4 quantum/guarantee constants via crate::afxdp::tx::*,
// so that re-export is load-bearing.
pub(super) mod drain;
pub(super) use drain::{
    bound_pending_tx_local, bound_pending_tx_prepared, drain_pending_tx,
    drain_pending_tx_local_owner, pending_tx_capacity,
};
pub(in crate::afxdp) use drain::{
    COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES,
    COS_GUARANTEE_VISIT_NS, COS_SURPLUS_ROUND_QUANTUM_BYTES,
};

// #984 P2d (FINAL): CoS classify + enqueue + cached-selection cluster
// extracted to sibling module `tx/cos_classify.rs`. Closes #984.
pub(super) mod cos_classify;

// #984 P3 follow-up: shared test helpers hoisted out of the inline
// `mod tests` so per-file test modules in `tx/*.rs` and `cos/*.rs`
// siblings can reuse them via `crate::afxdp::tx::test_support::*`.
#[cfg(test)]
pub(in crate::afxdp) mod test_support;

pub(super) use cos_classify::{
    CoSTxSelection, enqueue_local_into_cos, resolve_cached_cos_tx_selection,
    resolve_cos_queue_id, resolve_cos_tx_selection,
};
pub(in crate::afxdp) use cos_classify::cos_queue_dscp_rewrite;
// Private import (NOT re-export — E0364 if pub(super) re-export of
// pub(super) source): drain.rs reaches it via `use super::*;`.
use cos_classify::enqueue_prepared_into_cos;

// #956: cos/ submodule imports.
//
// Phase 1 (PR #976) extracted ECN marking into cos/ecn.rs.
// Phase 2 (PR #977) extracted the flow-hash helpers into
// cos/flow_hash.rs. Phase 3 (PR #978) extracted admission policy +
// flow-fair promotion into cos/admission.rs. Phase 4 (PR #979)
// extracted token-bucket lease/refill into cos/token_bucket.rs.
// Phase 5 (this PR) extracts queue ops + MQFQ ordering bookkeeping
// + V-min slot lifecycle into cos/queue_ops.rs.
//
// Production code uses the entry points re-exported from
// cos/mod.rs (marker fns + flow-hash + admission gates +
// flow-fair promotion entry + token-bucket helpers + queue-ops
// fns).
use super::cos::{
    apply_cos_admission_ecn_policy, cos_flow_aware_buffer_limit, cos_flow_bucket_index,
    cos_item_flow_key, cos_queue_drain_all, cos_queue_flow_share_limit,
    cos_queue_is_empty, cos_queue_push_back, cos_queue_restore_front,
    drain_shaped_tx, ensure_cos_interface_runtime, mark_cos_queue_runnable,
    publish_committed_queue_vtime, redirect_prepared_cos_request_to_owner,
    redirect_prepared_cos_request_to_owner_binding,
    resolve_local_routing_decision, LocalRoutingDecision, Step1Action,
};
#[cfg(test)]
use super::cos::COS_MIN_BURST_BYTES;
