// #956 cos/ submodule. Phase 1 extracted ECN marking; Phase 2
// extracted flow-hashing helpers; Phase 3 extracted admission
// policy + flow-fair promotion; Phase 4 extracted token-bucket
// lease/refill; Phase 5 extracted queue ops + MQFQ ordering +
// V-min lifecycle; Phase 6 extracted CoS interface-runtime
// builders; Phase 7 extracted the dispatch / drain / submit
// subsystem; Phase 8 (this commit) extracts the cross-binding
// redirect helpers — FINAL phase of #956.
// See docs/pr/956-phase8-cross-binding/plan.md for this phase
// and docs/pr/956-tx-decomposition/plan.md for the full plan.

pub(super) mod admission;
pub(super) mod builders;
pub(super) mod cross_binding;
pub(super) mod ecn;
pub(super) mod flow_hash;
pub(super) mod queue_ops;
pub(super) mod queue_service;
pub(super) mod token_bucket;
pub(super) mod tx_completion;

pub(super) use admission::{
    apply_cos_admission_ecn_policy, cos_flow_aware_buffer_limit, cos_queue_flow_share_limit,
};
pub(super) use builders::ensure_cos_interface_runtime;
pub(super) use cross_binding::{
    redirect_prepared_cos_request_to_owner, redirect_prepared_cos_request_to_owner_binding,
    resolve_local_routing_decision, LocalRoutingDecision, Step1Action,
};
pub(super) use flow_hash::{cos_flow_bucket_index, cos_item_flow_key};
pub(super) use queue_ops::{
    cos_item_len, cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all,
    cos_queue_front, cos_queue_is_empty, cos_queue_len, cos_queue_pop_front,
    cos_queue_pop_front_no_snapshot, cos_queue_push_back, cos_queue_push_front,
    cos_queue_restore_front, cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
    publish_committed_queue_vtime,
};
pub(super) use queue_service::drain_shaped_tx;
pub(super) use token_bucket::{
    cos_refill_ns_until, maybe_top_up_cos_queue_lease,
    refill_cos_tokens, release_all_cos_queue_leases, release_all_cos_root_leases,
    COS_MIN_BURST_BYTES,
};
#[cfg(test)]
pub(super) use token_bucket::{maybe_top_up_cos_root_lease, release_cos_root_lease};
// tx.rs reaches `mark_cos_queue_runnable` via `super::cos::` for its
// non-moving `enqueue_cos_item` path. Other production callers
// (queue_service, builders) reach moved items directly via
// `super::tx_completion::*`.
pub(super) use tx_completion::mark_cos_queue_runnable;

#[cfg(test)]
pub(super) use admission::{
    apply_cos_queue_flow_fair_promotion, bdp_floor_bytes, COS_ECN_MARK_THRESHOLD_DEN,
    COS_ECN_MARK_THRESHOLD_NUM, COS_FLOW_FAIR_MIN_SHARE_BYTES,
};
#[cfg(test)]
pub(super) use builders::build_cos_interface_runtime;
#[cfg(test)]
pub(super) use cross_binding::{
    redirect_local_cos_request_to_owner_binding,
};
#[cfg(test)]
pub(super) use ecn::{maybe_mark_ecn_ce, ECN_CE, ECN_ECT_0, ECN_ECT_1, ECN_MASK, ECN_NOT_ECT};
#[cfg(test)]
pub(super) use flow_hash::{cos_flow_hash_seed_from_os, cos_queue_prospective_active_flows};
#[cfg(test)]
pub(super) use queue_ops::{
    account_cos_queue_flow_dequeue, account_cos_queue_flow_enqueue,
    V_MIN_CONSECUTIVE_SKIP_HARD_CAP, V_MIN_SUSPENSION_BATCHES,
};
#[cfg(test)]
pub(super) use tx_completion::{
    advance_cos_timer_wheel, normalize_cos_queue_state,
    restore_cos_local_items_inner, restore_cos_prepared_items_inner,
    COS_TIMER_WHEEL_TICK_NS,
};
#[cfg(test)]
pub(super) use tx_completion::{
    count_park_reason, park_cos_queue, CoSServicePhase, ParkReason,
};
#[cfg(test)]
pub(super) use queue_service::{
    assign_local_dscp_rewrite, cos_batch_tx_made_progress, cos_guarantee_quantum_bytes,
    drain_exact_local_fifo_items_to_scratch,
    drain_exact_local_items_to_scratch_flow_fair, drain_exact_prepared_fifo_items_to_scratch,
    drain_exact_prepared_items_to_scratch_flow_fair, estimate_cos_queue_wakeup_tick,
    release_exact_local_scratch_frames, release_exact_prepared_scratch,
    select_cos_guarantee_batch, select_cos_guarantee_batch_with_fast_path,
    select_cos_surplus_batch, select_exact_cos_guarantee_queue_with_fast_path,
    select_nonexact_cos_guarantee_batch, settle_exact_local_fifo_submission,
    settle_exact_local_scratch_submission_flow_fair, settle_exact_prepared_fifo_submission,
    CoSBatch, ExactCoSScratchBuild,
};
