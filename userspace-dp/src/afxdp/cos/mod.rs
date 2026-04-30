// #956 cos/ submodule. Phase 1 extracted ECN marking; Phase 2
// extracted flow-hashing helpers; Phase 3 extracted admission
// policy + flow-fair promotion; Phase 4 extracted the token-bucket
// lease/refill subsystem; Phase 5 (this commit) extracts queue ops
// + MQFQ ordering bookkeeping + V-min slot lifecycle. Subsequent
// phases: Phase 6 builders, Phase 7 queue service, Phase 8
// cross-binding.
// See docs/pr/956-phase5-queue-ops/plan.md for the current phase
// and docs/pr/956-tx-decomposition/plan.md for the full plan.

pub(super) mod admission;
pub(super) mod ecn;
pub(super) mod flow_hash;
pub(super) mod queue_ops;
pub(super) mod token_bucket;

// Re-export the items consumed by callers across the afxdp module.
// The items themselves are `pub(in crate::afxdp)` in their source
// files; these re-exports shorten the import path on call sites.
// Consumers as of Phase 5:
//   - `tx.rs` consumes admission gates, flow_hash helpers,
//     5 of 7 token-bucket helpers + COS_MIN_BURST_BYTES, and
//     the 14 always-on queue_ops helpers.
//   - `worker.rs` consumes the 2 `release_all_cos_*_leases`
//     plus `cos_queue_len` and `cos_queue_pop_front_no_snapshot`.
//   - `cos/admission.rs` consumes `COS_MIN_BURST_BYTES` (Phase 4
//     replaced the Phase-3 admission -> tx back-edge with a
//     `super::COS_MIN_BURST_BYTES` re-export here).
//
// Production-side: only the entry points production code consumes.
// Test-only re-exports are gated below to avoid `unused_imports`
// warnings on non-test builds.
pub(super) use admission::{
    apply_cos_admission_ecn_policy, apply_cos_queue_flow_fair_promotion,
    cos_flow_aware_buffer_limit, cos_queue_flow_share_limit,
};
pub(super) use flow_hash::{cos_flow_bucket_index, cos_item_flow_key};
pub(super) use queue_ops::{
    cos_item_len, cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all,
    cos_queue_front, cos_queue_is_empty, cos_queue_len, cos_queue_pop_front,
    cos_queue_pop_front_no_snapshot, cos_queue_push_back, cos_queue_push_front,
    cos_queue_restore_front, cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
    publish_committed_queue_vtime,
};
pub(super) use token_bucket::{
    cos_refill_ns_until, maybe_top_up_cos_queue_lease, maybe_top_up_cos_root_lease,
    refill_cos_tokens, release_all_cos_queue_leases, release_all_cos_root_leases,
    release_cos_root_lease, COS_MIN_BURST_BYTES,
};

#[cfg(test)]
pub(super) use admission::{
    bdp_floor_bytes, COS_ECN_MARK_THRESHOLD_DEN, COS_ECN_MARK_THRESHOLD_NUM,
    COS_FLOW_FAIR_MIN_SHARE_BYTES,
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
