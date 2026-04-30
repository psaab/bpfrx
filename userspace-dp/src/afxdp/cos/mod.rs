// #956 cos/ submodule. Phase 1 extracted ECN marking; Phase 2
// extracted flow-hashing helpers; Phase 3 extracted admission
// policy + flow-fair promotion; Phase 4 extracted token-bucket
// lease/refill; Phase 5 extracted queue ops + MQFQ ordering +
// V-min lifecycle; Phase 6 (this commit) extracts CoS interface-
// runtime builders. Subsequent phases: Phase 7 queue service,
// Phase 8 cross-binding.
// See docs/pr/956-phase6-builders/plan.md for the current phase
// and docs/pr/956-tx-decomposition/plan.md for the full plan.

pub(super) mod admission;
pub(super) mod builders;
pub(super) mod ecn;
pub(super) mod flow_hash;
pub(super) mod queue_ops;
pub(super) mod token_bucket;

// Re-export the items consumed by callers across the afxdp module.
// The items themselves are `pub(in crate::afxdp)` in their source
// files; these re-exports shorten the import path on call sites.
// Consumers as of Phase 6:
//   - `tx.rs` consumes admission gates (no longer the promotion
//     entry — that's now consumed inside cos/builders.rs),
//     flow_hash helpers, 5 of 7 token-bucket helpers +
//     COS_MIN_BURST_BYTES, the 14 always-on queue_ops helpers,
//     and `ensure_cos_interface_runtime`.
//   - `worker.rs` consumes the 2 `release_all_cos_*_leases`
//     plus `cos_queue_len` and `cos_queue_pop_front_no_snapshot`.
//   - `cos/admission.rs` consumes `COS_MIN_BURST_BYTES`.
//   - `cos/builders.rs` consumes `apply_cos_queue_flow_fair_promotion`
//     and `COS_MIN_BURST_BYTES`.
//
// Production-side: only the entry points production code consumes.
// Test-only re-exports are gated below to avoid `unused_imports`
// warnings on non-test builds.
pub(super) use admission::{
    apply_cos_admission_ecn_policy, cos_flow_aware_buffer_limit, cos_queue_flow_share_limit,
};
pub(super) use builders::ensure_cos_interface_runtime;
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

// Phase 6 relocated apply_cos_queue_flow_fair_promotion's only
// remaining tx.rs caller (ensure_cos_interface_runtime) into
// cos/builders.rs. tx.rs's only direct callers now live in
// tx::tests, so the re-export shifts to cfg-gated.
#[cfg(test)]
pub(super) use admission::{
    apply_cos_queue_flow_fair_promotion, bdp_floor_bytes, COS_ECN_MARK_THRESHOLD_DEN,
    COS_ECN_MARK_THRESHOLD_NUM, COS_FLOW_FAIR_MIN_SHARE_BYTES,
};
#[cfg(test)]
pub(super) use builders::build_cos_interface_runtime;
#[cfg(test)]
pub(super) use ecn::{maybe_mark_ecn_ce, ECN_CE, ECN_ECT_0, ECN_ECT_1, ECN_MASK, ECN_NOT_ECT};
#[cfg(test)]
pub(super) use flow_hash::{cos_flow_hash_seed_from_os, cos_queue_prospective_active_flows};
#[cfg(test)]
pub(super) use queue_ops::{
    account_cos_queue_flow_dequeue, account_cos_queue_flow_enqueue,
    V_MIN_CONSECUTIVE_SKIP_HARD_CAP, V_MIN_SUSPENSION_BATCHES,
};
