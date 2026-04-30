// #956 cos/ submodule. Phase 1 extracted ECN marking; Phase 2
// extracted flow-hashing helpers; Phase 3 (this commit) extracts
// admission policy + flow-fair promotion. Subsequent phases:
// Phase 4 token bucket, Phase 5 queue ops, Phase 6 builders,
// Phase 7 queue service, Phase 8 cross-binding.
// See docs/pr/956-phase3-admission/plan.md for the current phase
// and docs/pr/956-tx-decomposition/plan.md for the full plan.

pub(super) mod admission;
pub(super) mod ecn;
pub(super) mod flow_hash;

// Re-export the items consumed by sibling `tx.rs`. The items
// themselves are `pub(in crate::afxdp)` in their source files;
// these re-exports shorten the import path on call sites.
//
// Production-side: only the entry points tx.rs's non-test code
// consumes. Test-only re-exports are gated below to avoid
// `unused_imports` warnings on non-test builds.
pub(super) use admission::{
    apply_cos_admission_ecn_policy, apply_cos_queue_flow_fair_promotion,
    cos_flow_aware_buffer_limit, cos_queue_flow_share_limit,
};
pub(super) use flow_hash::{cos_flow_bucket_index, cos_item_flow_key};

#[cfg(test)]
pub(super) use admission::{
    bdp_floor_bytes, COS_ECN_MARK_THRESHOLD_DEN, COS_ECN_MARK_THRESHOLD_NUM,
    COS_FLOW_FAIR_MIN_SHARE_BYTES,
};
#[cfg(test)]
pub(super) use ecn::{maybe_mark_ecn_ce, ECN_CE, ECN_ECT_0, ECN_ECT_1, ECN_MASK, ECN_NOT_ECT};
#[cfg(test)]
pub(super) use flow_hash::{cos_flow_hash_seed_from_os, cos_queue_prospective_active_flows};
