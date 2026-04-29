// #956 cos/ submodule. Phase 1 extracted ECN marking; Phase 2
// (this commit) extracts flow-hashing helpers. Subsequent phases:
// Phase 3 admission, Phase 4 token bucket, Phase 5 queue ops,
// Phase 6 builders, Phase 7 queue service, Phase 8 cross-binding.
// See docs/pr/956-tx-decomposition/plan.md for the full plan.

pub(super) mod ecn;
pub(super) mod flow_hash;

// Re-export the items consumed by sibling `tx.rs`. The items
// themselves are `pub(in crate::afxdp)` in their source files;
// these re-exports shorten the import path on call sites.
pub(super) use ecn::{
    maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared, ECN_CE, ECN_ECT_0, ECN_ECT_1, ECN_MASK,
    ECN_NOT_ECT,
};
pub(super) use flow_hash::{
    cos_flow_bucket_index, cos_flow_hash_seed_from_os, cos_item_flow_key,
    cos_queue_prospective_active_flows,
};
