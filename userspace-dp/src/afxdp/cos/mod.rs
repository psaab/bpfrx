// #956 Phase 1: cos/ submodule. Phase 1 extracts ECN marking;
// subsequent phases extend with admission, token bucket, flow hash,
// queue ops, builders, queue service, and cross-binding (see
// docs/pr/956-tx-decomposition/plan.md for the full phased plan).

pub(super) mod ecn;

// Re-export the items consumed by sibling `tx.rs`. The items
// themselves are `pub(in crate::afxdp)` in `ecn.rs`; this re-export
// shortens the import path on call sites.
pub(super) use ecn::{
    maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared, ECN_CE, ECN_ECT_0, ECN_ECT_1, ECN_MASK,
    ECN_NOT_ECT,
};
