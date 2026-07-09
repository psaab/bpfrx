// Tests for afxdp/cos/queue_ops/pop.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep pop.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "pop_tests.rs"]` from pop.rs.

// MQFQ + flow-fair ordering tests colocated with pop.rs.
// pop_front_inner is the heart of MQFQ ordering (per-flow finish-
// time tracking, bucket draining, snapshot stack management);
// these tests pin its invariants. Moved here from queue_ops/mod.rs
// per #1034 P5.
use super::*;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::PROTO_TCP;
use crate::afxdp::cos::admission::{
    apply_cos_queue_flow_fair_promotion, cos_flow_aware_buffer_limit, cos_queue_flow_share_limit,
};
use crate::afxdp::cos::queue_ops::{
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all, cos_queue_pop_front,
    cos_queue_pop_front_no_snapshot, cos_queue_push_back, cos_queue_push_front,
    cos_queue_restore_front,
};
use crate::afxdp::cos::queue_service::{
    ExactCoSScratchBuild, drain_exact_local_fifo_items_to_scratch,
    drain_exact_local_items_to_scratch_flow_fair, drain_exact_prepared_fifo_items_to_scratch,
    drain_exact_prepared_items_to_scratch_flow_fair, settle_exact_local_fifo_submission,
    settle_exact_local_scratch_submission_flow_fair, settle_exact_prepared_fifo_submission,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::cos_classify::{
    cos_queue_accepts_prepared, demote_prepared_cos_queue_to_local,
};
use crate::afxdp::tx::test_support::*;
use crate::afxdp::tx_frame_capacity;
use crate::afxdp::types::{
    COS_FLOW_FAIR_BUCKETS, CoSQueueConfig, FastMap, PreparedTxRecycle, PreparedTxRequest, TxRequest,
};
use crate::afxdp::umem::MmapArea;

mod ordering;
mod rollback;
mod snapshot_stack;
