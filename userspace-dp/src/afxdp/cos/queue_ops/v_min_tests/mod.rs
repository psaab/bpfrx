// Tests for afxdp/cos/queue_ops/v_min.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep v_min.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "v_min_tests.rs"]` from v_min.rs.

// V_min coordination tests colocated with the production fns,
// moved here per #1034 P4 from queue_ops/mod.rs's `mod tests`
// (where they were originally placed before the V_min split
// landed in #1036).
use super::*;
use crate::afxdp::cos::admission::apply_cos_queue_flow_fair_promotion;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::types::SharedCoSQueueVtimeFloor;
use crate::afxdp::PROTO_TCP;
use std::sync::Arc;
use crate::afxdp::cos::queue_ops::{
    cos_queue_pop_front, cos_queue_push_back, cos_queue_push_front,
};
use crate::afxdp::cos::queue_service::{
    drain_exact_local_items_to_scratch_flow_fair, drain_exact_prepared_items_to_scratch_flow_fair,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::cos_classify::demote_prepared_cos_queue_to_local;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{CoSQueueConfig, PreparedTxRecycle, PreparedTxRequest, TxRequest};
use crate::afxdp::umem::MmapArea;

mod publish;
mod throttle;
mod vacate;
mod hard_cap;
mod prepared_drain;
mod cadence;
mod rejoiner;
