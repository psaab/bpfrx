// #956 Phase 6: CoS interface-runtime builders, extracted from
// tx.rs. Provides the construction half of the binding lifecycle:
//
//   - `ensure_cos_interface_runtime` — production caller hook
//     (binding lifecycle). Sits on the steady-state enqueue path
//     because every enqueue checks whether the runtime exists for
//     the egress ifindex; carries `#[inline]`.
//   - `build_cos_interface_runtime` — pure constructor from
//     `CoSInterfaceConfig`. Called once by `ensure_*` and 3 times
//     by `tx::tests`; pub(in crate::afxdp) plus cfg-gated
//     re-export from cos/mod.rs.
//
// `cos_tick_for_ns` moved to cos/tx_completion.rs in #956 P1; the
// Phase-6 cos/builders -> tx back-edge is now closed.
//
// `apply_cos_queue_flow_fair_promotion` (cos/admission.rs) is
// imported here. After this PR, ensure_cos_interface_runtime is
// the only non-test caller of that fn — cos/mod.rs's re-export
// for it shifts from always-on to cfg-gated.

use std::collections::VecDeque;

use crate::afxdp::types::{
    CoSInterfaceConfig, CoSInterfaceRuntime, CoSQueueDropCounters, CoSQueueOwnerProfile,
    CoSQueueRuntime, CoSTimerWheelRuntime, FlowRrRing, ForwardingState, COS_FLOW_FAIR_BUCKETS,
    COS_PRIORITY_LEVELS,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::TX_BATCH_SIZE;
use super::admission::apply_cos_queue_flow_fair_promotion;
use super::tx_completion::cos_tick_for_ns;
use super::COS_MIN_BURST_BYTES;

#[inline]
pub(in crate::afxdp) fn ensure_cos_interface_runtime(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    now_ns: u64,
) -> bool {
    if egress_ifindex <= 0 {
        return false;
    }
    // #774 fast path: if the runtime is already materialised,
    // that's the dominant case on steady state. A single
    // `contains_key` on the cos_interfaces hot map skips the two
    // forwarding.cos.interfaces + cos_fast_interfaces lookups
    // and the later-pass duplicate. Profiled at 0.9% CPU before
    // this fix.
    if binding.cos_interfaces.contains_key(&egress_ifindex) {
        return true;
    }
    let Some(config) = forwarding.cos.interfaces.get(&egress_ifindex) else {
        return false;
    };
    if !binding.cos_fast_interfaces.contains_key(&egress_ifindex) {
        return false;
    }
    {
        let mut runtime = build_cos_interface_runtime(config, now_ns);
        if let Some(iface_fast) = binding.cos_fast_interfaces.get(&egress_ifindex) {
            apply_cos_queue_flow_fair_promotion(
                &mut runtime,
                &iface_fast.queue_fast_path,
                binding.worker_id,
            );
        }
        binding.cos_interfaces.insert(egress_ifindex, runtime);
        binding.cos_interface_order.push(egress_ifindex);
        binding.cos_interface_order.sort_unstable();
    }
    true
}

pub(in crate::afxdp) fn build_cos_interface_runtime(config: &CoSInterfaceConfig, now_ns: u64) -> CoSInterfaceRuntime {
    let mut queue_indices_by_priority: [Vec<usize>; COS_PRIORITY_LEVELS] =
        std::array::from_fn(|_| Vec::new());
    for (idx, queue) in config.queues.iter().enumerate() {
        let priority = usize::from(queue.priority).min(COS_PRIORITY_LEVELS - 1);
        queue_indices_by_priority[priority].push(idx);
    }
    CoSInterfaceRuntime {
        shaping_rate_bytes: config.shaping_rate_bytes,
        burst_bytes: config.burst_bytes.max(COS_MIN_BURST_BYTES),
        tokens: 0,
        default_queue: config.default_queue,
        nonempty_queues: 0,
        runnable_queues: 0,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: config
            .queues
            .iter()
            .map(|queue| CoSQueueRuntime {
                queue_id: queue.queue_id,
                priority: queue.priority,
                transmit_rate_bytes: queue.transmit_rate_bytes,
                exact: queue.exact,
                flow_fair: false,
                // Populated by `promote_cos_queue_flow_fair` from the
                // live `WorkerCoSQueueFastPath.shared_exact` signal.
                shared_exact: false,
                // Zero until `ensure_cos_interface_runtime` promotes a queue
                // onto the flow-fair path and draws a real seed. On the
                // non-flow-fair path this field is never read.
                flow_hash_seed: 0,
                surplus_weight: queue.surplus_weight,
                surplus_deficit: 0,
                buffer_bytes: queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
                dscp_rewrite: queue.dscp_rewrite,
                tokens: if queue.exact {
                    0
                } else {
                    queue.buffer_bytes.max(COS_MIN_BURST_BYTES)
                },
                last_refill_ns: if queue.exact { 0 } else { now_ns },
                queued_bytes: 0,
                active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
            })
            .collect(),
        queue_indices_by_priority,
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: cos_tick_for_ns(now_ns),
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
        },
    }
}
