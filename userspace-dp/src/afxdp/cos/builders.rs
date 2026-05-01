// CoS interface-runtime construction. `ensure_cos_interface_runtime`
// sits on the steady-state enqueue path (every enqueue checks
// whether the runtime exists for the egress ifindex) and carries
// `#[inline]`.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::tx::test_support::*;
    use crate::afxdp::types::{CoSQueueConfig, FastMap};

    #[test]
    fn build_cos_interface_runtime_starts_exact_queue_with_zero_local_tokens() {
        let runtime = build_cos_interface_runtime(
            &CoSInterfaceConfig {
                shaping_rate_bytes: 25_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 5,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                }],
            },
            1_000_000_000,
        );

        assert_eq!(runtime.queues[0].tokens, 0);
        assert_eq!(runtime.queues[0].last_refill_ns, 0);
    }

    #[test]
    fn build_cos_interface_runtime_leaves_flow_hash_seed_zero_until_promotion() {
        // The seed is drawn in `ensure_cos_interface_runtime`, not in
        // `build_cos_interface_runtime`. Pin this so a refactor that
        // accidentally moves the getrandom call into the builder is
        // caught: builder-time seeding would burn a syscall per non-
        // flow-fair queue and would also drift the struct doc invariant
        // that non-flow-fair queues keep seed=0.
        let root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        for queue in &root.queues {
            assert!(!queue.flow_fair);
            assert_eq!(queue.flow_hash_seed, 0);
        }
    }

}
