// Tests for afxdp/cos/builders.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep builders.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "builders_tests.rs"]` from builders.rs.

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
