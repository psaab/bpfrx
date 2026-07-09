use super::*;

/// Build a single NON-exact shaped queue and mark it
/// `flow_fair_eligible` (as `promote_cos_queue_flow_fair` would for any
/// queue reaching it on an interface with a CoSInterfaceRuntime). It
/// starts with `flow_fair_state == None` — the lazy-promotion subject.
fn test_nonexact_eligible_root() -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 4,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.queues[0].config.flow_fair_eligible = true;
    root
}

#[test]
fn flow_fair_gate_is_state_is_some_not_config() {
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Eligible but unpromoted: flow_fair() must be FALSE.
    assert!(queue.config.flow_fair_eligible);
    assert!(queue.flow_fair_state.is_none());
    assert!(!queue.flow_fair(), "None state must gate as non-flow-fair");
    // Allocate state directly: flow_fair() flips true with no config touch.
    enable_test_flow_fair(queue);
    assert!(queue.flow_fair());
    disable_test_flow_fair(queue);
    assert!(!queue.flow_fair());
}

#[test]
fn best_effort_single_flow_never_promotes() {
    // The #1183 fast-path guard: a single-flow best-effort queue stays
    // FIFO (flow_fair_state == None) no matter how many packets arrive.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    for _ in 0..64 {
        cos_queue_push_back(queue, test_flow_cos_item(40000, 1500));
    }
    assert!(
        queue.flow_fair_state.is_none(),
        "single-flow best-effort must NOT promote (no hash, no FlowFairState)"
    );
    assert_eq!(queue.hot.items.len(), 64, "items stay in the FIFO");
    assert_eq!(queue.hot.local_item_count, 64);
}

#[test]
fn best_effort_keyless_traffic_never_promotes() {
    // Keyless items (flow_key == None) compare equal under the probe
    // (None == None) and must NOT promote — matches today's bucket-0
    // semantics and avoids promoting on keyless noise.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    for _ in 0..16 {
        cos_queue_push_back(queue, test_cos_item(1500));
    }
    assert!(queue.flow_fair_state.is_none());
    assert_eq!(queue.hot.items.len(), 16);
}

#[test]
fn best_effort_promotes_on_first_differing_flow_with_correct_migration() {
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Three packets of flow A (src_port 100) — stays FIFO.
    for _ in 0..3 {
        cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
    }
    assert!(queue.flow_fair_state.is_none(), "single flow stays FIFO");
    let total_a = 3 * 1500u64;
    // First packet of flow B (src_port 200) — triggers promotion.
    cos_queue_push_back(queue, test_flow_cos_item(200, 1000));
    assert!(queue.flow_fair_state.is_some(), "second flow promotes");
    let ff = test_flow_fair_state(queue);
    // Collision-aware: the OS-seeded hash MAY (rarely) collide flow A and
    // flow B into the same 4096-bucket slot. Derive the expected bucket
    // layout from the ACTUAL runtime seed so the assertions are
    // deterministic regardless of collision (Copilot review).
    let seed = ff.flow_hash_seed;
    let bucket_a = cos_flow_bucket_index(seed, Some(&test_session_key(100, 5201)));
    let bucket_b = cos_flow_bucket_index(seed, Some(&test_session_key(200, 5201)));
    if bucket_a == bucket_b {
        // Hash collision: both flows share one bucket. Bytes accumulate
        // there; one active bucket. (Migration + accounting still correct.)
        assert_eq!(ff.active_flow_buckets, 1, "collision: single shared bucket");
        assert_eq!(
            ff.flow_bucket_bytes[bucket_a],
            total_a + 1000,
            "collision: A+B bytes share the bucket, none lost"
        );
    } else {
        assert_eq!(ff.active_flow_buckets, 2, "A and B each in their own bucket");
        assert_eq!(ff.flow_bucket_bytes[bucket_a], total_a, "migrated A bytes intact");
        assert_eq!(ff.flow_bucket_bytes[bucket_b], 1000, "B accounted once");
    }
    // FIFO is drained into buckets; local_item_count nets to all 4 items.
    assert!(queue.hot.items.is_empty(), "FIFO emptied by migration");
    assert_eq!(queue.hot.local_item_count, 4, "no double-count / loss");
    // No v8 lease / V_min on a non-exact queue.
    assert!(queue.queue_lease_v8.is_none());
    assert!(queue.v_min.vtime_floor.is_none());
}

#[test]
fn promoted_best_effort_pops_in_mqfq_interleave_not_fifo_bursts() {
    // Elephant (flow A, many packets) interleaved with a mouse (flow B,
    // one packet) must NOT drain A,A,...,A,B (FIFO) — MQFQ gives the
    // mouse a fair turn near the front.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    for _ in 0..8 {
        cos_queue_push_back(queue, test_flow_cos_item(100, 1500)); // elephant A
    }
    cos_queue_push_back(queue, test_flow_cos_item(200, 1500)); // mouse B (promotes)
    assert!(queue.flow_fair());
    let seed = test_flow_fair_state(queue).flow_hash_seed;
    let bucket_e = cos_flow_bucket_index(seed, Some(&test_session_key(100, 5201)));
    let bucket_m = cos_flow_bucket_index(seed, Some(&test_session_key(200, 5201)));
    // Pop everything; record the flow of each popped item by src_port.
    let mut order = Vec::new();
    while let Some(item) = cos_queue_pop_front(queue) {
        let port = cos_item_flow_key(&item).map(|k| k.src_port).unwrap_or(0);
        order.push(port);
    }
    assert_eq!(order.len(), 9);
    if bucket_e == bucket_m {
        // Rare hash collision: both flows share one bucket, so MQFQ
        // degenerates to FIFO within it and the mouse (enqueued last) is
        // legitimately last. The cross-flow interleave property only
        // applies to distinct buckets; nothing to assert here.
        return;
    }
    // Distinct buckets: the mouse (200) must appear before the LAST
    // elephant packet — a pure FIFO would put it dead last. MQFQ
    // frontends it.
    let mouse_pos = order.iter().position(|&p| p == 200).unwrap();
    assert!(
        mouse_pos < order.len() - 1,
        "mouse must not be starved to the FIFO tail; order = {:?}",
        order
    );
}

#[test]
fn best_effort_elephant_vs_mice_per_flow_fairness() {
    // Headline acceptance proxy: 1 elephant (200 pkts) + 4 mice (1 pkt
    // each) on a shaped best-effort queue. After promotion, assert each
    // mouse is admitted to its own bucket and none is starved — per-flow
    // max/min bucket occupancy is bounded, not elephant-dominated.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Mice first so the elephant arriving second triggers promotion and
    // each mouse gets its own bucket.
    for port in [301u16, 302, 303, 304] {
        cos_queue_push_back(queue, test_flow_cos_item(port, 1500));
    }
    // The 4 mice are 4 distinct flows; the 2nd one already promoted.
    assert!(queue.flow_fair());
    for _ in 0..200 {
        cos_queue_push_back(queue, test_flow_cos_item(999, 1500)); // elephant
    }
    let ff = test_flow_fair_state(queue);
    // Collision-aware (Copilot review): with 4096 buckets the 5 flows
    // MAY (rarely) collide. Derive the distinct-bucket set under the
    // ACTUAL runtime seed and assert against THAT, so the test is
    // deterministic regardless of collision. The fairness property —
    // the first MQFQ round touches every DISTINCT bucket (no flow
    // starved behind the elephant) — holds either way.
    let seed = ff.flow_hash_seed;
    let mut distinct_buckets = std::collections::HashSet::new();
    for port in [301u16, 302, 303, 304, 999] {
        distinct_buckets.insert(cos_flow_bucket_index(seed, Some(&test_session_key(port, 5201))));
    }
    let n_buckets = distinct_buckets.len();
    assert_eq!(
        usize::from(ff.active_flow_buckets),
        n_buckets,
        "active_flow_buckets must equal the distinct-bucket count under the seed"
    );
    // Pop the first `n_buckets` items and assert each touches a distinct
    // bucket — the first MQFQ round visits every active flow's bucket
    // rather than draining the elephant wholesale (no starvation).
    let mut seen_buckets = std::collections::HashSet::new();
    for _ in 0..n_buckets {
        let item = cos_queue_pop_front(queue).expect("item");
        let b = cos_flow_bucket_index(seed, cos_item_flow_key(&item));
        seen_buckets.insert(b);
    }
    assert_eq!(
        seen_buckets.len(),
        n_buckets,
        "first MQFQ round must touch every active bucket (no flow starved); saw {:?}",
        seen_buckets
    );
}

#[test]
fn lazy_demotion_after_hysteresis_on_drained_nonexact_queue() {
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Promote via two flows, then fully drain.
    cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(200, 1500));
    assert!(queue.flow_fair());
    while cos_queue_pop_front(queue).is_some() {}
    queue.hot.queued_bytes = 0;
    // Each quiescent settle bumps the counter; demote only at threshold.
    for i in 1..COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS {
        maybe_demote_drained_best_effort(queue);
        assert!(
            queue.flow_fair_state.is_some(),
            "must not demote before hysteresis (settle {i})"
        );
    }
    maybe_demote_drained_best_effort(queue);
    assert!(
        queue.flow_fair_state.is_none(),
        "demotes once hysteresis reached; FlowFairState box dropped"
    );
    assert_eq!(queue.hot.cos_demote_empty_settles, 0);
}

#[test]
fn demotion_hysteresis_resets_on_nonquiescent_settle() {
    // A queue oscillating between drained and busy must NOT demote.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(200, 1500));
    assert!(queue.flow_fair());
    for _ in 0..(COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS as usize + 2) {
        // Drain, observe a couple empty settles...
        while cos_queue_pop_front(queue).is_some() {}
        queue.hot.queued_bytes = 0;
        maybe_demote_drained_best_effort(queue);
        // ...then a new burst arrives BEFORE the threshold (non-quiescent
        // settle resets the counter).
        cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(200, 1500));
        maybe_demote_drained_best_effort(queue); // non-quiescent -> reset
        assert!(
            queue.flow_fair_state.is_some(),
            "oscillating 1<->2 flow queue must not thrash-demote"
        );
    }
}

#[test]
fn exact_queue_never_demotes() {
    // Exact queues promote eagerly and must stay promoted through full
    // drain (V_min / v8-lease coordination assumes stable state).
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-a".into(),
            priority: 4,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    queue.config.flow_fair_eligible = true;
    enable_test_flow_fair(queue);
    assert!(queue.flow_fair());
    for _ in 0..(COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS as usize + 4) {
        queue.hot.queued_bytes = 0;
        maybe_demote_drained_best_effort(queue);
    }
    assert!(
        queue.flow_fair_state.is_some(),
        "exact queue must never demote (stable flow_fair_state)"
    );
}

