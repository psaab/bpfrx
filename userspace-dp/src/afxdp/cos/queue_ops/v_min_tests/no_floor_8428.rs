use super::*;

/// #8428 — a NON-EXACT high-rate queue is routed into the shared_exact
/// flow-fair drain with NO `vtime_floor`, and `cos_queue_v_min_continue`
/// panicked on it.
///
/// # The two predicates, and why the divergence is not itself the bug
///
/// `queue_uses_shared_exact_service` (worker/cos/mod.rs) routes on RATE alone:
/// `queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES`. The floor
/// allocator (`build_shared_cos_queue_vtime_floors_reusing_existing`) admits on
/// EXACTNESS as well: `!queue.exact || rate < MIN` skips.
///
/// That divergence is DELIBERATE and documented at the allocator — "#1598: this
/// filter is intentionally STRICTER than the routing-side gate ... V_min
/// coordination is an exact-only concept ... So both gates keep their own
/// predicate: shared_exact-routing is broader, V_min-floor is exact-only."
///
/// So the fix is NOT to allocate a floor for everything the routing gate
/// admits; that would contradict a decision the code states outright and the
/// same comment calls "useless work". The fix is that the CONSUMER must tolerate
/// the difference the producer deliberately creates. `promote_cos_queue_flow_fair`
/// copies both fields straight from the fast-path struct, so a queue with
/// `shared_exact = true` and `vtime_floor = None` is an ordinary, reachable
/// production state — not corruption.
///
/// # What was actually wrong
///
/// `cos_queue_v_min_continue` did `.expect("shared_exact queue without
/// vtime_floor")` on a worker thread. The worker dies, its bindings stall, and
/// there is no auto-recovery — the daemon must be restarted. Reachable from
/// ordinary traffic on a configuration the commit path accepts.
///
/// This cell is the HARM, not the shape: it drives the real entry point on the
/// real state and asserts the drain CONTINUES.
#[test]
fn a_shared_exact_queue_without_a_floor_is_unthrottled_not_a_panic_8428() {
    // Rate is comfortably above COS_SHARED_EXACT_MIN_RATE_BYTES, and NON-zero
    // so the #2981 unshaped escape cannot be what carries this cell.
    let rate = 10_000_000_000u64 / 8; // 1.25 GB/s — the observed panic state
    let mut root = test_cos_runtime_with_queues(
        rate,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "uncapped".into(),
            priority: 5,
            transmit_rate_bytes: rate,
            guarantee_enabled: true,
            // THE POINT: not exact, so the floor allocator skips it while the
            // routing gate admits it.
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];

    // Exactly what `promote_cos_queue_flow_fair` produces from a fast-path
    // struct whose `shared_exact` came from the rate-only routing gate and
    // whose `vtime_floor` the exact-gated allocator never built.
    queue.config.shared_exact = true;
    queue.config.flow_fair_eligible = true;
    queue.flow_fair_state = Some(FlowFairState::new_boxed(0));
    queue.v_min.worker_id = 0;
    assert!(
        queue.v_min.vtime_floor.is_none(),
        "fixture: the whole point is that no floor was allocated"
    );
    assert!(
        queue.shared_exact(),
        "fixture: the queue must be routed as shared_exact, or this cell \
         returns early at the `!shared_exact()` gate and proves nothing"
    );
    assert!(
        queue.transmit_rate_bytes() > 0,
        "fixture: a zero rate takes the #2981 unshaped escape, which would \
         carry this cell for the wrong reason"
    );

    // Before #8428 this panicked on the worker thread.
    assert!(
        cos_queue_v_min_continue(queue, 1),
        "a shared_exact queue with no vtime_floor has no peers to coordinate \
         against, so the V_min lag check does not apply and the drain must \
         CONTINUE — the same disposition as the `!shared_exact()` and unshaped \
         arms above it (#8428)"
    );
}

/// CONTROL: the throttle still fires when a floor IS present.
///
/// Without this, the fix could be "always return true" — which would silently
/// disable V_min coordination for every exact queue and pass the cell above.
#[test]
fn a_shared_exact_queue_with_a_floor_still_throttles_8428() {
    let rate = 10_000_000_000u64 / 8;
    let mut root = test_cos_runtime_with_queues(
        rate,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: rate,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    assert!(
        !cos_queue_v_min_continue(queue, 1),
        "control: with a floor present and a peer pegged far behind, the V_min \
         lag check must still THROTTLE. A fix that made the no-floor case \
         continue by short-circuiting the whole function would red here"
    );
}

/// The SECOND panic from the same root, one line earlier — and the one the
/// issue does not name.
///
/// `promote_cos_queue_flow_fair` allocates `flow_fair_state` only
/// `if queue.config.exact`. A non-exact queue promotes LAZILY, on its second
/// distinct flow, so between being routed shared_exact and that second flow
/// arriving it is shared_exact with NO flow-fair state — and
/// `cos_queue_v_min_continue` hit its `.expect()` at v_min.rs:212 before ever
/// reaching the vtime_floor one at :219.
///
/// That makes this arm strictly MORE reachable than the reported one: it fires
/// immediately, not after a second flow. Measured, not reasoned — a probe on
/// master panicked at 212:10 with exactly this state.
///
/// Fixing only the reported line would have left this one live, from the
/// identical false invariant.
#[test]
fn a_shared_exact_queue_without_flow_fair_state_is_unthrottled_not_a_panic_8428() {
    let rate = 10_000_000_000u64 / 8;
    let mut root = test_cos_runtime_with_queues(
        rate,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "uncapped".into(),
            priority: 5,
            transmit_rate_bytes: rate,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    queue.config.shared_exact = true;
    queue.config.flow_fair_eligible = true;
    // NOT set: exactly what `promote_cos_queue_flow_fair` leaves for a
    // non-exact queue before lazy promotion.
    assert!(
        queue.flow_fair_state.is_none(),
        "fixture: the whole point is that flow-fair state was never allocated"
    );
    assert!(
        queue.shared_exact(),
        "fixture: the queue must be routed shared_exact, or this returns early \
         at the `!shared_exact()` gate and proves nothing"
    );

    assert!(
        cos_queue_v_min_continue(queue, 1),
        "a shared_exact queue with no flow-fair state has no virtual time to \
         compare against peers, so the V_min lag check does not apply and the \
         drain must CONTINUE (#8428)"
    );
}
