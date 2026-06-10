// Tests for afxdp/cos/queue_service/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::*;
use crate::afxdp::FastMap;
use crate::afxdp::cos::admission::apply_cos_queue_flow_fair_promotion;
use crate::afxdp::cos::queue_ops::cos_queue_push_back;
use crate::afxdp::cos::tx_completion::COS_TIMER_WHEEL_TICK_NS;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{
    CoSQueueWaterfillCounters, SharedCoSExactBacklog, SharedCoSQueueLease, SharedCoSRootLease,
    V8RateMode, WorkerCoSInterfaceFastPath,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{PROTO_TCP, UMEM_FRAME_SHIFT};
use std::sync::Arc;

const TEST_EPOCH_DURATION_NS: u64 = 200_000;

#[test]
fn surplus_phase_selects_non_exact_queue_without_guarantee_tokens() {
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    let batch = select_cos_surplus_batch(&mut root, 1);

    assert!(matches!(
        batch,
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Surplus,
            ..
        })
    ));
}

#[test]
fn nonexact_guarantee_skips_residual_only_scheduler_map_queue() {
    let mut root = test_cos_runtime_with_queues(
        1_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: false,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 1500;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(
        select_nonexact_cos_guarantee_batch(&mut root, 1).is_none(),
        "residual-only queue must not consume non-exact guarantee service"
    );
    assert!(matches!(
        select_cos_surplus_batch(&mut root, 1),
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Surplus,
            ..
        })
    ));
}

fn residual_and_exact_test_root(exact_surplus_sharing: bool) -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                guarantee_enabled: false,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 10,
                forwarding_class: "iperf-24g".into(),
                priority: 5,
                transmit_rate_bytes: 24_000_000_000 / 8,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: exact_surplus_sharing,
                equal_flow_enforcement: false,
                surplus_weight: 16,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.runnable = true;
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.queued_bytes = 1500;
    }
    root.queues[0].hot.tokens = 0;
    root.queues[1].hot.tokens = 0;
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    root
}

fn residual_and_exact_fast_interfaces(
    shared_exact_backlog: Option<Arc<SharedCoSExactBacklog>>,
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    let mut fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![
            (0, test_queue_fast_path(false, 0, None, None)),
            (10, test_queue_fast_path(false, 0, None, None)),
        ],
        None,
        None,
    );
    if let Some(shared_exact_backlog) = shared_exact_backlog {
        fast_interfaces
            .get_mut(&42)
            .expect("test fast path")
            .shared_exact_backlog = Some(shared_exact_backlog);
    }
    fast_interfaces
}

#[test]
fn build_nonexact_suppresses_residual_surplus_when_local_exact_backlogged() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[1].config.transmit_rate_bytes = root.shaping_rate_bytes;
    root.queues[1].hot.tokens = 1500;
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "best-effort residual surplus must not drain when exact demand consumes the root shape"
    );
}

#[test]
fn build_nonexact_keeps_nonexact_guarantee_when_exact_backlogged() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[0].config.guarantee_enabled = true;
    root.queues[0].hot.tokens = 1500;
    root.queues[1].hot.tokens = 1500;
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let batch = build_nonexact_cos_batch(&mut binding, 42, 1)
        .expect("non-exact explicit transmit-rate guarantee must still drain");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Guarantee,
            ..
        }
    ));
}

#[test]
fn build_nonexact_allows_residual_surplus_when_local_exact_is_token_starved() {
    let root = residual_and_exact_test_root(false);
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let batch = build_nonexact_cos_batch(&mut binding, 42, 1)
        .expect("token-starved exact queue must not idle root while residual work is runnable");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn build_nonexact_suppresses_residual_surplus_when_peer_exact_backlogged() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[1].hot.items.clear();
    root.queues[1].hot.queued_bytes = 0;
    root.queues[1].hot.runnable = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    shared_exact_backlog.publish(1, 1500);
    let fast_interfaces = residual_and_exact_fast_interfaces(Some(shared_exact_backlog));
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "best-effort residual surplus must not drain while a peer binding reports exact backlog"
    );
}

#[test]
fn build_nonexact_allows_residual_surplus_when_peer_exact_budget_refills() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[1].hot.items.clear();
    root.queues[1].hot.queued_bytes = 0;
    root.queues[1].hot.runnable = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    shared_exact_backlog.publish_with_serviceable(1, 1500, 0, 1 << 1);
    let fast_interfaces = residual_and_exact_fast_interfaces(Some(shared_exact_backlog));
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "shared residual budget starts closed when peer exact demand appears"
    );
    let batch = build_nonexact_cos_batch(&mut binding, 42, 2_000_000)
        .expect("peer exact demand should allow only refilled residual surplus");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn build_nonexact_counts_shared_exact_queue_once_across_bindings() {
    let root = residual_and_exact_test_root(false);
    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    shared_exact_backlog.publish_with_serviceable(1, 1500, 0, 1 << 1);
    let fast_interfaces = residual_and_exact_fast_interfaces(Some(shared_exact_backlog));
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "shared residual budget starts closed when aggregate exact demand appears"
    );
    let batch = build_nonexact_cos_batch(&mut binding, 42, 2_000_000)
        .expect("local and peer backlog on the same exact queue reserve that queue's rate once");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn build_nonexact_still_allows_exact_surplus_sharing_when_exact_backlogged() {
    let mut root = residual_and_exact_test_root(true);
    root.queues[1].config.transmit_rate_bytes = root.shaping_rate_bytes;
    root.queues[1].hot.tokens = 1500;
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let batch = build_nonexact_cos_batch(&mut binding, 42, 1)
        .expect("surplus-sharing exact queue should remain surplus eligible");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 1,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn nonexact_guarantee_selects_explicit_transmit_rate_queue() {
    let mut root = test_cos_runtime_with_queues(
        1_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 1500;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(matches!(
        select_nonexact_cos_guarantee_batch(&mut root, 1),
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Guarantee,
            ..
        })
    ));
}

#[test]
fn fallback_root_shaped_default_queue_has_guarantee_service() {
    let mut root = test_cos_runtime_with_queues(
        1_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 1500;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(matches!(
        select_nonexact_cos_guarantee_batch(&mut root, 1),
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Guarantee,
            ..
        })
    ));
}

#[test]
fn surplus_phase_skips_exact_queue_without_guarantee_tokens() {
    let mut root = test_cos_runtime_with_exact(true);
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    assert!(select_cos_surplus_batch(&mut root, 1).is_none());
}

// #915: surplus_sharing=true on an exact queue with empty
// queue.hot.tokens — surplus selector picks it up because the
// `queue.config.exact && !surplus_sharing` skip evaluates to false.
#[test]
fn surplus_phase_includes_exact_with_surplus_sharing() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_surplus_batch(&mut root, 1);
    assert!(matches!(
        batch,
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Surplus,
            ..
        })
    ));
}

// #915 §4.5 isolation test: an exact queue with surplus_sharing
// must NOT be parked when queue.hot.tokens runs out in the
// exact-guarantee selector. The drain_park_queue_tokens counter
// still increments (diagnostic parity), but `runnable` stays
// true and `parked` stays false so surplus phase can pick the
// queue up on the same drain pass. Failure here catches the
// Codex round-1 MAJOR 1 regression.
#[test]
fn exact_with_surplus_sharing_not_parked_on_queue_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 1_000_000; // root has plenty of tokens
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0; // queue bucket empty
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.parked = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let pre_park_count = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);

    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    // Selector returns None because queue.hot.tokens<head_len AND
    // surplus_sharing skips parking.
    assert!(
        selection.is_none(),
        "exact-guarantee selector must not select a token-starved queue"
    );
    assert!(
        !root.queues[0].hot.parked,
        "surplus_sharing exact queue must NOT be parked"
    );
    assert!(
        root.queues[0].hot.runnable,
        "surplus_sharing exact queue must stay runnable"
    );
    let post_park_count = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        post_park_count,
        pre_park_count + 1,
        "drain_park_queue_tokens must still increment for diagnostic parity"
    );
}

// #915 Codex round-2 MINOR fix: the root-starvation branch in
// select_exact_cos_guarantee_queue_with_fast_path is also
// no-park'd for surplus_sharing exact queues (the §4.5 fix
// addressed only the queue-token branch in plan v3; round-1
// code review caught that the EARLIER root-token branch had
// the same problem). Pin that branch directly: when both
// root.tokens AND queue.hot.tokens are short, a surplus_sharing
// exact queue still must NOT be parked by the exact-guarantee
// selector. The drain_park_root_tokens diagnostic counter
// still increments. The same-pass surplus selector then
// handles the root-only park with require_queue_tokens=false.
#[test]
fn exact_with_surplus_sharing_not_parked_on_root_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 0; // root bucket empty (root-token starvation)
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0; // queue bucket also empty
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.parked = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let pre_root_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_root_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    let pre_queue_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);

    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    // Selector returns None because root.tokens<head_len; the
    // root-starvation no-park branch fires first, so the queue
    // is not parked.
    assert!(
        selection.is_none(),
        "exact-guarantee selector must not select a root-starved queue"
    );
    assert!(
        !root.queues[0].hot.parked,
        "surplus_sharing exact queue must NOT be parked on root-token starvation"
    );
    assert!(
        root.queues[0].hot.runnable,
        "surplus_sharing exact queue must stay runnable"
    );
    let post_root_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_root_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    let post_queue_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        post_root_park,
        pre_root_park + 1,
        "drain_park_root_tokens must still increment for diagnostic parity"
    );
    assert_eq!(
        post_queue_park, pre_queue_park,
        "queue-token branch must NOT fire (we exited via root-token branch)"
    );

    // The same-pass surplus selector is the eventual park site
    // for root-token starvation: it uses require_queue_tokens=false
    // so the wake_tick is bound only by root refill. Verify it
    // parks the queue rather than leaving it spinning.
    let surplus = select_cos_surplus_batch(&mut root, 1);
    assert!(
        surplus.is_none(),
        "surplus selector returns None when root.tokens<head_len"
    );
    assert!(
        root.queues[0].hot.parked,
        "surplus selector must park the queue on root-token starvation"
    );
}

// #915 §4.5 contrast: a non-surplus-sharing exact queue still
// parks on queue-token starvation (preserves today's behavior).
#[test]
fn exact_without_surplus_sharing_parks_on_queue_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    // surplus_sharing left as false (default)
    root.tokens = 1_000_000;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let _ = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(
        root.queues[0].hot.parked,
        "non-surplus-sharing exact queue must be parked on queue-token starvation"
    );
}

// #915 production-order end-to-end smoke (Codex round-2 MINOR 4).
// The cleanest in-process production-order check is to call the
// exact-guarantee selector first and then the surplus selector
// — exactly what `drain_shaped_tx → service_exact_guarantee_*
// → build_nonexact_cos_batch → select_cos_surplus_batch` does in
// the real path. A surplus-sharing exact queue with empty
// queue.hot.tokens must NOT be picked by the exact-guarantee
// selector AND MUST be picked by the surplus selector on the
// same drain attempt.
#[test]
fn surplus_sharing_exact_reaches_surplus_through_full_drain_pass() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    // First: production-order exact-guarantee selector. Returns
    // None because queue.hot.tokens<head_len AND no parking (§4.5).
    let exact_pick = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(
        exact_pick.is_none(),
        "exact-guarantee selector must decline token-starved surplus_sharing queue"
    );

    // Then: surplus selector picks the queue up on the same pass.
    let surplus_pick = select_cos_surplus_batch(&mut root, 1);
    assert!(
        matches!(
            surplus_pick,
            Some(CoSBatch::Local {
                phase: CoSServicePhase::Surplus,
                ..
            })
        ),
        "surplus selector must pick up surplus_sharing exact queue \
         after exact-guarantee declines"
    );
}

#[test]
fn guarantee_phase_parks_non_exact_queue_on_root_only_wakeup() {
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 0;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    assert!(root.queues[0].hot.parked);
    assert_eq!(root.queues[0].hot.next_wakeup_tick, 30);
}

/// #1630 (P2): a low-rate queue with banked tokens drains its queued
/// frames whole in one visit, bounded by the per-visit FRAME-count cap
/// (`cos_guarantee_visit_cap_bytes` = TX_BATCH_SIZE × frame), NOT the
/// rate-scaled quantum. Before #1630 the 1 Mbps quantum (clamped to
/// 1500 B) limited the visit to a single frame and discarded the
/// sub-frame remainder, pinning the class near 60 % of its rate. Now
/// the rate is metered by `queue.hot.tokens` (refilled at the configured
/// rate) and the actual-byte debit, so a queue that has accumulated
/// tokens for several frames sends them in one pass.
#[test]
fn guarantee_phase_visit_cap_drains_banked_frames() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 64 * 1024;
    // Bank enough tokens for all four queued frames.
    root.queues[0].hot.tokens = 64 * 1024;
    root.queues[0].hot.runnable = true;
    for _ in 0..4 {
        root.queues[0].hot.items.push_back(test_cos_item(1500));
    }
    root.queues[0].hot.queued_bytes = 4 * 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
    match batch {
        CoSBatch::Local { items, .. } => assert_eq!(items.len(), 4),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(root.queues[0].hot.items.len(), 0);
}

#[test]
fn guarantee_phase_allows_larger_high_rate_visit_quantum() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000u64 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000u64 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 256 * 1024;
    root.queues[0].hot.tokens = 256 * 1024;
    root.queues[0].hot.runnable = true;
    for _ in 0..200 {
        root.queues[0].hot.items.push_back(test_cos_item(1500));
    }
    root.queues[0].hot.queued_bytes = 200 * 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    // #920: TX_BATCH_SIZE lowered 256 → 64 caps a single visit at
    // 64 items even when token budget would permit more (~166).
    // The remaining tokens stay with the queue for the next visit;
    // throughput is preserved across multiple shorter visits, with
    // the trade-off that mouse packets get an interleave point
    // every 64 packets instead of every 256.
    let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
    match batch {
        CoSBatch::Local { items, .. } => assert_eq!(items.len(), TX_BATCH_SIZE),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(root.queues[0].hot.items.len(), 200 - TX_BATCH_SIZE);
}

/// #920: separate from the batch-cap test above. Asserts the
/// rate-quantum invariant guarded by the original test name —
/// a 10 Gbps queue gets a strictly larger byte-budget visit
/// quantum than a 100 Mbps queue, regardless of TX_BATCH_SIZE.
/// Guards against silent regression if `cos_guarantee_quantum_bytes`
/// stops scaling with `transmit_rate_bytes`.
#[test]
fn guarantee_phase_quantum_scales_with_rate() {
    // cos_guarantee_quantum_bytes reached via super in cos/queue_service.
    let high_rate = test_cos_runtime_with_queues(
        10_000_000_000u64 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000u64 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let low_rate = test_cos_runtime_with_queues(
        100_000_000u64 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-low".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000u64 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let high_q = cos_guarantee_quantum_bytes(&high_rate.queues[0]);
    let low_q = cos_guarantee_quantum_bytes(&low_rate.queues[0]);
    assert!(
        high_q > low_q,
        "high-rate quantum ({high_q}) must exceed low-rate quantum ({low_q})"
    );
}

#[test]
fn guarantee_phase_rotates_between_backlogged_queues() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "af11".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.tokens = 64 * 1024;
        queue.hot.runnable = true;
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.queued_bytes = 2 * 1500;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    let first = select_cos_guarantee_batch(&mut root, 1).expect("first guarantee batch");
    let second = select_cos_guarantee_batch(&mut root, 1).expect("second guarantee batch");

    match first {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 0),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    match second {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
}

#[test]
fn exact_and_nonexact_guarantee_rr_cursors_advance_independently() {
    // #689 regression. Prior to the cursor split, serving an exact
    // queue advanced the shared `guarantee_rr` and could cause the
    // non-exact pass to skip a waiting queue on its next run. Pin
    // that the exact pass does not touch `nonexact_guarantee_rr`
    // and vice versa.
    let mut root = test_mixed_class_root_with_primed_queues();
    assert_eq!(root.exact_guarantee_rr, 0);
    assert_eq!(root.nonexact_guarantee_rr, 0);

    // Serving an exact queue must not disturb the non-exact cursor.
    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
        .expect("exact queue selection");
    assert_eq!(selection.queue_idx, 0);
    assert_eq!(
        root.exact_guarantee_rr, 1,
        "exact cursor must advance past the served queue"
    );
    assert_eq!(
        root.nonexact_guarantee_rr, 0,
        "serving an exact queue must not advance the non-exact cursor"
    );

    // Serving a non-exact queue must not disturb the exact cursor.
    let batch = select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact queue batch");
    match batch {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(
        root.exact_guarantee_rr, 1,
        "non-exact service must not advance the exact cursor"
    );
    assert_eq!(
        root.nonexact_guarantee_rr, 2,
        "non-exact cursor must advance past the served queue"
    );
}

#[test]
fn exact_guarantee_rr_walks_exact_queues_in_order_independent_of_nonexact() {
    // Exact queues must rotate exact-0 -> exact-2 -> exact-0 -> exact-2
    // regardless of non-exact activity between calls. #689 before-fix
    // behavior under the shared cursor was: exact-0 served (rr=1),
    // then a non-exact service would bump rr past exact-2's position,
    // so the next exact call would skip exact-2 and loop back to
    // exact-0. This test pins that the split cursor rotates exact
    // queues deterministically without regard for non-exact service.
    // Helper primes eight 1500-byte items and sets `queued_bytes`
    // to match; no additional priming needed here. Only bump
    // queue.hot.tokens on the exact queues to make sure they never hit
    // token-starvation during the four interleaved rounds below —
    // the exact selector does not refill exact-queue tokens itself
    // (that is done by the shared-lease path), so this test bypasses
    // that machinery by handing the queues a large local budget.
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }

    let mut exact_order = Vec::new();
    for _ in 0..4 {
        // Interleave a non-exact service between exact calls; the exact
        // rotation must not notice.
        let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
            .expect("exact queue");
        exact_order.push(selection.queue_idx);
        // Service a non-exact queue to simulate concurrent class activity;
        // ignore the result.
        let _ = select_nonexact_cos_guarantee_batch(&mut root, 1);
    }
    assert_eq!(exact_order, vec![0, 2, 0, 2]);
}

#[test]
fn nonexact_guarantee_rr_walks_nonexact_queues_in_order_independent_of_exact() {
    // Symmetric to the exact test: non-exact rotation is 1 -> 3 -> 1 -> 3
    // regardless of exact-queue activity between calls. Helper primes
    // eight 1500-byte items per queue with `queued_bytes` already
    // consistent; no additional priming needed.
    let mut root = test_mixed_class_root_with_primed_queues();

    let mut nonexact_order = Vec::new();
    for _ in 0..4 {
        let batch = select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact batch");
        let queue_idx = match batch {
            CoSBatch::Local { queue_idx, .. } => queue_idx,
            CoSBatch::Prepared { queue_idx, .. } => queue_idx,
        };
        nonexact_order.push(queue_idx);
        // Interleave an exact service; must not disturb non-exact rotation.
        let _ = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    }
    assert_eq!(nonexact_order, vec![1, 3, 1, 3]);
}

#[test]
fn legacy_guarantee_rr_does_not_advance_class_cursors() {
    // The entire reason `legacy_guarantee_rr` exists as a third cursor
    // (instead of the legacy unified selector reusing one of the
    // production cursors) is to keep the legacy walk isolated from the
    // production exact/nonexact rotation state. Pin that contract:
    // a call through the legacy selector must advance only its own
    // cursor, never the two production cursors.
    let mut root = test_mixed_class_root_with_primed_queues();
    let batch = select_cos_guarantee_batch(&mut root, 1).expect("legacy guarantee batch");
    // Served something, so `legacy_guarantee_rr` advanced.
    match batch {
        CoSBatch::Local { queue_idx, .. } => {
            assert_eq!(queue_idx, 0, "legacy walk starts at index 0");
        }
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(root.legacy_guarantee_rr, 1);
    // Production cursors untouched — this is the isolation guarantee
    // that justifies the extra field over reusing either production
    // cursor for the legacy walk.
    assert_eq!(
        root.exact_guarantee_rr, 0,
        "legacy selector must not advance exact production cursor"
    );
    assert_eq!(
        root.nonexact_guarantee_rr, 0,
        "legacy selector must not advance nonexact production cursor"
    );
}

#[test]
fn guarantee_rr_cursors_start_at_zero_after_runtime_build() {
    // Pin the invariant that a fresh runtime starts with both cursors
    // at 0. `build_cos_interface_runtime` is the one production init
    // site; any refactor that accidentally leaves a cursor uninitialized
    // or drops one of the fields fails here.
    let root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "q0".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    assert_eq!(root.exact_guarantee_rr, 0);
    assert_eq!(root.nonexact_guarantee_rr, 0);
    assert_eq!(root.legacy_guarantee_rr, 0);
}

#[test]
fn surplus_phase_prefers_higher_priority_queue() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "bulk".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "voice".into(),
                priority: 0,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.last_refill_ns = 1;
        queue.hot.tokens = 0;
        queue.hot.runnable = true;
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.queued_bytes = 1500;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    let batch = select_cos_surplus_batch(&mut root, 1).expect("surplus batch");
    match batch {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
}

#[test]
fn surplus_phase_applies_weighted_same_priority_sharing() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "small".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "large".into(),
                priority: 5,
                transmit_rate_bytes: 4_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 4,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.last_refill_ns = 1;
        queue.hot.tokens = 0;
        queue.hot.runnable = true;
        for _ in 0..8 {
            queue.hot.items.push_back(test_cos_item(1500));
        }
        queue.hot.queued_bytes = 8 * 1500;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    let first = select_cos_surplus_batch(&mut root, 1).expect("first surplus batch");
    let second = select_cos_surplus_batch(&mut root, 1).expect("second surplus batch");

    match first {
        CoSBatch::Local {
            queue_idx, items, ..
        } => {
            assert_eq!(queue_idx, 0);
            assert_eq!(items.len(), 1);
        }
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    match second {
        CoSBatch::Local {
            queue_idx, items, ..
        } => {
            assert_eq!(queue_idx, 1);
            assert_eq!(items.len(), 4);
        }
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
}

/// Pin that `apply_cos_queue_flow_fair_promotion` propagates the
/// per-queue `shared_exact` bits correctly when the interface
/// has a mix of shared_exact and owner-local-exact queues — the
/// common production shape (a low-rate iperf-a queue next to a
/// high-rate iperf-c queue on the same interface). Breaking the
/// zip alignment between `runtime.queues` and
/// `iface_fast.queue_fast_path` at the
/// `ensure_cos_interface_runtime` call site would swap the two
/// queues' `shared_exact` shadows and their `flow_fair` bits,
/// silently routing both to the wrong admission branch and
/// turning off SFQ on the iperf-a queue (re-breaking #784).
#[test]
fn apply_promotion_pairs_queues_with_their_fast_path_entries() {
    let mut runtime = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![
            CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );

    // Position 0 -> owner-local-exact; position 1 -> shared_exact.
    let fast_path = vec![
        test_queue_fast_path_for_promotion(false),
        test_queue_fast_path_for_promotion(true),
    ];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

    assert!(
        runtime.queues[0].flow_fair(),
        "queue at position 0 (iperf-a, shared_exact=false) must \
         be on the flow-fair path — #784 fairness fix depends on it",
    );
    assert!(
        !runtime.queues[0].shared_exact(),
        "queue at position 0 must get position-0's shared_exact=false",
    );
    assert!(
        runtime.queues[1].flow_fair(),
        "#785 Phase 3: queue at position 1 (iperf-c, \
         shared_exact=true) must also be on the flow-fair path \
         so MQFQ VFT ordering enforces per-flow fairness. The \
         admission gates (cos_queue_flow_share_limit, \
         apply_cos_admission_ecn_policy) separately downgrade to \
         aggregate-only on shared_exact queues.",
    );
    assert!(
        runtime.queues[1].shared_exact(),
        "queue at position 1 must get position-1's shared_exact=true \
         — zip misalignment would silently mis-route admission policy",
    );
}

#[test]
fn equal_flow_cap_reaches_drain_shaped_tx_entry_path() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: true,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 100_000;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.runnable = true;
    root.queues[0].v_min.worker_id = 0;
    enable_test_flow_fair(&mut root.queues[0]);
    while test_flow_fair_state(&root.queues[0]).active_flow_buckets < 4 {
        let port = 10_000 + root.queues[0].hot.local_item_count as u16;
        cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(port, 1500));
    }

    let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
    ));
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    root.queues[0].queue_lease_v8 = Some(lease.clone());
    let _ = lease.acquire_v8(0, TEST_EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, TEST_EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(0, 2 * TEST_EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * TEST_EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(1, 3 * TEST_EPOCH_DURATION_NS, 1);
    assert!(lease.v8_equal_flow_enforced());

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        4,
        vec![(4, test_queue_fast_path(true, 0, None, Some(lease.clone())))],
        None,
        None,
    );
    let queued_before = root.queues[0].hot.queued_bytes;
    let root_tokens_before = root.tokens;
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let mut shared_recycles = Vec::new();

    let drained = drain_shaped_tx(
        &mut binding,
        3 * TEST_EPOCH_DURATION_NS,
        &mut shared_recycles,
    )
    .expect("drain_shaped_tx must service the exact equal-flow queue");

    assert_eq!(drained.root_ifindex, 42);
    assert_eq!(drained.queue_idx, 0);
    assert_eq!(drained.queue_id, 4);
    let sent_bytes = binding
        .live
        .tx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(sent_bytes > 0);
    assert!(sent_bytes <= 7_200);
    assert!(
        lease.v8_equal_flow_cap_hit_events() > 0,
        "drain_shaped_tx must route through equal-flow lease top-up"
    );
    assert_eq!(binding.cos.cos_queue_lease_acquire_v8_calls, 1);
    assert_eq!(binding.cos.cos_queue_lease_acquire_v8_granted_bytes, 7_200);
    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(
        root.queues[0].hot.queued_bytes,
        queued_before.saturating_sub(sent_bytes)
    );
    // #1630 (P2): the per-visit budget is now a FRAME-count cap rather
    // than the rate-scaled quantum (which clamped a 100 Mbps class to a
    // single frame per visit). The four equal-flow frames drain in one
    // pass, leaving the queue empty. `refresh_cos_interface_activity`
    // then sees `nonempty_queues == 0` and calls `release_cos_root_lease`,
    // which returns the worker's unused root credit to the shared pool
    // (`core::mem::take(&mut root.tokens)`). So after a drain that empties
    // the interface, root.tokens is 0 — the unspent root tokens were not
    // leaked, they were released. (Pre-#1630 the queue stayed backlogged
    // after one frame, so the release path did not fire and root.tokens
    // was `root_tokens_before - sent_bytes`.)
    assert!(
        root.queues[0].hot.items.is_empty(),
        "all four equal-flow frames must drain in one visit under the P2 frame-cap"
    );
    assert_eq!(
        root.tokens, 0,
        "emptying the interface releases the unused root lease to the shared pool"
    );
    assert_eq!(
        root.queues[0]
            .telemetry
            .owner_profile
            .drain_sent_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        sent_bytes
    );
}

#[test]
fn drain_shaped_tx_skips_root_prime_for_parked_not_due_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    park_cos_queue(&mut root, 0, 10);

    let root_lease = Arc::new(SharedCoSRootLease::new(
        root.shaping_rate_bytes,
        root.burst_bytes,
        1,
    ));
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        Some(root_lease),
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let mut shared_recycles = Vec::new();

    let drained = drain_shaped_tx(
        &mut binding,
        9 * COS_TIMER_WHEEL_TICK_NS,
        &mut shared_recycles,
    );

    assert!(drained.is_none());
    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(
        root.timer_wheel.current_tick, 0,
        "not-yet-due parked queues must not advance the timer wheel"
    );
    assert_eq!(
        root.tokens, 0,
        "not-yet-due parked queues must not top up the root lease"
    );
    assert!(root.queues[0].hot.parked);
    assert!(!root.queues[0].hot.runnable);
}

#[test]
fn drain_shaped_tx_primes_and_services_due_parked_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    park_cos_queue(&mut root, 0, 10);

    let root_lease = Arc::new(SharedCoSRootLease::new(
        root.shaping_rate_bytes,
        root.burst_bytes,
        1,
    ));
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        Some(root_lease),
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let mut shared_recycles = Vec::new();

    let drained = drain_shaped_tx(
        &mut binding,
        10 * COS_TIMER_WHEEL_TICK_NS,
        &mut shared_recycles,
    )
    .expect("due parked queue must wake and service");

    assert_eq!(drained.root_ifindex, 42);
    assert_eq!(drained.queue_idx, 0);
    assert_eq!(drained.queue_id, 0);
    assert!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
}

use crate::afxdp::types::{
    COS_FLOW_FAIR_BUCKETS, CoSQueueConfig, CoSQueueDropCounters, CoSQueueOwnerProfile, FlowRrRing,
};

#[test]
fn cos_batch_tx_made_progress_requires_real_send_progress() {
    assert!(!cos_batch_tx_made_progress(Ok((0, 0))));
    assert!(cos_batch_tx_made_progress(Ok((1, 0))));
    assert!(cos_batch_tx_made_progress(Ok((0, 1500))));
}

#[test]
fn cos_batch_tx_made_progress_yields_on_retry_and_drop() {
    assert!(!cos_batch_tx_made_progress(Err(TxError::Retry(
        "no free TX frame available".to_string()
    ))));
    assert!(!cos_batch_tx_made_progress(Err(TxError::Drop(
        "tx ring insert failed".to_string()
    ))));
}

#[test]
fn drain_exact_local_fifo_items_to_scratch_keeps_queue_until_commit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1, 2, 3, 4],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![5, 6, 7, 8],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 256,
            len: 4,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut free_tx_frames = VecDeque::from([64, 128, 192]);
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 2);
    assert_eq!(free_tx_frames, VecDeque::from([192]));
    assert_eq!(area.slice(64, 4).expect("first frame"), &[1, 2, 3, 4]);
    assert_eq!(area.slice(128, 4).expect("second frame"), &[5, 6, 7, 8]);
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Local(_))
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(2),
        Some(CoSPendingTxItem::Prepared(_))
    ));
}

#[test]
fn drain_exact_local_fifo_drops_mirror_clone_before_tx_reserve() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "mirror".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    cos_queue_push_back(
        &mut root.queues[0],
        CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1, 2, 3, 4],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: true,
            enqueue_ns: 0,
        }),
    );
    let mut free_tx_frames = (0..MIRROR_TX_FRAME_RESERVE as u64)
        .map(|idx| idx << UMEM_FRAME_SHIFT)
        .collect::<VecDeque<_>>();
    let original_free = free_tx_frames.clone();
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(
        build,
        ExactCoSScratchBuild::MirrorTxFrameReserve { dropped_bytes: 4 }
    ));
    assert!(scratch_local_tx.is_empty());
    assert_eq!(free_tx_frames, original_free);
    assert!(root.queues[0].hot.items.is_empty());
}

#[test]
fn release_exact_local_scratch_frames_preserves_queue_after_failed_submit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![2],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    let mut free_tx_frames = VecDeque::from([64, 128]);
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    release_exact_local_scratch_frames(&mut free_tx_frames, &mut scratch_local_tx);
    assert!(scratch_local_tx.is_empty());
    assert_eq!(free_tx_frames, VecDeque::from([64, 128]));
    assert_eq!(root.queues[0].hot.items.len(), 2);
    match root.queues[0].hot.items.pop_front().expect("first queued") {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![1]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
    }
    match root.queues[0].hot.items.pop_front().expect("second queued") {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
    }
}

#[test]
fn settle_exact_local_fifo_submission_pops_only_committed_prefix() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![2],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    let mut free_tx_frames = VecDeque::new();
    let mut scratch_local_tx = vec![
        ExactLocalScratchTxRequest { offset: 64, len: 1 },
        ExactLocalScratchTxRequest {
            offset: 128,
            len: 1,
        },
        ExactLocalScratchTxRequest {
            offset: 192,
            len: 1,
        },
    ];

    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        1,
    );

    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert!(scratch_local_tx.is_empty());
    assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
    assert_eq!(root.queues[0].hot.items.len(), 2);
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("first restored")
    {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
    }
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("second restored")
    {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![3]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
    }
}

#[test]
fn release_exact_prepared_scratch_preserves_queue_after_failed_submit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 4,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    let frame = unsafe { area.slice_mut_unchecked(64, 4) }.expect("frame");
    frame.copy_from_slice(&[1, 2, 3, 4]);
    let mut scratch_prepared_tx = Vec::new();
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    release_exact_prepared_scratch(&mut scratch_prepared_tx);
    assert!(scratch_prepared_tx.is_empty());
    assert_eq!(root.queues[0].hot.items.len(), 1);
    match root.queues[0].hot.items.front().expect("queued prepared") {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 64),
        CoSPendingTxItem::Local(_) => panic!("unexpected local item"),
    }
}

#[test]
fn settle_exact_prepared_fifo_submission_pops_only_committed_prefix() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 128,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 192,
            len: 1,
            recycle: PreparedTxRecycle::FillOnSlot(9),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    let mut scratch_prepared_tx = vec![
        ExactPreparedScratchTxRequest { offset: 64, len: 1 },
        ExactPreparedScratchTxRequest {
            offset: 128,
            len: 1,
        },
        ExactPreparedScratchTxRequest {
            offset: 192,
            len: 1,
        },
    ];
    let mut in_flight_prepared_recycles = FastMap::default();

    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        Some(&mut root.queues[0]),
        &mut scratch_prepared_tx,
        &mut in_flight_prepared_recycles,
        1,
    );

    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert!(scratch_prepared_tx.is_empty());
    assert_eq!(
        in_flight_prepared_recycles.get(&64),
        Some(&PreparedTxRecycle::FillOnSlot(7))
    );
    assert!(!in_flight_prepared_recycles.contains_key(&128));
    assert!(!in_flight_prepared_recycles.contains_key(&192));
    assert_eq!(root.queues[0].hot.items.len(), 2);
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("first restored")
    {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 128),
        CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
    }
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("second restored")
    {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 192),
        CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
    }
}

#[test]
fn assign_local_dscp_rewrite_preserves_existing_filter_rewrite() {
    let mut items = VecDeque::from([
        TxRequest {
            bytes: vec![0; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        },
        TxRequest {
            bytes: vec![0; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: Some(0),
            mirror_clone: false,
            enqueue_ns: 0,
        },
    ]);

    assign_local_dscp_rewrite(&mut items, Some(46));

    assert_eq!(items[0].dscp_rewrite, Some(46));
    assert_eq!(items[1].dscp_rewrite, Some(0));
}

#[test]
fn estimate_cos_queue_wakeup_tick_uses_token_deficits() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].hot.tokens = 0;

    let wake_tick = estimate_cos_queue_wakeup_tick(
        root.tokens,
        root.shaping_rate_bytes,
        root.queues[0].hot.tokens,
        root.queues[0].transmit_rate_bytes(),
        1500,
        0,
        true,
    )
    .expect("wake tick");

    assert_eq!(wake_tick, 30);
}

#[test]
fn estimate_cos_queue_wakeup_tick_ignores_queue_deficit_for_surplus() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].hot.tokens = 0;

    let wake_tick = estimate_cos_queue_wakeup_tick(
        root.tokens,
        root.shaping_rate_bytes,
        root.queues[0].hot.tokens,
        root.queues[0].transmit_rate_bytes(),
        1500,
        0,
        false,
    )
    .expect("wake tick");

    assert_eq!(wake_tick, 30);
}

#[test]
fn restore_cos_local_items_marks_queue_runnable_after_retry() {
    let mut queue = CoSQueueRuntime {
        config: crate::afxdp::types::CoSQueueConfigState {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            flow_fair_eligible: false,
            shared_exact: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        },
        hot: crate::afxdp::types::CoSQueueHotState {
            surplus_deficit: 0,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,
            cos_demote_empty_settles: 0,
        },
        flow_fair_state: None,
        v_min: crate::afxdp::types::VMinQueueState {
            vtime_floor: None,
            worker_id: 0,
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
            v_min_throttles_scratch: 0,
        },
        telemetry: crate::afxdp::types::CoSQueueTelemetry {
            drop_counters: CoSQueueDropCounters::default(),
            waterfill_counters: CoSQueueWaterfillCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            sojourn: crate::afxdp::types::CoSQueueSojourn::default(),
        },
        queue_lease_v8: None,
    };
    let retry = VecDeque::from([TxRequest {
        bytes: vec![0; 1500],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    }]);

    let retry_bytes = restore_cos_local_items_inner(&mut queue, retry);

    assert_eq!(queue.hot.items.len(), 1);
    assert_eq!(retry_bytes, 1500);
    assert!(queue.hot.runnable);
    assert!(!queue.hot.parked);
}

#[test]
fn restore_cos_prepared_items_marks_queue_runnable_after_retry() {
    let mut queue = CoSQueueRuntime {
        config: crate::afxdp::types::CoSQueueConfigState {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            flow_fair_eligible: false,
            shared_exact: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        },
        hot: crate::afxdp::types::CoSQueueHotState {
            surplus_deficit: 0,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,
            cos_demote_empty_settles: 0,
        },
        flow_fair_state: None,
        v_min: crate::afxdp::types::VMinQueueState {
            vtime_floor: None,
            worker_id: 0,
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
            v_min_throttles_scratch: 0,
        },
        telemetry: crate::afxdp::types::CoSQueueTelemetry {
            drop_counters: CoSQueueDropCounters::default(),
            waterfill_counters: CoSQueueWaterfillCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            sojourn: crate::afxdp::types::CoSQueueSojourn::default(),
        },
        queue_lease_v8: None,
    };
    let retry = VecDeque::from([PreparedTxRequest {
        offset: 64,
        len: 1500,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    }]);

    let retry_bytes = restore_cos_prepared_items_inner(&mut queue, retry);

    assert_eq!(queue.hot.items.len(), 1);
    assert_eq!(retry_bytes, 1500);
    assert!(queue.hot.runnable);
    assert!(!queue.hot.parked);
}

#[test]
fn estimate_cos_queue_wakeup_tick_root_rate_zero_returns_some() {
    // #916: transparent root. When `root_rate_bytes == 0` and
    // queue_rate is non-zero, the root-refill question is
    // meaningless (transparent semantics: bucket always full).
    // Pre-fix: cos_refill_ns_until(_, _, 0) → None propagated by
    // `?` → the caller skips parking AND the queue stays in
    // limbo. Post-fix: bypass the root-refill check.
    let wake_tick = estimate_cos_queue_wakeup_tick(
        0, 0, // root: zero tokens, zero rate (transparent)
        0, 1_000_000, // queue: zero tokens, 1 Mbps rate
        1500, 0, true,
    );
    assert!(
        wake_tick.is_some(),
        "transparent root + queue with rate must produce a wake tick (Some)",
    );
}

#[test]
fn estimate_cos_queue_wakeup_tick_both_rates_zero_returns_some() {
    // #916: transparent root + transparent queue. Both refill
    // checks must be bypassed; estimator returns the next-tick
    // wake-tick (1ns past now ≈ next-tick).
    let wake_tick = estimate_cos_queue_wakeup_tick(
        0, 0, // root: transparent
        0, 0, // queue: transparent
        1500, 0, true,
    );
    assert!(
        wake_tick.is_some(),
        "fully transparent (root + queue both rate=0) must produce a wake tick (Some)",
    );
}

#[test]
fn estimate_cos_queue_wakeup_tick_root_rate_zero_with_require_queue_false() {
    // #916: surplus path (require_queue_tokens = false). With
    // transparent root, the root-refill check is bypassed; the
    // queue-refill check is skipped because require=false. Result
    // should be Some(_).
    let wake_tick = estimate_cos_queue_wakeup_tick(
        0, 0, // root: transparent
        0, 0, // queue: irrelevant when require=false
        1500, 0, false,
    );
    assert!(wake_tick.is_some());
}

// #1614 A1: waterfill selector tests.

#[test]
fn waterfill_default_proportional_mode_uses_legacy_rr() {
    // Default oversubscription_policy (Proportional) + fraction 0
    // must bypass the new waterfill and use legacy RR cursor. The
    // selector advances `exact_guarantee_rr` per call.
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    assert!(matches!(
        root.oversubscription_policy,
        CoSOversubscriptionPolicy::Proportional
    ));
    assert_eq!(root.oversubscription_guarantee_fraction, 0.0);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 2");
    // Legacy RR walks exact queues 0 → 2 → 0 → 2.
    assert_eq!(s1.queue_idx, 0);
    assert_eq!(s2.queue_idx, 2);
}

#[test]
fn waterfill_guarantee_rate_mode_picks_smallest_rate_first() {
    // GuaranteeRate mode with fraction > 0 routes to the waterfill
    // selector which iterates `exact_queues_by_rate_ascending`.
    // With two exact queues at SAME slow_rate (test_mixed_class
    // fixture), sorted-stable preserves queue_id order so the
    // smaller-queue_idx is selected first.
    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 0.7;
    // Build the sorted vector now (in production this happens at
    // config-apply time).
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    root.exact_queues_by_rate_ascending
        .sort_by_key(|&idx| root.queues[idx].config.transmit_rate_bytes);
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    // Both exact queues have the same slow_rate; stable-sorted order
    // preserves queue_idx ascending, so queue_idx 0 picks first.
    assert_eq!(s1.queue_idx, 0);
}

#[test]
fn waterfill_guarantee_rate_skips_non_exact_queues() {
    // The waterfill iterates only over exact queues (via
    // exact_queues_by_rate_ascending). Non-exact queues are
    // unaffected.
    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 0.5;
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    // Drain both exact queues entirely.
    for _ in 0..4 {
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    // After draining exacts, non-exact selector still works.
    let batch = select_nonexact_cos_guarantee_batch(&mut root, 1);
    assert!(batch.is_some(), "non-exact RR must remain reachable");
}

#[test]
fn waterfill_guarantee_rate_fraction_consulted_by_selector() {
    // Step-1 coverage: confirm the selector consults the
    // `guarantee_fraction` value rather than using it as a boolean.
    // Direct internal-state check: after one Phase 1 selection at
    // fraction=0.2, `waterfill_pass1_remaining_bytes` is strictly
    // less than the corresponding value at fraction=1.0 (the
    // budget refills to `quantum_sum * fraction`, so 0.2 produces
    // a strictly smaller initial budget and a strictly smaller
    // remaining value after one decrement).
    //
    // Note: this test does NOT pin the VISIBLE per-queue
    // distribution change under oversubscription — that is the
    // step-2 #1625 contract and requires the per-queue
    // per-epoch byte allocation mechanism not implemented in
    // step-1. Codex r1 #1+#2 are deferred to #1625.
    fn pass1_remaining_after_one_selection(frac: f64) -> u64 {
        let mut root = test_mixed_class_root_with_primed_queues();
        root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
        root.oversubscription_guarantee_fraction = frac;
        root.exact_queues_by_rate_ascending = (0..root.queues.len())
            .filter(|&idx| {
                root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled
            })
            .collect();
        // Give every exact queue a large per-queue token budget so
        // the only gate is the Phase 1 byte budget.
        for queue in &mut root.queues {
            if queue.config.exact {
                queue.hot.tokens = 128 * 1024;
            }
        }
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        // One selection in GuaranteeRate mode triggers the
        // Phase-1 budget refill via `pass1_remaining_bytes == 0`
        // gate, then decrements by the chosen queue's
        // secondary_budget. So `pass1_remaining_bytes` after one
        // selection is `(quantum_sum * frac).floor() - first_budget`.
        let _ =
            select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
        root.waterfill_pass1_remaining_bytes
    }
    let r_lo = pass1_remaining_after_one_selection(0.2);
    let r_hi = pass1_remaining_after_one_selection(1.0);
    // Internal-state invariant: fraction=1.0 refills the budget
    // to the full quantum_sum and fraction=0.2 refills to 20%
    // of it. After one identical decrement, the lower fraction
    // MUST leave a strictly smaller remaining budget. This
    // proves the selector consults `oversubscription_guarantee_fraction`
    // as a numeric value, not a boolean.
    assert!(
        r_hi > r_lo,
        "fraction=1.0 pass1_remaining ({r_hi}) must exceed fraction=0.2 ({r_lo})"
    );
    // Also: fraction=0.2 must produce a strictly smaller initial
    // budget than fraction=1.0 by at least 4x (1.0 / 0.2 = 5x).
    // After one decrement, the gap shrinks slightly; assert ≥ 2x
    // remains as a robust invariant.
    assert!(
        r_hi >= r_lo.saturating_mul(2),
        "fraction ratio not reflected in pass1_remaining: lo={r_lo} hi={r_hi}"
    );
}

/// #1732: build a GuaranteeRate root with THREE exact queues at distinct,
/// unequal `transmit_rate_bytes` chosen so each queue's
/// `cos_guarantee_quantum_bytes` is DISTINCT and strictly above the
/// `COS_GUARANTEE_QUANTUM_MIN_BYTES` (1500) floor (so the Phase-1 cost
/// ordering is rate-driven, not all clamped to the min). queue_idx order ==
/// ascending-rate order so a returned `queue_idx` directly names the
/// ascending ordinal. Every queue gets abundant per-queue tokens AND the
/// root gets abundant tokens, so the ONLY gate is the Phase-1 byte budget
/// (`fraction × quantum_sum`) — the selector gates on root tokens (`:856`,
/// `:1034`) and queue tokens (`:879`), all made non-binding here.
///
/// Rates: 100 Mbps / 400 Mbps / 1 Gbps → quantums 2500 / 10000 / 25000 B
/// (rate_bytes × 200_000 ns / 1e9). quantum_sum = 37500.
fn waterfill_three_unequal_exact_root(frac: f64) -> CoSInterfaceRuntime {
    fn exact_queue(queue_id: u8, fc: &str, rate_bytes: u64) -> CoSQueueConfig {
        CoSQueueConfig {
            queue_id,
            forwarding_class: fc.into(),
            priority: 5,
            transmit_rate_bytes: rate_bytes,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }
    }
    // #1743: the Phase-1 budget is now `shaper × VISIT_NS × fraction`, not
    // `quantum_sum × fraction`. Pin the shaper so cap_per_epoch equals the
    // quantum_sum (37,500 B) — `shaper × 200µs = 37,500` ⇒ shaper =
    // 187,500,000 B/s (1.5 Gbps). That keeps the per-epoch budget identical
    // to the pre-#1743 `quantum_sum`-based value at any fraction, so the
    // budget-break-into-Phase-2 semantics these tests pin are preserved
    // under the corrected formula.
    let mut root = test_cos_runtime_with_queues(
        187_500_000,
        vec![
            exact_queue(0, "exact-100m", 100_000_000 / 8),
            exact_queue(1, "exact-400m", 400_000_000 / 8),
            exact_queue(2, "exact-1g", 1_000_000_000 / 8),
        ],
    );
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = frac;
    // Built at config-apply time in production; rebuild here (stable sort by
    // ascending rate keeps queue_idx order, so ordinal i == queue_idx).
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    root.exact_queues_by_rate_ascending
        .sort_by_key(|&idx| root.queues[idx].config.transmit_rate_bytes);
    // Root tokens abundant so the root-token gate never fires.
    root.tokens = 8 * 1024 * 1024;
    for queue in &mut root.queues {
        // Abundant per-queue tokens (queue-token gate never fires) + frozen
        // refill clock so the selector sees a steady token bucket. Multi-item
        // backlog so no queue drains to empty across the epoch's selections.
        queue.hot.tokens = 1024 * 1024;
        queue.hot.last_refill_ns = 1;
        queue.hot.runnable = true;
        for _ in 0..8 {
            queue.hot.items.push_back(test_cos_item(1500));
        }
        queue.hot.queued_bytes = 8 * 1500;
    }
    root.nonempty_queues = root.queues.len();
    root.runnable_queues = root.queues.len();
    root
}

#[test]
fn waterfill_persistent_honored_set_distributes_phase1_across_queues() {
    // #1732: the persistent honored set makes Phase 1 honor each exact
    // queue AT MOST ONCE per epoch, smallest-rate-first, instead of
    // re-honoring the smallest queue on every selector call (the lowest-rate
    // skew the issue reports). With three exact queues at quantums
    // 2500/10000/25000 and fraction=0.4, the Phase-1 budget is
    // floor(37500 * 0.4) = 15000 bytes:
    //   - selection 1: honor q0 (cost 2500), budget -> 12500
    //   - selection 2: q0 SKIPPED (already honored), honor q1 (cost 10000),
    //     budget -> 2500
    //   - selection 3: q0,q1 SKIPPED; q1->q2 cost 25000 > 2500 -> Phase 1
    //     breaks, Phase 2 serves the largest un-honored queue q2
    // The OLD (broken) selector would re-honor q0 on selections 2 and 3
    // because Phase 1 had no honored-skip, monopolising the budget on the
    // smallest queue.
    let mut root = waterfill_three_unequal_exact_root(0.4);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();

    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 2");
    let s3 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 3");

    // Per-epoch service order across >1 selection: ascending, at-most-once.
    assert_eq!(s1.queue_idx, 0, "selection 1 honors the smallest-rate queue");
    assert_eq!(
        s2.queue_idx, 1,
        "selection 2 must advance to the next-smallest queue, NOT re-honor q0 \
         (this is the broken-mask behavior the fix corrects)"
    );
    assert_eq!(
        s3.queue_idx, 2,
        "selection 3 must reach the largest queue (Phase 2 residual after the \
         Phase-1 budget is exhausted), NOT re-serve a honored queue"
    );

    // Each of the two small queues took exactly one Phase-1 admission; the
    // largest queue took a Phase-2 admission (no Phase-1 honor — its cost
    // exceeded the residual budget).
    assert_eq!(
        root.queues[0].telemetry.waterfill_counters.phase1_admissions, 1,
        "q0 honored once in Phase 1"
    );
    assert_eq!(
        root.queues[1].telemetry.waterfill_counters.phase1_admissions, 1,
        "q1 honored once in Phase 1"
    );
    assert_eq!(
        root.queues[2].telemetry.waterfill_counters.phase1_admissions, 0,
        "q2 not honored in Phase 1 (budget exhausted before it)"
    );
    assert_eq!(
        root.queues[2].telemetry.waterfill_counters.phase2_admissions, 1,
        "q2 served as Phase-2 residual"
    );

    // The persistent bitset carries q0 and q1's ORDINAL bits across calls
    // within the epoch (ordinal == queue_idx here). q2 (ordinal 2) is never
    // honored in Phase 1, so its bit stays clear.
    assert_eq!(
        root.waterfill_honored_epoch_bits & 0b011,
        0b011,
        "BOTH ordinals 0 and 1 must be marked honored within the epoch \
         (each small queue took exactly one Phase-1 honor)"
    );
    assert_eq!(
        root.waterfill_honored_epoch_bits & 0b100,
        0,
        "ordinal 2 (the Phase-2-served queue) must NOT be marked Phase-1-honored"
    );
}

#[test]
fn waterfill_honored_set_clears_on_epoch_refill() {
    // #1732: the honored bitset must clear at the lazy Phase-1 refill so a
    // new epoch starts with a fresh honored set (otherwise the smallest
    // queue would be permanently skipped after its first honor). Drive the
    // selector until the epoch exhausts, force a refill by zeroing the
    // Phase-1 budget, and confirm the bitset is cleared and the smallest
    // queue is honored FIRST again in the next epoch.
    let mut root = waterfill_three_unequal_exact_root(0.4);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();

    // Epoch 1: drive three selections (q0, q1, then Phase-2 q2).
    for _ in 0..3 {
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    assert_ne!(
        root.waterfill_honored_epoch_bits, 0,
        "honored bits accumulate within an epoch"
    );

    // Force a GENUINE epoch boundary: zero the Phase-1 budget AND arm
    // `waterfill_epoch_wrap_pending`, exactly as the end-of-function Phase-2
    // WRAP (`None`) path does. #1743 r3: a bare `pass1 == 0` alone refills the
    // budget but does NOT clear the honored bits (that avoids the exact-fit
    // livelock); only the time tick or a genuine wrap clears them — which is
    // what this #1732 test means by "epoch boundary".
    root.waterfill_pass1_remaining_bytes = 0;
    root.waterfill_epoch_wrap_pending = true;
    let epochs_before = root.waterfill_epochs;

    let s_next = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection of the new epoch");

    assert_eq!(
        root.waterfill_epochs,
        epochs_before + 1,
        "refill must bump the epoch counter"
    );
    assert_eq!(
        s_next.queue_idx, 0,
        "after the refill clears the honored set, the smallest queue is \
         honored first again (not permanently skipped)"
    );
    // Only q0's ordinal bit is set in the fresh epoch.
    assert_eq!(
        root.waterfill_honored_epoch_bits, 0b001,
        "fresh epoch: only the just-honored smallest queue (ordinal 0) is marked"
    );
}

// #1628: per-class waterfill trace-counter tests. These pin that the
// counters increment at the right SITES (not that any one counter is a
// unique fingerprint — that interpretation requires pairing with
// queued_bytes + *_starvation_parks per the struct docs).

/// Build a GuaranteeRate root with the ascending-by-rate vec populated
/// and every exact queue given abundant per-queue tokens so the only
/// gate is the Phase-1 byte budget.
fn waterfill_guarantee_rate_root(frac: f64) -> CoSInterfaceRuntime {
    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = frac;
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    root.exact_queues_by_rate_ascending
        .sort_by_key(|&idx| root.queues[idx].config.transmit_rate_bytes);
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    root
}

#[test]
fn waterfill_counters_phase1_honor_increments_admission_and_visit() {
    // fraction=1.0: the full quantum_sum budget easily honors the first
    // (smallest) exact queue in Phase 1.
    let mut root = waterfill_guarantee_rate_root(1.0);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("phase-1 selection");
    let q = &root.queues[s.queue_idx];
    assert_eq!(
        q.telemetry.waterfill_counters.phase1_admissions, 1,
        "Phase-1 honor must bump phase1_admissions on the chosen queue"
    );
    assert_eq!(
        q.telemetry.waterfill_counters.phase2_admissions, 0,
        "a Phase-1 honor must NOT bump phase2_admissions"
    );
    assert!(
        q.telemetry.waterfill_counters.eligible_visits >= 1,
        "the honored queue must have been counted as an eligible visit"
    );
    // The epoch refill ran exactly once on this first call.
    assert_eq!(
        root.waterfill_epochs, 1,
        "first selection lazily refills the Phase-1 budget = one epoch"
    );
    // Budget was sufficient: no Phase-1 break.
    assert_eq!(
        root.waterfill_phase1_budget_breaks, 0,
        "fraction=1.0 must not exhaust the Phase-1 budget on the first queue"
    );
}

#[test]
fn waterfill_counters_proportional_mode_stays_zero() {
    // Counter-factual: on the Proportional (legacy RR) path, NONE of the
    // waterfill counters may move. A wrong write site (outside the
    // waterfill fn) would light these up here.
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    assert!(matches!(
        root.oversubscription_policy,
        CoSOversubscriptionPolicy::Proportional
    ));
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("legacy RR selection");
    assert_eq!(root.waterfill_epochs, 0);
    assert_eq!(root.waterfill_phase1_budget_breaks, 0);
    for q in &root.queues {
        assert_eq!(q.telemetry.waterfill_counters.phase1_admissions, 0);
        assert_eq!(q.telemetry.waterfill_counters.phase2_admissions, 0);
        assert_eq!(q.telemetry.waterfill_counters.eligible_visits, 0);
    }
}

#[test]
fn waterfill_counters_budget_break_into_phase2() {
    // A tiny fraction makes the Phase-1 budget too small to honor even
    // the first ascending queue's rate-scaled cost, forcing the break
    // into Phase 2 — which then admits a queue. Assert the per-interface
    // budget-break counter fires AND a Phase-2 admission is recorded.
    //
    // fraction is clamped 0.0..=1.0 at config-apply; here we set it
    // directly. With frac so small that floor(quantum_sum * frac) <
    // any single queue's quantum, the first ascending queue's
    // phase1_cost exceeds the remaining budget at mod.rs:906.
    let mut root = waterfill_guarantee_rate_root(0.0001);
    // #1743: use a TRANSPARENT root (shaping_rate_bytes == 0) so the
    // Phase-1 budget takes the legacy `quantum_sum × fraction` path. After
    // bumping the exact queues to 3 Gbps (quantum 75,000 B), raw pass1 =
    // floor(quantum_sum × 0.0001) is a few bytes, which the symmetric
    // anti-thrash clamp (Codex r1 #2) raises to one min-quantum (1500 B).
    // To force the Phase-1 break we need every exact queue's quantum to
    // EXCEED that clamped 1500 B floor — 75,000 B ≫ 1500 — so the clamped
    // budget is below every quantum and Phase 1 breaks immediately into
    // Phase 2. (The clamp itself is verified separately in
    // waterfill_pass1_tiny_fraction_clamped_to_min_quantum.)
    root.shaping_rate_bytes = 0;
    for q in &mut root.queues {
        if q.config.exact {
            q.config.transmit_rate_bytes = 3_000_000_000 / 8;
        }
    }
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("phase-2 selection after budget break");
    assert_eq!(
        root.waterfill_phase1_budget_breaks, 1,
        "an exhausted Phase-1 budget must bump the per-interface break counter"
    );
    let q = &root.queues[s.queue_idx];
    assert_eq!(
        q.telemetry.waterfill_counters.phase2_admissions, 1,
        "the Phase-2 walk must bump phase2_admissions on the chosen queue"
    );
    assert_eq!(
        q.telemetry.waterfill_counters.phase1_admissions, 0,
        "a Phase-2 admission must NOT bump phase1_admissions"
    );
    // Epoch refilled once (budget was 0 on entry).
    assert_eq!(root.waterfill_epochs, 1);
}

#[test]
fn waterfill_counters_phase1_admit_flake_5x() {
    // Stability pin: the Phase-1 honor counters are deterministic across
    // repeated fresh roots (the selector has no RNG on this path).
    for _ in 0..5 {
        let mut root = waterfill_guarantee_rate_root(1.0);
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
            .expect("phase-1 selection");
        assert_eq!(
            root.queues[s.queue_idx]
                .telemetry
                .waterfill_counters
                .phase1_admissions,
            1
        );
        assert_eq!(root.waterfill_epochs, 1);
    }
}

// ---------------------------------------------------------------------------
// #1743: shaper-anchored Phase-1 budget + stable honor charge + time refresh.
// ---------------------------------------------------------------------------

#[test]
fn waterfill_pass1_anchored_to_shaper_per_epoch() {
    // #1743 Hunk A: for a SHAPED root the Phase-1 budget must be
    // `shaper × VISIT_NS × fraction`, NOT `quantum_sum × fraction`. The
    // smoke fixture is oversubscribed (Σ R_i ≫ shaper), so the old formula
    // over-budgeted pass1 by ~4× and Phase-2 never fired. Pin the corrected
    // budget directly: a 25 Gbps shaper at fraction 0.7 yields
    // floor(25e9/8 × 200µs × 0.7) = floor(625_000 × 0.7) = 437_500 B,
    // regardless of how large the sum of configured class rates is.
    let mut root = waterfill_three_unequal_exact_root(0.7);
    root.shaping_rate_bytes = 25_000_000_000 / 8;
    // First selector call takes the exhausted refill path (pass1 seeded 0)
    // and computes the shaper-anchored budget. Inspect it before any honor
    // debit by checking the value the refill installs: drive one call then
    // add back the single honor charge it consumed.
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection");
    let charged = cos_guarantee_quantum_bytes(&root.queues[s.queue_idx])
        .max(1500 /* head_len of the primed 1500-byte item */);
    let installed_budget = root.waterfill_pass1_remaining_bytes + charged;
    assert_eq!(
        installed_budget, 437_500,
        "Phase-1 budget must be shaper × VISIT_NS × fraction (437,500 B at \
         25 Gbps / 0.7), not the oversubscribed quantum_sum × fraction"
    );
}

#[test]
fn waterfill_pass1_transparent_root_fallback_to_quantum_sum() {
    // #1743 Hunk A: a TRANSPARENT root (shaping_rate_bytes == 0) has no
    // shaper-delivered cap to anchor against, so it must fall back to the
    // legacy quantum_sum × fraction. Quanta 2500/10000/25000, sum 37,500;
    // fraction 0.4 ⇒ budget floor(37_500 × 0.4) = 15_000 B.
    let mut root = waterfill_three_unequal_exact_root(0.4);
    root.shaping_rate_bytes = 0;
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection");
    let charged = cos_guarantee_quantum_bytes(&root.queues[s.queue_idx]).max(1500);
    let installed_budget = root.waterfill_pass1_remaining_bytes + charged;
    assert_eq!(
        installed_budget, 15_000,
        "transparent-root budget must use quantum_sum × fraction (15,000 B)"
    );
}

#[test]
fn waterfill_phase1_honor_charge_is_configured_quantum_not_tokens() {
    // #1743 Hunk B: the Phase-1 honor charge must be the STABLE configured
    // quantum, NOT `queue.hot.tokens.min(quantum)`. Under v8-lease pressure
    // tokens collapse toward one frame; the old charge then fell to head_len,
    // the queue was marked fully honored for ~one frame, and Phase-2 skipped
    // it. With the fixed charge a token-pressured small queue still consumes
    // its full quantum against pass1 (or is left for Phase-2 if it does not
    // fit), so the budget is spent honestly.
    //
    // Shaper anchored so the budget equals quantum_sum (37,500 B) at frac 1.0
    // (see waterfill_three_unequal_exact_root). Pin q1's tokens to exactly
    // one frame; its configured quantum is 10,000 B (400 Mbps × 200µs).
    let mut root = waterfill_three_unequal_exact_root(1.0);
    // q0 quantum 2,500; q1 quantum 10,000; q2 quantum 25,000; sum 37,500.
    // Starve q1's token bank to one frame to exercise the old undercharge.
    root.queues[1].hot.tokens = 1500;
    let q1_quantum = cos_guarantee_quantum_bytes(&root.queues[1]);
    assert!(
        q1_quantum > root.queues[1].hot.tokens,
        "precondition: configured quantum exceeds the depleted token bank"
    );
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // Selection 1 honors q0 (smallest). Selection 2 reaches q1.
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    let budget_before_q1 = root.waterfill_pass1_remaining_bytes;
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 2");
    assert_eq!(s2.queue_idx, 1, "selection 2 honors q1");
    let charged = budget_before_q1 - root.waterfill_pass1_remaining_bytes;
    assert_eq!(
        charged, q1_quantum,
        "Phase-1 must charge q1's FULL configured quantum ({q1_quantum} B), \
         not its depleted token bank (1500 B) — the #1743 undercharge"
    );
}

#[test]
fn waterfill_pass1_refreshes_on_time_tick_clears_honored_bits() {
    // #1743 Hunk C: under saturation Phase-2 does not decrement pass1, so the
    // budget never hits 0 and the legacy exhausted-refill never fires. The
    // time-based path must refresh pass1 AND clear the persistent honored
    // bitset once `now_ns - epoch_start >= COS_GUARANTEE_VISIT_NS`, while
    // PRESERVING the Phase-2 cursor.
    //
    // Codex code-r1: use the DEFAULT 187,500,000 B/s shaper (cap_per_epoch
    // == quantum_sum == 37,500 B) so at fraction 0.7 the budget is 26,250 B
    // — enough to honor q0 (2,500) + q1 (10,000) in Phase 1 but NOT q2
    // (25,000) — which forces a Phase-2 admit and advances the cursor to a
    // NONZERO value. A 25 Gbps override here would budget 437,500 B, honor
    // all three queues in Phase 1, never advance Phase 2, and leave the
    // cursor at 0 — making the preservation assertion vacuous.
    let mut root = waterfill_three_unequal_exact_root(0.7);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // Epoch 1 at t = 1ns: honor q0+q1 (sets honored bits) and serve q2 in
    // Phase 2 (advances the cursor to nonzero).
    for _ in 0..3 {
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    assert_ne!(
        root.waterfill_honored_epoch_bits, 0,
        "honored bits accumulate within epoch 1"
    );
    let cursor_after_epoch1 = root.waterfill_phase2_cursor;
    assert_ne!(
        cursor_after_epoch1, 0,
        "epoch 1 must have advanced the Phase-2 cursor (a Phase-2 admit \
         occurred) so the preservation assertion below is non-vacuous"
    );
    let pass1_mid_epoch = root.waterfill_pass1_remaining_bytes;
    assert_ne!(pass1_mid_epoch, 0, "pass1 is non-zero mid-epoch (not exhausted)");
    let epochs_before = root.waterfill_epochs;

    // Advance the clock past one VISIT_NS without ever zeroing pass1. The
    // time-based refresh must fire on the next call.
    let next_ns = 1 + COS_GUARANTEE_VISIT_NS + 1;
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], next_ns, &mut tel)
        .expect("selection after time refresh");

    assert_eq!(
        root.waterfill_epochs,
        epochs_before + 1,
        "the time-based refresh must bump the epoch counter"
    );
    assert_eq!(
        root.waterfill_epoch_start_ns, next_ns,
        "the refresh must re-seed epoch_start_ns to now_ns"
    );
    // The honored bitset was cleared at the refresh, then the smallest queue
    // was re-honored on this same call — so only ordinal 0's bit is set now.
    assert_eq!(
        root.waterfill_honored_epoch_bits, 0b001,
        "timed refresh must clear honored bits, then Phase-1 re-honors q0"
    );
    assert_eq!(
        root.waterfill_phase2_cursor, cursor_after_epoch1,
        "the time-based refresh must PRESERVE the Phase-2 cursor (#1743 r2: \
         neither refill path resets it — only a genuine Phase-2 wrap does)"
    );
}

#[test]
fn waterfill_pass1_undersubscribed_shaper_honors_all_classes() {
    // Codex r1 #6: when the shaper is UNDERSUBSCRIBED (shaper > Σ R_i) the
    // cap-anchored budget is ≥ quantum_sum, so Phase-1 can honor every class
    // without spuriously pushing any to Phase-2. Shaper 10 Gbps, quanta
    // 2500/10000/25000 (sum 37,500), fraction 1.0 ⇒ cap_per_epoch =
    // floor(10e9/8 × 200µs) = 250,000 B ⇒ budget 250,000 ≫ 37,500.
    let mut root = waterfill_three_unequal_exact_root(1.0);
    root.shaping_rate_bytes = 10_000_000_000 / 8;
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("s1");
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("s2");
    let s3 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("s3");
    assert_eq!((s1.queue_idx, s2.queue_idx, s3.queue_idx), (0, 1, 2));
    for qi in 0..3 {
        assert_eq!(
            root.queues[qi].telemetry.waterfill_counters.phase1_admissions, 1,
            "queue {qi} must be honored in Phase 1 under an undersubscribed shaper"
        );
        assert_eq!(
            root.queues[qi].telemetry.waterfill_counters.phase2_admissions, 0,
            "no class should fall to Phase 2 when shaper > Σ R_i"
        );
    }
}

#[test]
fn waterfill_pass1_tiny_fraction_clamped_to_min_quantum() {
    // AGY RISK-1: a tiny-positive fraction floors the shaped budget to 0,
    // which would make `exhausted` true every call → refill + cursor-reset
    // thrash. The shaped path clamps pass1 to ≥ COS_GUARANTEE_QUANTUM_MIN_BYTES
    // so at least the smallest class is honorable and the exhausted path does
    // not fire on every selector call.
    let mut root = waterfill_three_unequal_exact_root(0.0000001);
    root.shaping_rate_bytes = 25_000_000_000 / 8;
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // The tiny fraction floors raw to 0; the clamp installs pass1 =
    // COS_GUARANTEE_QUANTUM_MIN_BYTES (1500). 1500 is below the smallest
    // class quantum (2500), so Phase-1 breaks immediately into Phase-2 —
    // which still admits the largest un-honored queue. The point: pass1 is
    // NOT 0, so the exhausted path does not fire on every call.
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection still admits via Phase-2");
    // Phase-1 broke before honoring anyone and Phase-2 does not debit pass1,
    // so the installed clamped budget is observable directly.
    assert_eq!(
        root.waterfill_pass1_remaining_bytes, COS_GUARANTEE_QUANTUM_MIN_BYTES,
        "a tiny fraction must clamp the Phase-1 budget to one min-quantum, \
         not floor it to 0"
    );
    assert_eq!(
        root.queues[s.queue_idx].telemetry.waterfill_counters.phase2_admissions, 1,
        "the budget-broke selection is served by Phase-2"
    );
    assert_eq!(
        root.waterfill_phase1_budget_breaks, 1,
        "Phase-1 broke because the clamped budget (1500) is below the \
         smallest quantum (2500)"
    );
}

#[test]
fn waterfill_exhausted_refill_does_not_reset_phase2_cursor() {
    // #1743 (Codex code-r2): the exhausted (`pass1 == 0`) refill path must
    // NOT reset the Phase-2 cursor. A degenerate config can land pass1 at
    // exactly 0 after a Phase-1 honor (phase1_cost == the remaining budget),
    // returning before Phase 2 — so an exhausted-refill cursor reset on the
    // next call would restart the descending walk from the largest class and
    // starve it. Only a genuine Phase-2 wrap (the end-of-function `None`
    // path) may reset the cursor. Pin that an exhausted refill preserves a
    // nonzero cursor.
    let mut root = waterfill_three_unequal_exact_root(0.7);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // Drive epoch 1 to advance the Phase-2 cursor to a nonzero value (q0+q1
    // honored Phase-1, q2 served Phase-2 — see the time-tick test).
    for _ in 0..3 {
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    let cursor = root.waterfill_phase2_cursor;
    assert_ne!(cursor, 0, "precondition: Phase-2 cursor advanced in epoch 1");
    // Force the exhausted refill path WITHOUT advancing the clock (so it is
    // the exhausted trigger, not the time-based one) by zeroing pass1.
    root.waterfill_pass1_remaining_bytes = 0;
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    assert_eq!(
        root.waterfill_phase2_cursor, cursor,
        "the exhausted refill path must PRESERVE the Phase-2 cursor; only a \
         genuine Phase-2 wrap (`None` path) may reset it"
    );
}

#[test]
fn waterfill_exact_fit_honor_does_not_livelock_phase1() {
    // #1743 (Codex code-r3): the deeper degenerate-config defect. When a
    // Phase-1 exact-fit honor subtracts the budget to exactly 0, the next
    // call's bare `exhausted` refill must NOT clear the honored bitset — only
    // a genuine epoch boundary (time tick OR Phase-2 wrap) clears it.
    // Clearing on a bare mid-walk `pass1 == 0` re-enabled a livelock: q0
    // honored → pass1=0 → next call clears q0's bit → q0 re-honored → … with
    // Phase 2 NEVER reached, starving every larger class.
    //
    // Fixture: shaper 187,500,000 B/s (cap_per_epoch == quantum_sum ==
    // 37,500 B); fraction tuned so the Phase-1 budget == q0's quantum exactly
    // (2,500 B). q0 (100m, quantum 2,500) is an exact-fit honor; q1 (400m,
    // 10,000) and q2 (1g, 25,000) must still get Phase-2 service.
    let mut root = waterfill_three_unequal_exact_root(2_500.0 / 37_500.0);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();

    // Call 1: Phase-1 honors q0 (cost 2,500), pass1 → 0.
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("call 1");
    assert_eq!(s1.queue_idx, 0, "call 1 honors q0 (smallest, exact-fit)");
    assert_eq!(
        root.waterfill_pass1_remaining_bytes, 0,
        "the exact-fit honor drained pass1 to exactly 0"
    );

    // Drive several more calls at the SAME now_ns (no time tick) and confirm
    // a non-q0 queue is serviced — i.e. Phase 2 IS reached, no livelock. With
    // the pre-r3 bug (clearing bits on bare exhausted) q0 would be re-honored
    // on every call and q1/q2 would never run.
    let mut serviced_non_q0 = false;
    let mut q0_admits = 0u64;
    for _ in 0..8 {
        if let Some(s) =
            select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        {
            if s.queue_idx == 0 {
                q0_admits += 1;
            } else {
                serviced_non_q0 = true;
            }
        }
    }
    assert!(
        serviced_non_q0,
        "Phase 2 must service a larger class within a few calls — q0's \
         exact-fit honor must not livelock Phase 1 (the #1743 r3 defect)"
    );
    // q0 is honored at most once per genuine epoch boundary, not on every
    // bare-exhausted refill. Over 8 same-tick calls it cannot dominate.
    assert!(
        q0_admits <= 2,
        "q0 must not be re-honored on every bare-exhausted refill (got \
         {q0_admits} Phase-1 admits in 8 same-tick calls)"
    );
}

// ---------------------------------------------------------------------------
// #1829 Phase 1: sojourn telemetry at the fused #1763 dequeue-commit
// boundary. These pin (a) the FIFO batch-build arm and the flow-fair
// drain arms record `now_ns - enqueue_ns` into
// `queue.telemetry.sojourn` exactly at pop commit, and (b) the
// `enqueue_ns == 0` legacy guard records NOTHING at the queue level
// (plan invariant 10).
// ---------------------------------------------------------------------------

/// Stamp the Local item's `enqueue_ns` (test items default to 0).
fn stamp_cos_item(mut item: CoSPendingTxItem, enqueue_ns: u64) -> CoSPendingTxItem {
    match &mut item {
        CoSPendingTxItem::Local(req) => req.enqueue_ns = enqueue_ns,
        CoSPendingTxItem::Prepared(req) => req.enqueue_ns = enqueue_ns,
    }
    item
}

#[test]
fn sojourn_recorded_at_fifo_surplus_batch_pop_commit() {
    use crate::afxdp::types::COS_SOJOURN_WINDOW_NS;
    let now_ns = 10 * COS_SOJOURN_WINDOW_NS;
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = now_ns;
    root.queues[0].hot.tokens = 0;
    root.queues[0]
        .hot
        .items
        .push_back(stamp_cos_item(test_cos_item(1500), now_ns - 5_000_000));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_surplus_batch(&mut root, now_ns);
    assert!(batch.is_some(), "surplus batch must build");

    let sojourn = &root.queues[0].telemetry.sojourn;
    assert_eq!(sojourn.peak_ns, 5_000_000);
    assert_eq!(sojourn.windowed_min_export(now_ns), 5_000_000);
    assert!(sojourn.ewma_ns > 0);
}

#[test]
fn sojourn_recorded_at_flow_fair_local_drain_commit() {
    use crate::afxdp::types::COS_SOJOURN_WINDOW_NS;
    let now_ns = 10 * COS_SOJOURN_WINDOW_NS;
    let area = MmapArea::new(65536).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let fast_path = vec![test_queue_fast_path_for_promotion(false)];
    apply_cos_queue_flow_fair_promotion(&mut root, &fast_path, 0);
    assert!(root.queues[0].flow_fair());
    // Two flows with distinct stamps: the windowed min must be the
    // SMALLER sojourn, the peak the larger.
    cos_queue_push_back(
        &mut root.queues[0],
        stamp_cos_item(test_flow_cos_item(5201, 512), now_ns - 7_000_000),
    );
    cos_queue_push_back(
        &mut root.queues[0],
        stamp_cos_item(test_flow_cos_item(5202, 512), now_ns - 3_000_000),
    );
    root.queues[0].hot.queued_bytes = 1024;

    let mut free_tx_frames = VecDeque::from([0u64, 4096]);
    let mut scratch_local_tx = Vec::new();
    let build = drain_exact_local_items_to_scratch_flow_fair(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
        now_ns,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 2);

    let sojourn = &root.queues[0].telemetry.sojourn;
    assert_eq!(sojourn.peak_ns, 7_000_000);
    assert_eq!(sojourn.windowed_min_export(now_ns), 3_000_000);
    // Snapshot taken ≥ 2 windows later must report a zero windowed
    // min (no fresh standing-queue evidence), while peak persists.
    assert_eq!(
        sojourn.windowed_min_export(now_ns + 2 * COS_SOJOURN_WINDOW_NS),
        0
    );
}

#[test]
fn sojourn_recorded_at_flow_fair_prepared_drain_commit() {
    use crate::afxdp::types::COS_SOJOURN_WINDOW_NS;
    let now_ns = 10 * COS_SOJOURN_WINDOW_NS;
    let area = MmapArea::new(65536).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let fast_path = vec![test_queue_fast_path_for_promotion(false)];
    apply_cos_queue_flow_fair_promotion(&mut root, &fast_path, 0);
    cos_queue_push_back(
        &mut root.queues[0],
        stamp_cos_item(
            test_flow_prepared_cos_item(5201, 512, 4096),
            now_ns - 4_000_000,
        ),
    );
    root.queues[0].hot.queued_bytes = 512;

    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    let mut shared_recycles = Vec::new();
    let mut scratch_prepared_tx = Vec::new();
    let build = drain_exact_prepared_items_to_scratch_flow_fair(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        0,
        &mut shared_recycles,
        u64::MAX,
        u64::MAX,
        None,
        now_ns,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_prepared_tx.len(), 1);

    let sojourn = &root.queues[0].telemetry.sojourn;
    assert_eq!(sojourn.peak_ns, 4_000_000);
    assert_eq!(sojourn.windowed_min_export(now_ns), 4_000_000);
}

#[test]
fn sojourn_zero_stamp_items_record_nothing_at_drain() {
    use crate::afxdp::types::CoSQueueSojourn;
    let now_ns = 1_000_000_000;
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = now_ns;
    root.queues[0].hot.tokens = 0;
    // test_cos_item leaves enqueue_ns at 0 (the pre-#1829 / non-CoS
    // construction default) — the drain must record NOTHING.
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_surplus_batch(&mut root, now_ns);
    assert!(batch.is_some(), "surplus batch must build");
    assert_eq!(
        root.queues[0].telemetry.sojourn,
        CoSQueueSojourn::default(),
        "enqueue_ns == 0 must be treated as no-data, never a sample",
    );
}
