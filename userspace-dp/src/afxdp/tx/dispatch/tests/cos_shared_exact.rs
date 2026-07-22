// #1598 shared-exact CoS TX-dispatch policy tests: `request_runs_under_shared_
// exact_policy` for requested/default queue, the non-exact uncapped
// shared_exact=true-with-no-lease admission, single-owner rejection, and
// unknown queue/interface fallback. Local fixtures `test_cos_fast_interfaces`
// and `test_cos_fast_interfaces_decoupled`.

use super::*;

fn test_cos_fast_interfaces(
    egress_ifindex: i32,
    default_queue: u8,
    shared_exact_queues: &[(u8, bool)],
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    // Legacy fixture: shared_exact AND shared_queue_lease set together.
    // For the post-#1598 decoupled case where a queue can be
    // shared_exact=true with NO lease (non-exact uncapped class), use
    // `test_cos_fast_interfaces_decoupled` below.
    let decoupled: Vec<(u8, bool, bool)> = shared_exact_queues
        .iter()
        .copied()
        .map(|(queue_id, shared_exact)| (queue_id, shared_exact, shared_exact))
        .collect();
    test_cos_fast_interfaces_decoupled(egress_ifindex, default_queue, &decoupled)
}

fn test_cos_fast_interfaces_decoupled(
    egress_ifindex: i32,
    default_queue: u8,
    queues: &[(u8, bool, bool)],
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    // Each tuple: (queue_id, shared_exact, has_lease).
    // The pair (true, false) models the #1598 non-exact uncapped case:
    // the routing-level shared_exact flag is set, but the
    // exact-only `shared_queue_lease` is absent.
    let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
    let mut queue_fast_path = Vec::new();
    for (idx, (queue_id, shared_exact, has_lease)) in queues.iter().copied().enumerate() {
        queue_index_by_id[usize::from(queue_id)] = idx as u16;
        queue_fast_path.push(WorkerCoSQueueFastPath {
            shared_exact,
            owner_worker_id: 0,
            owner_live: None,
            shared_queue_lease: has_lease
                .then(|| Arc::new(SharedCoSQueueLease::new(1_250_000_000, 256 * 1024, 2))),
            vtime_floor: None,
        });
    }
    let mut interfaces = FastMap::default();
    interfaces.insert(
        egress_ifindex,
        WorkerCoSInterfaceFastPath {
            tx_ifindex: 11,
            default_queue_index: queue_index_by_id[usize::from(default_queue)] as usize,
            queue_index_by_id,
            tx_owner_live: None,
            shared_root_lease: None,
            shared_exact_backlog: None,
            queue_fast_path,
        },
    );
    interfaces
}

#[test]
fn shared_exact_policy_uses_requested_queue_id() {
    let cos_fast_interfaces = test_cos_fast_interfaces(80, 5, &[(5, true)]);

    assert!(request_runs_under_shared_exact_policy(
        &cos_fast_interfaces,
        80,
        Some(5),
    ));
    assert!(!request_runs_under_shared_exact_policy(
        &cos_fast_interfaces,
        80,
        Some(4),
    ));
}

#[test]
fn shared_exact_policy_uses_interface_default_queue() {
    let cos_fast_interfaces = test_cos_fast_interfaces(80, 5, &[(5, true)]);

    assert!(request_runs_under_shared_exact_policy(
        &cos_fast_interfaces,
        80,
        None,
    ));
}

#[test]
fn shared_exact_policy_admits_non_exact_uncapped_queue_without_lease() {
    // #1598 secondary fix: non-exact uncapped queues run under
    // `shared_exact = true` (from worker/cos/mod.rs:126-131) but have
    // NO `shared_queue_lease` (filtered out at coordinator/mod.rs:1058
    // because `!queue.exact`). The TX-dispatch path must keep these
    // requests local rather than funneling them to a single
    // owner_worker_id; that is precisely the failure mode that the
    // smoke run caught (port 5211 push P=12 capped at ~9 Gbps even
    // after the primary fix).
    let cos_fast_interfaces = test_cos_fast_interfaces_decoupled(
        80,
        11,
        // queue 11: shared_exact = true, has_lease = false (uncapped class)
        &[(11, true, false)],
    );

    assert!(
        request_runs_under_shared_exact_policy(&cos_fast_interfaces, 80, Some(11)),
        "#1598: non-exact uncapped queue with shared_exact=true must \
         signal 'stay local' to the TX dispatch, even with no lease"
    );
    // Verify the state divergence at the source — `shared_exact=true`
    // AND `shared_queue_lease=None` is the post-#1598 production shape
    // that the previous lease-as-proxy gate mis-classified. This pin
    // ensures the test fixture actually models the failure mode (not
    // a coincidental shape that happens to pass the new helper).
    let iface_fast = cos_fast_interfaces.get(&80).expect("iface fixture");
    let queue_fast = iface_fast
        .queue_fast_path(Some(11))
        .expect("queue 11 fixture");
    assert!(
        queue_fast.shared_exact,
        "#1598 fixture invariant: queue 11 must have shared_exact=true"
    );
    assert!(
        queue_fast.shared_queue_lease.is_none(),
        "#1598 fixture invariant: queue 11 must have shared_queue_lease=None \
         to model the non-exact uncapped class"
    );
}

#[test]
fn shared_exact_policy_rejects_single_owner_queue() {
    // Single-owner queue (low-rate exact or non-exact below threshold)
    // has shared_exact = false. The policy helper must return false so
    // the dispatch path routes to owner_worker_id (the intended
    // single-FIFO arbitration domain for low-rate classes — #680/#690).
    let cos_fast_interfaces = test_cos_fast_interfaces_decoupled(
        80,
        1,
        // queue 1: shared_exact = false, has_lease = true (this would be
        // a hypothetical legacy state — verify the helper still says no)
        &[(1, false, true)],
    );
    assert!(
        !request_runs_under_shared_exact_policy(&cos_fast_interfaces, 80, Some(1)),
        "#1598: shared_exact=false must keep the request funnel-routed \
         to the queue owner regardless of lease presence"
    );
}

#[test]
fn shared_exact_policy_handles_unknown_queue() {
    // Defensive: a request whose `cos_queue_id` does not resolve in
    // the fast-path table must return false (the dispatch path falls
    // back to single-owner / local TX). This mirrors the existing
    // is_some_and shape on the lease-only helper.
    let cos_fast_interfaces = test_cos_fast_interfaces_decoupled(80, 5, &[(5, true, true)]);
    assert!(
        !request_runs_under_shared_exact_policy(&cos_fast_interfaces, 80, Some(42)),
        "an unknown queue_id must not be reported as shared_exact policy"
    );
    assert!(
        !request_runs_under_shared_exact_policy(&cos_fast_interfaces, 999, Some(5)),
        "an unknown egress_ifindex must not be reported as shared_exact policy"
    );
}

#[test]
fn cos_owner_live_for_request_borrows_map_owned_arc() {
    // #4972: `cos_owner_live_for_request` now returns a *borrow* of the
    // map-owned owner `Arc` rather than a per-eligible-packet clone. Both
    // callers only need a reference — `enqueue_local_request_to_target_or_
    // owner` for an `Arc::ptr_eq` + `enqueue_tx_owned(&self)`, and the
    // in-place-rewrite `owner_matches_target` gate for a bare `Arc::ptr_eq`.
    // The borrow-vs-clone distinction is a compile-time guarantee (the
    // return type is `Option<&Arc<..>>`); this test pins the *contract*
    // those callers depend on: the returned reference identifies the exact
    // `Arc` stored in the fast-path table (ptr-eq true), so the routing
    // decision is byte-identical to the pre-#4972 owned-clone behavior.
    use crate::afxdp::tx::test_support::{test_cos_fast_interfaces, test_queue_fast_path};

    let owner_live = Arc::new(BindingLiveState::new());
    let other_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        11,
        4,
        vec![
            (
                4,
                test_queue_fast_path(false, 7, Some(owner_live.clone()), None),
            ),
            (5, test_queue_fast_path(false, 7, None, None)),
        ],
        None,
        None,
    );

    // Queue 4 has an owner: the returned reference is ptr-eq to the exact
    // Arc held in the map (same allocation), not a distinct one.
    let got = cos_owner_live_for_request(&ifaces, 80, Some(4)).expect("owner present");
    assert!(
        Arc::ptr_eq(got, &owner_live),
        "must reference the map-owned owner Arc"
    );
    assert!(
        !Arc::ptr_eq(got, &other_live),
        "must not reference an unrelated Arc"
    );

    // Queue 5 has no owner: None (request funnels / stays local).
    assert!(cos_owner_live_for_request(&ifaces, 80, Some(5)).is_none());
    // Unknown queue id and unknown egress ifindex: None.
    assert!(cos_owner_live_for_request(&ifaces, 80, Some(42)).is_none());
    assert!(cos_owner_live_for_request(&ifaces, 999, Some(4)).is_none());
}
