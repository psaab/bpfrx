// #4800: tests for the publish and sibling-replication legs of the
// new-flow-install contention surface.
//
// The issue these serve exists because "new flows/sec plateaued" settles
// nothing. Three cross-worker synchronization points sit on every transit
// install — the SNAT allocator's map mutex (covered in
// `nat/tests_newflow_lock.rs`), `publish_shared_session`, and the N-way
// `replicate_session_upsert` fan-out — and the #2852 Phase-2 sharding
// decision turns on WHICH of them saturates first. These tests bind that
// each leg reports both its call rate and its blocked-acquisition count, and
// that the replication leg additionally reports queue DEPTH, because
// "producers collided on the mutex" and "the consumer is not draining" are
// different diagnoses with different fixes.
//
// NOTE on process-global statics: these counters are process-wide, and cargo
// runs tests in parallel inside one process, so a sibling test that publishes
// or replicates can inflate any reading taken here. Two disciplines keep that
// from becoming a flake generator (#6819):
//
//   * PUBLISH-side assertions are DELTAS with a `>=` bound in the direction
//     pollution can only push. Never an equality on an absolute value. `>=`
//     still binds, because under the revert the counters do not move at all
//     and the delta is 0.
//   * REPLICATION-side assertions may be exact, but only because
//     `replication_counter_test_guard` below serializes every test in the
//     process that touches those counters. Exactness is required there: a
//     `>=` bound cannot distinguish the per-call WORST sibling depth from the
//     sum ACROSS siblings, and getting that wrong inflates the analyzer's
//     mean by the fan-out so every run reads as backlogged.

use super::*;
use crate::afxdp::shared_ops::{
    SHARED_SESSION_PUBLISH_LOCK_ACQUISITIONS, SHARED_SESSION_PUBLISH_LOCK_CONTENDED,
    SHARED_SESSION_PUBLISHES, publish_shared_session, remove_shared_session,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const PROTO_TCP_LOCAL: u8 = 6;
const TCP_FLAG_ACK_LOCAL: u8 = 0x10;

/// Serialize every test that READS the process-global replication counters
/// against every test that MOVES them.
///
/// The counters are process-wide and cargo runs tests in parallel inside one
/// process, so a sibling test replicating a session between two readings
/// turns an exact delta into a flake (#6819). The depth-sum assertions need
/// exactness: a `>=` bound cannot distinguish the per-call WORST sibling
/// depth from the sum ACROSS siblings, and confusing those inflates the
/// analyzer's mean by the fan-out so every run reads as backlogged.
///
/// EVERY test that calls `replicate_session_upsert` or
/// `replicate_session_delete` must hold this guard, not only the ones that
/// assert on a counter — a mover without the guard defeats it just as
/// thoroughly as a reader without it. Today that is this file plus the two
/// poisoned-queue tests in `tests.rs`, which reach it as
/// `super::newflow_contention_tests::replication_counter_test_guard()`.
pub(super) fn replication_counter_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP_LOCAL,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5201,
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }
}

fn entry(src_port: u16) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: key(src_port),
        decision: SessionDecision {
            resolution: resolution(),
            nat: NatDecision::default(),
        },
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP_LOCAL,
        tcp_flags: TCP_FLAG_ACK_LOCAL,
        generation: 0,
        session_id: 0,
    }
}

type SharedMap = Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>;

struct SharedMaps {
    sessions: SharedMap,
    nat_sessions: SharedMap,
    forward_wire_sessions: SharedMap,
    indexes: SharedSessionOwnerRgIndexes,
}

impl SharedMaps {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            indexes: SharedSessionOwnerRgIndexes::default(),
        }
    }

    fn publish(&self, e: &SyncedSessionEntry) {
        publish_shared_session(
            &self.sessions,
            &self.nat_sessions,
            &self.forward_wire_sessions,
            &self.indexes,
            e,
        );
    }

    fn remove(&self, k: &SessionKey) {
        remove_shared_session(
            &self.sessions,
            &self.nat_sessions,
            &self.forward_wire_sessions,
            &self.indexes,
            k,
        );
    }
}

#[derive(Clone, Copy)]
struct PublishCounters {
    publishes: u64,
    acquisitions: u64,
    contended: u64,
}

fn publish_counters() -> PublishCounters {
    PublishCounters {
        publishes: SHARED_SESSION_PUBLISHES.load(Ordering::Relaxed),
        acquisitions: SHARED_SESSION_PUBLISH_LOCK_ACQUISITIONS.load(Ordering::Relaxed),
        contended: SHARED_SESSION_PUBLISH_LOCK_CONTENDED.load(Ordering::Relaxed),
    }
}

#[derive(Clone, Copy)]
struct ReplicationCounters {
    upserts: u64,
    enqueued: u64,
    contended: u64,
    depth_sum: u64,
    depth_max: u64,
}

fn replication_counters() -> ReplicationCounters {
    ReplicationCounters {
        upserts: SESSION_REPLICATION_UPSERTS.load(Ordering::Relaxed),
        enqueued: SESSION_REPLICATION_ENQUEUED.load(Ordering::Relaxed),
        contended: SESSION_REPLICATION_LOCK_CONTENDED.load(Ordering::Relaxed),
        depth_sum: SESSION_REPLICATION_QUEUE_DEPTH_SUM.load(Ordering::Relaxed),
        depth_max: SESSION_REPLICATION_QUEUE_DEPTH_MAX.load(Ordering::Relaxed),
    }
}

/// The publish leg reports a call count and a lock-acquisition count. The
/// call count is the publish-side new-flow rate; the acquisition count is the
/// denominator that makes the contention count below interpretable.
///
/// A forward (non-reverse) entry takes all three shared maps, so publishing
/// one entry must add at least three acquisitions — that "at least 3, not
/// exactly 1" shape is what pins the counter to the per-map acquisition
/// rather than to the call.
///
/// RED on revert: restoring `lock_shared_recover` at the three
/// `publish_shared_session` sites and dropping the `SHARED_SESSION_PUBLISHES`
/// bump leaves both deltas at 0 and both assertions fail on their messages.
#[test]
fn publish_shared_session_counts_calls_and_lock_acquisitions() {
    let maps = SharedMaps::new();
    let before = publish_counters();
    maps.publish(&entry(40000));
    let after = publish_counters();

    assert!(
        after.publishes >= before.publishes + 1,
        "publish_shared_session must count its call: {} -> {}",
        before.publishes,
        after.publishes
    );
    assert!(
        after.acquisitions >= before.acquisitions + 3,
        "a forward publish takes the sessions, nat_sessions and \
         forward_wire_sessions maps — expected >= 3 counted acquisitions, \
         saw {}",
        after.acquisitions - before.acquisitions
    );
}

/// The contention counter must fire when a sibling worker already holds a
/// shared map. Forced deterministically: the test thread parks on
/// `shared_sessions`, so the publishing thread's `try_lock` is guaranteed to
/// fail before the guard is released.
///
/// RED on revert: the plain `lock()` has no try-lock probe, the counter never
/// moves, and the `>= 1` assertion fails on its message. The publish itself
/// still completes under the revert, so this cannot go red for a compile or
/// behavioural reason.
#[test]
fn publish_shared_session_counts_a_blocked_acquisition() {
    let maps = Arc::new(SharedMaps::new());
    let before = publish_counters();
    let entered = Arc::new(AtomicBool::new(false));

    let guard = maps.sessions.lock().expect("held by the test thread");
    let publisher = {
        let maps = Arc::clone(&maps);
        let entered = Arc::clone(&entered);
        std::thread::spawn(move || {
            entered.store(true, Ordering::SeqCst);
            maps.publish(&entry(40001));
        })
    };
    while !entered.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    drop(guard);
    publisher.join().expect("publishing thread must not panic");

    let after = publish_counters();
    assert!(
        after.contended >= before.contended + 1,
        "a publish that blocked on a held shared-session map must be counted \
         as contended: {} -> {}",
        before.contended,
        after.contended
    );
    // The entry still landed — counting is observation, not a side effect.
    assert!(
        maps.sessions
            .lock()
            .expect("map readable after publish")
            .contains_key(&key(40001)),
        "the contended publish must still have inserted the session"
    );
}

/// OVER-REACH GUARD. `remove_shared_session` takes the same three mutexes
/// through the UNCOUNTED `lock_shared_recover`. If removals were folded into
/// the publish counters, the denominator would include session teardown —
/// and on a connection-rate run, where every flow is created and torn down,
/// that roughly doubles the denominator and halves every contention ratio the
/// harness reports. The measurement would understate publish saturation in
/// exactly the regime it is meant to characterise.
///
/// Stays GREEN under the revert (which pins all three counters at 0, so
/// "removal adds nothing" still holds).
#[test]
fn remove_shared_session_is_not_counted_as_a_publish() {
    let maps = SharedMaps::new();
    let e = entry(40002);
    maps.publish(&e);

    let before = publish_counters();
    maps.remove(&e.key);
    let after = publish_counters();

    assert_eq!(
        after.publishes, before.publishes,
        "session removal is not a publish"
    );
    assert_eq!(
        after.acquisitions, before.acquisitions,
        "session removal must not inflate the publish-lock denominator"
    );
    assert_eq!(
        after.contended, before.contended,
        "session removal must not inflate the publish-lock numerator"
    );
    assert!(
        !maps
            .sessions
            .lock()
            .expect("map readable after remove")
            .contains_key(&e.key),
        "the removal itself must still have taken effect"
    );
}

/// The replication leg reports a call count, an enqueue count, and a queue
/// depth. `enqueued / upserts` recovers the N-way sibling fan-out multiplier
/// without the analysis layer needing the worker count out of band, which is
/// why both are counted rather than just one: three sibling queues must show
/// exactly three enqueues for one call.
///
/// RED on revert: dropping the counter bumps from `replicate_session_upsert`
/// leaves every delta at 0 and the fan-out assertion fails on its message.
#[test]
fn replicate_session_upsert_counts_fanout_and_queue_depth() {
    // #4800: serialize against every other test that moves the
    // process-global replication counters (#6819 flake class).
    let _g = replication_counter_test_guard();
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..3)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();

    let before = replication_counters();
    replicate_session_upsert(&queues, &entry(40003));
    let after = replication_counters();

    assert_eq!(
        after.upserts - before.upserts,
        1,
        "exactly one replication call"
    );
    assert_eq!(
        after.enqueued - before.enqueued,
        3,
        "three sibling queues must record three enqueues — this ratio IS the \
         fan-out multiplier the analysis layer divides by"
    );
    assert!(
        after.depth_max >= 1,
        "pushing onto an empty queue must record a depth high-water of at \
         least 1; got {}",
        after.depth_max
    );
    for (worker, q) in queues.iter().enumerate() {
        assert_eq!(
            q.lock().expect("queue readable").len(),
            1,
            "worker {worker} must have received exactly one replica"
        );
    }
}

/// The replication contention counter must fire when a sibling's command
/// queue is already held. Forced deterministically, same shape as the publish
/// case.
///
/// RED on revert: reverting `lock_recover_counting` back to `lock_recover`
/// removes the try-lock probe, the counter never moves, and the `>= 1`
/// assertion fails on its message.
#[test]
fn replicate_session_upsert_counts_a_blocked_enqueue() {
    // #4800: serialize against every other test that moves the
    // process-global replication counters (#6819 flake class).
    let _g = replication_counter_test_guard();
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..2)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    let before = replication_counters();
    let entered = Arc::new(AtomicBool::new(false));

    // Hold the SECOND sibling's queue: the fan-out reaches it only after the
    // first enqueue has already succeeded uncontended, so the delta is
    // unambiguously the blocked one.
    let guard = queues[1].lock().expect("held by the test thread");
    let replicator = {
        let queues: Vec<_> = queues.iter().map(Arc::clone).collect();
        let entered = Arc::clone(&entered);
        std::thread::spawn(move || {
            entered.store(true, Ordering::SeqCst);
            replicate_session_upsert(&queues, &entry(40004));
        })
    };
    while !entered.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    drop(guard);
    replicator.join().expect("replicating thread must not panic");

    let after = replication_counters();
    assert!(
        after.contended >= before.contended + 1,
        "an enqueue that blocked on a held sibling queue must be counted as \
         contended: {} -> {}",
        before.contended,
        after.contended
    );
    assert_eq!(
        queues[1].lock().expect("queue readable").len(),
        1,
        "the contended enqueue must still have delivered its replica"
    );
}

/// The depth SUM is the differenceable backlog statistic — the only one the
/// analysis layer may key a verdict on.
///
/// The high-water max next to it is a process-lifetime `fetch_max`: it never
/// falls, so across any window `after - before == 0` spans everything from
/// "no backlog" to "a backlog up to the previous all-time high", and one
/// spike leaves the absolute value elevated for the life of the helper.
/// Reading it as a window value made every cell after the first spike report
/// a replication backlog. The SUM carries no history: divided by the upsert
/// count over the same window it is the mean worst-sibling depth for THAT
/// window and nothing else.
///
/// RED on revert: dropping the `fetch_add` leaves the sum at 0 and the
/// backlog assertion fails on its message.
#[test]
fn replicate_session_upsert_depth_sum_accumulates_per_call_backlog() {
    // #4800: serialize against every other test that moves the
    // process-global replication counters (#6819 flake class).
    let _g = replication_counter_test_guard();
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..3)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();

    // Seed an uneven backlog: the SUM must take the per-call MAX across
    // siblings (the worst one), not their total, so the mean it feeds is a
    // depth and not a depth-times-fanout.
    for (i, depth) in [3usize, 11, 7].iter().enumerate() {
        let mut q = queues[i].lock().expect("seed queue");
        for n in 0..*depth {
            q.push_back(WorkerCommand::UpsertSynced(entry(60_000 + n as u16)));
        }
    }

    let before = replication_counters();
    replicate_session_upsert(&queues, &entry(40007));
    let after = replication_counters();

    // Post-push depths are 4 / 12 / 8; the worst is 12.
    // Exact, and sound because the guard above excludes every concurrent
    // mover of this counter.
    assert_eq!(
        after.depth_sum - before.depth_sum,
        12,
        "the depth sum must accumulate the per-call WORST sibling depth (12), \
         not the sum across siblings (24) — otherwise the mean the analyzer \
         derives is inflated by the fan-out and every run looks backlogged"
    );
    assert_eq!(
        after.upserts - before.upserts,
        1,
        "one call, so sum/upserts is exactly the worst-sibling depth"
    );
}

/// OVER-REACH GUARD for the counter shapes themselves: the SUM must keep
/// rising across calls (it is a running total) while the MAX must NOT rise
/// when a later call is shallower than an earlier one (it is a high-water).
/// Getting these backwards is what produced the stale-verdict bug: a
/// "max" that accumulated, or a "sum" that saturated, would each break the
/// analyzer's differencing in a way that reads as a real backlog.
///
/// Stays GREEN under the revert of either counter's update (both deltas go
/// to zero, and zero is neither a rise nor a spurious rise).
#[test]
fn depth_sum_accumulates_while_depth_max_stays_a_high_water() {
    // #4800: serialize against every other test that moves the
    // process-global replication counters (#6819 flake class).
    let _g = replication_counter_test_guard();
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> =
        vec![Arc::new(Mutex::new(VecDeque::new()))];

    // Deep call first: seeds a high high-water.
    {
        let mut q = queues[0].lock().expect("seed queue");
        for n in 0..200 {
            q.push_back(WorkerCommand::UpsertSynced(entry(61_000 + n as u16)));
        }
    }
    replicate_session_upsert(&queues, &entry(40008));
    let after_deep = replication_counters();

    // Now drain to empty and replicate again — a SHALLOW call.
    queues[0].lock().expect("drain queue").clear();
    replicate_session_upsert(&queues, &entry(40009));
    let after_shallow = replication_counters();

    assert!(
        after_shallow.depth_sum > after_deep.depth_sum,
        "the SUM must keep accumulating on every call ({} -> {})",
        after_deep.depth_sum,
        after_shallow.depth_sum
    );
    assert_eq!(
        after_shallow.depth_max, after_deep.depth_max,
        "the MAX is a high-water: a shallower later call must not move it. \
         (It also must not FALL — which is exactly why it cannot be \
         differenced across a window, and why the analyzer keys the backlog \
         verdict on the sum instead.)"
    );
}

/// The high-water max must actually track a BACKLOG, not just report 1 for
/// every push — a max that never exceeds 1 would be useless even as the
/// operator gauge it is kept for.
///
/// RED on revert: without the `fetch_max` the high-water never rises and the
/// assertion fails on its message.
#[test]
fn replicate_session_upsert_depth_high_water_tracks_backlog() {
    // #4800: serialize against every other test that moves the
    // process-global replication counters (#6819 flake class).
    let _g = replication_counter_test_guard();
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..1)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();

    // Simulate a worker that has not drained: seed a deep backlog. The value
    // is well above anything a sibling test could leave behind on an
    // ordinary 1-3 element queue.
    let backlog = 500usize;
    {
        let mut q = queues[0].lock().expect("seed queue");
        for i in 0..backlog {
            q.push_back(WorkerCommand::UpsertSynced(entry(50000 + i as u16)));
        }
    }

    replicate_session_upsert(&queues, &entry(40005));

    let after = replication_counters();
    assert!(
        after.depth_max >= (backlog + 1) as u64,
        "a push onto a {}-deep backlog must raise the depth high-water to at \
         least {}; got {} — a depth that never exceeds 1 cannot distinguish \
         'replication is the bottleneck' from 'replication is merely busy'",
        backlog,
        backlog + 1,
        after.depth_max
    );
}

/// OVER-REACH GUARD. `replicate_session_delete` fans out over the same sibling
/// queues through the same helper. Counting deletes as upserts would corrupt
/// the fan-out ratio (`enqueued / upserts`) that the analysis layer uses to
/// recover the sibling worker count — on a connection-rate run, where each
/// flow is installed and later torn down, it would report roughly double the
/// worker count and silently rescale the whole attribution.
///
/// Stays GREEN under the revert (all counters pinned at 0, so "delete adds
/// nothing" still holds).
#[test]
fn replicate_session_delete_is_not_counted_as_an_upsert() {
    // #4800: serialize against every other test that moves the
    // process-global replication counters (#6819 flake class).
    let _g = replication_counter_test_guard();
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..3)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();

    let before = replication_counters();
    replicate_session_delete(&queues, &key(40006));
    let after = replication_counters();

    assert_eq!(
        after.upserts, before.upserts,
        "a delete replication is not an upsert"
    );
    assert_eq!(
        after.enqueued, before.enqueued,
        "delete enqueues must not inflate the fan-out denominator"
    );
    for (worker, q) in queues.iter().enumerate() {
        assert!(
            q.lock()
                .expect("queue readable")
                .iter()
                .any(|c| matches!(c, WorkerCommand::DeleteSynced(k) if k == &key(40006))),
            "worker {worker} must still have received the delete"
        );
    }
}
