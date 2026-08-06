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
// or replicates can inflate any reading taken here. Every assertion is
// therefore a DELTA with a `>=` bound in the direction pollution can only
// push — never an equality on an absolute value. That is deliberate: an
// equality here would be a flake generator (#6819), and `>=` still binds,
// because under the revert the counters never move at all and the delta is 0.

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
    depth_max: u64,
}

fn replication_counters() -> ReplicationCounters {
    ReplicationCounters {
        upserts: SESSION_REPLICATION_UPSERTS.load(Ordering::Relaxed),
        enqueued: SESSION_REPLICATION_ENQUEUED.load(Ordering::Relaxed),
        contended: SESSION_REPLICATION_LOCK_CONTENDED.load(Ordering::Relaxed),
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

/// The depth high-water must actually track a BACKLOG, not just report 1 for
/// every push. A queue that already holds undrained commands is exactly the
/// "consumer is not keeping up" condition the depth counter exists to
/// distinguish from mutex contention, so pushing onto a pre-loaded queue must
/// move the high-water above what an empty queue produces.
///
/// RED on revert: without the `fetch_max` the high-water never rises and the
/// assertion fails on its message.
#[test]
fn replicate_session_upsert_depth_high_water_tracks_backlog() {
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
