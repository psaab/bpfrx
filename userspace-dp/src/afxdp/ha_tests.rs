// Tests for afxdp/ha.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep ha.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "ha_tests.rs"]` from ha.rs.

use super::*;
use crate::test_zone_ids::*;

fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

#[test]
fn demoted_owner_rgs_detects_active_to_inactive_transitions() {
    let previous = BTreeMap::from([(1, active_ha_runtime(11)), (2, active_ha_runtime(12))]);
    let current = BTreeMap::from([(1, inactive_ha_runtime(21)), (2, active_ha_runtime(22))]);

    assert_eq!(demoted_owner_rgs(&previous, &current), vec![1]);
}

#[test]
fn activated_owner_rgs_detects_inactive_to_active_transitions() {
    let previous = BTreeMap::from([(1, inactive_ha_runtime(11)), (2, active_ha_runtime(12))]);
    let current = BTreeMap::from([(1, active_ha_runtime(21)), (2, active_ha_runtime(22))]);

    assert_eq!(activated_owner_rgs(&previous, &current), vec![1]);
}

#[test]
fn update_ha_state_seeds_lease_for_active_group_without_watchdog() {
    let coordinator = Coordinator::new();
    let before = monotonic_nanos() / 1_000_000_000;

    coordinator
        .update_ha_state(&[HAGroupStatus {
            rg_id: 1,
            active: true,
            watchdog_timestamp: 0,
            ..HAGroupStatus::default()
        }])
        .expect("update ha state");

    let after = monotonic_nanos() / 1_000_000_000;
    let state = coordinator.ha.rg_runtime.load();
    let group = state.get(&1).expect("ha group");
    assert!(group.active);
    assert_eq!(group.watchdog_timestamp, 0);
    assert!(matches!(group.lease, HAForwardingLease::ActiveUntil(until)
            if until >= before + HA_WATCHDOG_STALE_AFTER_SECS
                && until <= after + HA_WATCHDOG_STALE_AFTER_SECS));
    assert!(group.is_forwarding_active(after));
}

#[test]
fn ha_groups_reports_forwarding_lease_status() {
    let coordinator = Coordinator::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    coordinator.ha.rg_runtime.store(Arc::new(BTreeMap::from([
        (1, active_ha_runtime(now_secs)),
        (2, inactive_ha_runtime(0)),
    ])));

    let groups = coordinator.ha_groups();

    assert!(groups.iter().any(|group| {
        group.rg_id == 1
            && group.active
            && group.forwarding_active
            && group.lease_state == "active"
            && group.lease_until >= now_secs
    }));
    assert!(groups.iter().any(|group| {
        group.rg_id == 2
            && !group.active
            && !group.forwarding_active
            && group.lease_state == "inactive"
            && group.lease_until == 0
    }));
}

#[test]
fn immediate_synced_bpf_programming_skips_locally_active_owner_rg() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);

    assert!(!synced_entry_allows_local_replace(&state, 1, now_secs));
}

#[test]
fn immediate_synced_bpf_programming_skips_unknown_owner_when_any_rg_is_active() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);

    assert!(!synced_entry_allows_local_replace(&state, 0, now_secs));
}

#[test]
fn immediate_synced_bpf_programming_allows_inactive_owner_rg() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);

    assert!(synced_entry_allows_local_replace(&state, 1, now_secs));
}

fn test_resolution() -> ForwardingResolution {
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

fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
    }
}

fn test_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 55068,
        dst_port: 5201,
    }
}

fn test_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: true,
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

fn test_forwarding_state_with_fabric() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        ifindex: 6,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (6, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("sfmix".to_string(), 2);
    forwarding.zone_name_to_id.insert("wan".to_string(), 3);
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    forwarding
}

fn test_forwarding_state_split_rgs() -> ForwardingState {
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 2,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding
}

fn test_worker_handle(commands: Arc<Mutex<VecDeque<WorkerCommand>>>) -> WorkerHandle {
    WorkerHandle {
        stop: Arc::new(AtomicBool::new(false)),
        heartbeat: Arc::new(AtomicU64::new(0)),
        commands,
        session_export_ack: Arc::new(AtomicU64::new(0)),
        cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(super::cold_path_hist::WorkerColdPathAtomics::new()),
        join: None,
    }
}

#[test]
fn update_ha_state_prewarms_split_rg_reverse_sessions_on_activation() {
    let mut coordinator = Coordinator::new();
    coordinator.forwarding = test_forwarding_state_split_rgs();
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.records.insert(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(worker_commands.clone())),
    );

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions,
        &coordinator.forwarding,
        coordinator.dynamic_neighbors_ref(),
        None,
        Some(&entry),
    );

    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: false,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("seed initial HA state");
    worker_commands.lock().expect("commands").clear();

    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: true,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("activate rg1");

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    let commands = worker_commands.lock().expect("commands");
    assert_eq!(commands.len(), 3);
    assert!(matches!(
        commands.front(),
        Some(WorkerCommand::RefreshOwnerRGS { owner_rgs }) if owner_rgs == &vec![1]
    ));
    assert!(commands.iter().any(|command| matches!(
        command,
        WorkerCommand::UpsertSynced(session)
            if session.metadata.is_reverse && session.metadata.owner_rg_id == 2
    )));
}

#[test]
fn update_ha_state_demotion_recovers_from_poisoned_worker_command_mutex() {
    // #1790 regression: update_ha_state publishes the new HA state via
    // rg_runtime.store BEFORE propagating demotion side effects. The
    // demote loop used to `?`-return on a poisoned worker command mutex,
    // so a retry diffed against the already-stored state (empty
    // demoted_rgs) and the demotion was permanently lost — partial
    // worker delivery, no demote_shared_owner_rgs, no epoch bump.
    // Poison one of three worker command mutexes and assert the SAME
    // call still completes ALL propagation and returns Ok.
    let mut coordinator = Coordinator::new();
    coordinator.forwarding = test_forwarding_state_with_fabric();
    let worker_queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..3u32)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    for (worker_id, queue) in worker_queues.iter().enumerate() {
        coordinator.workers.records.insert(
            worker_id as u32,
            WorkerRuntimeRecord::for_test(test_worker_handle(queue.clone())),
        );
    }

    // Locally-owned (non-peer-synced) shared session in RG 1. The
    // demotion must flip its origin to a peer-synced one via
    // demote_shared_owner_rgs.
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );

    // Previous state: RG 1 locally owned (active).
    coordinator
        .update_ha_state(&[HAGroupStatus {
            rg_id: 1,
            active: true,
            ..HAGroupStatus::default()
        }])
        .expect("seed active HA state");
    for queue in &worker_queues {
        queue.lock().expect("commands").clear();
    }

    // Poison one worker's command mutex deterministically: a thread
    // panics while holding the lock, and join() observes the panic, so
    // the mutex is poisoned before update_ha_state runs.
    let to_poison = worker_queues[1].clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison worker command mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(
        worker_queues[1].lock().is_err(),
        "worker 1 command mutex must be poisoned"
    );

    let epoch_before = coordinator.rg_epochs[1].load(Ordering::Acquire);

    // New state: RG 1 demoted. Must return Ok (no early return) and
    // apply every side effect despite the poisoned mutex.
    coordinator
        .update_ha_state(&[HAGroupStatus {
            rg_id: 1,
            active: false,
            ..HAGroupStatus::default()
        }])
        .expect("update_ha_state must recover from poisoned worker mutex");

    // ALL workers — the poisoned one included (recovered via
    // into_inner) — received both demote commands.
    for (worker_id, queue) in worker_queues.iter().enumerate() {
        let pending = queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            pending.iter().any(|command| matches!(
                command,
                WorkerCommand::DemoteOwnerRGS { owner_rgs } if owner_rgs == &vec![1]
            )),
            "worker {worker_id} missing DemoteOwnerRGS for RG 1"
        );
        assert!(
            pending
                .iter()
                .any(|command| matches!(command, WorkerCommand::VacateAllSharedExactSlots)),
            "worker {worker_id} missing VacateAllSharedExactSlots"
        );
    }

    // demote_shared_owner_rgs ran: the locally-owned RG 1 entry was
    // marked peer-synced.
    let demoted = coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .get(&entry.key)
        .cloned()
        .expect("shared entry survives demotion");
    assert!(
        demoted.origin.is_peer_synced(),
        "demotion must mark the shared entry peer-synced"
    );

    // The demoted RG's flow-cache epoch was bumped exactly once.
    assert_eq!(
        coordinator.rg_epochs[1].load(Ordering::Acquire),
        epoch_before + 1,
        "rg_epochs[1] must be bumped by the demotion"
    );
}

#[test]
fn prewarm_recovers_from_poisoned_shared_session_mutex() {
    // #2402 regression: the activation prewarm path acquired the shared
    // session mutex with `.lock().map(..).unwrap_or_default()`. If a
    // worker thread had panicked while holding that lock, `lock()` returns
    // Err, the `.map(..)` closure is SKIPPED, and `unwrap_or_default()`
    // substitutes EMPTY (forward_entries, reverse_entries) — so RG
    // activation proceeded as if there were NO sessions to promote and
    // silently dropped every active synced session at the moment of
    // failover. The fix recovers the poisoned guard
    // (`lock_shared_recover` / `into_inner`) and promotes the EXISTING
    // sessions. This test populates a shared session, poisons the mutex,
    // runs prewarm, and asserts the reverse companion is still
    // synthesized + published (with the old code it would be absent).
    let mut coordinator = Coordinator::new();
    coordinator.forwarding = test_forwarding_state_split_rgs();
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions,
        &coordinator.forwarding,
        coordinator.dynamic_neighbors_ref(),
        None,
        Some(&entry),
    );

    // Poison the shared session mutex deterministically: a thread panics
    // while holding the lock, and join() observes the panic.
    let to_poison = coordinator.sessions.synced.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison shared session mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(
        coordinator.sessions.synced.lock().is_err(),
        "shared session mutex must be poisoned"
    );

    let recoveries_before =
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed);

    let ha_state = BTreeMap::from([(1, active_ha_runtime(1_000)), (2, active_ha_runtime(1_000))]);
    prewarm_reverse_synced_sessions_for_owner_rgs(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        std::slice::from_ref(&worker_commands),
        -1,
        &coordinator.forwarding,
        &ha_state,
        coordinator.dynamic_neighbors_ref(),
        &[1, 2],
        1_000,
    );

    // The poisoned guard was recovered, not swallowed.
    assert!(
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed)
            > recoveries_before,
        "prewarm must recover (count) the poisoned shared session lock"
    );

    // Fail-on-revert: with the old `.unwrap_or_default()`, the poisoned
    // lock yields empty entries and the reverse companion is NEVER
    // published — this lookup returns None and the assert fails.
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = coordinator
        .sessions
        .synced
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&reverse_key)
        .cloned()
        .expect("reverse companion must survive a poisoned shared lock");
    assert!(reverse.metadata.is_reverse);

    // The worker also received the reverse UpsertSynced (promotion was not
    // silently dropped).
    let commands = worker_commands
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        commands.iter().any(|command| matches!(
            command,
            WorkerCommand::UpsertSynced(session) if session.metadata.is_reverse
        )),
        "worker must receive the recovered reverse UpsertSynced"
    );
}

// --- #4069 RG-activation prewarm dedup is O(N+M), not O(N·M) --------------

#[test]
fn merge_owner_rg_candidate_keys_preserves_order_and_dedups() {
    // The merge must be a stable, deduplicated union: forward keys in their
    // original order, then each reverse key not already present in first-seen
    // order, with duplicates (cross-list AND repeated within reverse) removed.
    // This is the exact semantic contract the O(N+M) hash-set rewrite must
    // preserve versus the former O(N·M) `Vec::contains` dedup.
    let key = |port: u16| SessionKey {
        src_port: port,
        ..test_key()
    };
    let forward = vec![key(1), key(2), key(3)];
    // reverse: key(2) is already in forward (drop), key(10)/key(11) are new,
    // the second key(10) is a within-reverse duplicate (drop).
    let reverse = vec![key(2), key(10), key(11), key(10)];

    let merged = merge_owner_rg_candidate_keys(forward, reverse);

    assert_eq!(
        merged,
        vec![key(1), key(2), key(3), key(10), key(11)],
        "merge must keep forward order then append new reverse keys, deduped"
    );
}

#[test]
fn merge_owner_rg_candidate_keys_scales_linearly_not_quadratically() {
    // RED-on-revert: the former O(N·M) `Vec::contains` dedup re-scanned the
    // growing forward Vec once per reverse key. At N = M = 200_000 that is on
    // the order of 4e10 SessionKey comparisons — tens of seconds to minutes.
    // The O(N+M) hash-set merge completes in well under a second, so this
    // generous 5s budget passes on the fix and blows out (RED) on a quadratic
    // regression. Every key is distinct, so nothing is deduped and the merge
    // performs the full N+M of work (worst case for the old linear scan too,
    // which never finds a match and walks the entire forward Vec each time).
    const N: u32 = 200_000;
    let distinct_key = |i: u32| SessionKey {
        // 10.x.x.x — encode i into the low 24 bits so every key is unique.
        src_ip: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | (i & 0x00ff_ffff))),
        ..test_key()
    };
    let forward: Vec<SessionKey> = (0..N).map(distinct_key).collect();
    let reverse: Vec<SessionKey> = (N..2 * N).map(distinct_key).collect();

    let start = std::time::Instant::now();
    let merged = merge_owner_rg_candidate_keys(forward, reverse);
    let elapsed = start.elapsed();

    assert_eq!(
        merged.len() as u32,
        2 * N,
        "all keys are distinct — the union must contain every one"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "O(N+M) prewarm merge took {elapsed:?} for N=M={N}; a quadratic \
         Vec::contains regression (O(N·M)) would blow this 5s budget"
    );
}

// --- #2170 install-generation guard (helper-side belt-and-suspenders) -----

fn synced_entry_with_generation(generation: u64) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation,
        session_id: 0,
    }
}

fn synced_generation(coordinator: &Coordinator, key: &SessionKey) -> Option<u64> {
    coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .get(key)
        .map(|entry| entry.generation)
}

// #6819 R3: the property the whole counter-scoping change exists to establish,
// bound DETERMINISTICALLY.
//
// Every other assertion on these three counters is a DELTA capture (`let before
// = ...` then `before + 1` or `== before`). A process-global satisfies every one
// of them identically whenever tests do not interleave — and the sanctioned gate
// (`make test-rust`) pins `-- --test-threads=1`, so WITHOUT this test, reverting
// any of the three fields to a `static` leaves the entire gated suite GREEN.
// That is measured, not assumed: reverting `import_cap_drops` reds 24 of 60
// PARALLEL runs and 0 of 12 single-threaded ones; reverting both stale counters
// reds 43 of 60 parallel and 0 of 5 single-threaded.
//
// This test does not depend on interleaving at all, so it reds at ANY thread
// count including the gate's. It drives one refusal of each kind on a BUSY
// coordinator and asserts that an IDLE coordinator, alive in the same process,
// observed none of them. Under a process-global the idle instance reads the busy
// instance's increments and every assertion in the final block fails.
#[test]
fn refusal_counters_are_per_coordinator_not_process_global() {
    let mut busy = Coordinator::new();
    let idle = Coordinator::new();

    // Both instances start clean. (Also the reason the `== before` captures
    // elsewhere in this file are now always `0 == 0` — see the note on
    // `current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex`.)
    //
    // These carry the SAME diagnostic as the payload assertions at the bottom,
    // because under the sanctioned gate they are what actually fires. libtest
    // runs alphabetically at `--test-threads=1`, so `current_generation_…` (c),
    // `delete_synced_session_gen_…` (d) and `over_ceiling_import_…` (o) all
    // execute BEFORE `refusal_counters_…` (r) and would have already bumped a
    // restored global. A bare `assert_eq!(x, 0)` here reports `left: 1,
    // right: 0` with no explanation, forty lines above the sentence that
    // explains it — and the payload assertions below are reachable only when
    // this test is run in isolation, which is not how `make test-rust` runs it.
    assert_eq!(
        idle.session_install_stale_ignored_total(),
        0,
        "precondition: a fresh Coordinator must read zero stale-install \
         refusals — a nonzero value here means an EARLIER test's refusal leaked \
         in, i.e. `install_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.session_delete_stale_ignored_total(),
        0,
        "precondition: a fresh Coordinator must read zero stale-delete \
         refusals — a nonzero value here means an EARLIER test's refusal leaked \
         in, i.e. `delete_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.synced_import_cap_drops_total(),
        0,
        "precondition: a fresh Coordinator must read zero cap drops — a nonzero \
         value here means an EARLIER test's refusal leaked in, i.e. \
         `import_cap_drops` is process-global again (#6819)"
    );

    // Entry cap = 2 (logical override 1, doubled for the synthesized reverse).
    busy.synced_import_cap_override = 1;
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    busy.workers.records.insert(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
    );

    let key = test_key();
    busy.upsert_synced_session(synced_entry_with_generation(2));
    // (a) stale install — refused, counted.
    busy.upsert_synced_session(synced_entry_with_generation(1));
    // (b) stale delete — refused, counted; the entry survives.
    busy.delete_synced_session_gen(key.clone(), 1);
    // (c) over-ceiling NEW forward — the map already holds the forward + its
    // synthesized reverse, so it is at the entry cap. Refused, counted.
    busy.upsert_synced_session(synced_entry_port(2000, 0));

    assert_eq!(
        busy.session_install_stale_ignored_total(),
        1,
        "setup: the busy coordinator must have refused exactly one stale install"
    );
    assert_eq!(
        busy.session_delete_stale_ignored_total(),
        1,
        "setup: the busy coordinator must have refused exactly one stale delete"
    );
    assert_eq!(
        busy.synced_import_cap_drops_total(),
        1,
        "setup: the busy coordinator must have refused exactly one over-ceiling \
         import"
    );

    // THE BINDING ASSERTIONS. A process-global would have leaked all three of
    // the refusals above into this second, untouched Coordinator.
    assert_eq!(
        idle.session_install_stale_ignored_total(),
        0,
        "a second Coordinator observed another instance's stale-install \
         refusal — `install_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.session_delete_stale_ignored_total(),
        0,
        "a second Coordinator observed another instance's stale-delete \
         refusal — `delete_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.synced_import_cap_drops_total(),
        0,
        "a second Coordinator observed another instance's over-ceiling import \
         refusal — `import_cap_drops` is process-global again (#6819)"
    );
}

// A stale-generation upsert (gen=1 after gen=2 is stored) must be refused so
// the per-key stored generation never regresses (the delayed-stale-install
// variant, SMR C3). Mirrors the Go install guard.
#[test]
fn upsert_synced_session_refuses_stale_generation_install() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_install_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    assert_eq!(synced_generation(&coordinator, &key), Some(2));

    // Delayed stale install (gen=1) — must be refused, stored gen stays 2.
    coordinator.upsert_synced_session(synced_entry_with_generation(1));
    assert_eq!(
        synced_generation(&coordinator, &key),
        Some(2),
        "stale-generation install rolled the stored generation back"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        before + 1,
        "stale install should be counted"
    );

    // #6819 §7 positive control. Without this leg the test accepts a guard
    // that refuses EVERY generation-1 install, or every install whose
    // generation differs from the stored one — rejecting the whole category
    // still yields "stored stays 2, counter +1". Pin that the refusal is
    // SELECTIVE, so the test carries its own control rather than depending on
    // `upsert_synced_session_applies_equal_and_newer_generation` being read
    // alongside it.
    coordinator.upsert_synced_session(synced_entry_with_generation(3));
    assert_eq!(
        synced_generation(&coordinator, &key),
        Some(3),
        "a NEWER-generation install must still apply — the guard refuses only \
         strictly-older generations, not every generation change"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        before + 1,
        "a legitimate newer install must not bump the stale-refusal counter"
    );
}

// ── #5674: synced-import aggregate admission bound (coordinator) ──────
//
// Peer-synced sessions were imported with NO cap and fanned out to EVERY
// worker command queue+table, so a peer under session-table pressure — or a
// malicious/compromised peer — could drive this node PAST its own aggregate
// session ceiling and multiply that state across all workers (the
// availability/DoS root of #5674). `upsert_synced_session` now bounds the
// shared synced map at `2 * worker_count * DEFAULT_MAX_SESSIONS` and drop-
// newest-rejects an over-ceiling NEW FORWARD key. The 2× matters: each
// admitted forward logical session publishes TWO entries into `sessions.synced`
// (the forward key + a synthesized reverse companion), so a full symmetric
// peer holding N logical sessions arrives as 2N entries. Sizing the cap to the
// LOGICAL ceiling N while counting ENTRIES (the pre-fix bug) rejected ~half of
// a legitimate full-peer import above ~50% peer load; the entry cap is 2N so a
// full logical set EXACTLY fits.
//
// This test pins: (a) a FULL symmetric-peer logical set (LOGICAL_CEILING
// forward sessions = 2×LOGICAL_CEILING entries) ALL admit with ZERO drops —
// the regression the review found (a >50% silent under-sync); (b) the NEXT
// forward, EXCEEDING the logical ceiling, is drop-newest REJECTED and never
// fanned out to the worker command queue (the per-worker multiplication is
// bounded); (c) a REPLACE of an admitted key still applies at the ceiling (the
// cap is scoped to NEW forward keys, not a blanket block).
//
// PARENT-RED recipe: neutralize the single reject in the
// `upsert_synced_session` gate (`ha.rs`, the
// `if synced_cap != 0 && synced_len >= synced_cap { ...; return; }` — e.g.
// delete the `return;` so the over-ceiling forward falls through and is
// admitted). The over-ceiling key then lands in the shared map + the worker
// queue, so the `is_none()` / not-enqueued reject assertions below fail as
// clean assertions. Target-count = 1 gate site.
fn synced_entry_port(port: u16, generation: u64) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: SessionKey {
            src_port: port,
            ..test_key()
        },
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation,
        session_id: 0,
    }
}

#[test]
fn upsert_synced_session_rejects_over_ceiling_import_and_does_not_fan_out() {
    let mut coordinator = Coordinator::new();
    // The override expresses a LOGICAL session ceiling; `synced_import_cap()`
    // doubles it to the ENTRY cap (2×LOGICAL_CEILING) because each admitted
    // forward logical session publishes a forward AND a synthesized reverse
    // companion into the shared `synced` map. Choose a small logical ceiling so
    // the boundary is reachable without inserting DEFAULT_MAX_SESSIONS (131072)
    // sessions. In production the logical ceiling is
    // `worker_count * DEFAULT_MAX_SESSIONS` and the entry cap is 2× that.
    const LOGICAL_CEILING: u16 = 3;
    coordinator.synced_import_cap_override = LOGICAL_CEILING as usize;
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.records.insert(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
    );

    let before = coordinator.synced_import_cap_drops_total();

    // (a) A FULL symmetric-peer logical set — LOGICAL_CEILING forward sessions,
    // each publishing a forward + synthesized reverse = 2×LOGICAL_CEILING
    // entries — must ALL admit with ZERO drops. This is the #5674 dual-entry
    // regression the review found: sizing the cap to the LOGICAL ceiling while
    // counting ENTRIES silently dropped ~half of a legitimate full-peer import
    // above ~50% peer load. Every forward here is a NEW key at/below the logical
    // ceiling, so none may be rejected. Under the pre-fix (non-2×) cap the third
    // forward would find synced_len == 4 >= cap 3 and be dropped — this loop
    // REDs it.
    let mut admitted_keys = Vec::new();
    for i in 0..LOGICAL_CEILING {
        let entry = synced_entry_port(1000 + i, 0);
        let key = entry.key.clone();
        coordinator.upsert_synced_session(entry);
        assert!(
            synced_generation(&coordinator, &key).is_some(),
            "forward logical session {i} within the ceiling must be admitted — \
             a full symmetric-peer set of {LOGICAL_CEILING} logical sessions \
             ({} entries) must all fit the 2× entry cap (#5674)",
            2 * LOGICAL_CEILING
        );
        admitted_keys.push(key);
    }
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        before,
        "a full symmetric-peer logical set must import with NO cap drop — a \
         nonzero count here is the #5674 >50% silent under-sync regression"
    );

    // (b) BEYOND the logical ceiling: the next NEW forward key (a peer
    // exceeding its OWN logical ceiling) is drop-newest rejected.
    let rejected = synced_entry_port(2000, 0);
    let rejected_key = rejected.key.clone();
    coordinator.upsert_synced_session(rejected);
    assert!(
        synced_generation(&coordinator, &rejected_key).is_none(),
        "an over-ceiling synced FORWARD import must be REJECTED, not admitted \
         past the aggregate cap (#5674 admission bound)"
    );
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        before + 1,
        "the rejected over-ceiling import must bump synced_import_cap_drops"
    );

    // The rejected import must NOT be fanned out to the worker command queue —
    // the per-worker queue multiplication is bounded (#5674 second half). The
    // admitted sessions did fan out (the gate is scoped, not a blanket drop of
    // all fan-out).
    {
        let pending = commands.lock().expect("commands");
        let rejected_enqueued = pending.iter().any(|cmd| {
            matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == rejected_key)
        });
        assert!(
            !rejected_enqueued,
            "a rejected over-ceiling synced import must not be fanned out to \
             any worker command queue (#5674 queue-multiplication bound)"
        );
        let admitted_enqueued = pending.iter().any(|cmd| {
            matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == admitted_keys[0])
        });
        assert!(
            admitted_enqueued,
            "the admitted within-ceiling sessions must still fan out to the worker"
        );
    }

    // (c) A REPLACE of an already-admitted key is NOT subject to the cap (it
    // does not grow the map) — an in-flight synced session keeps refreshing at
    // the ceiling. A newer-generation upsert of an admitted key applies even
    // though the shared map is at the entry cap, and it is NOT counted as a
    // drop.
    let drops_after_reject = coordinator.synced_import_cap_drops_total();
    coordinator.upsert_synced_session(synced_entry_port(1000, 7));
    assert_eq!(
        synced_generation(&coordinator, &admitted_keys[0]),
        Some(7),
        "a REPLACE of an existing synced key must apply at the ceiling (the \
         cap gates NEW forward keys, never a refresh) — else a legitimate \
         failover session-refresh would be dropped"
    );
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        drops_after_reject,
        "a replace at the ceiling must NOT count as a cap drop"
    );
}

// #5154: the #5674 ceiling read must RECOVER poison too. The test above
// exercises the ceiling on a HEALTHY mutex, so it cannot see the fail-open:
// `upsert_synced_session` read the map length with
// `.lock().map(|s| s.len()).unwrap_or(0)`, which on a poisoned mutex yields
// 0 — and `0 >= synced_cap` is false for ANY nonzero cap, so the aggregate
// admission bound was skipped entirely and the over-ceiling import was
// admitted AND fanned out to every worker queue. Identical fail-open shape to
// the two generation guards, in the same critical section, reached by the
// same contained worker panic.
//
// PARENT-RED recipe: revert ONLY the length read to
// `.lock().map(|s| s.len()).unwrap_or(0)`, ORDERED BEFORE the recovered
// stored-entry read. The ordering is load-bearing: `lock_shared_recover`
// calls `clear_poison()`, so a swallowing read placed AFTER it observes a
// healthy mutex and the mutation is invisible. Target-count = 1 read site.
#[test]
fn over_ceiling_import_rejected_on_poisoned_shared_mutex() {
    let mut coordinator = Coordinator::new();
    const LOGICAL_CEILING: u16 = 3;
    coordinator.synced_import_cap_override = LOGICAL_CEILING as usize;
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.records.insert(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
    );

    // Fill to the ENTRY cap (2×LOGICAL_CEILING): each admitted forward
    // publishes a forward key AND a synthesized reverse companion.
    for i in 0..LOGICAL_CEILING {
        let entry = synced_entry_port(1000 + i, 0);
        let key = entry.key.clone();
        coordinator.upsert_synced_session(entry);
        assert!(
            synced_generation_recovered(&coordinator, &key).is_some(),
            "setup: forward logical session {i} within the ceiling must be \
             admitted before the map is at its entry cap"
        );
    }

    let before = coordinator.synced_import_cap_drops_total();

    poison_shared_synced(&coordinator);

    // A NEW forward key beyond the ceiling, arriving while the mutex is
    // poisoned, must still be drop-newest REJECTED.
    let rejected = synced_entry_port(2000, 0);
    let rejected_key = rejected.key.clone();
    coordinator.upsert_synced_session(rejected);

    assert!(
        synced_generation_recovered(&coordinator, &rejected_key).is_none(),
        "a poisoned shared mutex let an over-ceiling synced import through — \
         the #5674 admission bound read the map length as 0 via the \
         non-recovering read, so the ceiling never evaluated while the \
         recovering write published the entry anyway"
    );
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        before + 1,
        "the over-ceiling import must be REFUSED and counted on a poisoned \
         mutex, exactly as on a healthy one"
    );

    // And it must not reach any worker queue — the #5674 per-worker
    // multiplication bound has to hold on the poisoned path too.
    let pending = commands.lock().expect("commands");
    assert!(
        !pending.iter().any(|cmd| {
            matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == rejected_key)
        }),
        "a rejected over-ceiling import must not be fanned out to any worker \
         command queue, even when the shared mutex was poisoned"
    );
}

// #6819 §7: both admission tests above set `synced_import_cap_override`, which
// returns from the `#[cfg(test)]` branch of `synced_import_cap` BEFORE the
// production expression runs. That test-only seam SHADOWS the production
// formula: with only those two tests, deleting the trailing
// `.saturating_mul(2)` from the production path leaves every cap assertion
// green, because no test ever evaluates it. This test leaves the override at
// its default 0 so the production arithmetic is the thing under test.
//
// The 2x is the property being pinned, not an implementation detail: the cap
// counts ENTRIES while the ceiling it must express is LOGICAL sessions, and
// each admitted forward publishes a forward key AND a synthesized reverse
// companion. A cap sized to the logical ceiling rejects ~half of a legitimate
// full-peer failover import above ~50% peer load (the #5674 dual-entry
// regression).
#[test]
fn synced_import_cap_production_formula_is_twice_the_logical_ceiling() {
    let mut coordinator = Coordinator::new();
    assert_eq!(
        coordinator.synced_import_cap_override, 0,
        "this test must exercise the PRODUCTION formula — a nonzero override \
         short-circuits `synced_import_cap` before it is reached"
    );
    // A per-worker ceiling of zero would make the 2x assertion below vacuous
    // (0 == 2*0), so pin that the multiplicand is real first.
    let per_worker = crate::session::default_max_sessions();
    assert!(
        per_worker > 0,
        "DEFAULT_MAX_SESSIONS must be positive or the ceiling assertions below \
         cannot distinguish the logical ceiling from twice it"
    );

    // No workers registered (early boot / teardown): a zero ceiling DISABLES
    // the bound, so a transient window never rejects legitimate imports.
    assert_eq!(
        coordinator.synced_import_cap(),
        0,
        "an unregistered-worker coordinator must report a zero (disabled) \
         ceiling, not a nonzero cap that would reject during early boot"
    );

    const WORKERS: usize = 3;
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    for worker in 0..WORKERS {
        coordinator.workers.records.insert(
            worker as u32,
            WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        );
    }

    let logical_ceiling = WORKERS * per_worker;
    assert_eq!(
        coordinator.synced_import_cap(),
        2 * logical_ceiling,
        "the production ENTRY cap must be TWICE the logical ceiling \
         (worker_count * DEFAULT_MAX_SESSIONS), because each admitted forward \
         logical session publishes a forward key AND a synthesized reverse"
    );
    // Stated separately and explicitly: dropping the trailing 2x is the #5674
    // regression, and it yields exactly the logical ceiling.
    assert_ne!(
        coordinator.synced_import_cap(),
        logical_ceiling,
        "the ENTRY cap must not equal the LOGICAL ceiling — that is the \
         pre-#5674 sizing that silently under-syncs a peer above ~50% load"
    );
}

// An equal- or newer-generation upsert must apply (equality is NOT refusal).
#[test]
fn upsert_synced_session_applies_equal_and_newer_generation() {
    let coordinator = Coordinator::new();
    let key = test_key();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    coordinator.upsert_synced_session(synced_entry_with_generation(2)); // equal — applies
    assert_eq!(synced_generation(&coordinator, &key), Some(2));
    coordinator.upsert_synced_session(synced_entry_with_generation(5)); // newer — applies
    assert_eq!(synced_generation(&coordinator, &key), Some(5));
}

// A gen-0 (legacy/local) install must apply unconditionally — the guard only
// acts when BOTH the stored and incoming generations are non-zero.
#[test]
fn upsert_synced_session_legacy_zero_generation_applies() {
    let coordinator = Coordinator::new();
    let key = test_key();
    coordinator.upsert_synced_session(synced_entry_with_generation(5));
    coordinator.upsert_synced_session(synced_entry_with_generation(0)); // legacy — applies
    assert!(
        synced_generation(&coordinator, &key).is_some(),
        "a legacy gen-0 install must apply (it overwrites the stored entry)"
    );
}

// delete_synced_session_gen refuses a strictly-older-generation delete and
// applies an equal/newer/zero one (belt-and-suspenders for helper-side
// generation-aware deletes).
#[test]
fn delete_synced_session_gen_refuses_stale_generation() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_delete_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));

    // Stale delete (gen=1) — refused, entry survives.
    coordinator.delete_synced_session_gen(key.clone(), 1);
    assert!(
        synced_generation(&coordinator, &key).is_some(),
        "stale-generation delete wrongly removed the live entry"
    );
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        before + 1
    );

    // Equal-generation delete (gen=2) — applies. This is the positive control:
    // without it the test accepts a guard that refuses EVERY generation-aware
    // delete.
    coordinator.delete_synced_session_gen(key.clone(), 2);
    assert!(
        synced_generation(&coordinator, &key).is_none(),
        "equal-generation delete should remove the entry"
    );
    // #6819 §7: and the legitimate delete must not be counted either —
    // otherwise "refuse everything, count once" still satisfies the pair above.
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        before + 1,
        "an applied equal-generation delete must not bump the stale-refusal \
         counter"
    );
}

// The plain delete_synced_session (delete_gen=0) is unconditional — helper-
// local purges must always remove the entry regardless of its generation.
#[test]
fn delete_synced_session_zero_generation_is_unconditional() {
    let coordinator = Coordinator::new();
    let key = test_key();
    coordinator.upsert_synced_session(synced_entry_with_generation(9));
    coordinator.delete_synced_session(key.clone());
    assert!(
        synced_generation(&coordinator, &key).is_none(),
        "a gen-0 (unconditional) delete must remove the entry"
    );
}

// ── #5154: the generation guards must survive a poisoned shared mutex ──
//
// `upsert_synced_session` read the stored entry with `.lock().ok()` and the
// map length with `.lock().map(..).unwrap_or(0)`;
// `delete_synced_session_gen` read with `.lock().ok()`. After a CONTAINED
// worker panic (#925 supervisor) poisoned `sessions.synced`, all three reads
// silently yielded "nothing stored / empty map" — so the #2170 generation
// guards never evaluated — while the WRITE half (`publish_shared_session` /
// `remove_shared_session`) went through `lock_shared_recover`, which
// `clear_poison()`s and mutates anyway. Validation and mutation applied
// OPPOSITE poison policies, so a delayed stale-generation install regressed
// the stored generation and a stale delete removed a newer live entry.
//
// The fix makes the reads RECOVER too (the #2402 / #1807 module policy), so
// the guards always evaluate against the committed map.
//
// PARENT-RED recipe: restore either read to its swallowing form — e.g.
// `let (previous_entry, synced_len) = self.sessions.synced.lock().ok()
//  .map(|s| (s.get(&entry.key).cloned(), s.len())).unwrap_or((None, 0));`
// in `upsert_synced_session`, or `.lock().ok().and_then(|s|
// s.get(&key).cloned())` in `delete_synced_session_gen`
// (userspace-dp/src/afxdp/ha/session_import.rs). Target-count = 2 read sites.

// Poison `sessions.synced` deterministically: a scoped thread panics while
// holding the lock and `join()` observes the panic (the panic is CONTAINED —
// it never unwinds into the test thread), mirroring a worker panic under the
// #925 supervisor. Every `lock_shared_recover` CLEARS poison, so each
// operation under test must be freshly poisoned.
fn poison_shared_synced(coordinator: &Coordinator) {
    let to_poison = coordinator.sessions.synced.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison shared session mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(
        coordinator.sessions.synced.lock().is_err(),
        "shared session mutex must be poisoned"
    );
}

// Read the stored generation WITHOUT `expect()` so a still-poisoned mutex
// yields a clean assertion failure below rather than a panic in the reader.
fn synced_generation_recovered(coordinator: &Coordinator, key: &SessionKey) -> Option<u64> {
    coordinator
        .sessions
        .synced
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(key)
        .map(|entry| entry.generation)
}

#[test]
fn stale_generation_install_refused_on_poisoned_shared_mutex() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_install_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    assert_eq!(synced_generation_recovered(&coordinator, &key), Some(2));

    poison_shared_synced(&coordinator);

    // Delayed stale install (gen=1) against stored gen=2. Pre-fix the poisoned
    // read returned None, the guard was skipped, and `publish_shared_session`
    // recovered the poison and OVERWROTE the entry — rolling the stored
    // generation back to 1.
    coordinator.upsert_synced_session(synced_entry_with_generation(1));
    assert_eq!(
        synced_generation_recovered(&coordinator, &key),
        Some(2),
        "a poisoned shared mutex let a stale-generation install roll the \
         stored generation back — the #2170 guard was skipped by the \
         non-recovering read while the recovering write committed it"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        before + 1,
        "the stale install must be REFUSED and counted, not silently applied"
    );
    // #6819 §7 scope note: this test alone accepts a build that refuses EVERY
    // nonzero-generation install once the mutex has been poisoned — rejecting
    // the whole category also leaves the stored generation at 2 with the
    // counter at +1. The selectivity is controlled by
    // `current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex`,
    // which asserts that newer/equal operations still APPLY across poisoning
    // AND that stale ones are still refused. The two are a pair: deleting that
    // control silently widens what this test accepts.
}

#[test]
fn stale_generation_delete_refused_on_poisoned_shared_mutex() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_delete_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    assert_eq!(synced_generation_recovered(&coordinator, &key), Some(2));

    poison_shared_synced(&coordinator);

    // Stale delete (gen=1) against stored gen=2. Pre-fix the poisoned read
    // returned None, so the delete-side guard never evaluated and
    // `remove_shared_session` recovered the poison and removed the entry —
    // a stale delete killing a newer same-key replacement.
    coordinator.delete_synced_session_gen(key.clone(), 1);
    assert_eq!(
        synced_generation_recovered(&coordinator, &key),
        Some(2),
        "a poisoned shared mutex let a stale-generation delete remove a \
         NEWER live entry — the #2170 delete guard was skipped by the \
         non-recovering read while the recovering remove committed it"
    );
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        before + 1,
        "the stale delete must be REFUSED and counted, not silently applied"
    );
    // #6819 §7 scope note: as with the install variant, this test alone accepts
    // a build that refuses EVERY nonzero-generation delete after poisoning. The
    // selectivity is controlled by
    // `current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex`;
    // deleting that control silently widens what this test accepts.
}

// NEGATIVE CONTROL: the fix must RECOVER the poison and keep evaluating the
// guard — not refuse everything it sees on a poisoned mutex. A current/newer
// install and an equal-generation delete must still APPLY across poisoning,
// so HA session sync keeps working after a contained worker panic. (This is
// also what rules out the "refuse the write on poison" alternative: it would
// fail every assertion here.)
#[test]
fn current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let stale_installs_before = coordinator.session_install_stale_ignored_total();
    let stale_deletes_before = coordinator.session_delete_stale_ignored_total();
    let recoveries_before =
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed);

    coordinator.upsert_synced_session(synced_entry_with_generation(2));

    // Newer-generation install on a poisoned mutex — must APPLY.
    poison_shared_synced(&coordinator);
    coordinator.upsert_synced_session(synced_entry_with_generation(3));
    assert_eq!(
        synced_generation_recovered(&coordinator, &key),
        Some(3),
        "a newer-generation install must still apply after poison recovery"
    );

    // Equal-generation delete on a (re-)poisoned mutex — must APPLY.
    poison_shared_synced(&coordinator);
    coordinator.delete_synced_session_gen(key.clone(), 3);
    assert!(
        synced_generation_recovered(&coordinator, &key).is_none(),
        "an equal-generation delete must still remove the entry after \
         poison recovery"
    );

    // Neither legitimate operation was counted as a stale refusal.
    //
    // #6819 note on what the per-instance scoping COST here: `..._before` is now
    // always 0, because each `#[test]` owns its Coordinator. Under the previous
    // process-global scheme these were genuine moving-baseline deltas — another
    // test's refusals could make `stale_installs_before` nonzero — whereas now
    // the two assertions immediately below are literally `0 == 0`, which is also
    // what a never-incremented counter reads. Deleting the `fetch_add` bumps
    // outright leaves THIS test passing in isolation. That is determinism bought
    // at the cost of these two assertions' independence, and it is an acceptable
    // trade only because the same mutation reds four other tests in this file
    // (the two non-poison rejection tests, the two poison ones) plus
    // `refusal_counters_are_per_coordinator_not_process_global`. The family is
    // bound; this negative control is individually weak, which is normal for a
    // negative control but should not be mistaken for coverage.
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        stale_installs_before,
        "a legitimate install must not be counted as a stale refusal"
    );
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        stale_deletes_before,
        "a legitimate delete must not be counted as a stale refusal"
    );

    // #6819 §7: the legs above only exercise NEWER/EQUAL operations, so on
    // their own they accept DELETING the generation guard outright — a build
    // that recovers the poison and then applies everything satisfies every
    // assertion so far, and both stale-counter expectations are just the
    // per-instance zero baseline. A negative control that accepts the removal
    // of the thing it is controlling for is not controlling anything, so the
    // selectivity of the recovery is asserted here directly: recovery must
    // keep EVALUATING the guard, not bypass it.
    let stale_key = test_key();
    coordinator.upsert_synced_session(synced_entry_with_generation(9));
    assert_eq!(
        synced_generation_recovered(&coordinator, &stale_key),
        Some(9),
        "setup: the re-seeded entry must be stored before the stale probes"
    );

    poison_shared_synced(&coordinator);
    coordinator.upsert_synced_session(synced_entry_with_generation(8));
    assert_eq!(
        synced_generation_recovered(&coordinator, &stale_key),
        Some(9),
        "poison recovery must not turn into accept-everything: a STALE \
         install is still refused after the mutex is recovered"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        stale_installs_before + 1,
        "the stale install refused after recovery must be counted exactly once"
    );

    poison_shared_synced(&coordinator);
    coordinator.delete_synced_session_gen(stale_key.clone(), 8);
    assert_eq!(
        synced_generation_recovered(&coordinator, &stale_key),
        Some(9),
        "poison recovery must not turn into accept-everything: a STALE \
         delete is still refused after the mutex is recovered"
    );
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        stale_deletes_before + 1,
        "the stale delete refused after recovery must be counted exactly once"
    );

    // The panic that poisoned the mutex is OBSERVABLE: each recovery bumps
    // the shared counter and emits a journald line. Pre-fix the two guard
    // reads recovered nothing and logged nothing.
    //
    // This bound is >= rather than == on purpose, and it is the ONE assertion
    // in this file that is still measured against a process-global
    // (`SHARED_SESSION_POISON_RECOVERIES`, shared_ops.rs — bumped inside
    // `lock_shared_recover`, which takes only the mutex and so has no
    // per-Coordinator home to move to under #6819). A concurrent test's
    // recovery can only push the observed value UP, so a lower bound cannot
    // false-FAIL; an equality could. It can be satisfied by another test's
    // bumps, which is why the precise claims above ride on the per-instance
    // stale counters instead. `+ 4` is the number of poisonings this test
    // performs: `> before` alone passed even if a single recovery served all
    // of them.
    const POISONINGS: u64 = 4;
    assert!(
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed)
            >= recoveries_before + POISONINGS,
        "each poisoning must be recovered and counted so the underlying worker \
         panic is not silently self-healed"
    );
}

// --- #4393 peer-synced SNAT reverse-NAT dnat_table publish/delete wiring ----

fn synced_snat_entry() -> SyncedSessionEntry {
    let mut decision = test_decision();
    // Forward SNAT: the client source is rewritten to the WAN pool
    // (addr, port) — exactly what the primary published into dnat_table.
    decision.nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    };
    SyncedSessionEntry {
        key: test_key(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
    }
}

/// #4393 FAIL-ON-REVERT: installing a peer-synced forward SNAT session on the
/// standby must publish the reverse-SNAT `dnat_table` entry (the embedded-ICMP
/// steering map), and deleting the session must release it. Without the publish
/// the standby has no reverse-NAT steering entry, so after failover an inbound
/// embedded-ICMP error (PMTUD Too-Big / traceroute Time-Exceeded) quoting the
/// NATed inner packet is not steered to the helper and is never reverse-NAT'd
/// back to the original client (PMTUD blackhole).
///
/// Real BPF maps cannot be created under `cargo test` (the host runs with
/// `kernel.unprivileged_bpf_disabled`), so the publish/delete are observed via
/// the test-only `DNAT_PUBLISH_ATTEMPTS` / `DNAT_DELETE_ATTEMPTS` counters bumped
/// inside `publish_dnat_table_entry` / `delete_dnat_table_entry` whenever a
/// keyed syscall is issued. The fd is `-1` (EBADF after the keyed attempt is
/// counted). RED on revert: remove the publish from `upsert_synced_session` and
/// the SNAT publish assertion fails; remove the delete from
/// `delete_synced_session_gen` and the SNAT delete assertion fails. The
/// non-SNAT control guards against publishing/deleting for flows that carry no
/// source rewrite.
#[test]
fn synced_snat_install_publishes_and_delete_releases_dnat_table_entry() {
    use crate::afxdp::checksum::{DNAT_DELETE_ATTEMPTS, DNAT_PUBLISH_ATTEMPTS};

    // Serialize against any other test touching the process-global counters.
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = GUARD.lock().expect("counter guard");

    let mut coordinator = Coordinator::new();
    // A live v4 dnat_table fd so the publish/delete path is reached; -1 makes
    // the syscall a harmless EBADF after the keyed attempt is counted.
    coordinator.bpf_maps.dnat_table_fd = Some(OwnedFd { fd: -1 });
    let key = test_key();

    // Forward SNAT synced install must publish the reverse-SNAT entry.
    let before_pub = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.upsert_synced_session(synced_snat_entry());
    let after_pub = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_pub - before_pub,
        1,
        "peer-synced forward SNAT install must publish the reverse-SNAT dnat_table entry \
         (#4393); got {} attempts",
        after_pub - before_pub
    );

    // Deleting the synced SNAT session must release the reverse-SNAT entry.
    let before_del = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(key.clone());
    let after_del = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_del - before_del,
        1,
        "deleting the synced SNAT session must release its reverse-SNAT dnat_table entry \
         (#4393); got {} attempts",
        after_del - before_del
    );

    // Non-SNAT control: a plain synced session (test_decision -> no source
    // rewrite) publishes and deletes nothing.
    let before_pub2 = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.upsert_synced_session(synced_entry_with_generation(0));
    let after_pub2 = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_pub2 - before_pub2,
        0,
        "a non-SNAT synced install must not publish a dnat_table entry"
    );
    let before_del2 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(key);
    let after_del2 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_del2 - before_del2,
        0,
        "deleting a non-SNAT synced session must not attempt a dnat_table delete"
    );
}

// #2962: kicking an export for an EMPTY owner-RG set is a no-op — it must
// not consume an export sequence and the wait must drain nothing, preserving
// the pre-split early return semantics.
#[test]
fn kick_owner_rg_export_empty_set_is_noop_and_consumes_no_sequence() {
    let coordinator = Coordinator::new();
    let before = coordinator.sessions.export_seq.load(Ordering::Relaxed);
    let wait = coordinator.kick_owner_rg_export(&[], 0);
    assert_eq!(
        coordinator.sessions.export_seq.load(Ordering::Relaxed),
        before,
        "empty owner-RG export must not consume a sequence"
    );
    assert!(
        wait.wait_and_collect().expect("empty export").is_empty(),
        "empty owner-RG export must drain no deltas"
    );
}

// #2962: the locked KICK phase enqueues the export command (with the bumped
// sequence) to every worker and returns immediately; the lock-free wait
// completes once the worker acks. This isolates the blocking ack-wait into
// `OwnerRgExportWait::wait_and_collect`, off the global ServerState lock.
#[test]
fn kick_owner_rg_export_enqueues_command_then_wait_completes_on_ack() {
    let mut coordinator = Coordinator::new();
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let handle = test_worker_handle(commands.clone());
    let ack = handle.session_export_ack.clone();
    coordinator
        .workers
        .records
        .insert(0, WorkerRuntimeRecord::for_test(handle));

    let wait = coordinator.kick_owner_rg_export(&[1, 2], 0);

    {
        let pending = commands.lock().expect("commands");
        assert_eq!(pending.len(), 1, "exactly one export command enqueued");
        match pending.front().expect("front") {
            WorkerCommand::ExportOwnerRGSessions { sequence, owner_rgs } => {
                assert_eq!(*sequence, 1, "first export bumps the sequence to 1");
                assert_eq!(owner_rgs, &vec![1, 2], "owner-RG set propagated verbatim");
            }
            other => panic!("expected ExportOwnerRGSessions, got {other:?}"),
        }
    }

    // No real bindings, so the drain yields an empty set once the worker acks.
    ack.store(1, Ordering::Release);
    assert!(
        wait.wait_and_collect().expect("export after ack").is_empty(),
        "no bindings means no deltas to drain"
    );
}

// ---------------------------------------------------------------------------
// #2880: purge_remapped_tunnel_sessions must not silently swallow a failed
// lossless close-delta push. On a disconnected/saturated event stream the
// close delta cannot be queued — the local sessions are still deleted, and the
// undelivered delta MUST be recorded in the event-stream dropped-frames metric
// (error hygiene), not discarded by the old `let _ =`. The purge is
// CLEANUP-only (not a correctness boundary): a surviving stale entry is
// harmless (encap ifindex guard) and self-heals via the standby's own
// snapshot-apply purge + idle GC, so no resync is forced.
// ---------------------------------------------------------------------------

/// Install one forward synced session whose resolution carries
/// `tunnel_endpoint_id`, returning the coordinator + the session key. The
/// session is in the shared `synced` table (publish_shared_session), so the
/// purge finds it and `delete_synced_session` can remove it.
fn coordinator_with_tunnel_session(tunnel_endpoint_id: u16) -> (Coordinator, SessionKey) {
    let mut coordinator = Coordinator::new();
    coordinator.forwarding = ForwardingState::default();
    let mut decision = test_decision();
    decision.resolution.tunnel_endpoint_id = tunnel_endpoint_id;
    let key = test_key();
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(), // is_reverse = false -> emits a close delta
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    (coordinator, key)
}

#[test]
fn purge_remapped_tunnel_sessions_records_drop_on_lossless_failure() {
    let (mut coordinator, key) = coordinator_with_tunnel_session(7);

    // Disconnected event stream: push_delta_lossless fails immediately
    // (connected = false), like a wedged/disconnected consumer. Keep `_rx`
    // alive so the channel does not also report Disconnected for an unrelated
    // reason.
    let (sender, _rx) = crate::event_stream::EventStreamSender::test_sender(false, 16);
    coordinator.event_stream = Some(sender);

    let purged = coordinator.purge_remapped_tunnel_sessions(&[7]);

    // The local delete still happened and the count is accurate for the local
    // purge (the count is purely local; propagation failure is recorded
    // separately, not conflated).
    assert_eq!(purged, 1, "the local session is purged regardless of push");
    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("synced")
            .get(&key)
            .is_none(),
        "the remapped tunnel session must be deleted locally"
    );

    // FAIL-ON-REVERT: restoring `let _ = handle.push_delta_lossless(...)` (the
    // silent swallow) stops recording the drop, so this assertion goes RED —
    // the undelivered close is once again invisible (#2880).
    let dropped = coordinator
        .event_stream
        .as_ref()
        .expect("event stream")
        .stats()
        .dropped;
    assert_eq!(
        dropped, 1,
        "an undelivered lossless close delta must be recorded in the \
         event-stream dropped-frames metric, not silently swallowed"
    );
}

#[test]
fn purge_remapped_tunnel_sessions_no_drop_on_lossless_success() {
    let (mut coordinator, key) = coordinator_with_tunnel_session(7);

    // Connected event stream with a live receiver and ample capacity: the
    // lossless close-delta push SUCCEEDS, so nothing is recorded as dropped.
    let (sender, rx) = crate::event_stream::EventStreamSender::test_sender(true, 16);
    coordinator.event_stream = Some(sender);

    let purged = coordinator.purge_remapped_tunnel_sessions(&[7]);

    assert_eq!(purged, 1, "the local session is purged and the count is correct");
    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("synced")
            .get(&key)
            .is_none(),
        "the remapped tunnel session must be deleted locally"
    );
    // The close delta reached the consumer and nothing was dropped.
    assert!(
        rx.try_recv().is_ok(),
        "a close delta must be queued to the connected consumer"
    );
    let stats = coordinator
        .event_stream
        .as_ref()
        .expect("event stream")
        .stats();
    assert_eq!(stats.sent, 1, "the close delta must be counted as sent");
    assert_eq!(
        stats.dropped, 0,
        "no drop must be recorded when the close delta was queued losslessly"
    );
}

#[test]
fn drain_session_deltas_from_live_is_fair_across_bindings() {
    // #5290: the owner-RG bulk-export mirror of `Coordinator::drain_session_deltas`
    // must share the same fair rotating-cursor drain — a capped export budget
    // below the aggregate pending count is spread across every binding, not
    // handed whole to the first. Reverting to whole-budget-first would drain all
    // 30 from binding 0 and leave bindings 1..3 untouched.
    let live: Vec<Arc<BindingLiveState>> = (0..3)
        .map(|_| {
            let b = Arc::new(BindingLiveState::new());
            for _ in 0..40 {
                b.push_session_delta(SessionDeltaInfo::default());
            }
            b
        })
        .collect();

    let (drained, cursor) = drain_session_deltas_from_live(&live, 30, 0); // quantum 10
    assert_eq!(drained.len(), 30, "capped export returns exactly the budget");
    // Cursor wrapped back to 0 after serving all three (10 each).
    assert_eq!(cursor % 3, 0, "cursor rotated through every binding");

    for (i, b) in live.iter().enumerate() {
        let residual = b.drain_session_deltas(usize::MAX).len();
        assert_eq!(
            residual, 30,
            "binding {i} must have been served an equal 10-delta quantum, \
             leaving 30 — a whole-budget-first export would not"
        );
    }
}
