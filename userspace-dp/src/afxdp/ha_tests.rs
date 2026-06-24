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
        owner_rg_id: 1,
        fabric_ingress: true,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
    }
}

fn test_forwarding_state_with_fabric() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        ifindex: 6,
        tunnel_endpoint_id: 0,
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
    coordinator
        .workers
        .handles
        .insert(0, test_worker_handle(worker_commands.clone()));

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
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
        coordinator
            .workers
            .handles
            .insert(worker_id as u32, test_worker_handle(queue.clone()));
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

    // Equal-generation delete (gen=2) — applies.
    coordinator.delete_synced_session_gen(key.clone(), 2);
    assert!(
        synced_generation(&coordinator, &key).is_none(),
        "equal-generation delete should remove the entry"
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
