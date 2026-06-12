// Tests for afxdp/tunnel.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep tunnel.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tunnel_tests.rs"]` from tunnel.rs.

use super::*;

fn dummy_session_key(id: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: id,
        dst_port: 5201,
    }
}

#[test]
fn prune_local_tunnel_sessions_drops_old_entries_when_threshold_exceeded() {
    let now_ns = 100_000_000_000u64;
    let mut sessions = FastMap::default();
    let mut last_prune_ns = 0;
    for idx in 0..LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD {
        sessions.insert(
            dummy_session_key(idx as u16),
            now_ns.saturating_sub(LOCAL_TUNNEL_SESSION_STALE_NS + 1),
        );
    }
    sessions.insert(dummy_session_key(60000), now_ns);

    prune_local_tunnel_sessions(&mut sessions, &mut last_prune_ns, now_ns);

    assert_eq!(sessions.len(), 1);
    assert!(sessions.contains_key(&dummy_session_key(60000)));
    assert_eq!(last_prune_ns, now_ns);
}

#[test]
fn local_tunnel_io_error_is_fatal_for_permanent_tunnel_fd_errors() {
    assert!(local_tunnel_io_error_is_fatal(
        &io::Error::from_raw_os_error(libc::EINVAL,)
    ));
    assert!(local_tunnel_io_error_is_fatal(
        &io::Error::from_raw_os_error(libc::EBADF,)
    ));
    assert!(local_tunnel_io_error_is_fatal(
        &io::Error::from_raw_os_error(libc::EBADFD,)
    ));
    assert!(local_tunnel_io_error_is_fatal(
        &io::Error::from_raw_os_error(libc::ENODEV,)
    ));
    assert!(local_tunnel_io_error_is_fatal(
        &io::Error::from_raw_os_error(libc::ENXIO,)
    ));
}

#[test]
fn local_tunnel_io_error_is_not_fatal_for_retryable_io() {
    assert!(!local_tunnel_io_error_is_fatal(&io::Error::from(
        io::ErrorKind::WouldBlock
    ),));
    assert!(!local_tunnel_io_error_is_fatal(&io::Error::from(
        io::ErrorKind::Interrupted
    ),));
    assert!(!local_tunnel_io_error_is_fatal(
        &io::Error::from_raw_os_error(libc::ETIMEDOUT),
    ));
}

#[test]
fn select_live_binding_for_ifindex_round_robins_without_allocating_candidates() {
    let live_a = Arc::new(BindingLiveState::new());
    live_a.bound.store(true, Ordering::Relaxed);
    let live_b = Arc::new(BindingLiveState::new());
    live_b.bound.store(true, Ordering::Relaxed);
    let live_other = Arc::new(BindingLiveState::new());
    live_other.bound.store(true, Ordering::Relaxed);

    let identities = BTreeMap::from([
        (
            1,
            BindingIdentity {
                slot: 1,
                queue_id: 0,
                worker_id: 0,
                interface: Arc::<str>::from("ge-0-0-0"),
                ifindex: 10,
            },
        ),
        (
            2,
            BindingIdentity {
                slot: 2,
                queue_id: 1,
                worker_id: 0,
                interface: Arc::<str>::from("ge-0-0-0"),
                ifindex: 10,
            },
        ),
        (
            3,
            BindingIdentity {
                slot: 3,
                queue_id: 0,
                worker_id: 0,
                interface: Arc::<str>::from("ge-0-0-1"),
                ifindex: 11,
            },
        ),
    ]);
    let live = BTreeMap::from([(1, live_a.clone()), (2, live_b.clone()), (3, live_other)]);

    assert!(Arc::ptr_eq(
        &select_live_binding_for_ifindex(&identities, &live, 10, 0).expect("slot 0"),
        &live_a
    ));
    assert!(Arc::ptr_eq(
        &select_live_binding_for_ifindex(&identities, &live, 10, 1).expect("slot 1"),
        &live_b
    ));
    assert!(Arc::ptr_eq(
        &select_live_binding_for_ifindex(&identities, &live, 10, 2).expect("slot wrap"),
        &live_a
    ));
    assert!(select_live_binding_for_ifindex(&identities, &live, 12, 0).is_none());
}

// --- #1881 D.1b rotation gate -----------------------------------------

use super::super::test_fixtures::native_gre_snapshot;

fn gre1881_state() -> ForwardingState {
    // native_gre_snapshot: GRE endpoint id=1, logical ifindex 362,
    // attachment label "gr-0-0-0" (linux_name).
    build_forwarding_state(&native_gre_snapshot(false))
}

#[test]
fn endpoint_attachment_valid_accepts_matching_attachment() {
    let state = gre1881_state();
    assert!(endpoint_attachment_valid(&state, 1, 362, "gr-0-0-0"));
}

#[test]
fn endpoint_attachment_valid_rejects_missing_id_and_drift() {
    let state = gre1881_state();
    assert!(
        !endpoint_attachment_valid(&state, 2, 362, "gr-0-0-0"),
        "absent id must park (removed endpoint)"
    );
    assert!(
        !endpoint_attachment_valid(&state, 1, 363, "gr-0-0-0"),
        "ifindex drift must park (reattached endpoint)"
    );
    assert!(
        !endpoint_attachment_valid(&state, 1, 362, "gr-0-0-1"),
        "name drift must park (renamed attachment)"
    );
}

#[test]
fn endpoint_attachment_valid_rejects_mode_flip() {
    let mut state = gre1881_state();
    state
        .tunnel_endpoints
        .get_mut(&1)
        .expect("fixture endpoint")
        .mode = "wireguard".to_string();
    assert!(
        !endpoint_attachment_valid(&state, 1, 362, "gr-0-0-0"),
        "same-id mode flip must park — the #1873 owner check cannot \
         detect a thread reading the wrong TUN (Codex plan r1 MAJOR 1)"
    );
}

// --- #1881 delivery-drain stop latency (Codex plan r1 MAJOR 2) --------

#[test]
fn drain_local_tunnel_deliveries_observes_stop_under_busy_producer() {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(8);
    let stop = Arc::new(AtomicBool::new(true));
    let recent = Arc::new(Mutex::new(VecDeque::new()));
    let producer_quit = Arc::new(AtomicBool::new(false));
    let producer_quit_clone = producer_quit.clone();
    let producer = thread::spawn(move || {
        // Busy producer: keep the queue non-empty for the whole test.
        while !producer_quit_clone.load(Ordering::Relaxed) {
            let _ = tx.try_send(vec![0u8; 64]);
        }
    });
    let started = std::time::Instant::now();
    let mut sink: Vec<u8> = Vec::new();
    let outcome =
        drain_local_tunnel_deliveries(&mut sink, &rx, &stop, "gre1881drain", &recent);
    let elapsed = started.elapsed();
    producer_quit.store(true, Ordering::Relaxed);
    producer.join().expect("producer joins");
    assert!(
        matches!(outcome, LocalTunnelDrainOutcome::Stopped),
        "stop observed before any recv"
    );
    assert!(sink.is_empty(), "stopped drain consumes nothing");
    assert!(
        elapsed < Duration::from_millis(500),
        "stop must bound the drain even with a producer refilling the \
         queue (was unbounded pre-#1881): took {elapsed:?}"
    );
}

#[test]
fn drain_local_tunnel_deliveries_drains_then_returns_when_not_stopped() {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(8);
    tx.try_send(vec![1, 2, 3]).expect("queued");
    tx.try_send(vec![4, 5]).expect("queued");
    let stop = Arc::new(AtomicBool::new(false));
    let recent = Arc::new(Mutex::new(VecDeque::new()));
    let mut sink: Vec<u8> = Vec::new();
    let outcome =
        drain_local_tunnel_deliveries(&mut sink, &rx, &stop, "gre1881drain2", &recent);
    assert!(matches!(outcome, LocalTunnelDrainOutcome::Drained));
    assert_eq!(sink, vec![1, 2, 3, 4, 5], "all queued deliveries written");
}

// --- #1881 write-vs-read fatal-errno split (live finding) -------------

#[test]
fn local_tunnel_write_error_einval_is_not_fatal() {
    // A TUN write EINVAL is a per-packet rejection (malformed inner),
    // observed live: the off-by-VLAN local-delivery slice made every
    // peer keepalive reply kill the thread (forever on pre-#1881
    // master; 15s respawn churn with liveness). Drop the packet, keep
    // the thread.
    let einval = io::Error::from_raw_os_error(libc::EINVAL);
    assert!(!local_tunnel_write_error_is_fatal(&einval));
    assert!(
        local_tunnel_io_error_is_fatal(&einval),
        "read-side EINVAL stays fatal (fd/iface-level condition)"
    );
    for code in [libc::EBADF, libc::EBADFD, libc::ENODEV, libc::ENXIO] {
        let err = io::Error::from_raw_os_error(code);
        assert!(
            local_tunnel_write_error_is_fatal(&err),
            "fd-death errnos stay fatal on writes too"
        );
    }
}

#[test]
fn drain_survives_einval_write_and_thread_keeps_draining() {
    struct EinvalSink;
    impl Write for EinvalSink {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(8);
    tx.try_send(vec![0u8, 0x50, 0x86, 0xdd]).expect("queued");
    let stop = Arc::new(AtomicBool::new(false));
    let recent = Arc::new(Mutex::new(VecDeque::new()));
    let outcome = drain_local_tunnel_deliveries(
        &mut EinvalSink,
        &rx,
        &stop,
        "gre1881einval",
        &recent,
    );
    assert!(
        matches!(outcome, LocalTunnelDrainOutcome::Drained),
        "EINVAL delivery write must NOT be FatalIo — the loop continues"
    );
    assert_eq!(
        recent.lock().unwrap().len(),
        1,
        "the rejected delivery is recorded as an exception"
    );
}
