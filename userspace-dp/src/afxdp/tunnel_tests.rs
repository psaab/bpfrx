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
