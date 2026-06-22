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

// --- #2303 GRE outer-header DSCP/ECN propagation ----------------------

/// Build a minimal well-formed inner IPv4 packet (20-byte header, no
/// L4 payload beyond the header) with the given TOS byte (DSCP high 6
/// bits + ECN low 2 bits) so the encap site has a real inner to copy.
fn inner_ipv4_with_tos(tos: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = tos; // DSCP + ECN
    pkt[2..4].copy_from_slice(&20u16.to_be_bytes()); // total length
    pkt[8] = 64; // TTL (> 1 so the build-path decrement guard passes)
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
    pkt
}

/// Resolution that points the gre1881 fixture endpoint (id=1, logical
/// ifindex 362, IPv6 outer) at itself with both MACs resolved, so
/// `encapsulate_native_gre_frame` builds a full frame (the #1873 R-C
/// gate requires egress_ifindex == endpoint.logical_ifindex).
fn gre_encap_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 12,
        egress_ifindex: 362,
        tx_ifindex: 12,
        tunnel_endpoint_id: 1,
        next_hop: Some(IpAddr::V6("2001:559:8585:80::1".parse().unwrap())),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
        tx_vlan_id: 80,
    }
}

#[test]
fn gre_encap_copies_inner_dscp_ecn_to_outer_ipv6_traffic_class() {
    // #2303: the outer IPv6 Traffic Class must carry the inner DSCP+ECN,
    // not the pre-fix hardcoded 0. Inner TOS = EF (DSCP 46) + ECT(1)
    // (ECN 0b01) = (46 << 2) | 1 = 0xB9.
    let inner_tos = (46u8 << 2) | 0x01;
    let inner = inner_ipv4_with_tos(inner_tos);
    let inner_frame = wrap_raw_ip_packet_for_tunnel(&inner, libc::AF_INET as u8);

    let state = gre1881_state();
    let decision = SessionDecision {
        resolution: gre_encap_resolution(),
        nat: NatDecision::default(),
    };
    let mut meta = ForwardPacketMeta::default();
    meta.addr_family = libc::AF_INET as u8;
    meta.protocol = PROTO_TCP;
    meta.l3_offset = 14;

    let out = encapsulate_native_gre_frame(&inner_frame, meta, &decision, &state)
        .expect("gre encap must build a frame");

    // Outer is IPv6 (fixture outer_family inet6). With a VLAN-80 tag the
    // L2 header is 18 bytes; the IPv6 Traffic Class spans the low nibble
    // of octet 0 and the high nibble of octet 1: TC = (b0 << 4) | (b1 >> 4).
    let ip = &out[18..];
    let outer_tc = (ip[0] << 4) | (ip[1] >> 4);
    assert_eq!(
        outer_tc, inner_tos,
        "outer IPv6 Traffic Class must equal the inner TOS (DSCP+ECN); \
         pre-#2303 this was hardcoded 0"
    );
    // Fail-on-revert sharpener: the byte must be non-zero (the exact
    // failure the hardcoded-0 path produced).
    assert_ne!(outer_tc, 0, "stripped DSCP/ECN regression");
}

#[test]
fn inner_tos_byte_reads_ipv4_and_ipv6() {
    // IPv4: TOS is octet 1.
    let v4 = inner_ipv4_with_tos(0xB9);
    assert_eq!(
        crate::afxdp::gre::inner_tos_byte(&v4, libc::AF_INET as u8),
        0xB9
    );

    // IPv6: TC spans the low nibble of octet 0 and high nibble of octet 1.
    // Encode TC = 0xB9: octet0 low nibble = 0xB, octet1 high nibble = 0x9.
    let mut v6 = vec![0u8; 40];
    v6[0] = 0x60 | 0x0B; // version 6 + TC high nibble
    v6[1] = 0x90; // TC low nibble in the high nibble of octet 1
    assert_eq!(
        crate::afxdp::gre::inner_tos_byte(&v6, libc::AF_INET6 as u8),
        0xB9
    );

    // Too-short / unknown family fall back to 0, never panic.
    assert_eq!(crate::afxdp::gre::inner_tos_byte(&[], libc::AF_INET as u8), 0);
    assert_eq!(
        crate::afxdp::gre::inner_tos_byte(&v4, 99u8),
        0,
        "unknown family yields 0"
    );
}

// --- #2315 RFC 6040 §4.2 decap-side ECN combine -----------------------

use super::super::gre::{
    apply_decap_ecn_combine, decap_ecn_combine, DecapEcn, GRE_DECAP_ECN_ILLEGAL_DROPS,
};

// 2-bit ECN codepoints (low 2 bits of the DiffServ octet).
const NOT_ECT: u8 = 0b00;
const ECT_1: u8 = 0b01;
const ECT_0: u8 = 0b10;
const CE: u8 = 0b11;

#[test]
fn rfc6040_combine_table_is_exact() {
    // The full 4×4 RFC 6040 §4.2 decapsulation table. Rows = arriving
    // inner ECN; columns = arriving outer ECN. Every cell is asserted
    // so a future edit that flips one entry fails here.
    use DecapEcn::*;
    let table: [[(u8, DecapEcn); 4]; 4] = [
        // inner Not-ECT: outer CE is the illegal combo (Drop); else Keep.
        [
            (NOT_ECT, Keep),
            (ECT_0, Keep),
            (ECT_1, Keep),
            (CE, Drop),
        ],
        // inner ECT(0): outer CE → SetCe; outer ECT(1) → Keep (MAY,
        // compliant); else Keep.
        [
            (NOT_ECT, Keep),
            (ECT_0, Keep),
            (ECT_1, Keep),
            (CE, SetCe),
        ],
        // inner ECT(1): outer CE → SetCe; else Keep.
        [
            (NOT_ECT, Keep),
            (ECT_0, Keep),
            (ECT_1, Keep),
            (CE, SetCe),
        ],
        // inner CE: already the strongest signal — always Keep.
        [(NOT_ECT, Keep), (ECT_0, Keep), (ECT_1, Keep), (CE, Keep)],
    ];
    let inner_codes = [NOT_ECT, ECT_0, ECT_1, CE];
    for (row, inner) in inner_codes.iter().enumerate() {
        for (outer, expect) in table[row].iter() {
            assert_eq!(
                decap_ecn_combine(*inner, *outer),
                *expect,
                "RFC 6040 §4.2 cell inner={inner:#04b} outer={outer:#04b} \
                 must be {expect:?}"
            );
        }
    }
}

#[test]
fn rfc6040_combine_masks_high_bits() {
    // High DSCP bits in the byte must not leak into the ECN decision —
    // only the low 2 bits matter.
    assert_eq!(
        decap_ecn_combine(0xFC | ECT_0, 0xFC | CE),
        DecapEcn::SetCe,
        "DSCP bits must be masked off before the combine"
    );
    assert_eq!(
        decap_ecn_combine(0xFC | NOT_ECT, 0xFC | CE),
        DecapEcn::Drop,
        "DSCP bits must not turn the illegal combo into a keep"
    );
}

/// Validate an IPv4 header checksum: the one's-complement sum over the
/// 20-byte header (including the checksum field) must be 0xFFFF.
fn ipv4_header_checksum_ok(packet: &[u8]) -> bool {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    crate::afxdp::frame::checksum16(&packet[..ihl]) == 0
}

#[test]
fn apply_decap_combine_sets_ipv4_ce_and_recomputes_checksum() {
    // Inner IPv4, ECT(0), valid checksum. Outer CE → inner must become
    // CE and the IPv4 header checksum must stay valid after the TOS
    // byte changed.
    let before = GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed);
    let mut inner = inner_ipv4_with_tos((0u8 << 2) | ECT_0); // DSCP 0, ECT(0)
    // Seed a correct checksum for the starting header.
    inner[10] = 0;
    inner[11] = 0;
    let cs = crate::afxdp::frame::checksum16(&inner[..20]);
    inner[10..12].copy_from_slice(&cs.to_be_bytes());
    assert!(ipv4_header_checksum_ok(&inner), "fixture must start valid");

    let forward = apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, CE);
    assert!(forward, "ECT inner + outer CE forwards (after CE upgrade)");
    assert_eq!(inner[1] & 0x03, CE, "inner ECN must be upgraded to CE");
    assert_eq!(inner[1] >> 2, 0, "inner DSCP must be untouched (was 0)");
    assert!(
        ipv4_header_checksum_ok(&inner),
        "IPv4 header checksum must be recomputed after the TOS change"
    );
    assert_eq!(
        GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed),
        before,
        "a legal upgrade must not bump the illegal-drop counter"
    );
}

#[test]
fn apply_decap_combine_preserves_dscp_on_ce_upgrade() {
    // EF (DSCP 46) + ECT(1), outer CE → DSCP stays 46, ECN becomes CE.
    let mut inner = inner_ipv4_with_tos((46u8 << 2) | ECT_1);
    inner[10] = 0;
    inner[11] = 0;
    let cs = crate::afxdp::frame::checksum16(&inner[..20]);
    inner[10..12].copy_from_slice(&cs.to_be_bytes());

    assert!(apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, CE));
    assert_eq!(inner[1] >> 2, 46, "DSCP (EF) must survive the CE upgrade");
    assert_eq!(inner[1] & 0x03, CE);
    assert!(ipv4_header_checksum_ok(&inner));
}

#[test]
fn apply_decap_combine_drops_illegal_ipv4_combo_and_counts() {
    // Inner Not-ECT + outer CE → drop + counter bump.
    let before = GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed);
    let mut inner = inner_ipv4_with_tos((34u8 << 2) | NOT_ECT); // AF41, Not-ECT
    let forward = apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, CE);
    assert!(!forward, "outer CE over a Not-ECT inner must DROP (§4.2)");
    assert_eq!(
        GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed),
        before + 1,
        "the illegal-combo drop must bump the counter"
    );
}

#[test]
fn apply_decap_combine_keeps_inner_when_outer_not_congested() {
    // Outer Not-ECT must never touch the inner (no checksum change, no
    // ECN change), even for an ECN-capable inner.
    let mut inner = inner_ipv4_with_tos((10u8 << 2) | ECT_0);
    inner[10] = 0;
    inner[11] = 0;
    let cs = crate::afxdp::frame::checksum16(&inner[..20]);
    inner[10..12].copy_from_slice(&cs.to_be_bytes());
    let snapshot = inner.clone();

    assert!(apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, NOT_ECT));
    assert_eq!(
        inner, snapshot,
        "outer Not-ECT must leave the inner byte-for-byte unchanged"
    );
}

#[test]
fn apply_decap_combine_sets_ipv6_ce_without_checksum() {
    // Inner IPv6 with DSCP 0 + ECT(0). The Traffic Class spans the low
    // nibble of octet 0 and the high nibble of octet 1; ECN is the low 2
    // bits of TC = bits 4-5 of octet 1. Start: version 6 + TC high
    // nibble 0 (octet0 = 0x60); ECN(ECT0) in octet1 high nibble
    // (octet1 = ECT_0 << 4 = 0x20).
    let mut v6 = vec![0u8; 40];
    v6[0] = 0x60; // version 6, TC high nibble = 0 (DSCP top bits 0)
    v6[1] = ECT_0 << 4; // ECN = ECT(0) in the high nibble of octet 1
    let snapshot_octet0 = v6[0];

    assert!(apply_decap_ecn_combine(&mut v6, libc::AF_INET6 as u8, CE));
    // ECN = (octet1 >> 4) & 0x03 must be CE.
    assert_eq!((v6[1] >> 4) & 0x03, CE, "inner IPv6 ECN must become CE");
    assert_eq!(
        v6[0], snapshot_octet0,
        "octet 0 (version + DSCP high bits) untouched"
    );
}

#[test]
fn apply_decap_combine_drops_illegal_ipv6_combo_and_counts() {
    let before = GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed);
    let mut v6 = vec![0u8; 40];
    v6[0] = 0x60;
    v6[1] = (NOT_ECT) << 4; // inner Not-ECT
    assert!(!apply_decap_ecn_combine(&mut v6, libc::AF_INET6 as u8, CE));
    assert_eq!(
        GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed),
        before + 1
    );
}

#[test]
fn apply_decap_combine_short_packet_forwards_unchanged() {
    // Too short to hold the TOS byte: forward, never panic, no counter.
    let before = GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed);
    let mut tiny = vec![0x45u8]; // 1 byte
    assert!(apply_decap_ecn_combine(&mut tiny, libc::AF_INET as u8, CE));
    assert_eq!(GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed), before);
}

// --- #2299 WG SYN MSS clamp uses the WG-overhead formula --------------

#[test]
fn tunnel_tcp_mss_wireguard_uses_wg_overhead_not_gre() {
    // The gre1881 fixture endpoint is IPv6-outer with a 1500-byte
    // transport (reth0.80). Resolve the MSS for an inner IPv4 segment
    // under GRE mode, then flip the SAME endpoint to wireguard and
    // re-resolve: the WG value MUST be strictly smaller (the WG record +
    // UDP + §5.4.6 padding overhead the GRE formula ignores) and MUST
    // equal the standalone wg_tcp_mss() computed from the same outer
    // family / inner family / outer MTU.
    let mut state = gre1881_state();
    let decision = SessionDecision {
        resolution: gre_encap_resolution(),
        nat: NatDecision::default(),
    };
    let inner_family = libc::AF_INET as u8;

    let gre_mss = tunnel_tcp_mss(&state, &decision, inner_family);
    assert!(gre_mss > 0, "GRE branch must produce a clamp value");

    state
        .tunnel_endpoints
        .get_mut(&1)
        .expect("fixture endpoint")
        .mode = "wireguard".to_string();

    let wg_mss = tunnel_tcp_mss(&state, &decision, inner_family);
    assert!(wg_mss > 0, "WG branch must produce a clamp value");

    // The WG overhead (UDP 8 + WG hdr 16 + tag 16 + pad ≤15) is larger
    // than the GRE overhead (4/8), so the WG-clamped MSS is smaller.
    assert!(
        wg_mss < gre_mss,
        "WG MSS ({wg_mss}) must be smaller than GRE MSS ({gre_mss}); \
         pre-#2299 both went through native_gre_tcp_mss and matched"
    );

    // Cross-check against the canonical WG formula with the same inputs.
    let endpoint = state.tunnel_endpoints.get(&1).unwrap();
    let outer_mtu =
        tunnel_outer_mtu(&state, &decision, endpoint);
    let expected = crate::afxdp::wg::mss::wg_tcp_mss(
        endpoint.outer_family,
        inner_family as i32,
        outer_mtu,
    );
    assert_eq!(
        wg_mss, expected,
        "tunnel_tcp_mss must route WG endpoints through wg_tcp_mss"
    );
}

#[test]
fn tunnel_tcp_mss_gre_unchanged_for_gre_endpoint() {
    // Fail-on-revert guard: a GRE endpoint must keep the exact GRE
    // formula value (the dispatcher must not regress GRE).
    let state = gre1881_state();
    let decision = SessionDecision {
        resolution: gre_encap_resolution(),
        nat: NatDecision::default(),
    };
    let inner_family = libc::AF_INET as u8;
    assert_eq!(
        tunnel_tcp_mss(&state, &decision, inner_family),
        native_gre_tcp_mss(&state, &decision, inner_family),
        "GRE endpoint must take the GRE branch bit-for-bit"
    );
}
