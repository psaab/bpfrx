//! #5618: the xpf forward zone-policy gate over decapped WireGuard
//! plaintext.
//!
//! Every test here drives the REAL path: two `WgEngine`s complete a real
//! framed Noise handshake, the peer `try_encap`s a real inner IP packet,
//! and the resulting type-4 datagram goes through the production
//! `dispatch_inbound` with a `ForwardingState` built by the production
//! `build_forwarding_state` from a `ConfigSnapshot`. The "final
//! interface" is a pipe standing in for the `wgN` TUN — what reaches the
//! kernel is exactly what lands there, so "no bytes on the pipe" is the
//! proof the packet never reached the kernel FIB.

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
use crate::test_zone_ids::{TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID};
use crate::{
    ConfigSnapshot, InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot,
    PolicyRuleSnapshot, RouteSnapshot, TunnelEndpointSnapshot, ZoneSnapshot,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// The WireGuard logical interface (`wg0.0`) — the INGRESS identity the
/// gate must adjudicate on, never the outer UDP interface.
const WG_IFINDEX: i32 = 900;
/// The routed egress interface for the inner destination.
const LAN_IFINDEX: i32 = 800;
const WG_ENDPOINT_ID: u16 = 7;

// ===================================================================
// fixtures
// ===================================================================

fn keypair() -> ([u8; 32], [u8; 32]) {
    let kp = snow::Builder::new(crate::afxdp::wg::WG_NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    private.copy_from_slice(&kp.private);
    public.copy_from_slice(&kp.public);
    (private, public)
}

/// Two engines that know each other, with a completed framed handshake.
/// Returns `(xpf_engine, peer_engine, xpf_pub)` — `peer_engine` is the
/// REMOTE side that will encap inner packets toward us.
fn handshaken_pair() -> (Arc<WgEngine>, WgEngine, [u8; 32]) {
    let (xpf_priv, xpf_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let any: Vec<ipnet::IpNet> = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
    let xpf = Arc::new(WgEngine::new(WgEngineConfig {
        local_private_key: xpf_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: any.clone(),
            preshared_key: [0u8; 32].into(),
        }],
    }));
    let peer = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: xpf_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: any,
            preshared_key: [0u8; 32].into(),
        }],
    });
    // Peer initiates so ITS session is confirmed at install and it can
    // encap immediately (the initiator is the side that sends first).
    let mut msg1 = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
    peer.create_initiation(&xpf_pub, &mut msg1).expect("msg1");
    let mut msg2 = [0u8; crate::afxdp::wg::WG_MSG_RESPONSE_LEN];
    xpf.consume_initiation_create_response(&msg1, &mut msg2)
        .expect("xpf consumes msg1");
    peer.consume_response(&msg2).expect("peer consumes msg2");
    (xpf, peer, xpf_pub)
}

/// A minimal IPv4 TCP packet (20-byte IP header + 20-byte TCP header).
fn ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64; // ttl
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5 words
    pkt[33] = 0x02; // SYN
    pkt
}

/// A minimal IPv6 TCP packet (40-byte IP header + 20-byte TCP header).
fn ipv6_tcp(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 60];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload length
    pkt[6] = 6; // next header = TCP
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[52] = 0x50;
    pkt[53] = 0x02;
    pkt
}

struct GateFixture {
    /// The write end handed to `dispatch_inbound` as the `wgN` TUN.
    tun: std::fs::File,
    /// The read end — anything here escaped to the kernel.
    tun_read: std::fs::File,
    exceptions: Arc<Mutex<ExceptionEventRing>>,
    socket: UdpSocket,
}

fn gate_fixture() -> GateFixture {
    use std::os::fd::FromRawFd;
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);
    set_fd_nonblocking(read_fd).unwrap();
    set_fd_nonblocking(write_fd).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.set_nonblocking(true).unwrap();
    GateFixture {
        tun: unsafe { std::fs::File::from_raw_fd(write_fd) },
        tun_read: unsafe { std::fs::File::from_raw_fd(read_fd) },
        exceptions: Arc::new(Mutex::new(ExceptionEventRing::new())),
        socket,
    }
}

impl GateFixture {
    /// Everything that reached the "kernel" side of the TUN.
    fn drain_tun(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; 65_535];
        match self.tun_read.read(&mut out) {
            Ok(n) => {
                out.truncate(n);
                out
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Vec::new(),
            Err(e) => panic!("tun read: {e}"),
        }
    }
}

/// Base snapshot: `wg0.0` (ifindex 900) in zone `untrust`, `ge-0/0/9.0`
/// (ifindex 800, 10.88.0.1/24) in zone `trust`, plus a v6 connected
/// prefix on the same LAN interface. No policies — the caller adds them.
fn base_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "untrust".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "trust".to_string(),
                id: TEST_TRUST_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "wg0.0".to_string(),
                zone: "untrust".to_string(),
                linux_name: "wg0".to_string(),
                ifindex: WG_IFINDEX,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/9.0".to_string(),
                zone: "trust".to_string(),
                linux_name: "ge-0-0-9".to_string(),
                ifindex: LAN_IFINDEX,
                hardware_addr: "02:bf:72:00:09:01".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "10.88.0.1/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:db8:88::1/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            },
        ],
        tunnel_endpoints: vec![TunnelEndpointSnapshot {
            id: WG_ENDPOINT_ID,
            interface: "wg0.0".to_string(),
            linux_name: "wg0".to_string(),
            ifindex: WG_IFINDEX,
            zone: "untrust".to_string(),
            mode: "wireguard".to_string(),
            outer_family: "inet".to_string(),
            source: "172.16.50.8".to_string(),
            wg_listen_port: 51820,
            wg_local_privkey_hex: "11".repeat(32),
            // `hydrate_wg_identity` DROPS a peerless WG row, which would
            // leave the gate with no endpoint to resolve a from-zone
            // from. One peer keeps the row (its keys are unrelated to
            // the engines the test drives — the gate only reads
            // `logical_ifindex` off this row).
            wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex: "22".repeat(32),
                wg_allowed_ips: vec!["10.77.0.0/24".to_string(), "2001:db8:77::/64".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }],
        neighbors: vec![NeighborSnapshot {
            interface: "ge-0-0-9".to_string(),
            ifindex: LAN_IFINDEX,
            ip: "10.88.0.9".to_string(),
            mac: "02:bf:72:00:09:09".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn permit_rule(from: &str, to: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: format!("{from}-to-{to}-permit"),
        from_zone: from.to_string(),
        to_zone: to.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }
}

fn deny_rule(from: &str, to: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: format!("{from}-to-{to}-deny"),
        from_zone: from.to_string(),
        to_zone: to.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    }
}

/// Run one authenticated inner packet through the production
/// `dispatch_inbound` and return `(bytes that escaped to the kernel,
/// inner_policy_denies, inner_policy_unadjudicated)`.
fn run_inner(forwarding: &ForwardingState, inner: &[u8]) -> (Vec<u8>, u64, u64) {
    let (xpf, peer, xpf_pub) = handshaken_pair();
    let mut fixture = gate_fixture();
    let mut wire = vec![0u8; 65_535];
    let enc = peer.try_encap(&xpf_pub, inner, &mut wire).expect("encap");
    let mut decap_buf = vec![0u8; 65_535];
    let mut response_buf = vec![0u8; 65_535];
    let mut gate_buf = vec![0u8; super::policy_gate::WG_GATE_ETH_LEN + 65_535];
    let outcome = dispatch_inbound(
        &xpf,
        &fixture.socket,
        false,
        &mut fixture.tun,
        &wire[..enc.len],
        "198.51.100.7:51820".parse().unwrap(),
        None,
        &mut decap_buf,
        &mut response_buf,
        forwarding,
        WG_ENDPOINT_ID,
        &mut gate_buf,
        "wg0",
        &fixture.exceptions,
    );
    // The record AUTHENTICATED in every case here — a policy verdict on
    // the inner flow must not suppress per-peer endpoint learning.
    assert!(
        outcome.authenticated(),
        "an authenticated transport record must stay authenticated regardless of the inner verdict"
    );
    let escaped = fixture.drain_tun();
    let counters = xpf.counters();
    (
        escaped,
        counters.inner_policy_denies.load(Ordering::Relaxed),
        counters.inner_policy_unadjudicated.load(Ordering::Relaxed),
    )
}

fn v4_route_to_lan() -> RouteSnapshot {
    RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "10.88.0.0/24".to_string(),
        next_hops: vec!["10.88.0.1@ge-0/0/9.0".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    }
}

// ===================================================================
// #5618 fail-on-revert: the DENY must be enforced by xpf
// ===================================================================

/// **The #5618 fail-on-revert test.** An authenticated WireGuard
/// transport record carrying an inner flow that the operator's
/// `from-zone untrust to-zone trust` policy DENIES must never reach the
/// `wgN` TUN. Reverting the gate restores the direct
/// `write_packet_nonblocking(wgN)` path and the denied packet escapes to
/// the kernel FIB, which forwards it — the exact bypass #5618 reports.
///
/// The assertion is on BYTES AT THE FINAL INTERFACE, not on an internal
/// verdict: the TUN write is the only way this packet can reach the
/// kernel, so an empty pipe is proof that xpf — not the kernel —
/// enforced the verdict.
#[test]
fn authenticated_wg_plaintext_denied_by_zone_policy_never_reaches_the_tun() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    // The tunnel's own zone pair DENIES; an unrelated permit exists so
    // the verdict comes from a real matched rule, not from an empty
    // policy table falling through to the implicit default.
    snapshot.policies = vec![
        deny_rule("untrust", "trust"),
        permit_rule("trust", "untrust"),
    ];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert!(
        escaped.is_empty(),
        "a zone-policy-DENIED inner packet reached the wgN TUN and would be routed by the \
         kernel — xpf forward authority is bypassed ({} bytes escaped)",
        escaped.len()
    );
    assert_eq!(
        denies, 1,
        "the drop must be attributed to the xpf inner zone-policy verdict"
    );
    assert_eq!(
        unadjudicated, 0,
        "xpf HAD authority here (zoned tunnel, zoned routed egress) — it must not fall back \
         to kernel delegation"
    );
}

/// IPv6 parity: the same denied zone pair on an inner IPv6 flow.
#[test]
fn authenticated_wg_plaintext_denied_by_zone_policy_v6_never_reaches_the_tun() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![RouteSnapshot {
        table: "inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "2001:db8:88::/64".to_string(),
        next_hops: vec!["2001:db8:88::1@ge-0/0/9.0".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    }];
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv6_tcp(
        "2001:db8:77::5".parse().unwrap(),
        "2001:db8:88::9".parse().unwrap(),
        44_100,
        443,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert!(
        escaped.is_empty(),
        "a zone-policy-DENIED inner IPv6 packet reached the wgN TUN ({} bytes escaped)",
        escaped.len()
    );
    assert_eq!(denies, 1, "v6 deny must be attributed to the policy verdict");
    assert_eq!(unadjudicated, 0, "v6 zone pair was fully resolvable");
}

/// A COLD ARP/ND entry must not read as "no authority". The FIB
/// resolution is `MissingNeighbor` (no MAC yet) but it still carries the
/// egress ifindex, so the zone pair is known and the DENY is enforced.
/// If this ever regressed to fail-open, every first packet of a denied
/// flow would escape while the neighbor resolved.
#[test]
fn denied_inner_packet_is_dropped_even_with_a_cold_neighbor() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.neighbors.clear(); // cold ARP -> MissingNeighbor
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert!(
        escaped.is_empty(),
        "a denied inner packet escaped because the neighbor was not yet resolved — a cold \
         ARP/ND entry must not disable the policy gate"
    );
    assert_eq!(denies, 1, "MissingNeighbor still yields a real zone pair");
    assert_eq!(unadjudicated, 0);
}

// ===================================================================
// negative controls: legitimate tunnel traffic must be UNAFFECTED
// ===================================================================

/// Negative control 1: a PERMITTED inter-zone inner flow still transits,
/// byte-for-byte. A fix that drops legitimate tunnel traffic is worse
/// than the bug.
#[test]
fn permitted_inter_zone_inner_traffic_still_transits() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.policies = vec![permit_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert_eq!(
        escaped, inner,
        "a POLICY-PERMITTED inner packet must reach the wgN TUN unchanged"
    );
    assert_eq!(denies, 0, "a permitted flow must not be counted as denied");
    assert_eq!(
        unadjudicated, 0,
        "a permitted flow was really adjudicated, not delegated"
    );
}

/// Negative control 2: INTRA-zone WireGuard traffic — the inner
/// destination routes back out an interface in the tunnel's OWN zone
/// (the hairpin/peer-to-peer case) — is unaffected when the operator
/// permits that zone pair.
#[test]
fn permitted_intra_zone_wireguard_traffic_is_unaffected() {
    let mut snapshot = base_snapshot();
    // Put the LAN egress interface in the SAME zone as the tunnel.
    snapshot.interfaces[1].zone = "untrust".to_string();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.policies = vec![permit_rule("untrust", "untrust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert_eq!(
        escaped, inner,
        "permitted intra-zone WireGuard traffic must transit unchanged"
    );
    assert_eq!(denies, 0);
    assert_eq!(unadjudicated, 0);
}

/// Negative control 3: an ICMP echo permitted by an icmp-type-constrained
/// application term (`junos-ping`) must still transit. Passing `None` for
/// the packet's ICMP type/code would fail that term closed (#3020) and
/// silently break ping through the tunnel.
#[test]
fn permitted_icmp_echo_matches_its_icmp_typed_application_term() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    let mut rule = permit_rule("untrust", "trust");
    rule.applications = vec!["junos-ping".to_string()];
    snapshot.policies = vec![rule];
    let forwarding = build_forwarding_state(&snapshot);

    // IPv4 ICMP echo-request (type 8, code 0).
    let mut inner = vec![0u8; 28];
    inner[0] = 0x45;
    inner[2..4].copy_from_slice(&28u16.to_be_bytes());
    inner[8] = 64;
    inner[9] = 1; // ICMP
    inner[12..16].copy_from_slice(&Ipv4Addr::new(10, 77, 0, 5).octets());
    inner[16..20].copy_from_slice(&Ipv4Addr::new(10, 88, 0, 9).octets());
    inner[20] = 8; // echo-request
    inner[21] = 0;

    let (escaped, denies, _unadjudicated) = run_inner(&forwarding, &inner);
    assert_eq!(
        escaped, inner,
        "an echo-request permitted by junos-ping must transit — the gate must carry the real \
         ICMP type/code into policy evaluation"
    );
    assert_eq!(denies, 0);
}

// ===================================================================
// the documented residual: where xpf declines authority, it COUNTS
// ===================================================================

/// A tunnel interface with NO security zone has no from-zone, so there
/// is no zone pair to evaluate. Preserve today's kernel delegation
/// (dropping on a zone pair xpf could not compute would be worse than
/// the bug) — but COUNT it, so the residual is operator-visible.
#[test]
fn unzoned_tunnel_preserves_kernel_delegation_and_counts_it() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.interfaces[0].zone = String::new();
    snapshot.tunnel_endpoints[0].zone = String::new();
    // A deny that WOULD match if the tunnel were zoned.
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert_eq!(
        escaped, inner,
        "an unzoned tunnel has no from-zone; the packet must keep today's kernel delegation"
    );
    assert_eq!(denies, 0, "no zone pair means no policy verdict to enforce");
    assert_eq!(
        unadjudicated, 1,
        "the residual kernel delegation must be COUNTED, not silent"
    );
}

/// A host-bound inner destination is a host-inbound-admission question,
/// not a forward zone-pair question. The forward gate declines authority
/// (and counts it) rather than applying the wrong policy plane.
#[test]
fn host_bound_inner_destination_is_not_forward_adjudicated() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    // 10.88.0.1 is the firewall's OWN address on ge-0/0/9.0.
    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 1),
        44_100,
        22,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert_eq!(
        escaped, inner,
        "host-bound inner traffic must not be judged by a TRANSIT zone-pair policy"
    );
    assert_eq!(denies, 0);
    assert_eq!(unadjudicated, 1, "the host-bound residual must be counted");
}

/// No route to the inner destination in the xpf FIB means no to-zone, so
/// no zone pair. Counted, delegated — never dropped on a zone pair we
/// could not compute.
#[test]
fn unroutable_inner_destination_is_counted_not_dropped() {
    let mut snapshot = base_snapshot();
    snapshot.routes = Vec::new();
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(203, 0, 113, 9),
        44_100,
        80,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);

    assert_eq!(escaped, inner, "an unroutable inner packet keeps today's behaviour");
    assert_eq!(denies, 0);
    assert_eq!(unadjudicated, 1);
}

// ===================================================================
// unit-level gate contract
// ===================================================================

/// The gate reads the from-zone off the tunnel's LOGICAL interface, not
/// the outer UDP interface — the invariant the #5618 design comment
/// calls out explicitly ("Do not fix this by assigning the underlay
/// interface's zone").
#[test]
fn gate_takes_the_from_zone_from_the_tunnel_logical_interface() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);
    let mut gate_buf = vec![0u8; super::policy_gate::WG_GATE_ETH_LEN + 65_535];
    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    let verdict = super::policy_gate::evaluate_wg_inner_ingress(
        &forwarding,
        WG_ENDPOINT_ID,
        &inner,
        &mut gate_buf,
    );
    assert_eq!(
        verdict,
        super::policy_gate::InnerVerdict::Deny {
            from_zone: TEST_UNTRUST_ZONE_ID,
            to_zone: TEST_TRUST_ZONE_ID,
        },
        "the from-zone must be the wg0.0 logical interface's zone and the to-zone the routed \
         egress interface's zone"
    );
}

/// An endpoint id absent from the snapshot (teardown in flight) has no
/// ingress identity: decline authority rather than adjudicate against
/// some other tunnel's zone.
#[test]
fn gate_declines_authority_for_an_absent_endpoint() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);
    let mut gate_buf = vec![0u8; super::policy_gate::WG_GATE_ETH_LEN + 65_535];
    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    let verdict = super::policy_gate::evaluate_wg_inner_ingress(
        &forwarding,
        WG_ENDPOINT_ID + 99,
        &inner,
        &mut gate_buf,
    );
    assert!(
        matches!(verdict, super::policy_gate::InnerVerdict::Unadjudicated(_)),
        "an unknown endpoint id must not resolve a from-zone, got {verdict:?}"
    );
}

/// A non-IP inner payload has no 5-tuple to adjudicate. It must be
/// unadjudicated (delegated + counted), never evaluated against a
/// fabricated tuple.
#[test]
fn gate_declines_authority_for_a_non_ip_inner_payload() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);
    let mut gate_buf = vec![0u8; super::policy_gate::WG_GATE_ETH_LEN + 65_535];
    let verdict = super::policy_gate::evaluate_wg_inner_ingress(
        &forwarding,
        WG_ENDPOINT_ID,
        &[0x00, 0x11, 0x22, 0x33],
        &mut gate_buf,
    );
    assert!(
        matches!(verdict, super::policy_gate::InnerVerdict::Unadjudicated(_)),
        "a non-IP inner payload must not be adjudicated, got {verdict:?}"
    );
}
