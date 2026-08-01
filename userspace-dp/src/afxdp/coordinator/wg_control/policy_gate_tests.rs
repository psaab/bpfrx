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
    PolicyApplicationSnapshot, PolicyRuleSnapshot, RouteSnapshot, TunnelEndpointSnapshot,
    ZoneSnapshot,
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

/// A minimal IPv4 packet carrying an arbitrary IP protocol number with an
/// 8-byte opaque payload. The vehicle for the r2 MAJOR 1 bypass: the
/// attacker picks the protocol byte and nothing else changes.
fn ipv4_proto(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = protocol;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt
}

/// A minimal IPv4 ICMP packet with an explicit type/code.
fn ipv4_icmp(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: u8, icmp_code: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20] = icmp_type;
    pkt[21] = icmp_code;
    pkt
}

/// A minimal IPv6 ICMPv6 packet with an explicit type/code.
fn ipv6_icmp(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: u8, icmp_code: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
    pkt[6] = 58; // ICMPv6
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40] = icmp_type;
    pkt[41] = icmp_code;
    pkt
}

/// `ipv4_tcp` with a NON-ZERO fragment offset — a non-first fragment,
/// whose post-IP bytes are payload, not a TCP header.
fn ipv4_tcp_non_first_fragment(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut pkt = ipv4_tcp(src, dst, 44_100, 80);
    // frag_off field (octets 6..8): offset 2 (in 8-octet units), MF clear.
    pkt[6..8].copy_from_slice(&2u16.to_be_bytes());
    pkt
}

/// An IPv6 packet whose NON-FIRST Fragment header (offset != 0) precedes
/// what would be the TCP header — the v6 twin of the shape above.
fn ipv6_tcp_non_first_fragment(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let mut pkt = vec![0u8; 68];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&28u16.to_be_bytes()); // frag hdr (8) + 20
    pkt[6] = 44; // Fragment header
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // Fragment header at 40: next-header TCP, offset 2 (<<3), M=0.
    pkt[40] = 6;
    pkt[41] = 0;
    pkt[42..44].copy_from_slice(&(2u16 << 3).to_be_bytes());
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

/// The EXPANDED `junos-ping` application term exactly as the Go control
/// plane emits it (`PolicyApplicationSnapshot { protocol: "icmp",
/// icmp_type: Some(8) }`, #3020). Attaching this — rather than a bare
/// `applications: ["junos-ping"]` name with no terms — is what makes an
/// ICMP control DISCRIMINATE: without the icmp-type constraint the rule
/// matches every ICMP packet and cannot detect a fabricated type.
fn junos_ping_term() -> PolicyApplicationSnapshot {
    PolicyApplicationSnapshot {
        name: "junos-ping".to_string(),
        protocol: "icmp".to_string(),
        icmp_type: Some(8),
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

/// As [`run_inner`], but reports the non-policy forward-drop counter too:
/// `(escaped, denies, forward_drops, unadjudicated)`.
fn run_inner_full(forwarding: &ForwardingState, inner: &[u8]) -> (Vec<u8>, u64, u64, u64) {
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
    assert!(outcome.authenticated());
    let escaped = fixture.drain_tun();
    let counters = xpf.counters();
    (
        escaped,
        counters.inner_policy_denies.load(Ordering::Relaxed),
        counters.inner_forward_drops.load(Ordering::Relaxed),
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
// r2 MAJOR 1: a DENY must not be bypassable by choosing a protocol
// number or by fragmenting
// ===================================================================

/// Build the exact configuration the enforcement test above uses —
/// tunnel zoned, egress zoned, route present, `untrust -> trust` DENY —
/// so these tests differ from it ONLY in the inner packet's shape.
fn denied_zone_pair_forwarding() -> ForwardingState {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![
        v4_route_to_lan(),
        RouteSnapshot {
            table: "inet6.0".to_string(),
            family: "inet6".to_string(),
            destination: "2001:db8:88::/64".to_string(),
            next_hops: vec!["2001:db8:88::1@ge-0/0/9.0".to_string()],
            discard: false,
            next_table: String::new(),
            preference: 0,
        },
    ];
    snapshot.policies = vec![deny_rule("untrust", "trust")];
    build_forwarding_state(&snapshot)
}

/// **The r2 MAJOR 1 fail-on-revert test.** `parse_flow_ports` yields no
/// 5-tuple for any IP protocol except TCP, UDP, and identifier-bearing
/// ICMP/ICMPv6, and none for a fragment. The first cut of this gate
/// bailed to `Unadjudicated` on exactly that condition, so an
/// AUTHENTICATED WireGuard peer — the very entity the DENY exists to
/// constrain — bypassed it by setting one byte: SCTP, GRE, IPIP, ESP/AH,
/// an ICMP error type, or any TCP/UDP flow fragmented.
///
/// AllowedIPs gates the inner SOURCE; nothing gates the inner PROTOCOL
/// NUMBER. Every shape below must now be DENIED on its L3 identity.
#[test]
fn denied_zone_pair_cannot_be_bypassed_by_the_inner_protocol_or_fragmentation() {
    let forwarding = denied_zone_pair_forwarding();
    let v4_src = Ipv4Addr::new(10, 77, 0, 5);
    let v4_dst = Ipv4Addr::new(10, 88, 0, 9);
    let v6_src: Ipv6Addr = "2001:db8:77::5".parse().unwrap();
    let v6_dst: Ipv6Addr = "2001:db8:88::9".parse().unwrap();

    let shapes: Vec<(&str, Vec<u8>)> = vec![
        // A real, usable transport the matcher has no port parser for.
        ("sctp (proto 132)", ipv4_proto(v4_src, v4_dst, 132)),
        // Arbitrary encapsulated transit.
        ("gre (proto 47)", ipv4_proto(v4_src, v4_dst, 47)),
        ("ipip (proto 4)", ipv4_proto(v4_src, v4_dst, 4)),
        ("esp (proto 50)", ipv4_proto(v4_src, v4_dst, 50)),
        // Non-identifier-bearing ICMP: no pseudo-port, so no 5-tuple.
        ("icmp dest-unreachable (type 3)", ipv4_icmp(v4_src, v4_dst, 3, 1)),
        ("icmp time-exceeded (type 11)", ipv4_icmp(v4_src, v4_dst, 11, 0)),
        ("icmpv6 packet-too-big (type 2)", ipv6_icmp(v6_src, v6_dst, 2, 0)),
        // Fragmented TCP: every non-first fragment was flowless.
        ("v4 non-first fragment", ipv4_tcp_non_first_fragment(v4_src, v4_dst)),
        ("v6 non-first fragment", ipv6_tcp_non_first_fragment(v6_src, v6_dst)),
    ];

    for (label, inner) in shapes {
        let (escaped, denies, forward_drops, unadjudicated) = run_inner_full(&forwarding, &inner);
        assert!(
            escaped.is_empty(),
            "{label}: a DENIED inner packet reached the wgN TUN and would be routed by the \
             kernel — the deny is bypassable by choosing the inner protocol/fragment bit \
             ({} bytes escaped)",
            escaped.len()
        );
        assert_eq!(
            denies, 1,
            "{label}: the drop must be the xpf ZONE-POLICY verdict (adjudicated on the L3 \
             identity via l4_present = false), not an incidental forward drop \
             (forward_drops={forward_drops})"
        );
        assert_eq!(
            unadjudicated, 0,
            "{label}: xpf HAD authority here — a missing 5-tuple must not read as \
             'no zone pair' and delegate to the kernel"
        );
    }
}

/// The same shapes under a PERMIT must still transit — the L3-aware
/// adjudication must not become a blanket drop of everything without a
/// 5-tuple. This is what makes fail-closed-by-drop the wrong answer and
/// L3 adjudication the right one.
#[test]
fn permitted_zone_pair_still_passes_protocols_without_a_5_tuple() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    snapshot.policies = vec![permit_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);
    let v4_src = Ipv4Addr::new(10, 77, 0, 5);
    let v4_dst = Ipv4Addr::new(10, 88, 0, 9);

    for (label, inner) in [
        ("sctp (proto 132)", ipv4_proto(v4_src, v4_dst, 132)),
        ("icmp dest-unreachable", ipv4_icmp(v4_src, v4_dst, 3, 1)),
        ("v4 non-first fragment", ipv4_tcp_non_first_fragment(v4_src, v4_dst)),
    ] {
        let (escaped, denies, forward_drops, unadjudicated) = run_inner_full(&forwarding, &inner);
        assert_eq!(
            escaped, inner,
            "{label}: a PERMITTED inner packet with no 5-tuple must still transit unchanged \
             (denies={denies} forward_drops={forward_drops} unadjudicated={unadjudicated})"
        );
        assert_eq!(denies, 0);
        assert_eq!(forward_drops, 0);
        assert_eq!(unadjudicated, 0);
    }
}

/// An UNINSPECTABLE inner packet is a definite xpf verdict, not an
/// absence of authority: a truncated/degenerate IP header and an IPv6
/// extension chain still unresolved at `MAX_IPV6_EXT_HEADERS` (#4743's
/// IDS-evasion shape) must DROP rather than delegate.
///
/// Asserted at the GATE, then end-to-end. The two layers are separated
/// deliberately: some degenerate headers are also refused earlier by
/// `try_decap` (its AllowedIPs check reads the inner source), which is
/// defense in depth — but it means an end-to-end "nothing escaped"
/// assertion alone would pass even if the GATE fail-opened. The direct
/// verdict assertion is what binds the gate's own behaviour.
#[test]
fn uninspectable_inner_packets_are_dropped_not_delegated() {
    let forwarding = denied_zone_pair_forwarding();
    let mut gate_buf = vec![0u8; super::policy_gate::WG_GATE_ETH_LEN + 65_535];

    // A v4 header whose declared IHL is 4 words = 16 bytes, below the
    // 20-byte minimum, so the shared L4 resolver refuses it.
    let mut bad_ihl = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        44_100,
        80,
    );
    bad_ihl[0] = 0x44;

    // A v6 packet with 9 chained Destination-Options headers — one past
    // MAX_IPV6_EXT_HEADERS, so the shared walker refuses the chain.
    let mut over_limit = vec![0u8; 40 + 9 * 8 + 8];
    over_limit[0] = 0x60;
    over_limit[4..6].copy_from_slice(&((9 * 8 + 8) as u16).to_be_bytes());
    over_limit[6] = 60; // Destination Options
    over_limit[7] = 64;
    over_limit[8..24].copy_from_slice(&"2001:db8:77::5".parse::<Ipv6Addr>().unwrap().octets());
    over_limit[24..40].copy_from_slice(&"2001:db8:88::9".parse::<Ipv6Addr>().unwrap().octets());
    for i in 0..9 {
        let at = 40 + i * 8;
        over_limit[at] = if i == 8 { 6 } else { 60 };
        over_limit[at + 1] = 0; // 8 bytes
    }

    for (label, inner) in [
        ("v4 header with IHL < 5", bad_ihl),
        ("over-limit v6 extension chain", over_limit),
    ] {
        let verdict = super::policy_gate::evaluate_wg_inner_ingress(
            &forwarding,
            WG_ENDPOINT_ID,
            &inner,
            &mut gate_buf,
        );
        assert!(
            matches!(verdict, super::policy_gate::InnerVerdict::ForwardDrop(_)),
            "{label}: an uninspectable inner packet must fail CLOSED at the gate, got {verdict:?}"
        );
        // ...and end-to-end it must never reach the kernel, whichever
        // layer refuses it first.
        let (escaped, _denies, _forward_drops, unadjudicated) =
            run_inner_full(&forwarding, &inner);
        assert!(
            escaped.is_empty(),
            "{label}: an uninspectable inner packet reached the wgN TUN ({} bytes escaped)",
            escaped.len()
        );
        assert_eq!(
            unadjudicated, 0,
            "{label}: xpf reached a verdict — it must not read as kernel delegation"
        );
    }
}

/// r2 MINOR 5: xpf's own FIB resolved a DISCARD route for the inner
/// destination. That is a definite verdict; handing the plaintext to the
/// kernel afterwards is incoherent.
#[test]
fn discard_route_inner_destination_is_dropped_not_delegated() {
    let mut snapshot = base_snapshot();
    // 10.99.0.0/24 is deliberately OUTSIDE the LAN interface's connected
    // prefix: `choose_v4_route` prefers a connected route whose prefix is
    // at least as specific, so a discard route for 10.88.0.0/24 would
    // simply lose to the 10.88.0.1/24 connected route and never surface
    // the `DiscardRoute` disposition this test exists to pin.
    snapshot.routes = vec![RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "10.99.0.0/24".to_string(),
        next_hops: Vec::new(),
        discard: true,
        next_table: String::new(),
        preference: 0,
    }];
    // Permit, so only the FIB verdict can drop this.
    snapshot.policies = vec![permit_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_tcp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 99, 0, 9),
        44_100,
        80,
    );
    let (escaped, denies, forward_drops, unadjudicated) = run_inner_full(&forwarding, &inner);
    assert!(
        escaped.is_empty(),
        "xpf's FIB said DISCARD and the plaintext still reached the kernel ({} bytes escaped)",
        escaped.len()
    );
    assert_eq!(forward_drops, 1, "a discard route is an xpf forward drop");
    assert_eq!(denies, 0, "the policy permitted it — the FIB dropped it");
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

/// Negative control 3 (r2 MODERATE 3 — REWRITTEN to DISCRIMINATE). The
/// original version attached a BARE `junos-ping` name with no
/// `application_terms`, so the rule matched every ICMP packet regardless
/// of what the gate passed for type/code — it passed identically with
/// the real type, with a fabricated `(0,0)`, and with `None`. It could
/// not detect the r2 MAJOR 2 defect it claimed to guard.
///
/// This version attaches the REAL expanded term the Go control plane
/// emits (`PolicyApplicationSnapshot { protocol: "icmp", icmp_type:
/// Some(8) }`), so a permitted echo-request transits ONLY if the gate
/// hands policy the true type 8. With `l4_offset` unstamped the gate
/// reads type/code out of the zeroed synthetic Ethernet header, policy
/// sees `(0,0)`, the term does not match, and the echo-request is
/// DROPPED — ping dead through every tunnel.
#[test]
fn permitted_icmp_echo_matches_its_icmp_typed_application_term() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    let mut rule = permit_rule("untrust", "trust");
    rule.applications = vec!["junos-ping".to_string()];
    rule.application_terms = vec![junos_ping_term()];
    snapshot.policies = vec![rule];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_icmp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        8, // echo-request
        0,
    );
    let (escaped, denies, _unadjudicated) = run_inner(&forwarding, &inner);
    assert_eq!(
        escaped, inner,
        "an echo-request permitted by an icmp-type-8 junos-ping term must transit — a gate that \
         fabricates the ICMP type breaks ping through every WireGuard tunnel"
    );
    assert_eq!(denies, 0);
}

/// The security half of the same defect, and the DISCRIMINATING control:
/// a `deny ... application junos-ping` must actually DENY a real
/// echo-request. With a fabricated `(0,0)` the icmp-type-8 term never
/// matches, the deny is skipped, and the packet escapes — a fail-open on
/// traffic the operator explicitly denied.
#[test]
fn denied_icmp_echo_is_dropped_by_its_icmp_typed_application_term() {
    let mut snapshot = base_snapshot();
    snapshot.routes = vec![v4_route_to_lan()];
    let mut deny = deny_rule("untrust", "trust");
    deny.applications = vec!["junos-ping".to_string()];
    deny.application_terms = vec![junos_ping_term()];
    // A trailing permit-any: without it the implicit default-deny would
    // drop the packet regardless, and the test would pass whether or not
    // the icmp-typed DENY matched. The permit makes the DENY load-bearing.
    snapshot.policies = vec![deny, permit_rule("untrust", "trust")];
    let forwarding = build_forwarding_state(&snapshot);

    let inner = ipv4_icmp(
        Ipv4Addr::new(10, 77, 0, 5),
        Ipv4Addr::new(10, 88, 0, 9),
        8,
        0,
    );
    let (escaped, denies, unadjudicated) = run_inner(&forwarding, &inner);
    assert!(
        escaped.is_empty(),
        "a real echo-request escaped a `deny application junos-ping` — the gate handed policy a \
         fabricated ICMP type, so the icmp-type-8 term never matched ({} bytes escaped)",
        escaped.len()
    );
    assert_eq!(denies, 1, "the icmp-typed DENY must be the matched verdict");
    assert_eq!(unadjudicated, 0);
}

/// Direct proof of the r2 MAJOR 2 root cause, at the value the gate
/// actually computes: `term_match_extra_from_frame` over the gate's own
/// synthetic frame must report the packet's TRUE type/code. This is the
/// probe that read `(0,0)` before `l4_offset` was stamped.
#[test]
fn gate_synthetic_frame_yields_the_real_icmp_type_and_code() {
    for (family, inner, want_type) in [
        (
            libc::AF_INET as u8,
            ipv4_icmp(
                Ipv4Addr::new(10, 77, 0, 5),
                Ipv4Addr::new(10, 88, 0, 9),
                8,
                0,
            ),
            8u8,
        ),
        (
            libc::AF_INET6 as u8,
            ipv6_icmp(
                "2001:db8:77::5".parse().unwrap(),
                "2001:db8:88::9".parse().unwrap(),
                128, // echo-request (ICMPv6)
                0,
            ),
            128u8,
        ),
    ] {
        let mut gate_buf = vec![0u8; super::policy_gate::WG_GATE_ETH_LEN + 65_535];
        let (frame_len, meta) =
            super::policy_gate::synthetic_frame_and_meta_for_test(&inner, family, &mut gate_buf)
                .expect("gate must build a synthetic frame + meta");
        let extra = crate::afxdp::frame::term_match_extra_from_frame(&gate_buf[..frame_len], meta);
        assert!(
            extra.l4_present,
            "family {family}: a complete ICMP header must read as L4-present"
        );
        assert_eq!(
            (extra.icmp_type, extra.icmp_code),
            (want_type, 0),
            "family {family}: the gate must hand policy the REAL ICMP type/code, not the zeroed \
             synthetic Ethernet header (l4_offset unstamped reads (0,0))"
        );
    }
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

/// A non-IPv4/IPv6 inner payload is malformed by construction —
/// WireGuard is an IP tunnel and the version nibble is 4 or 6 (a
/// zero-length keepalive exits decap through the `MalformedInner` arm and
/// never reaches here). r2 changed this from a delegation to a
/// fail-CLOSED drop: there is no tuple to adjudicate and no reason to
/// hand it to the kernel.
#[test]
fn gate_drops_a_non_ip_inner_payload() {
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
        matches!(verdict, super::policy_gate::InnerVerdict::ForwardDrop(_)),
        "a non-IP inner payload must fail CLOSED, got {verdict:?}"
    );
}
