//! S2 — NAT rewrite properties (#1824 plan §5.3-S2).
//!
//! P-N1 round-trip identity on non-checksum bytes, P-N2 validity
//! oracle at every hop, P-N3 descriptor-vs-generic differential
//! (success cases, `expected_ports = None`, checksum bytes masked),
//! P-N3b decline/divergence pins as deterministic examples, P-N4
//! payload immutability.
//!
//! Domain restrictions (documented production divergences, NOT
//! property violations — each pinned below):
//!   - #1838 (D3): NAT-applying inputs are v6-ext-free.
//!   - #1839 (D1): byte comparisons exclude L4 checksum bytes.
//!   - #1840 (D2): generators never emit v6 UDP zero checksums.

use super::oracle::{checksum_byte_ranges, first_diff_outside, oracle_packet_valid};
use super::strategies::{
    arb_packet_with_nat, arb_vlan, build_valid_frame, ExtHdr, PacketSpec, ValidPacket, AF4, AF6,
};
use super::*;
use crate::afxdp::checksum::{compute_ip_csum_delta, compute_l4_csum_delta};

/// Harness-defined same-packet inverse of a NAT decision (plan P-N1).
/// Explicitly NOT `NatDecision::reverse` (nat/mod.rs:63-79) — that
/// builds the reverse-FLOW decision (src↔dst swapped) for reply
/// packets and would corrupt a same-direction packet.
fn undo_of(nat: NatDecision, pkt: &ValidPacket) -> NatDecision {
    NatDecision {
        rewrite_src: nat.rewrite_src.map(|_| pkt.src_ip),
        rewrite_dst: nat.rewrite_dst.map(|_| pkt.dst_ip),
        rewrite_src_port: nat.rewrite_src_port.map(|_| pkt.src_port),
        rewrite_dst_port: nat.rewrite_dst_port.map(|_| pkt.dst_port),
        nat64: false,
        nptv6: false,
    }
}

/// One NAT hop, composed exactly as the production caller does it
/// (`rewrite_apply_v4`, frame/mod.rs:514-525): `apply_nat_ipv4` owns
/// the L4 checksum only — the IPv4 HEADER checksum is the caller's
/// job via `adjust_ipv4_header_checksum`, normally folded together
/// with the TTL decrement. The harness applies no TTL change, so
/// passing the current TTL as `old_ttl` makes that term identity.
fn apply_nat_family(packet: &mut [u8], pkt: &ValidPacket, nat: NatDecision) -> Option<()> {
    if pkt.addr_family == AF4 {
        let old_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let old_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let ttl = packet[8];
        apply_nat_ipv4(packet, pkt.protocol, nat)?;
        adjust_ipv4_header_checksum(&mut packet[..pkt.rel_l4], old_src, old_dst, ttl)
    } else {
        apply_nat_ipv6(packet, pkt.protocol, nat)
    }
}

proptest! {
    #![proptest_config(super::cfg(256))]

    /// P-N2 vacuity guard: the oracle accepts every generator output
    /// (including ext-header chains and v4 UDP zero-checksum frames).
    /// If this fails, the oracle or the builders are wrong — every
    /// other property in this file depends on both.
    #[test]
    fn oracle_accepts_generator_output(pkt in super::strategies::arb_parse_packet(6)) {
        let packet = pkt.l3_packet();
        let verdict = oracle_packet_valid(
            &packet,
            pkt.addr_family,
            pkt.protocol,
            pkt.rel_l4,
            pkt.udp_zero_csum,
        );
        prop_assert!(verdict.is_ok(), "oracle rejected builder output: {:?}", verdict);
    }

    /// P-N1 + P-N2: apply(D) then apply(undo(D)) restores every
    /// non-checksum byte, and the checksums are VALID (not necessarily
    /// bit-equal — one's-complement zero has two encodings) at all
    /// three points. v4 UDP "no checksum" stays zero across both hops.
    #[test]
    fn nat_round_trip_identity((pkt, nat) in arb_packet_with_nat()) {
        let original = pkt.l3_packet();
        prop_assert!(oracle_packet_valid(
            &original, pkt.addr_family, pkt.protocol, pkt.rel_l4, pkt.udp_zero_csum,
        ).is_ok());

        let mut packet = original.clone();
        prop_assert!(apply_nat_family(&mut packet, &pkt, nat).is_some());
        let fwd_verdict = oracle_packet_valid(
            &packet, pkt.addr_family, pkt.protocol, pkt.rel_l4, pkt.udp_zero_csum,
        );
        prop_assert!(fwd_verdict.is_ok(), "after forward NAT: {:?}", fwd_verdict);

        let undo = undo_of(nat, &pkt);
        prop_assert!(apply_nat_family(&mut packet, &pkt, undo).is_some());
        let undo_verdict = oracle_packet_valid(
            &packet, pkt.addr_family, pkt.protocol, pkt.rel_l4, pkt.udp_zero_csum,
        );
        prop_assert!(undo_verdict.is_ok(), "after undo NAT: {:?}", undo_verdict);

        let excluded = checksum_byte_ranges(pkt.addr_family, pkt.protocol, pkt.rel_l4);
        let diff = first_diff_outside(&original, &packet, &excluded);
        prop_assert!(
            diff.is_none(),
            "round trip diverged outside checksum bytes at offset {:?} (rel_l4 {})",
            diff,
            pkt.rel_l4,
        );

        // RFC 768 pin: a v4 UDP datagram sent without a checksum keeps
        // the 0x0000 encoding through both rewrites.
        if pkt.udp_zero_csum {
            let off = pkt.rel_l4 + 6;
            prop_assert_eq!(&packet[off..off + 2], &[0u8, 0u8]);
        }
    }

    /// P-N4: bytes after the L4 header (the payload) are untouched by
    /// a single forward NAT application.
    #[test]
    fn nat_payload_immutable((pkt, nat) in arb_packet_with_nat()) {
        let original = pkt.l3_packet();
        let mut packet = original.clone();
        prop_assert!(apply_nat_family(&mut packet, &pkt, nat).is_some());
        let payload_start = pkt.rel_l4 + pkt.l4_header_len;
        prop_assert_eq!(
            &packet[payload_start..],
            &original[payload_start..],
        );
    }
}

// ---------------------------------------------------------------------------
// P-N3 — descriptor-vs-generic differential
// ---------------------------------------------------------------------------

fn make_decision(pkt: &ValidPacket, nat: NatDecision, tx_vlan: u16) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(pkt.dst_ip),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: tx_vlan,
        },
        nat,
    }
}

/// Build the rewrite descriptor exactly as the flow cache does
/// (flow_cache.rs:323-355): same MACs, same NAT fields, deltas from
/// `compute_ip_csum_delta` / `compute_l4_csum_delta`.
fn make_descriptor(pkt: &ValidPacket, nat: NatDecision, tx_vlan: u16) -> RewriteDescriptor {
    let flow = pkt.session_flow();
    RewriteDescriptor {
        dst_mac: [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        fabric_redirect: false,
        tx_vlan_id: tx_vlan,
        ether_type: if pkt.addr_family == AF6 { 0x86dd } else { 0x0800 },
        rewrite_src_ip: nat.rewrite_src,
        rewrite_dst_ip: nat.rewrite_dst,
        rewrite_src_port: nat.rewrite_src_port,
        rewrite_dst_port: nat.rewrite_dst_port,
        ip_csum_delta: compute_ip_csum_delta(&flow, &nat),
        l4_csum_delta: compute_l4_csum_delta(&flow, &nat),
        egress_ifindex: 12,
        tx_ifindex: 11,
        target_binding_index: None,
        input_filter_log: None,
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: false,
        nptv6: false,
        apply_nat_on_fabric: false,
    }
}

const DIFF_ADDR: usize = 256;

fn area_with_frame(frame: &[u8]) -> MmapArea {
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(DIFF_ADDR, frame.len())
        .expect("frame fits area")
        .copy_from_slice(frame);
    area
}

proptest! {
    #![proptest_config(super::cfg(128))]

    /// P-N3: the generic in-place rewrite and the descriptor fast path
    /// produce byte-identical output frames except the checksum fields
    /// (#1839 / RFC 1624 zero-encoding — both must still be VALID by
    /// the oracle), for the success domain: TCP/UDP, TTL ≥ 2, v6
    /// ext-free, v6 UDP checksum nonzero, `expected_ports = None`
    /// (the two paths check expected ports at different pipeline
    /// points — descriptor pre-NAT as a DMA-race guard, generic
    /// post-NAT via `enforce_expected_ports` — so port-mismatch inputs
    /// are not differential-comparable).
    #[test]
    fn descriptor_generic_differential(
        (pkt, nat) in arb_packet_with_nat(),
        tx_vlan in arb_vlan(),
    ) {
        let frame = &pkt.frame;
        let area_a = area_with_frame(frame);
        let area_b = area_with_frame(frame);
        let desc = XdpDesc {
            addr: DIFF_ADDR as u64,
            len: frame.len() as u32,
            options: 0,
        };

        let decision = make_decision(&pkt, nat, tx_vlan);
        let generic = rewrite_forwarded_frame_in_place(
            &area_a, desc, pkt.meta, &decision, false, None,
        );
        let rd = make_descriptor(&pkt, nat, tx_vlan);
        let fast = apply_rewrite_descriptor(&area_b, desc, pkt.meta, &rd, None);

        let generic = generic.expect("generic rewrite must succeed on valid input");
        let fast = fast.expect("descriptor rewrite must succeed on valid input");
        prop_assert_eq!(generic, fast, "InPlaceRewriteResult (offset/len/l2) must agree");

        let out_a = area_a
            .slice(generic.offset as usize, generic.len as usize)
            .expect("generic output slice");
        let out_b = area_b
            .slice(fast.offset as usize, fast.len as usize)
            .expect("descriptor output slice");

        let out_l3 = if tx_vlan > 0 { 18usize } else { 14usize };
        let excluded: Vec<_> =
            checksum_byte_ranges(pkt.addr_family, pkt.protocol, pkt.rel_l4)
                .into_iter()
                .map(|r| (r.start + out_l3)..(r.end + out_l3))
                .collect();
        let diff = first_diff_outside(out_a, out_b, &excluded);
        prop_assert!(
            diff.is_none(),
            "paths diverged outside checksum bytes at output offset {:?}",
            diff,
        );

        // Both outputs must be independently valid (P-N2 oracle).
        for (label, out) in [("generic", out_a), ("descriptor", out_b)] {
            let verdict = oracle_packet_valid(
                &out[out_l3..],
                pkt.addr_family,
                pkt.protocol,
                pkt.rel_l4,
                pkt.udp_zero_csum,
            );
            prop_assert!(verdict.is_ok(), "{} output invalid: {:?}", label, verdict);
        }

        // P-N4 (in-place flavor): payload bytes after the L4 header
        // are exactly the input's.
        let payload_in = &frame[pkt.l3 + pkt.rel_l4 + pkt.l4_header_len..];
        let payload_out = &out_a[out_l3 + pkt.rel_l4 + pkt.l4_header_len..];
        prop_assert_eq!(payload_out, payload_in);

        // TTL/hop-limit decremented exactly once (both paths agree by
        // the masked compare; check the generic output against input).
        let ttl_off = if pkt.addr_family == AF4 { 8 } else { 7 };
        prop_assert_eq!(
            out_a[out_l3 + ttl_off],
            frame[pkt.l3 + ttl_off] - 1,
        );
    }
}

// ---------------------------------------------------------------------------
// P-N3b — decline conditions + divergence pins (deterministic examples)
// ---------------------------------------------------------------------------

fn pin_packet(v6: bool, protocol: u8, ttl: u8, ext: Vec<ExtHdr>) -> ValidPacket {
    build_valid_frame(&PacketSpec {
        v6,
        src4: 0x0a00_3d66,           // 10.0.61.102
        dst4: 0xac10_50c8,           // 172.16.80.200
        src6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66],
        dst6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8],
        protocol,
        src_port: 0x1111,
        dst_port: 0x2222,
        vlan_id: 0,
        ttl,
        ihl: 20,
        ext,
        payload_len: 8,
        payload_seed: 42,
        udp_zero_csum: false,
        tcp_flags: 0x18,
        tcp_opt_len: 0,
        seq: 100,
    })
}

/// (a) TTL/hop-limit ≤ 1 → BOTH paths decline with bytes from L3
/// onward untouched. The L2 header IS legitimately scribbled — both
/// paths write the Ethernet header during `rewrite_prepare_eth*`
/// BEFORE TTL validation (frame/mod.rs:403/413 via mod.rs:581,
/// rewrite/mod.rs:56); harmless in production because the caller
/// drops the frame on `None`.
#[test]
fn pin_ttl_expired_declines_l3_untouched() {
    for v6 in [false, true] {
        let pkt = pin_packet(v6, PROTO_TCP, 1, Vec::new());
        let nat = NatDecision {
            rewrite_src_port: Some(0x3333),
            ..NatDecision::default()
        };
        let desc = XdpDesc {
            addr: DIFF_ADDR as u64,
            len: pkt.frame.len() as u32,
            options: 0,
        };

        let area = area_with_frame(&pkt.frame);
        let decision = make_decision(&pkt, nat, 0);
        assert!(
            rewrite_forwarded_frame_in_place(&area, desc, pkt.meta, &decision, false, None)
                .is_none(),
            "generic path must decline TTL≤1 (v6={v6})"
        );
        let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
        assert_eq!(
            &after[pkt.l3..],
            &pkt.frame[pkt.l3..],
            "generic decline must leave L3+ untouched (v6={v6})"
        );

        let area = area_with_frame(&pkt.frame);
        let rd = make_descriptor(&pkt, nat, 0);
        assert!(
            apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).is_none(),
            "descriptor path must decline TTL≤1 (v6={v6})"
        );
        let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
        assert_eq!(&after[pkt.l3..], &pkt.frame[pkt.l3..]);
    }
}

/// (b) Descriptor port-mismatch (DMA-race guard, rewrite/ipv4.rs:36)
/// → `None` with L3+ untouched. The generic path treats expected
/// ports differently (post-NAT enforce) — that is exactly why P-N3
/// runs with `expected_ports = None`.
#[test]
fn pin_descriptor_port_mismatch_declines() {
    let pkt = pin_packet(false, PROTO_TCP, 64, Vec::new());
    let nat = NatDecision::default();
    let area = area_with_frame(&pkt.frame);
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let rd = make_descriptor(&pkt, nat, 0);
    assert!(
        apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, Some((0x1112, 0x2222))).is_none(),
        "descriptor must decline on expected-port mismatch"
    );
    let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
    assert_eq!(&after[pkt.l3..], &pkt.frame[pkt.l3..]);
}

/// (c) NAT64/NPTv6 descriptors decline BEFORE the eth prep
/// (rewrite/mod.rs:52) — frame fully untouched, including L2. The
/// flow cache never builds such descriptors (`should_cache` gates at
/// flow_cache.rs:223-224); this pins the defense-in-depth check.
#[test]
fn pin_descriptor_nat64_nptv6_decline_frame_untouched() {
    let pkt = pin_packet(false, PROTO_TCP, 64, Vec::new());
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    for (nat64, nptv6) in [(true, false), (false, true)] {
        let area = area_with_frame(&pkt.frame);
        let mut rd = make_descriptor(&pkt, NatDecision::default(), 0);
        rd.nat64 = nat64;
        rd.nptv6 = nptv6;
        assert!(apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).is_none());
        let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
        assert_eq!(
            after,
            &pkt.frame[..],
            "nat64/nptv6 decline happens before any byte is written"
        );
    }
}

/// (d) #1838 (D3) pin: the GENERIC v6 NAT path hardcodes L4 at offset
/// 40 (frame/mod.rs:840-841 port rewrite; checksum adjusters at
/// frame/checksum.rs:490/516-517). On a valid IPv6 packet with a
/// hop-by-hop extension header and a dst-port rewrite it writes the
/// "port" into the extension header and the "checksum adjust" into
/// TCP header bytes, leaving the real port untouched. The descriptor
/// path parses the real offset (rewrite/ipv6.rs:35-41) and gets it
/// right. THIS TEST PINS A DEFECT — when #1838 is fixed, flip these
/// assertions and re-admit ext-header packets to the NAT generators.
#[test]
fn pin_1838_generic_v6_nat_ext_header_corruption() {
    let pkt = pin_packet(true, PROTO_TCP, 64, vec![ExtHdr::HopByHop(0)]);
    assert_eq!(pkt.rel_l4, 48, "one hop-by-hop header → L4 at 48");
    let nat = NatDecision {
        rewrite_dst_port: Some(0x3333),
        ..NatDecision::default()
    };

    // Generic path (apply_nat_ipv6 is what both the in-place rewrite
    // and the copy builder call).
    let original = pkt.l3_packet();
    let mut packet = original.clone();
    assert!(apply_nat_ipv6(&mut packet, PROTO_TCP, nat).is_some());
    assert_eq!(
        &packet[48 + 2..48 + 4],
        &original[48 + 2..48 + 4],
        "DEFECT #1838: real TCP dst port is NOT rewritten"
    );
    assert_eq!(
        u16::from_be_bytes([packet[42], packet[43]]),
        0x3333,
        "DEFECT #1838: 'port' write lands inside the hop-by-hop header (offset 42)"
    );
    assert_ne!(
        &packet[56..58],
        &original[56..58],
        "DEFECT #1838: 'checksum adjust' at 40+16 mutates TCP header bytes (ack field)"
    );

    // Descriptor path on the same input handles the ext header
    // correctly: real port rewritten, ext header intact.
    let area = area_with_frame(&pkt.frame);
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let rd = make_descriptor(&pkt, nat, 0);
    let res = apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None)
        .expect("descriptor path succeeds");
    let out = area.slice(res.offset as usize, res.len as usize).unwrap();
    assert_eq!(
        u16::from_be_bytes([out[14 + 48 + 2], out[14 + 48 + 3]]),
        0x3333,
        "descriptor path rewrites the REAL dst port"
    );
    assert_eq!(
        &out[14 + 40..14 + 48],
        &pkt.frame[14 + 40..14 + 48],
        "descriptor path leaves the hop-by-hop header intact"
    );
}

/// Craft a valid v6 packet whose TRUE L4 checksum is zero, stored with
/// the 0x0000 encoding (legitimate for TCP — only UDP forbids it on
/// the wire). The last two payload bytes are the balancing word.
fn pin_packet_v6_with_zero_csum(protocol: u8) -> ValidPacket {
    let mut pkt = pin_packet(true, protocol, 64, Vec::new());
    let l4 = pkt.l4();
    let csum_off = l4 + if protocol == PROTO_TCP { 16 } else { 6 };
    // Zero the stored checksum and the balancing word, then set the
    // balancer so the segment sums to one's-complement zero.
    pkt.frame[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
    let end = pkt.frame.len();
    pkt.frame[end - 2..].copy_from_slice(&[0, 0]);
    let balance = checksum16_ipv6(
        Ipv6Addr::from(<[u8; 16]>::try_from(&pkt.frame[14 + 8..14 + 24]).unwrap()),
        Ipv6Addr::from(<[u8; 16]>::try_from(&pkt.frame[14 + 24..14 + 40]).unwrap()),
        protocol,
        &pkt.frame[l4..],
    );
    pkt.frame[end - 2..].copy_from_slice(&balance.to_be_bytes());
    pkt
}

/// (e) #1839 (D1) pin: descriptor path canonicalizes a computed
/// 0x0000 L4 checksum to 0xFFFF for ALL v6 protocols
/// (rewrite/ipv6.rs:96-98); the generic path does so only for
/// UDP/ICMPv6 (checksum.rs:85-90). Same input + same (no-op-
/// equivalent) port rewrite → 0x0000 from generic, 0xFFFF from
/// descriptor. Both encodings are valid one's-complement zero — this
/// is exactly why P-N3 masks checksum bytes. Flip when #1839 is fixed.
#[test]
fn pin_1839_v6_tcp_zero_encoding_divergence() {
    let pkt = pin_packet_v6_with_zero_csum(PROTO_TCP);
    let csum_rel = pkt.rel_l4 + 16;
    // Sanity: the crafted packet is genuinely valid with stored 0x0000.
    assert!(oracle_packet_valid(
        &pkt.frame[pkt.l3..], AF6, PROTO_TCP, pkt.rel_l4, false,
    )
    .is_ok());

    // Same-port "rewrite": generic short-circuits (old == new port,
    // frame/mod.rs:871) and leaves 0x0000; the descriptor applies its
    // ≡0 delta (0xFFFF) and canonicalizes the resulting 0 to 0xFFFF.
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port),
        ..NatDecision::default()
    };
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };

    let area = area_with_frame(&pkt.frame);
    let decision = make_decision(&pkt, nat, 0);
    let g = rewrite_forwarded_frame_in_place(&area, desc, pkt.meta, &decision, false, None)
        .expect("generic succeeds");
    let out_g = area.slice(g.offset as usize, g.len as usize).unwrap();
    assert_eq!(
        u16::from_be_bytes([out_g[14 + csum_rel], out_g[14 + csum_rel + 1]]),
        0x0000,
        "generic path keeps the 0x0000 encoding for v6 TCP"
    );

    let area = area_with_frame(&pkt.frame);
    let rd = make_descriptor(&pkt, nat, 0);
    assert_eq!(rd.l4_csum_delta, 0xffff, "same-port delta is ≡0 (0xFFFF)");
    let d = apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None)
        .expect("descriptor succeeds");
    let out_d = area.slice(d.offset as usize, d.len as usize).unwrap();
    assert_eq!(
        u16::from_be_bytes([out_d[14 + csum_rel], out_d[14 + csum_rel + 1]]),
        0xffff,
        "DEFECT #1839: descriptor canonicalizes v6 TCP 0x0000 → 0xFFFF"
    );

    // Both encodings verify — the divergence is representation-only.
    for out in [out_g, out_d] {
        assert!(
            oracle_packet_valid(&out[14..], AF6, PROTO_TCP, pkt.rel_l4, false).is_ok()
        );
    }
}

/// (f) #1840 (D2) pin: `adjust_l4_checksum_port` (frame/mod.rs:905-907)
/// skips the checksum update for UDP `current == 0` WITHOUT checking
/// the address family. A (malformed) v6 UDP datagram with checksum
/// 0x0000 keeps it through a generic port rewrite, while the
/// descriptor path applies its delta. Only reachable on malformed
/// input — the valid-packet generators never emit v6 UDP zero. Flip
/// when #1840 is fixed.
#[test]
fn pin_1840_v6_udp_zero_skip_not_family_gated() {
    let mut pkt = pin_packet(true, PROTO_UDP, 64, Vec::new());
    let csum_off = pkt.l4() + 6;
    // Force the malformed v6-UDP-zero encoding.
    pkt.frame[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port.wrapping_add(1)),
        ..NatDecision::default()
    };

    // Generic path: port rewritten, checksum skip leaves 0x0000.
    let mut packet = pkt.l3_packet();
    assert!(apply_nat_ipv6(&mut packet, PROTO_UDP, nat).is_some());
    assert_eq!(
        u16::from_be_bytes([packet[40], packet[41]]),
        pkt.src_port.wrapping_add(1),
        "generic path rewrites the port"
    );
    assert_eq!(
        u16::from_be_bytes([packet[40 + 6], packet[40 + 7]]),
        0x0000,
        "DEFECT #1840: v6 UDP zero-checksum takes the IPv4-only RFC 768 skip"
    );

    // Descriptor path applies the delta to the same input.
    let area = area_with_frame(&pkt.frame);
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let rd = make_descriptor(&pkt, nat, 0);
    let d = apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None)
        .expect("descriptor succeeds");
    let out = area.slice(d.offset as usize, d.len as usize).unwrap();
    assert_ne!(
        u16::from_be_bytes([out[14 + 40 + 6], out[14 + 40 + 7]]),
        0x0000,
        "descriptor path adjusts the checksum where the generic path skipped"
    );
}
