// Tests for nat64.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep nat64.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "nat64_tests.rs"]` from nat64.rs.

use super::*;
use crate::policy::SnapshotIntegrityError;

fn well_known_prefix() -> NAT64RuleSnapshot {
    NAT64RuleSnapshot {
        name: "nat64-wkp".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()],
        no_v6_frag_header: false,
    }
}

#[test]
fn parse_well_known_prefix() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    assert!(state.is_active());
    assert_eq!(state.prefixes.len(), 1);
    assert_eq!(
        state.prefixes[0].prefix_bytes,
        [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
}

#[test]
fn match_ipv6_dest_extracts_v4() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 64:ff9b::198.51.100.50 = 64:ff9b::c633:6432
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let (idx, v4) = state.match_ipv6_dest(dst).expect("should match");
    assert_eq!(idx, 0);
    assert_eq!(v4, Ipv4Addr::new(198, 51, 100, 50));
}

#[test]
fn match_ipv6_dest_no_match() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(state.match_ipv6_dest(dst).is_none());
}

#[test]
fn pool_allocation_round_robin() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let a1 = state.allocate_v4_source(0).expect("alloc1");
    let a2 = state.allocate_v4_source(0).expect("alloc2");
    let a3 = state.allocate_v4_source(0).expect("alloc3");
    assert_eq!(a1, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(a2, Ipv4Addr::new(198, 51, 100, 2));
    assert_eq!(a3, Ipv4Addr::new(198, 51, 100, 1)); // wraps
}

#[test]
fn empty_pool_returns_none() {
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "no-pool".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![],
        no_v6_frag_header: false,
    }]);
    assert!(state.allocate_v4_source(0).is_none());
}

#[test]
fn nat64_pool_with_cidr_mask_yields_nonempty_pool() {
    // #2123: a range-form source pool (`address A to B`) is expanded by the
    // Go compiler into per-IP /32 entries. Ipv4Addr::from_str rejects the
    // mask, so pre-fix the filter_map discarded every entry, leaving pool_v4
    // empty and allocate_v4_source returning None. The parse must strip the
    // /32 mask. This test FAILS on the unfixed code.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-range".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "100.64.0.1/32".to_string(),
            "100.64.0.2/32".to_string(),
        ],
        no_v6_frag_header: false,
    }]);
    assert!(state.is_active());
    assert_eq!(
        state.prefixes[0].pool_v4.len(),
        2,
        "range-expanded /32 pool addresses must parse, not be dropped"
    );
    // Round-robin allocation must now succeed (was None pre-fix).
    let a1 = state.allocate_v4_source(0).expect("alloc1");
    let a2 = state.allocate_v4_source(0).expect("alloc2");
    let a3 = state.allocate_v4_source(0).expect("alloc3 wraps");
    assert_eq!(a1, Ipv4Addr::new(100, 64, 0, 1));
    assert_eq!(a2, Ipv4Addr::new(100, 64, 0, 2));
    assert_eq!(a3, Ipv4Addr::new(100, 64, 0, 1));
}

#[test]
fn nat64_pool_mixed_bare_and_masked() {
    // Discrete bare-IP `address` lines and range-expanded /32 entries must
    // coexist: stripping the mask must not break the bare-IP parse.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-mixed".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "198.51.100.1".to_string(),
            "198.51.100.5/32".to_string(),
        ],
        no_v6_frag_header: false,
    }]);
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
    assert!(state.prefixes[0].pool_v4.contains(&Ipv4Addr::new(198, 51, 100, 1)));
    assert!(state.prefixes[0].pool_v4.contains(&Ipv4Addr::new(198, 51, 100, 5)));
}

#[test]
fn nat64_pool_genuinely_invalid_rejects_snapshot() {
    // #2212: a genuinely-malformed pool address must FAIL THE SNAPSHOT CLOSED
    // (one bad entry rejects the whole rule), NOT be silently filtered while
    // the rest of the pool installs. Silently dropping it narrows the pool —
    // a fail-open in the retired-eBPF enforcement plane.
    //
    // FAIL-ON-REVERT: the pre-fix `filter_map(parse_pool_v4)` returned a state
    // with pool_v4 == [100.64.0.7] and never an Err, so this assert_matches
    // FAILS if the silent-drop behavior is restored.
    let err = Nat64State::try_from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-bad".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "not-an-ip".to_string(),
            "100.64.0.7/32".to_string(),
        ],
        no_v6_frag_header: false,
    }])
    .expect_err("a malformed pool address must reject the snapshot, not be dropped");
    match err {
        SnapshotIntegrityError::Nat64UnparseableRule { rule_name, field } => {
            assert_eq!(rule_name, "nat64-bad");
            assert!(
                field.contains("not-an-ip"),
                "error must name the offending pool address, got {field:?}"
            );
        }
        other => panic!("expected Nat64UnparseableRule, got {other:?}"),
    }
}

#[test]
fn nat64_pool_non_host_mask_rejects_snapshot() {
    // #2212: a non-host mask or garbage suffix on a pool address must REJECT
    // the snapshot (fail closed), not be silently filtered while a valid /32
    // alongside it survives. Each malformed form independently rejects.
    //
    // FAIL-ON-REVERT: pre-fix this produced pool_v4 == [100.64.0.9] with no
    // Err; the expect_err below FAILS if silent-filter behavior returns.
    for bad in [
        "100.64.0.1/24",      // non-host prefix
        "100.64.0.2/notanum", // non-numeric mask
        "100.64.0.3/",        // empty mask
        "100.64.0.4//32",     // double slash
    ] {
        let result = Nat64State::try_from_snapshots(&[NAT64RuleSnapshot {
            name: "nat64-bad-mask".to_string(),
            prefix: "64:ff9b::/96".to_string(),
            pool_addresses: vec![bad.to_string(), "100.64.0.9/32".to_string()],
            no_v6_frag_header: false,
        }]);
        assert!(
            matches!(result, Err(SnapshotIntegrityError::Nat64UnparseableRule { .. })),
            "malformed pool entry {bad:?} must reject the snapshot, got {result:?}"
        );
    }
    // Verify the canonical /32-only pool DOES install (the good path still works).
    let ok = Nat64State::try_from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-good-mask".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["100.64.0.9/32".to_string()],
        no_v6_frag_header: false,
    }])
    .expect("a canonical /32 host pool must install");
    assert_eq!(ok.prefixes[0].pool_v4, vec![Ipv4Addr::new(100, 64, 0, 9)]);
}

#[test]
fn invalid_prefix_length_rejects_snapshot() {
    // #2212: a non-/96 prefix length must REJECT the snapshot (fail closed),
    // not be silently ignored leaving the rule absent at the dataplane.
    //
    // FAIL-ON-REVERT: pre-fix this `continue`d and produced an empty,
    // !is_active() state with no Err; expect_err FAILS if the skip returns.
    let err = Nat64State::try_from_snapshots(&[NAT64RuleSnapshot {
        name: "bad".to_string(),
        prefix: "64:ff9b::/64".to_string(),
        pool_addresses: vec!["1.2.3.4".to_string()],
        no_v6_frag_header: false,
    }])
    .expect_err("a non-/96 prefix must reject the snapshot, not be silently ignored");
    match err {
        SnapshotIntegrityError::Nat64UnparseableRule { rule_name, field } => {
            assert_eq!(rule_name, "bad");
            assert!(field.contains("/96"), "error must mention the /96 requirement, got {field:?}");
        }
        other => panic!("expected Nat64UnparseableRule, got {other:?}"),
    }
}

#[test]
fn empty_prefix_rejects_snapshot() {
    // #2212: an empty prefix is anomalous (the Go side never emits one) and
    // must reject the snapshot rather than being silently dropped.
    let err = Nat64State::try_from_snapshots(&[NAT64RuleSnapshot {
        name: "empty-prefix".to_string(),
        prefix: String::new(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
    }])
    .expect_err("an empty prefix must reject the snapshot");
    assert!(
        matches!(err, SnapshotIntegrityError::Nat64UnparseableRule { .. }),
        "empty prefix must surface a Nat64UnparseableRule, got {err:?}"
    );
}

#[test]
fn malformed_prefix_address_rejects_snapshot() {
    // #2212: a /96-masked but unparseable prefix address must reject (was
    // silently `continue`d pre-fix).
    let err = Nat64State::try_from_snapshots(&[NAT64RuleSnapshot {
        name: "bad-addr".to_string(),
        prefix: "not:an:ipv6::garbage::x/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
    }])
    .expect_err("a malformed prefix address must reject the snapshot");
    assert!(matches!(
        err,
        SnapshotIntegrityError::Nat64UnparseableRule { .. }
    ));
}

#[test]
fn valid_nat64_rule_still_applies_after_fail_closed() {
    // #2212 companion: a wholly valid NAT64 config must still apply cleanly
    // through the fallible path (the fail-closed gate does not over-reject).
    let state = Nat64State::try_from_snapshots(&[well_known_prefix()])
        .expect("a valid NAT64 rule must apply");
    assert!(state.is_active());
    assert_eq!(state.prefixes.len(), 1);
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
    // And it translates a forward packet (proves the rule reached the
    // translator, not just parsed).
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let (idx, dst_v4) = state.match_ipv6_dest(dst_v6).expect("dst must match prefix");
    let snat = state.allocate_v4_source(idx).expect("pool must allocate");
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"ok");
    let v4 = translate_v6_to_v4(&pkt, snat, dst_v4, false).expect("forward translate");
    assert_eq!(v4[0], 0x45);
    assert_eq!(checksum16(&v4[..20]), 0, "header checksum must verify");
}

// --- Packet translation tests ---

fn make_ipv6_tcp_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut pkt = vec![0u8; 40 + tcp_len];
    // IPv6 header
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    pkt[6] = PROTO_TCP;
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // TCP header (minimal)
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[52] = 0x50; // data offset = 5 (20 bytes)
    pkt[53] = 0x02; // SYN
    pkt[54..56].copy_from_slice(&1024u16.to_be_bytes()); // window
                                                         // Copy payload
    pkt[60..60 + payload.len()].copy_from_slice(payload);
    // Compute TCP checksum
    pkt[56..58].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src, dst, PROTO_TCP, &pkt[40..]);
    pkt[56..58].copy_from_slice(&sum.to_be_bytes());
    pkt
}

fn make_ipv4_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len;
    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5
    pkt[33] = 0x12; // SYN+ACK
    pkt[34..36].copy_from_slice(&1024u16.to_be_bytes());
    pkt[40..40 + payload.len()].copy_from_slice(payload);
    // Compute checksums
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[36..38].copy_from_slice(&[0, 0]);
    let tcp_sum = checksum16_ipv4_pseudo(src, dst, PROTO_TCP, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    pkt
}

#[test]
fn translate_v6_to_v4_tcp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    let ipv4_pkt = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // Verify IPv4 header.
    assert_eq!(ipv4_pkt[0], 0x45);
    assert_eq!(ipv4_pkt[8], 63); // TTL = 64-1
    assert_eq!(ipv4_pkt[9], PROTO_TCP);
    assert_eq!(&ipv4_pkt[12..16], &snat_v4.octets());
    assert_eq!(&ipv4_pkt[16..20], &dst_v4.octets());

    // Verify size: IPv6 was 40+25=65, IPv4 should be 20+25=45.
    assert_eq!(ipv4_pkt.len(), 45);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv4_pkt[20], ipv4_pkt[21]]), 12345);
    assert_eq!(u16::from_be_bytes([ipv4_pkt[22], ipv4_pkt[23]]), 80);

    // Verify IPv4 header checksum.
    assert_eq!(checksum16(&ipv4_pkt[..20]), 0);

    // Verify TCP checksum.
    let tcp_payload = &ipv4_pkt[20..];
    let src = Ipv4Addr::new(ipv4_pkt[12], ipv4_pkt[13], ipv4_pkt[14], ipv4_pkt[15]);
    let dst = Ipv4Addr::new(ipv4_pkt[16], ipv4_pkt[17], ipv4_pkt[18], ipv4_pkt[19]);
    assert_eq!(checksum16_ipv4_pseudo(src, dst, PROTO_TCP, tcp_payload), 0);
}

#[test]
fn translate_v4_to_v6_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // server→client reply
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let ipv4_pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"world");
    let ipv6_pkt = translate_v4_to_v6(&ipv4_pkt, src_v6, dst_v6).expect("translate");

    // Verify IPv6 header.
    assert_eq!(ipv6_pkt[0] >> 4, 6);
    assert_eq!(ipv6_pkt[6], PROTO_TCP);
    assert_eq!(ipv6_pkt[7], 63); // hop limit = 64-1
    assert_eq!(&ipv6_pkt[8..24], &src_v6.octets());
    assert_eq!(&ipv6_pkt[24..40], &dst_v6.octets());

    // Verify size: IPv4 was 20+25=45, IPv6 should be 40+25=65.
    assert_eq!(ipv6_pkt.len(), 65);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv6_pkt[40], ipv6_pkt[41]]), 80);
    assert_eq!(u16::from_be_bytes([ipv6_pkt[42], ipv6_pkt[43]]), 12345);

    // Verify TCP checksum.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0
    );
}

#[test]
fn translate_v6_to_v4_udp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build IPv6 + UDP.
    let dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns_query.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = PROTO_UDP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&53u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..48 + dns_query.len()].copy_from_slice(dns_query);
    // UDP checksum
    pkt[46..48].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &pkt[40..]);
    pkt[46..48].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4[9], PROTO_UDP);
    assert_eq!(checksum16(&v4[..20]), 0);
}

#[test]
fn translate_v6_to_v4_icmp_echo() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build ICMPv6 Echo Request.
    let icmp_len = 8; // type(1) + code(1) + checksum(2) + id(2) + seq(2)
    let mut pkt = vec![0u8; 40 + icmp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt[6] = PROTO_ICMPV6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40] = ICMPV6_ECHO_REQUEST;
    pkt[41] = 0; // code
    pkt[44..46].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    pkt[46..48].copy_from_slice(&0x0001u16.to_be_bytes()); // seq
                                                           // ICMPv6 checksum
    pkt[42..44].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6, &pkt[40..]);
    pkt[42..44].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4[9], PROTO_ICMP);
    assert_eq!(v4[20], ICMP_ECHO_REQUEST); // type mapped
    assert_eq!(checksum16(&v4[..20]), 0);
    // ICMPv4 checksum: no pseudo-header.
    assert_eq!(checksum16(&v4[20..]), 0);
}

#[test]
fn translate_v4_to_v6_icmp_echo_reply() {
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // Build ICMPv4 Echo Reply.
    let icmp_len = 8;
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&src_v4.octets());
    pkt[16..20].copy_from_slice(&dst_v4.octets());
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[20] = ICMP_ECHO_REPLY;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[26..28].copy_from_slice(&0x0001u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&[0, 0]);
    let icmp_sum = checksum16(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());

    let v6 = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("translate");
    assert_eq!(v6[6], PROTO_ICMPV6);
    assert_eq!(v6[40], ICMPV6_ECHO_REPLY); // type mapped
                                           // ICMPv6 checksum verification.
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6, &v6[40..]), 0);
}

#[test]
fn packet_size_delta() {
    // IPv6 packet: 40 header + 20 TCP header + 5 payload = 65 bytes
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"hello");
    assert_eq!(pkt.len(), 65); // 40 + 20 + 5

    let v4 = translate_v6_to_v4(
        &pkt,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        false,
    )
    .expect("translate");
    assert_eq!(v4.len(), 45); // 20 + 20 + 5
    assert_eq!(pkt.len() - v4.len(), 20); // IPv6→IPv4 shrinks by 20 bytes
}

#[test]
fn forward_decision_sets_nat64_flag() {
    let d = Nat64State::forward_decision(Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(8, 8, 8, 8));
    assert!(d.nat64);
    assert_eq!(
        d.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
    );
    assert_eq!(d.rewrite_dst, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn frame_building_v6_to_v4() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    // Build Ethernet + IPv6 frame.
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"test");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]); // dst mac
    frame.extend_from_slice(&[0xbb; 6]); // src mac
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        0,
        false,
    )
    .expect("build");

    // Should be 14 (eth) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 44);
    // Check Ethernet type is IPv4.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x0800);
}

#[test]
fn frame_building_v4_to_v6() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"resp");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let result =
        build_nat64_v4_to_v6_frame(&frame, src_v6, dst_v6, [0x11; 6], [0x22; 6], 0).expect("build");

    // Should be 14 (eth) + 64 (40 ipv6 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 64);
    // Check Ethernet type is IPv6.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x86dd);
}

#[test]
fn ttl_expired_returns_none() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let mut pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"x");
    pkt[7] = 1; // hop limit = 1
                // Need to recompute TCP checksum after modifying hop limit
                // (hop limit isn't in pseudo-header so checksum is still valid).
    assert!(
        translate_v6_to_v4(&pkt, Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8), false).is_none()
    );
}

#[test]
fn frame_building_v6_to_v4_with_vlan() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"vlan");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        100, // VLAN 100
        false,
    )
    .expect("build");

    // 18 (eth+vlan) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 18 + 44);
    // VLAN tag
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([result[16], result[17]]), 0x0800);
}

// ---------------------------------------------------------------------------
// Regression tests for #1641: translate_v4_to_v6 must trim the L4 payload to
// the IPv4 Total Length field, not the end of the input slice. The caller
// passes the whole L3-onward frame, which can carry Ethernet padding when the
// reply is shorter than the 60/64-byte minimum frame size. Before the fix the
// padding was copied into the IPv6 packet, inflating payload_len and poisoning
// the L4 checksum so the receiver dropped the reply.
// ---------------------------------------------------------------------------

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // A minimal TCP segment with no L4 payload: 20B IP + 20B TCP = 40B on the
    // wire (make_ipv4_tcp_packet sets SYN+ACK flags; the exact flag bits are
    // irrelevant to the padding bug). The NIC/driver pads the frame to the
    // 60-byte L2 minimum, so the L3-onward slice the caller hands us is 46
    // bytes (40B real + 6B zero padding).
    let mut packet = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"");
    assert_eq!(packet.len(), 40, "unpadded segment should be 40 bytes");
    let real_len = packet.len();
    packet.extend_from_slice(&[0u8; 6]); // simulate trailing Ethernet padding
    assert_eq!(packet.len(), 46);

    let ipv6_pkt = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");

    // payload_len must reflect the real L4 length (20B TCP), NOT the padded
    // slice length. Before the fix this was 26 (20 + 6 padding bytes).
    let payload_len = u16::from_be_bytes([ipv6_pkt[4], ipv6_pkt[5]]) as usize;
    assert_eq!(payload_len, 20, "payload_len must exclude Ethernet padding");
    // Total translated length = 40B IPv6 header + 20B TCP, with no padding.
    assert_eq!(ipv6_pkt.len(), 40 + (real_len - 20));
    assert_eq!(ipv6_pkt.len(), 60);

    // The L4 checksum must verify over the trimmed payload. A padding-poisoned
    // checksum (the pre-fix bug) leaves a non-zero residual here.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0,
        "TCP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_udp_dns() {
    // Short UDP/DNS reply (the canonical Ethernet-padded case). Build a 12B
    // DNS-ish payload: 20B IP + 8B UDP + 12B = 40B real, padded to 46B.
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let dns = b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = PROTO_UDP;
    packet[12..16].copy_from_slice(&src_v4.octets());
    packet[16..20].copy_from_slice(&dst_v4.octets());
    packet[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[20..22].copy_from_slice(&53u16.to_be_bytes()); // src port
    packet[22..24].copy_from_slice(&12345u16.to_be_bytes()); // dst port
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..28 + dns.len()].copy_from_slice(dns);
    packet[26..28].copy_from_slice(&[0, 0]);
    let udp_sum = checksum16_ipv4_pseudo(src_v4, dst_v4, PROTO_UDP, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_sum.to_be_bytes());

    assert_eq!(packet.len(), 40);
    packet.extend_from_slice(&[0u8; 6]); // Ethernet padding to 46B L3 slice

    let v6 = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");
    let payload_len = u16::from_be_bytes([v6[4], v6[5]]) as usize;
    assert_eq!(payload_len, udp_len, "payload_len must exclude padding");
    assert_eq!(v6.len(), 40 + udp_len);

    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_UDP, &v6[40..]),
        0,
        "UDP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_total_len_larger_than_slice_returns_none() {
    // Malformed Total Length advertising more bytes than we received: must be
    // rejected safely (no panic, no out-of-bounds), not trusted.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    // Advertise a Total Length 100 bytes beyond the actual slice.
    let bogus = (packet.len() + 100) as u16;
    packet[2..4].copy_from_slice(&bogus.to_be_bytes());
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "oversized total_len must be rejected"
    );
}

// ---------------------------------------------------------------------------
// #1662: NAT64 must copy the IP traffic class (DSCP + ECN) across translation
// in BOTH directions. Before the fix the IPv4 TOS byte / IPv6 traffic class was
// hard-zeroed, so DiffServ marking and end-to-end ECN were lost across the
// translator. RFC 7915 §4/§5 default is a verbatim full-byte copy (DSCP copied,
// ECN copied verbatim) — NAT64 is stateless translation, not RFC 6040 tunnel
// encapsulation.
//
// All cases use TOS/TC = 0xBA = (DSCP 46 EF << 2) | ECN 0b10 (ECT(0)). The
// non-zero ECN nibble means a DSCP-only implementation that dropped ECN would
// also fail these assertions.
// ---------------------------------------------------------------------------

/// DSCP 46 (EF) in bits 7:2, ECN 0b10 (ECT(0)) in bits 1:0 → 0xBA.
const TC_EF_ECT0: u8 = (46u8 << 2) | 0b10;

#[test]
fn translate_v6_to_v4_copies_traffic_class() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let mut ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"qos");
    // Set the IPv6 traffic class to 0xBA across bytes 0-1 (preserving version
    // nibble and flow label). TC[7:4] in byte0 low nibble, TC[3:0] in byte1
    // high nibble. (TCP checksum does not cover the TC byte, so no recompute.)
    ipv6_pkt[0] = (ipv6_pkt[0] & 0xf0) | (TC_EF_ECT0 >> 4);
    ipv6_pkt[1] = (ipv6_pkt[1] & 0x0f) | ((TC_EF_ECT0 & 0x0f) << 4);
    // Sanity: reconstruct and confirm the input really carries 0xBA.
    let in_tc = ((ipv6_pkt[0] & 0x0f) << 4) | (ipv6_pkt[1] >> 4);
    assert_eq!(in_tc, TC_EF_ECT0);

    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // IPv4 TOS byte must equal the source traffic class exactly (DSCP+ECN).
    assert_eq!(v4[1], TC_EF_ECT0, "IPv4 TOS must copy the IPv6 traffic class");
    // IPv4 header checksum must still verify with the non-zero TOS byte.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");
}

#[test]
fn translate_v4_to_v6_copies_traffic_class() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let mut ipv4_pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"qos");
    // Set the IPv4 TOS byte to 0xBA and recompute the IPv4 header checksum
    // (the header checksum DOES cover the TOS byte).
    ipv4_pkt[1] = TC_EF_ECT0;
    ipv4_pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&ipv4_pkt[..20]);
    ipv4_pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let v6 = translate_v4_to_v6(&ipv4_pkt, src_v6, dst_v6).expect("translate");

    // Reconstruct the IPv6 traffic class from bytes 0-1 and compare exactly.
    let out_tc = ((v6[0] & 0x0f) << 4) | (v6[1] >> 4);
    assert_eq!(
        out_tc, TC_EF_ECT0,
        "IPv6 traffic class must copy the IPv4 TOS byte"
    );
    // Version nibble must remain 6.
    assert_eq!(v6[0] >> 4, 6, "IPv6 version nibble must be preserved");
    // Flow label (low nibble of byte 1 + bytes 2-3) must stay 0.
    assert_eq!(v6[1] & 0x0f, 0, "flow-label high nibble must be 0");
    assert_eq!(v6[2], 0, "flow label must be 0");
    assert_eq!(v6[3], 0, "flow label must be 0");
}

#[test]
fn nat64_traffic_class_round_trips() {
    // v6 → v4 → v6: the traffic class survives a full round trip.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let mut ipv6_pkt = make_ipv6_tcp_packet(client_v6, dst_v6, 12345, 80, b"rt");
    ipv6_pkt[0] = (ipv6_pkt[0] & 0xf0) | (TC_EF_ECT0 >> 4);
    ipv6_pkt[1] = (ipv6_pkt[1] & 0x0f) | ((TC_EF_ECT0 & 0x0f) << 4);

    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("v6->v4");
    assert_eq!(v4[1], TC_EF_ECT0);

    // Translate the IPv4 packet back to IPv6 (reply direction reuses the same
    // helper). The TOS byte carried by v4 must reappear in the IPv6 TC.
    let v6 = translate_v4_to_v6(&v4, dst_v6, client_v6).expect("v4->v6");
    let rt_tc = ((v6[0] & 0x0f) << 4) | (v6[1] >> 4);
    assert_eq!(rt_tc, TC_EF_ECT0, "traffic class must survive round trip");
    assert_eq!(v6[0] >> 4, 6);

    // v4 → v6 → v4: the traffic class also survives the opposite round trip.
    let server_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let client_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let client_v6_reverse: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let mut ipv4_pkt = make_ipv4_tcp_packet(server_v4, client_v4, 80, 12345, b"rt2");
    ipv4_pkt[1] = TC_EF_ECT0;
    ipv4_pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&ipv4_pkt[..20]);
    ipv4_pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let v6_reverse = translate_v4_to_v6(&ipv4_pkt, server_v6, client_v6_reverse).expect("v4->v6");
    let v6_reverse_tc = ((v6_reverse[0] & 0x0f) << 4) | (v6_reverse[1] >> 4);
    assert_eq!(v6_reverse_tc, TC_EF_ECT0);

    let v4_reverse = translate_v6_to_v4(&v6_reverse, server_v4, client_v4, false).expect("v6->v4");
    assert_eq!(
        v4_reverse[1], TC_EF_ECT0,
        "traffic class must survive v4->v6->v4 round trip"
    );
    assert_eq!(
        checksum16(&v4_reverse[..20]),
        0,
        "IPv4 header checksum must verify"
    );
}

#[test]
fn translate_v4_to_v6_total_len_below_ihl_returns_none() {
    // Total Length shorter than the IPv4 header is nonsensical: reject it.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    packet[2..4].copy_from_slice(&10u16.to_be_bytes()); // < 20B IHL
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "total_len below the IPv4 header length must be rejected"
    );
}

// ---------------------------------------------------------------------------
// #2008 H16: `security nat natv6v4 no-v6-frag-header` must be honored by the
// IPv6->IPv4 translator. Before the fix the option parsed, compiled into typed
// config, and rode the snapshot wire but had NO runtime consumer: the global
// flag never reached the dataplane snapshot and translate_v6_to_v4 always set
// the Don't-Fragment (DF) bit. These tests pin the runtime enforcement: the
// flags+frag-offset word (IPv4 header bytes 6-7) must be DF=1 (0x4000) by
// default and DF=0 (0x0000) when the option is set. The DF clearing is an
// option-gated LOCAL policy, not the size-driven RFC 7915 5.1 selection.
//
// They also pin the DF/Identification consistency the Copilot review on #2014
// flagged: a DF=1 atomic datagram keeps Identification=0 (legal per RFC 6864
// 4.1), while a DF=0 fragmentable datagram MUST carry a non-zero, non-repeating
// Identification drawn from the per-translator generator (RFC 7915 5.1 / RFC
// 6864 4.1) — pinning ID=0 while clearing DF was the original bug.
// ---------------------------------------------------------------------------

/// Helper: read the IPv4 flags + fragment-offset word from a translated L3
/// packet (bytes 6-7).
fn ipv4_frag_word(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[6], pkt[7]])
}

/// Helper: read the IPv4 Identification field (bytes 4-5) from a translated L3
/// packet.
fn ipv4_identification(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[4], pkt[5]])
}

#[test]
fn translate_v6_to_v4_default_sets_df_bit() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"df");
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // Default (no-v6-frag-header NOT set): DF=1, no fragment offset.
    assert_eq!(
        ipv4_frag_word(&v4),
        0x4000,
        "default translation must set the DF bit (atomic, non-fragmentable)"
    );
    // ID=0 is legal for an ATOMIC datagram (DF=1) per RFC 6864 4.1.
    assert_eq!(
        ipv4_identification(&v4),
        0,
        "atomic (DF=1) translation keeps Identification=0"
    );
    // Header checksum must still verify.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");
}

#[test]
fn translate_v6_to_v4_no_v6_frag_header_clears_df_bit() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"nofrag");
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate");

    // With no-v6-frag-header set: DF cleared so the packet stays fragmentable.
    assert_eq!(
        ipv4_frag_word(&v4),
        0x0000,
        "no-v6-frag-header must clear the DF bit (fragmentable, per RFC 7915 5.1)"
    );
    // A fragmentable (DF=0) datagram is NON-ATOMIC. RFC 7915 5.1 sets the
    // Identification from a per-translator generator, and RFC 6864 4.1 forbids
    // a constant/repeated ID for non-atomic datagrams. A pinned ID=0 (the
    // pre-fix bug) would mis-reassemble distinct datagrams when a downstream
    // router fragments them, so the ID MUST be non-zero here.
    assert_ne!(
        ipv4_identification(&v4),
        0,
        "fragmentable (DF=0) translation MUST carry a non-zero Identification \
         (RFC 7915 5.1 / RFC 6864 4.1)"
    );
    // The change must not break the IPv4 header checksum.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");

    // Everything else (TTL, protocol, addresses, payload) must be unchanged
    // relative to the default translation — only the DF bit (bytes 6-7), the
    // Identification (bytes 4-5), and the resulting header checksum (bytes
    // 10-11) differ.
    let v4_default = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4.len(), v4_default.len());
    assert_eq!(v4[8], v4_default[8], "TTL unchanged");
    assert_eq!(v4[9], v4_default[9], "protocol unchanged");
    assert_eq!(&v4[12..20], &v4_default[12..20], "src/dst addresses unchanged");
    assert_eq!(&v4[20..], &v4_default[20..], "L4 payload unchanged");
    // The frag word is one header field that must differ.
    assert_ne!(
        ipv4_frag_word(&v4),
        ipv4_frag_word(&v4_default),
        "frag word must differ between the two modes"
    );
}

#[test]
fn translate_v6_to_v4_no_v6_frag_header_identification_is_unique() {
    // RFC 6864 4.1: a source emitting non-atomic (DF=0) datagrams MUST NOT
    // repeat the Identification for a given src/dst/proto tuple within one MDL.
    // The per-translator generator advances on every fragmentable translation,
    // so successive DF=0 translations must carry DISTINCT non-zero IDs.
    //
    // This test is DETERMINISTIC and robust to the process-global counter's
    // start value (it does not assume the generator begins at any particular
    // raw value): it exercises the pure mapping `map_frag_id` over a CONTROLLED
    // consecutive sequence that crosses the 0/1 boundary AND a full 16-bit wrap,
    // and asserts the cycle invariants directly. The old test passed only by
    // accident — other tests advanced the shared atomic before it ran, so it
    // FAILED in isolation (`cargo test <name> -- --exact`).
    //
    // Mutation check: the pre-fix mapping `if raw==0 {1} else {raw as u16}`
    // maps BOTH raw=0 and raw=1 to 1, so the raw=0->raw=1 step below produces a
    // consecutive duplicate and the no-repeat assertion fails.
    let mut prev: Option<u16> = None;
    // 0..=65536 covers the first two values (raw=0,1 — the boundary that the
    // pre-fix remap collided), the top of the cycle (raw=65534 -> 65535), and
    // the wrap (raw=65535 -> 1, raw=65536 -> 2). Iterating one full period plus
    // a step proves there is no consecutive duplicate ANYWHERE, including the
    // 65535 -> 1 jump.
    for raw in 0u32..=65536 {
        let id = map_frag_id(raw);
        assert_ne!(id, 0, "Identification must be non-zero (raw={raw})");
        assert!(
            (1..=65535).contains(&id),
            "Identification must lie in 1..=65535 (raw={raw}, id={id})"
        );
        if let Some(p) = prev {
            assert_ne!(
                p, id,
                "successive Identifications must differ (RFC 6864 4.1 no-repeat): \
                 raw={raw} produced {id} == previous {p}"
            );
        }
        prev = Some(id);
    }
    // Spot-check the boundary and wrap values the pre-fix mapping got wrong.
    assert_eq!(map_frag_id(0), 1);
    assert_eq!(map_frag_id(1), 2, "raw=1 must NOT collide with raw=0 (the bug)");
    assert_eq!(map_frag_id(65534), 65535, "top of the cycle");
    assert_eq!(map_frag_id(65535), 1, "wrap is a jump 65535 -> 1, not a repeat");
    assert_eq!(map_frag_id(65536), 2);

    // End-to-end smoke: two back-to-back fragmentable translations both carry
    // non-zero IDs and stay DF=0 with valid checksums. (The no-consecutive-dup
    // proof lives in the deterministic loop above; this only confirms the
    // generator is actually wired into the DF=0 translation path.)
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"uniq");
    let a = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate a");
    let b = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate b");
    assert_ne!(ipv4_identification(&a), 0, "first fragmentable ID must be non-zero");
    assert_ne!(ipv4_identification(&b), 0, "second fragmentable ID must be non-zero");
    assert_ne!(
        ipv4_identification(&a),
        ipv4_identification(&b),
        "two back-to-back fragmentable translations must use distinct IDs"
    );
    assert_eq!(ipv4_frag_word(&a), 0x0000);
    assert_eq!(ipv4_frag_word(&b), 0x0000);
    assert_eq!(checksum16(&a[..20]), 0, "header checksum must verify (a)");
    assert_eq!(checksum16(&b[..20]), 0, "header checksum must verify (b)");
}

#[test]
fn build_nat64_v6_to_v4_frame_honors_no_v6_frag_header() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"frame");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    // no_v6_frag_header = true: the inner IPv4 header (after the 14B Ethernet
    // header) must carry DF=0.
    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        0,
        true,
    )
    .expect("build");
    let ipv4 = &result[14..];
    assert_eq!(
        ipv4_frag_word(ipv4),
        0x0000,
        "frame builder must thread no-v6-frag-header into the IPv4 framing"
    );
}

#[test]
fn nat64_state_threads_no_v6_frag_header_from_snapshot() {
    // The flag rides on the per-rule snapshot (the Go side stamps the global
    // natv6v4 option onto every rule). from_snapshots must surface it.
    let mut snap = well_known_prefix();
    assert!(
        !Nat64State::from_snapshots(&[snap.clone()]).no_v6_frag_header,
        "default snapshot must leave no_v6_frag_header unset"
    );
    snap.no_v6_frag_header = true;
    assert!(
        Nat64State::from_snapshots(&[snap]).no_v6_frag_header,
        "from_snapshots must surface the no_v6_frag_header flag"
    );
}

// ---------------------------------------------------------------------------
// #2150: NAT64 L2 offset must agree with the canonical contract on a single
// 0x88a8 (802.1ad) tag. Pre-fix `frame_l3_offset` matched only 0x8100, so a
// 0x88a8-tagged frame was treated as untagged (l3=14) and the IP header was
// read 4 bytes into the VLAN tag → corrupted translation. This canary FAILS on
// pre-fix code (l3=14) and passes after (l3=18).
// ---------------------------------------------------------------------------

#[test]
fn nat64_l2_offset_canary() {
    // dst+src MAC, then the outer ethertype slot.
    let mut frame = vec![0u8; 14];
    frame[12] = 0x88;
    frame[13] = 0xa8; // 802.1ad
    frame.extend_from_slice(&0x0064u16.to_be_bytes()); // TCI VID 100
    frame.extend_from_slice(&0x86ddu16.to_be_bytes()); // inner ethertype
    frame.extend_from_slice(&[0u8; 64]); // body

    // Single 0x88a8 tag → l3 at 18, matching frame/inspect::frame_l3_offset.
    assert_eq!(frame_l3_offset(&frame), Some(18));

    // 0x8100 still maps to 18.
    frame[12] = 0x81;
    frame[13] = 0x00;
    assert_eq!(frame_l3_offset(&frame), Some(18));

    // Untagged (inner ethertype directly at 12..14) → l3 at 14.
    let untagged = {
        let mut f = vec![0u8; 14];
        f[12] = 0x86;
        f[13] = 0xdd;
        f.extend_from_slice(&[0u8; 64]);
        f
    };
    assert_eq!(frame_l3_offset(&untagged), Some(14));
}

#[test]
fn nat64_v4_to_v6_frame_reads_ip_at_offset_18_under_8021ad() {
    // End-to-end proof: a 0x88a8-tagged IPv4 frame fed to the reverse NAT64
    // builder reads the IPv4 header at offset 18 (not 14). Pre-fix the
    // builder offset the IP read into the VLAN tag and translate_v4_to_v6
    // would see a corrupted (version != 4) header.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let inner = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"x",
    );

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]); // dst
    frame.extend_from_slice(&[0xbb; 6]); // src
    frame.extend_from_slice(&0x88a8u16.to_be_bytes()); // 802.1ad TPID
    frame.extend_from_slice(&0x0064u16.to_be_bytes()); // TCI VID 100
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // inner: IPv4
    frame.extend_from_slice(&inner);

    let out = build_nat64_v4_to_v6_frame(
        &frame,
        src_v6,
        dst_v6,
        [0x11; 6],
        [0x22; 6],
        100, // emit a VLAN-tagged output
    )
    .expect("v4->v6 build must succeed for an 0x88a8-tagged input");

    // The output IPv6 header (after the rebuilt eth+vlan = 18 bytes) must be
    // a valid IPv6 header (version nibble 6), proving the inner IPv4 was read
    // from offset 18, not from inside the VLAN tag.
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
    assert_eq!(out[18] >> 4, 6, "translated payload must be a valid IPv6 header");
}

// ---------------------------------------------------------------------------
// #2211: the NAT64 transit translate path must NOT heap-allocate per packet.
// The old path allocated an intermediate L3 `Vec`, a pseudo-header `Vec` per
// checksum, and a second full output `Vec` — copying the L4 payload at least
// twice. The `write_*_into` cores now translate directly into a caller-provided
// buffer with the pseudo-header checksum STREAMED (no Vec). These tests assert:
//   1. zero heap allocations across many translations into a reused buffer; and
//   2. the `_into` output is BYTE-IDENTICAL to the legacy Vec translator, so
//      the optimization is on-the-wire equivalent (correctness preserved).
// ---------------------------------------------------------------------------

#[test]
fn write_v6_to_v4_into_writes_caller_buffer_without_realloc() {
    // #2211: the `_into` core translates straight into a caller-provided buffer.
    // Translating thousands of packets into ONE reused buffer must NOT
    // reallocate it: the buffer's backing pointer and capacity stay fixed,
    // proving the translator does not grow/replace the caller's allocation
    // (the same hot-path-discipline proof the WG scratch-buffer test uses).
    // It cannot internally `vec![]` an L3 packet either, because that
    // intermediate buffer no longer exists — translation writes header bytes,
    // the L4 payload (one copy), and a streamed checksum directly into `out`.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let ipv6_tcp = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello-nat64-payload");

    let mut out = vec![0u8; 2048];
    let initial_ptr = out.as_ptr();
    let initial_cap = out.capacity();
    let mut written = 0usize;
    for i in 0..4096 {
        let no_frag = i % 2 == 0;
        written = write_v6_to_v4_into(&mut out, &ipv6_tcp, snat_v4, dst_v4, no_frag)
            .expect("translate into reused buffer");
    }
    assert_eq!(written, 20 + 20 + b"hello-nat64-payload".len());
    assert_eq!(
        out.as_ptr(),
        initial_ptr,
        "v6->v4 translate-into must not reallocate the caller buffer (#2211)"
    );
    assert_eq!(
        out.capacity(),
        initial_cap,
        "v6->v4 translate-into must not change the caller buffer capacity (#2211)"
    );
}

#[test]
fn write_v4_to_v6_into_writes_caller_buffer_without_realloc() {
    // #2211 reverse-direction twin of the above.
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let ipv4_tcp = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"reverse-nat64-payload");

    let mut out = vec![0u8; 2048];
    let initial_ptr = out.as_ptr();
    let initial_cap = out.capacity();
    let mut written = 0usize;
    for _ in 0..4096 {
        written = write_v4_to_v6_into(&mut out, &ipv4_tcp, src_v6, dst_v6)
            .expect("translate into reused buffer");
    }
    assert_eq!(written, 40 + 20 + b"reverse-nat64-payload".len());
    assert_eq!(
        out.as_ptr(),
        initial_ptr,
        "v4->v6 translate-into must not reallocate the caller buffer (#2211)"
    );
    assert_eq!(
        out.capacity(),
        initial_cap,
        "v4->v6 translate-into must not change the caller buffer capacity (#2211)"
    );
}

// Source guard for the streamed pseudo-header checksum (#2211): the two
// `checksum16_*_pseudo` helpers must NOT build an intermediate `Vec` per call
// (the old code did, allocating 12+payload / 40+payload bytes on every L4
// checksum). The bodies are uniquely delimited, so a precise body scan FAILS if
// a future edit reintroduces a per-checksum buffer.
#[test]
fn pseudo_header_checksum_helpers_have_no_per_packet_vec() {
    let src = include_str!("nat64.rs");
    for fn_name in ["fn checksum16_ipv4_pseudo", "fn checksum16_ipv6_pseudo"] {
        let start = src.find(fn_name).unwrap_or_else(|| panic!("{fn_name} must exist"));
        // The body ends at the function's column-0 closing brace `\n}`. Each
        // helper is a short free function, so the FIRST `\n}` after the opener
        // is its terminator.
        let after = &src[start + fn_name.len()..];
        let body_end = after.find("\n}").unwrap_or(after.len());
        let body = &after[..body_end];
        for needle in ["vec![", "Vec::with_capacity", "Vec::new(", "extend_from_slice"] {
            assert!(
                !body.contains(needle),
                "{fn_name} must stream the checksum with NO per-packet {needle:?} (#2211)"
            );
        }
    }
}

#[test]
fn write_v6_to_v4_into_byte_identical_to_vec_translator() {
    // Differential: the allocation-free `_into` core must produce EXACTLY the
    // same L3 bytes as the legacy Vec translator across protocols, DF modes,
    // and traffic-class settings. (DF=0 draws a fresh Identification from the
    // process-global generator each call, so compare those two runs with the
    // Identification field masked out; everything else must match byte-for-byte
    // and the DF=1 runs match in full.)
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let cases: Vec<(Ipv6Addr, Vec<u8>, Ipv4Addr)> = vec![
        (
            "64:ff9b::c633:6432".parse().unwrap(),
            make_ipv6_tcp_packet(src_v6, "64:ff9b::c633:6432".parse().unwrap(), 12345, 80, b"abc"),
            Ipv4Addr::new(198, 51, 100, 50),
        ),
    ];
    for (_dst6, pkt, dst_v4) in cases {
        // DF=1 (atomic): full byte-identity, including Identification (=0).
        let mut buf = vec![0u8; 2048];
        let n = write_v6_to_v4_into(&mut buf, &pkt, snat_v4, dst_v4, false).expect("into");
        let vec_out = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("vec");
        assert_eq!(
            &buf[..n],
            vec_out.as_slice(),
            "DF=1 translate-into must be byte-identical to the Vec translator"
        );
        assert_eq!(checksum16(&vec_out[..20]), 0, "vec header checksum verifies");
        assert_eq!(checksum16(&buf[..20]), 0, "into header checksum verifies");

        // DF=0 (fragmentable): everything EXCEPT the Identification (bytes 4-5)
        // and the header checksum (bytes 10-11, which covers the ID) must match.
        let mut buf2 = vec![0u8; 2048];
        let n2 = write_v6_to_v4_into(&mut buf2, &pkt, snat_v4, dst_v4, true).expect("into df0");
        let vec_out2 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, true).expect("vec df0");
        assert_eq!(n2, vec_out2.len());
        // Mask Identification + header checksum before comparing.
        let mut a = buf2[..n2].to_vec();
        let mut b = vec_out2.clone();
        for p in [&mut a, &mut b] {
            p[4] = 0;
            p[5] = 0;
            p[10] = 0;
            p[11] = 0;
        }
        assert_eq!(
            a, b,
            "DF=0 translate-into must match the Vec translator outside the per-call ID"
        );
        // Both still carry a non-zero ID and a verifying header checksum.
        assert_ne!(u16::from_be_bytes([buf2[4], buf2[5]]), 0);
        assert_eq!(checksum16(&buf2[..20]), 0);
    }
}

#[test]
fn write_v4_to_v6_into_byte_identical_to_vec_translator() {
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    // Cover TCP, UDP-with-padding, and ICMP plus a non-zero traffic class.
    let mut tcp = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"world",
    );
    // Set a non-zero TOS and refresh the header checksum so the TC-copy path is
    // exercised in the differential.
    tcp[1] = (46u8 << 2) | 0b10;
    tcp[10..12].copy_from_slice(&[0, 0]);
    let s = checksum16(&tcp[..20]);
    tcp[10..12].copy_from_slice(&s.to_be_bytes());

    // A padded short reply (the #1641 trim path).
    let mut padded = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"",
    );
    padded.extend_from_slice(&[0u8; 8]); // simulate Ethernet padding

    for pkt in [tcp, padded] {
        let mut buf = vec![0u8; 2048];
        let n = write_v4_to_v6_into(&mut buf, &pkt, src_v6, dst_v6).expect("into");
        let vec_out = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("vec");
        assert_eq!(
            &buf[..n],
            vec_out.as_slice(),
            "translate-into must be byte-identical to the Vec translator"
        );
        // L4 checksum must verify over the trimmed payload in BOTH outputs.
        let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap());
        let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).unwrap());
        assert_eq!(
            checksum16_ipv6_pseudo(s6, d6, PROTO_TCP, &buf[40..n]),
            0,
            "translated L4 checksum must verify"
        );
    }
}

#[test]
fn streamed_pseudo_header_checksum_matches_contiguous_buffer() {
    // The pseudo-header checksum is now STREAMED (no per-packet Vec). Prove the
    // streamed result equals the historical "build a contiguous pseudo+payload
    // buffer then checksum16" computation, so no checksum drift was introduced.
    let src4 = Ipv4Addr::new(198, 51, 100, 7);
    let dst4 = Ipv4Addr::new(8, 8, 8, 8);
    let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    for payload_len in [0usize, 1, 7, 8, 15, 16, 40, 1500] {
        let payload: Vec<u8> = (0..payload_len).map(|i| ((i * 37 + 11) & 0xff) as u8).collect();

        // IPv4 reference: contiguous pseudo-header + payload.
        let mut buf4 = Vec::with_capacity(12 + payload.len());
        buf4.extend_from_slice(&src4.octets());
        buf4.extend_from_slice(&dst4.octets());
        buf4.push(0);
        buf4.push(PROTO_UDP);
        buf4.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf4.extend_from_slice(&payload);
        assert_eq!(
            checksum16_ipv4_pseudo(src4, dst4, PROTO_UDP, &payload),
            checksum16(&buf4),
            "streamed IPv4 pseudo-header checksum must match the contiguous buffer (len={payload_len})"
        );

        // IPv6 reference: contiguous pseudo-header + payload.
        let mut buf6 = Vec::with_capacity(40 + payload.len());
        buf6.extend_from_slice(&src6.octets());
        buf6.extend_from_slice(&dst6.octets());
        buf6.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf6.extend_from_slice(&[0, 0, 0, PROTO_TCP]);
        buf6.extend_from_slice(&payload);
        assert_eq!(
            checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &payload),
            checksum16(&buf6),
            "streamed IPv6 pseudo-header checksum must match the contiguous buffer (len={payload_len})"
        );
    }
}

// ---------------------------------------------------------------------------
// #2219: ICMP ERROR-message translation (Dest-Unreachable, Time-Exceeded,
// Packet-Too-Big <-> Fragmentation-Needed, Parameter-Problem) across NAT64.
//
// Pre-fix the ICMP type translators handled ONLY echo (128/129, 8/0) and
// returned None for every error type, which aborted the whole frame build
// (`?` on the translator) — so PMTUD and traceroute were blackholed. These
// tests are FAIL-ON-REVERT: each asserts the outer ICMP type/code/checksum AND
// the EMBEDDED translated IP header (addresses NAT64-mapped, lengths/checksums
// correct), with an independent oracle for both checksums. Reverting the fix
// (translators return None for errors) drops the packet -> `expect("translate")`
// panics, failing the test.
//
// ICMP error message layout: type(1) code(1) checksum(2) rest-of-header(4) then
// the quoted original packet (IP header + leading L4 bytes).
// ---------------------------------------------------------------------------

const PROTO_ICMP_C: u8 = 1;
const PROTO_ICMPV6_C: u8 = 58;

/// Build an IPv4 packet (header + given L4 bytes) with a valid header checksum.
/// Used to construct the embedded/quoted original packet inside an ICMP error.
fn build_v4_with_l4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, l4: &[u8]) -> Vec<u8> {
    let total = 20 + l4.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    p[8] = ttl;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let s = checksum16(&p[..20]);
    p[10..12].copy_from_slice(&s.to_be_bytes());
    p[20..].copy_from_slice(l4);
    p
}

/// Build an IPv6 packet (header + given L4 bytes).
fn build_v6_with_l4(src: Ipv6Addr, dst: Ipv6Addr, nh: u8, hl: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40 + l4.len()];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
    p[6] = nh;
    p[7] = hl;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40..].copy_from_slice(l4);
    p
}

/// Wrap a quoted packet as an ICMPv4 error message: type/code/rest + quote.
/// Computes a correct ICMPv4 checksum so the input is well-formed.
fn build_icmpv4_error(typ: u8, code: u8, rest: [u8; 4], quote: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; 8 + quote.len()];
    m[0] = typ;
    m[1] = code;
    m[4..8].copy_from_slice(&rest);
    m[8..].copy_from_slice(quote);
    let s = checksum16(&m);
    m[2..4].copy_from_slice(&s.to_be_bytes());
    m
}

/// Wrap a quoted packet as an ICMPv6 error message (checksum filled by caller
/// via the IPv6 pseudo-header).
fn build_icmpv6_error(typ: u8, code: u8, rest: [u8; 4], quote: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; 8 + quote.len()];
    m[0] = typ;
    m[1] = code;
    m[4..8].copy_from_slice(&rest);
    m[8..].copy_from_slice(quote);
    m
}

// === v4 -> v6 reverse direction (the PMTUD / traceroute return path) =========

#[test]
fn nat64_v4_to_v6_time_exceeded_translates_outer_and_embedded() {
    // Topology: v6 client 2001:db8::1 reached v4 server 192.0.2.5 via the WKP.
    // SNAT pool source 198.51.100.1. A v4 hop (203.0.113.9) returns ICMPv4
    // Time Exceeded quoting the original forward v4 packet
    // (198.51.100.1 -> 192.0.2.5). The reverse translation rewrites the outer
    // addresses from the session reverse-info (src_v6 = prefix::server,
    // dst_v6 = client).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap(); // prefix::192.0.2.5
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);

    // Embedded = original forward v4 packet, quoting IP header + 8 L4 bytes.
    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0xaa, 0xbb, 0xcc, 0xdd]; // src/dst ports + seq
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_TCP, 1, &inner_l4);
    let icmp = build_icmpv4_error(11, 0, [0, 0, 0, 0], &embedded);
    let v4_pkt = build_v4_with_l4(
        Ipv4Addr::new(203, 0, 113, 9),
        pool_v4,
        PROTO_ICMP_C,
        64,
        &icmp,
    );

    // Reverse builder args: src_v6 = orig_dst (prefix::server), dst_v6 = client.
    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6)
        .expect("ICMPv4 Time-Exceeded must translate, not drop");

    // Outer IPv6 header.
    assert_eq!(v6[6], PROTO_ICMPV6_C, "outer next-header must be ICMPv6");
    assert_eq!(&v6[8..24], &server_v6.octets(), "outer src = prefix::server");
    assert_eq!(&v6[24..40], &client_v6.octets(), "outer dst = client");
    // Outer ICMPv6 type/code: Time Exceeded (3), code preserved (0).
    assert_eq!(v6[40], 3, "ICMPv6 Time Exceeded type");
    assert_eq!(v6[41], 0, "code preserved");
    // Outer ICMPv6 checksum valid (independent oracle: pseudo-header sum == 0).
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]),
        0,
        "outer ICMPv6 checksum must verify"
    );

    // EMBEDDED translated IPv6 header begins at v6[48] (40 outer IP + 8 ICMP).
    let emb = &v6[48..];
    assert_eq!(emb[0] >> 4, 6, "embedded must be IPv6");
    assert_eq!(emb[6], PROTO_TCP, "embedded protocol preserved");
    // Embedded src (was pool_v4) -> original v6 client.
    assert_eq!(&emb[8..24], &client_v6.octets(), "embedded src = client");
    // Embedded dst (was server_v4) -> prefix::server.
    assert_eq!(&emb[24..40], &server_v6.octets(), "embedded dst = prefix::server");
    // Embedded TTL copied verbatim (NOT decremented — it's a quote).
    assert_eq!(emb[7], 1, "embedded hop limit copied verbatim");
    // Embedded quoted L4 bytes preserved.
    assert_eq!(&emb[40..48], &inner_l4, "embedded quoted L4 preserved");
    // Embedded payload length consistent.
    assert_eq!(
        u16::from_be_bytes([emb[4], emb[5]]) as usize,
        inner_l4.len(),
        "embedded payload length"
    );
}

#[test]
fn nat64_v4_to_v6_frag_needed_becomes_packet_too_big_with_mtu() {
    // ICMPv4 Dest-Unreachable / Fragmentation-Needed (3/4) carrying Next-Hop
    // MTU 1400 in bytes 6-7 -> ICMPv6 Packet-Too-Big (2/0) with MTU 1420
    // (1400 + 20, the NAT64 header delta), clamped to the v6 minimum (1280).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x11, 0x22, 0x33, 0x44];
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_TCP, 60, &inner_l4);
    // RFC 1191: Frag-Needed rest-of-header = [unused(2)][next-hop MTU(2)].
    let rest = [0u8, 0, (1400u16 >> 8) as u8, 1400u16 as u8];
    let icmp = build_icmpv4_error(3, 4, rest, &embedded);
    let v4_pkt = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6)
        .expect("ICMPv4 Frag-Needed must translate to Packet-Too-Big, not drop");

    assert_eq!(v6[40], 2, "ICMPv6 Packet Too Big type");
    assert_eq!(v6[41], 0, "PTB code 0");
    // MTU is the full 32-bit rest-of-header word (bytes 4-7 of the ICMPv6 msg).
    let mtu = u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]);
    assert_eq!(mtu, 1420, "PTB MTU must be v4 next-hop MTU + 20");
    // Checksum oracle.
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]), 0);

    // Embedded check: addresses mapped.
    let emb = &v6[48..];
    assert_eq!(&emb[8..24], &client_v6.octets(), "embedded src = client");
    assert_eq!(&emb[24..40], &server_v6.octets(), "embedded dst = prefix::server");
}

#[test]
fn nat64_v4_to_v6_frag_needed_mtu_clamped_to_v6_minimum() {
    // A tiny advertised v4 MTU (e.g. 1000) + 20 = 1020 < 1280; clamp to 1280
    // so the v6 client is never told to go below the IPv6 minimum link MTU.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);

    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_UDP, 60, &[0u8; 8]);
    let rest = [0u8, 0, (1000u16 >> 8) as u8, 1000u16 as u8];
    let icmp = build_icmpv4_error(3, 4, rest, &embedded);
    let v4_pkt = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6).expect("translate");
    let mtu = u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]);
    assert_eq!(mtu, 1280, "MTU must clamp to the IPv6 minimum link MTU");
}

#[test]
fn nat64_v4_to_v6_dest_unreachable_port_maps() {
    // ICMPv4 Dest-Unreachable / Port-Unreachable (3/3) -> ICMPv6
    // Dest-Unreachable / Port-Unreachable (1/4).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);

    let inner_l4 = [0x00u8, 0x35, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef];
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_UDP, 60, &inner_l4);
    let icmp = build_icmpv4_error(3, 3, [0, 0, 0, 0], &embedded);
    let v4_pkt = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6)
        .expect("ICMPv4 Port-Unreachable must translate, not drop");
    assert_eq!(v6[40], 1, "ICMPv6 Destination Unreachable type");
    assert_eq!(v6[41], 4, "ICMPv6 Port Unreachable code");
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]), 0);
    let emb = &v6[48..];
    assert_eq!(&emb[8..24], &client_v6.octets());
    assert_eq!(&emb[24..40], &server_v6.octets());
    assert_eq!(emb[6], PROTO_UDP, "embedded protocol preserved");
    assert_eq!(&emb[40..48], &inner_l4, "embedded quoted L4 preserved");
}

// === v6 -> v4 forward direction =============================================

#[test]
fn nat64_v6_to_v4_packet_too_big_becomes_frag_needed_with_mtu() {
    // ICMPv6 Packet-Too-Big (type 2) MTU 1500 -> ICMPv4 Dest-Unreachable /
    // Fragmentation-Needed (3/4), next-hop MTU 1480 (1500 - 20).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap(); // prefix::8.8.8.8
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Embedded = original v6 forward packet (client -> prefix::8.8.8.8).
    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04];
    let embedded = build_v6_with_l4(client_v6, dst_v6, PROTO_TCP, 1, &inner_l4);
    // ICMPv6 PTB rest-of-header = the 32-bit MTU.
    let icmp = build_icmpv6_error(2, 0, 1500u32.to_be_bytes(), &embedded);
    // Wrap as a v6 packet from a v6 hop back toward dst_v6 with valid checksum.
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    // Fix the outer ICMPv6 checksum for the input.
    let icmp_off = 40;
    v6_pkt[icmp_off + 2..icmp_off + 4].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[icmp_off..]);
    v6_pkt[icmp_off + 2..icmp_off + 4].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 Packet-Too-Big must translate to Frag-Needed, not drop");

    assert_eq!(v4[9], PROTO_ICMP_C, "outer protocol ICMPv4");
    assert_eq!(v4[20], 3, "ICMPv4 Destination Unreachable type");
    assert_eq!(v4[21], 4, "ICMPv4 Fragmentation Needed code");
    // Next-hop MTU in bytes 26-27 (ICMP rest-of-header word, low 16 bits).
    let mtu = u16::from_be_bytes([v4[26], v4[27]]);
    assert_eq!(mtu, 1480, "next-hop MTU = v6 MTU - 20");
    // Outer IPv4 + ICMPv4 checksums valid (oracle).
    assert_eq!(checksum16(&v4[..20]), 0, "outer IPv4 header checksum");
    assert_eq!(checksum16(&v4[20..]), 0, "outer ICMPv4 checksum");

    // EMBEDDED translated IPv4 header begins at v4[28] (20 IP + 8 ICMP).
    let emb = &v4[28..];
    assert_eq!(emb[0], 0x45, "embedded IPv4 header");
    assert_eq!(emb[9], PROTO_TCP, "embedded protocol preserved");
    // Embedded src (was client_v6) -> dst_v4 (the mapped embedded src).
    assert_eq!(&emb[12..16], &dst_v4.octets(), "embedded src mapped to dst_v4");
    // Embedded dst (was prefix::8.8.8.8) -> snat_v4 (mapped embedded dst).
    assert_eq!(&emb[16..20], &snat_v4.octets(), "embedded dst mapped to snat_v4");
    // Embedded IPv4 header checksum valid (oracle).
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum");
    assert_eq!(&emb[20..28], &inner_l4, "embedded quoted L4 preserved");
}

#[test]
fn nat64_v6_to_v4_time_exceeded_translates() {
    // ICMPv6 Time Exceeded (3) -> ICMPv4 Time Exceeded (11), code preserved.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x09, 0x08, 0x07, 0x06];
    let embedded = build_v6_with_l4(client_v6, dst_v6, PROTO_UDP, 1, &inner_l4);
    let icmp = build_icmpv6_error(3, 0, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 Time-Exceeded must translate, not drop");
    assert_eq!(v4[20], 11, "ICMPv4 Time Exceeded type");
    assert_eq!(v4[21], 0, "code preserved");
    assert_eq!(checksum16(&v4[..20]), 0);
    assert_eq!(checksum16(&v4[20..]), 0);
    let emb = &v4[28..];
    assert_eq!(&emb[12..16], &dst_v4.octets());
    assert_eq!(&emb[16..20], &snat_v4.octets());
    assert_eq!(checksum16(&emb[..20]), 0);
}

#[test]
fn nat64_v6_to_v4_dest_unreachable_admin_maps() {
    // ICMPv6 Dest-Unreachable / admin-prohibited (1/1) -> ICMPv4
    // Dest-Unreachable / comm-administratively-prohibited (3/10).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let embedded = build_v6_with_l4(client_v6, dst_v6, PROTO_TCP, 1, &[0u8; 8]);
    let icmp = build_icmpv6_error(1, 1, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 admin-prohibited must translate, not drop");
    assert_eq!(v4[20], 3, "ICMPv4 Destination Unreachable type");
    assert_eq!(v4[21], 10, "ICMPv4 comm admin prohibited code");
    assert_eq!(checksum16(&v4[20..]), 0);
}

// === regression: echo still works (no behavior change) ======================

#[test]
fn nat64_icmp_echo_unaffected_by_error_path() {
    // The echo path must remain byte-correct after the error-path refactor.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let mut icmp = vec![0u8; 8];
    icmp[0] = ICMPV6_ECHO_REQUEST;
    icmp[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    icmp[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
    let mut pkt = build_v6_with_l4(src_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    let s = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6_C, &pkt[40..]);
    pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("echo translate");
    assert_eq!(v4[20], ICMP_ECHO_REQUEST);
    assert_eq!(v4.len(), 20 + 8, "echo length unchanged");
    assert_eq!(checksum16(&v4[20..]), 0);
}

#[test]
fn nat64_truncated_icmp_error_header_dropped_not_panicked() {
    // A Packet-Too-Big / Frag-Needed message with a truncated rest-of-header
    // (< 8 ICMP bytes) must be dropped, never panic on an out-of-bounds index
    // of the attacker-controlled MTU word.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    // ICMPv6 PTB header truncated to 6 bytes (no full MTU word).
    let icmp = vec![2u8, 0, 0, 0, 0, 0];
    let mut pkt = build_v6_with_l4(src_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    let s = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6_C, &pkt[40..]);
    pkt[42..44].copy_from_slice(&s.to_be_bytes());
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "truncated ICMPv6 PTB must be dropped"
    );

    // ICMPv4 Frag-Needed header truncated to 6 bytes.
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let icmp4 = vec![3u8, 4, 0, 0, 0, 0]; // 6 bytes, no next-hop MTU word
    let mut p4 = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp4);
    let s4 = checksum16(&p4[20..]);
    p4[22..24].copy_from_slice(&s4.to_be_bytes());
    assert!(
        translate_v4_to_v6(&p4, server_v6, client_v6).is_none(),
        "truncated ICMPv4 Frag-Needed must be dropped"
    );
}

#[test]
fn nat64_unsupported_icmpv6_type_still_dropped() {
    // A link-local-only ICMPv6 type (e.g. Neighbor Solicitation 135) has no
    // IPv4 mapping and must still be dropped (None), not mistranslated.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let icmp = vec![135u8, 0, 0, 0, 0, 0, 0, 0]; // Neighbor Solicitation
    let mut pkt = build_v6_with_l4(src_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    let s = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6_C, &pkt[40..]);
    pkt[42..44].copy_from_slice(&s.to_be_bytes());
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "unmappable ICMPv6 type must be dropped"
    );
}

// ===========================================================================
// #2290: IPv6 extension-header walk in the v6->v4 translator.
//
// Pre-fix the translator read packet[6] as the L4 protocol and assumed L4 at
// byte 40, so any packet carrying a Hop-by-Hop / Routing / Dest-Opts / AH /
// Fragment header before its transport header was dropped as "unsupported
// protocol". These tests are FAIL-ON-REVERT: each builds a valid v6 packet
// with an extension header before TCP/UDP and asserts it TRANSLATES (not
// dropped). Reverting the fix (fixed offset 40 + raw next-header) reads the
// ext-header type as the L4 protocol -> `expect("translate")` panics.
// ===========================================================================

/// Build an IPv6 packet carrying ONE extension header (`ext_type`, given
/// option bytes) before the terminal L4 (`l4_proto`, `l4` bytes). The ext
/// header is `Type-Length-Optiondata` per RFC 8200: byte 0 = next-header
/// (the L4 proto), byte 1 = Hdr Ext Len in 8-octet units NOT counting the
/// first 8 octets. `ext_payload` is the option data AFTER the 2-byte
/// type/len; its length must make the ext header a multiple of 8 octets.
fn build_v6_with_ext_then_l4(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    ext_type: u8,
    ext_payload: &[u8],
    l4_proto: u8,
    hl: u8,
    l4: &[u8],
) -> Vec<u8> {
    // ext header = [next_header, hdr_ext_len, ext_payload...]
    let ext_len_bytes = 2 + ext_payload.len();
    assert_eq!(ext_len_bytes % 8, 0, "ext header must be a multiple of 8");
    let hdr_ext_len = (ext_len_bytes / 8 - 1) as u8;
    let mut p = vec![0u8; 40 + ext_len_bytes + l4.len()];
    p[0] = 0x60;
    // IPv6 payload_len covers ext header + L4.
    p[4..6].copy_from_slice(&((ext_len_bytes + l4.len()) as u16).to_be_bytes());
    p[6] = ext_type; // first next-header points at the ext header
    p[7] = hl;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    // Extension header.
    p[40] = l4_proto; // ext's next-header = terminal L4
    p[41] = hdr_ext_len;
    p[42..42 + ext_payload.len()].copy_from_slice(ext_payload);
    // L4.
    let l4_off = 40 + ext_len_bytes;
    p[l4_off..l4_off + l4.len()].copy_from_slice(l4);
    p
}

#[test]
fn ipv6_l4_offset_walks_dest_opts_then_tcp() {
    // Dest-Opts (60) 8 bytes, then TCP at offset 48.
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pkt = build_v6_with_ext_then_l4(src, dst, 60, &[0u8; 6], PROTO_TCP, 64, &[0u8; 20]);
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("walk must find L4");
    assert_eq!(off, 48, "TCP starts after the 8-byte Dest-Opts header");
    assert_eq!(proto, PROTO_TCP);
}

#[test]
fn ipv6_l4_offset_walks_hop_by_hop_then_udp() {
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pkt = build_v6_with_ext_then_l4(src, dst, 0, &[0u8; 6], PROTO_UDP, 64, &[0u8; 8]);
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("walk must find L4");
    assert_eq!(off, 48);
    assert_eq!(proto, PROTO_UDP);
}

#[test]
fn translate_v6_to_v4_tcp_behind_dest_opts() {
    // FAIL-ON-REVERT: a Dest-Opts header before TCP. Pre-fix this read
    // next_header=60 (Dest-Opts) as the protocol -> `_ => return None` drop.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    // Minimal TCP header (20 bytes) + 5-byte payload, ports 12345 -> 80.
    let mut tcp = vec![0u8; 25];
    tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    tcp[12] = 0x50; // data offset 5
    tcp[13] = 0x02; // SYN
    tcp[20..25].copy_from_slice(b"hello");

    let ipv6_pkt =
        build_v6_with_ext_then_l4(src_v6, dst_v6, 60, &[0u8; 6], PROTO_TCP, 64, &tcp);
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false)
        .expect("TCP behind Dest-Opts must translate, not drop");

    assert_eq!(v4[0], 0x45);
    assert_eq!(v4[9], PROTO_TCP, "protocol must be the terminal L4, not 60");
    assert_eq!(&v4[12..16], &snat_v4.octets());
    assert_eq!(&v4[16..20], &dst_v4.octets());
    // The ext header is stripped: IPv4 length = 20 + 25 (NOT 20 + 8 + 25).
    assert_eq!(v4.len(), 20 + 25, "Dest-Opts header stripped from output");
    // TCP ports preserved at the IPv4 L4 offset.
    assert_eq!(u16::from_be_bytes([v4[20], v4[21]]), 12345);
    assert_eq!(u16::from_be_bytes([v4[22], v4[23]]), 80);
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum valid");
}

#[test]
fn translate_v6_to_v4_udp_behind_hop_by_hop() {
    // FAIL-ON-REVERT: UDP behind a Hop-by-Hop (0) header.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let mut udp = vec![0u8; 8 + 4];
    udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(12u16).to_be_bytes()); // UDP length
    udp[8..12].copy_from_slice(b"data");

    let ipv6_pkt = build_v6_with_ext_then_l4(src_v6, dst_v6, 0, &[0u8; 6], PROTO_UDP, 64, &udp);
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false)
        .expect("UDP behind Hop-by-Hop must translate, not drop");

    assert_eq!(v4[9], PROTO_UDP, "protocol must be the terminal L4, not 0");
    assert_eq!(v4.len(), 20 + 12, "Hop-by-Hop header stripped");
    assert_eq!(u16::from_be_bytes([v4[20], v4[21]]), 5353);
    assert_eq!(u16::from_be_bytes([v4[22], v4[23]]), 53);
}

#[test]
fn translate_v6_to_v4_non_first_fragment_dropped() {
    // A non-first fragment carries no L4 header. The walker must NOT read its
    // payload bytes as a transport header — fail closed (drop).
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Fragment header (44), 8 bytes: next-header=TCP, frag-offset != 0.
    // bytes: [nh, reserved, frag_off_hi, frag_off_lo|flags, id(4)].
    // Set fragment offset to 0x0010 (>0) in the upper 13 bits.
    let mut frag = vec![0u8; 8 + 16]; // frag header + 16 "payload" bytes
    frag[0] = PROTO_TCP; // next-header
    frag[2..4].copy_from_slice(&0x0010u16.to_be_bytes()); // frag offset != 0
    let mut pkt = vec![0u8; 40 + frag.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(frag.len() as u16).to_be_bytes());
    pkt[6] = 44; // first next-header = Fragment
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..].copy_from_slice(&frag);

    assert!(
        ipv6_is_non_first_fragment(&pkt),
        "predicate must flag the non-first fragment"
    );
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "non-first fragment must be dropped, not translated from payload bytes"
    );
}

#[test]
fn translate_v6_to_v4_first_fragment_still_translates() {
    // A FIRST fragment (offset 0) carries the real L4 header and must still
    // translate — the non-first-fragment guard must not over-reject.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&1111u16.to_be_bytes());
    udp[2..4].copy_from_slice(&2222u16.to_be_bytes());
    udp[4..6].copy_from_slice(&8u16.to_be_bytes());

    // Fragment header with offset 0 (first fragment), MF can be set.
    let mut frag = vec![0u8; 8 + udp.len()];
    frag[0] = PROTO_UDP;
    frag[2..4].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0, MF=1
    frag[8..].copy_from_slice(&udp);
    let mut pkt = vec![0u8; 40 + frag.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(frag.len() as u16).to_be_bytes());
    pkt[6] = 44;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..].copy_from_slice(&frag);

    assert!(!ipv6_is_non_first_fragment(&pkt), "first fragment is not non-first");
    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false)
        .expect("first fragment must translate");
    assert_eq!(v4[9], PROTO_UDP);
    assert_eq!(u16::from_be_bytes([v4[20], v4[21]]), 1111);
}

#[test]
fn nat64_v6_to_v4_time_exceeded_quoting_ext_headered_tcp_translates() {
    // FAIL-ON-REVERT (#2290 embedded path): an ICMPv6 Time-Exceeded whose
    // quoted original packet carries a Dest-Opts header before TCP. Pre-fix
    // the embedded translator read quote[6]=60 as the protocol and dropped
    // the whole error -> PMTUD/traceroute blackhole. Now it walks the quoted
    // ext-header chain and translates the embedded packet.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Quoted original = v6 packet with Dest-Opts then 8 bytes of TCP.
    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x09, 0x08, 0x07, 0x06];
    let embedded =
        build_v6_with_ext_then_l4(client_v6, dst_v6, 60, &[0u8; 6], PROTO_TCP, 1, &inner_l4);
    let icmp = build_icmpv6_error(3, 0, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 error quoting ext-headered TCP must translate, not drop");
    assert_eq!(v4[20], 11, "outer ICMPv4 Time Exceeded type");
    assert_eq!(checksum16(&v4[..20]), 0);
    // Embedded translated IPv4 header starts at v4[28] (20 outer IP + 8 ICMP).
    let emb = &v4[28..];
    assert_eq!(emb[9], PROTO_TCP, "embedded protocol = TCP, ext header stripped");
    assert_eq!(&emb[12..16], &dst_v4.octets(), "embedded src mapped to dst_v4");
    assert_eq!(&emb[16..20], &snat_v4.octets(), "embedded dst mapped to snat_v4");
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum valid");
}

#[test]
fn nat64_v6_to_v4_ext_header_path_unaffects_plain_tcp() {
    // Regression: a PLAIN TCP packet (no ext header) must still translate
    // byte-identically after the walk was added — the walk returns offset 40
    // for a packet whose first next-header is already the L4.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("plain walk");
    assert_eq!(off, 40, "no ext header -> L4 at byte 40");
    assert_eq!(proto, PROTO_TCP);
    let v4 = translate_v6_to_v4(
        &pkt,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        false,
    )
    .expect("plain TCP translate");
    assert_eq!(v4.len(), 45, "plain TCP length unchanged (20 + 25)");
    assert_eq!(v4[9], PROTO_TCP);
}

// ===========================================================================
// #2291: fail-closed tri-state NAT64 lookup. A matched prefix with no usable
// source pool must drop, not fall through to IPv6 routing on the synthetic
// destination.
// ===========================================================================

#[test]
fn classify_no_prefix_match_continues_ipv6_routing() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap(); // not the NAT64 prefix
    assert_eq!(state.classify_ipv6_dest(dst), Nat64Match::NoPrefixMatch);
}

#[test]
fn classify_match_ready_when_pool_has_source() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // ::198.51.100.50
    match state.classify_ipv6_dest(dst) {
        Nat64Match::MatchReady {
            prefix_idx,
            dst_v4,
            snat_v4,
            dst_v6,
        } => {
            assert_eq!(prefix_idx, 0);
            assert_eq!(dst_v4, Ipv4Addr::new(198, 51, 100, 50));
            assert!(
                snat_v4 == Ipv4Addr::new(198, 51, 100, 1)
                    || snat_v4 == Ipv4Addr::new(198, 51, 100, 2),
                "snat from configured pool"
            );
            assert_eq!(dst_v6, dst);
        }
        other => panic!("expected MatchReady, got {other:?}"),
    }
}

#[test]
fn classify_match_unavailable_on_empty_pool_fails_closed() {
    // The exact #2291 wire state: a configured NAT64 prefix with an empty
    // (no-source) pool. The lookup MUST report MatchUnavailable so the caller
    // drops, NOT NoPrefixMatch (which would continue IPv6 routing on the
    // synthetic destination — the pre-fix fail-open).
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "no-pool".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![],
        no_v6_frag_header: false,
    }]);
    let dst: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();

    // Sanity: the prefix DOES match, and the source allocation DOES fail.
    assert!(state.match_ipv6_dest(dst).is_some(), "prefix must match");
    assert!(state.allocate_v4_source(0).is_none(), "empty pool yields no source");

    let result = state.classify_ipv6_dest(dst);
    assert_eq!(
        result,
        Nat64Match::MatchUnavailable,
        "empty-pool match must fail closed (drop), not fall through to IPv6 routing"
    );
    // Counter-factual: the pre-fix chain collapsed this to None ==
    // NoPrefixMatch, which the caller treats as "route as IPv6". Assert the
    // new result is NOT that fail-open value.
    assert_ne!(
        result,
        Nat64Match::NoPrefixMatch,
        "must NOT be treated as no-match (would IPv6-route the synthetic dest)"
    );
}
