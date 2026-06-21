//! #2151: truth-table tests for the shared TCP-flag constants and
//! predicates. These pin the on-wire bit values and assert each predicate
//! computes EXACTLY what the inline check it replaced computed, so the
//! consolidation is provably behavior-preserving.

use super::*;

#[test]
fn constants_match_wire_bit_values() {
    // RFC 9293 §3.1 control-bits octet (TCP header offset 13), low bit
    // first. These are load-bearing wire values — never change them.
    assert_eq!(TCP_FIN, 0x01);
    assert_eq!(TCP_SYN, 0x02);
    assert_eq!(TCP_RST, 0x04);
    assert_eq!(TCP_PSH, 0x08);
    assert_eq!(TCP_ACK, 0x10);
    assert_eq!(TCP_URG, 0x20);
    // The control mask is FIN | SYN | RST | ACK = 0x17.
    assert_eq!(TCP_FLAGS_CTRL_MASK, 0x17);
    assert_eq!(TCP_FLAGS_CTRL_MASK, TCP_FIN | TCP_SYN | TCP_RST | TCP_ACK);
}

#[test]
fn single_bit_predicates_match_inline_mask() {
    // For every possible flags byte, each single-bit predicate must equal
    // the raw `(flags & BIT) != 0` it replaced.
    for f in 0u8..=255 {
        assert_eq!(has_syn(f), (f & 0x02) != 0, "has_syn flags=0x{f:02x}");
        assert_eq!(has_ack(f), (f & 0x10) != 0, "has_ack flags=0x{f:02x}");
        assert_eq!(has_rst(f), (f & 0x04) != 0, "has_rst flags=0x{f:02x}");
        assert_eq!(has_fin(f), (f & 0x01) != 0, "has_fin flags=0x{f:02x}");
        assert_eq!(has_urg(f), (f & 0x20) != 0, "has_urg flags=0x{f:02x}");
        assert_eq!(has_psh(f), (f & 0x08) != 0, "has_psh flags=0x{f:02x}");
    }
}

#[test]
fn is_ack_only_matches_flow_cache_inline() {
    // flow_cache.rs admission was `(meta.tcp_flags & 0x17) == 0x10`.
    for f in 0u8..=255 {
        assert_eq!(
            is_ack_only(f),
            (f & 0x17) == 0x10,
            "is_ack_only flags=0x{f:02x}"
        );
    }
    // Spot checks: pure ACK and PSH-ACK qualify; SYN-ACK, RST-ACK,
    // FIN-ACK, and bare SYN do not.
    assert!(is_ack_only(TCP_ACK));
    assert!(is_ack_only(TCP_ACK | TCP_PSH));
    assert!(is_ack_only(TCP_ACK | TCP_URG));
    assert!(!is_ack_only(TCP_SYN | TCP_ACK));
    assert!(!is_ack_only(TCP_RST | TCP_ACK));
    assert!(!is_ack_only(TCP_FIN | TCP_ACK));
    assert!(!is_ack_only(TCP_SYN));
    assert!(!is_ack_only(0));
}

#[test]
fn is_initial_syn_matches_forwarding_inline() {
    // forwarding.rs cluster-return shortcut was
    // `(flags & SYN) != 0 && (flags & ACK) == 0`.
    for f in 0u8..=255 {
        assert_eq!(
            is_initial_syn(f),
            (f & 0x02) != 0 && (f & 0x10) == 0,
            "is_initial_syn flags=0x{f:02x}"
        );
    }
    assert!(is_initial_syn(TCP_SYN));
    assert!(is_initial_syn(TCP_SYN | TCP_PSH));
    assert!(!is_initial_syn(TCP_SYN | TCP_ACK));
    assert!(!is_initial_syn(TCP_ACK));
    assert!(!is_initial_syn(0));
}

#[test]
fn local_delivery_skip_predicate_matches_inline() {
    // forwarding.rs local-delivery caching skipped pure-ACK-without-SYN:
    // `(tcp_flags & ACK) != 0 && (tcp_flags & SYN) == 0`. Expressed at
    // the call site as `has_ack(f) && !has_syn(f)`.
    for f in 0u8..=255 {
        assert_eq!(
            has_ack(f) && !has_syn(f),
            (f & 0x10) != 0 && (f & 0x02) == 0,
            "ack-not-syn flags=0x{f:02x}"
        );
    }
}

#[test]
fn is_syn_ack_matches_rx_telemetry_inline() {
    // rx_telemetry.rs SYN+ACK detection was `(flags & 0x12) == 0x12`.
    for f in 0u8..=255 {
        assert_eq!(
            is_syn_ack(f),
            (f & 0x12) == 0x12,
            "is_syn_ack flags=0x{f:02x}"
        );
    }
    assert!(is_syn_ack(TCP_SYN | TCP_ACK));
    assert!(is_syn_ack(TCP_SYN | TCP_ACK | TCP_PSH));
    assert!(!is_syn_ack(TCP_SYN));
    assert!(!is_syn_ack(TCP_ACK));
}

#[test]
fn is_closing_matches_session_inline() {
    // session/conntrack closing test was `(tcp_flags & (FIN | RST)) != 0`.
    for f in 0u8..=255 {
        assert_eq!(
            is_closing(f),
            (f & (0x01 | 0x04)) != 0,
            "is_closing flags=0x{f:02x}"
        );
    }
    assert!(is_closing(TCP_FIN));
    assert!(is_closing(TCP_RST));
    assert!(is_closing(TCP_FIN | TCP_RST));
    assert!(is_closing(TCP_FIN | TCP_ACK));
    assert!(!is_closing(TCP_SYN));
    assert!(!is_closing(TCP_ACK));
    assert!(!is_closing(0));
}
