// Tests for nptv6.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep nptv6.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "nptv6_tests.rs"]` from nptv6.rs.

use super::*;

#[test]
fn parse_prefix_48() {
    let (prefix, words) = parse_prefix("2001:db8:1::/48").unwrap();
    assert_eq!(words, 3);
    assert_eq!(prefix[0], 0x2001);
    assert_eq!(prefix[1], 0x0db8);
    assert_eq!(prefix[2], 0x0001);
    assert_eq!(prefix[3], 0);
}

#[test]
fn parse_prefix_64() {
    let (prefix, words) = parse_prefix("2001:db8:1:2::/64").unwrap();
    assert_eq!(words, 4);
    assert_eq!(prefix[0], 0x2001);
    assert_eq!(prefix[1], 0x0db8);
    assert_eq!(prefix[2], 0x0001);
    assert_eq!(prefix[3], 0x0002);
}

#[test]
fn parse_prefix_unsupported_length() {
    assert!(parse_prefix("2001:db8::/32").is_none());
    assert!(parse_prefix("2001:db8:1:2:3::/80").is_none());
    assert!(parse_prefix("2001:db8:1:2:3:4::/96").is_none());
}

#[test]
fn compute_adjustment_simple() {
    // Internal: fd00:1::/48, External: 2001:db8:1::/48
    let internal = [0xfd00, 0x0001, 0x0000, 0x0000];
    let external = [0x2001, 0x0db8, 0x0001, 0x0000];
    let adj = compute_adjustment(&internal, &external, 3);
    // Verify it's not zero (would be pathological)
    // The exact value depends on the prefix pair.
    // Key property: applying adjustment outbound then ~adjustment inbound
    // gives back the original address.
    assert_ne!(adj, 0);
}

#[test]
fn inbound_translation_48() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "test".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    }]);
    let mut dst: Ipv6Addr = "2001:db8:1:abcd::1".parse().unwrap();
    assert!(state.translate_inbound(&mut dst));
    // Prefix should be fd00:1::
    let words = ipv6_to_words(&dst);
    assert_eq!(words[0], 0xfd00);
    assert_eq!(words[1], 0x0001);
    assert_eq!(words[2], 0x0000);
    // word[3] is adjusted, rest preserved
    assert_eq!(words[4], 0);
    assert_eq!(words[5], 0);
    assert_eq!(words[6], 0);
    assert_eq!(words[7], 1);
}

#[test]
fn outbound_translation_48() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "test".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    }]);
    let mut src: Ipv6Addr = "fd00:1:0:abcd::1".parse().unwrap();
    assert!(state.translate_outbound(&mut src));
    let words = ipv6_to_words(&src);
    assert_eq!(words[0], 0x2001);
    assert_eq!(words[1], 0x0db8);
    assert_eq!(words[2], 0x0001);
    // word[3] adjusted
    assert_eq!(words[4], 0);
    assert_eq!(words[5], 0);
    assert_eq!(words[6], 0);
    assert_eq!(words[7], 1);
}

#[test]
fn round_trip_48() {
    // Translate outbound then inbound should produce the original address.
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "test".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    }]);
    let original: Ipv6Addr = "fd00:1:0:abcd::1".parse().unwrap();
    let mut addr = original;

    // Outbound: internal -> external
    assert!(state.translate_outbound(&mut addr));
    let words = ipv6_to_words(&addr);
    assert_eq!(words[0], 0x2001);
    assert_eq!(words[1], 0x0db8);
    assert_eq!(words[2], 0x0001);

    // Inbound: external -> internal
    assert!(state.translate_inbound(&mut addr));
    assert_eq!(
        addr, original,
        "round-trip should preserve original address"
    );
}

#[test]
fn round_trip_64() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "test64".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1:2:3::/64".to_string(),
        external_prefix: "2001:db8:1:2::/64".to_string(),
    }]);
    let original: Ipv6Addr = "fd00:1:2:3:abcd:ef01:2345:6789".parse().unwrap();
    let mut addr = original;

    assert!(state.translate_outbound(&mut addr));
    let words = ipv6_to_words(&addr);
    assert_eq!(words[0], 0x2001);
    assert_eq!(words[1], 0x0db8);
    assert_eq!(words[2], 0x0001);
    assert_eq!(words[3], 0x0002);

    assert!(state.translate_inbound(&mut addr));
    assert_eq!(
        addr, original,
        "round-trip should preserve original address"
    );
}

#[test]
fn checksum_neutrality() {
    // Verify that the ones-complement sum of all 8 words is the same
    // before and after translation.
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "csum".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd35:1940:27::/48".to_string(),
        external_prefix: "2602:fd41:70::/48".to_string(),
    }]);

    let original: Ipv6Addr = "fd35:1940:27:100::42".parse().unwrap();
    let orig_words = ipv6_to_words(&original);
    let orig_sum = ones_complement_sum(&orig_words);

    let mut translated = original;
    assert!(state.translate_outbound(&mut translated));
    let xlat_words = ipv6_to_words(&translated);
    let xlat_sum = ones_complement_sum(&xlat_words);

    assert_eq!(
        orig_sum, xlat_sum,
        "NPTv6 translation must be checksum-neutral: original sum=0x{:04x}, translated sum=0x{:04x}",
        orig_sum, xlat_sum
    );
}

#[test]
fn checksum_neutrality_64() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "csum64".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:aaaa:bbbb:cccc::/64".to_string(),
        external_prefix: "2001:db8:face:cafe::/64".to_string(),
    }]);

    let original: Ipv6Addr = "fd00:aaaa:bbbb:cccc:1234:5678:9abc:def0".parse().unwrap();
    let orig_words = ipv6_to_words(&original);
    let orig_sum = ones_complement_sum(&orig_words);

    let mut translated = original;
    assert!(state.translate_outbound(&mut translated));
    let xlat_words = ipv6_to_words(&translated);
    let xlat_sum = ones_complement_sum(&xlat_words);

    assert_eq!(orig_sum, xlat_sum);
}

#[test]
fn edge_case_0xffff_becomes_0x0000() {
    // Construct a scenario where the adjusted word would be 0xFFFF.
    // We need internal and external prefixes such that the adjustment,
    // when added to a specific word[3], yields 0xFFFF.
    //
    // Use two identical prefixes: adjustment = 0.
    // Then word[3] = 0xFFFF should become 0x0000 after outbound (add 0).
    // Wait - adjustment of 0 means word stays the same... Let's think more carefully.
    //
    // For identical prefixes: isum == esum, so adj = isum + ~esum = isum + ~isum = 0xFFFF.
    // That's the edge case! Adding 0xFFFF to any word w gives:
    //   w + 0xFFFF = w + (-0) in ones-complement = w (with carry fold).
    // So same-prefix NPTv6 is a no-op (identity), which makes sense.
    //
    // To get 0xFFFF result, we need word + adj = 0xFFFF (mod ones-complement).
    // For adj=1 and word=0xFFFE: sum = 0xFFFE + 1 = 0xFFFF -> mapped to 0x0000.
    //
    // Use prefixes that give adj=1:
    // isum - esum = 1 in ones-complement.
    // Internal: 0001:0000:0000::/48 -> isum = 1
    // External: 0000:0000:0000::/48 -> esum = 0
    // adj = 1 + ~0 = 1 + 0xFFFF = 0x10000 -> fold -> 1. Wait: 1 + 0xFFFF = 0x10000
    // fold: 0x0000 + 1 = 1. So adj = 1.
    //
    // But 0000::/48 is not a valid routable prefix. Let's just test programmatically.

    // Create rules where we know adjustment = 1
    let internal = [0x0001u16, 0x0000, 0x0000, 0x0000];
    let external = [0x0000u16, 0x0000, 0x0000, 0x0000];
    let adj = compute_adjustment(&internal, &external, 3);

    // Use that adjustment with word = 0xFFFE
    let result = adjust_word(0xFFFE, adj);
    // 0xFFFE + adj. If adj=1 => 0xFFFF -> 0x0000
    if adj == 1 {
        assert_eq!(result, 0x0000, "0xFFFF adjusted result must become 0x0000");
    }
    // The key invariant: result should never be 0xFFFF
    assert_ne!(result, 0xFFFF, "adjusted word must never be 0xFFFF");
}

#[test]
fn no_match_returns_false() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "test".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    }]);
    // Address that doesn't match either prefix.
    let mut addr: Ipv6Addr = "2001:db8:2:abcd::1".parse().unwrap();
    let original = addr;
    assert!(!state.translate_inbound(&mut addr));
    assert_eq!(addr, original, "non-matching address should be unchanged");

    let mut addr2: Ipv6Addr = "fd00:2:0:abcd::1".parse().unwrap();
    let original2 = addr2;
    assert!(!state.translate_outbound(&mut addr2));
    assert_eq!(addr2, original2);
}

#[test]
fn empty_state() {
    let state = Nptv6State::from_snapshots(&[]);
    assert!(state.is_empty());
    let mut addr: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    assert!(!state.translate_inbound(&mut addr));
    assert!(!state.translate_outbound(&mut addr));
}

#[test]
fn invalid_snapshot_skipped() {
    let state = Nptv6State::from_snapshots(&[
        Nptv6RuleSnapshot {
            name: "bad".to_string(),
            from_zone: String::new(),
            internal_prefix: "not-a-prefix".to_string(),
            external_prefix: "2001:db8:1::/48".to_string(),
        },
        Nptv6RuleSnapshot {
            name: "bad-len".to_string(),
            from_zone: String::new(),
            internal_prefix: "fd00:1::/48".to_string(),
            external_prefix: "2001:db8:1:2::/64".to_string(), // mismatched length
        },
        Nptv6RuleSnapshot {
            name: "good".to_string(),
            from_zone: String::new(),
            internal_prefix: "fd00:1::/48".to_string(),
            external_prefix: "2001:db8:1::/48".to_string(),
        },
    ]);
    // Only the good rule should be present.
    assert_eq!(state.inbound.len(), 1);
    assert_eq!(state.outbound.len(), 1);
}

#[test]
fn real_world_prefixes() {
    // Test with the prefixes from the existing BPF tests.
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "nptv6-test".to_string(),
        from_zone: "untrust".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);

    // Inbound: external dst -> internal dst
    let mut dst: Ipv6Addr = "2602:fd41:70:100::1".parse().unwrap();
    assert!(state.translate_inbound(&mut dst));
    let words = ipv6_to_words(&dst);
    assert_eq!(words[0], 0xfd35);
    assert_eq!(words[1], 0x1940);
    assert_eq!(words[2], 0x0027);

    // Round-trip
    let original_src: Ipv6Addr = "fd35:1940:27:200::42".parse().unwrap();
    let mut src = original_src;
    assert!(state.translate_outbound(&mut src));
    assert!(state.translate_inbound(&mut src));
    assert_eq!(src, original_src);
}

#[test]
fn multiple_addresses_same_prefix() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "test".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    }]);

    // Multiple addresses under the same prefix should all translate correctly.
    // Note: addresses with 0xFFFF in the adjustment word (word[3] for /48)
    // are special -- 0xFFFF maps to 0x0000 irreversibly per RFC 6296.
    // Avoid such addresses in round-trip tests.
    for addr_str in [
        "fd00:1:0:0::1",
        "fd00:1:0:0::2",
        "fd00:1:0:100::42",
        "fd00:1:0:abcd:ffff:ffff:ffff:ffff",
    ] {
        let original: Ipv6Addr = addr_str.parse().unwrap();
        let mut addr = original;
        assert!(state.translate_outbound(&mut addr));
        assert!(state.translate_inbound(&mut addr));
        assert_eq!(addr, original, "round-trip failed for {original}");
    }
}

/// Compute ones-complement sum of 8 words (for checksum neutrality test).
fn ones_complement_sum(words: &[u16; 8]) -> u16 {
    let mut sum: u32 = 0;
    for &w in words {
        sum += w as u32;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}
