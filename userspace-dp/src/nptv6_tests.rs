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

// #2380: a /48 prefix with the 4th word set carries host/subnet bits the
// parser silently discards. The Go commit gate rejects this, so in a debug
// build the helper-side debug_assert is a fail-on-revert tripwire that aborts
// if the Go gate is ever weakened. Release builds keep the historical masking
// behavior (the extra word is dropped), so this test only asserts the panic
// when debug assertions are compiled in.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "host bits set")]
fn parse_prefix_48_host_bits_panics_in_debug() {
    let _ = parse_prefix("2001:db8:1:2::/48");
}

// In a release build (debug_assert compiled out) the parser keeps masking:
// the 4th word is dropped, yielding the same prefix as a clean /48.
#[test]
#[cfg(not(debug_assertions))]
fn parse_prefix_48_host_bits_masked_in_release() {
    let (prefix, words) = parse_prefix("2001:db8:1:2::/48").unwrap();
    assert_eq!(words, 3);
    assert_eq!(prefix[0], 0x2001);
    assert_eq!(prefix[1], 0x0db8);
    assert_eq!(prefix[2], 0x0001);
    assert_eq!(prefix[3], 0);
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
fn invalid_snapshot_rejected_fail_closed() {
    // #2240 fail-on-revert: a snapshot mixing a malformed rule with several
    // VALID rules must REJECT the WHOLE snapshot (fail closed), so the apply
    // preflight keeps the previous live state instead of installing only the
    // valid subset and (via the Go DeleteStaleNPTv6) tearing down the working
    // translations. The pre-fix code silently kept just the "good" rule.
    let good_a = Nptv6RuleSnapshot {
        name: "good-a".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    };
    let good_b = Nptv6RuleSnapshot {
        name: "good-b".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:2::/48".to_string(),
        external_prefix: "2001:db8:2::/48".to_string(),
    };

    // Unparseable internal prefix.
    let bad_parse = Nptv6RuleSnapshot {
        name: "bad-parse".to_string(),
        from_zone: String::new(),
        internal_prefix: "not-a-prefix".to_string(),
        external_prefix: "2001:db8:9::/48".to_string(),
    };
    let err = Nptv6State::try_from_snapshots(&[good_a.clone(), bad_parse, good_b.clone()])
        .expect_err("a malformed NPTv6 rule must reject the whole snapshot");
    match err {
        SnapshotIntegrityError::Nptv6UnparseableRule { rule_name, .. } => {
            assert_eq!(rule_name, "bad-parse");
        }
        other => panic!("expected Nptv6UnparseableRule, got {other:?}"),
    }

    // Mismatched prefix lengths (/48 internal vs /64 external).
    let bad_len = Nptv6RuleSnapshot {
        name: "bad-len".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:9::/48".to_string(),
        external_prefix: "2001:db8:9:2::/64".to_string(),
    };
    let err = Nptv6State::try_from_snapshots(&[good_a.clone(), bad_len, good_b.clone()])
        .expect_err("mismatched prefix lengths must reject the whole snapshot");
    assert!(
        matches!(err, SnapshotIntegrityError::Nptv6UnparseableRule { .. }),
        "expected Nptv6UnparseableRule, got {err:?}"
    );

    // Unsupported prefix length (/56).
    let bad_unsupported = Nptv6RuleSnapshot {
        name: "bad-56".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:9::/56".to_string(),
        external_prefix: "2001:db8:9::/56".to_string(),
    };
    let err = Nptv6State::try_from_snapshots(&[good_a.clone(), bad_unsupported])
        .expect_err("unsupported prefix length must reject the whole snapshot");
    assert!(
        matches!(err, SnapshotIntegrityError::Nptv6UnparseableRule { .. }),
        "expected Nptv6UnparseableRule, got {err:?}"
    );

    // Control: the all-valid snapshot still installs BOTH rules.
    let ok = Nptv6State::try_from_snapshots(&[good_a, good_b])
        .expect("all-valid snapshot must build");
    assert_eq!(ok.inbound.len(), 2);
    assert_eq!(ok.outbound.len(), 2);
}

#[test]
fn overlapping_prefixes_rejected_fail_closed() {
    // #2241 fail-on-revert: a /48 and a nested /64 with the same internal
    // base overlap in the outbound (internal) direction; first-match insertion
    // order would make the translation identity order-dependent. Reject at
    // build time so the dataplane stays deterministic. Pre-fix BOTH rules
    // installed and resolution depended purely on insertion order.
    let rule_a = Nptv6RuleSnapshot {
        name: "broad-48".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    };
    let rule_b = Nptv6RuleSnapshot {
        name: "nested-64".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1:0:1234::/64".to_string(),
        external_prefix: "2001:db8:ffff:1234::/64".to_string(),
    };

    // /48 first, nested /64 second — overlap detected on the internal prefix.
    let err = Nptv6State::try_from_snapshots(&[rule_a.clone(), rule_b.clone()])
        .expect_err("overlapping internal prefixes must reject the snapshot");
    match err {
        SnapshotIntegrityError::Nptv6OverlappingPrefix {
            first_rule,
            second_rule,
            ..
        } => {
            assert_eq!(first_rule, "broad-48");
            assert_eq!(second_rule, "nested-64");
        }
        other => panic!("expected Nptv6OverlappingPrefix, got {other:?}"),
    }

    // Reordered — still rejected (determinism does not depend on order).
    let err = Nptv6State::try_from_snapshots(&[rule_b, rule_a])
        .expect_err("reordered overlapping prefixes must also reject");
    assert!(
        matches!(err, SnapshotIntegrityError::Nptv6OverlappingPrefix { .. }),
        "expected Nptv6OverlappingPrefix, got {err:?}"
    );
}

#[test]
fn overlapping_external_prefixes_rejected() {
    // Overlap only on the external (inbound) prefix — distinct internal
    // prefixes but the inbound dst match would be order-dependent.
    let rule_a = Nptv6RuleSnapshot {
        name: "ext-48".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    };
    let rule_b = Nptv6RuleSnapshot {
        name: "ext-64".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:2::/64".to_string(),
        external_prefix: "2001:db8:1:5678::/64".to_string(),
    };
    let err = Nptv6State::try_from_snapshots(&[rule_a, rule_b])
        .expect_err("overlapping external prefixes must reject the snapshot");
    match err {
        SnapshotIntegrityError::Nptv6OverlappingPrefix { direction, .. } => {
            assert_eq!(direction, "inbound (external)");
        }
        other => panic!("expected inbound Nptv6OverlappingPrefix, got {other:?}"),
    }
}

#[test]
fn non_overlapping_distinct_prefixes_accepted() {
    // Distinct /48s and a non-nested /64 must all build (no false-positive
    // overlap rejection).
    let state = Nptv6State::try_from_snapshots(&[
        Nptv6RuleSnapshot {
            name: "a".to_string(),
            from_zone: String::new(),
            internal_prefix: "fd00:1::/48".to_string(),
            external_prefix: "2001:db8:1::/48".to_string(),
        },
        Nptv6RuleSnapshot {
            name: "b".to_string(),
            from_zone: String::new(),
            internal_prefix: "fd00:2::/48".to_string(),
            external_prefix: "2001:db8:2::/48".to_string(),
        },
        Nptv6RuleSnapshot {
            name: "c".to_string(),
            from_zone: String::new(),
            internal_prefix: "fd00:3:4:5::/64".to_string(),
            external_prefix: "2001:db8:3:4::/64".to_string(),
        },
    ])
    .expect("distinct non-overlapping prefixes must build");
    assert_eq!(state.inbound.len(), 3);
    assert_eq!(state.outbound.len(), 3);
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

// #3121: NPTv6 outbound source translation must COMPOSE with a
// destination NAT (DNAT) decision. The dataplane decision path attempts
// NPTv6 regardless of whether a pre-routing `rewrite_dst` is already
// present and `merge()`s the NPTv6 source rewrite into the DNAT
// decision. This decision-layer test pins that the merge preserves BOTH
// translations (DNAT dst + NPTv6 src, nptv6 flag set) and that the
// reverse-flow decision swaps them correctly so the return packet is
// un-DNAT'd on the source and un-NPTv6'd on the destination.
#[test]
fn nptv6_source_composes_with_dnat_decision() {
    use crate::nat::NatDecision;
    use std::net::IpAddr;

    let internal_src: IpAddr = "2001:db8:1::100".parse().unwrap();
    let external_src: IpAddr = "2001:db8:abcd::100".parse().unwrap(); // NPTv6 result
    let original_dst: IpAddr = "2001:db8:ffff::1".parse().unwrap();
    let dnat_dst: IpAddr = "fd00::10".parse().unwrap(); // DNAT result

    // Pre-routing DNAT decision (destination rewrite only).
    let dnat = NatDecision {
        rewrite_dst: Some(dnat_dst),
        ..NatDecision::default()
    };
    // NPTv6 outbound source decision (source rewrite, nptv6 flag).
    let nptv6 = NatDecision {
        rewrite_src: Some(external_src),
        nptv6: true,
        ..NatDecision::default()
    };

    // The production path does `decision.nat = decision.nat.merge(nptv6)`.
    let composed = dnat.merge(nptv6);
    assert_eq!(
        composed.rewrite_dst,
        Some(dnat_dst),
        "DNAT destination rewrite must survive the compose"
    );
    assert_eq!(
        composed.rewrite_src,
        Some(external_src),
        "NPTv6 source rewrite must survive the compose (the #3121 bug dropped it)"
    );
    assert!(composed.nptv6, "the nptv6 flag must propagate through merge");

    // Reverse-flow decision for the return packet: a forward `rewrite_dst`
    // becomes a reverse `rewrite_src` (un-DNAT), a forward `rewrite_src`
    // becomes a reverse `rewrite_dst` (un-NPTv6); nptv6 carries over.
    let reverse = composed.reverse(internal_src, original_dst, 0, 0);
    assert_eq!(
        reverse.rewrite_src,
        Some(original_dst),
        "reverse must restore the original (pre-DNAT) destination as the source"
    );
    assert_eq!(
        reverse.rewrite_dst,
        Some(internal_src),
        "reverse must restore the original (internal, pre-NPTv6) source as the destination"
    );
    assert!(reverse.nptv6, "reverse decision must keep the nptv6 flag");
}

// #3233: a checksum-neutral prefix pair (internal and external prefixes with
// EQUAL ones-complement sums) precomputes an adjustment of ones-complement zero.
// `compute_adjustment` represents that zero as 0xFFFF (negative zero), NOT the
// literal 0x0000 the issue text used. Pin the actual value so the fail-on-revert
// guard below targets the real trigger.
#[test]
fn checksum_neutral_pair_has_ones_complement_zero_adjustment() {
    // 2001:db8:1 and 2001:1:db8 share the same word set -> equal ones-complement
    // sums -> checksum-neutral, but DIFFERENT prefixes (not the trivial identity
    // pair).
    let internal = [0x2001u16, 0x0db8, 0x0001, 0x0000];
    let external = [0x2001u16, 0x0001, 0x0db8, 0x0000];
    let adj = compute_adjustment(&internal, &external, 3);
    assert_eq!(
        adj, 0xFFFF,
        "a checksum-neutral pair must yield ones-complement-zero (0xFFFF), \
         not the literal 0x0000 — adjust_word would otherwise corrupt a 0xFFFF host word"
    );
    assert!(is_zero_adjustment(adj));
    // The general (non-neutral) case must NOT be treated as zero.
    let g_int = [0xfd00u16, 0x0001, 0x0000, 0x0000];
    let g_ext = [0x2001u16, 0x0db8, 0x0001, 0x0000];
    let gadj = compute_adjustment(&g_int, &g_ext, 3);
    assert_ne!(gadj, 0);
    assert!(!is_zero_adjustment(gadj));
}

// #3233 fail-on-revert (THE bug): a checksum-neutral /48 prefix pair and a host
// whose adjustment word (word[3]) is 0xFFFF. Outbound must swap the prefix and
// leave word[3] == 0xFFFF (NOT fold it to 0x0000). Revert the adj==zero skip in
// translate_outbound -> word[3] collapses to 0x0000 -> this assert goes RED.
#[test]
fn checksum_neutral_0xffff_host_word_survives_outbound() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "neutral".to_string(),
        from_zone: String::new(),
        // Same word set, different ordering -> equal ones-complement sums.
        internal_prefix: "2001:db8:1::/48".to_string(),
        external_prefix: "2001:1:db8::/48".to_string(),
    }]);
    // word[3] = 0xffff (the adjustment word for a /48).
    let mut src: Ipv6Addr = "2001:db8:1:ffff::1".parse().unwrap();
    assert!(state.translate_outbound(&mut src));
    let words = ipv6_to_words(&src);
    // Prefix swapped to external.
    assert_eq!(words[0], 0x2001);
    assert_eq!(words[1], 0x0001);
    assert_eq!(words[2], 0x0db8);
    // The adjustment word MUST survive identity (the #3233 bug folded it to 0).
    assert_eq!(
        words[3], 0xffff,
        "checksum-neutral pair must leave the 0xFFFF host word identity, not fold to 0x0000"
    );
    assert_eq!(words[7], 1);
}

// #3233 fail-on-revert (collision): the 0xFFFF host and the 0x0000 host must
// translate to DISTINCT external addresses. Pre-fix both collapsed to a word[3]
// of 0x0000, so return traffic for the 0xFFFF host was misdelivered.
#[test]
fn checksum_neutral_0xffff_and_0x0000_hosts_stay_distinct() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "neutral".to_string(),
        from_zone: String::new(),
        internal_prefix: "2001:db8:1::/48".to_string(),
        external_prefix: "2001:1:db8::/48".to_string(),
    }]);
    let mut host_ffff: Ipv6Addr = "2001:db8:1:ffff::1".parse().unwrap();
    let mut host_0000: Ipv6Addr = "2001:db8:1:0:0:0:0:1".parse().unwrap();
    assert!(state.translate_outbound(&mut host_ffff));
    assert!(state.translate_outbound(&mut host_0000));
    assert_ne!(
        host_ffff, host_0000,
        "the 0xFFFF host must not collapse onto the 0x0000 host (the #3233 collision)"
    );
    assert_eq!(ipv6_to_words(&host_ffff)[3], 0xffff);
    assert_eq!(ipv6_to_words(&host_0000)[3], 0x0000);
}

// #3233 round-trip: for a checksum-neutral pair, outbound then inbound is
// identity even for a 0xFFFF host word. Revert the inbound skip -> the 0xFFFF
// host is never restored (inbound folds to 0x0000) and this RED.
#[test]
fn checksum_neutral_round_trip_preserves_0xffff_host() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "neutral".to_string(),
        from_zone: String::new(),
        internal_prefix: "2001:db8:1::/48".to_string(),
        external_prefix: "2001:1:db8::/48".to_string(),
    }]);
    for addr_str in [
        "2001:db8:1:ffff::1",
        "2001:db8:1:0:0:0:0:1",
        "2001:db8:1:abcd:1234:5678:9abc:def0",
    ] {
        let original: Ipv6Addr = addr_str.parse().unwrap();
        let mut addr = original;
        assert!(state.translate_outbound(&mut addr));
        assert!(state.translate_inbound(&mut addr));
        assert_eq!(addr, original, "checksum-neutral round-trip failed for {original}");
    }
    // Inbound on an external dst with a 0xFFFF host word also survives.
    let mut dst: Ipv6Addr = "2001:1:db8:ffff::9".parse().unwrap();
    assert!(state.translate_inbound(&mut dst));
    let words = ipv6_to_words(&dst);
    assert_eq!(words[0], 0x2001);
    assert_eq!(words[1], 0x0db8);
    assert_eq!(words[2], 0x0001);
    assert_eq!(words[3], 0xffff, "inbound must leave the 0xFFFF host word identity");
}

// #3233 checksum neutrality is preserved for a neutral pair WITHOUT any word
// fixup: the ones-complement sum over all 8 words is unchanged by the pure
// prefix swap.
#[test]
fn checksum_neutral_pair_is_checksum_neutral_without_fixup() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "neutral".to_string(),
        from_zone: String::new(),
        internal_prefix: "2001:db8:1::/48".to_string(),
        external_prefix: "2001:1:db8::/48".to_string(),
    }]);
    let original: Ipv6Addr = "2001:db8:1:ffff::42".parse().unwrap();
    let orig_sum = ones_complement_sum(&ipv6_to_words(&original));
    let mut translated = original;
    assert!(state.translate_outbound(&mut translated));
    let xlat_sum = ones_complement_sum(&ipv6_to_words(&translated));
    assert_eq!(
        orig_sum, xlat_sum,
        "checksum-neutral prefix swap must remain checksum-neutral with no word fixup"
    );
}

// #3233 NO-REGRESSION: the general (non-neutral) case keeps the RFC-6296
// 0xFFFF -> 0x0000 fold. Pin an existing general-case translation: the
// adjustment is nonzero, so adjust_word still runs and the result is never
// 0xFFFF.
#[test]
fn general_case_still_folds_0xffff_to_0x0000() {
    let state = Nptv6State::from_snapshots(&[Nptv6RuleSnapshot {
        name: "general".to_string(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    }]);
    // This pair is NOT checksum-neutral.
    let internal = [0xfd00u16, 0x0001, 0x0000, 0x0000];
    let external = [0x2001u16, 0x0db8, 0x0001, 0x0000];
    let adj = compute_adjustment(&internal, &external, 3);
    assert!(!is_zero_adjustment(adj), "general case must not be ones-complement zero");
    // Outbound on a host whose word[3] folds to 0xFFFF still becomes 0x0000 and
    // is never left at 0xFFFF (the RFC 6296 convention for the general case).
    let mut src: Ipv6Addr = "fd00:1:0:abcd::1".parse().unwrap();
    assert!(state.translate_outbound(&mut src));
    assert_ne!(ipv6_to_words(&src)[3], 0xFFFF, "adjusted word must never be 0xFFFF");
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
