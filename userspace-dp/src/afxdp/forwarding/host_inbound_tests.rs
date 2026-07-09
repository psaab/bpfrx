use super::*;

// #3405: a CONFIGURED zone with an EMPTY admission set (the on-wire shape of a
// security zone that declared no `host-inbound-traffic` stanza — the Go
// control plane now marks every zone host_inbound_configured) must
// default-DENY every host-bound service/protocol, while the global
// ICMP/ND/PMTUD accept still admits error/PMTUD control. This pins the
// load-bearing Rust half of the #3405 default-deny: `Some(empty) => deny`,
// NOT the pre-#3405 admit. Fail-on-revert: change the `Some(hi)` arm of
// host_inbound_admits to admit when the set is empty (or special-case an
// empty zone back to admit) and the SSH assertion below flips RED.
#[test]
fn empty_configured_zone_default_denies() {
    const TCP: u8 = 6;
    const ZONE: u16 = 7;

    let mut state = ForwardingState::default();
    // A configured zone with NO tokens = the no-stanza / empty-stanza shape.
    state
        .zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&[], &[]));

    // SSH (tcp/22) to the host on this zone is DENIED — the zone opened
    // nothing. (Pre-#3405 a no-stanza zone was absent from the table and this
    // returned admit via `None => true`.)
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 22, false, 0),
        "empty configured zone must deny ssh (tcp/22) — #3405 default-deny",
    );
    // HTTPS (tcp/443) and an arbitrary UDP service are likewise denied.
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 443, false, 0),
        "empty configured zone must deny https (tcp/443)",
    );
    assert!(
        !host_inbound_admits(&state, ZONE, 17, 53, true, 0),
        "empty configured zone must deny udp/53 on v6",
    );

    // The global ICMP error/PMTUD accept (#3171) still fires: v4
    // destination-unreachable (type 3) and v6 packet-too-big (type 2) reach
    // the host even on a default-deny zone, so PMTUD is never black-holed.
    assert!(
        host_inbound_admits(&state, ZONE, 1, 0, false, 3),
        "ICMPv4 destination-unreachable must stay globally admitted",
    );
    assert!(
        host_inbound_admits(&state, ZONE, 58, 0, true, 2),
        "ICMPv6 packet-too-big (PMTUD) must stay globally admitted",
    );

    // A genuinely unknown / global ingress zone (id not in the table) keeps
    // the admit default — #3405 is scoped to configured zones only.
    assert!(
        host_inbound_admits(&state, 999, TCP, 22, false, 0),
        "unknown/global zone (absent from table) keeps the admit default",
    );
}

// #3310: `system-services ident-reset` must NOT admit TCP/113 on the AF_XDP
// secondary path — Junos ident-reset resets ident probes, it does not permit
// the service. The kernel nft chain emits the actual `reject with tcp reset`
// (primary path); this classifier just stops admitting 113 so the rare
// AF_XDP-reached ident packet (DNAT/static-NAT-to-113) is dropped. Co-declared
// services on the SAME zone (ssh/http) must still admit (no over-removal), and
// UDP/113 (not ident) is likewise not admitted. Fail-on-revert: restore
// `hi.tcp_ports.insert(113)` in the ident-reset classifier arm and the
// tcp/113-denied assertion flips RED.
#[test]
fn ident_reset_does_not_admit_113() {
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const ZONE: u16 = 11;

    let mut state = ForwardingState::default();
    // A zone that declares ident-reset ALONGSIDE ssh + http (so the test
    // proves ident-reset removes ONLY 113, not the co-declared services —
    // ssh/http admit only from their own classifier arms).
    state.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(
            &[
                "ident-reset".to_string(),
                "ssh".to_string(),
                "http".to_string(),
            ],
            &[],
        ),
    );

    // TCP/113 is NOT admitted (dropped on the secondary path), v4 and v6.
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 113, false, 0),
        "ident-reset must NOT admit TCP/113 on v4 (#3310) — it resets, not permits",
    );
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 113, true, 0),
        "ident-reset must NOT admit TCP/113 on v6 (#3310)",
    );
    // UDP/113 (not ident) is not admitted either.
    assert!(
        !host_inbound_admits(&state, ZONE, UDP, 113, false, 0),
        "UDP/113 must not be admitted (ident is TCP-only)",
    );
    // The co-declared services on the same zone still admit (no over-removal).
    assert!(
        host_inbound_admits(&state, ZONE, TCP, 22, false, 0),
        "co-declared ssh (tcp/22) must still admit",
    );
    assert!(
        host_inbound_admits(&state, ZONE, TCP, 80, false, 0),
        "co-declared http (tcp/80) must still admit",
    );
}

// #3311: the `protocols all` expansion must EXCLUDE every L2/non-IP protocol
// (IS-IS) — they cannot produce an IP host-inbound admit and are handled by
// FRR over L2. This guards the SSOT-driven exclusion
// (routing_protocol_all_expansion = KNOWN_ROUTING_PROTOCOL_TOKENS minus
// HOST_INBOUND_L2_PROTOCOLS), the load-bearing job of the L2 set on this
// surface. Fail-on-revert: remove "isis" from HOST_INBOUND_L2_PROTOCOLS and
// isis (still in KNOWN_ROUTING_PROTOCOL_TOKENS) reappears in the expansion,
// turning the exclusion assertion RED. Mirrors the Go
// TestHostInboundProtocolsAllExcludesL2.
#[test]
fn protocols_all_excludes_l2() {
    let expansion: Vec<&str> = routing_protocol_all_expansion().collect();

    // Every L2 protocol is excluded from the IP `all` expansion.
    for l2 in HOST_INBOUND_L2_PROTOCOLS {
        assert!(
            !expansion.contains(l2),
            "L2 protocol {l2:?} must be excluded from the `protocols all` IP expansion",
        );
    }
    // IS-IS specifically: a recognized routing token that is nonetheless
    // kept out of the expansion BECAUSE it is in the L2 set.
    assert!(
        KNOWN_ROUTING_PROTOCOL_TOKENS.contains(&"isis"),
        "isis must be a recognized routing token (so the exclusion is meaningful)",
    );
    assert!(
        !expansion.contains(&"isis"),
        "isis (L2) must not appear in the `protocols all` IP expansion",
    );
    // Sanity: real IP routing protocols still expand.
    for p in ["ospf", "ospf3", "bgp", "bfd", "router-discovery"] {
        assert!(
            expansion.contains(&p),
            "IP routing protocol {p:?} must remain in the `protocols all` expansion",
        );
    }
}

// #3362: the per-interface host-inbound OVERRIDE keys the admit check by
// ingress ifindex. An interface with an override is matched against ITS
// effective set; an interface without one falls back to the from-zone set.
// Fail-on-revert: make host_inbound_admits_iface ignore ifindex_host_inbound
// (i.e. always defer to the zone) and the override-scoped assertions flip.
#[test]
fn per_interface_override_keys_by_ifindex() {
    const TCP: u8 = 6;
    const IFINDEX_UPLINK: i32 = 100; // ssh override
    const IFINDEX_OTHER: i32 = 200; // no override (zone fallback)
    const ZONE: u16 = 5; // zone-keyed set = ping only

    let mut state = ForwardingState::default();
    // Zone-level set: ping (ICMP echo) only — NO ssh.
    state.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(&["ping".to_string()], &[]),
    );
    // Per-interface override on the uplink: ssh only.
    state.ifindex_host_inbound.insert(
        IFINDEX_UPLINK,
        zone_host_inbound_from_tokens(&["ssh".to_string()], &[]),
    );

    // Uplink (override present): admits ssh, denies https, and does NOT
    // inherit the zone's ping (the override REPLACES the zone set on this
    // interface — its set is the Go-side effective union).
    assert!(
        host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, TCP, 22, false, 0),
        "uplink override must admit ssh (tcp/22)",
    );
    assert!(
        !host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, TCP, 443, false, 0),
        "uplink override (ssh only) must deny https (tcp/443)",
    );

    // Other interface (no override): falls back to the zone set — denies ssh,
    // admits the zone's ping echo-request (icmp v4 type 8).
    assert!(
        !host_inbound_admits_iface(&state, IFINDEX_OTHER, ZONE, TCP, 22, false, 0),
        "non-overridden interface must fall back to the zone set (no ssh)",
    );
    assert!(
        host_inbound_admits_iface(&state, IFINDEX_OTHER, ZONE, 1, 0, false, 8),
        "non-overridden interface must inherit the zone's ping admit",
    );

    // Global ICMP error/PMTUD accept (#3171) still applies on the override
    // path: destination-unreachable (v4 type 3) is admitted even though the
    // override set is ssh-only.
    assert!(
        host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, 1, 0, false, 3),
        "ICMP error/PMTUD must stay globally admitted on the override path",
    );
}

// #3311: a zone with `protocols all` must NOT admit IS-IS as an IP protocol
// (proto 124, integrated IS-IS-over-IP), proving the L2 exclusion holds end
// to end through classify_protocol. It must still admit a real expanded IP
// protocol (OSPF, proto 89). Fail-on-revert: remove isis from
// HOST_INBOUND_L2_PROTOCOLS — isis enters the expansion, but its
// classify_protocol arm is a no-op, so this stays green; the
// protocols_all_excludes_l2 token test above is the real RED-on-revert guard.
// #3341: the routing-control tokens rsvp/pgm/sap/dvmrp must each classify to
// the correct IP admit with the correct family scoping, mirroring the nft
// matcher (hostInboundProtocolMatches) and the Go SSOT. Fail-on-revert:
// before #3341 these hit the catch-all `_ => {}` no-op arm, so every admit
// assertion below goes RED.
#[test]
fn routing_control_protocol_tokens_classify() {
    // rsvp — IP proto 46, dual-family.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("rsvp", &mut hi);
    assert!(hi.admits(46, 0, false, 0), "rsvp must admit proto 46 on v4");
    assert!(
        hi.admits(46, 0, true, 0),
        "rsvp must admit proto 46 on v6 (dual)"
    );

    // pgm — IP proto 113, dual-family.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("pgm", &mut hi);
    assert!(
        hi.admits(113, 0, false, 0),
        "pgm must admit proto 113 on v4"
    );
    assert!(
        hi.admits(113, 0, true, 0),
        "pgm must admit proto 113 on v6 (dual)"
    );

    // sap — UDP/9875, dual-family.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("sap", &mut hi);
    assert!(
        hi.admits(17, 9875, false, 0),
        "sap must admit udp/9875 on v4"
    );
    assert!(
        hi.admits(17, 9875, true, 0),
        "sap must admit udp/9875 on v6 (dual)"
    );

    // dvmrp — IGMP-encapsulated (proto 2), IPv4-only.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("dvmrp", &mut hi);
    assert!(
        hi.admits(2, 0, false, 0),
        "dvmrp must admit proto 2 (IGMP) on v4"
    );
    assert!(
        !hi.admits(2, 0, true, 0),
        "dvmrp must NOT admit proto 2 on v6 (IPv4-only)",
    );

    // All four are recognized routing tokens (so `protocols all` covers them)
    // and none are L2.
    for tok in ["rsvp", "pgm", "sap", "dvmrp"] {
        assert!(
            KNOWN_ROUTING_PROTOCOL_TOKENS.contains(&tok),
            "{tok} must be a recognized routing token",
        );
        assert!(
            !is_host_inbound_l2_protocol(tok),
            "{tok} rides IP, must not be an L2 protocol",
        );
    }
}

#[test]
fn protocols_all_admits_ip_routing_not_l2() {
    let mut hi = ZoneHostInbound::default();
    classify_protocol("all", &mut hi);
    // OSPFv2 (proto 89) admitted on v4 via the expansion.
    assert!(
        hi.admits(89, 0, false, 0),
        "`protocols all` must admit OSPF (proto 89) on v4",
    );
    // Integrated IS-IS-over-IP (proto 124) is NOT admitted — isis is L2.
    assert!(
        !hi.admits(124, 0, false, 0),
        "`protocols all` must not admit IS-IS (proto 124) — L2/OSI, handled by FRR",
    );
}
