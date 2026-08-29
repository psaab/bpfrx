// Tests for afxdp/bpf_map/ — relocated from inline
// `#[cfg(test)] mod tests` to keep bpf_map under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "../bpf_map_tests.rs"]` from bpf_map/mod.rs (#1356 split the
// flat bpf_map.rs into a directory; this file stays at the parent
// afxdp/ scope and is pulled back into the bpf_map namespace by the
// path attribute).

use super::*;
use crate::test_zone_ids::*;

fn local_delivery_decision(tunnel_endpoint_id: u16) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn synced_forward_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_TRUST_ZONE_ID,
        egress_zone: TEST_TRUST_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

#[test]
fn kernel_local_session_map_entry_requires_zero_tunnel_endpoint() {
    let metadata = synced_forward_metadata();
    assert!(uses_kernel_local_session_map_entry(
        local_delivery_decision(0),
        &metadata,
        SessionOrigin::SyncImport,
    ));
    assert!(!uses_kernel_local_session_map_entry(
        local_delivery_decision(7),
        &metadata,
        SessionOrigin::SyncImport,
    ));
}

#[test]
fn kernel_local_session_map_entry_rejects_non_kernel_local_cases() {
    let metadata = synced_forward_metadata();
    // Not local delivery → rejected
    assert!(!uses_kernel_local_session_map_entry(
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                ..local_delivery_decision(0).resolution
            },
            nat: NatDecision::default(),
        },
        &metadata,
        SessionOrigin::SyncImport,
    ));

    // Non-peer-synced origin → rejected
    assert!(!uses_kernel_local_session_map_entry(
        local_delivery_decision(0),
        &metadata,
        SessionOrigin::ForwardFlow,
    ));

    // Reverse session → rejected
    let mut reverse_metadata = synced_forward_metadata();
    reverse_metadata.is_reverse = true;
    assert!(!uses_kernel_local_session_map_entry(
        local_delivery_decision(0),
        &reverse_metadata,
        SessionOrigin::SyncImport,
    ));
}

#[test]
fn degraded_path_reason_names_cover_retained_shim_actions() {
    assert_eq!(DEGRADED_PATH_REASON_NAMES.len(), 16);
    assert_eq!(DEGRADED_PATH_REASON_NAMES[4], "heartbeat_missing");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[5], "heartbeat_stale");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[11], "interface_nat_no_session");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[13], "strict_drop");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[14], "pass_to_kernel");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[15], "transit_drop");
}

// --- #2332: monotonic HA-liveness freshness (Rust sibling of #1792) ---
//
// `heartbeat_fresh_mono` MUST decide worker liveness purely from two
// CLOCK_MONOTONIC nanosecond readings, never the wall clock. These tests
// pin that contract and FAIL if the function is reverted to a wall-clock
// (`Utc::now()` minus a `DateTime<Utc>`) comparison: the simulated
// forward clock step only changes the wall clock, so a wall-clock revert
// would flip `fresh` to false and fail `heartbeat_fresh_survives_*`.

// Derived from the production threshold so the tests can never drift from
// it if HEARTBEAT_STALE_AFTER ever changes (was a hard-coded 5_000_000_000).
const HB_STALE_NS: u64 = HEARTBEAT_STALE_AFTER.as_nanos() as u64;

#[test]
fn heartbeat_fresh_mono_recent_is_fresh() {
    // Worker stamped 1s of monotonic time ago, well under the 5s limit.
    let last = 100_000_000_000_u64;
    let now = last + 1_000_000_000; // +1s monotonic
    assert!(heartbeat_fresh_mono(last, now));
}

#[test]
fn heartbeat_fresh_mono_overdue_is_stale() {
    // Genuinely overdue: 6s of monotonic elapsed > 5s threshold → dead.
    let last = 100_000_000_000_u64;
    let now = last + 6_000_000_000; // +6s monotonic
    assert!(!heartbeat_fresh_mono(last, now));
}

#[test]
fn heartbeat_fresh_mono_exactly_at_limit_is_fresh() {
    // age == HEARTBEAT_STALE_AFTER is inclusive-fresh (`<=`).
    let last = 100_000_000_000_u64;
    let now = last + HB_STALE_NS;
    assert!(heartbeat_fresh_mono(last, now));
    // One nanosecond past the limit is stale.
    assert!(!heartbeat_fresh_mono(last, now + 1));
}

#[test]
fn heartbeat_fresh_mono_zero_sentinel_is_never_fresh() {
    // last_heartbeat_ns == 0 means "never stamped" → not fresh.
    assert!(!heartbeat_fresh_mono(0, 1_000_000_000));
    assert!(!heartbeat_fresh_mono(0, 0));
}

#[test]
fn heartbeat_fresh_survives_forward_wall_clock_step() {
    // FAIL-ON-REVERT: the worker's last heartbeat is monotonically recent
    // (1ms ago), but the wall clock has jumped FORWARD by 1 hour (NTP
    // makestep / VM resume) between the heartbeat stamp and this check.
    //
    // The monotonic decision below depends ONLY on the monotonic readings,
    // so the wall-clock step is invisible and the binding stays FRESH. A
    // wall-clock revert (Utc::now() - last_DateTime) would compute a ~1h
    // age, exceed the 5s limit, and return false — failing this test.
    let last_mono = 500_000_000_000_u64;
    let now_mono = last_mono + 1_000_000; // +1ms monotonic — clearly fresh

    // Build the wall-clock view the OLD code would have used: at heartbeat
    // time the wall clock was `t0`; by check time it stepped forward 1h.
    let t0 = chrono::Utc::now();
    let last_wall = t0; // worker-stamped wall instant (back-projected)
    let now_wall_after_step = t0 + chrono::TimeDelta::hours(1);
    let wall_age = now_wall_after_step.signed_duration_since(last_wall);
    // Sanity: the wall-clock age the old code saw really does exceed 5s.
    assert!(wall_age.to_std().unwrap() > std::time::Duration::from_secs(5));

    // The monotonic decision is unaffected by the wall-clock step.
    assert!(
        heartbeat_fresh_mono(last_mono, now_mono),
        "monotonic liveness must ignore a forward wall-clock step (#2332)"
    );
}

#[test]
fn heartbeat_fresh_backward_monotonic_anomaly_clamps_fresh() {
    // A backward CLOCK_MONOTONIC reading cannot happen on a well-behaved
    // kernel, but saturating_sub clamps it to a zero age (fail-safe:
    // treated as fresh, never spuriously dead).
    let last = 100_000_000_000_u64;
    let now = last - 1_000_000; // now < last
    assert!(heartbeat_fresh_mono(last, now));
}

#[test]
fn bpf_conntrack_struct_sizes_match_c() {
    // Must match C struct sizes from xpf_conntrack.h exactly.
    // The value structs grew 128->136 / 176->184 when `flags` widened from
    // __u8 to __u16 (#5460): the compiler pads the leading state/flags/
    // tcp_state/is_reverse block from 8 to 16 bytes. #4983 appended the
    // `ingress_ifindex` u32 (the session's TRUE ingress-binding identity),
    // growing them again 136->144 / 184->192: the u32 lands on the existing
    // 8-byte boundary and the compiler tail-pads 4 bytes to the struct's
    // 8-byte alignment. The Go on-map ABI mirror (bpfSessionValue /
    // bpfSessionValueV6, whose tail pad is DECLARED for the #6082 zero-copy
    // marshal path) is asserted to the same 144/192 in
    // pkg/dataplane/bpf_session_value_test.go.
    assert_eq!(core::mem::size_of::<BpfSessionKeyV4>(), 16);
    assert_eq!(core::mem::size_of::<BpfSessionValueV4>(), 144);
    assert_eq!(core::mem::size_of::<BpfSessionKeyV6>(), 40);
    assert_eq!(core::mem::size_of::<BpfSessionValueV6>(), 192);
}

// #5460: SESS_FLAG_NPTV6 is bit 8 (0x100 = 256), which does not fit the
// __u8 `session_value.flags` field it belonged to before this fix — setting it
// truncated to 0 (colliding with "no flags"). This is a counter-factual pin:
// it writes the NPTv6 bit into the flags field and reads it back. On the
// pre-fix u8 field `SESS_FLAG_NPTV6 as _` truncates to 0, so the read-back
// masks to 0 and the assertion FAILS; on the u16 field the bit survives.
#[test]
fn nptv6_session_flag_survives_roundtrip_v4() {
    const SESS_FLAG_NPTV6: u32 = 1 << 8; // 256
    let mut v: BpfSessionValueV4 = unsafe { core::mem::zeroed() };
    // `as _` casts 256 to whatever width `flags` is: u8 (pre-fix) => 0, u16 => 256.
    v.flags = SESS_FLAG_NPTV6 as _;
    // Round-trip through the exact bytes written to the BPF map.
    let bytes: [u8; core::mem::size_of::<BpfSessionValueV4>()] =
        unsafe { core::mem::transmute_copy(&v) };
    let back: BpfSessionValueV4 = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
    assert_ne!(
        u32::from(back.flags) & SESS_FLAG_NPTV6,
        0,
        "NPTv6 session flag (bit 8) lost -- session_value.flags too narrow for SESS_FLAG_NPTV6",
    );
}

#[test]
fn nptv6_session_flag_survives_roundtrip_v6() {
    const SESS_FLAG_NPTV6: u32 = 1 << 8; // 256
    let mut v: BpfSessionValueV6 = unsafe { core::mem::zeroed() };
    v.flags = SESS_FLAG_NPTV6 as _;
    let bytes: [u8; core::mem::size_of::<BpfSessionValueV6>()] =
        unsafe { core::mem::transmute_copy(&v) };
    let back: BpfSessionValueV6 = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
    assert_ne!(
        u32::from(back.flags) & SESS_FLAG_NPTV6,
        0,
        "NPTv6 session flag (bit 8) lost -- session_value_v6.flags too narrow for SESS_FLAG_NPTV6",
    );
}

#[test]
fn session_map_redirect_keys_for_forward_session_include_nat_aliases() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 14,
            tx_ifindex: 14,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };

    let keys = session_map_redirect_keys_for_session(
        &key,
        decision,
        &metadata,
        SessionOrigin::SharedPromote,
    );

    assert!(keys.contains(&key));
    assert!(keys.contains(&forward_wire_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_session_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_canonical_key(&key, decision.nat)));
}

#[test]
fn session_map_redirect_keys_for_kernel_local_synced_session_delete_superset() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 1,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 0,
        dst_port: 0,
            discriminator: Default::default(),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 14,
            egress_ifindex: 14,
            tx_ifindex: 14,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = synced_forward_metadata();

    let keys =
        session_map_redirect_keys_for_session(&key, decision, &metadata, SessionOrigin::SyncImport);

    assert_eq!(keys.len(), 4);
    assert!(keys.contains(&key));
    assert!(keys.contains(&forward_wire_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_session_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_canonical_key(&key, decision.nat)));
}

#[test]
fn bpf_conntrack_key_port_byte_order() {
    // BPF session_key uses __be16 ports (network byte order).
    // SessionKey stores ports in host order (u16::from_be_bytes in parsing).
    // publish_bpf_conntrack_entry must apply .to_be() to produce the correct
    // big-endian byte pattern in the packed struct.
    // #7743: this fixture used to build the struct literal INLINE, with its own
    // `.to_be()` calls. It therefore asserted only that `u16::to_be` works —
    // reverting the production encoding left it GREEN, because no production
    // code was on the path. It now calls the single-source builder every
    // publish/refresh/delete site uses, so dropping a `.to_be()` there REDS.
    let port: u16 = 80;
    let bpf_key = bpf_session_key_v4([10, 0, 1, 102], [10, 0, 2, 1], port, 443, 6);
    // The packed struct bytes at the port offsets must be big-endian:
    // port 80 = 0x0050 -> bytes [0x00, 0x50]
    // port 443 = 0x01BB -> bytes [0x01, 0xBB]
    let bytes: [u8; 16] = unsafe { core::mem::transmute(bpf_key) };
    assert_eq!(bytes[8], 0x00, "src_port high byte");
    assert_eq!(bytes[9], 0x50, "src_port low byte");
    assert_eq!(bytes[10], 0x01, "dst_port high byte");
    assert_eq!(bytes[11], 0xBB, "dst_port low byte");
}

// #5213 FAIL-ON-REVERT: the v4 conntrack mirror value must carry the STABLE
// dataplane session id resolved from the session table
// (`SessionEntry.session_id`, #4915) — NOT the `0` it hardcoded before.
// `show security flow session` reads this exact slot
// (`dataplane.SessionValue.SessionID`) and, when non-zero, renders it verbatim
// so the id matches the one RT_FLOW emits (SESSION_CREATE/CLOSE) for the same
// session. Reverting the builder to `session_id: 0` turns this RED (and the Go
// render then falls back to the per-iteration ordinal — the #5213 mismatch).
#[test]
fn build_conntrack_value_stamps_stable_session_id_v4() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
    };
    let decision = local_delivery_decision(0);
    let metadata = synced_forward_metadata();
    // worker 7 (high 16 bits) + per-worker counter 42 — a representative
    // #4915-namespaced id that is clearly not 0 or a small ordinal.
    const SID: u64 = (7u64 << 48) | 42;
    let value = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, SID,
    )
    .expect("a v4 session must map to a v4 conntrack value");
    assert_eq!(
        value.session_id, SID,
        "conntrack mirror must carry the stable session id, not 0"
    );
}

// #5213 FAIL-ON-REVERT: v6 sibling of the above — the v6 conntrack mirror value
// must likewise carry the stable session id.
#[test]
fn build_conntrack_value_stamps_stable_session_id_v6() {
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x102)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
    };
    let decision = local_delivery_decision(0);
    let metadata = synced_forward_metadata();
    const SID: u64 = (3u64 << 48) | 7;
    let value = publish_conntrack::build_conntrack_value_v6(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, SID,
    )
    .expect("a v6 session must map to a v6 conntrack value");
    assert_eq!(
        value.session_id, SID,
        "v6 conntrack mirror must carry the stable session id, not 0"
    );
}

// #5287 FAIL-ON-REVERT: `refresh_bpf_conntrack_last_seen` is an INCREMENTAL,
// budgeted slice — NOT a full-table pass. It must advance a persistent cursor
// by at most `budget` slab slots per call and resume across calls, so no single
// packet-loop tick walks the whole table (the old behaviour did tens of
// thousands of synchronous BPF syscalls between two RX/TX polls, spiking
// latency near the 131072-entry cap).
//
// With fd=-1 no BPF syscalls run, but the walk still advances the cursor, so
// the budget/continuation contract is observable directly: the first slice from
// the top returns a cursor advanced by EXACTLY the budget (it does not wrap to 0
// while the table still has unwalked slots), and draining a full cycle takes
// MORE THAN ONE slice. Reverting the refresh to the unbounded single-pass scan
// makes the first call walk the whole table and wrap to 0 -> the `== BUDGET`
// assertion reddens.
#[test]
fn refresh_bpf_conntrack_last_seen_is_budgeted_across_slices() {
    use crate::session::SessionTable;
    let mut table = SessionTable::new();
    const N: usize = 40;
    const BUDGET: usize = 8;
    assert!(N > BUDGET, "test only meaningful when the table exceeds one slice");

    let install_time = 1_000_000_000u64;
    for i in 0..N {
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 10_000 + i as u16, // distinct 5-tuples -> distinct forward entries
            dst_port: 443,
                    discriminator: Default::default(),
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let metadata = SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        };
        assert!(table.install_with_protocol(key, decision, metadata, install_time, 6, 0x10));
    }

    let policy = crate::policy::PolicyState::default();
    let now = install_time + 5_000_000_000;

    // First slice from the top: cursor advances by EXACTLY the budget and does
    // NOT wrap (the table still has N - BUDGET unwalked slots). fd=-1 => no BPF
    // I/O, but the cursor bookkeeping is exercised.
    let c1 = refresh_bpf_conntrack_last_seen(-1, -1, &table, &policy, now, 0, BUDGET);
    assert_eq!(
        c1, BUDGET,
        "first slice must be bounded to the budget, not a full single-pass scan"
    );

    // Draining a full cycle takes >1 slice; each returned cursor advances by at
    // most BUDGET until it wraps to 0.
    let mut cursor = c1;
    let mut slices = 1usize;
    for _ in 0..1024 {
        let next = refresh_bpf_conntrack_last_seen(-1, -1, &table, &policy, now, cursor, BUDGET);
        slices += 1;
        if next != 0 {
            assert!(
                next.saturating_sub(cursor) <= BUDGET,
                "slice advanced {} past budget {BUDGET}",
                next.saturating_sub(cursor),
            );
        }
        cursor = next;
        if cursor == 0 {
            break; // full-table cycle completed
        }
    }
    assert!(
        slices > 1,
        "full table must span more than one budgeted slice, got {slices}"
    );
}

// #4983 FAIL-ON-REVERT: the conntrack mirror value must carry the session's
// TRUE ingress-interface identity — `SessionMetadata::ingress_ifindex` plus
// `ingress_vlan_id`, the binding its first packet arrived on, stamped once at
// install. `show security flow session interface <name>` and the matching
// `clear` read exactly these two slots (Go `dataplane.SessionValue`
// .IngressIfindex/.IngressVlanID) and, when the ifindex is non-zero, resolve
// the one interface it names instead of asking "is <name> bound to the
// session's ingress ZONE?" — the approximation that made a session on
// interface X match a filter for every sibling interface Y of that zone.
// Reverting the builder to `ingress_ifindex: 0` turns this RED and the Go
// filter silently falls back to the zone answer for every session.
#[test]
fn build_conntrack_value_stamps_ingress_identity_v4_4983() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
    };
    let decision = local_delivery_decision(0);
    let mut metadata = synced_forward_metadata();
    // A plain kernel ifindex on a VLAN 80 trunk unit — the loss cluster's own
    // shape (reth0.80 over the physical WAN NIC), not a sentinel.
    metadata.ingress_ifindex = 24;
    metadata.ingress_vlan_id = 80;

    let value = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0,
    )
    .expect("a v4 session must map to a v4 conntrack value");

    assert_eq!(
        value.ingress_ifindex, 24,
        "the conntrack mirror must carry the session's recorded ingress ifindex, not 0 \
         (0 sends the Go filter back to the zone approximation, #4983)"
    );
    assert_eq!(
        value.ingress_vlan_id, 80,
        "the conntrack mirror must carry the ingress VLAN id: without it two units of \
         one trunk NIC alias onto the parent and the cross-interface match returns (#4983)"
    );
}

// #4983 v6 sibling — matchesV6 carries the identical filter arm, so the v6
// mirror must carry the identical identity.
#[test]
fn build_conntrack_value_stamps_ingress_identity_v6_4983() {
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x102)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
    };
    let decision = local_delivery_decision(0);
    let mut metadata = synced_forward_metadata();
    metadata.ingress_ifindex = 24;
    metadata.ingress_vlan_id = 80;

    let value = publish_conntrack::build_conntrack_value_v6(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0,
    )
    .expect("a v6 session must map to a v6 conntrack value");

    assert_eq!(
        value.ingress_ifindex, 24,
        "v6 mirror must carry the ingress ifindex (#4983)"
    );
    assert_eq!(
        value.ingress_vlan_id, 80,
        "v6 mirror must carry the ingress VLAN id (#4983)"
    );
}

// #4983 OVER-REACH GUARD: the ingress identity and the cached FIB EGRESS
// result are two different things occupying two different slots. A session
// with a recorded ingress must leave fib_ifindex/fib_vlan_id exactly as the
// pre-#4983 builder left them (0 — the helper does not populate the FIB cache
// here), so the CLI's egress arm keeps resolving from the FIB result and its
// zone fallback rather than from the ingress binding. This assertion stays
// GREEN with the ingress stamping reverted; it fails only if someone
// "implements" the ingress identity by reusing the egress slots.
#[test]
fn ingress_identity_does_not_occupy_the_fib_egress_slots_4983() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
    };
    let decision = local_delivery_decision(0);
    let mut metadata = synced_forward_metadata();
    metadata.ingress_ifindex = 24;
    metadata.ingress_vlan_id = 80;

    let value = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0,
    )
    .expect("a v4 session must map to a v4 conntrack value");

    assert_eq!(
        value.fib_ifindex, 0,
        "the ingress identity must not leak into the FIB EGRESS ifindex slot: the CLI \
         resolves the egress interface from it and would report the ingress one (#4983)"
    );
    assert_eq!(
        value.fib_vlan_id, 0,
        "the ingress VLAN must not leak into the FIB EGRESS vlan slot (#4983)"
    );
}

// #7743: the v6 twin of `bpf_conntrack_key_port_byte_order`. The v6 key is
// `#[repr(C, packed)]` and 40 bytes, so the ports sit at offsets 32..36 with no
// alignment padding before them.
#[test]
fn bpf_conntrack_key_v6_port_byte_order() {
    let src = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200);
    let dst = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 8);
    let bpf_key = bpf_session_key_v6(src.octets(), dst.octets(), 80, 443, 6);
    let bytes: [u8; 40] = unsafe { core::mem::transmute(bpf_key) };
    assert_eq!(bytes[32], 0x00, "src_port high byte");
    assert_eq!(bytes[33], 0x50, "src_port low byte");
    assert_eq!(bytes[34], 0x01, "dst_port high byte");
    assert_eq!(bytes[35], 0xBB, "dst_port low byte");
    assert_eq!(bytes[36], 6, "protocol");
    assert_eq!(&bytes[37..40], &[0, 0, 0], "pad must be zeroed");
}

// #7743 ANTI-DRIFT: the conntrack key encoding is single-sourced in
// `bpf_session_key_v4` / `bpf_session_key_v6` precisely because publish,
// refresh and delete must address the same map row byte-for-byte. A ninth
// hand-rolled literal would silently reintroduce the drift this consolidated,
// and it would not fail any behavioural test — publish and delete would simply
// stop matching, leaking the row. Scan the source for a struct literal that
// builds the key from `.octets()` outside the builders.
#[test]
fn conntrack_key_encoding_has_no_hand_rolled_copies() {
    let sources = [
        (
            "bpf_map/mod.rs",
            include_str!("bpf_map/mod.rs"),
        ),
        (
            "bpf_map/publish_conntrack.rs",
            include_str!("bpf_map/publish_conntrack.rs"),
        ),
    ];
    for (name, src) in sources {
        // Strip line comments so this test's own prose (and the builder doc
        // comments, which name the literal) cannot satisfy or trip the scan.
        let code: String = src
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        for family in ["BpfSessionKeyV4", "BpfSessionKeyV6"] {
            for (idx, _) in code.match_indices(&format!("{family} {{")) {
                let tail = &code[idx..];
                let end = tail.find('}').map_or(tail.len(), |e| e + 1);
                let body = &tail[..end];
                assert!(
                    !body.contains(".octets()"),
                    "{name}: hand-rolled {family} literal built from .octets() — \
                     use bpf_session_key_v4/v6 so publish, refresh and delete \
                     cannot drift apart (#7743). Offending block:\n{body}"
                );
            }
        }
    }
}
