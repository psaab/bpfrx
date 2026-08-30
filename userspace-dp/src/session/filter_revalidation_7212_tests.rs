// #7212: the per-entry static input-filter revalidation stamp
// (`SessionEntry::filter_revalidated_gen` + the `SessionTable` accessors).
//
// The stamp is what makes the revocation LAZY and per-tuple instead of a
// family-wide purge: a session whose verdict was already computed under the
// live config generation is not re-derived at all, and a session whose verdict
// predates it is re-derived exactly once. These cells pin the lifecycle; the
// verdict itself and the revocation are pinned in
// `afxdp/poll_descriptor/filter_revalidation_7212_tests.rs`.
//
// Loaded as a sibling submodule via `#[path]` from session/mod.rs.

use super::*;
use crate::test_zone_ids::*;
use std::net::Ipv4Addr;

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn metadata(is_reverse: bool) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
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
    }
}

fn install(table: &mut SessionTable, k: &SessionKey, is_reverse: bool) {
    assert!(table.install_with_protocol_with_origin(
        k.clone(),
        decision(),
        metadata(is_reverse),
        SessionOrigin::ForwardFlow,
        1_000,
        PROTO_TCP,
        0,
    ));
}

/// The ingress interfaces the cells below stamp against. Two of them, because
/// the stamp names the interface as well as the generation and a single-value
/// fixture cannot show that.
const IF_A: i32 = 24;
const IF_B: i32 = 25;

/// An INSTALL leaves the entry unvalidated, so its next packet derives a
/// verdict; `mark_filter_revalidated` is the only thing that clears that.
///
/// The install used to stamp the live generation, on the reasoning that the
/// forward session's first packet had just been adjudicated by the session-MISS
/// path. That is true of the forward entry and FALSE of the reverse companion
/// this same constructor builds, whose ingress is explicitly unobserved at
/// install (#4983) — a live stamp there claims a filter judged a direction no
/// filter has seen. Uniformly unvalidated costs one side-effect-free term walk
/// per direction, on an interface that has an input filter at all.
#[test]
fn install_leaves_the_entry_unvalidated_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(41);
    let k = key(49152);
    install(&mut table, &k, false);

    assert!(
        table.filter_revalidation_stale(&k, IF_A),
        "a fresh install carries no verdict, so its next packet must derive one"
    );
    table.mark_filter_revalidated(&k, IF_A);
    assert!(!table.filter_revalidation_stale(&k, IF_A));
}

/// A generation bump makes a revalidated session stale again. Without this the
/// stamp could be a one-shot "seen" bit and nothing would notice.
#[test]
fn a_generation_bump_makes_a_revalidated_session_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(41);
    let k = key(49152);
    install(&mut table, &k, false);
    table.mark_filter_revalidated(&k, IF_A);
    assert!(!table.filter_revalidation_stale(&k, IF_A));

    table.set_filter_revalidation_gen(42);
    assert!(
        table.filter_revalidation_stale(&k, IF_A),
        "a config generation bump must make the stamped verdict stale"
    );
}

/// An INGRESS change makes it stale too, at a FIXED generation.
///
/// The verdict is a function of the interface as well as the snapshot: the
/// filter that judged the session on A says nothing about B's filter. A
/// generation-only stamp reports the session already judged when a
/// same-direction packet arrives on B — asymmetric routing, a redundancy-group
/// member change — and B's deny is skipped. The generation is deliberately held
/// FIXED here so the only thing that can move the answer is the interface.
#[test]
fn an_ingress_change_makes_a_revalidated_session_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(41);
    let k = key(49152);
    install(&mut table, &k, false);
    table.mark_filter_revalidated(&k, IF_A);

    assert!(!table.filter_revalidation_stale(&k, IF_A));
    assert!(
        table.filter_revalidation_stale(&k, IF_B),
        "the same generation on a DIFFERENT ingress must be stale — that \
         interface's filter has not judged this session"
    );
}

/// `mark_filter_revalidated` clears the staleness, and clears it only for the
/// key it names. The second half is what keeps the revalidation per-tuple: a
/// re-stamp that touched more than its own entry would silently suppress the
/// revalidation of every other session on the interface.
#[test]
fn mark_filter_revalidated_clears_only_its_own_entry_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(2);
    let a = key(49152);
    let b = key(49153);
    install(&mut table, &a, false);
    install(&mut table, &b, false);

    table.mark_filter_revalidated(&a, IF_A);
    assert!(!table.filter_revalidation_stale(&a, IF_A));
    assert!(
        table.filter_revalidation_stale(&b, IF_A),
        "re-stamping one session must not re-stamp its neighbours"
    );
}

/// Forward and reverse are separate entries with separate stamps, which is what
/// gives each DIRECTION its own revalidation against the interface ITS packets
/// arrive on. A shared stamp would let the forward direction's re-derivation
/// suppress the reverse direction's — the reply would keep forwarding under a
/// filter that now denies it on the reply-side interface.
#[test]
fn forward_and_reverse_carry_independent_stamps_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(6);
    let fwd = key(49152);
    let mut rev = key(49152);
    std::mem::swap(&mut rev.src_ip, &mut rev.dst_ip);
    std::mem::swap(&mut rev.src_port, &mut rev.dst_port);
    install(&mut table, &fwd, false);
    install(&mut table, &rev, true);

    table.mark_filter_revalidated(&fwd, IF_A);
    assert!(!table.filter_revalidation_stale(&fwd, IF_A));
    assert!(
        table.filter_revalidation_stale(&rev, IF_B),
        "the reverse direction must revalidate on its own ingress interface"
    );
}

/// A peer-SYNCED import carries stamp `0`, which is never a live generation, so
/// the first packet the promoted session forwards revalidates against THIS
/// node's filter state. That is the #7212 failover fence: without it a standby
/// that imported a session before the commit would cold-serve, after a
/// promotion, a flow the primary had already revoked.
#[test]
fn peer_synced_import_is_always_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(9);
    let k = key(49152);
    assert!(table.upsert_synced(
        k.clone(),
        decision(),
        metadata(false),
        1_000,
        PROTO_TCP,
        0,
        true,
    ));
    assert!(
        table.filter_revalidation_stale(&k, IF_A),
        "an imported session carries no locally-derived verdict, so it must \
         revalidate before this node forwards on it"
    );
    // Not vacuous against "everything is stale": marking it clears it, so the
    // predicate is reading the stamp rather than returning a constant.
    table.mark_filter_revalidated(&k, IF_A);
    assert!(!table.filter_revalidation_stale(&k, IF_A));
}

/// A key with no entry answers "not stale". The caller would otherwise be sent
/// into a re-derivation whose re-stamp has nowhere to land, and would re-derive
/// (and possibly re-emit a reject reply for) the same phantom on every packet.
#[test]
fn an_absent_key_is_not_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(3);
    assert!(!table.filter_revalidation_stale(&key(49152), IF_A));
    // ...and re-stamping it is a no-op rather than a panic.
    table.mark_filter_revalidated(&key(49152), IF_A);
}

/// The generation `mark_filter_revalidated` writes is the one the worker
/// published, not a value the table invents. `set_filter_revalidation_gen` is
/// called once per poll pass with the SAME `ValidationState` the pass
/// classifies packets against; if the table drifted from it, a session could be
/// stamped with a generation its verdict was never derived under.
#[test]
fn the_published_generation_is_what_gets_stamped_7212() {
    let mut table = SessionTable::new();
    assert_eq!(table.filter_revalidation_gen(), 0);
    table.set_filter_revalidation_gen(77);
    assert_eq!(table.filter_revalidation_gen(), 77);
    let k = key(49152);
    install(&mut table, &k, false);
    table.mark_filter_revalidated(&k, IF_A);

    // Rewinding to the value the entry should carry proves it was stamped with
    // 77 specifically, not merely "some non-stale value".
    table.set_filter_revalidation_gen(78);
    assert!(table.filter_revalidation_stale(&k, IF_A));
    table.set_filter_revalidation_gen(77);
    assert!(!table.filter_revalidation_stale(&k, IF_A));
}
