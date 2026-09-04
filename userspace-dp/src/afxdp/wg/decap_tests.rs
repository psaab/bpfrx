//! #8274 step 3: the worker-side WireGuard decap stage, driven end to end on a
//! REAL authenticated record.
//!
//! The defect these cells exist for is not subtle and not narrow: an
//! authenticated peer's inner plaintext was written straight to the `wgN` TUN
//! for the kernel to route, with no zone lookup, no session, no policy and no
//! counter between `try_decap` and the write. A peer's `allowed-ips` is a
//! cryptographic check on the inner SOURCE address — no destination, no zone
//! pair, no application, no direction — so it is not a security policy and it
//! was the only thing in the path.
//!
//! WHAT THE LOAD-BEARING ASSERTION IS, and why it is the zone rather than the
//! absence of a TUN write. A cell asserting "the plaintext no longer reaches
//! the TUN" would pass for a stage that dropped the packet on the floor, and it
//! would pass for one that adjudicated the inner packet under the UNDERLAY's
//! zone — which is the #7167 invariant-2 failure and would silently give inner
//! traffic the WAN's policy. So the assertion is that the decapsulated meta
//! carries the TUNNEL's logical ifindex and the zone that ifindex maps to.

use super::super::test_fixtures::wg_outer_mtu_snapshot;
use crate::test_zone_ids::TEST_SFMIX_ZONE_ID;
use super::super::*;
use super::super::tests_support::{txn_ha_state, txn_run_descriptor};
use super::tests::established_pair;
use super::{WgEngine, WgWorkerScratch};

const TUNNEL_LOGICAL_IFINDEX: i32 = 400;
const WG_PORT: u16 = 51820;
/// The fixture's tunnel source — the outer DESTINATION of an inbound record.
const XPF_OUTER: [u8; 4] = [172, 16, 80, 8];
/// The fixture's configured peer endpoint — the outer SOURCE.
const PEER_OUTER: [u8; 4] = [203, 0, 113, 7];
const PEER_SPORT: u16 = 51820;

/// An inner IPv4 packet (UDP) from `src` to `dst`, the plaintext the peer sends.
fn inner_v4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&1111u16.to_be_bytes());
    p[22..24].copy_from_slice(&2222u16.to_be_bytes());
    p[24..26].copy_from_slice(&8u16.to_be_bytes());
    p
}

/// Wrap `record` in Ethernet + IPv4 + UDP, as it arrives on the underlay.
fn outer_frame(record: &[u8], dst_port: u16) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 20 + 8 + record.len()];
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[14] = 0x45;
    let ip_total = (20 + 8 + record.len()) as u16;
    f[16..18].copy_from_slice(&ip_total.to_be_bytes());
    f[22] = 64;
    f[23] = PROTO_UDP;
    f[26..30].copy_from_slice(&PEER_OUTER);
    f[30..34].copy_from_slice(&XPF_OUTER);
    f[34..36].copy_from_slice(&PEER_SPORT.to_be_bytes());
    f[36..38].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + record.len()) as u16;
    f[38..40].copy_from_slice(&udp_len.to_be_bytes());
    f[42..].copy_from_slice(record);
    f
}

fn outer_meta(frame_len: usize) -> UserspaceDpMeta {
    UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame_len as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        // #7167 invariant 5: the stage MUST inherit these from the RX meta.
        // Distinctive values so a cell can prove they were carried rather than
        // defaulted.
        config_generation: 0x5150_4646,
        fib_generation: 0x0BAD_F00D,
        rx_queue_index: 3,
        ..UserspaceDpMeta::default()
    }
}

/// Build the fixture forwarding state with `resp` installed as the live engine
/// for the WireGuard tunnel endpoint, and return it with that endpoint's id.
fn forwarding_with_engine(resp: WgEngine) -> (ForwardingState, u16) {
    let mut forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
    let id = *forwarding
        .wg_engines
        .keys()
        .next()
        .expect("the fixture configures a WireGuard tunnel");
    // Replace the fixture's engine (whose keys nothing holds) with one that has
    // a live session, so the decap below is a REAL AEAD open and not a stub.
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    (forwarding, id)
}

/// Sum of every decap outcome counter the engine keeps. A record the stage
/// declines on its OWN gate must leave all of them untouched; a record it
/// hands to `try_decap` moves exactly one, whichever way `try_decap` rules.
/// That difference is the only observable distinction between "the worker
/// refused to claim this" and "the worker claimed it and the crypto said no",
/// and without it a cell asserting only `is_none()` stays green when the
/// stage's type gate is deleted (the mutation that escaped on first run).
fn decap_outcomes_observed(engine: &WgEngine) -> u64 {
    let c = engine.counters();
    [
        &c.decap_keepalives,
        &c.decap_drops_malformed_header,
        &c.decap_drops_unknown_session,
        &c.decap_drops_counter_ceiling,
        &c.decap_drops_crypto,
        &c.decap_drops_replay,
        &c.decap_drops_allowed_ips,
        &c.decap_drops_malformed_inner,
        &c.decap_drops_buffer,
        &c.decap_drops_expired,
    ]
    .iter()
    .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
    .sum()
}

/// The whole point of #8274: an authenticated transport-data record is
/// decapsulated in the WORKER and its inner packet is presented for
/// adjudication under the TUNNEL's zone.
#[test]
fn worker_decap_presents_inner_under_the_tunnel_zone_8274() {
    let inner_src = [10, 123, 0, 5];
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);

    let inner = inner_v4(inner_src, [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("initiator encap");
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let meta = outer_meta(frame.len());

    let scratch = WgWorkerScratch::new(4096);
    let decapped = super::decap::try_wg_decap_from_frame(&frame, meta, &forwarding, &scratch)
        .expect("an authenticated transport-data record must be decapsulated by the worker");

    // THE assertion. Adjudicating the inner packet under the UNDERLAY's zone
    // would be the #7167 invariant-2 failure: inner traffic would get the WAN's
    // policy, which is a different and equally wrong answer from the old
    // no-policy-at-all behaviour.
    assert_eq!(
        decapped.meta.ingress_ifindex as i32, TUNNEL_LOGICAL_IFINDEX,
        "the decapsulated inner packet must present the TUNNEL's logical \
         ifindex, not the underlay's — the ingress zone is derived from it, so \
         a physical ifindex here adjudicates inner traffic under the WAN's zone \
         (#7167 invariant 2 / #8274)"
    );
    assert_eq!(
        decapped.meta.ingress_zone, TEST_SFMIX_ZONE_ID,
        "the inner packet must be adjudicated under the tunnel interface's own \
         zone. This is what the old path never did at all: it wrote the \
         plaintext to the wgN TUN and let the kernel forward it with no zone \
         policy (#8274)"
    );
    // #7167 invariant 5: fabricating these would compile, adjudicate, and look
    // current. They must be the RX meta's.
    assert_eq!(
        decapped.meta.config_generation, 0x5150_4646,
        "the inner meta must INHERIT config_generation from the triggering RX \
         meta — a fabricated generation always looks current and silently \
         defeats attachment fencing (#7167 invariant 5)"
    );
    assert_eq!(decapped.meta.fib_generation, 0x0BAD_F00D, "fib_generation");
    // The plaintext survived intact behind the synthesized Ethernet header.
    assert_eq!(
        &decapped.frame[14..],
        &inner[..],
        "the decapsulated inner packet must be the plaintext the peer sent"
    );
    assert_eq!(
        decapped.peer_pubkey, init_pub,
        "the record must be attributed to the peer whose keys opened it"
    );

    // The roam report: the endpoint the worker observed is queued for the
    // control thread, which no longer sees these records on its socket.
    let engine = forwarding.wg_engines.get(&id).unwrap();
    assert_eq!(
        engine.take_worker_observed_endpoint(&init_pub),
        Some(std::net::SocketAddr::from((PEER_OUTER, PEER_SPORT))),
        "the worker must report the endpoint it observed on an authenticated \
         record — moving type-4 decap off the control thread's socket takes its \
         dominant endpoint-learning signal away (#8274)"
    );
    // Drained, not merely readable: a second take must be empty, or the control
    // thread would re-adopt the same roam on every pass.
    assert_eq!(engine.take_worker_observed_endpoint(&init_pub), None);
}

/// A HANDSHAKE record on the same 5-tuple is not the worker's.
///
/// The control thread owns the handshake state machine and the #1865
/// unknown-type accounting. This is the direction that would break the tunnel
/// if it were wrong, and it varies ONLY the first payload byte — a fixture that
/// varied the 5-tuple would pass on the port match and prove nothing.
#[test]
fn worker_decap_declines_a_handshake_record_8274() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, id) = forwarding_with_engine(resp);
    let engine = std::sync::Arc::clone(&forwarding.wg_engines[&id]);

    let inner = inner_v4([10, 123, 0, 5], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut record = wire[..enc.len].to_vec();
    // The ONLY difference from the admitted case above.
    record[0] = super::WG_TYPE_INITIATION;

    let frame = outer_frame(&record, WG_PORT);
    let scratch = WgWorkerScratch::new(4096);
    let before = decap_outcomes_observed(&engine);
    assert!(
        super::decap::try_wg_decap_from_frame(
            &frame,
            outer_meta(frame.len()),
            &forwarding,
            &scratch
        )
        .is_none(),
        "a handshake record must be left for the control thread; claiming it \
         here hands the handshake state machine to a stage that does not \
         implement it (#8274)"
    );
    assert_eq!(
        decap_outcomes_observed(&engine),
        before,
        "the stage must decline a non-type-4 record on its OWN gate, without \
         calling try_decap. try_decap also refuses this record (its header \
         parse fails), so `is_none()` alone stays true with the gate deleted — \
         only counter-freedom distinguishes declining from claiming-and-failing. \
         A stage that forwards handshakes into try_decap turns every peer's \
         handshake into a spurious decap drop and races the control thread for \
         the session map (#8274)"
    );
}

/// A datagram on a port no WireGuard tunnel listens on is not the worker's,
/// however well-formed the payload looks.
#[test]
fn worker_decap_declines_a_foreign_port_8274() {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let (forwarding, _id) = forwarding_with_engine(resp);

    let inner = inner_v4([10, 123, 0, 5], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let frame = outer_frame(&wire[..enc.len], WG_PORT + 1);
    let scratch = WgWorkerScratch::new(4096);
    assert!(
        super::decap::try_wg_decap_from_frame(
            &frame,
            outer_meta(frame.len()),
            &forwarding,
            &scratch
        )
        .is_none(),
        "a datagram on a port no tunnel listens on must take the ordinary \
         policy path, not a decap stage (#8274)"
    );
}

/// An `allowed-ips` mismatch is refused by the ENGINE, before any of this
/// stage's output exists — so no inner packet is presented for adjudication and
/// nothing counts as if it had reached the policy evaluator.
#[test]
fn worker_decap_refuses_an_allowed_ips_mismatch_8274() {
    // The responder permits 10.123.0.0/24; the initiator sends from outside it.
    let permitted: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) =
        established_pair(permitted.clone(), permitted.clone());
    let (forwarding, _id) = forwarding_with_engine(resp);

    let inner = inner_v4([192, 0, 2, 77], [10, 0, 61, 102]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let frame = outer_frame(&wire[..enc.len], WG_PORT);
    let scratch = WgWorkerScratch::new(4096);
    assert!(
        super::decap::try_wg_decap_from_frame(
            &frame,
            outer_meta(frame.len()),
            &forwarding,
            &scratch
        )
        .is_none(),
        "a record whose inner source is outside the peer's allowed-ips must be \
         refused before it becomes a packet — `allowed-ips` is the ONE check \
         the old path did have, and this stage must not lose it (#8274)"
    );
}

// ---------------------------------------------------------------------------
// #8274 WIRING binding.
//
// The four cells above call `try_wg_decap_from_frame` directly. Every one of
// them stays GREEN when the stage is deleted from the poll loop — verified by
// mutation: replacing the `if wg_frame.is_some()` adoption in
// `poll_descriptor/mod.rs` with `if false` reds nothing above. That is the
// exact failure this board has paid for twice (a packet-path change that is
// never called, every cell green, the box unchanged), so the wiring gets its
// own cells, driven through the REAL `poll_binding_process_descriptor` body.
//
// The pair below is one packet and one difference. Same authenticated record,
// same fixture, same underlay ingress; the ONLY thing that changes is whether
// a policy permits the INNER flow. Permit installs a session stamped with the
// TUNNEL's ingress identity; deny installs nothing. Before #8274 neither
// outcome was reachable, because the inner plaintext never met a policy at
// all — it went to the `wgN` TUN and the kernel routed it. That the two
// outcomes now DIFFER on the policy is the whole security-posture change, and
// it is stated in the direction the change actually runs: traffic that flows
// today can start being DENIED.

/// Build the WG fixture with an optional `sfmix -> wan` permit for the inner
/// flow, and an engine holding a live session.
fn wiring_fixture(permit_inner: bool) -> (ForwardingState, WgEngine, [u8; 32]) {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _ipub, rpub) = established_pair(allowed.clone(), allowed);
    let mut snap = wg_outer_mtu_snapshot();
    if permit_inner {
        snap.policies = vec![crate::PolicyRuleSnapshot {
            name: "permit-inner".to_string(),
            from_zone: "sfmix".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }];
    } else {
        snap.policies = Vec::new();
    }
    let mut forwarding = build_forwarding_state(&snap);
    let id = *forwarding.wg_engines.keys().next().expect("wg tunnel");
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    (forwarding, init, rpub)
}

/// One authenticated type-4 record on the wire, as it arrives on the underlay.
fn wiring_record(init: &WgEngine, rpub: &[u8; 32]) -> Vec<u8> {
    let inner = inner_v4([10, 123, 0, 5], [203, 0, 113, 50]);
    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(rpub, &inner, &mut wire).unwrap();
    outer_frame(&wire[..enc.len], WG_PORT)
}

fn wiring_meta(frame_len: usize) -> UserspaceDpMeta {
    let mut m = outer_meta(frame_len);
    // The record arrives on the WAN unit reth0.80 (ifindex 12) — the UNDERLAY.
    m.ingress_ifindex = 12;
    // The direct-call cells above use DISTINCTIVE generations to prove the
    // stage inherits rather than fabricates them. Here the packet must clear
    // `classify_metadata`'s generation fence to reach the stage at all, so it
    // carries the harness's validated pair (`txn_meta_v4`: 7 / 9). Leaving the
    // distinctive values here drops the frame as STALE before any stage runs —
    // which presents as "the stage never fired", i.e. exactly the failure this
    // cell is built to detect, from an unrelated cause.
    m.config_generation = 7;
    m.fib_generation = 9;
    // `try_parse_metadata` reads the descriptor's meta out of the UMEM and
    // refuses it on magic/version — a default-constructed meta parses as
    // NOTHING and the descriptor is dropped before any stage. The direct-call
    // cells never go through that reader, which is why they do not need these.
    m.magic = USERSPACE_META_MAGIC;
    m.version = USERSPACE_META_VERSION;
    m.length = std::mem::size_of::<UserspaceDpMeta>() as u16;
    m
}

/// WIRING, permit arm. The poll loop must actually CALL the decap stage, and
/// the session it installs must carry the TUNNEL's ingress identity.
///
/// A session keyed on the inner flow and stamped `ingress_ifindex 400` cannot
/// exist unless the stage ran inside `poll_binding_process_descriptor`: nothing
/// else in the loop can turn an outer UDP datagram addressed to the firewall
/// into an inner-flow session on a tunnel ifindex.
#[test]
fn poll_loop_adjudicates_wg_inner_plaintext_under_the_tunnel_zone_8274() {
    let (forwarding, init, rpub) = wiring_fixture(true);
    let frame = wiring_record(&init, &rpub);
    let meta = wiring_meta(frame.len());

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let (_b, _dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    let mut tunnel_zones: Vec<u16> = Vec::new();
    let mut total = 0usize;
    sessions.iter_with_origin(|_k, _d, m, _o| {
        total += 1;
        if m.ingress_ifindex == TUNNEL_LOGICAL_IFINDEX as u32 {
            tunnel_zones.push(m.ingress_zone);
        }
    });
    assert!(
        !tunnel_zones.is_empty(),
        "the poll loop must call the WireGuard decap stage: no session carries \
         the tunnel's ingress ifindex {TUNNEL_LOGICAL_IFINDEX}, so the inner \
         plaintext never reached policy. This is the assertion that dies when \
         the stage is built but not WIRED — every direct-call cell in this file \
         stays green in that state. Installed sessions: {total}"
    );
    for z in &tunnel_zones {
        assert_eq!(
            *z, TEST_SFMIX_ZONE_ID,
            "the inner flow must be adjudicated in the TUNNEL's zone; the \
             underlay's zone here would give inner traffic the WAN's policy \
             (#7167 invariant 2)"
        );
    }
}

/// WIRING, deny arm — and the security DIRECTION of #8274 stated as a test.
///
/// The same record, the same fixture, the policy removed. Before this change
/// the inner packet was written to the `wgN` TUN and the kernel forwarded it
/// with no policy consulted, so this packet was DELIVERED. After it, the flow
/// has no permitting policy and installs nothing. An operator upgrading into
/// this sees exactly that on the first packet: WireGuard inner traffic that
/// flowed yesterday is denied until a policy admits it.
#[test]
fn poll_loop_denies_wg_inner_plaintext_with_no_permitting_policy_8274() {
    let (forwarding, init, rpub) = wiring_fixture(false);
    let frame = wiring_record(&init, &rpub);
    let meta = wiring_meta(frame.len());

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = std::sync::Arc::<str>::from("ge-0-0-2.80");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    // NON-VACUITY CONTROL. "No tunnel session" is also what a packet that never
    // reached the stage produces, and this cell was observed GREEN in exactly
    // that state while its permit sibling was red — the descriptor was being
    // dropped on the metadata magic before any stage ran. So the cell asserts
    // the packet got FAR ENOUGH to be denied: the deny must come from policy,
    // not from the frame never arriving.
    assert!(
        dbg.policy_deny >= 1,
        "the inner flow must reach POLICY and be denied there. Zero policy \
         denies means the packet never got that far, and the \
         no-tunnel-session assertion below would hold for free"
    );

    let mut tunnel_sessions = 0usize;
    sessions.iter_with_origin(|_k, _d, m, _o| {
        if m.ingress_ifindex == TUNNEL_LOGICAL_IFINDEX as u32 {
            tunnel_sessions += 1;
        }
    });
    assert_eq!(
        tunnel_sessions, 0,
        "with no policy admitting sfmix -> wan the inner flow must install NO \
         session. A session here means the decap stage is presenting plaintext \
         that policy never adjudicated — the pre-#8274 posture wearing the new \
         code path's shape"
    );
}
