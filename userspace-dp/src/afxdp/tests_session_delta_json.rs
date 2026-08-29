// #6312: the JSON leg of the session-delta wire must carry the #5212 stable
// RT_FLOW session id, at parity with the binary event-stream open frame.
//
// The JSON `SessionDeltaInfo` is what the `drain_session_deltas` polling
// fallback (used whenever the binary event stream is down) and the owner-RG
// resync export put on the control-plane RPC. Before this it had no session-id
// field at all, so every session recovered through that leg imported id 0 and
// the peer minted a fresh local one — the originating node's SESSION_CREATE and
// the peer's post-failover SESSION_CLOSE no longer shared an id.
//
// Sibling `#[path]` test module loaded from afxdp/mod.rs, mirroring the #4840
// split.
#![allow(unused_imports)]

use super::session_delta::session_delta_info;
use super::*;
use crate::nat::NatDecision;
use crate::session::{
    SessionCounters, SessionDecision, SessionDelta, SessionDeltaKind, SessionKey, SessionMetadata,
    SessionOrigin,
};
use std::net::{IpAddr, Ipv4Addr};

fn delta_with_session_id(session_id: u64) -> SessionDelta {
    SessionDelta {
        kind: SessionDeltaKind::Open,
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 2,
                egress_ifindex: 3,
                tx_ifindex: 3,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
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
        },
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id,
    }
}

fn test_binding_identity() -> BindingIdentity {
    BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 7,
        interface: Arc::from("ge-0-0-1"),
        ifindex: 12,
    }
}

fn zone_names() -> FastMap<u16, String> {
    let mut m: FastMap<u16, String> = FastMap::default();
    m.insert(1, "lan".to_string());
    m.insert(2, "wan".to_string());
    m
}

/// Fail-on-revert: drop `rt_flow_session_id: delta.session_id` from
/// `session_delta_info` and the id arrives as 0, so the peer allocates a fresh
/// local id and the cross-node correlation is lost.
#[test]
fn session_delta_info_carries_rt_flow_session_id_6312() {
    let want = 7u64 << 48 | 0x1234_5678;
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(want),
        &zone_names(),
    );
    assert_eq!(
        info.rt_flow_session_id, want,
        "the JSON resync leg must carry the originating node's stable RT_FLOW \
         session id, like the binary open frame does (#6312)"
    );
    // Positive control: this really is the delta -> JSON conversion, so a
    // mismatch above cannot be a wrongly-built fixture.
    assert_eq!(info.src_port, 12345, "conversion produced the delta's tuple");
    assert_eq!(info.ingress_zone, "lan", "conversion resolved zone names");
}

/// The wire KEY is the cross-language contract: the Go consumer decodes this
/// field as `SessionDeltaInfo.RTFlowSessionID` with `json:"rt_flow_session_id"`
/// (pkg/dataplane/userspace/protocol_ha.go). A rename on this side would ship a
/// key the Go decoder ignores — the field would be present and the id still
/// silently lost, which the struct-level assertion above cannot see.
#[test]
fn session_delta_info_rt_flow_session_id_wire_key_6312() {
    let want = 0x0BAD_F00D_u64;
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(want),
        &zone_names(),
    );
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    let on_wire = v
        .get("rt_flow_session_id")
        .unwrap_or_else(|| panic!("no `rt_flow_session_id` key on the wire: {v}"));
    assert_eq!(
        on_wire.as_u64(),
        Some(want),
        "`rt_flow_session_id` must carry the id verbatim: {v}"
    );
}

/// A delta with no backing entry (`session_id == 0`) must still emit the key
/// carrying 0 — the pre-existing "no id" sentinel the peer maps to a fresh local
/// allocation. This is the rolling-upgrade fallback, so it must not become an
/// absent key or a synthesized non-zero value.
#[test]
fn session_delta_info_zero_session_id_is_the_no_id_sentinel_6312() {
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(0),
        &zone_names(),
    );
    assert_eq!(info.rt_flow_session_id, 0);
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    assert_eq!(
        v.get("rt_flow_session_id").and_then(|x| x.as_u64()),
        Some(0),
        "the zero sentinel must still ride the wire: {v}"
    );
}

// ---------------------------------------------------------------------------
// #6949: the JSON leg must carry the SAME policy attribution as the binary
// event-stream open frame.
//
// The binary MSG_SESSION_OPEN frame has carried policy_id (#3056/#3301),
// policy_counter_idx (#3073), the per-application inactivity timeout (#3227)
// and the NAT64 pool source (#4565) as trailing fields. The JSON
// `SessionDeltaInfo` carried NONE of them, while the Go consumer
// (`pkg/dataplane/userspace/protocol_ha.go`) declared and read all of them, so
// every session recovered through this leg imported policy 0 / counter 0 / the
// global idle timeout / no reverse-BIB pool source.
//
// The tests below assert on the SERIALIZED JSON rather than on struct fields
// wherever they are the red-at-master proof: at master those fields do not
// exist, and a struct-field assertion would be a BUILD BREAK rather than a
// named failing test.
// ---------------------------------------------------------------------------

use crate::event_stream::codec::{EventFrame, FLAG_NAT64, FRAME_HEADER_SIZE};

/// One session carrying a DISTINCTIVE, non-zero attribution on every field.
///
/// `policy_id` is deliberately NOT 0. A rendered 0 displays as `unattributed`
/// (#6851) and is also what a dropped field decodes to, so a fixture whose
/// correct `policy_id` is 0 cannot tell "attributed to policy 0" from
/// "attribution lost" — the exact confusion that hid this defect. It is a
/// NAT64 v6 session so `nat64` / `nat64_snat_v4` carry real values too.
fn delta_with_attribution() -> SessionDelta {
    use std::net::Ipv6Addr;
    let mut delta = delta_with_session_id(0x5EED_5EED);
    delta.key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        dst_ip: IpAddr::V6("64:ff9b::c0a8:101".parse::<Ipv6Addr>().unwrap()),
        src_port: 5001,
        dst_port: 80,
            discriminator: Default::default(),
    };
    delta.metadata.policy_id = 4242;
    delta.metadata.policy_counter_idx = 9;
    // 1800 s, expressed in ns: exercises the ns -> s conversion rather than a
    // value that survives either rounding.
    delta.metadata.inactivity_timeout_ns = Some(1_800 * 1_000_000_000);
    delta.decision.nat.nat64 = true;
    delta.decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    delta
}

/// The attribution as the BINARY open frame actually puts it on the wire.
///
/// Parsed from the frame bytes, not from the encoder's inputs: this is the leg
/// the JSON leg has to agree WITH, so it must be read the way the Go decoder
/// reads it (`pkg/dataplane/userspace/eventstream.go`). The #3301 block is the
/// last thing on the frame apart from the #4565 snat_v4 and the #5212 session
/// id, so it is addressed from the END.
struct BinaryAttribution {
    policy_id: u32,
    policy_counter_idx: u32,
    app_timeout: u32,
    nat64: bool,
    nat64_snat_v4: String,
}

fn binary_attribution(delta: &SessionDelta) -> BinaryAttribution {
    let zones: FxHashMap<String, u16> = FxHashMap::default();
    let frame = EventFrame::encode_session_open(
        1,
        &delta.key,
        &delta.decision,
        &delta.metadata,
        &zones,
        delta.fabric_redirect_sync,
        delta.session_id,
    );
    let payload = &frame.as_bytes()[FRAME_HEADER_SIZE..];
    let n = payload.len();
    let u32_at = |off: usize| -> u32 {
        u32::from_le_bytes(payload[off..off + 4].try_into().expect("4 bytes"))
    };
    // [n-24..n-20] policy_id, [n-20..n-16] policy_counter_idx,
    // [n-16..n-12] inactivity secs, [n-12..n-8] snat_v4, [n-8..n] session id.
    let snat = &payload[n - 12..n - 8];
    BinaryAttribution {
        policy_id: u32_at(n - 24),
        policy_counter_idx: u32_at(n - 20),
        app_timeout: u32_at(n - 16),
        nat64: payload[26] & FLAG_NAT64 != 0,
        nat64_snat_v4: if snat == [0, 0, 0, 0] {
            String::new()
        } else {
            format!("{}.{}.{}.{}", snat[0], snat[1], snat[2], snat[3])
        },
    }
}

/// CROSS-PRODUCER AGREEMENT (#6949). One session, both wires, same attribution.
///
/// Neither side is pinned to a literal here on purpose. A test that asserted
/// `policy_id == 4242` on the JSON leg alone would encode a belief that the
/// binary leg is the correct one; this asserts only that the two legs DESCRIBE
/// THE SAME SESSION, which is the actual contract — the Go control plane reads
/// whichever leg delivered the delta and cannot tell them apart afterwards.
///
/// RED AT MASTER: at master `session_delta_info` emits none of these keys, so
/// every `.get()` below is `None` and the JSON side reads as 0/""/false against
/// a binary side carrying 4242/9/1800/true/203.0.113.5.
///
/// NOTE on what an agreement assertion can and cannot see. A mutation INSIDE
/// the shared derivation (return `policy_id: 0` from
/// `SessionSyncAttribution::from_session`) moves BOTH legs together, so the
/// five equality assertions below all still hold — two legs can agree on a
/// wrong value. Measured as cell M6 of the #6949 matrix: what actually reds is
/// the POSITIVE CONTROL at the end (`want.policy_id == 4242`), alongside the
/// pre-existing binary-side `test_encode_session_open_carries_policy_fields_3301`.
/// That is why the controls are assertions and not a comment, and why the
/// #3301/#4565 codec tests that pin the binary leg's own values are the other
/// half of this guard and must not be deleted.
#[test]
fn session_delta_json_and_binary_agree_on_policy_attribution_6949() {
    let delta = delta_with_attribution();
    let want = binary_attribution(&delta);
    let info = session_delta_info(&test_binding_identity(), &delta, &zone_names());
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");

    let u32_key = |k: &str| -> u32 {
        v.get(k)
            .unwrap_or_else(|| {
                panic!(
                    "the JSON session-delta leg carries no `{k}` key at all, so every session \
                     recovered through the drain fallback or a FullResync export imports 0 for \
                     it while the binary open frame carries a real value (#6949): {v}"
                )
            })
            .as_u64()
            .unwrap_or_else(|| panic!("`{k}` is not a number: {v}")) as u32
    };

    assert_eq!(
        u32_key("policy_id"),
        want.policy_id,
        "the two session-delta legs disagree on the admitting policy id. A session learned \
         through the JSON leg would render `unattributed` (#6851 renders 0 that way) and be \
         skipped by the commit-time deletion-clear and the #4234 policy-rematch, both of which \
         exclude id 0"
    );
    assert_eq!(
        u32_key("policy_counter_idx"),
        want.policy_counter_idx,
        "the two legs disagree on the per-rule hit-counter handle (#3073): no rule counter is \
         attributed after a failover promotion"
    );
    assert_eq!(
        u32_key("app_timeout"),
        want.app_timeout,
        "the two legs disagree on the per-application inactivity timeout (#3227): the session \
         ages on the global per-protocol timeout instead"
    );
    assert_eq!(
        v.get("nat64").and_then(|x| x.as_bool()).unwrap_or(false),
        want.nat64,
        "the two legs disagree on the NAT64 cross-family marker (#4565): {v}"
    );
    assert_eq!(
        v.get("nat64_snat_v4")
            .and_then(|x| x.as_str())
            .unwrap_or_default(),
        want.nat64_snat_v4,
        "the two legs disagree on the NAT64 translated pool SOURCE. This one is not a \
         mis-attribution: it is the ONE datum the standby cannot reconstruct from the synced \
         forward v6 key, so without it a NAT64 session promoted from this leg cannot rebuild \
         its reverse v4->v6 BIB at all (#4565): {v}"
    );

    // Positive controls: the binary side really did carry the fixture, so an
    // equality above cannot be two legs agreeing on nothing.
    assert_eq!(want.policy_id, 4242, "binary leg carried the fixture policy");
    assert_eq!(want.app_timeout, 1800, "binary leg converted ns -> s");
    assert_eq!(want.nat64_snat_v4, "203.0.113.5", "binary leg carried snat");
    // ...and this really is the delta -> JSON conversion of THAT session.
    assert_eq!(info.src_port, 5001, "conversion produced the delta's tuple");
}

/// THREE STATES, NOT TWO (#6949 / #6851). A session genuinely admitted by
/// policy 0 must emit the keys carrying 0 — present-and-zero — so that
/// "attributed to policy 0" stays distinguishable from "the producer dropped
/// the field". An absent key is the pre-#6949 defect, and it decodes to the
/// same 0 on the Go side, which is exactly why the defect survived four
/// releases without an operator noticing.
///
/// RED AT MASTER: the keys are absent, so `get()` returns `None`.
#[test]
fn session_delta_info_zero_attribution_is_present_not_absent_6949() {
    // delta_with_session_id leaves policy_id / policy_counter_idx 0,
    // inactivity_timeout_ns None and the NatDecision default (no NAT64).
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(1),
        &zone_names(),
    );
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    for key in ["policy_id", "policy_counter_idx", "app_timeout"] {
        assert_eq!(
            v.get(key).and_then(|x| x.as_u64()),
            Some(0),
            "`{key}` must ride the wire as an explicit 0 for an unattributed session, not be \
             absent — absent is indistinguishable from the dropped-field defect: {v}"
        );
    }
    assert_eq!(
        v.get("nat64").and_then(|x| x.as_bool()),
        Some(false),
        "`nat64` must ride the wire as an explicit false for a non-NAT64 session: {v}"
    );
    assert_eq!(
        v.get("nat64_snat_v4").and_then(|x| x.as_str()),
        Some(""),
        "`nat64_snat_v4` must ride the wire as an explicit empty string when there is no pool \
         source — the Go consumer's `net.ParseIP(...).To4() != nil` test treats it as not-NAT64: \
         {v}"
    );
}

/// The single-source seam is only load-bearing while BOTH producers destructure
/// `SessionSyncAttribution` EXHAUSTIVELY. A `..` in either destructure restores
/// the pre-#6949 escape hatch: a field added to the struct would then be
/// carried by whichever producer happened to be updated, and nothing would fail
/// to compile — which is precisely how policy_id, policy_counter_idx,
/// app_timeout, nat64 and nat64_snat_v4 came to ride only one of the two legs.
///
/// Textual because the property is about the ABSENCE of a token; there is no
/// value to observe at runtime. Comment lines are stripped before matching so
/// this gate cannot be satisfied by prose that quotes the pattern it looks for.
#[test]
fn sync_attribution_exhaustive_destructure_6949() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read_code = |rel: &str| -> String {
        let p = root.join(rel);
        let src = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("read {}: {e} (the #6949 seam guard cannot run)", p.display()));
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // The field set is read from the definition, never restated here: a
    // constant written down twice is two constants.
    let def = read_code("src/session/sync_attribution.rs");
    let body = def
        .split_once("pub(crate) struct SessionSyncAttribution {")
        .expect("SessionSyncAttribution definition")
        .1
        .split_once("\n}")
        .expect("end of the struct definition")
        .0;
    let mut want: Vec<String> = body
        .lines()
        .filter_map(|l| l.trim().strip_suffix(','))
        .filter_map(|l| l.strip_prefix("pub(crate) "))
        .map(|l| l.split(':').next().unwrap_or_default().trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    want.sort();
    assert_eq!(
        want.len(),
        5,
        "expected the 5 HA-carried attribution fields, parsed {want:?}"
    );

    for producer in [
        "src/afxdp/session_delta.rs",
        "src/event_stream/codec/session_sync.rs",
    ] {
        let src = read_code(producer);
        let block = src
            .split_once("let SessionSyncAttribution {")
            .unwrap_or_else(|| {
                panic!(
                    "{producer} no longer destructures SessionSyncAttribution. If this producer \
                     stopped deriving its attribution from the shared helper, the two \
                     session-delta legs can silently diverge again (#6949) — restore the \
                     destructure or UPDATE this guard, do not delete it"
                )
            })
            .1
            .split_once('}')
            .expect("end of the destructure")
            .0;
        assert!(
            !block.contains(".."),
            "{producer} destructures SessionSyncAttribution with `..`, so a field added to the \
             struct would be carried by only one of the two session-delta legs and still \
             compile — the #6949 defect, restored silently: {block}"
        );
        let mut got: Vec<String> = block
            .split(',')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect();
        got.sort();
        assert_eq!(
            got, want,
            "{producer} binds {got:?} of SessionSyncAttribution's {want:?}"
        );
    }
}
