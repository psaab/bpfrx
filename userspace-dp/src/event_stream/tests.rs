// Tests for event_stream/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::codec::{
    DataplaneEventKind, DataplaneEventPayload, MSG_DRAIN_COMPLETE, MSG_FULL_RESYNC,
    MSG_SESSION_CREATE_RT_FLOW,
};
use super::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};

fn build_raw_ack_frame(seq: u64) -> [u8; FRAME_HEADER_SIZE] {
    let mut buf = [0u8; FRAME_HEADER_SIZE];
    // payload_len = 0 (header-only)
    buf[0..4].copy_from_slice(&0u32.to_le_bytes());
    buf[4] = MSG_ACK;
    // reserved bytes 5..8 stay zero
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
    buf
}

fn test_dataplane_event(kind: DataplaneEventKind, ingress_zone_id: u16) -> DataplaneEventPayload {
    DataplaneEventPayload {
        kind,
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        action: 0,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port: 12345,
        dst_port: 443,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 9,
        ingress_ifindex: 42,
        policy_id: 101,
        rule_id: 202,
        term_id: 303,
        reason: 5,
        owner_rg_id: 1,
        application_id: 404,
        filter_id: 505,
        screen_id: 606,
        timestamp_ns: 123_456_789,
    }
}

// #2460: build a forward Close SessionDelta for the RT_FLOW close-emit
// pairing tests.
#[cfg(test)]
fn test_close_delta(kind: crate::session::SessionDeltaKind) -> crate::session::SessionDelta {
    use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
    use crate::nat::NatDecision;
    use crate::session::{
        SessionCounters, SessionDecision, SessionDelta, SessionKey, SessionMetadata,
        SessionOrigin,
    };
    SessionDelta {
        kind,
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
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
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                rewrite_src_port: Some(40000),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            owner_rg_id: 0,
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
        // #2749: ToS byte 0xB8 (DSCP EF=46 << 2) and TCP flags SYN|FIN|ACK so
        // the close-emit / round-trip tests can assert real wire values.
        observed_tos: 0xB8,
        observed_tcp_flags: 0x13,
    }
}

#[test]
fn test_emit_session_close_rt_flow_pairs_with_ha_delta() {
    // #2460 no-double-emit contract: a single close emits exactly ONE type-2
    // HA session-sync close delta (push_delta, unchanged) AND exactly ONE
    // type-14 RT_FLOW SESSION_CLOSE frame (emit_session_close_rt_flow). The
    // two are a 1:1 pair — the RT_FLOW frame is additive, it does not
    // duplicate or replace the HA delta.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let zone_map = FxHashMap::default();
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);

    // Mirror flush_session_deltas: the HA delta then the RT_FLOW frame.
    handle.push_delta(&delta, &zone_map);
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);

    let frames: Vec<EventFrame> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(frames.len(), 2, "expected exactly one HA delta + one RT_FLOW frame");

    let ha = frames.iter().filter(|f| f.data[4] == codec::MSG_SESSION_CLOSE).count();
    let rt = frames
        .iter()
        .filter(|f| f.data[4] == codec::MSG_SESSION_CLOSE_RT_FLOW)
        .count();
    assert_eq!(ha, 1, "exactly one type-2 HA close delta");
    assert_eq!(rt, 1, "exactly one type-14 RT_FLOW close frame");

    // The RT_FLOW frame carries the SESSION_CLOSE event-type byte and tuple.
    let rt_frame = frames
        .iter()
        .find(|f| f.data[4] == codec::MSG_SESSION_CLOSE_RT_FLOW)
        .unwrap();
    let p = &rt_frame.data[FRAME_HEADER_SIZE..rt_frame.len as usize];
    assert_eq!(p[52], 2, "RT_FLOW event type must be SESSION_CLOSE (2)");
    assert_eq!(&p[8..12], &[10, 0, 1, 102]);
    assert_eq!(&p[24..28], &[172, 16, 80, 200]);
}

#[test]
fn test_monotonic_ns_to_unix_conversions() {
    // #2465: pure-function contract for the monotonic→wall-clock conversion
    // used by emit_session_close_rt_flow. Anchored against a (mono, wall)
    // reference, a creation instant 30s in the monotonic past maps to a
    // wall-clock time 30s before the wall reference.
    let now_mono = 1_000_000_000_000u64; // 1000s monotonic
    let now_unix = 1_700_000_000_000_000_000u64; // 1.7e9 s in ns
    let created_mono = now_mono - 30 * NS_PER_SEC; // 30s ago
    let created_ns_abs = monotonic_ns_to_unix_ns(created_mono, now_mono, now_unix);
    assert_eq!(created_ns_abs, now_unix - 30 * NS_PER_SEC);
    assert_eq!(
        monotonic_ns_to_unix_secs(created_mono, now_mono, now_unix),
        1_700_000_000 - 30
    );

    // 0 / unknown inputs map to 0 (→ the Go-side packet-count fallback).
    assert_eq!(monotonic_ns_to_unix_ns(0, now_mono, now_unix), 0);
    assert_eq!(monotonic_ns_to_unix_secs(0, now_mono, now_unix), 0);
    assert_eq!(monotonic_ns_to_unix_ns(created_mono, 0, now_unix), 0);
    assert_eq!(monotonic_ns_to_unix_ns(created_mono, now_mono, 0), 0);

    // A monotonic value slightly AHEAD of the reference (cross-CPU read skew)
    // clamps to the present, never the future.
    let ahead = now_mono + 5 * NS_PER_SEC;
    assert_eq!(monotonic_ns_to_unix_ns(ahead, now_mono, now_unix), now_unix);
}

#[test]
fn test_monotonic_ns_to_unix_secs_subnanos() {
    // #2853: the secs+subnanos split must reconstruct the exact wall-clock
    // nanosecond instant, preserving the sub-second remainder the seconds-only
    // helper truncated. A creation instant 30.123456789s before a sub-second
    // wall reference splits into the right second and the right nanos.
    let now_mono = 1_000_000_000_000u64; // 1000s monotonic
    let now_unix = 1_700_000_000_123_456_789u64; // 1.7e9 s + 123456789 ns
    let created_mono = now_mono - 30 * NS_PER_SEC; // 30s ago (whole seconds)
    let (secs, subnanos) = monotonic_ns_to_unix_secs_subnanos(created_mono, now_mono, now_unix);
    assert_eq!(secs, 1_700_000_000 - 30);
    assert_eq!(subnanos, 123_456_789);
    // The seconds-only helper still returns just the truncated second.
    assert_eq!(
        monotonic_ns_to_unix_secs(created_mono, now_mono, now_unix),
        1_700_000_000 - 30
    );
    // Reconstruction is lossless.
    assert_eq!(
        secs as u64 * NS_PER_SEC + subnanos as u64,
        now_unix - 30 * NS_PER_SEC
    );
    // 0 / unknown maps to (0, 0).
    assert_eq!(
        monotonic_ns_to_unix_secs_subnanos(0, now_mono, now_unix),
        (0, 0)
    );
    // subnanos is always a valid sub-second remainder.
    assert!(subnanos < NS_PER_SEC as u32);
}

#[test]
fn test_emit_session_close_rt_flow_carries_real_created_stamp() {
    // #2465 fail-on-revert: a close delta with a real (non-zero) created_ns
    // must produce a non-zero `created` (offset 108) and `timestamp_ns`
    // (offset 0) on the RT_FLOW frame. If the producer drops the created_ns →
    // wire conversion (or the encoder reverts to writing 0), these stay 0 and
    // the flow exporter falls back to the packet-count heuristic StartTime —
    // exactly the #2465 bug. A monotonic created_ns ~60s in the past must land
    // ~60s before the close timestamp on the wire.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    // Anchor the delta's monotonic timestamps to the live CLOCK_MONOTONIC so
    // the conversion against the emit-time reading yields a plausible age.
    let (now_mono, _now_wall) = read_mono_and_wall_clocks();
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Close);
    delta.created_ns = now_mono.saturating_sub(60 * NS_PER_SEC);
    delta.last_seen_ns = now_mono;

    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];

    let created_secs = u32::from_le_bytes(p[108..112].try_into().unwrap());
    let ts_ns = u64::from_le_bytes(p[0..8].try_into().unwrap());
    assert!(created_secs > 0, "created stamp must be populated (not the #2465 zero)");
    assert!(ts_ns > 0, "record timestamp must be populated");
    // created is ~60s before the close timestamp (allow a few seconds of GC /
    // scheduling slack on top of the 60s age).
    let ts_secs = ts_ns / NS_PER_SEC;
    let delta_secs = ts_secs.saturating_sub(created_secs as u64);
    assert!(
        (58..=65).contains(&delta_secs),
        "expected ~60s session age on the wire, got {delta_secs}s (created={created_secs}, close_secs={ts_secs})"
    );
}

#[test]
fn test_emit_session_close_rt_flow_carries_app_id() {
    // #2520 fail-on-revert: the AppID the caller resolves (the same
    // app_catalog.lookup the forwarding hot path runs) must ride the
    // [132:134] wire slot of the SESSION_CLOSE frame so the Go RT_FLOW logger
    // renders application=<name> instead of UNKNOWN. Reverting
    // emit_session_close_rt_flow / encode_session_close_rt_flow to drop the
    // app_id (leaving the slot 0) makes this assertion fail.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);
    handle.emit_session_close_rt_flow(&delta, 7, 42, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u16::from_le_bytes([p[132], p[133]]),
        7,
        "SESSION_CLOSE RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
    );
    // #2615 fail-on-revert: the ingress ifindex the caller threads
    // (ident.ifindex) must ride the [128:132] slot so the close record renders
    // packet-incoming-interface=<name> instead of N/A. Reverting the emit /
    // encode path to leave the slot 0 makes this assertion fail.
    assert_eq!(
        u32::from_le_bytes(p[128..132].try_into().unwrap()),
        42,
        "SESSION_CLOSE RT_FLOW must carry the ingress ifindex, not N/A(0)"
    );
}

#[test]
fn test_emit_session_close_rt_flow_carries_admitting_policy_id() {
    // #3056 fail-on-revert: a session admitted by a policy must carry that
    // policy's ID on the SESSION_CLOSE RT_FLOW frame so the
    // RT_FLOW_SESSION_CLOSE syslog record (and the NetFlow/IPFIX close
    // exporters) name the admitting policy instead of policy 0. The admit path
    // stamps SessionMetadata.policy_id, which the Close delta carries;
    // emit_session_close_rt_flow threads it into the trailing [136:140] wire
    // slot — NOT [44:48], which #2853 took for the created-subsec-nanos on a
    // close. The Go decoder reads [136:140] back as PolicyID only on a close.
    // Reverting the stamp (metadata.policy_id) or the encode ([136:140]) back to
    // 0 makes this assertion fail (the record would log policy 0 / the first
    // configured policy).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Close);
    // The session was admitted by policy ID 42.
    delta.metadata.policy_id = 42;
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u32::from_le_bytes(p[136..140].try_into().unwrap()),
        42,
        "SESSION_CLOSE RT_FLOW must carry the admitting policy ID in [136:140], \
         not the policy-0 sentinel"
    );
    // The event type byte must be SESSION_CLOSE (2); the policy ID rides
    // [136:140] precisely because [44:48] is the #2853 created-subsec-nanos here.
    assert_eq!(p[52], 2, "RT_FLOW event type must be SESSION_CLOSE (2)");
}

#[test]
fn test_emit_session_close_rt_flow_zero_created_stays_zero() {
    // #2465: a close delta with an UNKNOWN (0) created_ns must keep the wire
    // created/timestamp fields 0 so the Go exporter falls back to the
    // packet-count estimate (the explicit-delete / HA-purge close paths).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close); // created_ns == 0
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(u32::from_le_bytes(p[108..112].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(p[0..8].try_into().unwrap()), 0);
}

#[test]
fn test_emit_session_close_rt_flow_ignores_open_delta() {
    // #2460: the RT_FLOW close emit is gated on Close — calling it for an
    // Open delta is a no-op (guards against a future caller misusing it and
    // injecting a bogus SESSION_CLOSE for an opening session).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    assert!(rx.try_recv().is_err(), "Open delta must emit no RT_FLOW close frame");
}

#[test]
fn test_emit_session_close_rt_flow_accounts_under_session_close_kind() {
    // #2512 fail-on-revert: a SESSION_CLOSE RT_FLOW frame must travel the same
    // per-kind budget path as deny/screen/filter — NOT a bare unaccounted
    // `try_send`. With an UNLIMITED limiter but a tiny queue capacity, a
    // close burst beyond the per-kind queue budget must increment the
    // SessionClose `dropped`/`queue_full` counters (and the generic
    // frames_dropped), and the accepted prefix must be counted under
    // SessionClose `sent`. If a reviewer reverts the emit path back to
    // `self.try_send(frame)`, no SessionClose counter ever moves and the
    // dropped close is silent — this test fails.
    //
    // capacity 4 → max_total_queued = 4/2 = 2; per-kind budget = ceil(2/5) = 1.
    let (handle, _rx) = test_worker_handle(
        4,
        DataplaneEventRateLimitConfig {
            events_per_second: 0, // unlimited: isolate the queue-budget gate
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);

    // Emit 4 closes; the per-kind budget admits 1, the rest are queue-full.
    // (`_rx` is never drained, so the budget is never released.)
    for _ in 0..4 {
        handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    }

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.session_close.sent, 1, "one close fits the per-kind budget");
    assert_eq!(
        stats.session_close.queue_full, 3,
        "three closes shed by the per-kind queue budget"
    );
    assert_eq!(
        stats.session_close.dropped, 3,
        "queue-full drops roll into the SessionClose dropped total"
    );
    // The bare-try_send revert leaves every other kind at zero AND moves no
    // SessionClose counter; assert the close kind owns the accounting.
    assert_eq!(stats.policy_deny.sent, 0);
    assert_eq!(stats.policy_deny.dropped, 0);
}

#[test]
fn test_emit_session_close_rt_flow_rate_limited_is_counted() {
    // #2512 fail-on-revert: a SESSION_CLOSE burst beyond the per-(kind,zone)
    // rate-limiter token budget must be counted as a SessionClose
    // `rate_limited` drop. Session-table closes can be bursty at GC time;
    // this proves the limiter is actually applied to type-14 (a bare
    // try_send would never rate-limit and this counter would stay 0).
    let (handle, rx) = test_worker_handle(
        64, // large channel/budget so the limiter, not the queue, is the gate
        DataplaneEventRateLimitConfig {
            events_per_second: 1_000,
            burst: 2, // only 2 closes allowed in the instantaneous burst
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);

    for _ in 0..5 {
        handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    }

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.session_close.sent, 2, "burst of 2 closes admitted");
    assert_eq!(
        stats.session_close.rate_limited, 3,
        "the 3 closes past the burst are rate-limited, not silently sent"
    );
    assert_eq!(stats.session_close.dropped, 3);
    // Exactly the admitted prefix reached the channel.
    let frames: Vec<EventFrame> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(frames.len(), 2);
}

#[test]
fn test_emit_session_create_rt_flow_accounts_under_session_create_kind() {
    // #2512: the SESSION_CREATE (type 15) sibling of the close path also
    // rides the per-kind budget under DataplaneEventKind::SessionCreate.
    let (handle, _rx) = test_worker_handle(
        4, // per-kind budget = 1
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    delta.metadata.log_session_init = true;

    for _ in 0..3 {
        handle.emit_session_create_rt_flow(&delta, 0, 0);
    }

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.session_create.sent, 1);
    assert_eq!(stats.session_create.queue_full, 2);
    assert_eq!(stats.session_create.dropped, 2);
    // Must not steal the close kind's budget/counters.
    assert_eq!(stats.session_close.sent, 0);
    assert_eq!(stats.session_close.dropped, 0);
}

#[test]
fn test_emit_session_create_rt_flow_carries_app_id_and_ifindex() {
    // #2615 fail-on-revert: the SESSION_CREATE emit path must thread the
    // resolved AppID ([132:134]) and the admitting binding's ingress ifindex
    // ([128:132]) into the wire frame, mirroring the #2520 close-side AppID
    // fix. Reverting emit_session_create_rt_flow / encode_session_create_rt_flow
    // to leave either slot 0 makes the create record log application="UNKNOWN"
    // / packet-incoming-interface="N/A" — and these assertions fail.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    delta.metadata.log_session_init = true;
    handle.emit_session_create_rt_flow(&delta, 9, 77);
    let frame = rx.try_recv().expect("RT_FLOW create frame");
    assert_eq!(frame.data[4], MSG_SESSION_CREATE_RT_FLOW);
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u16::from_le_bytes([p[132], p[133]]),
        9,
        "SESSION_CREATE RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
    );
    assert_eq!(
        u32::from_le_bytes(p[128..132].try_into().unwrap()),
        77,
        "SESSION_CREATE RT_FLOW must carry the ingress ifindex, not N/A(0)"
    );
}

#[test]
fn test_emit_session_create_rt_flow_carries_admitting_policy_id() {
    // #3056 fail-on-revert: a session admitted by a policy must carry that
    // policy's ID on the SESSION_CREATE RT_FLOW frame so the
    // RT_FLOW_SESSION_CREATE syslog record names the admitting policy instead
    // of policy 0. The admit path stamps SessionMetadata.policy_id, which the
    // Open delta carries; emit_session_create_rt_flow threads it into the
    // [44:48] policy_id wire slot — the same slot the Go decoder reads as
    // PolicyID for non-close frames and resolves a policy name from. Reverting
    // the stamp (metadata.policy_id) or the encode ([44:48]) back to 0 makes
    // this assertion fail (the record would log policy 0 / the first configured
    // policy).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    delta.metadata.log_session_init = true;
    // The session was admitted by policy ID 42.
    delta.metadata.policy_id = 42;
    handle.emit_session_create_rt_flow(&delta, 0, 0);
    let frame = rx.try_recv().expect("RT_FLOW create frame");
    assert_eq!(frame.data[4], MSG_SESSION_CREATE_RT_FLOW);
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u32::from_le_bytes(p[44..48].try_into().unwrap()),
        42,
        "SESSION_CREATE RT_FLOW must carry the admitting policy ID in [44:48], \
         not the policy-0 sentinel"
    );
    // The Go decoder reads [44:48] as PolicyID for non-close frames; the event
    // type byte must therefore be SESSION_CREATE (1), not SESSION_CLOSE (2)
    // (whose [44:48] is repurposed by #2853).
    assert_eq!(p[52], 1, "RT_FLOW event type must be SESSION_CREATE (1)");
}

#[test]
fn test_sequence_monotonicity() {
    let shared = Arc::new(EventStreamShared::new());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let s = shared.clone();
            std::thread::spawn(move || {
                let mut seqs = Vec::with_capacity(100);
                for _ in 0..100 {
                    let seq = s.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
                    seqs.push(seq);
                }
                seqs
            })
        })
        .collect();

    let mut all_seqs: Vec<u64> = Vec::new();
    for h in handles {
        all_seqs.extend(h.join().unwrap());
    }
    all_seqs.sort();
    all_seqs.dedup();
    // All 400 sequences should be unique
    assert_eq!(all_seqs.len(), 400);
    // Should be 1..=400
    assert_eq!(*all_seqs.first().unwrap(), 1);
    assert_eq!(*all_seqs.last().unwrap(), 400);
}

#[test]
fn test_replay_buffer_trim() {
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Add 10 frames with seq 1..=10
    for seq in 1..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    assert_eq!(replay_buf.len(), 10);

    // Simulate Ack seq=5: trim frames <= 5
    let acked_seq = 5u64;
    while let Some(front) = replay_buf.front() {
        if front.seq <= acked_seq {
            replay_buf.pop_front();
        } else {
            break;
        }
    }
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(replay_buf.front().unwrap().seq, 6);
}

#[test]
fn test_replay_gap_at_zero_ack_sends_full_resync() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Simulate a replay buffer overrun before the daemon ever ACKed anything:
    // seq 1 has been trimmed, so replaying seq 2.. would silently lose the
    // first audit/session event unless the helper requests FullResync.
    for seq in 2..=REPLAY_BUFFER_CAPACITY as u64 + 1 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    replay_buffered(&helper_side, &mut replay_buf, 0, &shared).expect("replay gap");

    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    daemon_side.read_exact(&mut hdr).expect("full resync frame");
    assert_eq!(hdr[4], MSG_FULL_RESYNC);
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 1);
    assert_eq!(
        replay_buf.front().map(|f| f.seq),
        Some(2),
        "full resync keeps stale replay window until the daemon ACKs"
    );
}

#[test]
fn test_channel_backpressure() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(2);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    // Fill the channel (capacity 2)
    let frame = EventFrame::encode_drain_complete(1);
    assert!(handle.try_send(frame.clone()));
    assert!(handle.try_send(frame.clone()));

    // Third send should fail (channel full)
    assert!(!handle.try_send(frame));
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 2);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 1);
}

#[test]
fn dataplane_event_budget_stays_held_after_connected_loop_drains_channel() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    helper_side.set_nonblocking(true).unwrap();

    let capacity = 1;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
            capacity,
        ),
    );
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        let reconnect = run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            Duration::from_secs(10),
        );
        drain_remaining(&rx, &loop_shared);
        release_replay_dataplane_event_queue_budget(&loop_shared, &mut replay_buf);
        reconnect
    });

    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    daemon_side
        .read_exact(&mut hdr)
        .expect("dataplane frame header");
    let payload_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; payload_len];
    daemon_side
        .read_exact(&mut payload)
        .expect("dataplane frame payload");

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::QueueFull
        },
        "draining the mpsc channel into replay must not release telemetry budget"
    );

    daemon_side
        .write_all(&build_raw_ack_frame(1))
        .expect("send ACK");
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match handle
            .try_emit_dataplane_event_at(test_dataplane_event(DataplaneEventKind::PolicyDeny, 7), 0)
        {
            DataplaneEventEmitOutcome::Queued { seq: 2 } => break,
            DataplaneEventEmitOutcome::Dropped {
                reason: DataplaneEventDropReason::QueueFull,
            } if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            other => panic!("telemetry budget should release after ACK, got {other:?}"),
        }
    }

    shared.stop.store(true, Ordering::Release);
    assert!(
        !loop_join.join().expect("connected loop thread"),
        "test loop should stop without requesting reconnect"
    );
}

#[test]
fn dataplane_event_budget_releases_when_replay_eviction_drops_frame() {
    let capacity = 1;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
            capacity,
        ),
    );
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );
    let frame = rx.try_recv().expect("queued dataplane frame");
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
    push_replay_frame(&shared, &mut replay_buf, frame);

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::QueueFull
        }
    );

    for seq in 2..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(seq),
        );
    }
    push_replay_frame(
        &shared,
        &mut replay_buf,
        EventFrame::encode_drain_complete(REPLAY_BUFFER_CAPACITY as u64 + 1),
    );

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 2 },
        "replay eviction is a definitive drop and must release telemetry budget"
    );

    drain_remaining(&rx, &shared);
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
}

// #2382: replay-buffer eviction (buffer wrapped at capacity before ACK) is a
// real telemetry loss and must be counted; ACK-trim (acknowledged-frame
// removal) is NOT a loss and must NOT bump the eviction counter. These tests
// fail if the increment is removed or moved into the shared pop path.

#[test]
fn replay_buffer_eviction_counts_telemetry_loss_2382() {
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);

    // Fill the replay buffer exactly to capacity — no eviction yet.
    for seq in 1..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(&shared, &mut replay_buf, EventFrame::encode_drain_complete(seq));
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "filling to capacity must not evict anything"
    );

    // Push N more frames past capacity: each wraps the buffer and evicts the
    // oldest unACKed frame. The counter must go 0 -> N. This assertion FAILS
    // (stays 0) if the eviction increment in `evict_replay_frame` is removed.
    let overflow = 5u64;
    for seq in 0..overflow {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(REPLAY_BUFFER_CAPACITY as u64 + 1 + seq),
        );
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        overflow,
        "each buffer-full wrap must count exactly one replay eviction"
    );
    // And the surviving window starts past the evicted prefix.
    assert_eq!(replay_buf.front().map(|f| f.seq), Some(overflow + 1));
}

#[test]
fn ack_trim_does_not_count_as_replay_eviction_2382() {
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Buffer well under capacity so no wrap occurs.
    for seq in 1..=10u64 {
        push_replay_frame(&shared, &mut replay_buf, EventFrame::encode_drain_complete(seq));
    }
    assert_eq!(shared.frames_replay_evicted.load(Ordering::Relaxed), 0);

    // Simulate the MSG_ACK trim path: acked_seq = 5 removes the first 5 frames
    // via `pop_replay_frame`. Those frames were DELIVERED (acknowledged), not
    // lost — the eviction counter must stay 0.
    let acked_seq = 5u64;
    while let Some(front) = replay_buf.front() {
        if front.seq <= acked_seq {
            pop_replay_frame(&shared, &mut replay_buf);
        } else {
            break;
        }
    }
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(replay_buf.front().unwrap().seq, 6);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "ACK-trim is acknowledged removal, not a telemetry loss — must not \
         bump the replay-eviction counter"
    );

    // Shutdown drain (release_replay_dataplane_event_queue_budget → pop) also
    // must not count as eviction.
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
    assert_eq!(replay_buf.len(), 0);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "shutdown drain must not bump the replay-eviction counter"
    );
}

#[test]
fn replay_evictions_surface_in_event_stream_stats_2382() {
    let sender = EventStreamSender {
        tx: mpsc::sync_channel(1).0,
        shared: Arc::new(EventStreamShared::new()),
        io_thread: None,
    };
    sender
        .shared
        .frames_replay_evicted
        .store(42, Ordering::Relaxed);
    assert_eq!(sender.stats().replay_evictions, 42);
}

// #2381: the write-backlog cap converts a wedged daemon reader from
// unbounded helper heap growth into bounded, counted telemetry loss at the
// already-bounded mpsc channel. These tests fail if the cap is removed or the
// stall is not counted.

#[test]
fn write_backlog_cap_halts_drain_and_counts_stall() {
    // Channel holds frames the I/O thread would normally migrate into the
    // pending write backlog. With the backlog already at the cap, the drain
    // must stop, count the stall, and LEAVE the frames in the channel.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    for seq in 1..=4u64 {
        tx.send(EventFrame::encode_drain_complete(seq))
            .expect("seed channel");
    }

    // Simulate a wedged consumer: the backlog is already at the cap because
    // prior socket writes returned WouldBlock.
    let mut write_buf: Vec<u8> = vec![0u8; WRITE_BACKLOG_MAX_BYTES];

    let outcome = drain_channel_into_write_buf(&rx, &shared, &mut replay_buf, &mut write_buf, false);

    assert!(outcome.stalled, "drain must report the backlog stall");
    assert!(!outcome.disconnected);
    assert!(!outcome.drained_any, "no frame may move into a full backlog");
    assert_eq!(
        write_buf.len(),
        WRITE_BACKLOG_MAX_BYTES,
        "backlog must not grow past the cap"
    );
    assert_eq!(
        shared.frames_write_stalled.load(Ordering::Relaxed),
        1,
        "the stall must be counted"
    );
    // Frames stay in the channel (the real backpressure surface), not silently
    // relocated into one unbounded heap buffer.
    assert_eq!(rx.try_recv().map(|f| f.seq).ok(), Some(1));
}

#[test]
fn write_backlog_stall_makes_channel_the_backpressure_surface() {
    // Once the backlog is capped, the bounded channel fills and worker
    // try_send drops the NEWEST events with the existing frames_dropped
    // counter — bounded, counted loss instead of unbounded growth.
    let capacity = 4;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let mut write_buf: Vec<u8> = vec![0u8; WRITE_BACKLOG_MAX_BYTES];

    // Fill the channel to capacity.
    for seq in 1..=capacity as u64 {
        assert!(handle.try_send(EventFrame::encode_drain_complete(seq)));
    }

    // I/O thread cannot drain into the full backlog: channel stays full.
    let outcome = drain_channel_into_write_buf(&rx, &shared, &mut replay_buf, &mut write_buf, false);
    assert!(outcome.stalled);
    assert!(!outcome.drained_any);

    // Subsequent producer sends now drop (newest-first) and are counted.
    assert!(
        !handle.try_send(EventFrame::encode_drain_complete(99)),
        "producer must drop, never block, when the channel is full"
    );
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), capacity as u64);
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        1,
        "the bounded channel drop must be counted"
    );
}

#[test]
fn paused_drain_ignores_backlog_cap_and_never_stalls() {
    // While paused, frames are consumed into the already-bounded replay
    // buffer only (never the write backlog), so the cap must not engage even
    // with a pre-filled write_buf.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let mut write_buf: Vec<u8> = vec![0u8; WRITE_BACKLOG_MAX_BYTES];

    for seq in 1..=3u64 {
        tx.send(EventFrame::encode_drain_complete(seq))
            .expect("seed channel");
    }

    let outcome = drain_channel_into_write_buf(&rx, &shared, &mut replay_buf, &mut write_buf, true);
    assert!(!outcome.stalled, "paused drain must not stall on the cap");
    assert!(outcome.drained_any);
    assert_eq!(
        write_buf.len(),
        WRITE_BACKLOG_MAX_BYTES,
        "paused frames must not be added to the write backlog"
    );
    assert_eq!(replay_buf.len(), 3, "paused frames go to the replay buffer");
    assert_eq!(shared.frames_write_stalled.load(Ordering::Relaxed), 0);
}

#[test]
fn stalled_consumer_does_not_grow_backlog_unbounded_end_to_end() {
    // End-to-end: a daemon that connects but never reads (socket buffer fills
    // → write returns WouldBlock). Pump far more than the backlog cap worth of
    // frames through the channel and assert the loop SHEDS at the bounded
    // channel (frames_dropped grows, stalls counted) instead of migrating
    // every frame into an unbounded write_buf.
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    // Never read on the daemon side: let the socket buffer wedge.

    let capacity = 64;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            Duration::from_secs(10),
        )
    });

    // Encode-only frame size; pump >> WRITE_BACKLOG_MAX_BYTES worth of frames.
    let frame_bytes = EventFrame::encode_drain_complete(1).as_bytes().len();
    let frames_to_pump = (WRITE_BACKLOG_MAX_BYTES / frame_bytes) * 3 + 4096;

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut sent_ok = 0u64;
    for seq in 0..frames_to_pump as u64 {
        // Non-blocking producer: retry on transient full but never block the
        // "worker" forever. A persistently full channel is the expected
        // backpressure once the backlog caps.
        loop {
            if handle.try_send(EventFrame::encode_drain_complete(seq + 1)) {
                sent_ok += 1;
                break;
            }
            // Channel full → backpressure engaged; that is the intended state.
            if shared.frames_dropped.load(Ordering::Relaxed) > 0 {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::yield_now();
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    // The defining proof: with a wedged reader and a sustained source far
    // exceeding the cap, the loop must have stalled and shed at the channel.
    let deadline2 = Instant::now() + Duration::from_secs(5);
    while shared.frames_write_stalled.load(Ordering::Relaxed) == 0
        && Instant::now() < deadline2
    {
        let _ = handle.try_send(EventFrame::encode_drain_complete(0));
        thread::sleep(Duration::from_millis(1));
    }

    shared.stop.store(true, Ordering::Release);
    let _ = loop_join.join();

    assert!(
        shared.frames_write_stalled.load(Ordering::Relaxed) > 0,
        "a wedged reader with a sustained source must trip the backlog cap"
    );
    assert!(
        shared.frames_dropped.load(Ordering::Relaxed) > 0,
        "shedding must happen at the bounded channel (counted), not via \
         unbounded write_buf growth"
    );
    // The channel is bounded, so accepted frames are bounded by capacity +
    // whatever the (capped) backlog/replay absorbed — never the full source.
    assert!(
        sent_ok < frames_to_pump as u64,
        "not every pumped frame can be accepted once backpressure engages"
    );
    drop(daemon_side);
}

#[test]
fn keeping_up_consumer_sees_full_fidelity_and_no_stalls() {
    // A daemon that drains the socket promptly must lose nothing: no stalls,
    // no drops, every byte delivered in order.
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let capacity = 16;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };

    let total: u64 = 5000;
    let mut expected: Vec<u8> = Vec::new();
    for seq in 1..=total {
        expected.extend_from_slice(EventFrame::encode_drain_complete(seq).as_bytes());
    }

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            Duration::from_secs(10),
        )
    });

    let frame_bytes = EventFrame::encode_drain_complete(1).as_bytes().len();
    let want = total as usize * frame_bytes;

    // Reader thread drains promptly so the helper never backs up.
    let mut reader = daemon_side;
    let read_join = thread::spawn(move || {
        let mut got: Vec<u8> = Vec::with_capacity(want);
        let mut chunk = [0u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(15);
        while got.len() < want && Instant::now() < deadline {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        got
    });

    for seq in 1..=total {
        // Lossless producer-side feed paced by the bounded channel; the prompt
        // reader keeps it draining so this never has to drop.
        let mut frame = EventFrame::encode_drain_complete(seq);
        loop {
            match tx.try_send(frame) {
                Ok(()) => {
                    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(mpsc::TrySendError::Full(returned)) => {
                    frame = returned;
                    thread::yield_now();
                }
                Err(mpsc::TrySendError::Disconnected(_)) => panic!("channel closed"),
            }
        }
    }

    let got = read_join.join().expect("reader thread");
    shared.stop.store(true, Ordering::Release);
    let _ = loop_join.join();

    assert_eq!(got.len(), want, "every frame byte must be delivered");
    assert_eq!(got, expected, "frames must arrive in order, unmodified");
    assert_eq!(
        shared.frames_write_stalled.load(Ordering::Relaxed),
        0,
        "a keeping-up consumer must never trip the backlog cap"
    );
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        0,
        "a keeping-up consumer must see zero drops"
    );
}

#[test]
fn test_lossless_send_waits_for_capacity() {
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    shared.connected.store(true, Ordering::Release);
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert!(handle.try_send(EventFrame::encode_drain_complete(1)));

    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let (attempt_tx, attempt_rx) = mpsc::sync_channel::<()>(0);
    let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(0);
    let (hold_tx, hold_rx) = mpsc::sync_channel::<()>(0);

    let consumer_join = thread::spawn(move || {
        release_rx.recv().expect("release consumer");
        rx.recv().expect("drain queued frame");
        hold_rx
            .recv()
            .expect("hold consumer open until sender finishes");
    });

    let sender_handle = handle.clone();
    let sender_join = thread::spawn(move || {
        attempt_tx
            .send(())
            .expect("notify that lossless send is about to start");
        let result = sender_handle.send_frame_lossless(EventFrame::encode_drain_complete(2));
        done_tx.send(result).expect("send lossless result");
    });

    attempt_rx
        .recv()
        .expect("wait for sender thread to begin lossless send");

    assert!(
        done_rx.recv_timeout(Duration::from_millis(20)).is_err(),
        "lossless send should still be waiting while the channel remains full"
    );

    release_tx.send(()).expect("allow consumer to drain");

    done_rx
        .recv_timeout(Duration::from_millis(100))
        .expect("lossless send should finish once capacity is available")
        .expect("lossless send should wait for capacity");

    hold_tx.send(()).expect("release consumer thread");
    sender_join.join().expect("sender thread");
    consumer_join.join().expect("consumer thread");
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 2);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 0);
}

// #2874: the HA session-sync delta must route through the LOSSLESS producer
// (which surfaces a queue failure) while RT_FLOW telemetry stays best-effort
// (silently drops on a full channel). This documents the lossless-vs-telemetry
// split that `flush_session_deltas` relies on.
#[test]
fn session_delta_lossless_surfaces_failure_while_telemetry_drops() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new()); // connected=false
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };
    let zone_map = FxHashMap::default();
    let open = test_close_delta(crate::session::SessionDeltaKind::Open);

    // Session-sync delta: lossless surfaces the failure (NOT silently dropped).
    let err = handle
        .push_delta_lossless(&open, &zone_map)
        .expect_err("session-sync delta must not be silently dropped");
    assert!(err.contains("not connected"), "unexpected error: {err}");

    // Telemetry stays best-effort: try_send fills then silently drops.
    assert!(
        handle.try_send(EventFrame::encode_drain_complete(1)),
        "first telemetry frame fills the channel"
    );
    assert!(
        !handle.try_send(EventFrame::encode_drain_complete(2)),
        "telemetry frame must silently drop on a full channel"
    );
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        1,
        "the silently-dropped telemetry frame is counted in frames_dropped"
    );
}

#[test]
fn test_lossless_send_fails_when_not_connected() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle { tx, shared };

    let err = handle
        .send_frame_lossless(EventFrame::encode_drain_complete(1))
        .expect_err("lossless send should fail when disconnected");
    assert!(err.contains("not connected"));
}

#[test]
fn test_partial_read_accumulation() {
    // Simulate a partial Unix stream read: first 8 bytes, then the
    // remaining 8 bytes of a 16-byte ACK frame.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    // Seed replay buffer so we can observe the trim from the ACK.
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    // next_seq reflects the highest allocated seq so the ACK is in-range
    // for the #2959 watermark validation.
    shared.next_seq.store(5, Ordering::Relaxed);

    let raw = build_raw_ack_frame(3);
    let mut ctrl_buf: Vec<u8> = Vec::new();

    // We don't have a real stream for this unit test, so call
    // process_control_frames directly with partial data.

    // First "read": only the first 8 bytes arrive.
    ctrl_buf.extend_from_slice(&raw[..8]);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, 0, "partial frame must not be consumed");
    // Replay buffer untouched -- no ACK processed yet
    assert_eq!(replay_buf.len(), 5);

    // Second "read": remaining 8 bytes arrive.
    ctrl_buf.extend_from_slice(&raw[8..]);
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    // ACK seq=3 should have trimmed frames 1,2,3
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(replay_buf.front().unwrap().seq, 4);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 3);

    // Drain consumed bytes as the real loop would.
    ctrl_buf.drain(..consumed);
    assert!(ctrl_buf.is_empty());
}

#[test]
fn test_two_frames_in_one_read() {
    // Two complete ACK frames arrive in a single read.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(10, Ordering::Relaxed);

    let ack5 = build_raw_ack_frame(5);
    let ack8 = build_raw_ack_frame(8);
    let mut ctrl_buf: Vec<u8> = Vec::new();
    ctrl_buf.extend_from_slice(&ack5);
    ctrl_buf.extend_from_slice(&ack8);

    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, 2 * FRAME_HEADER_SIZE);
    // ACK 5, then ACK 8 -- replay should have frames 9,10
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 8);
}

#[test]
fn test_one_and_half_frames() {
    // 1.5 frames: one complete ACK + first 4 bytes of next frame.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(5, Ordering::Relaxed);

    let ack2 = build_raw_ack_frame(2);
    let ack4 = build_raw_ack_frame(4);
    let mut ctrl_buf: Vec<u8> = Vec::new();
    ctrl_buf.extend_from_slice(&ack2);
    ctrl_buf.extend_from_slice(&ack4[..4]); // partial second frame

    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE); // only first frame consumed
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 2);
    assert_eq!(replay_buf.len(), 3); // frames 3,4,5 remain

    // Drain consumed, then "read" remaining bytes of second frame.
    ctrl_buf.drain(..consumed);
    assert_eq!(ctrl_buf.len(), 4);
    ctrl_buf.extend_from_slice(&ack4[4..]);

    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 4);
    assert_eq!(replay_buf.len(), 1); // only frame 5 remains
}

#[test]
fn test_future_ack_beyond_next_seq_ignored_2959() {
    // A daemon ACKs a sequence the helper never allocated (seq > next_seq).
    // The helper must fail closed: leave acked_seq and the replay buffer
    // intact and bump invalid_acks.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    // Highest allocated seq is 5; ACK 99 is impossible.
    shared.next_seq.store(5, Ordering::Relaxed);
    shared.acked_seq.store(2, Ordering::Relaxed);

    let raw = build_raw_ack_frame(99);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&raw, &shared, &rx, &sock_a, &mut replay_buf);

    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE, "frame is still consumed");
    // Watermark unchanged, replay buffer fully intact (no frames suppressed).
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 2);
    assert_eq!(replay_buf.len(), 5, "future ACK must not trim replay buffer");
    assert_eq!(replay_buf.front().unwrap().seq, 1);
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 1);
}

#[test]
fn test_backward_ack_below_watermark_ignored_2959() {
    // A daemon ACKs a sequence below the current watermark. The helper must
    // ignore it: acked_seq stays put and the replay buffer is untouched.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 6..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(10, Ordering::Relaxed);
    shared.acked_seq.store(5, Ordering::Relaxed);

    let raw = build_raw_ack_frame(3); // below acked_seq=5
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&raw, &shared, &rx, &sock_a, &mut replay_buf);

    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 5, "watermark intact");
    assert_eq!(replay_buf.len(), 5, "backward ACK must not trim replay buffer");
    assert_eq!(replay_buf.front().unwrap().seq, 6);
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 1);
}

#[test]
fn test_future_ack_does_not_suppress_lower_buffered_frames_2959() {
    // The core impact in #2959: an ACK above next_seq while the replay buffer
    // holds lower-seq frames must NOT trim/suppress those lower frames.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=3u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(3, Ordering::Relaxed);
    shared.acked_seq.store(0, Ordering::Relaxed);

    // ACK 7 is beyond next_seq=3; without validation this would pop all three
    // buffered frames (1,2,3 <= 7) and store an impossible acked_seq=7.
    let raw = build_raw_ack_frame(7);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, _consumed) =
        process_control_frames(&raw, &shared, &rx, &sock_a, &mut replay_buf);

    assert!(action.is_none());
    assert_eq!(replay_buf.len(), 3, "lower buffered frames must survive");
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 0);
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 1);
}

#[test]
fn test_valid_acks_trim_as_before_no_regression_2959() {
    // Boundary cases that MUST still be accepted:
    //   - seq == acked_seq (duplicate ACK, benign no-op)
    //   - acked < seq < next (normal forward ACK, trims)
    //   - seq == next_seq (ACK of the latest allocated frame)
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(5, Ordering::Relaxed);
    shared.acked_seq.store(0, Ordering::Relaxed);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    // Duplicate ACK of the current watermark (0): benign no-op, no trim.
    let dup = build_raw_ack_frame(0);
    process_control_frames(&dup, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 0);

    // Normal forward ACK of 3: trims frames 1,2,3.
    let ack3 = build_raw_ack_frame(3);
    process_control_frames(&ack3, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 3);
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(replay_buf.front().unwrap().seq, 4);

    // ACK of the latest allocated seq (== next_seq=5): trims the rest.
    let ack5 = build_raw_ack_frame(5);
    process_control_frames(&ack5, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 5);
    assert_eq!(replay_buf.len(), 0);

    // No invalid ACKs were recorded across the valid sequence.
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 0);
}

// Build a benign header-only replay frame (MSG_SESSION_OPEN type) carrying the
// given seq. Used so drain replay frames are NOT mistaken for the type-8
// DrainComplete signal under test.
fn replay_seq_frame(seq: u64) -> EventFrame {
    let mut data = [0u8; 256];
    // payload_len = 0, msg_type = MSG_SESSION_OPEN (1)
    data[4] = super::codec::MSG_SESSION_OPEN;
    data[8..16].copy_from_slice(&seq.to_le_bytes());
    EventFrame {
        data,
        len: FRAME_HEADER_SIZE as u16,
        seq,
    }
}

// Helper: read one wire frame header from a stream (header-only frames).
// Returns (msg_type, seq) or None if no frame arrives within the read timeout.
fn try_read_frame_header(stream: &mut std::os::unix::net::UnixStream) -> Option<(u8, u64)> {
    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {
            let payload_len =
                u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
            // Consume any payload so the next header read is aligned.
            if payload_len > 0 {
                let mut sink = vec![0u8; payload_len];
                stream.read_exact(&mut sink).ok()?;
            }
            let msg_type = hdr[4];
            let seq = u64::from_le_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]);
            Some((msg_type, seq))
        }
        Err(_) => None,
    }
}

// #2876 fail-on-revert guard (Rust helper side): when the drain channel never
// reaches the target fence, handle_drain_request must time out and WITHHOLD
// DrainComplete -- it must NOT emit a DrainComplete carrying a below-target seq.
// This goes RED if the `reached_target` gate is removed and the helper falls
// back to sending DrainComplete with replay_buf.back().seq below the fence.
#[test]
fn test_drain_below_fence_withholds_drain_complete() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Channel holds only seq 3, but the fence target is 5: the drain can never
    // reach the fence and must time out (200ms) below it.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    tx.send(replay_seq_frame(3)).unwrap();

    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // No DrainComplete must reach the daemon side.
    if let Some((msg_type, seq)) = try_read_frame_header(&mut daemon_side) {
        // The replayed frame (seq 3) may be written, but a DrainComplete must
        // never appear below the fence. Walk any non-drain frames first.
        let mut t = msg_type;
        let mut s = seq;
        loop {
            assert_ne!(
                t, MSG_DRAIN_COMPLETE,
                "helper emitted DrainComplete seq {} below fence 5 (#2876 regression)",
                s
            );
            match try_read_frame_header(&mut daemon_side) {
                Some((nt, ns)) => {
                    t = nt;
                    s = ns;
                }
                None => break,
            }
        }
    }
}

// #2876: when the channel reaches the fence, handle_drain_request must emit a
// DrainComplete whose seq is >= the target.
#[test]
fn test_drain_at_fence_emits_drain_complete() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    for seq in 1..=5u64 {
        tx.send(replay_seq_frame(seq)).unwrap();
    }

    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // Drain frames until we observe the DrainComplete at/above the fence.
    let mut saw_complete = false;
    while let Some((msg_type, seq)) = try_read_frame_header(&mut daemon_side) {
        if msg_type == MSG_DRAIN_COMPLETE {
            assert!(
                seq >= 5,
                "DrainComplete seq {} must be >= fence 5",
                seq
            );
            saw_complete = true;
            break;
        }
    }
    assert!(saw_complete, "helper did not emit DrainComplete at fence");
}

// #2882 fail-on-revert guard: DrainRequest is contracted as "flush all
// buffered events UP TO target seq". With a replay buffer holding seqs 1..=10
// and a fence target of 5, handle_drain_request must write ONLY seqs 1..=5 and
// report DrainComplete == 5 (the fence) — not every buffered frame and not
// replay_buf.back().seq (10). Reverting the `frame.seq <= target_seq` filter
// makes 6..=10 leak onto the wire; reverting the drain_seq fix reports 10 ->
// either makes this RED.
#[test]
fn test_drain_filters_to_target_and_reports_target_2882() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());

    // Buffer holds frames newer than the fence (1..=10, fence = 5).
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=10u64 {
        replay_buf.push_back(replay_seq_frame(seq));
    }
    // Keep tx alive so the drain loop sees Empty (not Disconnected) and reaches
    // the fence via replay_buf.back().seq (10) >= target (5).
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);

    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // Collect everything the helper wrote until DrainComplete.
    let mut data_seqs: Vec<u64> = Vec::new();
    let mut drain_complete_seq: Option<u64> = None;
    while let Some((msg_type, seq)) = try_read_frame_header(&mut daemon_side) {
        if msg_type == MSG_DRAIN_COMPLETE {
            drain_complete_seq = Some(seq);
            break;
        }
        data_seqs.push(seq);
    }

    assert_eq!(
        data_seqs,
        vec![1, 2, 3, 4, 5],
        "drain must write only frames with seq <= target fence (#2882)"
    );
    assert_eq!(
        drain_complete_seq,
        Some(5),
        "DrainComplete must report the fence target, not replay_buf.back().seq (#2882)"
    );
}

// Fill a nonblocking socket's send buffer so subsequent writes return
// WouldBlock. Used to simulate a daemon that connected but stopped reading.
fn fill_send_buffer(stream: &std::os::unix::net::UnixStream) {
    let junk = [0u8; 65536];
    loop {
        match (&*stream).write(&junk) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

// #2877 fail-on-revert guard: a daemon that connects but stops reading must NOT
// wedge the I/O thread during REPLAY. With the old blocking `write_all`
// (set_nonblocking(false)) the replay write blocks forever on a full socket and
// cannot observe the stop flag, so `EventStreamSender::stop` (which joins the
// I/O thread) hangs. The fixed `write_all_backpressured` keeps the socket
// nonblocking and polls `shared.stop`, so replay returns promptly once stop is
// raised. Reverting to the blocking write makes this time out -> RED.
#[test]
fn test_replay_does_not_wedge_on_stuck_reader_2877() {
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    // Daemon never reads -> fill the send buffer so every write WouldBlocks.
    fill_send_buffer(&helper_side);

    let shared = Arc::new(EventStreamShared::new());
    // One buffered frame to replay (seq 1 > acked 0, no gap).
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    replay_buf.push_back(replay_seq_frame(1));

    let (done_tx, done_rx) = mpsc::channel::<bool>();
    let h_shared = shared.clone();
    let handle = thread::spawn(move || {
        let r = replay_buffered(&helper_side, &mut replay_buf, 0, &h_shared);
        done_tx.send(r.is_err()).ok();
    });

    // Let the replay write block on the full socket, then ask the helper to
    // stop. A stop-aware writer must observe this within one poll interval.
    thread::sleep(Duration::from_millis(50));
    shared.stop.store(true, Ordering::Release);

    let completed = done_rx.recv_timeout(Duration::from_secs(2));
    assert!(
        completed.is_ok(),
        "replay wedged on a stuck reader and never observed stop (#2877 regression)"
    );
    assert!(
        completed.unwrap(),
        "replay against a stuck/stopping reader must return Err, not succeed"
    );

    drop(daemon_side);
    let _ = handle.join();
}

// #2877 fail-on-revert guard: a stuck daemon reader must NOT wedge the I/O
// thread during DRAIN either. handle_drain_request used to flip the socket to
// blocking and `write_all` all frames; on a full socket that blocks forever and
// the stop flag is never seen. The fixed path uses `write_all_backpressured`,
// which bails on stop. Reverting makes this time out -> RED.
#[test]
fn test_drain_does_not_wedge_on_stuck_reader_2877() {
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    fill_send_buffer(&helper_side);

    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=3u64 {
        replay_buf.push_back(replay_seq_frame(seq));
    }
    // Keep `tx` alive so the drain loop sees Empty (not Disconnected) and
    // reaches the fence via replay_buf.back().seq (3) >= target (3).
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);

    let (done_tx, done_rx) = mpsc::channel::<()>();
    let h_shared = shared.clone();
    let handle = thread::spawn(move || {
        handle_drain_request(3, &rx, &helper_side, &h_shared, &mut replay_buf);
        done_tx.send(()).ok();
    });

    thread::sleep(Duration::from_millis(50));
    shared.stop.store(true, Ordering::Release);

    assert!(
        done_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "drain wedged on a stuck reader and never observed stop (#2877 regression)"
    );

    drop(daemon_side);
    let _ = handle.join();
}

// #2883 fail-on-revert guard: the idle keepalive must ride the normal write_buf
// backpressure path. The old code called write_all directly on the nonblocking
// socket and returned true (immediate reconnect) on ANY error, including
// WouldBlock when the kernel send buffer is full under a slow reader. Here a
// connected daemon stops reading (send buffer filled) and the keepalive fires
// (interval 0): the fixed loop enqueues it into write_buf as ordinary
// backpressure and keeps running; the old loop reconnects. We assert the loop
// does NOT report reconnect. Reverting to the write_all + `return true`
// keepalive makes the loop return true -> RED.
#[test]
fn test_idle_keepalive_wouldblock_is_backpressure_not_reconnect_2883() {
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    // Daemon connects but never reads -> fill the send buffer so the keepalive
    // write returns WouldBlock.
    fill_send_buffer(&helper_side);

    // Empty channel + alive tx -> the connected loop is idle (no data frames),
    // so the idle keepalive path is exercised.
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let shared = Arc::new(EventStreamShared::new());

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        // keepalive_interval 0 -> the keepalive fires as soon as the loop is
        // idle, against the already-full socket.
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            Duration::from_millis(0),
        )
    });

    // Give the idle keepalive several chances to fire against the full socket.
    // The buggy write_all keepalive would have reconnected (returned true) by
    // now; the fixed path keeps running as backpressure.
    thread::sleep(Duration::from_millis(200));
    shared.stop.store(true, Ordering::Release);
    let reconnect = loop_join.join().expect("connected loop thread");

    assert!(
        !reconnect,
        "idle keepalive WouldBlock must be backpressure, not a fatal reconnect (#2883)"
    );
    drop(daemon_side);
}

// ---------------------------------------------------------------------------
// #2875 — paused-demotion drain must not silently lose session-sync deltas
// ---------------------------------------------------------------------------

// Build a benign header-only TELEMETRY frame (RT_FLOW screen-drop type) so we
// can prove that evicting it while paused does NOT poison the drain. Unlike
// `replay_seq_frame` (a SESSION_OPEN), this msg_type is not a session-sync
// delta, so `EventFrame::is_session_sync()` returns false for it.
fn telemetry_seq_frame(seq: u64) -> EventFrame {
    let mut data = [0u8; 256];
    data[4] = super::codec::MSG_SCREEN_DROP;
    data[8..16].copy_from_slice(&seq.to_le_bytes());
    EventFrame {
        data,
        len: FRAME_HEADER_SIZE as u16,
        seq,
    }
}

// #2875 fail-on-revert guard: pause the helper, overrun the bounded replay
// buffer so a SESSION-SYNC delta is evicted, then issue DrainRequest. The drain
// MUST be poisoned — it withholds DrainComplete and emits a FullResync instead,
// forcing the daemon to full-resync rather than complete demotion with lost
// session mutations. Reverting the poison gate makes the helper emit
// DrainComplete here -> this goes RED.
#[test]
fn test_paused_session_eviction_poisons_drain_2875() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Fill the replay buffer to capacity with SESSION-SYNC deltas (no eviction
    // yet: the buffer holds exactly REPLAY_BUFFER_CAPACITY frames).
    for seq in 1..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(&shared, &mut replay_buf, replay_seq_frame(seq));
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert!(!shared.session_evicted_while_paused.load(Ordering::Acquire));

    // Demotion pause window begins, then one more session delta arrives and
    // evicts the OLDEST session frame (seq 1) — a lost session mutation.
    shared.paused.store(true, Ordering::Release);
    push_replay_frame(
        &shared,
        &mut replay_buf,
        replay_seq_frame(REPLAY_BUFFER_CAPACITY as u64 + 1),
    );
    assert!(
        shared.session_evicted_while_paused.load(Ordering::Acquire),
        "evicting a session delta while paused must poison the drain (#2875)"
    );

    // Keep tx alive so the drain loop sees Empty (not Disconnected) and reaches
    // the fence via replay_buf.back().seq >= target.
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // The daemon must observe a FullResync and NEVER a DrainComplete.
    let mut saw_full_resync = false;
    while let Some((msg_type, _seq)) = try_read_frame_header(&mut daemon_side) {
        assert_ne!(
            msg_type, MSG_DRAIN_COMPLETE,
            "poisoned drain must NOT report DrainComplete (#2875 regression)"
        );
        if msg_type == MSG_FULL_RESYNC {
            saw_full_resync = true;
        }
    }
    assert!(
        saw_full_resync,
        "poisoned drain must emit a FullResync so the daemon full-resyncs (#2875)"
    );
    // Poison is consumed once the resync is sent.
    assert!(!shared.session_evicted_while_paused.load(Ordering::Acquire));
}

// #2875: a TELEMETRY-only eviction while paused must NOT poison the drain — the
// drain still completes normally (no spurious FullResync / FullResync storm).
#[test]
fn test_paused_telemetry_eviction_does_not_poison_drain_2875() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Fill to capacity with TELEMETRY frames, then evict one while paused.
    for seq in 1..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(&shared, &mut replay_buf, telemetry_seq_frame(seq));
    }
    shared.paused.store(true, Ordering::Release);
    push_replay_frame(
        &shared,
        &mut replay_buf,
        telemetry_seq_frame(REPLAY_BUFFER_CAPACITY as u64 + 1),
    );
    assert!(
        !shared.session_evicted_while_paused.load(Ordering::Acquire),
        "telemetry eviction while paused must NOT poison the drain (#2875)"
    );

    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // The drain must complete normally — DrainComplete present, no FullResync.
    let mut saw_complete = false;
    while let Some((msg_type, _seq)) = try_read_frame_header(&mut daemon_side) {
        assert_ne!(
            msg_type, MSG_FULL_RESYNC,
            "telemetry eviction must not cause a spurious FullResync (#2875)"
        );
        if msg_type == MSG_DRAIN_COMPLETE {
            saw_complete = true;
        }
    }
    assert!(
        saw_complete,
        "non-poisoned drain must still report DrainComplete (#2875)"
    );
}

// #2875: a fresh pause window must start lossless — MSG_PAUSE clears any poison
// left by a previous drain so a stale flag cannot withhold this window's
// DrainComplete.
#[test]
fn test_pause_start_clears_drain_poison_2875() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    // Simulate a leftover poison from a prior window.
    shared
        .session_evicted_while_paused
        .store(true, Ordering::Release);

    // A PAUSE control frame must clear it.
    let mut pause = [0u8; FRAME_HEADER_SIZE];
    pause[4] = MSG_PAUSE;
    let (action, consumed) =
        process_control_frames(&pause, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert!(shared.paused.load(Ordering::Acquire));
    assert!(
        !shared.session_evicted_while_paused.load(Ordering::Acquire),
        "MSG_PAUSE must clear stale drain poison (#2875)"
    );
}

// ---------------------------------------------------------------------------
// #2879 — daemon→helper control frames must have a bounded payload
// ---------------------------------------------------------------------------

// Build a control header with an arbitrary payload_len and opcode.
fn build_ctrl_header(payload_len: u32, msg_type: u8) -> [u8; FRAME_HEADER_SIZE] {
    let mut buf = [0u8; FRAME_HEADER_SIZE];
    buf[0..4].copy_from_slice(&payload_len.to_le_bytes());
    buf[4] = msg_type;
    buf
}

// #2879 fail-on-revert guard: a daemon that declares payload_len = 1<<30 and
// trickles bytes must be DISCONNECTED before the helper buffers the (never
// completing) frame, so ctrl_read_buf cannot grow without bound. Reverting the
// cap makes process_control_frames return (None, 0) — incomplete-frame break —
// and the bytes accumulate -> this goes RED.
#[test]
fn test_oversized_control_payload_disconnects_2879() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    let mut ctrl: Vec<u8> = Vec::new();
    ctrl.extend_from_slice(&build_ctrl_header(1u32 << 30, MSG_PAUSE));
    // Trickle a few payload bytes — far short of 1<<30.
    ctrl.extend_from_slice(&[0u8; 8]);

    let (action, _consumed) =
        process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(
        action,
        Some(true),
        "oversized payload_len must force a disconnect, not unbounded buffering (#2879)"
    );
    // The bogus PAUSE frame must NOT have been processed before the disconnect.
    assert!(
        !shared.paused.load(Ordering::Acquire),
        "an invalid oversized frame must not be applied (#2879)"
    );
}

// #2879: the current daemon→helper opcodes (Ack/Pause/Resume/DrainRequest) are
// header-only; a NONZERO payload_len on any of them is invalid and must be
// rejected (disconnect).
#[test]
fn test_nonzero_payload_on_header_only_opcodes_rejected_2879() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    for opcode in [MSG_ACK, MSG_PAUSE, MSG_RESUME, MSG_DRAIN_REQUEST] {
        let mut ctrl: Vec<u8> = Vec::new();
        // payload_len = 8 (nonzero) plus 8 payload bytes so the frame is fully
        // present — proving the rejection is on the length, not on completeness.
        ctrl.extend_from_slice(&build_ctrl_header(8, opcode));
        ctrl.extend_from_slice(&[0u8; 8]);
        let (action, _consumed) =
            process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
        assert_eq!(
            action,
            Some(true),
            "nonzero payload on header-only opcode {opcode} must be rejected (#2879)"
        );
    }
}

// #2879 no-regression: a legitimate header-only control frame whose HEADER is
// split across two reads must still parse once complete — the cap only rejects
// an invalid payload_len, never a merely-incomplete header.
#[test]
fn test_split_header_only_frame_still_parses_2879() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    let header = build_ctrl_header(0, MSG_PAUSE); // header-only, zero payload
    let mut ctrl: Vec<u8> = Vec::new();

    // First read: only the first 8 bytes of the 16-byte header.
    ctrl.extend_from_slice(&header[..8]);
    let (action, consumed) =
        process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none(), "partial header must not disconnect (#2879)");
    assert_eq!(consumed, 0, "partial header must not be consumed");
    assert!(!shared.paused.load(Ordering::Acquire));

    // Second read: the rest of the header arrives; the PAUSE now applies.
    ctrl.extend_from_slice(&header[8..]);
    let (action, consumed) =
        process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert!(
        shared.paused.load(Ordering::Acquire),
        "a header-only frame split across reads must still parse (#2879)"
    );
}
