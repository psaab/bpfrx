use super::*;
use crate::event_stream::EventStreamWorkerHandle;
use crate::event_stream::codec::{DataplaneEventKind, DataplaneEventPayload};
use crate::filter::FilterAction;
use crate::policy::{AppCatalog, PolicyAction};
use crate::screen::ScreenPacketInfo;

const RT_FLOW_ACTION_DENY: u8 = 0;
const RT_FLOW_ACTION_PERMIT: u8 = 1;
const RT_FLOW_ACTION_REJECT: u8 = 2;
const RT_FLOW_CLOSE_REASON_POLICY: u8 = 5;
const NS_PER_SEC: u64 = 1_000_000_000;

const SCREEN_SYN_FLOOD: u32 = 1 << 0;
const SCREEN_ICMP_FLOOD: u32 = 1 << 1;
const SCREEN_UDP_FLOOD: u32 = 1 << 2;
const SCREEN_PORT_SCAN: u32 = 1 << 3;
const SCREEN_IP_SWEEP: u32 = 1 << 4;
const SCREEN_LAND_ATTACK: u32 = 1 << 5;
const SCREEN_PING_OF_DEATH: u32 = 1 << 6;
const SCREEN_TEARDROP: u32 = 1 << 7;
const SCREEN_TCP_SYN_FIN: u32 = 1 << 8;
const SCREEN_TCP_NO_FLAG: u32 = 1 << 9;
const SCREEN_TCP_FIN_NO_ACK: u32 = 1 << 10;
const SCREEN_WINNUKE: u32 = 1 << 11;
const SCREEN_IP_SOURCE_ROUTE: u32 = 1 << 12;
const SCREEN_SYN_FRAG: u32 = 1 << 13;
const SCREEN_SYN_COOKIE: u32 = 1 << 14;
const SCREEN_SESSION_LIMIT_SRC: u32 = 1 << 15;
const SCREEN_SESSION_LIMIT_DST: u32 = 1 << 16;
const SCREEN_ICMP_FRAGMENT: u32 = 1 << 17;
/// #2146: a frame whose L3 header could not be parsed far enough to
/// evaluate the fragment/TCP screens (e.g. a truncated IPv6
/// extension-header chain) is dropped FAIL-CLOSED under this reason.
const SCREEN_IP_MALFORMED: u32 = 1 << 18;
/// #2234: NOT a packet drop — a rare (logarithmic) operator ALARM that the
/// per-zone scan/sweep source table is saturated and the detector is
/// displacing stale sources (bounded stalest-eviction) to keep tracking a
/// fresh real scanner under a high-cardinality spoofed flood. Rides the
/// screen event path so it surfaces alongside other screen activity; the
/// triggering 5-tuple is the new source that forced an eviction.
const SCREEN_SCAN_TABLE_PRESSURE: u32 = 1 << 19;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FilterLogSource {
    Pbr,
    Input,
    Output,
    CachedOutput,
    Lo0,
}

impl FilterLogSource {
    #[inline]
    pub(super) fn wire_reason(self) -> u8 {
        match self {
            Self::Pbr => 1,
            Self::Input => 2,
            Self::Output => 3,
            Self::CachedOutput => 4,
            Self::Lo0 => 5,
        }
    }
}

#[inline]
pub(super) fn event_now_ns_from_secs(now_secs: u64) -> u64 {
    now_secs.saturating_mul(NS_PER_SEC)
}

/// #2520: resolve the AppID for a cold-path RT_FLOW record (policy-deny /
/// filter-log / session-close) from the flow 5-tuple, reusing the SAME
/// `app_catalog.lookup` the forwarding hot path runs when it stamps the
/// conntrack entry (`poll_descriptor` session-create:
/// `worker_ctx.forwarding.app_catalog.lookup(protocol, src_port, dst_port)`).
/// There is no duplicated resolution logic — the catalog probes both port
/// slots so a forward- or reverse-keyed tuple resolves to the same app_id.
/// Returns 0 (UNKNOWN) when nothing matches, which the Go RT_FLOW logger
/// renders as `application="UNKNOWN"` — the unchanged behavior for an
/// unresolvable tuple.
#[inline]
pub(super) fn resolve_flow_app_id(app_catalog: &AppCatalog, flow: &SessionFlow) -> u16 {
    app_catalog.lookup(
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
    )
}

#[inline]
pub(super) fn emit_policy_deny_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    owner_rg_id: i32,
    policy_id: u32,
    action: PolicyAction,
    app_id: u16,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::PolicyDeny,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        action: policy_action_to_rt_flow(action),
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id,
        rule_id: policy_id,
        term_id: 0,
        reason: RT_FLOW_CLOSE_REASON_POLICY,
        owner_rg_id: owner_rg_id_to_wire(owner_rg_id),
        // #2520: carry the resolved AppID (the caller runs the same
        // app_catalog.lookup the hot path uses) so policy-deny RT_FLOW
        // records show the resolved application instead of UNKNOWN.
        application_id: app_id,
        filter_id: 0,
        screen_id: 0,
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns)
        // here at emit time so a backlogged Go-side delivery cannot skew the
        // logged event time to consumption time. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

#[inline]
pub(super) fn emit_screen_drop_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    pkt: &ScreenPacketInfo,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    reason: &'static str,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::ScreenDrop,
        addr_family: pkt.addr_family,
        protocol: pkt.protocol,
        action: RT_FLOW_ACTION_DENY,
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 0,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id: 0,
        reason: 0,
        owner_rg_id: 0,
        application_id: 0,
        filter_id: 0,
        screen_id: screen_reason_id(reason),
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns) at
        // emit time. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

/// Emit a screen ALARM event — a `ScreenDrop`-kind event that did NOT drop
/// the packet (#2234 scan-table-pressure). It shares the screen event frame
/// so it surfaces alongside other screen activity, but the RT_FLOW action is
/// PERMIT (the flow forwards). The Go consumers classify the screen event by
/// BOTH kind AND action (#2298): a screen event with action=PERMIT is counted
/// as a screen ALARM (not a screen drop) and logged at NOTICE severity (not
/// ERROR), so downstream stats / syslog / dashboards do NOT treat it as a
/// deny/drop. See `pkg/dataplane/userspace/eventstream.go`
/// (`recordDataplaneEvent`) and `pkg/logging/ringbuf.go` (`eventSeverity`).
/// The `reason` maps to a dedicated `screen_id` bit; the 5-tuple is the source
/// that forced an eviction.
#[inline]
pub(super) fn emit_screen_alarm_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    pkt: &ScreenPacketInfo,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    reason: &'static str,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::ScreenDrop,
        addr_family: pkt.addr_family,
        protocol: pkt.protocol,
        // PERMIT — this is a saturation alarm, not a drop. The packet still
        // forwards; reporting DENY here would inflate drop/deny counters.
        action: RT_FLOW_ACTION_PERMIT,
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 0,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id: 0,
        reason: 0,
        owner_rg_id: 0,
        application_id: 0,
        filter_id: 0,
        screen_id: screen_reason_id(reason),
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns) at
        // emit time, same as the screen-drop path. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

/// Build a minimal `ScreenPacketInfo` describing an L3 header that the
/// screen extractor could NOT parse (#2146 fail-closed path). The
/// packet bytes are untrustworthy past L3, so only the fields the
/// upstream metadata/flow parser already resolved are populated —
/// enough for `emit_screen_drop_event` to log the offending 5-tuple.
/// Fragment/TCP fields stay at their conservative defaults; the verdict
/// is already DROP so they are never consulted for a screen decision.
#[inline]
pub(super) fn screen_parse_error_info(
    meta: &UserspaceDpMeta,
    flow: &SessionFlow,
) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: meta.addr_family,
        protocol: meta.protocol,
        tcp_flags: meta.tcp_flags,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: meta.pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 0,
        ip_payload_len: 0,
        frag_data_off: 0,
    }
}

#[inline]
pub(super) fn emit_filter_log_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    filter_id: u32,
    term_id: u32,
    action: FilterAction,
    source: FilterLogSource,
    app_id: u16,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::FilterLog,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        action: filter_action_to_rt_flow(action),
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id,
        reason: source.wire_reason(),
        owner_rg_id: 0,
        // #2520: carry the resolved AppID so filter-log RT_FLOW records show
        // the resolved application instead of UNKNOWN. Same lookup as the hot
        // path (see resolve_flow_app_id).
        application_id: app_id,
        filter_id,
        screen_id: 0,
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns) at
        // emit time. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

#[inline]
fn policy_action_to_rt_flow(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Permit => RT_FLOW_ACTION_PERMIT,
        PolicyAction::Deny => RT_FLOW_ACTION_DENY,
        // #2089: the policy-deny path now synthesizes a TCP RST / ICMP
        // unreachable for `reject` (poll_descriptor reject_reply), so the
        // RT_FLOW action reports reject, matching the wire behavior and
        // Junos. (#2521: filter reject — filter_action_to_rt_flow below —
        // now ALSO synthesizes an active reject reply (RST/ICMP) and maps
        // to RT_FLOW_ACTION_REJECT, same as policy reject; filter DISCARD
        // remains the silent-drop → deny case.)
        PolicyAction::Reject => RT_FLOW_ACTION_REJECT,
    }
}

#[inline]
fn filter_action_to_rt_flow(action: FilterAction) -> u8 {
    match action {
        FilterAction::Accept => RT_FLOW_ACTION_PERMIT,
        FilterAction::Discard => RT_FLOW_ACTION_DENY,
        // #2521: filter `then reject` now synthesizes an active reply (TCP
        // RST / ICMP unreachable) via the same path as policy reject
        // (poll_descriptor enqueue_filter_reject_reply), so RT_FLOW reports
        // reject — matching the wire behavior and Junos, like
        // policy_action_to_rt_flow above. `discard` stays a silent drop →
        // deny.
        FilterAction::Reject => RT_FLOW_ACTION_REJECT,
    }
}

#[inline]
fn ingress_ifindex_to_wire(ifindex: u32) -> i32 {
    ifindex.min(i32::MAX as u32) as i32
}

#[inline]
fn owner_rg_id_to_wire(owner_rg_id: i32) -> i16 {
    owner_rg_id.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

#[inline]
fn screen_reason_id(reason: &'static str) -> u32 {
    match reason {
        "syn-flood" => SCREEN_SYN_FLOOD,
        "icmp-flood" => SCREEN_ICMP_FLOOD,
        "udp-flood" => SCREEN_UDP_FLOOD,
        "port-scan" => SCREEN_PORT_SCAN,
        "ip-sweep" => SCREEN_IP_SWEEP,
        "land-attack" => SCREEN_LAND_ATTACK,
        "ping-of-death" => SCREEN_PING_OF_DEATH,
        "teardrop" => SCREEN_TEARDROP,
        "tcp-syn-fin" => SCREEN_TCP_SYN_FIN,
        "tcp-no-flag" => SCREEN_TCP_NO_FLAG,
        "tcp-fin-no-ack" => SCREEN_TCP_FIN_NO_ACK,
        "winnuke" => SCREEN_WINNUKE,
        "ip-source-route" => SCREEN_IP_SOURCE_ROUTE,
        "syn-frag" => SCREEN_SYN_FRAG,
        "syn-cookie" | "syn-cookie-unavailable" => SCREEN_SYN_COOKIE,
        "session-limit-src" => SCREEN_SESSION_LIMIT_SRC,
        "session-limit-dst" => SCREEN_SESSION_LIMIT_DST,
        "icmp-fragment" => SCREEN_ICMP_FRAGMENT,
        "ip-malformed" => SCREEN_IP_MALFORMED,
        "scan-table-pressure" => SCREEN_SCAN_TABLE_PRESSURE,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_stream::codec::DataplaneEventKind;
    use crate::event_stream::{DataplaneEventRateLimitConfig, EventStreamWorkerHandle};
    use crate::session::SessionKey;
    use std::net::{IpAddr, Ipv4Addr};

    /// A real CLOCK_MONOTONIC reading, mirroring what the worker poll loop
    /// hands the emitters as `now_ns`. The emitters convert this to a
    /// wall-clock Unix ns at emit time (#2470), so a realistic monotonic
    /// instant is required for the conversion to produce a present-day
    /// timestamp (a tiny synthetic value like `123` converts to ~0 because it
    /// reads as an "ancient" monotonic instant).
    fn mono_now_ns() -> u64 {
        crate::afxdp::neighbor::monotonic_nanos()
    }

    fn test_flow() -> SessionFlow {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        SessionFlow {
            src_ip,
            dst_ip,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip,
                dst_ip,
                src_port: 49152,
                dst_port: 443,
            },
        }
    }

    fn test_meta() -> UserspaceDpMeta {
        UserspaceDpMeta {
            ingress_ifindex: 42,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            pkt_len: 60,
            ..UserspaceDpMeta::default()
        }
    }

    fn unlimited_handle() -> (
        EventStreamWorkerHandle,
        std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
    ) {
        crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        )
    }

    #[test]
    fn policy_deny_event_emit_builds_rt_flow_payload() {
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        emit_policy_deny_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            9,
            3,
            101,
            PolicyAction::Deny,
            0,
            mono_now_ns(),
        );

        let event = rx
            .try_recv()
            .expect("policy event frame")
            .decode_dataplane_event()
            .expect("policy event payload");
        assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
        assert_eq!(event.action, RT_FLOW_ACTION_DENY);
        assert_eq!(event.reason, RT_FLOW_CLOSE_REASON_POLICY);
        assert_eq!(event.ingress_zone_id, 7);
        assert_eq!(event.egress_zone_id, 9);
        assert_eq!(event.ingress_ifindex, 42);
        assert_eq!(event.policy_id, 101);
        assert_eq!(event.rule_id, 101);
        assert_eq!(event.owner_rg_id, 3);
        assert_eq!(event.src_port, 49152);
        assert_eq!(event.dst_port, 443);
        // #2470 fail-on-revert: the emitter stamps the dataplane DECISION
        // instant (wall-clock Unix ns) on the wire instead of 0. Reverting
        // `timestamp_ns` back to 0 makes the Go side fall back to RECEIVE
        // time; this assertion fails in that case.
        assert!(
            event.timestamp_ns > 0,
            "policy-deny event must carry a real wall-clock timestamp, got 0"
        );
        assert_eq!(handle.dataplane_event_stats().policy_deny.sent, 1);
    }

    #[test]
    fn policy_deny_event_emit_reject_maps_to_reject_action() {
        // #2089: the policy-deny path now synthesizes a TCP RST / ICMP
        // unreachable for `reject`, so the RT_FLOW action must report
        // reject (was deny while reject was a silent drop).
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        emit_policy_deny_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            9,
            3,
            101,
            PolicyAction::Reject,
            0,
            123,
        );

        let event = rx
            .try_recv()
            .expect("policy event frame")
            .decode_dataplane_event()
            .expect("policy event payload");
        assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
        assert_eq!(event.action, RT_FLOW_ACTION_REJECT);
        assert_eq!(event.reason, RT_FLOW_CLOSE_REASON_POLICY);
        assert_eq!(handle.dataplane_event_stats().policy_deny.sent, 1);
    }

    #[test]
    fn screen_drop_event_emit_uses_screen_reason_flag() {
        let (handle, rx) = unlimited_handle();
        let pkt = ScreenPacketInfo {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 12345,
            dst_port: 80,
            tcp_seq: 1,
            tcp_ack: 0,
            tcp_mss: 1460,
            pkt_len: 60,
            is_fragment: false,
            is_first_fragment: false,
            ip_ihl: 5,
            ip_frag_off: 0,
            ip_total_len: 60,
            ip_payload_len: 0,
            frag_data_off: 0,
        };

        emit_screen_drop_event(Some(&handle), &pkt, test_meta(), 11, "land-attack", mono_now_ns());

        let event = rx
            .try_recv()
            .expect("screen event frame")
            .decode_dataplane_event()
            .expect("screen event payload");
        assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
        assert_eq!(event.action, RT_FLOW_ACTION_DENY);
        assert_eq!(event.screen_id, SCREEN_LAND_ATTACK);
        assert_eq!(event.ingress_zone_id, 11);
        assert_eq!(event.egress_zone_id, 0);
        assert_eq!(event.src_ip, pkt.src_ip);
        assert_eq!(event.dst_ip, pkt.dst_ip);
        // #2470 fail-on-revert: a real decision timestamp on the wire.
        assert!(
            event.timestamp_ns > 0,
            "screen-drop event must carry a real wall-clock timestamp, got 0"
        );
        assert_eq!(handle.dataplane_event_stats().screen_drop.sent, 1);
    }

    #[test]
    fn screen_alarm_event_is_permit_not_deny() {
        // #2234 fail-on-revert: the scan-table-pressure ALARM must carry the
        // PERMIT action so downstream stats / syslog / dashboards do NOT count
        // it as a drop/deny (the packet still forwards). Reverting the alarm
        // emitter back to emit_screen_drop_event (action=DENY) breaks this.
        let (handle, rx) = unlimited_handle();
        let pkt = ScreenPacketInfo {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            src_port: 40000,
            dst_port: 443,
            tcp_seq: 1,
            tcp_ack: 0,
            tcp_mss: 1460,
            pkt_len: 60,
            is_fragment: false,
            is_first_fragment: false,
            ip_ihl: 5,
            ip_frag_off: 0,
            ip_total_len: 60,
            ip_payload_len: 0,
            frag_data_off: 0,
        };

        emit_screen_alarm_event(Some(&handle), &pkt, test_meta(), 2, "scan-table-pressure", mono_now_ns());

        let event = rx
            .try_recv()
            .expect("screen alarm frame")
            .decode_dataplane_event()
            .expect("screen alarm payload");
        assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
        assert_eq!(
            event.action, RT_FLOW_ACTION_PERMIT,
            "a pressure ALARM must not report a drop/deny action"
        );
        assert_eq!(event.screen_id, SCREEN_SCAN_TABLE_PRESSURE);
        assert_eq!(event.src_ip, pkt.src_ip);
        assert_eq!(event.dst_ip, pkt.dst_ip);
        // #2470 fail-on-revert: a real decision timestamp on the wire.
        assert!(
            event.timestamp_ns > 0,
            "screen-alarm event must carry a real wall-clock timestamp, got 0"
        );
    }

    #[test]
    fn screen_reason_id_maps_icmp_fragment() {
        let (handle, rx) = unlimited_handle();
        let pkt = ScreenPacketInfo {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            tcp_flags: 0,
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
            src_port: 0,
            dst_port: 0,
            tcp_seq: 0,
            tcp_ack: 0,
            tcp_mss: 0,
            pkt_len: 60,
            is_fragment: true,
            is_first_fragment: false,
            ip_ihl: 5,
            ip_frag_off: 0x2000,
            ip_total_len: 60,
            ip_payload_len: 0,
            frag_data_off: 0,
        };

        emit_screen_drop_event(Some(&handle), &pkt, test_meta(), 11, "icmp-fragment", mono_now_ns());

        let event = rx
            .try_recv()
            .expect("screen event frame")
            .decode_dataplane_event()
            .expect("screen event payload");
        assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
        assert_eq!(event.screen_id, SCREEN_ICMP_FRAGMENT);
    }

    #[test]
    fn screen_reason_id_maps_ip_malformed() {
        // #2146: the fail-closed reason for an unparseable L3 header
        // must map to a dedicated screen_id bit so operators can tell a
        // malformed-frame drop apart from the syn-frag screen.
        assert_eq!(screen_reason_id("ip-malformed"), SCREEN_IP_MALFORMED);
        assert_ne!(SCREEN_IP_MALFORMED, SCREEN_SYN_FRAG);
    }

    #[test]
    fn screen_reason_id_maps_scan_table_pressure() {
        // #2234: the bounded stalest-eviction operator ALARM must map to a
        // dedicated screen_id bit, distinct from the port-scan / ip-sweep
        // DROP reasons (it is a saturation signal, not a packet drop), so an
        // operator can tell "detector is saturated" apart from a real scan
        // detection.
        assert_eq!(
            screen_reason_id("scan-table-pressure"),
            SCREEN_SCAN_TABLE_PRESSURE
        );
        assert_ne!(SCREEN_SCAN_TABLE_PRESSURE, SCREEN_PORT_SCAN);
        assert_ne!(SCREEN_SCAN_TABLE_PRESSURE, SCREEN_IP_SWEEP);
    }

    #[test]
    fn screen_parse_error_info_carries_flow_tuple() {
        // The fail-closed event built from meta+flow must log the
        // offending 5-tuple even though the packet bytes past L3 are
        // untrustworthy.
        let info = screen_parse_error_info(&test_meta(), &test_flow());
        assert_eq!(info.addr_family, libc::AF_INET as u8);
        assert_eq!(info.protocol, PROTO_TCP);
        assert_eq!(info.src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(info.dst_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
        assert_eq!(info.src_port, 49152);
        assert_eq!(info.dst_port, 443);
    }

    #[test]
    fn filter_log_event_emit_builds_rt_flow_payload() {
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        emit_filter_log_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            0,
            23,
            5,
            FilterAction::Accept,
            FilterLogSource::Input,
            0,
            mono_now_ns(),
        );

        let event = rx
            .try_recv()
            .expect("filter event frame")
            .decode_dataplane_event()
            .expect("filter event payload");
        assert_eq!(event.kind, DataplaneEventKind::FilterLog);
        assert_eq!(event.action, RT_FLOW_ACTION_PERMIT);
        assert_eq!(event.filter_id, 23);
        assert_eq!(event.term_id, 5);
        assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
        assert_eq!(event.ingress_zone_id, 7);
        assert_eq!(event.egress_zone_id, 0);
        // #2470 fail-on-revert: a real decision timestamp on the wire.
        assert!(
            event.timestamp_ns > 0,
            "filter-log event must carry a real wall-clock timestamp, got 0"
        );
        assert_eq!(handle.dataplane_event_stats().filter_log.sent, 1);
    }

    /// #2521: filter `then reject` now synthesizes an active reply (the
    /// dataplane enqueues a TCP RST / ICMP unreachable), so the RT_FLOW filter
    /// log reports REJECT — matching policy reject and Junos. (Pre-#2521 this
    /// asserted DENY because no reply was generated.) `discard` still maps to
    /// DENY (`filter_log_event_emit_discard_as_deny`).
    #[test]
    fn filter_log_event_emit_reject_reports_reject() {
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        emit_filter_log_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            0,
            23,
            6,
            FilterAction::Reject,
            FilterLogSource::Lo0,
            0,
            mono_now_ns(),
        );

        let event = rx
            .try_recv()
            .expect("filter event frame")
            .decode_dataplane_event()
            .expect("filter event payload");
        assert_eq!(event.kind, DataplaneEventKind::FilterLog);
        assert_eq!(event.action, RT_FLOW_ACTION_REJECT);
        assert_eq!(event.filter_id, 23);
        assert_eq!(event.term_id, 6);
        assert_eq!(event.reason, FilterLogSource::Lo0.wire_reason());
        assert_eq!(handle.dataplane_event_stats().filter_log.sent, 1);
    }

    /// #2521: `then discard` stays a silent drop → RT_FLOW DENY (the
    /// distinction from reject above).
    #[test]
    fn filter_log_event_emit_discard_as_deny() {
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        emit_filter_log_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            0,
            23,
            6,
            FilterAction::Discard,
            FilterLogSource::Lo0,
            0,
            mono_now_ns(),
        );

        let event = rx
            .try_recv()
            .expect("filter event frame")
            .decode_dataplane_event()
            .expect("filter event payload");
        assert_eq!(event.kind, DataplaneEventKind::FilterLog);
        assert_eq!(event.action, RT_FLOW_ACTION_DENY);
        assert_eq!(handle.dataplane_event_stats().filter_log.sent, 1);
    }

    /// #2520 fail-on-revert: a CONFIGURED application (TCP/443 → app_id 7 in
    /// the catalog) must surface in BOTH the policy-deny and filter-log RT_FLOW
    /// records. The emitter call sites resolve the AppID with the SAME
    /// `app_catalog.lookup` the forwarding hot path uses (here via
    /// `resolve_flow_app_id`). Reverting the emitters back to a hardcoded
    /// `application_id: 0` makes both assertions fail (the wire slot reads 0,
    /// which the Go RT_FLOW logger renders as application="UNKNOWN").
    #[test]
    fn cold_path_events_carry_resolved_app_id() {
        // TCP/443 single-dst-port app → app_id 7 (matches test_flow()).
        let catalog = AppCatalog::from_snapshot(&[crate::AppCatalogEntry {
            app_id: 7,
            protocol: PROTO_TCP,
            dst_port_low: 443,
            dst_port_high: 443,
            src_port_low: 0,
            src_port_high: 0,
        }]);
        let flow = test_flow();
        let app_id = resolve_flow_app_id(&catalog, &flow);
        assert_eq!(app_id, 7, "configured TCP/443 app must resolve to id 7");

        let (handle, rx) = unlimited_handle();
        emit_policy_deny_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            9,
            3,
            101,
            PolicyAction::Deny,
            app_id,
            mono_now_ns(),
        );
        let deny = rx
            .try_recv()
            .expect("policy event frame")
            .decode_dataplane_event()
            .expect("policy event payload");
        assert_eq!(
            deny.application_id, 7,
            "policy-deny RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
        );

        emit_filter_log_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            0,
            23,
            5,
            FilterAction::Accept,
            FilterLogSource::Input,
            app_id,
            mono_now_ns(),
        );
        let filt = rx
            .try_recv()
            .expect("filter event frame")
            .decode_dataplane_event()
            .expect("filter event payload");
        assert_eq!(
            filt.application_id, 7,
            "filter-log RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
        );
    }

    /// #2520: a tuple with no catalog match resolves to 0 (UNKNOWN), the
    /// unchanged behavior — we must NOT fabricate an AppID.
    #[test]
    fn cold_path_events_unresolvable_tuple_stays_zero() {
        let catalog = AppCatalog::default();
        assert_eq!(resolve_flow_app_id(&catalog, &test_flow()), 0);
    }

    /// #2470: two events emitted in monotonic-instant order carry
    /// non-decreasing wall-clock timestamps on the wire. This is the timeline
    /// correctness property the fix delivers: under queued / backlogged
    /// Go-side delivery the logged ordering reflects the DECISION instants,
    /// not the (possibly reordered or bunched) consumption instants.
    #[test]
    fn emitted_timestamps_are_non_decreasing() {
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        let t0 = mono_now_ns();
        emit_policy_deny_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            9,
            3,
            101,
            PolicyAction::Deny,
            0,
            t0,
        );
        // A strictly later monotonic instant for the second event.
        let t1 = mono_now_ns().max(t0 + 1);
        emit_filter_log_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            0,
            23,
            5,
            FilterAction::Accept,
            FilterLogSource::Input,
            0,
            t1,
        );

        let first = rx
            .try_recv()
            .expect("first event frame")
            .decode_dataplane_event()
            .expect("first event payload");
        let second = rx
            .try_recv()
            .expect("second event frame")
            .decode_dataplane_event()
            .expect("second event payload");
        assert!(first.timestamp_ns > 0, "first event must be stamped");
        assert!(second.timestamp_ns > 0, "second event must be stamped");
        assert!(
            second.timestamp_ns >= first.timestamp_ns,
            "events emitted in monotonic order must have non-decreasing \
             wall-clock timestamps: first={} second={}",
            first.timestamp_ns,
            second.timestamp_ns
        );
    }
}
