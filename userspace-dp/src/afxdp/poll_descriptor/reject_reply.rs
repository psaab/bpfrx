// #2089 policy-`reject` reply synthesis: emit a TCP RST (for TCP) or an
// ICMP/ICMPv6 Destination Unreachable, administratively prohibited (for
// every other non-suppressed protocol) instead of the silent drop that
// `then deny` produces. Lifted out of poll_descriptor/mod.rs so the hot
// ingress loop does not carry the reject-path bodies in its codegen unit,
// mirroring cookie_reply.rs.
//
// `enqueue_policy_reject_reply` is on the cold policy-deny exception arm
// only and fires solely when the matched action is `PolicyAction::Reject`,
// so it is a true cold/exception body — `#[cold] #[inline(never)]` places
// it in `.text.unlikely`, away from the hot loop's cache lines. It reuses
// the SYN-cookie TX-frame budget gate so a rejected-flow flood can never
// starve transit TX frames; on a budget or build failure it returns false
// and the caller still drops the packet (fail-closed — never logs a reject
// that did not happen).

use super::cookie_reply::syn_cookie_reply_budget_available;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::afxdp::event_emit::emit_policy_deny_event;
use crate::afxdp::icmp::build_reject_icmp_unreachable;
use crate::afxdp::icmp_ratelimit::{GeneratedErrorReason, allow_generated_error};
use crate::event_stream::EventStreamWorkerHandle;
use crate::nat::NatDecision;
use crate::policy::PolicyAction;

/// Which `reject` source a synthesized reply is attributed to. Selects the
/// per-source counters so a policy `then reject` and a firewall-filter `then
/// reject` are independently observable, while both flow through the SAME
/// reply-synthesis + output-classification machinery (#2521). The
/// budget-exhaustion / output-filter-drop / parse-error legs are shared with
/// policy reject so #2472's future per-reason rate limiter (which hooks the
/// shared generated-reply path) covers filter reject automatically — there is
/// no parallel, un-limitable emit path.
#[derive(Clone, Copy)]
pub(super) enum RejectReplySource {
    Policy,
    Filter,
}

#[cold]
#[inline(never)]
pub(super) fn enqueue_policy_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
) -> bool {
    enqueue_reject_reply(
        tx_pipeline,
        forwarding,
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        RejectReplySource::Policy,
    )
}

/// #2521: firewall-filter `then reject` now synthesizes the SAME active
/// reply as policy `reject` (TCP RST for TCP, ICMP/ICMPv6 admin-prohibited
/// unreachable otherwise) instead of the historical silent drop. Reuses the
/// exact synthesis + #2238 output-classification path via the shared
/// `enqueue_reject_reply`; only the success counter differs
/// (`filter_reject_sent` vs `policy_reject_sent`). Budget, output-filter, and
/// parse-error drops share policy reject's counters and its fail-closed
/// behavior (the caller still drops the packet on a `false` return).
#[cold]
#[inline(never)]
pub(super) fn enqueue_filter_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
) -> bool {
    enqueue_reject_reply(
        tx_pipeline,
        forwarding,
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        RejectReplySource::Filter,
    )
}

/// #3071: unified deny-path reply decision shared by both policy-deny call
/// sites in `poll_descriptor`. Replaces the bare `if action == Reject` arm so
/// the zone-level `tcp-rst` knob is honored alongside explicit `then reject`:
///
/// * `is_reject` (policy `then reject`): active reject for EVERY protocol — a
///   TCP RST for TCP, an ICMP/ICMPv6 admin-prohibited unreachable otherwise.
///   Unchanged from #2089.
/// * otherwise (plain `deny` / default-deny): a silent drop UNLESS the flow is
///   TCP AND the INGRESS (from) zone has Junos `tcp-rst` enabled, in which
///   case a TCP RST is sent back toward the source. Junos `tcp-rst` only
///   resets TCP; non-TCP denied traffic and a deny in a non-tcp-rst zone stay
///   silent drops.
///
/// Both legs reuse `enqueue_policy_reject_reply` (the #2521/#2089 synthesis +
/// #2238 output classification + #2472 rate limit + fail-closed budget gate),
/// so a zone-tcp-rst RST is counted under `policy_reject_sent` — it is a
/// policy-deny-driven reset. Returns true iff a reply was enqueued; the caller
/// still performs the silent drop regardless (fail-closed).
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn enqueue_deny_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    is_reject: bool,
    from_zone_id: u16,
) -> bool {
    if is_reject {
        return enqueue_policy_reject_reply(
            tx_pipeline,
            forwarding,
            ingress_ifindex,
            packet_frame,
            meta,
            flow,
            counters,
        );
    }
    if meta.protocol == PROTO_TCP && forwarding.zone_tcp_rst_enabled(from_zone_id) {
        return enqueue_policy_reject_reply(
            tx_pipeline,
            forwarding,
            ingress_ifindex,
            packet_frame,
            meta,
            flow,
            counters,
        );
    }
    false
}

/// #3615: enqueue the policy deny/reject reply FIRST, THEN emit the policy-deny
/// RT_FLOW carrying the TRUTHFUL action. `enqueue_deny_reply` returns whether a
/// TCP RST / ICMP-unreachable was actually enqueued (an explicit `then reject`,
/// or a plain `deny` in a zone with `tcp-rst`); that outcome is threaded into
/// `emit_policy_deny_event` so a `reject` whose reply fail-closed
/// (budget/rate/parse/output-filter) is logged as the truthful DENY rather than
/// claiming an active reject that never left the box. A plain `deny` always
/// logs DENY regardless of whether a zone-`tcp-rst` RST rode out.
///
/// Both transit deny sites and the junos-host deny route through this single
/// helper so the poll-loop ordering (enqueue-outcome BEFORE emit) is the SAME
/// code path a unit test can drive — the poll loop body itself is un-callable.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn deny_reply_and_emit(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    nat: &NatDecision,
    from_zone_id: u16,
    to_zone_id: u16,
    owner_rg_id: i32,
    policy_id: u32,
    action: PolicyAction,
    app_id: u16,
    now_ns: u64,
) {
    let reject_reply_enqueued = enqueue_deny_reply(
        tx_pipeline,
        forwarding,
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        matches!(action, PolicyAction::Reject),
        from_zone_id,
    );
    emit_policy_deny_event(
        event_stream,
        flow,
        nat,
        meta,
        from_zone_id,
        to_zone_id,
        owner_rg_id,
        policy_id,
        action,
        app_id,
        reject_reply_enqueued,
        now_ns,
    );
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn enqueue_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    source: RejectReplySource,
) -> bool {
    if !syn_cookie_reply_budget_available(tx_pipeline) {
        counters.touched = true;
        // #3615 (L04): attribute the TX-frame-budget suppression to the
        // reply's SOURCE so a firewall-filter `then reject` drop is not
        // conflated with a policy `then reject` drop. Both still share the
        // same budget gate; only the observable counter differs.
        match source {
            RejectReplySource::Policy => counters.policy_reject_reply_budget_drops += 1,
            RejectReplySource::Filter => counters.filter_reject_reply_budget_drops += 1,
        }
        return false;
    }

    // #2472: per-reason token-bucket rate limit on the LOCALLY-GENERATED
    // reject reply (TCP RST or ICMP/ICMPv6 unreachable). The SYN-cookie
    // TX-frame budget gate above is a queue-protection gate (it keeps the
    // reply ring from starving transit TX), NOT a per-reason rate cap — under
    // a sustained rejected-flow flood it refills as fast as TX drains. The
    // token bucket bounds the generated-error RATE so a flood of rejected
    // flows cannot be amplified into unbounded RST/ICMP backscatter. Both
    // policy and filter reject share this `Reject` bucket (a single emit
    // path, per the RejectReplySource doc comment). On bucket-empty we
    // fail-closed to the silent drop the caller already performs and bump the
    // observable `Reject` rate-limited counter (inside
    // `allow_generated_error`).
    if !allow_generated_error(GeneratedErrorReason::Reject) {
        counters.touched = true;
        return false;
    }

    let bytes = if meta.protocol == PROTO_TCP {
        build_reject_rst_frame(packet_frame)
    } else {
        build_reject_icmp_unreachable(packet_frame, meta, ingress_ifindex, forwarding)
    };
    let Some(bytes) = bytes else {
        // Unparseable frame, ingress without a primary of the inbound
        // family, inbound RST/ICMP-error, or a non-first fragment:
        // fail-closed to the silent drop the caller already performs.
        return false;
    };

    // #2238: classify the GENERATED reply (TCP RST or ICMP/ICMPv6
    // unreachable) by its OWN egress 5-tuple + egress interface — the
    // reflected reply egresses on the interface it arrived on, so
    // `ingress_ifindex` IS the egress. An output firewall filter terminal
    // `discard`/`reject` (or three-color policer) on that interface drops
    // the reply; a parse failure of our own built bytes fails CLOSED (§6.2).
    // Pre-#2238 this enqueued an UNCLASSIFIED TxRequest (`cos_queue_id:
    // None, dscp_rewrite: None`) that the drain path honored verbatim — no
    // output filter / CoS / DSCP was ever applied to the reply.
    //
    // #3035: classify on the LOGICAL egress ifindex, NOT the physical
    // `ingress_ifindex`. CoS interfaces (forwarding_build/cos.rs) and output
    // filters (filter/compiler.rs) are keyed by the logical unit ifindex; on
    // a VLAN subinterface `ingress_ifindex` is the physical parent index, so
    // classifying by it applied the parent's (or first subinterface's) CoS
    // queue / DSCP rewrite / output filter instead of this unit's. Mirrors
    // the #3026 generated-ICMP-error fix and the filter/CoS sites via the
    // `resolve_ingress_logical_ifindex` SSOT; the physical `ingress_ifindex`
    // is still used for the reflected-reply build above and the XSK transmit
    // (`egress_ifindex`) below. For a non-VLAN port the logical and physical
    // indexes coincide, so this is a no-op there.
    let now_ns = monotonic_nanos();
    let classify_ifindex =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, meta.ingress_vlan_id)
            .unwrap_or(ingress_ifindex);
    let verdict = classify_generated_reply(forwarding, classify_ifindex, &bytes, now_ns);
    if verdict.drop {
        counters.touched = true;
        if verdict.parse_error {
            // A fail-CLOSED re-parse failure of our own generated bytes is a
            // builder/parser bug shared by every generated-reply type (cookie,
            // PTB, time-exceeded, reject), so it stays SOURCE-NEUTRAL (#3615).
            counters.generated_reply_classify_parse_errors += 1;
        } else {
            // #3615 (L05): attribute the egress output-filter suppression to
            // the reply's SOURCE — a filter `then reject` suppressed by an
            // output filter is no longer counted under policy_reject_*.
            match source {
                RejectReplySource::Policy => counters.policy_reject_output_filter_drops += 1,
                RejectReplySource::Filter => counters.filter_reject_output_filter_drops += 1,
            }
        }
        // Fail-closed to the silent drop the caller already performs.
        return false;
    }

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: Some(flow.forward_key.clone()),
        egress_ifindex: ingress_ifindex,
        cos_queue_id: verdict.cos_queue_id,
        dscp_rewrite: verdict.dscp_rewrite,
        mirror_clone: false,
        enqueue_ns: 0,
    });
    counters.touched = true;
    match source {
        RejectReplySource::Policy => counters.policy_reject_sent += 1,
        RejectReplySource::Filter => counters.filter_reject_sent += 1,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx_pipeline(max_pending_tx: usize, free_frames: usize) -> WorkerTxPipeline {
        WorkerTxPipeline {
            free_tx_frames: (0..free_frames as u64).collect(),
            pending_tx_prepared: VecDeque::new(),
            pending_tx_local: VecDeque::new(),
            max_pending_tx,
            outstanding_tx: 0,
            pending_fill_frames: VecDeque::new(),
            in_flight_prepared_recycles: FastMap::default(),
            tx_submit_ns: Vec::new().into_boxed_slice(),
        }
    }

    fn tcp_v4_syn() -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
        let src_ip = std::net::Ipv4Addr::new(192, 0, 2, 10);
        let dst_ip = std::net::Ipv4Addr::new(198, 51, 100, 20);
        let src_port = 49152u16;
        let dst_port = 22u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6, 0x08, 0x00,
        ]);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xfa, 0xf0, // data offset / SYN / window
            0x00, 0x00, 0x00, 0x00, // checksum + urgent
        ]);
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&src_ip.octets());
        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&dst_ip.octets());
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: 0x02,
            flow_src_addr: src_addr,
            flow_dst_addr: dst_addr,
            flow_src_port: src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: std::net::IpAddr::V4(src_ip),
            dst_ip: std::net::IpAddr::V4(dst_ip),
            src_port,
            dst_port,
        };
        let flow = SessionFlow {
            src_ip: std::net::IpAddr::V4(src_ip),
            dst_ip: std::net::IpAddr::V4(dst_ip),
            forward_key: key,
        };
        (frame, meta, flow)
    }

    #[test]
    fn reject_reply_budget_exhausted_fails_closed_no_send() {
        let (frame, meta, flow) = tcp_v4_syn();
        // Zero max-pending => budget unavailable => silent-drop fail-closed.
        let mut pipeline = tx_pipeline(0, 64);
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(!sent, "must fail-closed under budget exhaustion");
        assert_eq!(counters.policy_reject_sent, 0);
        assert_eq!(counters.policy_reject_reply_budget_drops, 1);
        assert!(pipeline.pending_tx_local.is_empty());
    }

    #[test]
    fn reject_tcp_with_egress_enqueues_rst() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        // #2472/#2955: the Reject token bucket is a global GCRA word whose TAT
        // advances monotonically; reset-to-full alone is not enough because a
        // parallel test can advance/drain the TAT after the reset. Hold the
        // shared global-bucket test lock for the whole reset→drive→assert window
        // so no sibling can starve this success-path assertion.
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let (frame, meta, flow) = tcp_v4_syn();
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let mut forwarding = ForwardingState::default();
        // build_reject_rst_frame is self-contained (it reflects the
        // inbound frame), so a TCP reject does not need an egress entry;
        // it should enqueue regardless.
        forwarding.egress.clear();
        let mut counters = BatchCounters::default();
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(sent, "TCP reject must enqueue a RST");
        assert_eq!(counters.policy_reject_sent, 1);
        let req = pipeline
            .pending_tx_local
            .pop_front()
            .expect("reject RST request");
        assert_eq!(req.egress_ifindex, 5);
        assert_eq!(req.cos_queue_id, None);
        assert_eq!(req.dscp_rewrite, None);
        assert!(!req.mirror_clone);
        assert_eq!(req.flow_key, Some(flow.forward_key));
        // Reflected RST: dst MAC is the inbound src MAC; RST flag set.
        assert_eq!(&req.bytes[0..6], &[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
        let tcp_flags = req.bytes[14 + 20 + 13];
        assert_ne!(tcp_flags & 0x04, 0, "RST flag must be set");
    }

    /// #2238: a generated reject reply matching an OUTPUT filter `then
    /// discard` (keyed on the reply's own tuple) is NOT enqueued, and the
    /// dedicated `policy_reject_output_filter_drops` counter increments.
    /// Uses a non-TCP (ICMP) trigger so the generated reply is an ICMP
    /// unreachable, and the egress output filter discards `protocol icmp`.
    #[test]
    fn reject_reply_dropped_by_egress_output_filter() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        // Inbound ICMP echo (a query, not an error) on ifindex 5 → the
        // reject path builds an ICMP unreachable, which the egress output
        // filter discards.
        let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
        let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let l3 = frame.len();
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0]);
        frame.extend_from_slice(&client.octets());
        frame.extend_from_slice(&server.octets());
        let _ = l3; // inbound IP csum not validated by the builders
        frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]); // ICMP echo
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            pkt_len: (frame.len() - 14) as u16,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: std::net::IpAddr::V4(client),
                dst_ip: std::net::IpAddr::V4(server),
                src_port: 0x1234,
                dst_port: 0,
            },
        };
        let filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "drop-icmp".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "drop-icmp".into(),
                    action: "discard".into(),
                    protocols: vec!["icmp".into()],
                    ..Default::default()
                }],
            }],
            &[],
            &[crate::InterfaceSnapshot {
                name: "ge-0/0/1.0".into(),
                ifindex: 5,
                filter_output_v4: "drop-icmp".into(),
                ..Default::default()
            }],
            "",
            "",
        ).expect("filter state compiles");
        let mut forwarding = ForwardingState {
            filter_state,
            tx_selection_enabled_v4: true,
            ..ForwardingState::default()
        };
        forwarding.egress.insert(
            5,
            EgressInterface {
                bind_ifindex: 5,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone_id: 0,
                redundancy_group: 0,
                primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let mut counters = BatchCounters::default();
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(!sent, "reject reply dropped by egress output filter must not enqueue");
        assert_eq!(counters.policy_reject_sent, 0);
        assert_eq!(counters.policy_reject_output_filter_drops, 1);
        assert_eq!(counters.generated_reply_classify_parse_errors, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }

    /// #2521: a firewall-filter `then reject` on a TCP flow synthesizes a TCP
    /// RST (not a silent drop) and increments `filter_reject_sent` — NOT
    /// `policy_reject_sent`. Fail-on-revert: if the call site reverts to a
    /// silent recycle (no synthesis), `pending_tx_local` stays empty and
    /// `filter_reject_sent` stays 0; if it routes through the policy counter,
    /// the per-source counter assertion fails.
    #[test]
    fn filter_reject_tcp_enqueues_rst_filter_counter() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let (frame, meta, flow) = tcp_v4_syn();
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        let sent = enqueue_filter_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(sent, "filter TCP reject must enqueue a RST");
        assert_eq!(
            counters.filter_reject_sent, 1,
            "filter reject must bump filter_reject_sent"
        );
        assert_eq!(
            counters.policy_reject_sent, 0,
            "filter reject must NOT bump policy_reject_sent"
        );
        let req = pipeline
            .pending_tx_local
            .pop_front()
            .expect("filter reject RST request");
        assert_eq!(req.egress_ifindex, 5);
        // Reflected RST: dst MAC is the inbound src MAC; RST flag set.
        assert_eq!(&req.bytes[0..6], &[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
        let tcp_flags = req.bytes[14 + 20 + 13];
        assert_ne!(tcp_flags & 0x04, 0, "RST flag must be set");
    }

    /// #2521: a firewall-filter `then reject` on a NON-TCP (ICMP) flow
    /// synthesizes an ICMP unreachable and increments `filter_reject_sent`.
    #[test]
    fn filter_reject_non_tcp_enqueues_icmp_unreachable() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
        let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0,
        ]);
        frame.extend_from_slice(&client.octets());
        frame.extend_from_slice(&server.octets());
        frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]); // ICMP echo
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            pkt_len: (frame.len() - 14) as u16,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: std::net::IpAddr::V4(client),
                dst_ip: std::net::IpAddr::V4(server),
                src_port: 0x1234,
                dst_port: 0,
            },
        };
        // build_reject_icmp_unreachable needs an egress with a v4 primary on
        // the reply's egress interface (the inbound ingress ifindex).
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            5,
            EgressInterface {
                bind_ifindex: 5,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone_id: 0,
                redundancy_group: 0,
                primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let mut counters = BatchCounters::default();
        let sent = enqueue_filter_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(sent, "filter non-TCP reject must enqueue an ICMP unreachable");
        assert_eq!(counters.filter_reject_sent, 1);
        assert_eq!(counters.policy_reject_sent, 0);
        let req = pipeline
            .pending_tx_local
            .pop_front()
            .expect("filter reject ICMP request");
        // ICMP unreachable: type 3 at the L4 offset of the reply.
        assert_eq!(req.bytes[14 + 20], 3, "ICMP type must be Destination Unreachable");
    }

    /// #3615 (L04) fail-on-revert: a FILTER `then reject` reply suppressed by
    /// TX-frame budget exhaustion must bump `filter_reject_reply_budget_drops`,
    /// NOT the policy sibling. Reverting the source-routed budget counter (back
    /// to always `policy_reject_reply_budget_drops`) turns this RED.
    #[test]
    fn filter_reject_budget_exhausted_uses_filter_counter() {
        let (frame, meta, flow) = tcp_v4_syn();
        let mut pipeline = tx_pipeline(0, 64); // zero budget => suppressed
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        let sent = enqueue_filter_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(!sent, "filter reject must fail-closed under budget exhaustion");
        assert_eq!(
            counters.filter_reject_reply_budget_drops, 1,
            "filter-source budget drop must bump the filter counter"
        );
        assert_eq!(
            counters.policy_reject_reply_budget_drops, 0,
            "a filter-reject budget drop must NOT bump the policy counter"
        );
        assert!(pipeline.pending_tx_local.is_empty());
    }

    /// #3615 (L05) fail-on-revert: a FILTER `then reject` reply discarded by an
    /// egress OUTPUT filter must bump `filter_reject_output_filter_drops`, NOT
    /// the policy sibling. Mirrors `reject_reply_dropped_by_egress_output_-
    /// filter` (policy source) but drives the FILTER entry point.
    #[test]
    fn filter_reject_output_filter_drop_uses_filter_counter() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
        let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0,
        ]);
        frame.extend_from_slice(&client.octets());
        frame.extend_from_slice(&server.octets());
        frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]); // ICMP echo
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            pkt_len: (frame.len() - 14) as u16,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: std::net::IpAddr::V4(client),
                dst_ip: std::net::IpAddr::V4(server),
                src_port: 0x1234,
                dst_port: 0,
            },
        };
        let filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "drop-icmp".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "drop-icmp".into(),
                    action: "discard".into(),
                    protocols: vec!["icmp".into()],
                    ..Default::default()
                }],
            }],
            &[],
            &[crate::InterfaceSnapshot {
                name: "ge-0/0/1.0".into(),
                ifindex: 5,
                filter_output_v4: "drop-icmp".into(),
                ..Default::default()
            }],
            "",
            "",
        )
        .expect("filter state compiles");
        let mut forwarding = ForwardingState {
            filter_state,
            tx_selection_enabled_v4: true,
            ..ForwardingState::default()
        };
        forwarding.egress.insert(
            5,
            EgressInterface {
                bind_ifindex: 5,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone_id: 0,
                redundancy_group: 0,
                primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let mut counters = BatchCounters::default();
        let sent = enqueue_filter_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(!sent, "filter reject discarded by egress output filter must not enqueue");
        assert_eq!(
            counters.filter_reject_output_filter_drops, 1,
            "filter-source output-filter drop must bump the filter counter"
        );
        assert_eq!(
            counters.policy_reject_output_filter_drops, 0,
            "a filter-reject output-filter drop must NOT bump the policy counter"
        );
        assert_eq!(counters.generated_reply_classify_parse_errors, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }

    /// #2472 call-site fail-on-revert: once the global per-reason `Reject`
    /// token bucket is empty, `enqueue_policy_reject_reply` MUST fail-closed
    /// (no RST enqueued, `policy_reject_sent` stays 0) and the observable
    /// `Reject` rate-limited counter MUST advance — even though the TX-frame
    /// budget is plentiful. Without the #2472 limiter the reject reply would
    /// enqueue regardless of how many were generated, so this test fails on a
    /// revert of the call-site gate.
    #[test]
    fn reject_reply_rate_limited_when_bucket_empty() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        use crate::afxdp::icmp_ratelimit::{
            GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
            rate_limited_count, reset_bucket_for_test,
        };
        // #2955: serialise with the other global Reject-bucket tests so a
        // parallel reset-to-full cannot undo the far-future drain mid-test.
        let _g = global_bucket_test_lock();
        let (frame, meta, flow) = tcp_v4_syn();
        // The call site samples the REAL `monotonic_nanos()` (boot-relative,
        // small), which we cannot freeze. To keep the global Reject bucket
        // empty across that call, pin its refill epoch (`last_ns`) to a FAR
        // FUTURE value, then drain it: the call site's smaller `now_ns` yields
        // `saturating_sub == 0` → zero refill → the bucket stays empty and the
        // call site's `allow_generated_error(Reject)` is denied. (On a deny
        // with no refill, `try_take` does NOT advance `last_ns`, so the
        // far-future epoch — and thus the empty state — survives the call.)
        let far_future = u64::MAX / 2;
        reset_bucket_for_test(GeneratedErrorReason::Reject, far_future);
        while allow_generated_error_at(GeneratedErrorReason::Reject, far_future, 1000, 1000) {}
        let before = rate_limited_count(GeneratedErrorReason::Reject);
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(!sent, "reject reply must fail-closed when rate-limited");
        assert_eq!(
            counters.policy_reject_sent, 0,
            "no reject must be counted as sent under rate limit"
        );
        assert!(
            pipeline.pending_tx_local.is_empty(),
            "no RST may be enqueued under rate limit"
        );
        assert!(
            rate_limited_count(GeneratedErrorReason::Reject) > before,
            "the rate-limited drop must bump the observable Reject counter"
        );
        // Restore a full bucket so sibling tests in this binary are unaffected.
        reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
    }

    #[test]
    fn reject_inbound_rst_is_not_answered() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let (mut frame, mut meta, flow) = tcp_v4_syn();
        // Flip the inbound to a RST: must not be answered (no RST storm).
        frame[14 + 20 + 13] = 0x04;
        meta.tcp_flags = 0x04;
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(!sent, "inbound RST must not be answered");
        assert_eq!(counters.policy_reject_sent, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }

    /// #3071: an ICMP echo (non-TCP) frame for the zone-tcp-rst tests. Reused
    /// to prove tcp-rst is TCP-only (non-TCP denied traffic stays silent).
    fn icmp_v4_echo() -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
        let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
        let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0,
        ]);
        frame.extend_from_slice(&client.octets());
        frame.extend_from_slice(&server.octets());
        frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            pkt_len: (frame.len() - 14) as u16,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: std::net::IpAddr::V4(client),
                dst_ip: std::net::IpAddr::V4(server),
                src_port: 0x1234,
                dst_port: 0,
            },
        };
        (frame, meta, flow)
    }

    /// #3071 fail-on-revert: a plain `deny` (is_reject=false) on a TCP flow
    /// whose INGRESS (from) zone has tcp-rst enabled MUST enqueue a TCP RST.
    /// Reverting the zone-tcp-rst arm of `enqueue_deny_reply` → no RST → RED.
    #[test]
    fn deny_reply_zone_tcp_rst_tcp_enqueues_rst() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let (frame, meta, flow) = tcp_v4_syn();
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let mut forwarding = ForwardingState::default();
        // From-zone id 7 has Junos `tcp-rst`.
        forwarding.zone_tcp_rst.insert(7, true);
        let mut counters = BatchCounters::default();
        let sent = enqueue_deny_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            false, // plain deny, not `then reject`
            7,     // ingress (from) zone id
        );
        assert!(sent, "denied TCP in a tcp-rst zone must enqueue a RST");
        assert_eq!(counters.policy_reject_sent, 1);
        let req = pipeline
            .pending_tx_local
            .pop_front()
            .expect("zone tcp-rst RST request");
        let tcp_flags = req.bytes[14 + 20 + 13];
        assert_ne!(tcp_flags & 0x04, 0, "RST flag must be set");
    }

    /// #3071: a plain `deny` on a TCP flow whose from-zone does NOT have
    /// tcp-rst stays a silent drop (no RST, no counter).
    #[test]
    fn deny_reply_no_zone_tcp_rst_is_silent_drop() {
        let (frame, meta, flow) = tcp_v4_syn();
        let mut pipeline = tx_pipeline(64, 64);
        let forwarding = ForwardingState::default(); // zone 7 not in zone_tcp_rst
        let mut counters = BatchCounters::default();
        let sent = enqueue_deny_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            false,
            7,
        );
        assert!(
            !sent,
            "denied TCP without zone tcp-rst must stay a silent drop"
        );
        assert_eq!(counters.policy_reject_sent, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }

    /// #3071: zone tcp-rst is TCP-only — a denied NON-TCP (ICMP) flow in a
    /// tcp-rst zone is unaffected (silent drop, no ICMP unreachable).
    #[test]
    fn deny_reply_zone_tcp_rst_non_tcp_is_silent_drop() {
        let (frame, meta, flow) = icmp_v4_echo();
        let mut pipeline = tx_pipeline(64, 64);
        let mut forwarding = ForwardingState::default();
        forwarding.zone_tcp_rst.insert(7, true);
        let mut counters = BatchCounters::default();
        let sent = enqueue_deny_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            false,
            7,
        );
        assert!(
            !sent,
            "non-TCP denied traffic must not get a zone tcp-rst reply"
        );
        assert_eq!(counters.policy_reject_sent, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }

    /// #3035: forwarding state where the VLAN unit reth0.80 (logical ifindex
    /// 202, parent 11, VID 80) carries a TCP-discard output filter and the
    /// physical parent 11 carries NONE. Proves the reject reply is classified
    /// on the LOGICAL unit ifindex, not the physical ingress port.
    fn vlan_drop_tcp_snapshot() -> crate::ConfigSnapshot {
        crate::ConfigSnapshot {
            interfaces: vec![crate::InterfaceSnapshot {
                name: "reth0.80".into(),
                ifindex: 202,
                parent_ifindex: 11,
                vlan_id: 80,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "drop-tcp".into(),
                ..Default::default()
            }],
            filters: vec![crate::FirewallFilterSnapshot {
                name: "drop-tcp".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "drop-tcp".into(),
                    action: "discard".into(),
                    protocols: vec!["tcp".into()],
                    ..Default::default()
                }],
            }],
            ..Default::default()
        }
    }

    /// #3035 fail-on-revert: a reject reply (TCP RST) for a SYN arriving on a
    /// VLAN sub-interface must be classified (output filter / CoS) on the
    /// LOGICAL unit ifindex, not the physical ingress port. The logical unit
    /// reth0.80 (202) carries a TCP-discard output filter; the physical parent
    /// 11 does not. Driving the real enqueue with the physical ingress ifindex
    /// 11 must resolve the logical unit and drop the RST. If the classify
    /// reverts to the physical `ingress_ifindex`, the parent has no filter and
    /// the reply is wrongly admitted -> this test goes RED. A reflected TCP RST
    /// needs no egress primary, so this isolates the classify ifindex.
    #[test]
    fn reject_reply_classifies_on_logical_vlan_ifindex_3035() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let (frame, mut meta, flow) = tcp_v4_syn();
        // Inbound SYN arrives on physical parent ifindex 11, tagged VID 80.
        meta.ingress_ifindex = 11;
        meta.ingress_vlan_id = 80;
        let forwarding = build_forwarding_state(&vlan_drop_tcp_snapshot());

        // Fixture sanity + divergence: logical-keyed classify drops (the
        // unit's drop-tcp filter), physical-parent-keyed classify admits.
        assert_eq!(
            resolve_ingress_logical_ifindex(&forwarding, 11, 80),
            Some(202),
            "parent 11 / VLAN 80 must resolve to logical ifindex 202"
        );
        let rst = build_reject_rst_frame(&frame).expect("reflected RST builds");
        let now_ns = monotonic_nanos();
        assert!(
            classify_generated_reply(&forwarding, 202, &rst, now_ns).drop,
            "logical-keyed classify must hit the VLAN unit's drop-tcp filter"
        );
        assert!(
            !classify_generated_reply(&forwarding, 11, &rst, now_ns).drop,
            "physical-parent-keyed classify has no filter and would wrongly admit"
        );

        // Drive the real enqueue with the PHYSICAL ingress ifindex 11.
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let mut counters = BatchCounters::default();
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            11, // physical parent ingress ifindex
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(
            !sent,
            "reject reply on a VLAN unit must be dropped by the unit's output filter"
        );
        assert_eq!(counters.policy_reject_output_filter_drops, 1);
        assert_eq!(counters.policy_reject_sent, 0);
        assert_eq!(counters.generated_reply_classify_parse_errors, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }

    /// #3035 non-VLAN regression: on an untagged interface the logical unit IS
    /// the ingress ifindex (no (parent, vlan) mapping), so `resolve_ingress_-
    /// logical_ifindex` returns None and the classify falls back to the
    /// physical ifindex unchanged — behavior is byte-identical to pre-#3035.
    #[test]
    fn reject_reply_non_vlan_classify_unchanged_3035() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let (frame, meta, flow) = tcp_v4_syn(); // ingress_ifindex 5, vlan 0
        let snapshot = crate::ConfigSnapshot {
            interfaces: vec![crate::InterfaceSnapshot {
                name: "ge-0/0/1.0".into(),
                ifindex: 5,
                hardware_addr: "02:bf:72:00:00:05".into(),
                filter_output_v4: "drop-tcp".into(),
                ..Default::default()
            }],
            filters: vec![crate::FirewallFilterSnapshot {
                name: "drop-tcp".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "drop-tcp".into(),
                    action: "discard".into(),
                    protocols: vec!["tcp".into()],
                    ..Default::default()
                }],
            }],
            ..Default::default()
        };
        let forwarding = build_forwarding_state(&snapshot);
        // An untagged unit maps to ITSELF (logical == physical == 5), so the
        // resolve is a no-op and the classify ifindex is unchanged.
        assert_eq!(
            resolve_ingress_logical_ifindex(&forwarding, 5, 0),
            Some(5),
            "an untagged port resolves logical == physical; the classify ifindex is unchanged"
        );
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let mut counters = BatchCounters::default();
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            5, // logical == physical for an untagged port
            &frame,
            meta,
            &flow,
            &mut counters,
        );
        assert!(
            !sent,
            "untagged interface still applies its own output filter (unchanged)"
        );
        assert_eq!(counters.policy_reject_output_filter_drops, 1);
        assert_eq!(counters.policy_reject_sent, 0);
    }

    /// #3071: the unified deny-reply still drives explicit policy `reject`
    /// (is_reject=true) through the active reject path regardless of zone
    /// tcp-rst — a TCP RST is enqueued even when the from-zone has no tcp-rst.
    #[test]
    fn deny_reply_explicit_reject_still_resets_tcp() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let (frame, meta, flow) = tcp_v4_syn();
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let forwarding = ForwardingState::default(); // no zone tcp-rst at all
        let mut counters = BatchCounters::default();
        let sent = enqueue_deny_reply(
            &mut pipeline,
            &forwarding,
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            true, // explicit `then reject`
            7,
        );
        assert!(
            sent,
            "explicit reject must enqueue a RST regardless of zone tcp-rst"
        );
        assert_eq!(counters.policy_reject_sent, 1);
        assert!(!pipeline.pending_tx_local.is_empty());
    }

    // #3615 M10: poll-loop-path ordering coverage for `deny_reply_and_emit` —
    // the combining helper the transit deny sites + junos-host deny call. RT_FLOW
    // action bytes mirror event_emit.rs (DENY = 0, REJECT = 2).
    const RT_FLOW_ACTION_DENY: u8 = 0;
    const RT_FLOW_ACTION_REJECT: u8 = 2;

    fn unlimited_event_handle() -> (
        EventStreamWorkerHandle,
        std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
    ) {
        crate::event_stream::test_worker_handle(
            8,
            crate::event_stream::DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        )
    }

    /// #3615 M10 fail-on-revert: a policy `then reject` whose reply is
    /// SUPPRESSED by TX-frame budget on the poll path must (a) NOT enqueue a
    /// reply, (b) bump `policy_reject_reply_budget_drops`, and (c) emit a
    /// policy-deny event whose action is the TRUTHFUL DENY, not REJECT.
    /// Reverting `deny_reply_and_emit` to emit BEFORE the enqueue (or hardcode
    /// `reject_reply_enqueued=true`) flips the wire action back to REJECT — RED
    /// on the event-action assertion. Asserts action + counter + TX queue
    /// length together (issue #3615 M10).
    #[test]
    fn deny_reply_and_emit_suppressed_reject_logs_deny() {
        let (frame, meta, flow) = tcp_v4_syn();
        let (handle, rx) = unlimited_event_handle();
        let mut pipeline = tx_pipeline(0, 64); // zero budget => reply suppressed
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        deny_reply_and_emit(
            &mut pipeline,
            &forwarding,
            Some(&handle),
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            &NatDecision::default(),
            7,   // from_zone
            9,   // to_zone
            0,   // owner_rg
            101, // policy_id
            PolicyAction::Reject,
            0, // app_id
            123,
        );
        assert!(
            pipeline.pending_tx_local.is_empty(),
            "no reply may be enqueued under budget exhaustion"
        );
        assert_eq!(counters.policy_reject_reply_budget_drops, 1);
        assert_eq!(counters.policy_reject_sent, 0);
        let event = rx
            .try_recv()
            .expect("policy-deny event frame")
            .decode_dataplane_event()
            .expect("policy-deny payload");
        assert_eq!(
            event.action, RT_FLOW_ACTION_DENY,
            "a suppressed reject on the poll path must log DENY, not REJECT"
        );
    }

    /// #3615 M10 (rate-limit suppression variant): once the global `Reject`
    /// token bucket is empty, `deny_reply_and_emit` enqueues no reply and the
    /// emitted policy-deny action is the truthful DENY.
    #[test]
    fn deny_reply_and_emit_rate_limited_reject_logs_deny() {
        use crate::afxdp::icmp_ratelimit::{
            GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
            reset_bucket_for_test,
        };
        let _g = global_bucket_test_lock();
        let (frame, meta, flow) = tcp_v4_syn();
        // Pin the refill epoch to the far future then drain, so the call site's
        // smaller monotonic `now_ns` yields zero refill (mirrors
        // reject_reply_rate_limited_when_bucket_empty).
        let far_future = u64::MAX / 2;
        reset_bucket_for_test(GeneratedErrorReason::Reject, far_future);
        while allow_generated_error_at(GeneratedErrorReason::Reject, far_future, 1000, 1000) {}
        let (handle, rx) = unlimited_event_handle();
        let mut pipeline = tx_pipeline(64, 64); // budget plentiful; rate limits
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        deny_reply_and_emit(
            &mut pipeline,
            &forwarding,
            Some(&handle),
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            &NatDecision::default(),
            7,
            9,
            0,
            101,
            PolicyAction::Reject,
            0,
            123,
        );
        assert!(
            pipeline.pending_tx_local.is_empty(),
            "no reply may be enqueued when rate-limited"
        );
        assert_eq!(counters.policy_reject_sent, 0);
        let event = rx
            .try_recv()
            .expect("policy-deny event frame")
            .decode_dataplane_event()
            .expect("policy-deny payload");
        assert_eq!(
            event.action, RT_FLOW_ACTION_DENY,
            "a rate-limited reject on the poll path must log DENY, not REJECT"
        );
        reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
    }

    /// #3615 M10 GREEN companion: a policy `then reject` whose reply IS enqueued
    /// logs the truthful REJECT and increments `policy_reject_sent`.
    #[test]
    fn deny_reply_and_emit_success_logs_reject() {
        use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
        let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
        crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
            0,
        );
        let (frame, meta, flow) = tcp_v4_syn();
        let (handle, rx) = unlimited_event_handle();
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        );
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        deny_reply_and_emit(
            &mut pipeline,
            &forwarding,
            Some(&handle),
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            &NatDecision::default(),
            7,
            9,
            0,
            101,
            PolicyAction::Reject,
            0,
            123,
        );
        assert_eq!(counters.policy_reject_sent, 1, "the RST must be enqueued");
        assert_eq!(pipeline.pending_tx_local.len(), 1);
        let event = rx
            .try_recv()
            .expect("policy-deny event frame")
            .decode_dataplane_event()
            .expect("policy-deny payload");
        assert_eq!(
            event.action, RT_FLOW_ACTION_REJECT,
            "an enqueued reject must log the truthful REJECT"
        );
    }
}
