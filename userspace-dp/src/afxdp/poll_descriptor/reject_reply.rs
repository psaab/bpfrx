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
use crate::afxdp::icmp::build_reject_icmp_unreachable;

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
        counters.policy_reject_reply_budget_drops += 1;
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
    let now_ns = monotonic_nanos();
    let verdict = classify_generated_reply(forwarding, ingress_ifindex, &bytes, now_ns);
    if verdict.drop {
        counters.touched = true;
        if verdict.parse_error {
            counters.generated_reply_classify_parse_errors += 1;
        } else {
            counters.policy_reject_output_filter_drops += 1;
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
}
