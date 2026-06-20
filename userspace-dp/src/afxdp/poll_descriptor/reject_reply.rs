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

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: Some(flow.forward_key.clone()),
        egress_ifindex: ingress_ifindex,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    });
    counters.touched = true;
    counters.policy_reject_sent += 1;
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
