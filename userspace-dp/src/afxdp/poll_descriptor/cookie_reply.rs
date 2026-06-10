// #1697 cold-path extraction: SYN-cookie reply enqueue machinery,
// lifted out of poll_descriptor/mod.rs so the hot ingress loop does not
// carry the cookie/DDoS-path bodies in its codegen unit.
//
// `enqueue_syn_cookie_reply` is on the SYN-cookie challenge path only
// (screen returns ScreenCheckOutcome::SynCookieChallenge), which never
// fires for established transit flows, so it is a true cold/exception
// body — `#[cold] #[inline(never)]` places it in `.text.unlikely`,
// away from the hot loop's cache lines. `syn_cookie_reply_budget_available`
// is a tiny helper called only from the (already-cold) enqueue body, so
// it stays `#[inline]` (let the inliner fold it into its single
// already-cold caller).
//
// The bodies are byte-for-byte identical to their previous location in
// mod.rs; only the enclosing module and the inline attributes change.

use super::worker::WorkerTxPipeline;
use super::*;
use crate::screen::SynCookieChallenge;

pub(super) const SYN_COOKIE_REPLY_PENDING_RESERVE: usize = TX_BATCH_SIZE;

pub(super) enum SynCookieReply {
    SynAck(SynCookieChallenge),
    AckRst,
}

#[inline]
pub(super) fn syn_cookie_reply_budget_available(tx_pipeline: &WorkerTxPipeline) -> bool {
    let max_pending = tx_pipeline.max_pending_tx;
    if max_pending == 0 {
        return false;
    }
    if tx_pipeline.free_tx_frames.len() <= SYN_COOKIE_REPLY_PENDING_RESERVE {
        return false;
    }
    let reserve = SYN_COOKIE_REPLY_PENDING_RESERVE.min(max_pending);
    let admitted = tx_pipeline
        .pending_tx_local
        .len()
        .saturating_add(tx_pipeline.pending_tx_prepared.len());
    admitted < max_pending.saturating_sub(reserve)
}

#[cold]
#[inline(never)]
pub(super) fn enqueue_syn_cookie_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    reply: SynCookieReply,
    counters: &mut BatchCounters,
) -> bool {
    if !syn_cookie_reply_budget_available(tx_pipeline) {
        counters.touched = true;
        counters.syn_cookie_reply_budget_drops += 1;
        return false;
    }

    let (bytes, sent_counter): (Option<Vec<u8>>, fn(&mut BatchCounters)) = match reply {
        SynCookieReply::SynAck(challenge) => (
            build_syn_cookie_syn_ack_frame(packet_frame, challenge.cookie_isn, challenge.peer_mss),
            |counters| counters.syn_cookie_syn_ack_sent += 1,
        ),
        SynCookieReply::AckRst => (build_syn_cookie_ack_rst_frame(packet_frame), |counters| {
            counters.syn_cookie_ack_rst_sent += 1
        }),
    };
    let Some(bytes) = bytes else {
        return false;
    };

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: flow.map(|flow| flow.forward_key.clone()),
        egress_ifindex: ifindex,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    });
    counters.touched = true;
    sent_counter(counters);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx_request() -> TxRequest {
        TxRequest {
            bytes: Vec::new(),
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: 0,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }
    }

    fn tx_pipeline(
        max_pending_tx: usize,
        free_frames: usize,
        pending_local: usize,
    ) -> WorkerTxPipeline {
        let mut pipeline = WorkerTxPipeline {
            free_tx_frames: (0..free_frames as u64).collect(),
            pending_tx_prepared: VecDeque::new(),
            pending_tx_local: VecDeque::new(),
            max_pending_tx,
            outstanding_tx: 0,
            pending_fill_frames: VecDeque::new(),
            in_flight_prepared_recycles: FastMap::default(),
            tx_submit_ns: Vec::new().into_boxed_slice(),
        };
        for _ in 0..pending_local {
            pipeline.pending_tx_local.push_back(dummy_tx_request());
        }
        pipeline
    }

    fn tcp_v4_syn_frame() -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
        let src_ip = std::net::Ipv4Addr::new(192, 0, 2, 10);
        let dst_ip = std::net::Ipv4Addr::new(198, 51, 100, 20);
        let src_port = 49152u16;
        let dst_port = 443u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6,
            0x08, 0x00,
        ]);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x2c, 0x12, 0x34,
            0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x60, TCP_FLAG_SYN, 0xfa, 0xf0, // data offset / flags / window
            0x00, 0x00, 0x00, 0x00, // checksum + urgent
            0x02, 0x04, 0x05, 0xb4, // MSS 1460
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
            payload_offset: 58,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
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
    fn syn_cookie_reply_budget_preserves_tx_batch_reserve() {
        let limit = SYN_COOKIE_REPLY_PENDING_RESERVE * 2;

        assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
            0,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            0,
        )));
        assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
            limit,
            SYN_COOKIE_REPLY_PENDING_RESERVE,
            0,
        )));
        assert!(syn_cookie_reply_budget_available(&tx_pipeline(
            limit,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            SYN_COOKIE_REPLY_PENDING_RESERVE - 1,
        )));
        assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
            limit,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            SYN_COOKIE_REPLY_PENDING_RESERVE,
        )));
    }

    #[test]
    fn syn_cookie_reply_enqueues_host_generated_frame_without_transit_policy_metadata() {
        let (frame, meta, flow) = tcp_v4_syn_frame();
        let mut pipeline = tx_pipeline(
            SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
            SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
            0,
        );
        let mut counters = BatchCounters::default();

        assert!(enqueue_syn_cookie_reply(
            &mut pipeline,
            5,
            &frame,
            meta,
            Some(&flow),
            SynCookieReply::SynAck(SynCookieChallenge {
                cookie_isn: 0xaabb_ccdd,
                peer_mss: 1460,
            }),
            &mut counters,
        ));

        let req = pipeline
            .pending_tx_local
            .pop_front()
            .expect("SYN-cookie reply request");
        assert_eq!(req.egress_ifindex, 5);
        assert_eq!(req.cos_queue_id, None);
        assert_eq!(req.dscp_rewrite, None);
        assert!(!req.mirror_clone);
        assert_eq!(req.flow_key, Some(flow.forward_key));
        assert_eq!(counters.syn_cookie_syn_ack_sent, 1);
        assert_eq!(counters.syn_cookie_reply_budget_drops, 0);
    }
}
