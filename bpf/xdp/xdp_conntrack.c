// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP connection tracking stage.
 *
 * Looks up the packet's 5-tuple in the session table. On a hit,
 * updates counters and TCP state, then fast-paths established
 * sessions directly to the forward stage. On a miss, marks the
 * packet as NEW and tail-calls the policy stage.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Build forward session key from 5-tuple */
	struct session_key fwd_key = {};
	fwd_key.src_ip   = meta->src_ip;
	fwd_key.dst_ip   = meta->dst_ip;
	fwd_key.src_port = meta->src_port;
	fwd_key.dst_port = meta->dst_port;
	fwd_key.protocol = meta->protocol;

	/* Try forward key first */
	struct session_value *sess = bpf_map_lookup_elem(&sessions, &fwd_key);
	__u8 direction = 0; /* forward */

	if (!sess) {
		/* Try reverse key */
		struct session_key rev_key;
		ct_reverse_key(&fwd_key, &rev_key);
		sess = bpf_map_lookup_elem(&sessions, &rev_key);
		if (!sess) {
			/* MISS: new connection */
			meta->ct_state = SESS_STATE_NEW;
			meta->ct_direction = 0;
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
			return XDP_PASS;
		}
		direction = 1; /* reverse */
	}

	/* HIT: existing session */
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;
	sess->last_seen = now;

	/* Update counters atomically */
	if (direction == sess->is_reverse) {
		/* We matched the forward entry and direction matches,
		 * or we matched the reverse entry and it's reverse */
		__sync_fetch_and_add(&sess->fwd_packets, 1);
		__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, 1);
		__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
	}

	/* TCP state machine update */
	if (meta->protocol == PROTO_TCP) {
		__u8 new_state = ct_tcp_update_state(
			sess->state, meta->tcp_flags, direction);
		if (new_state != sess->state) {
			sess->state = new_state;
			sess->timeout = ct_get_timeout(PROTO_TCP, new_state);
		}
	}

	/* Fill pkt_meta with session info */
	meta->ct_state = sess->state;
	meta->ct_direction = direction;
	meta->policy_id = sess->policy_id;

	/*
	 * NAT info propagation for established sessions.
	 * Determine if this is a forward or reverse packet relative
	 * to the original session initiator:
	 *   is_fwd = true when we matched the entry whose direction
	 *            matches the original flow direction.
	 */
	int is_fwd = (direction == sess->is_reverse);

	if (sess->flags & SESS_FLAG_SNAT) {
		if (is_fwd) {
			/* Forward SNAT: translate source to NAT IP */
			meta->src_ip   = sess->nat_src_ip;
			meta->src_port = sess->nat_src_port;
		}
		/* Reverse SNAT is handled by dnat_table in xdp_zone */
	}
	if (sess->flags & SESS_FLAG_DNAT) {
		if (!is_fwd) {
			/* Reverse DNAT: restore original VIP as source */
			meta->src_ip   = sess->nat_dst_ip;
			meta->src_port = sess->nat_dst_port;
		}
		/* Forward DNAT is handled by dnat_table in xdp_zone */
	}

	/* Determine tail call target: NAT stage if session has NAT flags */
	__u32 next_prog = XDP_PROG_FORWARD;
	if (sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT))
		next_prog = XDP_PROG_NAT;

	/* Fast-path decision based on state */
	switch (sess->state) {
	case SESS_STATE_CLOSED:
		/* RST received: drop */
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;

	case SESS_STATE_ESTABLISHED:
	case SESS_STATE_FIN_WAIT:
	case SESS_STATE_CLOSE_WAIT:
	case SESS_STATE_TIME_WAIT:
		/* Fast-path: skip policy */
		bpf_tail_call(ctx, &xdp_progs, next_prog);
		return XDP_PASS;

	case SESS_STATE_SYN_SENT:
	case SESS_STATE_SYN_RECV:
		/* Handshake in progress: session already permitted */
		bpf_tail_call(ctx, &xdp_progs, next_prog);
		return XDP_PASS;

	default:
		/* Unknown state, pass through policy */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
		return XDP_PASS;
	}
}

char _license[] SEC("license") = "GPL";
