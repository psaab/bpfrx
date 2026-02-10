// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP connection tracking stage.
 *
 * Looks up the packet's 5-tuple in the session table. On a hit,
 * updates counters and TCP state, then fast-paths established
 * sessions directly to the forward stage. On a miss, marks the
 * packet as NEW and tail-calls the policy stage.
 * Supports both IPv4 and IPv6 sessions.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Handle a conntrack hit for an IPv4 session.
 * Updates counters, TCP state, propagates NAT info.
 */
static __always_inline int
handle_ct_hit_v4(struct xdp_md *ctx, struct pkt_meta *meta,
		 struct session_value *sess, __u8 direction)
{
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;
	sess->last_seen = now;

	if (direction == sess->is_reverse) {
		__sync_fetch_and_add(&sess->fwd_packets, 1);
		__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, 1);
		__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
	}

	if (meta->protocol == PROTO_TCP) {
		__u8 new_state = ct_tcp_update_state(
			sess->state, meta->tcp_flags, direction);
		if (new_state != sess->state) {
			sess->state = new_state;
			sess->timeout = ct_get_timeout(PROTO_TCP, new_state);
		}
	}

	meta->ct_state = sess->state;
	meta->ct_direction = direction;
	meta->policy_id = sess->policy_id;

	int is_fwd = (direction == sess->is_reverse);

	if (sess->flags & SESS_FLAG_SNAT) {
		if (is_fwd) {
			__builtin_memset(&meta->src_ip, 0, sizeof(meta->src_ip));
			meta->src_ip.v4 = sess->nat_src_ip;
			meta->src_port  = sess->nat_src_port;
		}
	}
	if (sess->flags & SESS_FLAG_DNAT) {
		if (!is_fwd) {
			__builtin_memset(&meta->src_ip, 0, sizeof(meta->src_ip));
			meta->src_ip.v4 = sess->nat_dst_ip;
			meta->src_port  = sess->nat_dst_port;
		}
	}

	__u32 next_prog = XDP_PROG_FORWARD;
	if (sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT))
		next_prog = XDP_PROG_NAT;

	switch (sess->state) {
	case SESS_STATE_CLOSED:
		if (sess->log_flags & LOG_FLAG_SESSION_CLOSE)
			emit_event(meta, EVENT_TYPE_SESSION_CLOSE, ACTION_DENY,
				   sess->fwd_packets + sess->rev_packets,
				   sess->fwd_bytes + sess->rev_bytes);
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	case SESS_STATE_ESTABLISHED:
	case SESS_STATE_FIN_WAIT:
	case SESS_STATE_CLOSE_WAIT:
	case SESS_STATE_TIME_WAIT:
	case SESS_STATE_SYN_SENT:
	case SESS_STATE_SYN_RECV:
		bpf_tail_call(ctx, &xdp_progs, next_prog);
		return XDP_PASS;
	default:
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
		return XDP_PASS;
	}
}

/*
 * Handle a conntrack hit for an IPv6 session.
 */
static __always_inline int
handle_ct_hit_v6(struct xdp_md *ctx, struct pkt_meta *meta,
		 struct session_value_v6 *sess, __u8 direction)
{
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;
	sess->last_seen = now;

	if (direction == sess->is_reverse) {
		__sync_fetch_and_add(&sess->fwd_packets, 1);
		__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, 1);
		__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
	}

	if (meta->protocol == PROTO_TCP) {
		__u8 new_state = ct_tcp_update_state(
			sess->state, meta->tcp_flags, direction);
		if (new_state != sess->state) {
			sess->state = new_state;
			sess->timeout = ct_get_timeout(PROTO_TCP, new_state);
		}
	}

	meta->ct_state = sess->state;
	meta->ct_direction = direction;
	meta->policy_id = sess->policy_id;

	int is_fwd = (direction == sess->is_reverse);

	if (sess->flags & SESS_FLAG_SNAT) {
		if (is_fwd) {
			__builtin_memcpy(meta->src_ip.v6, sess->nat_src_ip, 16);
			meta->src_port = sess->nat_src_port;
		}
	}
	if (sess->flags & SESS_FLAG_DNAT) {
		if (!is_fwd) {
			__builtin_memcpy(meta->src_ip.v6, sess->nat_dst_ip, 16);
			meta->src_port = sess->nat_dst_port;
		}
	}

	__u32 next_prog = XDP_PROG_FORWARD;
	if (sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT))
		next_prog = XDP_PROG_NAT;

	switch (sess->state) {
	case SESS_STATE_CLOSED:
		if (sess->log_flags & LOG_FLAG_SESSION_CLOSE)
			emit_event(meta, EVENT_TYPE_SESSION_CLOSE, ACTION_DENY,
				   sess->fwd_packets + sess->rev_packets,
				   sess->fwd_bytes + sess->rev_bytes);
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	case SESS_STATE_ESTABLISHED:
	case SESS_STATE_FIN_WAIT:
	case SESS_STATE_CLOSE_WAIT:
	case SESS_STATE_TIME_WAIT:
	case SESS_STATE_SYN_SENT:
	case SESS_STATE_SYN_RECV:
		bpf_tail_call(ctx, &xdp_progs, next_prog);
		return XDP_PASS;
	default:
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
		return XDP_PASS;
	}
}

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	if (meta->addr_family == AF_INET) {
		/* IPv4 path */
		struct session_key fwd_key = {};
		fwd_key.src_ip   = meta->src_ip.v4;
		fwd_key.dst_ip   = meta->dst_ip.v4;
		fwd_key.src_port = meta->src_port;
		fwd_key.dst_port = meta->dst_port;
		fwd_key.protocol = meta->protocol;

		struct session_value *sess = bpf_map_lookup_elem(&sessions, &fwd_key);
		__u8 direction = 0;

		if (!sess) {
			struct session_key rev_key;
			ct_reverse_key(&fwd_key, &rev_key);
			sess = bpf_map_lookup_elem(&sessions, &rev_key);
			if (!sess) {
				/*
				 * NAT64 reverse check: IPv4 return traffic
				 * from a server that was translated from IPv6.
				 * Look up nat64_state to find original v6 info.
				 */
				struct nat64_state_key n64k = {
					.src_ip   = meta->src_ip.v4,
					.dst_ip   = meta->dst_ip.v4,
					.src_port = meta->src_port,
					.dst_port = meta->dst_port,
					.protocol = meta->protocol,
				};
				struct nat64_state_value *n64v =
					bpf_map_lookup_elem(&nat64_state, &n64k);
				if (n64v) {
					/*
					 * NAT64 reverse match: pass original
					 * v6 addresses via meta for xdp_nat64
					 * to do the v4→v6 translation.
					 * nat_src_ip = client v6 (dst of rebuilt pkt)
					 * nat_dst_ip = server v6 (src of rebuilt pkt)
					 */
					__builtin_memcpy(meta->nat_src_ip.v6,
							 n64v->orig_src_v6, 16);
					__builtin_memcpy(meta->nat_dst_ip.v6,
							 n64v->orig_dst_v6, 16);
					meta->nat_flags |= SESS_FLAG_NAT64;
					meta->dst_port = n64v->orig_src_port;

					/* Skip policy, go directly to NAT64
					 * translation (this is return traffic). */
					bpf_tail_call(ctx, &xdp_progs,
						      XDP_PROG_NAT64);
					return XDP_PASS;
				}

				meta->ct_state = SESS_STATE_NEW;
				meta->ct_direction = 0;
				bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
				return XDP_PASS;
			}
			direction = 1;
		}

		return handle_ct_hit_v4(ctx, meta, sess, direction);
	} else {
		/* IPv6 path */
		struct session_key_v6 fwd_key = {};
		__builtin_memcpy(fwd_key.src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(fwd_key.dst_ip, meta->dst_ip.v6, 16);
		fwd_key.src_port = meta->src_port;
		fwd_key.dst_port = meta->dst_port;
		fwd_key.protocol = meta->protocol;

		struct session_value_v6 *sess = bpf_map_lookup_elem(&sessions_v6, &fwd_key);
		__u8 direction = 0;

		if (!sess) {
			struct session_key_v6 rev_key;
			ct_reverse_key_v6(&fwd_key, &rev_key);
			sess = bpf_map_lookup_elem(&sessions_v6, &rev_key);
			if (!sess) {
				meta->ct_state = SESS_STATE_NEW;
				meta->ct_direction = 0;
				bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
				return XDP_PASS;
			}
			direction = 1;
		}

		return handle_ct_hit_v6(ctx, meta, sess, direction);
	}
}

char _license[] SEC("license") = "GPL";
