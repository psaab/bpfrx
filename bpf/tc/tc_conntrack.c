// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress connection tracking stage.
 *
 * Looks up existing sessions (v4 and v6), updates last_seen timestamp
 * and counters for egress packets, propagates NAT metadata from the
 * session, and routes to TC NAT or TC forward accordingly.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_conntrack.h"
#include "../headers/bpfrx_trace.h"

/*
 * Handle a conntrack hit for an IPv4 session on TC egress.
 * Updates counters and propagates NAT metadata.
 */
static __always_inline void
tc_ct_hit_v4(struct __sk_buff *skb, struct pkt_meta *meta,
	     struct session_value *sess, __u8 direction)
{
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;
	sess->last_seen = now;

	int is_fwd = (direction == sess->is_reverse);

	if (is_fwd) {
		__sync_fetch_and_add(&sess->fwd_packets, 1);
		__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, 1);
		__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
	}

	/* Propagate NAT metadata */
	meta->nat_flags = sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT);

	if (sess->flags & SESS_FLAG_SNAT) {
		if (is_fwd) {
			meta->src_ip.v4 = sess->nat_src_ip;
			meta->src_port  = sess->nat_src_port;
		}
	}
	if (sess->flags & SESS_FLAG_DNAT) {
		if (!is_fwd) {
			meta->src_ip.v4 = sess->nat_dst_ip;
			meta->src_port  = sess->nat_dst_port;
		}
	}

	/* Route to NAT if needed, otherwise forward */
	__u32 next = (meta->nat_flags) ? TC_PROG_NAT : TC_PROG_FORWARD;
	bpf_tail_call(skb, &tc_progs, next);
}

/*
 * Handle a conntrack hit for an IPv6 session on TC egress.
 * Updates counters and propagates NAT metadata.
 */
static __always_inline void
tc_ct_hit_v6(struct __sk_buff *skb, struct pkt_meta *meta,
	     struct session_value_v6 *sess, __u8 direction)
{
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;
	sess->last_seen = now;

	int is_fwd = (direction == sess->is_reverse);

	if (is_fwd) {
		__sync_fetch_and_add(&sess->fwd_packets, 1);
		__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, 1);
		__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
	}

	/* Propagate NAT metadata */
	meta->nat_flags = sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT);

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

	/* Route to NAT if needed, otherwise forward */
	__u32 next = (meta->nat_flags) ? TC_PROG_NAT : TC_PROG_FORWARD;
	bpf_tail_call(skb, &tc_progs, next);
}

SEC("tc")
int tc_conntrack_prog(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return TC_ACT_SHOT;

	if (meta->addr_family == AF_INET) {
		/* Build session key from egress packet */
		struct session_key fwd_key = {};
		fwd_key.src_ip   = meta->src_ip.v4;
		fwd_key.dst_ip   = meta->dst_ip.v4;
		fwd_key.src_port = meta->src_port;
		fwd_key.dst_port = meta->dst_port;
		fwd_key.protocol = meta->protocol;

		struct session_value *sess = bpf_map_lookup_elem(&sessions, &fwd_key);
		if (sess) {
			TRACE_TC_CT(meta, 1, 0);
			tc_ct_hit_v4(skb, meta, sess, 0);
		} else {
			struct session_key rev_key;
			ct_reverse_key(&fwd_key, &rev_key);
			sess = bpf_map_lookup_elem(&sessions, &rev_key);
			if (sess) {
				TRACE_TC_CT(meta, 1, 1);
				tc_ct_hit_v4(skb, meta, sess, 1);
			} else {
				TRACE_TC_CT(meta, 0, 0);
			}
		}
	} else {
		/* IPv6 path */
		struct session_key_v6 fwd_key = {};
		__builtin_memcpy(fwd_key.src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(fwd_key.dst_ip, meta->dst_ip.v6, 16);
		fwd_key.src_port = meta->src_port;
		fwd_key.dst_port = meta->dst_port;
		fwd_key.protocol = meta->protocol;

		struct session_value_v6 *sess = bpf_map_lookup_elem(&sessions_v6, &fwd_key);
		if (sess) {
			tc_ct_hit_v6(skb, meta, sess, 0);
		} else {
			struct session_key_v6 rev_key;
			ct_reverse_key_v6(&fwd_key, &rev_key);
			sess = bpf_map_lookup_elem(&sessions_v6, &rev_key);
			if (sess)
				tc_ct_hit_v6(skb, meta, sess, 1);
		}
	}

	/*
	 * No session found. If ingress_ifindex is set, this is a packet
	 * being forwarded by the kernel (not locally originated). Drop it
	 * to prevent un-NAT'd packets from leaking out — the XDP pipeline
	 * handles forwarded traffic via bpf_redirect. This path only
	 * triggers when XDP passed a packet to the kernel for ARP/NDP
	 * neighbor resolution (NO_NEIGH case).
	 */
	if (meta->ingress_ifindex != 0) {
		/* Allow ICMP error types through — these were already
		 * validated by the XDP pipeline against an existing
		 * session and rewritten to reach the original client. */
		if (meta->protocol == PROTO_ICMP &&
		    (meta->icmp_type == 3 || meta->icmp_type == 11 ||
		     meta->icmp_type == 12)) {
			__u32 fc_key = 0;
			struct flow_config *fc =
				bpf_map_lookup_elem(&flow_config_map, &fc_key);
			if (fc && fc->allow_embedded_icmp) {
				bpf_tail_call(skb, &tc_progs,
					      TC_PROG_FORWARD);
				return TC_ACT_OK;
			}
		}
		return TC_ACT_SHOT;
	}

	/* Locally-originated traffic -- tail-call to forward (pass through) */
	bpf_tail_call(skb, &tc_progs, TC_PROG_FORWARD);
	return TC_ACT_OK; /* fallthrough = pass */
}

char _license[] SEC("license") = "GPL";
