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
	__u64 now = meta->now_sec;
	if (sess->state != SESS_STATE_CLOSED && sess->last_seen != now)
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
	__u64 now = meta->now_sec;
	if (sess->state != SESS_STATE_CLOSED && sess->last_seen != now)
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

/*
 * Allocate a unique session ID from the per-CPU generator.
 * (Same as xdp_policy.c — static inline, not in a shared header.)
 */
static __always_inline __u64
alloc_session_id(void)
{
	__u32 z = 0;
	__u64 *gen = bpf_map_lookup_elem(&session_id_gen, &z);
	if (!gen)
		return 0;
	__u64 val = *gen + 1;
	*gen = val;
	return val;
}

/*
 * Create dual session entries for locally-originated IPv4 traffic.
 * ingress_zone = 0 (junos-host / self), egress_zone from meta.
 * No NAT, no policy, no FIB cache.
 */
static __always_inline void
tc_create_session_v4(struct pkt_meta *meta)
{
	__u64 now = meta->now_sec;

	struct session_key fwd_key = {};
	fwd_key.src_ip   = meta->src_ip.v4;
	fwd_key.dst_ip   = meta->dst_ip.v4;
	fwd_key.src_port = meta->src_port;
	fwd_key.dst_port = meta->dst_port;
	fwd_key.protocol = meta->protocol;

	struct session_key rev_key;
	ct_reverse_key(&fwd_key, &rev_key);

	__u8 initial_state;
	if (meta->protocol == PROTO_TCP && (meta->tcp_flags & 0x02))
		initial_state = SESS_STATE_SYN_SENT;
	else
		initial_state = SESS_STATE_ESTABLISHED;

	__u32 timeout = ct_get_timeout(meta->protocol, initial_state);

	__u32 idx0 = 0;
	struct session_value *fwd_val = bpf_map_lookup_elem(
		&session_v4_scratch, &idx0);
	if (!fwd_val)
		return;

	__u64 sid = alloc_session_id();

	__builtin_memset(fwd_val, 0, sizeof(*fwd_val));
	fwd_val->state        = initial_state;
	fwd_val->is_reverse   = 0;
	fwd_val->session_id   = sid;
	fwd_val->created      = now;
	fwd_val->last_seen    = now;
	fwd_val->timeout      = timeout;
	fwd_val->ingress_zone = 0; /* junos-host (self) */
	fwd_val->egress_zone  = meta->egress_zone;
	fwd_val->fwd_packets  = 1;
	fwd_val->fwd_bytes    = meta->pkt_len;
	fwd_val->reverse_key  = rev_key;

	int ret = bpf_map_update_elem(&sessions, &fwd_key, fwd_val,
				      BPF_NOEXIST);
	if (ret < 0)
		return;

	__u32 idx1 = 1;
	struct session_value *rev_val = bpf_map_lookup_elem(
		&session_v4_scratch, &idx1);
	if (!rev_val) {
		bpf_map_delete_elem(&sessions, &fwd_key);
		return;
	}

	__builtin_memset(rev_val, 0, sizeof(*rev_val));
	rev_val->state        = initial_state;
	rev_val->is_reverse   = 1;
	rev_val->session_id   = sid;
	rev_val->created      = now;
	rev_val->last_seen    = now;
	rev_val->timeout      = timeout;
	rev_val->ingress_zone = meta->egress_zone;
	rev_val->egress_zone  = 0; /* junos-host (self) */
	rev_val->reverse_key  = fwd_key;

	ret = bpf_map_update_elem(&sessions, &rev_key, rev_val,
				  BPF_NOEXIST);
	if (ret < 0) {
		bpf_map_delete_elem(&sessions, &fwd_key);
		return;
	}

	inc_counter(GLOBAL_CTR_SESSIONS_NEW);
}

/*
 * Create dual session entries for locally-originated IPv6 traffic.
 */
static __always_inline void
tc_create_session_v6(struct pkt_meta *meta)
{
	__u64 now = meta->now_sec;

	struct session_key_v6 fwd_key = {};
	__builtin_memcpy(fwd_key.src_ip, meta->src_ip.v6, 16);
	__builtin_memcpy(fwd_key.dst_ip, meta->dst_ip.v6, 16);
	fwd_key.src_port = meta->src_port;
	fwd_key.dst_port = meta->dst_port;
	fwd_key.protocol = meta->protocol;

	struct session_key_v6 rev_key;
	ct_reverse_key_v6(&fwd_key, &rev_key);

	__u8 initial_state;
	if (meta->protocol == PROTO_TCP && (meta->tcp_flags & 0x02))
		initial_state = SESS_STATE_SYN_SENT;
	else
		initial_state = SESS_STATE_ESTABLISHED;

	__u32 timeout = ct_get_timeout(meta->protocol, initial_state);

	__u32 idx0 = 0;
	struct session_value_v6 *fwd_val = bpf_map_lookup_elem(
		&session_v6_scratch, &idx0);
	if (!fwd_val)
		return;

	__u64 sid = alloc_session_id();

	__builtin_memset(fwd_val, 0, sizeof(*fwd_val));
	fwd_val->state        = initial_state;
	fwd_val->is_reverse   = 0;
	fwd_val->session_id   = sid;
	fwd_val->created      = now;
	fwd_val->last_seen    = now;
	fwd_val->timeout      = timeout;
	fwd_val->ingress_zone = 0;
	fwd_val->egress_zone  = meta->egress_zone;
	fwd_val->fwd_packets  = 1;
	fwd_val->fwd_bytes    = meta->pkt_len;
	fwd_val->reverse_key  = rev_key;

	int ret = bpf_map_update_elem(&sessions_v6, &fwd_key, fwd_val,
				      BPF_NOEXIST);
	if (ret < 0)
		return;

	__u32 idx1 = 1;
	struct session_value_v6 *rev_val = bpf_map_lookup_elem(
		&session_v6_scratch, &idx1);
	if (!rev_val) {
		bpf_map_delete_elem(&sessions_v6, &fwd_key);
		return;
	}

	__builtin_memset(rev_val, 0, sizeof(*rev_val));
	rev_val->state        = initial_state;
	rev_val->is_reverse   = 1;
	rev_val->session_id   = sid;
	rev_val->created      = now;
	rev_val->last_seen    = now;
	rev_val->timeout      = timeout;
	rev_val->ingress_zone = meta->egress_zone;
	rev_val->egress_zone  = 0;
	rev_val->reverse_key  = fwd_key;

	ret = bpf_map_update_elem(&sessions_v6, &rev_key, rev_val,
				  BPF_NOEXIST);
	if (ret < 0) {
		bpf_map_delete_elem(&sessions_v6, &fwd_key);
		return;
	}

	inc_counter(GLOBAL_CTR_SESSIONS_NEW);
}

SEC("tc")
int tc_conntrack_prog(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return TC_ACT_SHOT;

	/* Single flow_config lookup: reused for MSS clamp and
	 * allow_embedded_icmp check below. */
	struct flow_config *fc = bpf_map_lookup_elem(&flow_config_map, &zero);

	/* TCP MSS clamping on egress SYN packets (gre-out / ipsec-vpn). */
	if (meta->protocol == PROTO_TCP && (meta->tcp_flags & 0x02)) {
		/* Resolve deferred IPv6 CHECKSUM_PARTIAL for MSS clamp. */
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;
		resolve_csum_partial(data, data_end, meta);
		if (fc) {
			__u16 mss = fc->tcp_mss_gre_out;
			if (fc->tcp_mss_ipsec > 0 && (fc->tcp_mss_ipsec < mss || mss == 0))
				mss = fc->tcp_mss_ipsec;
			if (mss > 0)
				tc_tcp_mss_clamp(skb, meta->l4_offset, mss,
						 meta->csum_partial);
		}
	}

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
		if ((meta->protocol == PROTO_ICMP &&
		     (meta->icmp_type == 3 || meta->icmp_type == 11 ||
		      meta->icmp_type == 12)) ||
		    (meta->protocol == PROTO_ICMPV6 &&
		     (meta->icmp_type == 1 || meta->icmp_type == 3 ||
		      meta->icmp_type == 4))) {
			if (fc && fc->allow_embedded_icmp) {
				bpf_tail_call(skb, &tc_progs,
					      TC_PROG_FORWARD);
				return TC_ACT_OK;
			}
		}
		/* Allow fabric transit: packets forwarded from the
		 * fabric peer via kernel routing (XDP_PASS path).
		 * In active/active, the peer does NAT reversal and
		 * sends post-NAT traffic here for local delivery.
		 * The session lives on the peer, not locally, so
		 * TC conntrack won't find a match.  The peer's XDP
		 * pipeline already validated the traffic — trust it. */
		{
			__u32 ff_key0 = 0, ff_key1 = 1;
			struct fabric_fwd_info *ff0 =
				bpf_map_lookup_elem(&fabric_fwd,
						    &ff_key0);
			struct fabric_fwd_info *ff1 =
				bpf_map_lookup_elem(&fabric_fwd,
						    &ff_key1);
			if ((ff0 && ff0->ifindex != 0 && meta->ingress_ifindex == ff0->ifindex) ||
			    (ff1 && ff1->ifindex != 0 && meta->ingress_ifindex == ff1->ifindex)) {
				bpf_tail_call(skb, &tc_progs,
					      TC_PROG_FORWARD);
				return TC_ACT_OK;
			}
		}
		/* Allow tunnel-encapsulated outer packets.  When XDP
		 * does XDP_PASS for tunnel-routed traffic, the kernel
		 * forwards through the tunnel (GRE/ESP).  The tunnel
		 * driver prepends outer headers to the same skb, so
		 * ingress_ifindex is still set from the original inner
		 * packet.  The inner packet was validated by XDP — the
		 * outer encapsulation is trusted local kernel work.
		 * Create a session so XDP ingress can match the return
		 * (decapsulated reply) via the reverse conntrack entry. */
		if (meta->protocol == PROTO_GRE ||
		    meta->protocol == PROTO_ESP) {
			if (meta->addr_family == AF_INET)
				tc_create_session_v4(meta);
			else
				tc_create_session_v6(meta);
			bpf_tail_call(skb, &tc_progs,
				      TC_PROG_FORWARD);
			return TC_ACT_OK;
		}
		return TC_ACT_SHOT;
	}

	/* Locally-originated traffic — create session for return matching */
	if (meta->addr_family == AF_INET)
		tc_create_session_v4(meta);
	else
		tc_create_session_v6(meta);

	bpf_tail_call(skb, &tc_progs, TC_PROG_FORWARD);
	return TC_ACT_OK; /* fallthrough = pass */
}

char _license[] SEC("license") = "GPL";
