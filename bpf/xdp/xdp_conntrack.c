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
#include "../headers/bpfrx_nat.h"
#include "../headers/bpfrx_trace.h"

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

	/* Compute actual packet direction relative to the session.
	 * 'direction' is the lookup direction (0=found on first try),
	 * which with dual entries is almost always 0 regardless of
	 * packet direction.  XOR with is_reverse gives the true
	 * direction: 0=initiator (forward), 1=responder (reverse). */
	int is_fwd = (direction == sess->is_reverse);
	__u8 pkt_dir = direction ^ sess->is_reverse;

	if (meta->protocol == PROTO_TCP) {
		__u8 new_state = ct_tcp_update_state(
			sess->state, meta->tcp_flags, pkt_dir);
		if (new_state != sess->state) {
			sess->state = new_state;
			__u32 new_timeout = ct_get_timeout(PROTO_TCP, new_state);
			/* Per-app timeout overrides default for
			 * non-closing states (ESTABLISHED, SYN_RECV). */
			if (sess->app_timeout > 0 &&
			    new_state != SESS_STATE_CLOSED &&
			    new_state != SESS_STATE_FIN_WAIT)
				new_timeout = (__u32)sess->app_timeout;
			sess->timeout = new_timeout;
			/* Sync state to paired entry so both entries
			 * share the same TCP state and timeout. */
			struct session_value *paired =
				bpf_map_lookup_elem(&sessions,
						    &sess->reverse_key);
			if (paired) {
				paired->state = new_state;
				paired->timeout = new_timeout;
				paired->last_seen = now;
			}
		}
	}

	meta->ct_state = sess->state;
	meta->ct_direction = direction;
	meta->policy_id = sess->policy_id;

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

	__u32 next_prog = XDP_PROG_FORWARD;
	if (sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT))
		next_prog = XDP_PROG_NAT;

	switch (sess->state) {
	case SESS_STATE_CLOSED:
		/* Forward the RST that closed the session so the peer
		 * receives it.  Drop any subsequent non-RST packets. */
		if (meta->tcp_flags & 0x04) {
			bpf_tail_call(ctx, &xdp_progs, next_prog);
			return XDP_PASS;
		}
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

	/* Compute actual packet direction relative to the session.
	 * See handle_ct_hit_v4 for explanation. */
	int is_fwd = (direction == sess->is_reverse);
	__u8 pkt_dir = direction ^ sess->is_reverse;

	if (meta->protocol == PROTO_TCP) {
		__u8 new_state = ct_tcp_update_state(
			sess->state, meta->tcp_flags, pkt_dir);
		if (new_state != sess->state) {
			sess->state = new_state;
			__u32 new_timeout = ct_get_timeout(PROTO_TCP, new_state);
			if (sess->app_timeout > 0 &&
			    new_state != SESS_STATE_CLOSED &&
			    new_state != SESS_STATE_FIN_WAIT)
				new_timeout = (__u32)sess->app_timeout;
			sess->timeout = new_timeout;
			/* Sync state to paired entry so both entries
			 * share the same TCP state and timeout. */
			struct session_value_v6 *paired =
				bpf_map_lookup_elem(&sessions_v6,
						    &sess->reverse_key);
			if (paired) {
				paired->state = new_state;
				paired->timeout = new_timeout;
				paired->last_seen = now;
			}
		}
	}

	meta->ct_state = sess->state;
	meta->ct_direction = direction;
	meta->policy_id = sess->policy_id;

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
		/* Forward the RST that closed the session so the peer
		 * receives it.  Drop any subsequent non-RST packets. */
		if (meta->tcp_flags & 0x04) {
			bpf_tail_call(ctx, &xdp_progs, next_prog);
			return XDP_PASS;
		}
		if (sess->log_flags & LOG_FLAG_SESSION_CLOSE)
			emit_event_nat6(meta, EVENT_TYPE_SESSION_CLOSE,
					ACTION_DENY,
					sess->fwd_packets + sess->rev_packets,
					sess->fwd_bytes + sess->rev_bytes,
					sess->nat_src_ip, sess->nat_dst_ip,
					sess->nat_src_port, sess->nat_dst_port,
					(__u32)(sess->created & 0xFFFFFFFF));
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
 * Handle ICMP error packets (Dest Unreachable, Time Exceeded, Param Problem)
 * that contain an embedded original packet header.  Reverse-lookup the SNAT
 * translation via dnat_table, match the original session, then set up
 * forwarding + NAT rewrite metadata so the error reaches the client.
 *
 * Returns XDP_PASS on tail-call success, -1 on no match.
 */
static __always_inline int
handle_embedded_icmp_v4(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Locate embedded IP header (starts after 8-byte ICMP header) */
	__u16 emb_ip_off = meta->l4_offset + 8;
	if (emb_ip_off >= 200)
		return -1;
	struct iphdr *emb_ip = data + emb_ip_off;
	if ((void *)(emb_ip + 1) > data_end)
		return -1;

	/* Read all embedded IP fields to stack NOW -- the verifier
	 * loses packet range tracking after branches below. */
	__u8  emb_proto = emb_ip->protocol;
	__u8  emb_ihl   = emb_ip->ihl;
	__be32 emb_saddr = emb_ip->saddr;
	__be32 emb_daddr = emb_ip->daddr;

	if (emb_ihl < 5 || emb_ihl > 15)
		return -1;

	/* Parse embedded L4 ports (first 4 bytes guaranteed by RFC) */
	__u16 emb_l4_off = emb_ip_off + ((__u16)emb_ihl) * 4;
	if (emb_l4_off >= 250)
		return -1;

	/* Access embedded L4 through a single pointer variable so the
	 * verifier tracks the bounds check and access on the same reg. */
	__be16 emb_src_port = 0, emb_dst_port = 0;
	void *emb_l4 = data + emb_l4_off;
	if (emb_proto == PROTO_TCP || emb_proto == PROTO_UDP) {
		if (emb_l4 + 4 > data_end)
			return -1;
		emb_src_port = *(__be16 *)emb_l4;
		emb_dst_port = *(__be16 *)(emb_l4 + 2);
	} else if (emb_proto == PROTO_ICMP) {
		/* Echo ID is at offset 4 in ICMP header (type+code+csum+id) */
		if (emb_l4 + 6 > data_end)
			return -1;
		emb_src_port = *(__be16 *)(emb_l4 + 4);
		emb_dst_port = emb_src_port;
	}

	/* All packet data is now on the stack -- no more packet pointer
	 * dereferences.  Use stack copies (emb_saddr, emb_daddr, etc.). */

	/* Reverse SNAT via dnat_table: the embedded src is the SNAT'd address */
	struct dnat_key dk = {
		.protocol = emb_proto,
		.dst_ip   = emb_saddr,
		.dst_port = emb_src_port,
	};
	struct dnat_value *dv = bpf_map_lookup_elem(&dnat_table, &dk);

	__be32 orig_src_ip;
	__be16 orig_src_port;
	int needs_nat = 0;

	if (dv) {
		/* SNAT flow: dnat_table gives us the pre-SNAT source */
		orig_src_ip = dv->new_dst_ip;
		orig_src_port = dv->new_dst_port;
		needs_nat = 1;
	} else {
		/* Non-SNAT flow: use embedded addresses directly */
		orig_src_ip = emb_saddr;
		orig_src_port = emb_src_port;
	}

	/* Look up original session with pre-SNAT 5-tuple.
	 * For ICMP echo, src_port == dst_port == echo_id.  SNAT rewrites
	 * the echo ID, so both ports in the embedded packet are the
	 * SNAT'd value.  Use the de-SNAT'd port for both. */
	__be16 lookup_dst_port = emb_dst_port;
	if (emb_proto == PROTO_ICMP && needs_nat)
		lookup_dst_port = orig_src_port;

	struct session_key sk = {
		.src_ip   = orig_src_ip,
		.dst_ip   = emb_daddr,
		.src_port = orig_src_port,
		.dst_port = lookup_dst_port,
		.protocol = emb_proto,
	};
	struct session_value *sess = bpf_map_lookup_elem(&sessions, &sk);
	if (!sess) {
		struct session_key rk;
		ct_reverse_key(&sk, &rk);
		sess = bpf_map_lookup_elem(&sessions, &rk);
	}
	if (!sess)
		return -1;  /* No matching session */

	/* Touch the session so GC doesn't expire it while errors flow */
	sess->last_seen = bpf_ktime_get_ns() / 1000000000ULL;

	/* FIB lookup to route toward the original client */
	struct bpf_fib_lookup fib = {};
	fib.family = AF_INET;
	fib.l4_protocol = PROTO_ICMP;
	fib.tot_len = meta->pkt_len;
	fib.ifindex = meta->ingress_ifindex;
	fib.tbid = meta->routing_table;
	fib.ipv4_src = meta->src_ip.v4;
	fib.ipv4_dst = orig_src_ip;

	__u32 fib_flags = meta->routing_table ? BPF_FIB_LOOKUP_TBID : 0;
	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), fib_flags);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		return -1;

	/* Resolve VLAN sub-interface */
	__u32 egress_if = fib.ifindex;
	struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map,
							 &egress_if);
	if (vi) {
		meta->fwd_ifindex = vi->parent_ifindex;
		meta->egress_vlan_id = vi->vlan_id;
	} else {
		meta->fwd_ifindex = egress_if;
		meta->egress_vlan_id = 0;
	}
	__builtin_memcpy(meta->fwd_dmac, fib.dmac, 6);
	__builtin_memcpy(meta->fwd_smac, fib.smac, 6);

	/* Resolve egress zone */
	struct iface_zone_key ezk = {
		.ifindex = meta->fwd_ifindex,
		.vlan_id = meta->egress_vlan_id,
	};
	__u16 *ez = bpf_map_lookup_elem(&iface_zone_map, &ezk);
	if (ez)
		meta->egress_zone = *ez;

	if (needs_nat) {
		/* Outer dst rewrite: WAN IP -> original client */
		meta->dst_ip.v4 = orig_src_ip;
		meta->nat_flags = SESS_FLAG_DNAT;
		/* Embedded rewrite info */
		__builtin_memset(&meta->nat_src_ip, 0,
				 sizeof(meta->nat_src_ip));
		meta->nat_src_ip.v4 = orig_src_ip;
		meta->nat_src_port = orig_src_port;
		meta->meta_flags = META_FLAG_EMBEDDED_ICMP;
		meta->embedded_proto = emb_proto;
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_NAT);
	} else {
		/* No NAT, just forward */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	}
	return XDP_PASS;
}

/*
 * Handle ICMPv6 error packets (Dest Unreachable type 1, Time Exceeded type 3,
 * Param Problem type 4) that contain an embedded original IPv6 packet header.
 * Reverse-lookup the SNAT translation via dnat_table_v6, match the original
 * session, then set up forwarding + NAT rewrite metadata so the error reaches
 * the original client.
 *
 * Returns XDP_PASS on tail-call success, -1 on no match.
 */
static __always_inline int
handle_embedded_icmp_v6(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Locate embedded IPv6 header (starts after 8-byte ICMPv6 header) */
	__u16 emb_ip_off = meta->l4_offset + 8;
	if (emb_ip_off >= 200)
		return -1;
	struct ipv6hdr *emb_ip6 = data + emb_ip_off;
	if ((void *)(emb_ip6 + 1) > data_end)
		return -1;

	/* Read embedded IPv6 addresses to stack NOW -- the verifier
	 * loses packet range tracking after branches below. */
	__u8 emb_saddr[16], emb_daddr[16];
	__builtin_memcpy(emb_saddr, &emb_ip6->saddr, 16);
	__builtin_memcpy(emb_daddr, &emb_ip6->daddr, 16);

	/* Embedded L4 protocol: skip extension header walking.
	 * Extension headers in ICMPv6 error embedded packets are
	 * extremely rare — the embedded packet is the original
	 * offending packet (typically TCP/UDP/ICMPv6 with no ext
	 * headers).  Walking them causes BPF verifier failures:
	 * variable-offset pkt pointer tracking requires var_off
	 * bounded to ~8 bits, but ext header lengths are wider.
	 * If next header isn't a direct L4 protocol, give up. */
	__u8 emb_proto = emb_ip6->nexthdr;
	if (emb_proto != PROTO_TCP && emb_proto != PROTO_UDP &&
	    emb_proto != PROTO_ICMPV6)
		return -1;

	/* Parse embedded L4 ports.
	 * Use a CONSTANT offset from the already-validated emb_ip6
	 * pointer: (emb_ip6 + 1) is exactly +40 bytes, and the
	 * verifier can track constant-offset range additions. This
	 * avoids variable-offset pkt pointer arithmetic which causes
	 * verifier failures (__u16 sign-extension + wide var_off). */
	__be16 emb_src_port = 0, emb_dst_port = 0;
	void *emb_l4 = (void *)(emb_ip6 + 1);
	if (emb_l4 + 6 > data_end)
		return -1;
	if (emb_proto == PROTO_TCP || emb_proto == PROTO_UDP) {
		emb_src_port = *(__be16 *)emb_l4;
		emb_dst_port = *(__be16 *)(emb_l4 + 2);
	} else if (emb_proto == PROTO_ICMPV6) {
		/* Echo ID is at offset 4 in ICMPv6 header */
		emb_src_port = *(__be16 *)(emb_l4 + 4);
		emb_dst_port = emb_src_port;
	}

	/* All packet data is now on the stack -- use stack copies. */

	/* NPTv6 reverse: if embedded source matches an NPTv6 external
	 * prefix, translate it back to the internal prefix.  The session
	 * was created with the internal (pre-NPTv6) address, so the
	 * dnat_table and session lookups need the internal form. */
	int nptv6_hit = 0;
	{
		struct nptv6_key nk = {};
		nk.direction = NPTV6_INBOUND;
		nk.prefix_len = 64;
		__builtin_memcpy(nk.prefix, emb_saddr, 8);
		struct nptv6_value *nv = bpf_map_lookup_elem(&nptv6_rules, &nk);
		if (!nv) {
			__builtin_memset(&nk, 0, sizeof(nk));
			nk.direction = NPTV6_INBOUND;
			nk.prefix_len = 48;
			__builtin_memcpy(nk.prefix, emb_saddr, 6);
			nv = bpf_map_lookup_elem(&nptv6_rules, &nk);
		}
		if (nv) {
			nptv6_translate(emb_saddr, nv, NPTV6_INBOUND);
			nptv6_hit = 1;
		}
	}

	/* Reverse SNAT via dnat_table_v6: embedded src is the SNAT'd address */
	struct dnat_key_v6 dk6 = { .protocol = emb_proto };
	__builtin_memcpy(dk6.dst_ip, emb_saddr, 16);
	dk6.dst_port = emb_src_port;

	struct dnat_value_v6 *dv6 = bpf_map_lookup_elem(&dnat_table_v6, &dk6);

	__u8 orig_src_ip[16];
	__be16 orig_src_port;
	int needs_nat = 0;

	if (dv6) {
		/* SNAT flow: dnat_table_v6 gives us the pre-SNAT source */
		__builtin_memcpy(orig_src_ip, dv6->new_dst_ip, 16);
		orig_src_port = dv6->new_dst_port;
		needs_nat = 1;
	} else {
		/* Non-SNAT flow: use embedded addresses directly */
		__builtin_memcpy(orig_src_ip, emb_saddr, 16);
		orig_src_port = emb_src_port;
	}

	/* Look up original session with pre-SNAT 5-tuple.
	 * For ICMPv6 echo, src_port == dst_port == echo_id. SNAT rewrites
	 * the echo ID, so use the de-SNAT'd port for both. */
	__be16 lookup_dst_port = emb_dst_port;
	if (emb_proto == PROTO_ICMPV6 && needs_nat)
		lookup_dst_port = orig_src_port;

	struct session_key_v6 sk6 = { .protocol = emb_proto };
	__builtin_memcpy(sk6.src_ip, orig_src_ip, 16);
	__builtin_memcpy(sk6.dst_ip, emb_daddr, 16);
	sk6.src_port = orig_src_port;
	sk6.dst_port = lookup_dst_port;

	struct session_value_v6 *sess = bpf_map_lookup_elem(&sessions_v6, &sk6);
	if (!sess) {
		struct session_key_v6 rk6;
		ct_reverse_key_v6(&sk6, &rk6);
		sess = bpf_map_lookup_elem(&sessions_v6, &rk6);
	}
	if (!sess)
		return -1;  /* No matching session */

	/* Touch the session so GC doesn't expire it while errors flow */
	sess->last_seen = bpf_ktime_get_ns() / 1000000000ULL;

	/* FIB lookup to route toward the original client */
	struct bpf_fib_lookup fib = {};
	fib.family = AF_INET6;
	fib.l4_protocol = PROTO_ICMPV6;
	fib.tot_len = meta->pkt_len;
	fib.ifindex = meta->ingress_ifindex;
	fib.tbid = meta->routing_table;
	__builtin_memcpy(fib.ipv6_src, meta->src_ip.v6, 16);
	__builtin_memcpy(fib.ipv6_dst, orig_src_ip, 16);

	__u32 fib_flags6 = meta->routing_table ? BPF_FIB_LOOKUP_TBID : 0;
	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), fib_flags6);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		return -1;

	/* Resolve VLAN sub-interface */
	__u32 egress_if = fib.ifindex;
	struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map,
							 &egress_if);
	if (vi) {
		meta->fwd_ifindex = vi->parent_ifindex;
		meta->egress_vlan_id = vi->vlan_id;
	} else {
		meta->fwd_ifindex = egress_if;
		meta->egress_vlan_id = 0;
	}
	__builtin_memcpy(meta->fwd_dmac, fib.dmac, 6);
	__builtin_memcpy(meta->fwd_smac, fib.smac, 6);

	/* Resolve egress zone */
	struct iface_zone_key ezk = {
		.ifindex = meta->fwd_ifindex,
		.vlan_id = meta->egress_vlan_id,
	};
	__u16 *ez = bpf_map_lookup_elem(&iface_zone_map, &ezk);
	if (ez)
		meta->egress_zone = *ez;

	if (needs_nat || nptv6_hit) {
		/* Outer dst rewrite: WAN IP / NPTv6 external -> original client */
		__builtin_memcpy(meta->dst_ip.v6, orig_src_ip, 16);
		meta->nat_flags = SESS_FLAG_DNAT;
		/* Embedded rewrite info: restore embedded src to pre-NAT/NPTv6 */
		__builtin_memcpy(meta->nat_src_ip.v6, orig_src_ip, 16);
		meta->nat_src_port = orig_src_port;
		meta->meta_flags = META_FLAG_EMBEDDED_ICMP;
		meta->embedded_proto = emb_proto;
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_NAT);
	} else {
		/* No NAT, just forward */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	}
	return XDP_PASS;
}

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* TCP MSS clamping on SYN packets.
	 * For CHECKSUM_PARTIAL, csum_partial=1 tells tcp_mss_clamp to
	 * skip the incremental checksum update.  The MSS option bytes
	 * are in the L4 data region that the kernel sums during
	 * finalization (generic XDP), so the final checksum will be
	 * correct even though we modified the MSS value. */
	if (meta->protocol == PROTO_TCP && (meta->tcp_flags & 0x02)) {
		struct flow_config *fc = bpf_map_lookup_elem(&flow_config_map, &zero);
		if (fc) {
			__u16 mss = fc->tcp_mss_ipsec;
			if (fc->tcp_mss_gre_in > 0 && (fc->tcp_mss_gre_in < mss || mss == 0))
				mss = fc->tcp_mss_gre_in;
			if (mss > 0)
				tcp_mss_clamp(ctx, meta->l4_offset, mss,
					      meta->csum_partial);
		}
	}

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

				/* ICMP error embedded packet matching */
				if (meta->protocol == PROTO_ICMP &&
				    (meta->icmp_type == 3 ||
				     meta->icmp_type == 11 ||
				     meta->icmp_type == 12)) {
					int ret = handle_embedded_icmp_v4(
						ctx, meta);
					if (ret != -1)
						return ret;
					/* No matching forwarded session —
					 * pass to kernel as host-inbound
					 * (e.g. firewall-originated traceroute). */
					meta->fwd_ifindex = 0;
					bpf_tail_call(ctx, &xdp_progs,
						      XDP_PROG_FORWARD);
					return XDP_PASS;
				}

				/* allow-dns-reply: permit unsolicited DNS
				 * response packets (UDP src port 53) without
				 * a matching session. */
				if (meta->protocol == PROTO_UDP &&
				    meta->src_port == __bpf_htons(53)) {
					struct flow_config *fc =
						bpf_map_lookup_elem(
						&flow_config_map, &zero);
					if (fc && fc->allow_dns_reply) {
						bpf_tail_call(ctx, &xdp_progs,
							XDP_PROG_FORWARD);
						return XDP_PASS;
					}
				}

				meta->ct_state = SESS_STATE_NEW;
				meta->ct_direction = 0;
				TRACE_CT_MISS(meta);
				bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
				return XDP_PASS;
			}
			direction = 1;
		}

		TRACE_CT_HIT(meta, direction, sess->flags);
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
				/*
				 * NAT64 prefix check for new IPv6 sessions:
				 * O(1) hash lookup by /96 prefix.
				 * Use dst_ip.v6 directly as key (first 12 bytes
				 * match nat64_prefix_key layout).
				 */
				struct nat64_config *n64 =
					bpf_map_lookup_elem(
					&nat64_prefix_map,
					meta->dst_ip.v6);
				if (n64) {
					meta->nat_flags |= SESS_FLAG_NAT64;
					__builtin_memset(
						&meta->nat_dst_ip, 0,
						sizeof(meta->nat_dst_ip));
					__be32 *dst32 =
						(__be32 *)meta->dst_ip.v6;
					meta->nat_dst_ip.v4 = dst32[3];
				}

				/* ICMPv6 error embedded packet matching */
				if (meta->protocol == PROTO_ICMPV6 &&
				    (meta->icmp_type == 1 ||
				     meta->icmp_type == 3 ||
				     meta->icmp_type == 4)) {
					int ret = handle_embedded_icmp_v6(
						ctx, meta);
					if (ret != -1)
						return ret;
					/* No matching forwarded session —
					 * pass to kernel as host-inbound
					 * (e.g. firewall-originated traceroute6). */
					meta->fwd_ifindex = 0;
					bpf_tail_call(ctx, &xdp_progs,
						      XDP_PROG_FORWARD);
					return XDP_PASS;
				}

				/* allow-dns-reply: permit unsolicited DNS
				 * response packets (UDP src port 53) without
				 * a matching session. */
				if (meta->protocol == PROTO_UDP &&
				    meta->src_port == __bpf_htons(53)) {
					struct flow_config *fc =
						bpf_map_lookup_elem(
						&flow_config_map, &zero);
					if (fc && fc->allow_dns_reply) {
						bpf_tail_call(ctx, &xdp_progs,
							XDP_PROG_FORWARD);
						return XDP_PASS;
					}
				}

				meta->ct_state = SESS_STATE_NEW;
				meta->ct_direction = 0;
				TRACE_CT_MISS(meta);
				bpf_tail_call(ctx, &xdp_progs, XDP_PROG_POLICY);
				return XDP_PASS;
			}
			direction = 1;
		}

		TRACE_CT_HIT(meta, direction, sess->flags);
		return handle_ct_hit_v6(ctx, meta, sess, direction);
	}
}

char _license[] SEC("license") = "GPL";
