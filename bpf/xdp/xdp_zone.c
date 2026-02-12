// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP zone classification stage.
 *
 * Maps the ingress interface to a security zone and performs a FIB
 * lookup to determine the egress interface and egress zone.
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_trace.h"

/*
 * Fast-path conntrack update for established IPv4 sessions.
 * Called when xdp_zone finds a session (for FIB cache), eliminating
 * the duplicate session lookup that xdp_conntrack would perform.
 */
static __always_inline int
zone_ct_update_v4(struct xdp_md *ctx, struct pkt_meta *meta,
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

	if (sess->state == SESS_STATE_CLOSED) {
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
	}

	bpf_tail_call(ctx, &xdp_progs, next_prog);
	return XDP_PASS;
}

/*
 * Fast-path conntrack update for established IPv6 sessions.
 */
static __always_inline int
zone_ct_update_v6(struct xdp_md *ctx, struct pkt_meta *meta,
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

	if (sess->state == SESS_STATE_CLOSED) {
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
	}

	bpf_tail_call(ctx, &xdp_progs, next_prog);
	return XDP_PASS;
}

SEC("xdp")
int xdp_zone_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Look up ingress zone from {ifindex, vlan_id} composite key */
	struct iface_zone_key izk = {
		.ifindex = meta->ingress_ifindex,
		.vlan_id = meta->ingress_vlan_id,
	};
	__u16 *zone_id = bpf_map_lookup_elem(&iface_zone_map, &izk);
	if (!zone_id) {
		/* Interface not assigned to any zone -- drop */
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	}
	meta->ingress_zone = *zone_id;
	inc_zone_ingress((__u32)*zone_id, meta->pkt_len);

	/*
	 * Pre-routing NAT: check dnat_table before FIB lookup.
	 * This handles both static DNAT entries (from config) and
	 * dynamic SNAT return entries (from xdp_policy).
	 */
	if (meta->addr_family == AF_INET) {
		struct dnat_key dk = {
			.protocol = meta->protocol,
			.dst_ip   = meta->dst_ip.v4,
			.dst_port = meta->dst_port,
		};
		struct dnat_value *dv = bpf_map_lookup_elem(&dnat_table, &dk);
		/* Fallback: try wildcard port (port=0) for IP-only DNAT rules */
		if (!dv) {
			struct dnat_key dk_wild = {
				.protocol = meta->protocol,
				.dst_ip   = meta->dst_ip.v4,
				.dst_port = 0,
			};
			dv = bpf_map_lookup_elem(&dnat_table, &dk_wild);
		}
		if (dv) {
			meta->nat_dst_ip.v4 = meta->dst_ip.v4;
			meta->nat_dst_port  = meta->dst_port;
			meta->dst_ip.v4     = dv->new_dst_ip;
			meta->dst_port      = dv->new_dst_port;
			meta->nat_flags    |= SESS_FLAG_DNAT;
			/* ICMP: echo ID is symmetric, set src_port so
			 * conntrack finds session using original echo ID */
			if (meta->protocol == PROTO_ICMP ||
			    meta->protocol == PROTO_ICMPV6)
				meta->src_port = meta->dst_port;
		} else {
			/* Static 1:1 NAT DNAT lookup */
			struct static_nat_key_v4 snk = {
				.ip = meta->dst_ip.v4,
				.direction = STATIC_NAT_DNAT,
			};
			__be32 *sn_dst = bpf_map_lookup_elem(&static_nat_v4, &snk);
			if (sn_dst) {
				meta->nat_dst_ip.v4 = meta->dst_ip.v4;
				meta->nat_dst_port  = meta->dst_port;
				meta->dst_ip.v4     = *sn_dst;
				meta->nat_flags    |= SESS_FLAG_DNAT;
			}
		}
	} else {
		struct dnat_key_v6 dk6 = { .protocol = meta->protocol };
		__builtin_memcpy(dk6.dst_ip, meta->dst_ip.v6, 16);
		dk6.dst_port = meta->dst_port;

		struct dnat_value_v6 *dv6 = bpf_map_lookup_elem(&dnat_table_v6, &dk6);
		/* Fallback: try wildcard port (port=0) for IP-only DNAT rules */
		if (!dv6) {
			struct dnat_key_v6 dk6_wild = { .protocol = meta->protocol };
			__builtin_memcpy(dk6_wild.dst_ip, meta->dst_ip.v6, 16);
			dk6_wild.dst_port = 0;
			dv6 = bpf_map_lookup_elem(&dnat_table_v6, &dk6_wild);
		}
		if (dv6) {
			__builtin_memcpy(meta->nat_dst_ip.v6, meta->dst_ip.v6, 16);
			meta->nat_dst_port = meta->dst_port;
			__builtin_memcpy(meta->dst_ip.v6, dv6->new_dst_ip, 16);
			meta->dst_port     = dv6->new_dst_port;
			meta->nat_flags   |= SESS_FLAG_DNAT;
			/* ICMP: echo ID symmetry for conntrack */
			if (meta->protocol == PROTO_ICMP ||
			    meta->protocol == PROTO_ICMPV6)
				meta->src_port = meta->dst_port;
		} else {
			/* Static 1:1 NAT DNAT lookup (v6) */
			struct static_nat_key_v6 snk6 = { .direction = STATIC_NAT_DNAT };
			__builtin_memcpy(snk6.ip, meta->dst_ip.v6, 16);
			struct static_nat_value_v6 *sn_dst6 = bpf_map_lookup_elem(&static_nat_v6, &snk6);
			if (sn_dst6) {
				__builtin_memcpy(meta->nat_dst_ip.v6, meta->dst_ip.v6, 16);
				meta->nat_dst_port = meta->dst_port;
				__builtin_memcpy(meta->dst_ip.v6, sn_dst6->ip, 16);
				meta->nat_flags |= SESS_FLAG_DNAT;
			}
		}
	}

	/*
	 * VRRP multicast (224.0.0.18, proto 112) — allow to host for keepalived.
	 * Must be checked before the generic multicast pass-through so it
	 * reaches the host even with zone-pair deny-all.
	 */
	if (meta->addr_family == AF_INET && meta->protocol == PROTO_VRRP &&
	    meta->dst_ip.v4 == bpf_htonl(0xE0000012)) {
		meta->fwd_ifindex = 0;
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
		return XDP_PASS;
	}

	/*
	 * Broadcast / multicast → host-bound traffic.
	 * Skip the zone-pair policy pipeline and jump directly to the
	 * forward stage which applies host-inbound-traffic filtering.
	 * Without this, bpf_fib_lookup may match the default route and
	 * send the packet through the policy pipeline where deny-all
	 * would drop it (e.g. DHCP OFFER to 255.255.255.255).
	 */
	if (meta->addr_family == AF_INET) {
		if (meta->dst_ip.v4 == (__be32)0xFFFFFFFF) {
			meta->fwd_ifindex = 0;
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
			return XDP_PASS;
		}
		/* IPv4 multicast: first byte 0xE0-0xEF (224.0.0.0/4) */
		__u8 *ip4b = (__u8 *)&meta->dst_ip.v4;
		if ((ip4b[0] & 0xF0) == 0xE0) {
			meta->fwd_ifindex = 0;
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
			return XDP_PASS;
		}
	} else {
		/* IPv6 multicast: ff00::/8 */
		__u8 *ip6b = (__u8 *)meta->dst_ip.v6;
		if (ip6b[0] == 0xFF) {
			meta->fwd_ifindex = 0;
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
			return XDP_PASS;
		}
	}

	/*
	 * DHCP/DHCPv6 unicast responses bypass FIB lookup.
	 * When the zone allows DHCP host-inbound, unicast DHCP replies
	 * (e.g. DHCPOFFER to the offered IP before it's configured)
	 * must reach the host. Without this, bpf_fib_lookup matches
	 * the default route, sending the packet through the policy
	 * pipeline where deny-all drops it.
	 */
	{
		__u32 zone_key = (__u32)meta->ingress_zone;
		struct zone_config *zcfg = bpf_map_lookup_elem(&zone_configs, &zone_key);
		if (zcfg) {
			if (meta->protocol == PROTO_UDP) {
				__u16 dp = bpf_ntohs(meta->dst_port);
				if ((dp == 68 && (zcfg->host_inbound_flags & HOST_INBOUND_DHCP)) ||
				    (dp == 546 && (zcfg->host_inbound_flags & HOST_INBOUND_DHCPV6))) {
					meta->fwd_ifindex = 0;
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
					return XDP_PASS;
				}
			}
		}
	}

	/*
	 * Session lookup for FIB cache + conntrack fast-path.
	 * For established sessions, the egress interface + next-hop MAC
	 * are stable.  When cached, we also perform conntrack updates
	 * here (counters, TCP state, NAT propagation), eliminating the
	 * duplicate session lookup that xdp_conntrack would do.
	 *
	 * Skip for TCP SYN (new connections) — no session exists yet.
	 */
	int is_tcp_syn = (meta->protocol == PROTO_TCP &&
			  (meta->tcp_flags & 0x12) == 0x02);

	struct session_value *sv4 = NULL;
	struct session_value_v6 *sv6 = NULL;
	__u8 ct_direction = 0;

	if (!is_tcp_syn && meta->addr_family == AF_INET) {
		struct session_key sk = {};
		sk.src_ip   = meta->src_ip.v4;
		sk.dst_ip   = meta->dst_ip.v4;
		sk.src_port = meta->src_port;
		sk.dst_port = meta->dst_port;
		sk.protocol = meta->protocol;

		sv4 = bpf_map_lookup_elem(&sessions, &sk);
		if (!sv4) {
			struct session_key rk;
			ct_reverse_key(&sk, &rk);
			sv4 = bpf_map_lookup_elem(&sessions, &rk);
			if (sv4) ct_direction = 1;
		}
		if (sv4 && sv4->fib_ifindex != 0) {
			meta->fwd_ifindex    = sv4->fib_ifindex;
			meta->egress_vlan_id = sv4->fib_vlan_id;
			__builtin_memcpy(meta->fwd_dmac, sv4->fib_dmac, 6);
			__builtin_memcpy(meta->fwd_smac, sv4->fib_smac, 6);
			meta->egress_zone    = sv4->egress_zone;
			return zone_ct_update_v4(ctx, meta, sv4, ct_direction);
		}
	} else if (!is_tcp_syn) {
		struct session_key_v6 sk6 = {};
		__builtin_memcpy(sk6.src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(sk6.dst_ip, meta->dst_ip.v6, 16);
		sk6.src_port = meta->src_port;
		sk6.dst_port = meta->dst_port;
		sk6.protocol = meta->protocol;

		sv6 = bpf_map_lookup_elem(&sessions_v6, &sk6);
		if (!sv6) {
			struct session_key_v6 rk6;
			ct_reverse_key_v6(&sk6, &rk6);
			sv6 = bpf_map_lookup_elem(&sessions_v6, &rk6);
			if (sv6) ct_direction = 1;
		}
		if (sv6 && sv6->fib_ifindex != 0) {
			meta->fwd_ifindex    = sv6->fib_ifindex;
			meta->egress_vlan_id = sv6->fib_vlan_id;
			__builtin_memcpy(meta->fwd_dmac, sv6->fib_dmac, 6);
			__builtin_memcpy(meta->fwd_smac, sv6->fib_smac, 6);
			meta->egress_zone    = sv6->egress_zone;
			return zone_ct_update_v6(ctx, meta, sv6, ct_direction);
		}
	}

	/*
	 * FIB lookup to determine egress interface.
	 * Uses the (possibly translated) dst_ip for routing.
	 */
	struct bpf_fib_lookup fib = {};
	fib.l4_protocol = meta->protocol;
	fib.tot_len     = meta->pkt_len;
	fib.ifindex     = meta->ingress_ifindex;

	/* Use VRF routing table if set by firewall filter (policy-based routing).
	 * Only set tbid if routing_table is non-zero to avoid touching fib
	 * fields unnecessarily. */
	fib.tbid = meta->routing_table;

	if (meta->addr_family == AF_INET) {
		fib.family   = AF_INET;
		fib.ipv4_src = meta->src_ip.v4;
		fib.ipv4_dst = meta->dst_ip.v4;
	} else {
		fib.family = AF_INET6;
		__builtin_memcpy(fib.ipv6_src, meta->src_ip.v6, 16);
		__builtin_memcpy(fib.ipv6_dst, meta->dst_ip.v6, 16);
	}

	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
	TRACE_FIB_RESULT(rc, fib.ifindex);

	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		/* Store forwarding info -- resolve VLAN sub-interface */
		__u32 egress_if = fib.ifindex;
		__u16 egress_vlan = 0;
		__u32 egress_phys_if = egress_if;
		struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map, &egress_if);
		if (vi) {
			egress_phys_if = vi->parent_ifindex;
			egress_vlan = vi->vlan_id;
		}
		meta->fwd_ifindex = egress_phys_if;
		meta->egress_vlan_id = egress_vlan;
		__builtin_memcpy(meta->fwd_dmac, fib.dmac, ETH_ALEN);
		__builtin_memcpy(meta->fwd_smac, fib.smac, ETH_ALEN);

		/* Look up egress zone using {physical_ifindex, vlan_id} */
		struct iface_zone_key ezk = { .ifindex = egress_phys_if, .vlan_id = egress_vlan };
		__u16 *ez = bpf_map_lookup_elem(&iface_zone_map, &ezk);
		if (ez)
			meta->egress_zone = *ez;

		/* Populate FIB cache + conntrack fast-path using session
		 * pointer from FIB cache check above (avoids duplicate
		 * session lookup in xdp_conntrack). */
		if (sv4) {
			sv4->fib_ifindex = meta->fwd_ifindex;
			sv4->fib_vlan_id = meta->egress_vlan_id;
			__builtin_memcpy(sv4->fib_dmac, meta->fwd_dmac, 6);
			__builtin_memcpy(sv4->fib_smac, meta->fwd_smac, 6);
			return zone_ct_update_v4(ctx, meta, sv4, ct_direction);
		}
		if (sv6) {
			sv6->fib_ifindex = meta->fwd_ifindex;
			sv6->fib_vlan_id = meta->egress_vlan_id;
			__builtin_memcpy(sv6->fib_dmac, meta->fwd_dmac, 6);
			__builtin_memcpy(sv6->fib_smac, meta->fwd_smac, 6);
			return zone_ct_update_v6(ctx, meta, sv6, ct_direction);
		}

	} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		/*
		 * Route exists but no ARP/NDP entry for the next hop.
		 * We cannot proceed through the NAT pipeline because:
		 *   - SNAT would rewrite the source IP to a local address
		 *   - XDP_PASS with a local source IP gets dropped by the kernel
		 *     (kernel rejects forwarding packets with its own source IP)
		 *
		 * Instead, pass the ORIGINAL un-modified packet to the kernel.
		 * The kernel will do its own FIB lookup, trigger ARP/NDP neighbor
		 * resolution, and forward the packet. This first packet goes
		 * through un-NAT'd, but TCP retransmits (arriving ~1s later)
		 * will find ARP resolved and go through the full BPF pipeline
		 * with proper NAT and session tracking.
		 */
		TRACE_ZONE(meta);
		inc_counter(GLOBAL_CTR_HOST_INBOUND);
		if (meta->ingress_vlan_id != 0) {
			if (xdp_vlan_tag_push(ctx, meta->ingress_vlan_id) < 0)
				return XDP_DROP;
		}
		return XDP_PASS;

	} else {
		/*
		 * No route or packet is destined locally.
		 *
		 * ICMP error packets (Dest Unreachable, Time Exceeded,
		 * Param Problem) with a locally-destined outer IP may
		 * relate to a forwarded session whose original packet
		 * was SNAT'd.  Route through conntrack for embedded
		 * packet matching so the error reaches the client.
		 */
		if (meta->protocol == PROTO_ICMP &&
		    (meta->icmp_type == 3 || meta->icmp_type == 11 ||
		     meta->icmp_type == 12)) {
			struct flow_config *fc =
				bpf_map_lookup_elem(&flow_config_map, &zero);
			if (fc && fc->allow_embedded_icmp) {
				bpf_tail_call(ctx, &xdp_progs,
					      XDP_PROG_CONNTRACK);
				return XDP_PASS;
			}
		}

		/* Send to xdp_forward which handles host-inbound
		 * checks and VLAN tag restoration for sub-interfaces. */
		meta->fwd_ifindex = 0;
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
		return XDP_PASS;
	}

	TRACE_ZONE(meta);

	/* Tail call to conntrack for session lookup and policy evaluation */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_CONNTRACK);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
