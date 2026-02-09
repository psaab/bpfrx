// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP screen/IDS stage.
 *
 * Runs before zone classification. Looks up the ingress zone's screen
 * profile and applies stateless anomaly checks (LAND, TCP SYN+FIN,
 * TCP no-flag, TCP FIN-no-ACK, WinNuke, IP source-route, Ping of Death)
 * and rate-based flood protection (SYN flood, ICMP flood, UDP flood).
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Drop a packet due to a screen check.
 * Stores the screen flag in policy_id for event logging,
 * increments the screen drop counter, emits a ring buffer event,
 * and returns XDP_DROP.
 */
static __always_inline int
screen_drop(struct pkt_meta *meta, __u32 screen_flag)
{
	meta->policy_id = screen_flag;
	inc_counter(GLOBAL_CTR_SCREEN_DROPS);
	emit_event(meta, EVENT_TYPE_SCREEN_DROP, ACTION_DENY, 0, 0);
	return XDP_DROP;
}

/*
 * Check flood rate limits for a given zone.
 * Returns the SCREEN_* flag that was exceeded, or 0 if within limits.
 */
static __always_inline __u32
check_flood(struct pkt_meta *meta, struct screen_config *sc)
{
	__u32 zone = meta->ingress_zone;
	struct flood_state *fs = bpf_map_lookup_elem(&flood_counters, &zone);
	if (!fs)
		return 0;

	__u64 now_sec = bpf_ktime_get_ns() / 1000000000ULL;

	/* Reset window if a new second started */
	if (now_sec != fs->window_start) {
		fs->syn_count = 0;
		fs->icmp_count = 0;
		fs->udp_count = 0;
		fs->window_start = now_sec;
	}

	/* SYN flood: count TCP SYN (without ACK) */
	if ((sc->flags & SCREEN_SYN_FLOOD) && sc->syn_flood_thresh > 0) {
		if (meta->protocol == PROTO_TCP) {
			__u8 tf = meta->tcp_flags;
			if ((tf & 0x02) && !(tf & 0x10)) { /* SYN set, ACK not set */
				fs->syn_count++;
				if (fs->syn_count > sc->syn_flood_thresh)
					return SCREEN_SYN_FLOOD;
			}
		}
	}

	/* ICMP flood: count ICMP + ICMPv6 */
	if ((sc->flags & SCREEN_ICMP_FLOOD) && sc->icmp_flood_thresh > 0) {
		if (meta->protocol == PROTO_ICMP ||
		    meta->protocol == PROTO_ICMPV6) {
			fs->icmp_count++;
			if (fs->icmp_count > sc->icmp_flood_thresh)
				return SCREEN_ICMP_FLOOD;
		}
	}

	/* UDP flood: count UDP */
	if ((sc->flags & SCREEN_UDP_FLOOD) && sc->udp_flood_thresh > 0) {
		if (meta->protocol == PROTO_UDP) {
			fs->udp_count++;
			if (fs->udp_count > sc->udp_flood_thresh)
				return SCREEN_UDP_FLOOD;
		}
	}

	return 0;
}

SEC("xdp")
int xdp_screen_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Look up ingress zone from interface index */
	__u32 ifindex = meta->ingress_ifindex;
	__u16 *zone_ptr = bpf_map_lookup_elem(&iface_zone_map, &ifindex);
	if (!zone_ptr) {
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	}
	meta->ingress_zone = *zone_ptr;

	/* Look up zone config to find screen profile ID */
	__u32 zone_key = (__u32)*zone_ptr;
	struct zone_config *zc = bpf_map_lookup_elem(&zone_configs, &zone_key);
	if (!zc || zc->screen_profile_id == 0) {
		/* No screen profile assigned -- fast path to zone */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_ZONE);
		return XDP_PASS;
	}

	/* Look up screen config by profile ID */
	__u32 profile_key = (__u32)zc->screen_profile_id;
	struct screen_config *sc = bpf_map_lookup_elem(&screen_configs, &profile_key);
	if (!sc || sc->flags == 0) {
		/* Empty profile -- fast path */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_ZONE);
		return XDP_PASS;
	}

	/* ============================================================
	 * Stateless checks
	 * ============================================================ */

	/* LAND attack: src_ip == dst_ip */
	if (sc->flags & SCREEN_LAND_ATTACK) {
		if (meta->addr_family == AF_INET) {
			if (meta->src_ip.v4 == meta->dst_ip.v4)
				return screen_drop(meta, SCREEN_LAND_ATTACK);
		} else {
			if (ip_addr_eq_v6(meta->src_ip.v6, meta->dst_ip.v6))
				return screen_drop(meta, SCREEN_LAND_ATTACK);
		}
	}

	/* TCP-specific stateless checks */
	if (meta->protocol == PROTO_TCP) {
		__u8 tf = meta->tcp_flags;

		/* TCP SYN+FIN */
		if ((sc->flags & SCREEN_TCP_SYN_FIN) &&
		    (tf & 0x02) && (tf & 0x01))
			return screen_drop(meta, SCREEN_TCP_SYN_FIN);

		/* TCP no-flag */
		if ((sc->flags & SCREEN_TCP_NO_FLAG) && tf == 0)
			return screen_drop(meta, SCREEN_TCP_NO_FLAG);

		/* TCP FIN-no-ACK */
		if ((sc->flags & SCREEN_TCP_FIN_NO_ACK) &&
		    (tf & 0x01) && !(tf & 0x10))
			return screen_drop(meta, SCREEN_TCP_FIN_NO_ACK);

		/* WinNuke: TCP URG to port 139 */
		if ((sc->flags & SCREEN_WINNUKE) &&
		    (tf & 0x20) && meta->dst_port == bpf_htons(139))
			return screen_drop(meta, SCREEN_WINNUKE);

		/* TCP SYN fragment: SYN on a fragmented packet */
		if ((sc->flags & SCREEN_SYN_FRAG) &&
		    (tf & 0x02) && meta->is_fragment)
			return screen_drop(meta, SCREEN_SYN_FRAG);
	}

	/* IP source-route option (IPv4 only) */
	if ((sc->flags & SCREEN_IP_SOURCE_ROUTE) &&
	    meta->addr_family == AF_INET &&
	    meta->l3_offset < 64) {
		struct iphdr *iph = data + meta->l3_offset;
		if ((void *)(iph + 1) <= data_end && iph->ihl > 5)
			return screen_drop(meta, SCREEN_IP_SOURCE_ROUTE);
	}

	/* Ping of Death: oversized ICMP/ICMPv6 */
	if (sc->flags & SCREEN_PING_OF_DEATH) {
		if (meta->protocol == PROTO_ICMP ||
		    meta->protocol == PROTO_ICMPV6) {
			if (meta->pkt_len > 65535)
				return screen_drop(meta, SCREEN_PING_OF_DEATH);
		}
	}

	/* ============================================================
	 * Rate-based flood checks
	 * ============================================================ */
	__u32 flood_flag = check_flood(meta, sc);
	if (flood_flag)
		return screen_drop(meta, flood_flag);

	/* All checks passed -- proceed to zone classification */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_ZONE);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
