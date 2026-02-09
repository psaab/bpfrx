// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress screen/IDS stage.
 *
 * Mirrors xdp_screen.c but for the TC egress pipeline. Looks up the
 * egress zone's screen profile and applies stateless anomaly checks
 * and rate-based flood protection. On pass, tail-calls to conntrack.
 * On drop, returns TC_ACT_SHOT + increments screen drop counter +
 * emits ring buffer event.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Drop a packet due to a screen check (TC variant).
 * Returns TC_ACT_SHOT instead of XDP_DROP.
 */
static __always_inline int
screen_drop_tc(struct pkt_meta *meta, __u32 screen_flag)
{
	meta->policy_id = screen_flag;
	inc_counter(GLOBAL_CTR_SCREEN_DROPS);
	emit_event(meta, EVENT_TYPE_SCREEN_DROP, ACTION_DENY, 0, 0);
	return TC_ACT_SHOT;
}

/*
 * Check flood rate limits for egress zone.
 * Returns the SCREEN_* flag that was exceeded, or 0 if within limits.
 */
static __always_inline __u32
check_flood_egress(struct pkt_meta *meta, struct screen_config *sc)
{
	__u32 zone = meta->egress_zone;
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

SEC("tc")
int tc_screen_egress_prog(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return TC_ACT_SHOT;

	/* Look up zone config to find screen profile ID */
	__u32 zone_key = (__u32)meta->egress_zone;
	struct zone_config *zc = bpf_map_lookup_elem(&zone_configs, &zone_key);
	if (!zc || zc->screen_profile_id == 0) {
		/* No screen profile assigned -- fast path to conntrack */
		bpf_tail_call(skb, &tc_progs, TC_PROG_CONNTRACK);
		return TC_ACT_OK;
	}

	/* Look up screen config by profile ID */
	__u32 profile_key = (__u32)zc->screen_profile_id;
	struct screen_config *sc = bpf_map_lookup_elem(&screen_configs, &profile_key);
	if (!sc || sc->flags == 0) {
		/* Empty profile -- fast path */
		bpf_tail_call(skb, &tc_progs, TC_PROG_CONNTRACK);
		return TC_ACT_OK;
	}

	/* ============================================================
	 * Stateless checks
	 * ============================================================ */

	/* LAND attack: src_ip == dst_ip */
	if (sc->flags & SCREEN_LAND_ATTACK) {
		if (meta->addr_family == AF_INET) {
			if (meta->src_ip.v4 == meta->dst_ip.v4)
				return screen_drop_tc(meta, SCREEN_LAND_ATTACK);
		} else {
			if (ip_addr_eq_v6(meta->src_ip.v6, meta->dst_ip.v6))
				return screen_drop_tc(meta, SCREEN_LAND_ATTACK);
		}
	}

	/* TCP-specific stateless checks */
	if (meta->protocol == PROTO_TCP) {
		__u8 tf = meta->tcp_flags;

		/* TCP SYN+FIN */
		if ((sc->flags & SCREEN_TCP_SYN_FIN) &&
		    (tf & 0x02) && (tf & 0x01))
			return screen_drop_tc(meta, SCREEN_TCP_SYN_FIN);

		/* TCP no-flag */
		if ((sc->flags & SCREEN_TCP_NO_FLAG) && tf == 0)
			return screen_drop_tc(meta, SCREEN_TCP_NO_FLAG);

		/* TCP FIN-no-ACK */
		if ((sc->flags & SCREEN_TCP_FIN_NO_ACK) &&
		    (tf & 0x01) && !(tf & 0x10))
			return screen_drop_tc(meta, SCREEN_TCP_FIN_NO_ACK);

		/* WinNuke: TCP URG to port 139 */
		if ((sc->flags & SCREEN_WINNUKE) &&
		    (tf & 0x20) && meta->dst_port == bpf_htons(139))
			return screen_drop_tc(meta, SCREEN_WINNUKE);
	}

	/* IP source-route option (IPv4 only) */
	if ((sc->flags & SCREEN_IP_SOURCE_ROUTE) &&
	    meta->addr_family == AF_INET &&
	    meta->l3_offset < 64) {
		struct iphdr *iph = data + meta->l3_offset;
		if ((void *)(iph + 1) <= data_end && iph->ihl > 5)
			return screen_drop_tc(meta, SCREEN_IP_SOURCE_ROUTE);
	}

	/* Ping of Death: oversized ICMP/ICMPv6 */
	if (sc->flags & SCREEN_PING_OF_DEATH) {
		if (meta->protocol == PROTO_ICMP ||
		    meta->protocol == PROTO_ICMPV6) {
			if (meta->pkt_len > 65535)
				return screen_drop_tc(meta, SCREEN_PING_OF_DEATH);
		}
	}

	/* ============================================================
	 * Rate-based flood checks
	 * ============================================================ */
	__u32 flood_flag = check_flood_egress(meta, sc);
	if (flood_flag)
		return screen_drop_tc(meta, flood_flag);

	/* All checks passed -- proceed to conntrack */
	bpf_tail_call(skb, &tc_progs, TC_PROG_CONNTRACK);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
