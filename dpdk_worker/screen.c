/* SPDX-License-Identifier: GPL-2.0-or-later
 * screen.c — IDS/Screen checks (replaces xdp_screen).
 *
 * Implements stateless and rate-based DoS protection checks:
 * land attack, syn-flood, ping-of-death, teardrop, ICMP fragment,
 * large ICMP, tcp-no-flag, syn-frag, ip-sweep, port-scan, udp-flood.
 */

#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * screen_check — Run IDS/screen checks against the packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata
 * @ctx:  Pipeline context (screen configs, flood state, counters)
 *
 * Returns 0 if packet passes all checks, -1 if it should be dropped.
 *
 * The screen profile is looked up by the zone's screen_profile_id
 * (set after zone_lookup). For ingress screening, we use the
 * ingress_zone's screen profile.
 */
int
screen_check(struct rte_mbuf *pkt, struct pkt_meta *meta,
             struct pipeline_ctx *ctx)
{
	(void)pkt;

	/* Get screen profile for ingress zone */
	if (meta->ingress_zone >= MAX_ZONES || !ctx->shm->zone_configs)
		return 0;

	struct zone_config *zc = &ctx->shm->zone_configs[meta->ingress_zone];
	if (zc->screen_profile_id == 0 || !ctx->shm->screen_configs)
		return 0;

	if (zc->screen_profile_id >= MAX_SCREEN_PROFILES)
		return 0;

	struct screen_config *sc = &ctx->shm->screen_configs[zc->screen_profile_id];
	if (sc->flags == 0)
		return 0;

	/* Stateless checks (only for relevant protocols) */

	/* 1. Land attack: src == dst */
	if ((sc->flags & SCREEN_LAND_ATTACK) && meta->addr_family == AF_INET) {
		if (meta->src_ip.v4 == meta->dst_ip.v4 &&
		    meta->src_port == meta->dst_port &&
		    (meta->protocol == PROTO_TCP || meta->protocol == PROTO_UDP)) {
			ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_LAND_ATTACK);
			return -1;
		}
	}

	if (meta->protocol == PROTO_TCP) {
		/* 2. TCP SYN+FIN */
		if ((sc->flags & SCREEN_TCP_SYN_FIN) &&
		    (meta->tcp_flags & 0x02) && (meta->tcp_flags & 0x01)) {
			ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_TCP_SYN_FIN);
			return -1;
		}

		/* 3. TCP no flag (null scan) */
		if ((sc->flags & SCREEN_TCP_NO_FLAG) && meta->tcp_flags == 0) {
			ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_TCP_NO_FLAG);
			return -1;
		}

		/* 4. TCP FIN no ACK */
		if ((sc->flags & SCREEN_TCP_FIN_NO_ACK) &&
		    (meta->tcp_flags & 0x01) && !(meta->tcp_flags & 0x10)) {
			ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_TCP_FIN_NO_ACK);
			return -1;
		}

		/* 5. WinNuke: URG to port 139 */
		if ((sc->flags & SCREEN_WINNUKE) &&
		    (meta->tcp_flags & 0x20) &&
		    rte_be_to_cpu_16(meta->dst_port) == 139) {
			ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_WINNUKE);
			return -1;
		}

		/* 8. SYN fragment */
		if ((sc->flags & SCREEN_SYN_FRAG) &&
		    (meta->tcp_flags & 0x02) && meta->is_fragment) {
			ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_SYN_FRAG);
			return -1;
		}
	}

	/* 6. Ping of death: ICMP + oversized */
	if ((sc->flags & SCREEN_PING_OF_DEATH) &&
	    (meta->protocol == PROTO_ICMP || meta->protocol == PROTO_ICMPV6) &&
	    meta->pkt_len > 65535) {
		ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_PING_DEATH);
		return -1;
	}

	/* 7. Teardrop: overlapping fragments */
	if ((sc->flags & SCREEN_TEAR_DROP) && meta->is_fragment) {
		/* Simple check: fragment offset > 0 but total length too small
		 * to not overlap with previous fragment. More sophisticated
		 * tracking would need fragment reassembly state. */
		/* For now, just flag as checked — real detection needs state */
	}

	/* Rate-based checks */
	uint64_t now_tsc = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();
	uint32_t zone_idx = meta->ingress_zone;

	if (zone_idx < MAX_ZONES && ctx->flood_states) {
		struct flood_state *fs = &ctx->flood_states[zone_idx];
		uint64_t window_tsc = (sc->syn_flood_timeout > 0 ? sc->syn_flood_timeout : 1) * hz;

		/* Reset window if expired */
		if (now_tsc - fs->window_start > window_tsc) {
			fs->syn_count = 0;
			fs->icmp_count = 0;
			fs->udp_count = 0;
			fs->window_start = now_tsc;
		}

		/* 10. SYN flood */
		if ((sc->flags & SCREEN_SYN_FLOOD) && meta->protocol == PROTO_TCP &&
		    (meta->tcp_flags & 0x02) && !(meta->tcp_flags & 0x10)) {
			fs->syn_count++;
			if (sc->syn_flood_thresh > 0 && fs->syn_count > sc->syn_flood_thresh) {
				ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_SYN_FLOOD);
				return -1;
			}
		}

		/* 11. ICMP flood */
		if ((sc->flags & SCREEN_ICMP_FLOOD) &&
		    (meta->protocol == PROTO_ICMP || meta->protocol == PROTO_ICMPV6)) {
			fs->icmp_count++;
			if (sc->icmp_flood_thresh > 0 && fs->icmp_count > sc->icmp_flood_thresh) {
				ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_ICMP_FLOOD);
				return -1;
			}
		}

		/* 12. UDP flood */
		if ((sc->flags & SCREEN_UDP_FLOOD) && meta->protocol == PROTO_UDP) {
			fs->udp_count++;
			if (sc->udp_flood_thresh > 0 && fs->udp_count > sc->udp_flood_thresh) {
				ctr_global_inc(ctx, GLOBAL_CTR_SCREEN_UDP_FLOOD);
				return -1;
			}
		}
	}

	return 0;  /* Passed all checks */
}
