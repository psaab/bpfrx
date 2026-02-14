/* SPDX-License-Identifier: GPL-2.0-or-later
 * nat.c — NAT rewrite (replaces xdp_nat).
 *
 * Performs SNAT/DNAT IP and port rewriting, pool port allocation,
 * and incremental checksum updates.
 */

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <arpa/inet.h>
#include <string.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"
#include "events.h"

/**
 * csum_update_u32 — Incremental checksum update for a 32-bit field change.
 * From RFC 1624.
 */
static inline void
csum_update_u32(uint16_t *csum, uint32_t old_val, uint32_t new_val)
{
	uint32_t c = (~ntohs(*csum)) & 0xFFFF;
	uint32_t old_hi = (old_val >> 16) & 0xFFFF;
	uint32_t old_lo = old_val & 0xFFFF;
	uint32_t new_hi = (new_val >> 16) & 0xFFFF;
	uint32_t new_lo = new_val & 0xFFFF;

	c += (~old_hi & 0xFFFF) + new_hi;
	c += (~old_lo & 0xFFFF) + new_lo;
	c = (c >> 16) + (c & 0xFFFF);
	c += c >> 16;
	*csum = htons(~c & 0xFFFF);
}

static inline void
csum_update_u16(uint16_t *csum, uint16_t old_val, uint16_t new_val)
{
	uint32_t c = (~ntohs(*csum)) & 0xFFFF;
	c += (~ntohs(old_val) & 0xFFFF) + ntohs(new_val);
	c = (c >> 16) + (c & 0xFFFF);
	c += c >> 16;
	*csum = htons(~c & 0xFFFF);
}

/**
 * nat_rewrite — Apply NAT translations to the packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (nat_src_ip/port, nat_dst_ip/port set)
 * @ctx:  Pipeline context
 *
 * Rewrites source and/or destination IP and port based on meta->nat_flags.
 * Updates L3 and L4 checksums incrementally.
 *
 * Returns 0 on success, -1 if packet was dropped (TTL expired).
 */
int
nat_rewrite(struct rte_mbuf *pkt, struct pkt_meta *meta,
            struct pipeline_ctx *ctx)
{
	uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);

	/* TTL check before NAT rewrite — preserves original IPs
	 * for ICMP Time Exceeded generation. */
	if (meta->ip_ttl <= 1) {
		emit_event(ctx, meta, EVENT_TYPE_SCREEN_DROP, ACTION_DENY);
		ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
		rte_pktmbuf_free(pkt);
		return -1;
	}

	if (meta->addr_family == AF_INET) {
		struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)(data + meta->l3_offset);
		uint16_t *l4_csum = NULL;
		uint16_t *l4_sport = NULL;
		uint16_t *l4_dport = NULL;

		/* Get L4 checksum and port pointers */
		if (meta->protocol == PROTO_TCP) {
			struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(data + meta->l4_offset);
			l4_csum = &tcp->cksum;
			l4_sport = &tcp->src_port;
			l4_dport = &tcp->dst_port;
		} else if (meta->protocol == PROTO_UDP) {
			struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(data + meta->l4_offset);
			l4_csum = &udp->dgram_cksum;
			l4_sport = &udp->src_port;
			l4_dport = &udp->dst_port;
		}

		/* DNAT: rewrite destination */
		if (meta->nat_flags & SESS_FLAG_DNAT) {
			uint32_t old_ip = ip4->dst_addr;
			uint32_t new_ip = meta->nat_dst_ip.v4;

			if (old_ip != new_ip) {
				ip4->dst_addr = new_ip;
				csum_update_u32(&ip4->hdr_checksum, old_ip, new_ip);
				if (l4_csum)
					csum_update_u32(l4_csum, old_ip, new_ip);
			}

			if (meta->nat_dst_port != 0 && l4_dport) {
				uint16_t old_port = *l4_dport;
				*l4_dport = meta->nat_dst_port;
				if (l4_csum)
					csum_update_u16(l4_csum, old_port, meta->nat_dst_port);
			}
		}

		/* SNAT: rewrite source */
		if (meta->nat_flags & SESS_FLAG_SNAT) {
			uint32_t old_ip = ip4->src_addr;
			uint32_t new_ip = meta->nat_src_ip.v4;

			if (old_ip != new_ip) {
				ip4->src_addr = new_ip;
				csum_update_u32(&ip4->hdr_checksum, old_ip, new_ip);
				if (l4_csum)
					csum_update_u32(l4_csum, old_ip, new_ip);
			}

			if (meta->nat_src_port != 0 && l4_sport) {
				uint16_t old_port = *l4_sport;
				*l4_sport = meta->nat_src_port;
				if (l4_csum)
					csum_update_u16(l4_csum, old_port, meta->nat_src_port);
			}
		}

	} else if (meta->addr_family == AF_INET6) {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(data + meta->l3_offset);

		/* For IPv6, only TCP/UDP checksums need updating (no IPv6 header checksum) */
		uint16_t *l4_csum = NULL;
		uint16_t *l4_sport = NULL;
		uint16_t *l4_dport = NULL;

		if (meta->protocol == PROTO_TCP) {
			struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(data + meta->l4_offset);
			l4_csum = &tcp->cksum;
			l4_sport = &tcp->src_port;
			l4_dport = &tcp->dst_port;
		} else if (meta->protocol == PROTO_UDP) {
			struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(data + meta->l4_offset);
			l4_csum = &udp->dgram_cksum;
			l4_sport = &udp->src_port;
			l4_dport = &udp->dst_port;
		}

		if (meta->nat_flags & SESS_FLAG_DNAT) {
			/* Update L4 checksum for each 32-bit word of the address change */
			if (l4_csum) {
				for (int i = 0; i < 4; i++) {
					uint32_t old_w = ((uint32_t *)ip6->dst_addr.a)[i];
					uint32_t new_w = ((uint32_t *)meta->nat_dst_ip.v6)[i];
					if (old_w != new_w)
						csum_update_u32(l4_csum, old_w, new_w);
				}
			}
			memcpy(ip6->dst_addr.a, meta->nat_dst_ip.v6, 16);

			if (meta->nat_dst_port != 0 && l4_dport) {
				uint16_t old_port = *l4_dport;
				*l4_dport = meta->nat_dst_port;
				if (l4_csum)
					csum_update_u16(l4_csum, old_port, meta->nat_dst_port);
			}
		}

		if (meta->nat_flags & SESS_FLAG_SNAT) {
			if (l4_csum) {
				for (int i = 0; i < 4; i++) {
					uint32_t old_w = ((uint32_t *)ip6->src_addr.a)[i];
					uint32_t new_w = ((uint32_t *)meta->nat_src_ip.v6)[i];
					if (old_w != new_w)
						csum_update_u32(l4_csum, old_w, new_w);
				}
			}
			memcpy(ip6->src_addr.a, meta->nat_src_ip.v6, 16);

			if (meta->nat_src_port != 0 && l4_sport) {
				uint16_t old_port = *l4_sport;
				*l4_sport = meta->nat_src_port;
				if (l4_csum)
					csum_update_u16(l4_csum, old_port, meta->nat_src_port);
			}
		}
	}

	return 0;
}
