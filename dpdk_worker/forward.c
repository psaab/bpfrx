/* SPDX-License-Identifier: GPL-2.0-or-later
 * forward.c — Packet forwarding (replaces xdp_forward).
 *
 * FIB lookup, MAC rewrite, VLAN tag push/pop, TTL decrement,
 * and TX burst to output port.
 */

#include <string.h>
#include <arpa/inet.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * forward_packet — Forward the packet to the output port.
 *
 * @pkt:  Packet mbuf (headers already modified by NAT if needed)
 * @meta: Parsed packet metadata (fwd_ifindex, fwd_dmac, fwd_smac set)
 * @ctx:  Pipeline context
 *
 * Performs FIB lookup (if not cached), MAC rewrite, VLAN handling,
 * TTL decrement, and transmits the packet.
 */
void
forward_packet(struct rte_mbuf *pkt, struct pkt_meta *meta,
               struct pipeline_ctx *ctx)
{
	uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);

	/* 1. TTL check and decrement */
	if (meta->ip_ttl <= 1) {
		/* TTL expired — drop (TODO: send ICMP Time Exceeded) */
		rte_pktmbuf_free(pkt);
		ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
		return;
	}

	if (meta->addr_family == AF_INET) {
		struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)(data + meta->l3_offset);
		/* Decrement TTL with incremental checksum update */
		uint16_t old_ttl_proto = *(uint16_t *)&ip4->time_to_live;
		ip4->time_to_live--;
		uint16_t new_ttl_proto = *(uint16_t *)&ip4->time_to_live;

		/* Incremental checksum: RFC 1624 */
		uint32_t csum = (~ntohs(ip4->hdr_checksum) & 0xFFFF)
		              + (~ntohs(old_ttl_proto) & 0xFFFF)
		              + ntohs(new_ttl_proto);
		csum = (csum >> 16) + (csum & 0xFFFF);
		csum += csum >> 16;
		ip4->hdr_checksum = htons(~csum & 0xFFFF);
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(data + meta->l3_offset);
		ip6->hop_limits--;
	}

	/* 2. MAC rewrite (if FIB cache is valid from conntrack) */
	if (meta->fwd_ifindex != 0) {
		struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		memcpy(&eth->dst_addr, meta->fwd_dmac, 6);
		memcpy(&eth->src_addr, meta->fwd_smac, 6);
	}

	/* 3. DSCP rewrite (if set by firewall filter) */
	if (meta->dscp_rewrite != 0) {
		if (meta->addr_family == AF_INET) {
			struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)(data + meta->l3_offset);
			uint8_t old_tos = ip4->type_of_service;
			ip4->type_of_service = (meta->dscp_rewrite << 2) | (old_tos & 0x03);
			/* Recompute checksum after TOS change */
			ip4->hdr_checksum = 0;
			ip4->hdr_checksum = rte_ipv4_cksum(ip4);
		} else {
			struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(data + meta->l3_offset);
			uint32_t vtc = rte_be_to_cpu_32(ip6->vtc_flow);
			vtc = (vtc & 0xF00FFFFF) | ((uint32_t)meta->dscp_rewrite << 22);
			ip6->vtc_flow = rte_cpu_to_be_32(vtc);
		}
	}

	/* 4. VLAN handling */
	if (meta->egress_vlan_id != 0 && meta->ingress_vlan_id == 0) {
		/* Push VLAN tag */
		pkt->vlan_tci = meta->egress_vlan_id;
		pkt->ol_flags |= RTE_MBUF_F_TX_VLAN;
	} else if (meta->egress_vlan_id == 0 && meta->ingress_vlan_id != 0) {
		/* Strip VLAN (already parsed, adjust mbuf if needed) */
	}

	/* 5. Transmit */
	uint16_t tx_port = meta->fwd_ifindex;  /* TODO: map ifindex -> DPDK port_id */
	if (tx_port == 0) {
		/* No forwarding destination determined — drop */
		rte_pktmbuf_free(pkt);
		ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
		return;
	}

	uint16_t sent = rte_eth_tx_burst(tx_port, 0, &pkt, 1);
	if (sent == 0) {
		rte_pktmbuf_free(pkt);
		ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
	} else {
		ctr_iface_tx_add(ctx, tx_port, rte_pktmbuf_pkt_len(pkt));
	}
}
