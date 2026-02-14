/* SPDX-License-Identifier: GPL-2.0-or-later
 * nat64.c — NAT64 IPv6 <-> IPv4 translation (replaces xdp_nat64).
 *
 * Translates IPv6 packets with a NAT64 prefix destination to IPv4,
 * and reverse-translates IPv4 replies back to IPv6.
 */

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <string.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * icmpv4_type_to_v6 — Map ICMPv4 type/code to ICMPv6.
 * Returns 0 on success, -1 if unmappable.
 */
static inline int
icmpv4_type_to_v6(uint8_t v4_type, uint8_t v4_code,
                  uint8_t *v6_type, uint8_t *v6_code)
{
	switch (v4_type) {
	case 0:  /* Echo Reply */
		*v6_type = 129;  /* ICMPv6 Echo Reply */
		*v6_code = 0;
		return 0;
	case 8:  /* Echo Request */
		*v6_type = 128;  /* ICMPv6 Echo Request */
		*v6_code = 0;
		return 0;
	case 3:  /* Destination Unreachable */
		*v6_type = 1;    /* ICMPv6 Dest Unreachable */
		switch (v4_code) {
		case 0: case 1: case 5: case 6: case 7: case 8:
		case 11: case 12:
			*v6_code = 0;  /* No route */
			return 0;
		case 2:
			*v6_type = 4;  /* Parameter Problem */
			*v6_code = 1;  /* Unrecognized next header */
			return 0;
		case 3:
			*v6_code = 4;  /* Port unreachable */
			return 0;
		case 4:
			*v6_type = 2;  /* Packet Too Big */
			*v6_code = 0;
			return 0;
		case 9: case 10: case 13:
			*v6_code = 1;  /* Admin prohibited */
			return 0;
		default:
			*v6_code = 0;
			return 0;
		}
	case 11: /* Time Exceeded */
		*v6_type = 3;    /* ICMPv6 Time Exceeded */
		*v6_code = v4_code;
		return 0;
	case 12: /* Parameter Problem */
		*v6_type = 4;    /* ICMPv6 Parameter Problem */
		*v6_code = 0;
		return 0;
	default:
		return -1;
	}
}

/**
 * nat64_translate — Perform NAT64 header translation.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata
 * @ctx:  Pipeline context
 *
 * For IPv6->IPv4 (forward):
 *   - Strip IPv6 header, create IPv4 header
 *   - Extract embedded IPv4 address from NAT64 prefix (last 32 bits)
 *   - SNAT with pool address
 *   - Create nat64_state reverse entry for return traffic
 *
 * For IPv4->IPv6 (reverse):
 *   - Look up nat64_state by IPv4 5-tuple
 *   - Strip IPv4 header, create IPv6 header
 *   - Restore original IPv6 addresses from state
 */
void
nat64_translate(struct rte_mbuf *pkt, struct pkt_meta *meta,
                struct pipeline_ctx *ctx)
{
	uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);

	if (meta->addr_family == AF_INET6) {
		/* IPv6 -> IPv4 translation */
		if (!ctx->shm->nat64_prefix_map)
			return;

		/* Check if dst matches a NAT64 prefix (first 96 bits) */
		struct nat64_prefix_key pk;
		memcpy(pk.prefix, meta->dst_ip.v6, 12);

		int pos = rte_hash_lookup(ctx->shm->nat64_prefix_map, &pk);
		if (pos < 0)
			return;

		/* Extract embedded IPv4 from last 32 bits of IPv6 dst */
		uint32_t dst_v4;
		memcpy(&dst_v4, meta->dst_ip.v6 + 12, 4);

		/* Save original IPv6 addresses before header transform */
		uint8_t orig_src_v6[16], orig_dst_v6[16];
		memcpy(orig_src_v6, meta->src_ip.v6, 16);
		memcpy(orig_dst_v6, meta->dst_ip.v6, 16);
		uint16_t orig_src_port = meta->src_port;
		uint16_t orig_dst_port = meta->dst_port;

		/* Get IPv6 header */
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(data + meta->l3_offset);
		uint8_t next_hdr = ip6->proto;
		uint8_t hop_limit = ip6->hop_limits;
		uint16_t payload_len = rte_be_to_cpu_16(ip6->payload_len);

		/* Transform: remove 20 bytes (IPv6 40 - IPv4 20) */
		/* Adjust mbuf: shift ethernet header 20 bytes forward */
		uint16_t eth_len = meta->l3_offset;

		/* Save ethernet header */
		struct rte_ether_hdr eth_save;
		memcpy(&eth_save, data, sizeof(eth_save));

		/* Remove 20 bytes from the front of L3 */
		char *new_data = rte_pktmbuf_adj(pkt, 20);
		if (!new_data)
			return;

		/* Restore ethernet header at new position */
		data = (uint8_t *)new_data;
		memmove(data, &eth_save, eth_len);

		/* Update ethertype to IPv4 */
		struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
		eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

		/* Build IPv4 header */
		struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)(data + eth_len);
		memset(ip4, 0, sizeof(*ip4));
		ip4->version_ihl = 0x45;  /* IPv4, IHL=5 (20 bytes) */
		ip4->total_length = rte_cpu_to_be_16(20 + payload_len);
		ip4->time_to_live = hop_limit;
		ip4->next_proto_id = next_hdr;
		ip4->src_addr = meta->nat_src_ip.v4;  /* SNAT pool address */
		ip4->dst_addr = dst_v4;
		ip4->hdr_checksum = 0;
		ip4->hdr_checksum = rte_ipv4_cksum(ip4);

		/* Update meta for downstream */
		meta->addr_family = AF_INET;
		meta->src_ip.v4 = ip4->src_addr;
		meta->dst_ip.v4 = ip4->dst_addr;
		meta->l3_offset = eth_len;
		meta->l4_offset = eth_len + 20;

		/* Recompute L4 checksum (pseudo-header changed from IPv6 to IPv4) */
		if (meta->protocol == PROTO_TCP) {
			struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(data + meta->l4_offset);
			tcp->cksum = 0;
			tcp->cksum = rte_ipv4_udptcp_cksum(ip4, tcp);
		} else if (meta->protocol == PROTO_UDP) {
			struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(data + meta->l4_offset);
			udp->dgram_cksum = 0;
			udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip4, udp);
		}

		/* Create nat64_state reverse entry */
		if (ctx->shm->nat64_state) {
			struct nat64_state_key sk = {
				.src_ip = dst_v4,
				.dst_ip = meta->nat_src_ip.v4,
				.src_port = meta->dst_port,
				.dst_port = meta->nat_src_port,
				.protocol = meta->protocol,
			};
			struct nat64_state_value sv;
			memset(&sv, 0, sizeof(sv));
			memcpy(sv.orig_src_v6, orig_src_v6, 16);
			memcpy(sv.orig_dst_v6, orig_dst_v6, 16);
			sv.orig_src_port = orig_src_port;
			sv.orig_dst_port = orig_dst_port;

			int spos = rte_hash_add_key(ctx->shm->nat64_state, &sk);
			if (spos >= 0 && ctx->shm->nat64_state_values)
				ctx->shm->nat64_state_values[spos] = sv;
		}

	} else if (meta->addr_family == AF_INET) {
		/* IPv4 -> IPv6 reverse translation */
		if (!ctx->shm->nat64_state || !ctx->shm->nat64_state_values)
			return;

		struct nat64_state_key sk = {
			.src_ip = meta->src_ip.v4,
			.dst_ip = meta->dst_ip.v4,
			.src_port = meta->src_port,
			.dst_port = meta->dst_port,
			.protocol = meta->protocol,
		};

		int pos = rte_hash_lookup(ctx->shm->nat64_state, &sk);
		if (pos < 0)
			return;

		struct nat64_state_value *sv = &ctx->shm->nat64_state_values[pos];

		/* Read IPv4 header info before transformation */
		struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)(data + meta->l3_offset);
		uint8_t orig_proto = ip4->next_proto_id;
		uint8_t ip6_proto = orig_proto;
		uint8_t ttl = ip4->time_to_live;
		uint16_t ip4_tot_len = rte_be_to_cpu_16(ip4->total_length);
		uint16_t ip4_hdr_len = (ip4->version_ihl & 0x0F) * 4;
		uint16_t l4_len = (ip4_tot_len > ip4_hdr_len) ?
			ip4_tot_len - ip4_hdr_len : 0;

		/* Map ICMP -> ICMPv6 */
		if (orig_proto == PROTO_ICMP)
			ip6_proto = PROTO_ICMPV6;

		/* Original IPv6 addresses from state:
		 * orig_dst_v6 = server v6 (prefix + v4 server) -> becomes IPv6 src
		 * orig_src_v6 = client v6 (original requester) -> becomes IPv6 dst */
		uint8_t v6_src[16], v6_dst[16];
		memcpy(v6_src, sv->orig_dst_v6, 16);
		memcpy(v6_dst, sv->orig_src_v6, 16);

		/* Restore original destination port */
		uint16_t new_dport = sv->orig_src_port;

		/* Save ethernet header */
		uint16_t eth_len = meta->l3_offset;
		struct rte_ether_hdr eth_save;
		memcpy(&eth_save, data, sizeof(eth_save));

		/* Grow packet by 20 bytes (IPv6 40 - IPv4 20) */
		char *new_data = rte_pktmbuf_prepend(pkt, 20);
		if (!new_data)
			return;

		/* Restore ethernet header at new position */
		data = (uint8_t *)new_data;
		memmove(data, &eth_save, eth_len);

		/* Update ethertype to IPv6 */
		struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
		eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

		/* Build IPv6 header */
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(data + eth_len);
		memset(ip6, 0, sizeof(*ip6));
		ip6->vtc_flow = rte_cpu_to_be_32(0x60000000);
		ip6->payload_len = rte_cpu_to_be_16(l4_len);
		ip6->proto = ip6_proto;
		ip6->hop_limits = ttl;
		memcpy(ip6->src_addr.a, v6_src, 16);
		memcpy(ip6->dst_addr.a, v6_dst, 16);

		/* Update meta for downstream */
		meta->addr_family = AF_INET6;
		memcpy(meta->src_ip.v6, v6_src, 16);
		memcpy(meta->dst_ip.v6, v6_dst, 16);
		meta->protocol = ip6_proto;
		meta->l3_offset = eth_len;
		meta->l4_offset = eth_len + 40;
		meta->dst_port = new_dport;

		/* Recompute L4 checksums (pseudo-header changed IPv4 -> IPv6) */
		if (ip6_proto == PROTO_TCP) {
			struct rte_tcp_hdr *tcp =
				(struct rte_tcp_hdr *)(data + meta->l4_offset);
			tcp->dst_port = new_dport;
			tcp->cksum = 0;
			tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
		} else if (ip6_proto == PROTO_UDP) {
			struct rte_udp_hdr *udp =
				(struct rte_udp_hdr *)(data + meta->l4_offset);
			udp->dst_port = new_dport;
			udp->dgram_cksum = 0;
			udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);
			if (udp->dgram_cksum == 0)
				udp->dgram_cksum = 0xFFFF;
		} else if (ip6_proto == PROTO_ICMPV6) {
			struct rte_icmp_hdr *icmp =
				(struct rte_icmp_hdr *)(data + meta->l4_offset);
			/* Map ICMPv4 type/code to ICMPv6 */
			uint8_t v6_type, v6_code;
			if (icmpv4_type_to_v6(icmp->icmp_type, icmp->icmp_code,
			                      &v6_type, &v6_code) < 0)
				return;  /* Unmappable ICMP type */
			icmp->icmp_type = v6_type;
			icmp->icmp_code = v6_code;
			/* ICMPv6 checksum includes pseudo-header;
			 * use rte_ipv6_udptcp_cksum which works for any
			 * proto when the IPv6 header proto field is set */
			icmp->icmp_cksum = 0;
			icmp->icmp_cksum = rte_ipv6_udptcp_cksum(ip6, icmp);
		}
	}
}
