/* SPDX-License-Identifier: GPL-2.0-or-later
 * parse.c — Packet parsing (replaces xdp_main header parsing).
 *
 * Parses Ethernet, optional VLAN (802.1Q), IPv4/IPv6, and L4 headers
 * (TCP, UDP, ICMP/ICMPv6). Fills pkt_meta with parsed fields.
 */

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "shared_mem.h"
#include "tables.h"

/**
 * parse_packet — Parse packet headers and fill pkt_meta.
 *
 * @pkt:  Packet mbuf
 * @meta: Output metadata structure
 *
 * Returns 0 on success, -1 if packet is malformed or too short.
 */
int
parse_packet(struct rte_mbuf *pkt, struct pkt_meta *meta)
{
	uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t data_len = rte_pktmbuf_data_len(pkt);
	uint16_t offset = 0;
	uint16_t ether_type;

	meta->pkt_len = data_len;

	/* Ethernet header */
	if (data_len < sizeof(struct rte_ether_hdr))
		return -1;

	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
	ether_type = rte_be_to_cpu_16(eth->ether_type);
	offset = sizeof(struct rte_ether_hdr);

	/* VLAN (802.1Q) */
	if (ether_type == RTE_ETHER_TYPE_VLAN) {
		if (data_len < offset + 4)
			return -1;

		struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(data + offset);
		meta->ingress_vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0x0FFF;
		ether_type = rte_be_to_cpu_16(vlan->eth_proto);
		offset += sizeof(struct rte_vlan_hdr);
	}

	meta->l3_offset = offset;

	/* IPv4 */
	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		if (data_len < offset + sizeof(struct rte_ipv4_hdr))
			return -1;

		struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)(data + offset);
		uint8_t ihl_words = ip4->version_ihl & 0x0F;
		uint8_t ihl = ihl_words * 4;

		meta->addr_family = AF_INET;
		meta->ip_ihl = ihl_words;
		meta->src_ip.v4 = ip4->src_addr;
		meta->dst_ip.v4 = ip4->dst_addr;
		meta->protocol = ip4->next_proto_id;
		meta->ip_ttl = ip4->time_to_live;
		meta->dscp = (ip4->type_of_service >> 2) & 0x3F;

		/* Fragment detection */
		uint16_t frag_off = rte_be_to_cpu_16(ip4->fragment_offset);
		if (frag_off & (RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK))
			meta->is_fragment = 1;

		offset += ihl;
		meta->l4_offset = offset;

	/* IPv6 */
	} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
		if (data_len < offset + sizeof(struct rte_ipv6_hdr))
			return -1;

		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(data + offset);

		meta->addr_family = AF_INET6;
		memcpy(meta->src_ip.v6, ip6->src_addr.a, 16);
		memcpy(meta->dst_ip.v6, ip6->dst_addr.a, 16);
		meta->protocol = ip6->proto;
		meta->ip_ttl = ip6->hop_limits;

		uint32_t vtc_flow = rte_be_to_cpu_32(ip6->vtc_flow);
		meta->dscp = (vtc_flow >> 22) & 0x3F;

		offset += sizeof(struct rte_ipv6_hdr);

		/* Skip IPv6 extension headers (hop-by-hop, routing,
		 * fragment, auth, destination). Follow next-header chain
		 * until we reach a known transport protocol. */
		#define MAX_EXT_HDRS 6
		for (int i = 0; i < MAX_EXT_HDRS; i++) {
			switch (meta->protocol) {
			case 0:   /* Hop-by-Hop */
			case 43:  /* Routing */
			case 51:  /* Authentication Header */
			case 60:  /* Destination Options */
			{
				if (data_len < offset + 2)
					return -1;
				uint8_t next_hdr = data[offset];
				uint8_t ext_len = data[offset + 1];
				meta->protocol = next_hdr;
				offset += (ext_len + 1) * 8;
				if (offset > data_len)
					return -1;
				continue;
			}
			case 44:  /* Fragment Header (fixed 8 bytes) */
			{
				if (data_len < offset + 8)
					return -1;
				uint8_t next_hdr = data[offset];
				meta->protocol = next_hdr;
				meta->is_fragment = 1;
				offset += 8;
				continue;
			}
			default:
				goto ext_done;
			}
		}
		ext_done:

		meta->l4_offset = offset;

	} else {
		/* Unsupported L3 protocol */
		return -1;
	}

	/* L4 parsing */
	switch (meta->protocol) {
	case PROTO_TCP:
		if (data_len < meta->l4_offset + sizeof(struct rte_tcp_hdr))
			return -1;
		struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(data + meta->l4_offset);
		meta->src_port = tcp->src_port;
		meta->dst_port = tcp->dst_port;
		meta->tcp_flags = tcp->tcp_flags;
		meta->tcp_seq = tcp->sent_seq;
		meta->tcp_ack_seq = tcp->recv_ack;
		uint8_t tcp_hdr_len = (tcp->data_off >> 4) * 4;
		meta->payload_offset = meta->l4_offset + tcp_hdr_len;
		break;

	case PROTO_UDP:
		if (data_len < meta->l4_offset + sizeof(struct rte_udp_hdr))
			return -1;
		struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(data + meta->l4_offset);
		meta->src_port = udp->src_port;
		meta->dst_port = udp->dst_port;
		meta->payload_offset = meta->l4_offset + sizeof(struct rte_udp_hdr);
		break;

	case PROTO_ICMP:
		if (data_len < meta->l4_offset + 8)
			return -1;
		uint8_t *icmp = data + meta->l4_offset;
		meta->icmp_type = icmp[0];
		meta->icmp_code = icmp[1];
		meta->icmp_id = *(uint16_t *)(icmp + 4);
		/* Use ICMP id as "port" for session tracking */
		meta->src_port = meta->icmp_id;
		meta->dst_port = 0;
		meta->payload_offset = meta->l4_offset + 8;
		break;

	case PROTO_ICMPV6:
		if (data_len < meta->l4_offset + 8)
			return -1;
		uint8_t *icmp6 = data + meta->l4_offset;
		meta->icmp_type = icmp6[0];
		meta->icmp_code = icmp6[1];
		meta->icmp_id = *(uint16_t *)(icmp6 + 4);
		meta->src_port = meta->icmp_id;
		meta->dst_port = 0;
		meta->payload_offset = meta->l4_offset + 8;
		break;

	default:
		/* Other protocols: no L4 ports */
		meta->payload_offset = meta->l4_offset;
		break;
	}

	/* Record ingress interface from mbuf */
	meta->ingress_ifindex = pkt->port;

	return 0;
}
