/* SPDX-License-Identifier: GPL-2.0-or-later
 * reject.c — Packet rejection: TCP RST and ICMP Unreachable.
 *
 * When policy returns ACTION_REJECT, these functions craft and send
 * response packets (TCP RST for TCP, ICMP Unreachable for other
 * protocols) back to the sender via the ingress port.
 *
 * Reference: bpf/xdp/xdp_policy.c send_tcp_rst_v4/v6, send_icmp_unreach_v4/v6.
 */

#include <string.h>
#include <arpa/inet.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/* IPv6 header — DPDK doesn't define a compact writable one with all fields */
struct ipv6hdr_raw {
	uint32_t vtc_flow;	/* version(4) + TC(8) + flow_label(20) */
	uint16_t payload_len;
	uint8_t  nexthdr;
	uint8_t  hop_limit;
	uint8_t  src_addr[16];
	uint8_t  dst_addr[16];
};

/* ICMPv4 header */
struct icmphdr {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
	uint32_t unused;
};

/* ICMPv6 header */
struct icmp6hdr {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
	uint32_t unused;
};

/**
 * ip4_checksum — Compute IPv4 header checksum (20 bytes = 10 x 16-bit words).
 */
static inline uint16_t
ip4_checksum(const void *hdr, int len)
{
	const uint16_t *p = hdr;
	uint32_t csum = 0;

	for (int i = 0; i < len / 2; i++)
		csum += p[i];

	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += csum >> 16;
	return (uint16_t)(~csum);
}

/**
 * send_tcp_rst_v4 — Send a TCP RST reply for IPv4 REJECT action.
 *
 * Allocates a new mbuf, builds ETH(14) + IP(20) + TCP(20) = 54 bytes,
 * swaps MACs/IPs/ports, sets RST, computes checksums, and sends via
 * rte_eth_tx_burst() on the ingress port.
 */
void
send_tcp_rst_v4(struct rte_mbuf *pkt, struct pkt_meta *meta,
                struct pipeline_ctx *ctx)
{
	(void)ctx;

	/* Read MACs from original packet */
	struct rte_ether_hdr *orig_eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	uint8_t orig_smac[6], orig_dmac[6];
	memcpy(orig_smac, &orig_eth->src_addr, 6);
	memcpy(orig_dmac, &orig_eth->dst_addr, 6);

	/* Get IPs/ports from meta. For DNAT: use pre-DNAT address as RST source. */
	uint32_t orig_saddr = meta->src_ip.v4;
	uint32_t orig_daddr = (meta->nat_flags & SESS_FLAG_DNAT) ?
		meta->nat_dst_ip.v4 : meta->dst_ip.v4;
	uint16_t orig_sport = meta->src_port;
	uint16_t orig_dport = (meta->nat_flags & SESS_FLAG_DNAT) ?
		meta->nat_dst_port : meta->dst_port;

	uint32_t orig_seq = meta->tcp_seq;
	uint32_t orig_ack = meta->tcp_ack_seq;
	int orig_has_ack = meta->tcp_flags & 0x10;
	int orig_has_syn = meta->tcp_flags & 0x02;
	int orig_has_fin = meta->tcp_flags & 0x01;

	/* Payload length from meta offsets */
	uint16_t hdr_len = meta->payload_offset - meta->l3_offset;
	uint16_t payload_len = 0;
	if (meta->pkt_len > hdr_len)
		payload_len = meta->pkt_len - hdr_len;

	/* Allocate new mbuf for the RST packet */
	struct rte_mbuf *rst = rte_pktmbuf_alloc(pkt->pool);
	if (!rst)
		return;

	uint8_t *data = (uint8_t *)rte_pktmbuf_append(rst, 54);
	if (!data) {
		rte_pktmbuf_free(rst);
		return;
	}

	/* Ethernet header: swap MACs */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
	memcpy(&eth->dst_addr, orig_smac, 6);
	memcpy(&eth->src_addr, orig_dmac, 6);
	eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* IP header */
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(data + 14);
	memset(ip, 0, 20);
	ip->version_ihl = (4 << 4) | 5;
	ip->total_length = rte_cpu_to_be_16(40);
	ip->fragment_offset = rte_cpu_to_be_16(0x4000);  /* DF */
	ip->time_to_live = 64;
	ip->next_proto_id = PROTO_TCP;
	ip->src_addr = orig_daddr;
	ip->dst_addr = orig_saddr;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = ip4_checksum(ip, 20);

	/* TCP header */
	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(data + 34);
	memset(tcp, 0, 20);
	tcp->src_port = orig_dport;
	tcp->dst_port = orig_sport;
	tcp->data_off = (5 << 4);

	if (orig_has_ack) {
		tcp->tcp_flags = 0x04;  /* RST */
		tcp->sent_seq = orig_ack;
	} else {
		tcp->tcp_flags = 0x14;  /* RST + ACK */
		uint32_t seg_len = payload_len;
		if (orig_has_syn) seg_len++;
		if (orig_has_fin) seg_len++;
		if (seg_len == 0) seg_len = 1;
		tcp->recv_ack = rte_cpu_to_be_32(
			rte_be_to_cpu_32(orig_seq) + seg_len);
	}

	/* TCP checksum: pseudo-header + TCP header */
	struct {
		uint32_t saddr, daddr;
		uint8_t  zero;
		uint8_t  proto;
		uint16_t tcp_len;
	} __attribute__((packed)) pseudo = {
		.saddr = orig_daddr,
		.daddr = orig_saddr,
		.zero = 0,
		.proto = PROTO_TCP,
		.tcp_len = rte_cpu_to_be_16(20),
	};

	uint32_t csum = 0;
	const uint16_t *p16;

	p16 = (const uint16_t *)&pseudo;
	for (int i = 0; i < 6; i++)
		csum += p16[i];

	p16 = (const uint16_t *)tcp;
	for (int i = 0; i < 10; i++)
		csum += p16[i];

	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += csum >> 16;
	tcp->cksum = (uint16_t)(~csum);

	/* Send on ingress port */
	uint16_t tx_port = meta->ingress_ifindex;
	uint16_t sent = rte_eth_tx_burst(tx_port, 0, &rst, 1);
	if (sent == 0)
		rte_pktmbuf_free(rst);
}

/**
 * send_tcp_rst_v6 — Send a TCP RST reply for IPv6 REJECT action.
 *
 * Allocates a new mbuf, builds ETH(14) + IPv6(40) + TCP(20) = 74 bytes.
 * IPv6 has no header checksum. TCP checksum uses IPv6 pseudo-header.
 */
void
send_tcp_rst_v6(struct rte_mbuf *pkt, struct pkt_meta *meta,
                struct pipeline_ctx *ctx)
{
	(void)ctx;

	struct rte_ether_hdr *orig_eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	uint8_t orig_smac[6], orig_dmac[6];
	memcpy(orig_smac, &orig_eth->src_addr, 6);
	memcpy(orig_dmac, &orig_eth->dst_addr, 6);

	/* IPs from meta */
	uint8_t orig_saddr[16], orig_daddr[16];
	memcpy(orig_saddr, meta->src_ip.v6, 16);
	if (meta->nat_flags & SESS_FLAG_DNAT)
		memcpy(orig_daddr, meta->nat_dst_ip.v6, 16);
	else
		memcpy(orig_daddr, meta->dst_ip.v6, 16);

	uint16_t orig_sport = meta->src_port;
	uint16_t orig_dport = (meta->nat_flags & SESS_FLAG_DNAT) ?
		meta->nat_dst_port : meta->dst_port;

	uint32_t orig_seq = meta->tcp_seq;
	uint32_t orig_ack = meta->tcp_ack_seq;
	int orig_has_ack = meta->tcp_flags & 0x10;
	int orig_has_syn = meta->tcp_flags & 0x02;
	int orig_has_fin = meta->tcp_flags & 0x01;

	uint16_t hdr_len = meta->payload_offset - meta->l3_offset;
	uint16_t payload_len = 0;
	if (meta->pkt_len > hdr_len)
		payload_len = meta->pkt_len - hdr_len;

	struct rte_mbuf *rst = rte_pktmbuf_alloc(pkt->pool);
	if (!rst)
		return;

	uint8_t *data = (uint8_t *)rte_pktmbuf_append(rst, 74);
	if (!data) {
		rte_pktmbuf_free(rst);
		return;
	}

	/* Ethernet: swap MACs */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
	memcpy(&eth->dst_addr, orig_smac, 6);
	memcpy(&eth->src_addr, orig_dmac, 6);
	eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	/* IPv6 header (no checksum) */
	struct ipv6hdr_raw *ip6 = (struct ipv6hdr_raw *)(data + 14);
	memset(ip6, 0, 40);
	ip6->vtc_flow = rte_cpu_to_be_32(0x60000000);  /* version=6 */
	ip6->payload_len = rte_cpu_to_be_16(20);
	ip6->nexthdr = PROTO_TCP;
	ip6->hop_limit = 64;
	memcpy(ip6->src_addr, orig_daddr, 16);  /* response src = original dst */
	memcpy(ip6->dst_addr, orig_saddr, 16);  /* response dst = original src */

	/* TCP header */
	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(data + 54);
	memset(tcp, 0, 20);
	tcp->src_port = orig_dport;
	tcp->dst_port = orig_sport;
	tcp->data_off = (5 << 4);

	if (orig_has_ack) {
		tcp->tcp_flags = 0x04;  /* RST */
		tcp->sent_seq = orig_ack;
	} else {
		tcp->tcp_flags = 0x14;  /* RST + ACK */
		uint32_t seg_len = payload_len;
		if (orig_has_syn) seg_len++;
		if (orig_has_fin) seg_len++;
		if (seg_len == 0) seg_len = 1;
		tcp->recv_ack = rte_cpu_to_be_32(
			rte_be_to_cpu_32(orig_seq) + seg_len);
	}

	/* TCP checksum with IPv6 pseudo-header:
	 * src(16) + dst(16) + length(4) + nexthdr(4) + TCP header */
	uint32_t csum = 0;
	const uint16_t *p16;

	/* Pseudo-header: source address (response src = orig_daddr) */
	p16 = (const uint16_t *)orig_daddr;
	for (int i = 0; i < 8; i++)
		csum += p16[i];

	/* Pseudo-header: dest address (response dst = orig_saddr) */
	p16 = (const uint16_t *)orig_saddr;
	for (int i = 0; i < 8; i++)
		csum += p16[i];

	/* Pseudo-header: upper-layer length + next header */
	csum += rte_cpu_to_be_16(20);
	csum += rte_cpu_to_be_16(PROTO_TCP);

	/* TCP header (10 x 16-bit words) */
	p16 = (const uint16_t *)tcp;
	for (int i = 0; i < 10; i++)
		csum += p16[i];

	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += csum >> 16;
	tcp->cksum = (uint16_t)(~csum);

	/* Send on ingress port */
	uint16_t tx_port = meta->ingress_ifindex;
	uint16_t sent = rte_eth_tx_burst(tx_port, 0, &rst, 1);
	if (sent == 0)
		rte_pktmbuf_free(rst);
}

/**
 * send_icmp_unreach_v4 — Send ICMP Destination Unreachable for IPv4 REJECT.
 *
 * Packet layout: ETH(14) + IP(20) + ICMP(8) + orig_IP(20) + orig_L4(8) = 70 bytes.
 * ICMP type 3 (dest unreachable), code 13 (admin prohibited).
 */
void
send_icmp_unreach_v4(struct rte_mbuf *pkt, struct pkt_meta *meta,
                     struct pipeline_ctx *ctx)
{
	(void)ctx;

	uint8_t *orig_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t orig_data_len = rte_pktmbuf_data_len(pkt);

	/* Read MACs from original packet */
	struct rte_ether_hdr *orig_eth = (struct rte_ether_hdr *)orig_data;
	uint8_t orig_smac[6], orig_dmac[6];
	memcpy(orig_smac, &orig_eth->src_addr, 6);
	memcpy(orig_dmac, &orig_eth->dst_addr, 6);

	/* Save original IP header (20 bytes) + first 8 bytes of L4 = 28 bytes */
	uint8_t orig_hdr[28];
	if (orig_data_len < 14 + 28)
		return;
	memcpy(orig_hdr, orig_data + 14, 28);

	/* Source/dest IPs from meta (handle DNAT) */
	uint32_t orig_saddr = meta->src_ip.v4;
	uint32_t orig_daddr = (meta->nat_flags & SESS_FLAG_DNAT) ?
		meta->nat_dst_ip.v4 : meta->dst_ip.v4;

	/* Allocate new mbuf */
	struct rte_mbuf *icmp_pkt = rte_pktmbuf_alloc(pkt->pool);
	if (!icmp_pkt)
		return;

	uint8_t *data = (uint8_t *)rte_pktmbuf_append(icmp_pkt, 70);
	if (!data) {
		rte_pktmbuf_free(icmp_pkt);
		return;
	}

	/* Ethernet: swap MACs */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
	memcpy(&eth->dst_addr, orig_smac, 6);
	memcpy(&eth->src_addr, orig_dmac, 6);
	eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* IP header: total_len = 56 (IP 20 + ICMP 8 + payload 28) */
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(data + 14);
	memset(ip, 0, 20);
	ip->version_ihl = (4 << 4) | 5;
	ip->total_length = rte_cpu_to_be_16(56);
	ip->fragment_offset = rte_cpu_to_be_16(0x4000);  /* DF */
	ip->time_to_live = 64;
	ip->next_proto_id = PROTO_ICMP;
	ip->src_addr = orig_daddr;  /* firewall responds as dest */
	ip->dst_addr = orig_saddr;  /* back to sender */
	ip->hdr_checksum = 0;
	ip->hdr_checksum = ip4_checksum(ip, 20);

	/* ICMP header: type 3, code 13 (admin prohibited) */
	struct icmphdr *icmp = (struct icmphdr *)(data + 34);
	memset(icmp, 0, 8);
	icmp->type = 3;
	icmp->code = 13;

	/* Copy original IP header + 8 bytes L4 to ICMP payload */
	memcpy(data + 42, orig_hdr, 28);

	/* ICMP checksum: header(8) + payload(28) = 36 bytes = 18 words */
	uint32_t csum = 0;
	const uint16_t *p16 = (const uint16_t *)(data + 34);
	for (int i = 0; i < 18; i++)
		csum += p16[i];
	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += csum >> 16;
	icmp->checksum = (uint16_t)(~csum);

	/* Send on ingress port */
	uint16_t tx_port = meta->ingress_ifindex;
	uint16_t sent = rte_eth_tx_burst(tx_port, 0, &icmp_pkt, 1);
	if (sent == 0)
		rte_pktmbuf_free(icmp_pkt);
}

/**
 * send_icmp_unreach_v6 — Send ICMPv6 Destination Unreachable for IPv6 REJECT.
 *
 * Packet layout: ETH(14) + IPv6(40) + ICMPv6(8) + orig_IPv6(40) + orig_L4(8) = 110 bytes.
 * ICMPv6 type 1 (dest unreachable), code 1 (admin prohibited).
 */
void
send_icmp_unreach_v6(struct rte_mbuf *pkt, struct pkt_meta *meta,
                     struct pipeline_ctx *ctx)
{
	(void)ctx;

	uint8_t *orig_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t orig_data_len = rte_pktmbuf_data_len(pkt);

	/* Read MACs from original packet */
	struct rte_ether_hdr *orig_eth = (struct rte_ether_hdr *)orig_data;
	uint8_t orig_smac[6], orig_dmac[6];
	memcpy(orig_smac, &orig_eth->src_addr, 6);
	memcpy(orig_dmac, &orig_eth->dst_addr, 6);

	/* Save original IPv6 header (40 bytes) + first 8 bytes of L4 = 48 bytes */
	uint8_t orig_hdr[48];
	if (orig_data_len < 14 + 48)
		return;
	memcpy(orig_hdr, orig_data + 14, 48);

	/* Response addresses from meta (handle DNAT) */
	uint8_t resp_saddr[16];  /* response src = original dst */
	if (meta->nat_flags & SESS_FLAG_DNAT)
		memcpy(resp_saddr, meta->nat_dst_ip.v6, 16);
	else
		memcpy(resp_saddr, meta->dst_ip.v6, 16);

	/* Allocate new mbuf */
	struct rte_mbuf *icmp_pkt = rte_pktmbuf_alloc(pkt->pool);
	if (!icmp_pkt)
		return;

	uint8_t *data = (uint8_t *)rte_pktmbuf_append(icmp_pkt, 110);
	if (!data) {
		rte_pktmbuf_free(icmp_pkt);
		return;
	}

	/* Ethernet: swap MACs */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
	memcpy(&eth->dst_addr, orig_smac, 6);
	memcpy(&eth->src_addr, orig_dmac, 6);
	eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	/* IPv6 header: payload_len = 56 (ICMPv6 8 + payload 48) */
	struct ipv6hdr_raw *ip6 = (struct ipv6hdr_raw *)(data + 14);
	memset(ip6, 0, 40);
	ip6->vtc_flow = rte_cpu_to_be_32(0x60000000);  /* version=6 */
	ip6->payload_len = rte_cpu_to_be_16(56);
	ip6->nexthdr = PROTO_ICMPV6;
	ip6->hop_limit = 64;
	memcpy(ip6->src_addr, resp_saddr, 16);
	memcpy(ip6->dst_addr, meta->src_ip.v6, 16);

	/* ICMPv6 header: type 1 (dest unreachable), code 1 (admin prohibited) */
	struct icmp6hdr *icmp6 = (struct icmp6hdr *)(data + 54);
	memset(icmp6, 0, 8);
	icmp6->type = 1;
	icmp6->code = 1;

	/* Copy original IPv6 header + 8 bytes L4 to ICMPv6 payload */
	memcpy(data + 62, orig_hdr, 48);

	/* ICMPv6 checksum: pseudo-header + ICMPv6 message.
	 * Pseudo-header: src(16) + dst(16) + upper_layer_len(4) + nexthdr(4)
	 * ICMPv6 message: header(8) + payload(48) = 56 bytes */
	uint32_t csum = 0;
	const uint16_t *p16;

	/* Pseudo-header: source address */
	p16 = (const uint16_t *)resp_saddr;
	for (int i = 0; i < 8; i++)
		csum += p16[i];

	/* Pseudo-header: dest address */
	p16 = (const uint16_t *)meta->src_ip.v6;
	for (int i = 0; i < 8; i++)
		csum += p16[i];

	/* Pseudo-header: upper-layer length + next header */
	csum += rte_cpu_to_be_16(56);
	csum += rte_cpu_to_be_16(PROTO_ICMPV6);

	/* ICMPv6 header + payload (56 bytes = 28 words) */
	p16 = (const uint16_t *)(data + 54);
	for (int i = 0; i < 28; i++)
		csum += p16[i];

	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += csum >> 16;
	icmp6->checksum = (uint16_t)(~csum);

	/* Send on ingress port */
	uint16_t tx_port = meta->ingress_ifindex;
	uint16_t sent = rte_eth_tx_burst(tx_port, 0, &icmp_pkt, 1);
	if (sent == 0)
		rte_pktmbuf_free(icmp_pkt);
}
