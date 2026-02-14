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
#include "events.h"

/* ICMP Time Exceeded generation (reject.c) */
extern void send_icmp_time_exceeded_v4(struct rte_mbuf *pkt, struct pkt_meta *meta,
                                       struct pipeline_ctx *ctx);
extern void send_icmp_time_exceeded_v6(struct rte_mbuf *pkt, struct pkt_meta *meta,
                                       struct pipeline_ctx *ctx);

/**
 * host_inbound_flag — Map packet protocol/port to HOST_INBOUND_* flag.
 * Returns 0 for unrecognized services (allowed by default).
 */
static inline uint32_t
host_inbound_flag(struct pkt_meta *meta)
{
	uint8_t proto = meta->protocol;

	/* ICMP/ICMPv6 echo request */
	if (proto == PROTO_ICMP || proto == PROTO_ICMPV6) {
		if (meta->icmp_type == 8 || meta->icmp_type == 128)
			return HOST_INBOUND_PING;
		/* IRDP: Router Advertisement (9) / Router Solicitation (10) */
		if (proto == PROTO_ICMP &&
		    (meta->icmp_type == 9 || meta->icmp_type == 10))
			return HOST_INBOUND_ROUTER_DISCOVERY;
		return 0;  /* other ICMP always allowed */
	}

	/* OSPF is IP protocol 89, not port-based */
	if (proto == 89)
		return HOST_INBOUND_OSPF;

	/* ESP (protocol 50) */
	if (proto == PROTO_ESP)
		return HOST_INBOUND_ESP;

	/* VRRP (protocol 112) */
	if (proto == PROTO_VRRP)
		return HOST_INBOUND_VRRP;

	/* TCP/UDP port-based services */
	uint16_t port = rte_be_to_cpu_16(meta->dst_port);
	switch (port) {
	case 22:            return HOST_INBOUND_SSH;
	case 53:            return HOST_INBOUND_DNS;
	case 80:            return HOST_INBOUND_HTTP;
	case 443:           return HOST_INBOUND_HTTPS;
	case 67: case 68:   return HOST_INBOUND_DHCP;
	case 546: case 547: return HOST_INBOUND_DHCPV6;
	case 123:           return HOST_INBOUND_NTP;
	case 161:           return HOST_INBOUND_SNMP;
	case 179:           return HOST_INBOUND_BGP;
	case 23:            return HOST_INBOUND_TELNET;
	case 21:            return HOST_INBOUND_FTP;
	case 830:           return HOST_INBOUND_NETCONF;
	case 514:           return HOST_INBOUND_SYSLOG;
	case 1812: case 1813: return HOST_INBOUND_RADIUS;
	case 500: case 4500:  return HOST_INBOUND_IKE;
	}

	/* Traceroute: UDP ports 33434-33523 */
	if (proto == PROTO_UDP && port >= 33434 && port <= 33523)
		return HOST_INBOUND_TRACEROUTE;

	return 0;  /* unknown service → allow by default */
}

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

	/* 0. Host-inbound-traffic check: if no egress interface was
	 * resolved, the packet is locally destined. Check host-inbound
	 * policy before passing to the kernel stack. */
	if (meta->fwd_ifindex == 0) {
		if (meta->ingress_zone < MAX_ZONES && ctx->shm->zone_configs) {
			struct zone_config *zc = &ctx->shm->zone_configs[meta->ingress_zone];
			if (zc->host_inbound_flags != 0) {
				uint32_t flag = host_inbound_flag(meta);
				if (flag != 0 && !(zc->host_inbound_flags & flag)) {
					ctr_global_inc(ctx, GLOBAL_CTR_HOST_INBOUND_DENY);
					emit_event(ctx, meta, EVENT_TYPE_POLICY_DENY, ACTION_DENY);
					rte_pktmbuf_free(pkt);
					return;
				}
			}
		}
		/* Host-bound: pass to kernel (DPDK can't deliver locally,
		 * so for now count and drop — requires KNI or exception path) */
		ctr_global_inc(ctx, GLOBAL_CTR_HOST_INBOUND);
		rte_pktmbuf_free(pkt);
		return;
	}

	/* 1. TTL check and decrement */
	if (meta->ip_ttl <= 1) {
		if (meta->addr_family == AF_INET)
			send_icmp_time_exceeded_v4(pkt, meta, ctx);
		else
			send_icmp_time_exceeded_v6(pkt, meta, ctx);
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
	if (meta->dscp_rewrite != 0xFF) {
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

	/* 4. VLAN handling
	 *
	 * Ingress VLAN tag is still in the packet (parse.c doesn't strip).
	 * Egress VLAN tag must be set if forwarding to a VLAN sub-interface.
	 *
	 * Cases:
	 *   ingress=0, egress=0  → nothing
	 *   ingress=0, egress>0  → push VLAN tag
	 *   ingress>0, egress=0  → strip VLAN tag
	 *   ingress>0, egress>0  → rewrite VLAN ID if different
	 */
	if (meta->ingress_vlan_id != 0 && meta->egress_vlan_id == 0) {
		/* Strip VLAN tag: shift ETH header 4 bytes forward,
		 * overwriting the VLAN bytes */
		struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		struct rte_ether_hdr eth_copy;
		rte_ether_addr_copy(&eth->dst_addr, &eth_copy.dst_addr);
		rte_ether_addr_copy(&eth->src_addr, &eth_copy.src_addr);
		/* Use the ethertype AFTER the VLAN tag (already parsed) */
		eth_copy.ether_type = (meta->addr_family == AF_INET) ?
			rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) :
			rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		rte_pktmbuf_adj(pkt, 4);
		data = rte_pktmbuf_mtod(pkt, uint8_t *);
		memcpy(data, &eth_copy, sizeof(struct rte_ether_hdr));
	} else if (meta->egress_vlan_id != 0) {
		if (meta->ingress_vlan_id != 0) {
			/* Rewrite VLAN ID in existing tag */
			struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(
				data + sizeof(struct rte_ether_hdr));
			vlan->vlan_tci = rte_cpu_to_be_16(meta->egress_vlan_id);
		} else {
			/* Push new VLAN tag via TX offload */
			pkt->vlan_tci = meta->egress_vlan_id;
			pkt->ol_flags |= RTE_MBUF_F_TX_VLAN;
		}
	}

	/* 5. Transmit via TX buffer (batched) or direct fallback.
	 *
	 * fwd_ifindex is the DPDK port_id, populated by zone.c from
	 * the FIB nexthop's port_id field (not the kernel ifindex). */
	uint16_t tx_port = meta->fwd_ifindex;

	if (tx_port < MAX_PORTS && ctx->tx_bufs[tx_port]) {
		ctr_iface_tx_add(ctx, tx_port, rte_pktmbuf_pkt_len(pkt));
		uint16_t sent = rte_eth_tx_buffer(tx_port, ctx->tx_queue_id,
		                                  ctx->tx_bufs[tx_port], pkt);
		(void)sent;  /* auto-flushed packets counted by buffer */
	} else if (tx_port != 0) {
		/* Fallback: direct TX (port outside MAX_PORTS or no buffer) */
		uint16_t sent = rte_eth_tx_burst(tx_port, ctx->tx_queue_id,
		                                 &pkt, 1);
		if (sent == 0) {
			rte_pktmbuf_free(pkt);
			ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
		} else {
			ctr_iface_tx_add(ctx, tx_port, rte_pktmbuf_pkt_len(pkt));
		}
	} else {
		/* No forwarding destination — drop */
		rte_pktmbuf_free(pkt);
		ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
	}
}

/**
 * flush_tx_buffers — Flush all per-port TX buffers.
 *
 * Called at the end of each RX burst to send any remaining buffered
 * packets. Without this, the last few packets in each burst would
 * be delayed until the buffer fills up from the next burst.
 */
void
flush_tx_buffers(struct pipeline_ctx *ctx)
{
	for (uint16_t p = 0; p < ctx->nb_ports && p < MAX_PORTS; p++) {
		if (ctx->tx_bufs[p])
			rte_eth_tx_buffer_flush(p, ctx->tx_queue_id,
			                        ctx->tx_bufs[p]);
	}
}
