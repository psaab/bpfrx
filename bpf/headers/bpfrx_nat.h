#ifndef __BPFRX_NAT_H__
#define __BPFRX_NAT_H__

#include "bpfrx_common.h"
#include "bpfrx_helpers.h"

/*
 * Shared NAT rewrite helpers.
 * Used by both XDP (xdp_nat.c) and TC (tc_nat.c) pipelines.
 * All functions are context-agnostic -- they operate on
 * void *data / void *data_end / struct pkt_meta * only.
 */

/*
 * Update L4 (TCP/UDP) checksum for a 4-byte pseudo-header field change.
 * l4 must be pre-validated by caller.
 */
static __always_inline void
nat_update_l4_csum(void *l4, void *data_end, struct pkt_meta *meta,
		   __be32 old_ip, __be32 new_ip)
{
	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_4(&tcp->check, old_ip, new_ip);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		if (udp->check != 0)
			csum_update_4(&udp->check, old_ip, new_ip);
	}
}

/*
 * Update L4 checksum for a 128-bit IPv6 address change.
 * l4 must be pre-validated by caller.
 */
static __always_inline void
nat_update_l4_csum_v6(void *l4, void *data_end, struct pkt_meta *meta,
		      const __u8 *old_addr, const __u8 *new_addr)
{
	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_16(&tcp->check, old_addr, new_addr);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		/* IPv6 UDP checksum is mandatory -- always update */
		csum_update_16(&udp->check, old_addr, new_addr);
	} else if (meta->protocol == PROTO_ICMPV6) {
		/* ICMPv6 checksum covers pseudo-header with addresses */
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) > data_end)
			return;
		csum_update_16(&icmp6->icmp6_cksum, old_addr, new_addr);
	}
}

/*
 * Update L4 checksum for a 2-byte port field change.
 * l4 must be pre-validated by caller.
 */
static __always_inline void
nat_update_l4_port_csum(void *l4, void *data_end, struct pkt_meta *meta,
			__be16 old_port, __be16 new_port)
{
	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_2(&tcp->check, old_port, new_port);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		if (meta->addr_family == AF_INET6 || udp->check != 0)
			csum_update_2(&udp->check, old_port, new_port);
	}
}

/*
 * IPv4 NAT rewrite.
 */
static __always_inline void
nat_rewrite_v4(void *data, void *data_end, struct pkt_meta *meta)
{
	/* Bound offsets for verifier (real values: l3=14/18, l4=34/38) */
	if (meta->l3_offset >= 64 || meta->l4_offset >= 128)
		return;

	struct iphdr *iph = data + meta->l3_offset;
	if ((void *)(iph + 1) > data_end)
		return;

	/* Compute l4 pointer once -- all helpers share this */
	void *l4 = data + meta->l4_offset;

	/* Source IP rewrite */
	if (meta->src_ip.v4 != iph->saddr) {
		__be32 old_src = iph->saddr;
		csum_update_4(&iph->check, old_src, meta->src_ip.v4);
		nat_update_l4_csum(l4, data_end, meta, old_src, meta->src_ip.v4);
		iph->saddr = meta->src_ip.v4;
	}

	/* Source port rewrite */
	if (meta->src_port != 0) {
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->source != meta->src_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							tcp->source, meta->src_port);
				tcp->source = meta->src_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->source != meta->src_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							udp->source, meta->src_port);
				udp->source = meta->src_port;
			}
		}
	}

	/* Destination IP rewrite */
	if (meta->dst_ip.v4 != iph->daddr) {
		__be32 old_dst = iph->daddr;
		csum_update_4(&iph->check, old_dst, meta->dst_ip.v4);
		nat_update_l4_csum(l4, data_end, meta, old_dst, meta->dst_ip.v4);
		iph->daddr = meta->dst_ip.v4;
	}

	/* Destination port rewrite */
	if (meta->dst_port != 0) {
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->dest != meta->dst_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							tcp->dest, meta->dst_port);
				tcp->dest = meta->dst_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->dest != meta->dst_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							udp->dest, meta->dst_port);
				udp->dest = meta->dst_port;
			}
		}
	}

	/* ICMP echo ID rewrite */
	if (meta->protocol == PROTO_ICMP) {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) <= data_end &&
		    (icmp->type == 8 || icmp->type == 0)) {
			/* Forward: use allocated port as new echo ID.
			 * Return (DNAT): dst_port holds the original echo ID. */
			__be16 desired_id = meta->src_port;
			if (meta->nat_flags & SESS_FLAG_DNAT)
				desired_id = meta->dst_port;
			if (icmp->un.echo.id != desired_id) {
				csum_update_2(&icmp->checksum,
					      icmp->un.echo.id, desired_id);
				icmp->un.echo.id = desired_id;
			}
		}
	}
}

/*
 * IPv6 NAT rewrite.
 * IPv6 has no IP header checksum. Only L4 checksums need updating.
 */
static __always_inline void
nat_rewrite_v6(void *data, void *data_end, struct pkt_meta *meta)
{
	/* Bound offsets for verifier (real values: l3=14/18, l4=54/58) */
	if (meta->l3_offset >= 64 || meta->l4_offset >= 128)
		return;

	struct ipv6hdr *ip6h = data + meta->l3_offset;
	if ((void *)(ip6h + 1) > data_end)
		return;

	/* Compute l4 pointer once -- all helpers share this */
	void *l4 = data + meta->l4_offset;

	/* Source IP rewrite */
	if (!ip_addr_eq_v6(meta->src_ip.v6, (__u8 *)&ip6h->saddr)) {
		__u8 old_src[16];
		__builtin_memcpy(old_src, &ip6h->saddr, 16);
		nat_update_l4_csum_v6(l4, data_end, meta, old_src, meta->src_ip.v6);
		__builtin_memcpy(&ip6h->saddr, meta->src_ip.v6, 16);
	}

	/* Source port rewrite */
	if (meta->src_port != 0) {
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->source != meta->src_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							tcp->source, meta->src_port);
				tcp->source = meta->src_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->source != meta->src_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							udp->source, meta->src_port);
				udp->source = meta->src_port;
			}
		}
	}

	/* Destination IP rewrite */
	if (!ip_addr_eq_v6(meta->dst_ip.v6, (__u8 *)&ip6h->daddr)) {
		__u8 old_dst[16];
		__builtin_memcpy(old_dst, &ip6h->daddr, 16);
		nat_update_l4_csum_v6(l4, data_end, meta, old_dst, meta->dst_ip.v6);
		__builtin_memcpy(&ip6h->daddr, meta->dst_ip.v6, 16);
	}

	/* Destination port rewrite */
	if (meta->dst_port != 0) {
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->dest != meta->dst_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							tcp->dest, meta->dst_port);
				tcp->dest = meta->dst_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->dest != meta->dst_port) {
				nat_update_l4_port_csum(l4, data_end, meta,
							udp->dest, meta->dst_port);
				udp->dest = meta->dst_port;
			}
		}
	}

	/* ICMPv6 echo ID rewrite */
	if (meta->protocol == PROTO_ICMPV6) {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) <= data_end &&
		    (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129)) {
			__be16 desired_id = meta->src_port;
			if (meta->nat_flags & SESS_FLAG_DNAT)
				desired_id = meta->dst_port;
			if (icmp6->un.echo.id != desired_id) {
				csum_update_2(&icmp6->icmp6_cksum,
					      icmp6->un.echo.id, desired_id);
				icmp6->un.echo.id = desired_id;
			}
		}
	}
}

#endif /* __BPFRX_NAT_H__ */
