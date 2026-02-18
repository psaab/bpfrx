#ifndef __BPFRX_NAT_H__
#define __BPFRX_NAT_H__

#include "bpfrx_common.h"
#include "bpfrx_helpers.h"
#include "bpfrx_trace.h"

/*
 * Shared NAT rewrite helpers.
 * Used by both XDP (xdp_nat.c) and TC (tc_nat.c) pipelines.
 * All functions are context-agnostic -- they operate on
 * void *data / void *data_end / struct pkt_meta * only.
 */

/*
 * Update L4 (TCP/UDP) checksum for a 4-byte pseudo-header field change.
 * For CHECKSUM_PARTIAL packets, uses the non-complemented seed update.
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
		if (meta->csum_partial)
			csum_update_partial_4(&tcp->check, old_ip, new_ip);
		else
			csum_update_4(&tcp->check, old_ip, new_ip);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		if (udp->check != 0) {
			if (meta->csum_partial)
				csum_update_partial_4(&udp->check, old_ip, new_ip);
			else
				csum_update_4(&udp->check, old_ip, new_ip);
		}
	}
}

/*
 * Update L4 checksum for a 128-bit IPv6 address change.
 * For CHECKSUM_PARTIAL packets, uses the non-complemented seed update.
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
		if (meta->csum_partial)
			csum_update_partial_16(&tcp->check, old_addr, new_addr);
		else
			csum_update_16(&tcp->check, old_addr, new_addr);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		/* IPv6 UDP checksum is mandatory -- always update */
		if (meta->csum_partial)
			csum_update_partial_16(&udp->check, old_addr, new_addr);
		else
			csum_update_16(&udp->check, old_addr, new_addr);
	} else if (meta->protocol == PROTO_ICMPV6) {
		/* ICMPv6 checksum covers pseudo-header with addresses */
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) > data_end)
			return;
		if (meta->csum_partial)
			csum_update_partial_16(&icmp6->icmp6_cksum, old_addr, new_addr);
		else
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

	/* Trace actual packet state before rewrite */
#if BPFRX_TRACE
	if (TRACE_FILTER(meta->protocol)) {
		struct tcphdr *_t = l4;
		if (meta->protocol == PROTO_TCP && (void *)(_t + 1) <= data_end)
			bpf_printk("TRACE nat_rw: pkt src=%x:%d dst=%x:%d tcp_csum=0x%04x",
				   iph->saddr, bpf_ntohs(_t->source),
				   iph->daddr, bpf_ntohs(_t->dest),
				   (__u16)_t->check);
	}
#endif

	/* Source IP rewrite */
	if (meta->src_ip.v4 != iph->saddr) {
		__be32 old_src = iph->saddr;
		csum_update_4(&iph->check, old_src, meta->src_ip.v4);
		nat_update_l4_csum(l4, data_end, meta, old_src, meta->src_ip.v4);
		iph->saddr = meta->src_ip.v4;
	}

	/* Source port rewrite.
	 * For CHECKSUM_PARTIAL, skip the L4 checksum update -- the port
	 * is in the data that the NIC/skb_checksum_help will sum. */
	if (meta->src_port != 0) {
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->source != meta->src_port) {
				if (!meta->csum_partial)
					nat_update_l4_port_csum(l4, data_end, meta,
								tcp->source, meta->src_port);
				tcp->source = meta->src_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->source != meta->src_port) {
				if (!meta->csum_partial)
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
				if (!meta->csum_partial)
					nat_update_l4_port_csum(l4, data_end, meta,
								tcp->dest, meta->dst_port);
				tcp->dest = meta->dst_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->dest != meta->dst_port) {
				if (!meta->csum_partial)
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
 * Rewrite the embedded original packet inside an ICMP error message.
 * Reverses the SNAT translation so the error reaches the original client.
 * Updates: embedded src IP, embedded src port, outer ICMP checksum.
 */
static __always_inline void
nat_rewrite_embedded_v4(void *data, void *data_end, struct pkt_meta *meta)
{
	if (meta->l4_offset >= 128)
		return;
	struct icmphdr *outer_icmp = data + meta->l4_offset;
	if ((void *)(outer_icmp + 1) > data_end)
		return;

	__u16 emb_ip_off = meta->l4_offset + 8;
	if (emb_ip_off >= 200)
		return;
	struct iphdr *emb_ip = data + emb_ip_off;
	if ((void *)(emb_ip + 1) > data_end)
		return;

	/* Rewrite embedded source IP.
	 * The outer ICMP checksum covers the entire payload including the
	 * embedded IP header.  Changing emb_ip->saddr AND emb_ip->check
	 * both modify bytes in the outer ICMP payload, so the outer
	 * checksum must account for both changes. */
	__be32 old_src = emb_ip->saddr;
	__be32 new_src = meta->nat_src_ip.v4;
	if (old_src != new_src) {
		__sum16 old_ip_check = emb_ip->check;
		emb_ip->saddr = new_src;
		csum_update_4(&emb_ip->check, old_src, new_src);
		csum_update_4(&outer_icmp->checksum, old_src, new_src);
		csum_update_2(&outer_icmp->checksum,
			      old_ip_check, emb_ip->check);
	}

	/* Rewrite embedded L4 source port */
	__u8 emb_ihl = emb_ip->ihl;
	if (emb_ihl < 5 || emb_ihl > 15)
		return;
	__u16 emb_l4_off = emb_ip_off + ((__u16)emb_ihl) * 4;
	if (emb_l4_off >= 250)
		return;

	__u8 emb_proto = meta->embedded_proto;
	if (emb_proto == PROTO_TCP || emb_proto == PROTO_UDP) {
		__be16 *ports = data + emb_l4_off;
		if ((void *)(ports + 2) > data_end)
			return;
		__be16 old_port = ports[0];
		__be16 new_port = meta->nat_src_port;
		if (old_port != new_port) {
			ports[0] = new_port;
			csum_update_2(&outer_icmp->checksum,
				      old_port, new_port);
		}
	} else if (emb_proto == PROTO_ICMP) {
		struct icmphdr *emb_icmp = data + emb_l4_off;
		if ((void *)(emb_icmp + 1) > data_end)
			return;
		__be16 old_id = emb_icmp->un.echo.id;
		__be16 new_id = meta->nat_src_port;
		if (old_id != new_id) {
			__sum16 old_icmp_check = emb_icmp->checksum;
			emb_icmp->un.echo.id = new_id;
			csum_update_2(&emb_icmp->checksum,
				      old_id, new_id);
			csum_update_2(&outer_icmp->checksum,
				      old_id, new_id);
			csum_update_2(&outer_icmp->checksum,
				      old_icmp_check,
				      emb_icmp->checksum);
		}
	}
}

/*
 * Rewrite the embedded original packet inside an ICMPv6 error message.
 * Reverses the SNAT translation so the error reaches the original client.
 * IPv6 has no IP header checksum, simplifying the rewrite vs v4.
 * Updates: embedded src address (16 bytes), embedded L4 port,
 * outer ICMPv6 checksum (covers pseudo-header + full payload).
 */
static __always_inline void
nat_rewrite_embedded_v6(void *data, void *data_end, struct pkt_meta *meta)
{
	if (meta->l4_offset >= 128)
		return;
	struct icmp6hdr *outer_icmp6 = data + meta->l4_offset;
	if ((void *)(outer_icmp6 + 1) > data_end)
		return;

	/* Embedded IPv6 header starts after 8-byte ICMPv6 error header */
	__u16 emb_ip_off = meta->l4_offset + 8;
	if (emb_ip_off >= 200)
		return;
	struct ipv6hdr *emb_ip6 = data + emb_ip_off;
	if ((void *)(emb_ip6 + 1) > data_end)
		return;

	/* Rewrite embedded source address (16 bytes).
	 * The outer ICMPv6 checksum covers the entire payload including
	 * the embedded IPv6 header, so changing emb_ip6->saddr requires
	 * updating the outer checksum. No IP header checksum in IPv6. */
	__u8 old_src[16];
	__builtin_memcpy(old_src, &emb_ip6->saddr, 16);
	if (!ip_addr_eq_v6(old_src, meta->nat_src_ip.v6)) {
		__builtin_memcpy(&emb_ip6->saddr, meta->nat_src_ip.v6, 16);
		csum_update_16(&outer_icmp6->icmp6_cksum,
			       old_src, meta->nat_src_ip.v6);
	}

	/* Rewrite embedded L4 source port.
	 * Use constant offset from emb_ip6 (already validated) to
	 * avoid variable-offset pkt pointer issues with the verifier.
	 * Skip extension headers — they are extremely rare in
	 * embedded ICMPv6 error packets. */
	__u8 emb_proto = meta->embedded_proto;
	if (emb_proto != PROTO_TCP && emb_proto != PROTO_UDP &&
	    emb_proto != PROTO_ICMPV6)
		return;

	void *emb_l4 = (void *)(emb_ip6 + 1);

	if (emb_proto == PROTO_TCP || emb_proto == PROTO_UDP) {
		__be16 *ports = emb_l4;
		if ((void *)(ports + 2) > data_end)
			return;
		__be16 old_port = ports[0];
		__be16 new_port = meta->nat_src_port;
		if (old_port != new_port) {
			ports[0] = new_port;
			csum_update_2(&outer_icmp6->icmp6_cksum,
				      old_port, new_port);
		}
	} else if (emb_proto == PROTO_ICMPV6) {
		/* Embedded ICMPv6 echo: rewrite echo ID */
		struct icmp6hdr *emb_icmp6 = emb_l4;
		if ((void *)(emb_icmp6 + 1) > data_end)
			return;
		__be16 old_id = emb_icmp6->un.echo.id;
		__be16 new_id = meta->nat_src_port;
		if (old_id != new_id) {
			__sum16 old_icmp6_check = emb_icmp6->icmp6_cksum;
			emb_icmp6->un.echo.id = new_id;
			csum_update_2(&emb_icmp6->icmp6_cksum,
				      old_id, new_id);
			/* Outer ICMPv6 checksum covers embedded bytes:
			 * account for both the echo ID change and the
			 * embedded checksum field change. */
			csum_update_2(&outer_icmp6->icmp6_cksum,
				      old_id, new_id);
			csum_update_2(&outer_icmp6->icmp6_cksum,
				      old_icmp6_check,
				      emb_icmp6->icmp6_cksum);
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

	/* Source port rewrite.
	 * For CHECKSUM_PARTIAL, skip the L4 checksum update. */
	if (meta->src_port != 0) {
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->source != meta->src_port) {
				if (!meta->csum_partial)
					nat_update_l4_port_csum(l4, data_end, meta,
								tcp->source, meta->src_port);
				tcp->source = meta->src_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->source != meta->src_port) {
				if (!meta->csum_partial)
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
				if (!meta->csum_partial)
					nat_update_l4_port_csum(l4, data_end, meta,
								tcp->dest, meta->dst_port);
				tcp->dest = meta->dst_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->dest != meta->dst_port) {
				if (!meta->csum_partial)
					nat_update_l4_port_csum(l4, data_end, meta,
								udp->dest, meta->dst_port);
				udp->dest = meta->dst_port;
			}
		}
	}

	/* ICMPv6 echo ID rewrite.
	 * ICMPv6 checksum covers a pseudo-header, so CHECKSUM_PARTIAL
	 * applies -- skip ID checksum update when partial. */
	if (meta->protocol == PROTO_ICMPV6) {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) <= data_end &&
		    (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129)) {
			__be16 desired_id = meta->src_port;
			if (meta->nat_flags & SESS_FLAG_DNAT)
				desired_id = meta->dst_port;
			if (icmp6->un.echo.id != desired_id) {
				if (!meta->csum_partial)
					csum_update_2(&icmp6->icmp6_cksum,
						      icmp6->un.echo.id,
						      desired_id);
				icmp6->un.echo.id = desired_id;
			}
		}
	}
}

/*
 * NPTv6 (RFC 6296) stateless prefix translation.
 *
 * Supports /48 (rewrite words 0-2, adjust word 3) and /64 (rewrite
 * words 0-3, adjust word 4).  No L4 checksum update needed.
 *
 * Parameters:
 *   addr      - pointer to the 16-byte IPv6 address to rewrite in-place
 *   nv        - nptv6_value with xlat_prefix, adjustment, and prefix_words
 *   direction - NPTV6_INBOUND (add ~adjustment) or NPTV6_OUTBOUND (add adjustment)
 */
static __always_inline void
nptv6_translate(void *addr, const struct nptv6_value *nv, __u8 direction)
{
	__u16 *w = (__u16 *)addr;
	const __u16 *pfx = (const __u16 *)nv->xlat_prefix;

	/* Rewrite prefix words (always at least 3) */
	w[0] = pfx[0];
	w[1] = pfx[1];
	w[2] = pfx[2];

	__u16 adj = nv->adjustment;
	if (direction == NPTV6_INBOUND)
		adj = ~adj;

	if (nv->prefix_words >= 4) {
		/* /64: rewrite word[3], adjust word[4] */
		w[3] = pfx[3];

		__u32 sum = (__u32)w[4] + (__u32)adj;
		sum = (sum & 0xFFFF) + (sum >> 16);
		sum = (sum & 0xFFFF) + (sum >> 16);
		w[4] = (__u16)sum;
		if (w[4] == 0xFFFF)
			w[4] = 0x0000;
	} else {
		/* /48: adjust word[3] */
		__u32 sum = (__u32)w[3] + (__u32)adj;
		sum = (sum & 0xFFFF) + (sum >> 16);
		sum = (sum & 0xFFFF) + (sum >> 16);
		w[3] = (__u16)sum;
		if (w[3] == 0xFFFF)
			w[3] = 0x0000;
	}
}

#endif /* __BPFRX_NAT_H__ */
