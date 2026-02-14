#ifndef __BPFRX_HELPERS_H__
#define __BPFRX_HELPERS_H__

#include "bpfrx_common.h"

/* ============================================================
 * Packet parsing helpers
 * ============================================================ */

/* VLAN header for 802.1Q */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/*
 * Parse Ethernet header, handling one level of VLAN tagging.
 * Returns the EtherType of the inner protocol and updates l3_offset.
 * If vlan_id is non-NULL, writes the extracted VLAN ID (0 if untagged).
 */
static __always_inline int
parse_ethhdr(void *data, void *data_end, __u16 *l3_offset, __u16 *eth_proto,
	     __u16 *vlan_id)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	*eth_proto = bpf_ntohs(eth->h_proto);
	*l3_offset = sizeof(struct ethhdr);
	if (vlan_id)
		*vlan_id = 0;

	/* Handle one level of VLAN */
	if (*eth_proto == ETH_P_8021Q || *eth_proto == ETH_P_8021AD) {
		struct vlan_hdr *vlan = data + sizeof(struct ethhdr);
		if ((void *)(vlan + 1) > data_end)
			return -1;
		if (vlan_id)
			*vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
		*eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		*l3_offset += sizeof(struct vlan_hdr);
	}

	return 0;
}

/*
 * Strip 802.1Q VLAN tag from an XDP packet by shifting the Ethernet
 * header 4 bytes forward and shrinking the head.
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int
xdp_vlan_tag_pop(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Save the original Ethernet src/dst MAC and copy them after the shift */
	__u8 dmac[ETH_ALEN];
	__u8 smac[ETH_ALEN];
	__builtin_memcpy(dmac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(smac, eth->h_source, ETH_ALEN);

	/* Move head forward by 4 bytes (VLAN header size) */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)))
		return -1;

	/* Re-read pointers after adjust */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Restore MACs -- the inner EtherType is already in place
	 * because we shifted past the VLAN header. But the MACs were
	 * in the old position, so copy them into the new eth header. */
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);

	return 0;
}

/*
 * Push an 802.1Q VLAN tag onto an XDP packet by growing the head
 * by 4 bytes and inserting the VLAN header.
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int
xdp_vlan_tag_push(struct xdp_md *ctx, __u16 vid)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Save MACs and inner EtherType to stack before adjust_head,
	 * avoiding overlapping memcpy after the head grows by 4 bytes. */
	__u8 dmac[ETH_ALEN];
	__u8 smac[ETH_ALEN];
	__builtin_memcpy(dmac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(smac, eth->h_source, ETH_ALEN);
	__be16 inner_proto = eth->h_proto;

	/* Grow head by 4 bytes */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
		return -1;

	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Restore MACs from stack (no overlap) */
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_8021Q);

	/* Write VLAN header between Ethernet and inner EtherType */
	struct vlan_hdr *vhdr = data + sizeof(struct ethhdr);
	if ((void *)(vhdr + 1) > data_end)
		return -1;

	vhdr->h_vlan_TCI = bpf_htons(vid);
	vhdr->h_vlan_encapsulated_proto = inner_proto;

	return 0;
}

/*
 * Parse IPv4 header. Validates version and IHL.
 * Returns 0 on success, populates meta fields.
 */
static __always_inline int
parse_iphdr(void *data, void *data_end, struct pkt_meta *meta)
{
	struct iphdr *iph = data + meta->l3_offset;

	if ((void *)(iph + 1) > data_end)
		return -1;

	if (iph->version != 4)
		return -1;

	__u32 ihl = iph->ihl * 4;
	if (ihl < 20)
		return -1;
	if ((void *)iph + ihl > data_end)
		return -1;

	meta->src_ip.v4 = iph->saddr;
	meta->dst_ip.v4 = iph->daddr;
	meta->protocol  = iph->protocol;
	meta->ip_ttl    = iph->ttl;
	meta->dscp      = iph->tos >> 2;  /* top 6 bits of TOS = DSCP */
	meta->l4_offset = meta->l3_offset + ihl;
	meta->pkt_len   = bpf_ntohs(iph->tot_len);
	meta->addr_family = AF_INET;

	/* Fragmentation check */
	__u16 frag_off = bpf_ntohs(iph->frag_off);
	meta->is_fragment = (frag_off & 0x2000) || (frag_off & 0x1FFF);

	return 0;
}

/*
 * Parse IPv6 header with extension header chain walking.
 * Returns 0 on success, populates meta fields.
 */
static __always_inline int
parse_ipv6hdr(void *data, void *data_end, struct pkt_meta *meta)
{
	struct ipv6hdr *ip6h = data + meta->l3_offset;

	if ((void *)(ip6h + 1) > data_end)
		return -1;

	if (ip6h->version != 6)
		return -1;

	/* Copy 128-bit addresses */
	__builtin_memcpy(meta->src_ip.v6, &ip6h->saddr, 16);
	__builtin_memcpy(meta->dst_ip.v6, &ip6h->daddr, 16);

	meta->ip_ttl      = ip6h->hop_limit;
	meta->dscp        = (ip6h->priority << 2) | (ip6h->flow_lbl[0] >> 6);
	meta->pkt_len     = bpf_ntohs(ip6h->payload_len) + 40;
	meta->addr_family = AF_INET6;
	meta->is_fragment = 0;

	/* Walk extension header chain to find the upper-layer protocol */
	__u8 nexthdr = ip6h->nexthdr;
	__u16 offset = meta->l3_offset + sizeof(struct ipv6hdr);

	#pragma unroll
	for (int i = 0; i < MAX_EXT_HDRS; i++) {
		switch (nexthdr) {
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST: {
			struct ipv6_opt_hdr *opt = data + offset;
			if ((void *)(opt + 1) > data_end)
				return -1;
			nexthdr = opt->nexthdr;
			offset += (opt->hdrlen + 1) * 8;
			break;
		}
		case NEXTHDR_AUTH: {
			struct ipv6_opt_hdr *opt = data + offset;
			if ((void *)(opt + 1) > data_end)
				return -1;
			nexthdr = opt->nexthdr;
			offset += (opt->hdrlen + 2) * 4;
			break;
		}
		case NEXTHDR_FRAGMENT: {
			struct frag_hdr *frag = data + offset;
			if ((void *)(frag + 1) > data_end)
				return -1;
			nexthdr = frag->nexthdr;
			offset += sizeof(struct frag_hdr);
			/* Check MF bit or fragment offset */
			__u16 frag_off = bpf_ntohs(frag->frag_off);
			if ((frag_off & 0x1) || (frag_off & 0xFFF8))
				meta->is_fragment = 1;
			break;
		}
		case NEXTHDR_NONE:
			/* No next header */
			meta->protocol = nexthdr;
			meta->l4_offset = offset;
			return 0;
		default:
			/* Upper-layer protocol found */
			goto done;
		}
	}

done:
	meta->protocol  = nexthdr;
	meta->l4_offset = offset;
	return 0;
}

/* ============================================================
 * CHECKSUM_PARTIAL handling for XDP + TC paths.
 *
 * Virtio NICs deliver TCP/UDP packets with CHECKSUM_PARTIAL: the
 * L4 checksum field contains fold(PH) — a non-complemented
 * pseudo-header checksum seed.  The NIC (or skb_checksum_help)
 * finalizes by summing the actual L4 data bytes.
 *
 * Detection: parse_l4hdr computes the pseudo-header checksum from
 * the IP header and compares it with the L4 checksum field.
 * A match means the checksum field is only a pseudo-header seed.
 *
 * Generic XDP path: XDP_REDIRECT goes through dev_queue_xmit ->
 * validate_xmit_skb which DOES finalize the checksum.  We must
 * skip incremental updates for non-pseudo-header fields (ports,
 * MSS options) to keep the PH seed intact for kernel finalization.
 * IP address updates still apply since they change pseudo-header
 * fields, but must use csum_update_partial_4 (not csum_update_4)
 * because the seed is non-complemented: PH' = fold(PH + ~old + new).
 *
 * Native XDP path: XDP_REDIRECT uses __dev_direct_xmit which
 * bypasses finalization.  For native XDP, finalize_csum_partial()
 * must be called to compute the full checksum before nat_rewrite.
 *
 * TC path: Like generic XDP, the kernel finalizes after TC.
 * The same skip logic applies.
 * ============================================================ */

/*
 * Compute IPv4 pseudo-header checksum (folded to 16 bits, native byte order).
 * Uses the byte-order independence property of the internet checksum.
 */
static __always_inline __u16
compute_ph_csum_v4(__be32 saddr, __be32 daddr, __u8 protocol, __u16 l4_len)
{
	__u32 sum = 0;
	sum += ((__u32)saddr & 0xFFFF) + ((__u32)saddr >> 16);
	sum += ((__u32)daddr & 0xFFFF) + ((__u32)daddr >> 16);
	sum += (__u32)bpf_htons((__u16)protocol);
	sum += (__u32)bpf_htons(l4_len);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	/* Kernel CHECKSUM_PARTIAL stores fold(PH) in the L4 checksum
	 * field (see __tcp_v4_send_check: th->check = ~csum_fold(PH),
	 * and csum_fold returns ~fold, so th->check = fold(PH)). */
	return (__u16)sum;
}

/*
 * Compute IPv6 pseudo-header checksum (folded to 16 bits, native byte order).
 * IPv6 pseudo-header: src(128) + dst(128) + length(32) + next-hdr(32).
 */
static __always_inline __u16
compute_ph_csum_v6(const __u8 *saddr, const __u8 *daddr,
		   __u8 protocol, __u16 l4_len)
{
	__u32 sum = 0;
	const __u16 *s = (const __u16 *)saddr;
	const __u16 *d = (const __u16 *)daddr;
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		sum += (__u32)s[i];
		sum += (__u32)d[i];
	}
	sum += (__u32)bpf_htons((__u16)protocol);
	sum += (__u32)bpf_htons(l4_len);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return (__u16)sum;
}

/*
 * Finalize a CHECKSUM_PARTIAL packet's L4 checksum for XDP path.
 *
 * For native XDP, XDP_REDIRECT bypasses the kernel's TX path
 * (validate_xmit_skb / skb_checksum_help), so CHECKSUM_PARTIAL
 * packets would go out with only the pseudo-header seed in the
 * L4 checksum field.  This function computes the full checksum
 * from raw packet data, equivalent to skb_checksum_help().
 *
 * The L4 checksum field already contains the pseudo-header seed.
 * Summing all L4 bytes (which includes this seed) and folding
 * gives the correct final checksum -- same as skb_checksum_help.
 *
 * Must be called BEFORE any incremental checksum updates (NAT,
 * MSS clamping) in the XDP pipeline.  After this, csum_partial
 * is set to 0 and normal incremental updates can proceed.
 *
 * Do NOT call from TC programs -- the kernel handles finalization.
 */
static __always_inline void
finalize_csum_partial(void *data, void *data_end, struct pkt_meta *meta)
{
	if (!meta->csum_partial)
		return;

	if (meta->l4_offset >= 128)
		return;

	void *l4 = data + meta->l4_offset;
	if (l4 + 20 > data_end)
		return;

	/*
	 * Sum all L4 data as 16-bit words.  The checksum field
	 * contains the pseudo-header seed, which participates in
	 * the sum correctly (same as skb_checksum_help).
	 *
	 * Bounded loop with per-iteration packet check satisfies
	 * the BPF verifier.  Max 750 iterations for 1500-byte MTU.
	 */
	__u32 sum = 0;
	__u16 *p = (__u16 *)l4;

	#pragma unroll 1
	for (int i = 0; i < 750; i++) {
		if ((void *)(p + 1) > data_end)
			break;
		sum += *p;
		p++;
	}

	/* Handle trailing odd byte */
	__u8 *bp = (__u8 *)p;
	if ((void *)(bp + 1) <= data_end)
		sum += (__u32)*bp;

	/* Fold to 16 bits and complement */
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	__sum16 final_csum = (__sum16)(~sum & 0xFFFF);

	/* Write the finalized checksum back to the packet */
	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) <= data_end)
			tcp->check = final_csum;
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) <= data_end)
			udp->check = final_csum;
	} else if (meta->protocol == PROTO_ICMPV6) {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) <= data_end)
			icmp6->icmp6_cksum = final_csum;
	}

	meta->csum_partial = 0;
}

/*
 * Parse L4 header (TCP, UDP, ICMP, or ICMPv6).
 * Returns 0 on success.
 */
static __always_inline int
parse_l4hdr(void *data, void *data_end, struct pkt_meta *meta)
{
	void *l4 = data + meta->l4_offset;
	__sum16 l4_csum = 0;

	switch (meta->protocol) {
	case PROTO_TCP: {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		meta->src_port = tcp->source;
		meta->dst_port = tcp->dest;
		meta->tcp_flags = ((__u8 *)tcp)[13];
		meta->tcp_seq = tcp->seq;
		meta->tcp_ack_seq = tcp->ack_seq;
		meta->payload_offset = meta->l4_offset + tcp->doff * 4;
		l4_csum = tcp->check;
		break;
	}
	case PROTO_UDP: {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return -1;
		meta->src_port = udp->source;
		meta->dst_port = udp->dest;
		meta->payload_offset = meta->l4_offset + sizeof(struct udphdr);
		l4_csum = udp->check;
		break;
	}
	case PROTO_ICMP: {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) > data_end)
			return -1;
		meta->icmp_type = icmp->type;
		meta->icmp_code = icmp->code;
		meta->icmp_id   = icmp->un.echo.id;
		meta->src_port  = icmp->un.echo.id; /* use as port for CT */
		/* For echo req/reply, set dst_port = echo_id so pre-routing
		 * DNAT lookup works for return traffic */
		meta->dst_port  = (icmp->type == 8 || icmp->type == 0) ?
				  icmp->un.echo.id : 0;
		meta->payload_offset = meta->l4_offset + sizeof(struct icmphdr);
		/* ICMP has no pseudo-header -- l4_csum stays 0 */
		break;
	}
	case PROTO_ICMPV6: {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) > data_end)
			return -1;
		meta->icmp_type = icmp6->icmp6_type;
		meta->icmp_code = icmp6->icmp6_code;
		meta->icmp_id   = icmp6->un.echo.id;
		meta->src_port  = icmp6->un.echo.id; /* use as port for CT */
		/* For echo req/reply, set dst_port = echo_id */
		meta->dst_port  = (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129) ?
				  icmp6->un.echo.id : 0;
		meta->payload_offset = meta->l4_offset + sizeof(struct icmp6hdr);
		l4_csum = icmp6->icmp6_cksum;
		break;
	}
	case PROTO_ESP: {
		/* ESP header: 4-byte SPI + 4-byte sequence number */
		struct {
			__be32 spi;
			__be32 seq;
		} *esp = l4;
		if ((void *)(esp + 1) > data_end)
			return -1;
		/* Split 32-bit SPI into two 16-bit halves for session tracking.
		 * Combined src_port+dst_port reconstructs the full SPI. */
		meta->src_port = (__be16)(esp->spi >> 16);
		meta->dst_port = (__be16)(esp->spi & 0xFFFF);
		meta->payload_offset = meta->l4_offset + 8;
		/* No L4 checksum for ESP (auth covers entire payload) */
		break;
	}
	default:
		meta->payload_offset = meta->l4_offset;
		break;
	}

	/*
	 * Detect CHECKSUM_PARTIAL: if the L4 checksum field equals the
	 * pseudo-header checksum, the packet uses hardware checksum
	 * offload and we must NOT do incremental updates for non-
	 * pseudo-header fields (ports, TCP options) -- the NIC or
	 * skb_checksum_help will sum the actual data bytes later.
	 */
	meta->csum_partial = 0;
	if (l4_csum != 0) {
		__u16 l4_len = meta->pkt_len -
			       (meta->l4_offset - meta->l3_offset);
		__u16 ph;
		if (meta->addr_family == AF_INET)
			ph = compute_ph_csum_v4(meta->src_ip.v4,
						meta->dst_ip.v4,
						meta->protocol, l4_len);
		else
			ph = compute_ph_csum_v6(meta->src_ip.v6,
						meta->dst_ip.v6,
						meta->protocol, l4_len);
		if ((__u16)l4_csum == ph)
			meta->csum_partial = 1;
	}

	return 0;
}

/* ============================================================
 * Checksum helpers
 * ============================================================ */

/*
 * Incremental checksum update (RFC 1624) for a 4-byte field change.
 * For standard (complemented) checksums where field = ~fold(sum).
 */
static __always_inline void
csum_update_4(__sum16 *csum, __be32 old_val, __be32 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~bpf_ntohl(old_val) & 0xFFFF;
	sum += ~(bpf_ntohl(old_val) >> 16) & 0xFFFF;
	sum += bpf_ntohl(new_val) & 0xFFFF;
	sum += (bpf_ntohl(new_val) >> 16) & 0xFFFF;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/*
 * Incremental pseudo-header seed update for CHECKSUM_PARTIAL packets.
 *
 * CHECKSUM_PARTIAL L4 field contains fold(PH) — a non-complemented
 * pseudo-header checksum.  The standard RFC 1624 formula (csum_update_4)
 * complements input and output, which is wrong for this representation.
 * Correct formula: PH' = fold(PH + ~old + new).
 */
static __always_inline void
csum_update_partial_4(__sum16 *csum, __be32 old_val, __be32 new_val)
{
	__u32 sum;

	sum = ((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~bpf_ntohl(old_val) & 0xFFFF;
	sum += ~(bpf_ntohl(old_val) >> 16) & 0xFFFF;
	sum += bpf_ntohl(new_val) & 0xFFFF;
	sum += (bpf_ntohl(new_val) >> 16) & 0xFFFF;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(sum & 0xFFFF);
}

/*
 * Incremental checksum update for a 2-byte field change.
 */
static __always_inline void
csum_update_2(__sum16 *csum, __be16 old_val, __be16 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~((__u32)bpf_ntohs(old_val)) & 0xFFFF;
	sum += (__u32)bpf_ntohs(new_val);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/*
 * Incremental checksum update for a 128-bit (IPv6) address change.
 * Processes the address as four 32-bit words.
 */
static __always_inline void
csum_update_16(__sum16 *csum, const __u8 *old_addr, const __u8 *new_addr)
{
	/* Process as four 32-bit words */
	#pragma unroll
	for (int i = 0; i < 4; i++) {
		__be32 old_word, new_word;
		__builtin_memcpy(&old_word, old_addr + i * 4, 4);
		__builtin_memcpy(&new_word, new_addr + i * 4, 4);
		if (old_word != new_word)
			csum_update_4(csum, old_word, new_word);
	}
}

/*
 * Incremental pseudo-header seed update for a 128-bit (IPv6) address
 * change on CHECKSUM_PARTIAL packets.
 */
static __always_inline void
csum_update_partial_16(__sum16 *csum, const __u8 *old_addr,
		       const __u8 *new_addr)
{
	#pragma unroll
	for (int i = 0; i < 4; i++) {
		__be32 old_word, new_word;
		__builtin_memcpy(&old_word, old_addr + i * 4, 4);
		__builtin_memcpy(&new_word, new_addr + i * 4, 4);
		if (old_word != new_word)
			csum_update_partial_4(csum, old_word, new_word);
	}
}

/* ============================================================
 * IPv6 address comparison helper
 * ============================================================ */

static __always_inline int
ip_addr_eq_v6(const __u8 *a, const __u8 *b)
{
	const __u32 *a32 = (const __u32 *)a;
	const __u32 *b32 = (const __u32 *)b;
	return (a32[0] == b32[0]) && (a32[1] == b32[1]) &&
	       (a32[2] == b32[2]) && (a32[3] == b32[3]);
}

/* ============================================================
 * Configurable session timeout lookup (falls back to defaults)
 * ============================================================ */

static __always_inline __u32
ct_get_timeout(__u8 protocol, __u8 state)
{
	__u32 idx;
	switch (protocol) {
	case PROTO_TCP:
		switch (state) {
		case SESS_STATE_ESTABLISHED:
			idx = FLOW_TIMEOUT_TCP_ESTABLISHED;
			break;
		case SESS_STATE_FIN_WAIT:
		case SESS_STATE_CLOSE_WAIT:
			idx = FLOW_TIMEOUT_TCP_CLOSING;
			break;
		case SESS_STATE_TIME_WAIT:
			idx = FLOW_TIMEOUT_TCP_TIME_WAIT;
			break;
		default:
			idx = FLOW_TIMEOUT_TCP_INITIAL;
			break;
		}
		break;
	case PROTO_UDP:
		idx = FLOW_TIMEOUT_UDP;
		break;
	case PROTO_ICMP:
	case PROTO_ICMPV6:
		idx = FLOW_TIMEOUT_ICMP;
		break;
	default:
		idx = FLOW_TIMEOUT_OTHER;
		break;
	}
	__u32 *val = bpf_map_lookup_elem(&flow_timeouts, &idx);
	if (val && *val > 0)
		return *val;
	return ct_get_timeout_default(protocol, state);
}

/* ============================================================
 * Global counter increment helper
 * ============================================================ */

static __always_inline void
inc_counter(__u32 ctr_idx)
{
	__u64 *ctr = bpf_map_lookup_elem(&global_counters, &ctr_idx);
	if (ctr)
		__sync_fetch_and_add(ctr, 1);
}

/* Map a SCREEN_* flag bit to a per-screen-type counter index. */
static __always_inline void
inc_screen_counter(__u32 screen_flag)
{
	__u32 idx;
	switch (screen_flag) {
	case SCREEN_SYN_FLOOD:      idx = GLOBAL_CTR_SCREEN_SYN_FLOOD; break;
	case SCREEN_ICMP_FLOOD:     idx = GLOBAL_CTR_SCREEN_ICMP_FLOOD; break;
	case SCREEN_UDP_FLOOD:      idx = GLOBAL_CTR_SCREEN_UDP_FLOOD; break;
	case SCREEN_PORT_SCAN:      idx = GLOBAL_CTR_SCREEN_PORT_SCAN; break;
	case SCREEN_IP_SWEEP:       idx = GLOBAL_CTR_SCREEN_IP_SWEEP; break;
	case SCREEN_LAND_ATTACK:    idx = GLOBAL_CTR_SCREEN_LAND_ATTACK; break;
	case SCREEN_PING_OF_DEATH:  idx = GLOBAL_CTR_SCREEN_PING_OF_DEATH; break;
	case SCREEN_TEAR_DROP:      idx = GLOBAL_CTR_SCREEN_TEAR_DROP; break;
	case SCREEN_TCP_SYN_FIN:    idx = GLOBAL_CTR_SCREEN_TCP_SYN_FIN; break;
	case SCREEN_TCP_NO_FLAG:    idx = GLOBAL_CTR_SCREEN_TCP_NO_FLAG; break;
	case SCREEN_TCP_FIN_NO_ACK: idx = GLOBAL_CTR_SCREEN_TCP_FIN_NO_ACK; break;
	case SCREEN_WINNUKE:        idx = GLOBAL_CTR_SCREEN_WINNUKE; break;
	case SCREEN_IP_SOURCE_ROUTE:idx = GLOBAL_CTR_SCREEN_IP_SRC_ROUTE; break;
	case SCREEN_SYN_FRAG:       idx = GLOBAL_CTR_SCREEN_SYN_FRAG; break;
	default: return;
	}
	inc_counter(idx);
}

static __always_inline void
inc_iface_rx(__u32 ifindex, __u32 pkt_len)
{
	struct iface_counter_value *ic = bpf_map_lookup_elem(&interface_counters, &ifindex);
	if (ic) { ic->rx_packets++; ic->rx_bytes += pkt_len; }
}

static __always_inline void
inc_iface_tx(__u32 ifindex, __u32 pkt_len)
{
	struct iface_counter_value *ic = bpf_map_lookup_elem(&interface_counters, &ifindex);
	if (ic) { ic->tx_packets++; ic->tx_bytes += pkt_len; }
}

static __always_inline void
inc_zone_ingress(__u32 zone_id, __u32 pkt_len)
{
	__u32 idx = zone_id * 2;
	struct counter_value *zc = bpf_map_lookup_elem(&zone_counters, &idx);
	if (zc) { zc->packets++; zc->bytes += pkt_len; }
}

static __always_inline void
inc_zone_egress(__u32 zone_id, __u32 pkt_len)
{
	__u32 idx = zone_id * 2 + 1;
	struct counter_value *zc = bpf_map_lookup_elem(&zone_counters, &idx);
	if (zc) { zc->packets++; zc->bytes += pkt_len; }
}

static __always_inline void
inc_policy_counter(__u32 policy_id, __u32 pkt_len)
{
	struct counter_value *pc = bpf_map_lookup_elem(&policy_counters, &policy_id);
	if (pc) { pc->packets++; pc->bytes += pkt_len; }
}

/* ============================================================
 * Ring buffer event emission helper (shared by policy + screen)
 * ============================================================ */

static __always_inline void
emit_event(struct pkt_meta *meta, __u8 event_type, __u8 action,
	   __u64 packets, __u64 bytes)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();

	/* Copy IP addresses based on address family */
	__builtin_memset(evt->src_ip, 0, 16);
	__builtin_memset(evt->dst_ip, 0, 16);

	if (meta->addr_family == AF_INET) {
		__builtin_memcpy(evt->src_ip, &meta->src_ip.v4, 4);
		__builtin_memcpy(evt->dst_ip, &meta->dst_ip.v4, 4);
	} else {
		__builtin_memcpy(evt->src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(evt->dst_ip, meta->dst_ip.v6, 16);
	}

	evt->src_port = meta->src_port;
	evt->dst_port = meta->dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->addr_family = meta->addr_family;
	evt->session_packets = packets;
	evt->session_bytes = bytes;

	bpf_ringbuf_submit(evt, 0);
}

/* ============================================================
 * Host-inbound traffic flag resolution
 *
 * Maps a packet's protocol/port to the corresponding
 * HOST_INBOUND_* flag bit from bpfrx_common.h.
 * Returns 0 for unrecognized services (allowed by default).
 * ============================================================ */
static __always_inline __u32
host_inbound_flag(struct pkt_meta *meta)
{
	__u8 proto = meta->protocol;

	/* ICMP/ICMPv6 echo request → HOST_INBOUND_PING */
	if (proto == PROTO_ICMP || proto == PROTO_ICMPV6) {
		if (meta->icmp_type == 8 || meta->icmp_type == 128)
			return HOST_INBOUND_PING;
		/* IRDP: Router Advertisement (9) / Router Solicitation (10) */
		if (proto == PROTO_ICMP &&
		    (meta->icmp_type == 9 || meta->icmp_type == 10))
			return HOST_INBOUND_ROUTER_DISCOVERY;
		return 0; /* other ICMP always allowed */
	}

	/* OSPF is IP protocol 89, not port-based */
	if (proto == 89)
		return HOST_INBOUND_OSPF;

	/* ESP (protocol 50) → HOST_INBOUND_ESP */
	if (proto == PROTO_ESP)
		return HOST_INBOUND_ESP;

	/* TCP/UDP port-based services */
	__u16 port = bpf_ntohs(meta->dst_port);
	switch (port) {
	case 22:           return HOST_INBOUND_SSH;
	case 53:           return HOST_INBOUND_DNS;
	case 80:           return HOST_INBOUND_HTTP;
	case 443:          return HOST_INBOUND_HTTPS;
	case 67: case 68:  return HOST_INBOUND_DHCP;
	case 546: case 547: return HOST_INBOUND_DHCPV6;
	case 123:          return HOST_INBOUND_NTP;
	case 161:          return HOST_INBOUND_SNMP;
	case 179:          return HOST_INBOUND_BGP;
	case 23:           return HOST_INBOUND_TELNET;
	case 21:           return HOST_INBOUND_FTP;
	case 830:          return HOST_INBOUND_NETCONF;
	case 514:          return HOST_INBOUND_SYSLOG;
	case 1812: case 1813: return HOST_INBOUND_RADIUS;
	case 500:          return HOST_INBOUND_IKE;
	case 4500:         return HOST_INBOUND_IKE;   /* IKE NAT-T */
	}

	/* Traceroute: UDP ports 33434-33523 */
	if (proto == PROTO_UDP && port >= 33434 && port <= 33523)
		return HOST_INBOUND_TRACEROUTE;

	return 0; /* unknown service → allow by default */
}

/* ============================================================
 * Firewall filter evaluation
 *
 * Called from xdp_main after header parsing.
 * Evaluates the filter assigned to the ingress interface.
 * Returns:
 *   0  = no filter or "accept" — continue pipeline
 *   -1 = "discard" — drop the packet
 *   -2 = "reject" — reject the packet (currently same as discard in XDP)
 * On FILTER_ACTION_ROUTE: sets meta->routing_table and returns 0.
 * ============================================================ */
static __always_inline int
evaluate_firewall_filter(struct pkt_meta *meta)
{
	/* Look up filter ID for this interface + family */
	struct iface_filter_key fkey = {
		.ifindex = meta->ingress_ifindex,
		.vlan_id = meta->ingress_vlan_id,
		.family  = meta->addr_family,
	};
	__u32 *filter_id = bpf_map_lookup_elem(&iface_filter_map, &fkey);
	if (!filter_id)
		return 0; /* no filter assigned */

	/* Get filter config (num_rules, rule_start) */
	struct filter_config *fcfg = bpf_map_lookup_elem(&filter_configs, filter_id);
	if (!fcfg || fcfg->num_rules == 0)
		return 0;

	__u32 start = fcfg->rule_start;
	__u32 count = fcfg->num_rules;
	if (count > MAX_FILTER_RULES_PER_FILTER)
		count = MAX_FILTER_RULES_PER_FILTER;

	/* Evaluate terms sequentially (first-match wins) */
	#pragma unroll
	for (__u32 i = 0; i < MAX_FILTER_RULES_PER_FILTER; i++) {
		if (i >= count)
			break;

		__u32 idx = start + i;
		if (idx >= MAX_FILTER_RULES)
			break;

		struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &idx);
		if (!rule)
			break;

		__u16 flags = rule->match_flags;
		int match = 1;

		/* Check DSCP */
		if ((flags & FILTER_MATCH_DSCP) && rule->dscp != meta->dscp)
			match = 0;

		/* Check protocol */
		if (match && (flags & FILTER_MATCH_PROTOCOL) &&
		    rule->protocol != meta->protocol)
			match = 0;

		/* Check destination port (exact or range) */
		if (match && (flags & FILTER_MATCH_DST_PORT)) {
			if (rule->dst_port_hi) {
				__u16 p = bpf_ntohs(meta->dst_port);
				if (p < bpf_ntohs(rule->dst_port) ||
				    p > bpf_ntohs(rule->dst_port_hi))
					match = 0;
			} else if (rule->dst_port != meta->dst_port) {
				match = 0;
			}
		}

		/* Check source port (exact or range) */
		if (match && (flags & FILTER_MATCH_SRC_PORT)) {
			if (rule->src_port_hi) {
				__u16 p = bpf_ntohs(meta->src_port);
				if (p < bpf_ntohs(rule->src_port) ||
				    p > bpf_ntohs(rule->src_port_hi))
					match = 0;
			} else if (rule->src_port != meta->src_port) {
				match = 0;
			}
		}

		/* Check ICMP type */
		if (match && (flags & FILTER_MATCH_ICMP_TYPE) &&
		    rule->icmp_type != meta->icmp_type)
			match = 0;

		/* Check ICMP code */
		if (match && (flags & FILTER_MATCH_ICMP_CODE) &&
		    rule->icmp_code != meta->icmp_code)
			match = 0;

		/* Check TCP flags (all specified flags must be set) */
		if (match && (flags & FILTER_MATCH_TCP_FLAGS) &&
		    (meta->tcp_flags & rule->tcp_flags) != rule->tcp_flags)
			match = 0;

		/* Check IP fragment */
		if (match && (flags & FILTER_MATCH_FRAGMENT) &&
		    !meta->is_fragment)
			match = 0;

		/* Check source address (v4 or v6 depending on family) */
		if (match && (flags & FILTER_MATCH_SRC_ADDR)) {
			int src_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->src_ip.v4 &
					*(__be32 *)rule->src_mask;
				if (masked != *(__be32 *)rule->src_addr)
					src_hit = 0;
			} else {
				/* IPv6: compare 4 x 32-bit words */
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->src_ip.v6 + j) &
						  *(__u32 *)(rule->src_mask + j);
					if (m != *(__u32 *)(rule->src_addr + j)) {
						src_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_SRC_NEGATE)
				src_hit = !src_hit;
			if (!src_hit)
				match = 0;
		}

		/* Check destination address */
		if (match && (flags & FILTER_MATCH_DST_ADDR)) {
			int dst_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->dst_ip.v4 &
					*(__be32 *)rule->dst_mask;
				if (masked != *(__be32 *)rule->dst_addr)
					dst_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->dst_ip.v6 + j) &
						  *(__u32 *)(rule->dst_mask + j);
					if (m != *(__u32 *)(rule->dst_addr + j)) {
						dst_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_DST_NEGATE)
				dst_hit = !dst_hit;
			if (!dst_hit)
				match = 0;
		}

		if (!match)
			continue;

		/* Increment per-rule counter */
		struct counter_value *fc =
			bpf_map_lookup_elem(&filter_counters, &idx);
		if (fc) { fc->packets++; fc->bytes += meta->pkt_len; }

		/* Emit log event if configured */
		if (rule->log_flag) {
			__u8 act = (rule->action == FILTER_ACTION_ACCEPT ||
				    rule->action == FILTER_ACTION_ROUTE)
				   ? ACTION_PERMIT : ACTION_DENY;
			emit_event(meta, EVENT_TYPE_FILTER_LOG, act, 0, 0);
		}

		/* DSCP rewrite if configured */
		if (rule->dscp_rewrite != 0xFF)
			meta->dscp_rewrite = rule->dscp_rewrite;

		/* Term matched — apply action */
		switch (rule->action) {
		case FILTER_ACTION_ACCEPT:
			return 0;
		case FILTER_ACTION_DISCARD:
			return -1;
		case FILTER_ACTION_REJECT:
			return -2;
		case FILTER_ACTION_ROUTE:
			meta->routing_table = rule->routing_table;
			return 0;
		}
	}

	/* No term matched — implicit accept */
	return 0;
}

/* evaluate_firewall_filter_output — same as input but uses egress
 * interface index and direction=1 for the map lookup.
 * Returns:
 *   0  = no filter or "accept"
 *   -1 = "discard" — drop the packet
 */
static __always_inline int
evaluate_firewall_filter_output(struct pkt_meta *meta, __u32 egress_ifindex)
{
	struct iface_filter_key fkey = {
		.ifindex   = egress_ifindex,
		.vlan_id   = 0,  /* egress VLAN not tracked separately */
		.family    = meta->addr_family,
		.direction = 1,
	};
	__u32 *filter_id = bpf_map_lookup_elem(&iface_filter_map, &fkey);
	if (!filter_id)
		return 0;

	struct filter_config *fcfg = bpf_map_lookup_elem(&filter_configs, filter_id);
	if (!fcfg || fcfg->num_rules == 0)
		return 0;

	__u32 start = fcfg->rule_start;
	__u32 count = fcfg->num_rules;
	if (count > MAX_FILTER_RULES_PER_FILTER)
		count = MAX_FILTER_RULES_PER_FILTER;

	#pragma unroll
	for (__u32 i = 0; i < MAX_FILTER_RULES_PER_FILTER; i++) {
		if (i >= count)
			break;

		__u32 idx = start + i;
		if (idx >= MAX_FILTER_RULES)
			break;

		struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &idx);
		if (!rule)
			break;

		__u16 flags = rule->match_flags;
		int match = 1;

		if ((flags & FILTER_MATCH_DSCP) && rule->dscp != meta->dscp)
			match = 0;
		if (match && (flags & FILTER_MATCH_PROTOCOL) &&
		    rule->protocol != meta->protocol)
			match = 0;
		if (match && (flags & FILTER_MATCH_DST_PORT)) {
			if (rule->dst_port_hi) {
				__u16 p = bpf_ntohs(meta->dst_port);
				if (p < bpf_ntohs(rule->dst_port) ||
				    p > bpf_ntohs(rule->dst_port_hi))
					match = 0;
			} else if (rule->dst_port != meta->dst_port) {
				match = 0;
			}
		}
		if (match && (flags & FILTER_MATCH_SRC_PORT)) {
			if (rule->src_port_hi) {
				__u16 p = bpf_ntohs(meta->src_port);
				if (p < bpf_ntohs(rule->src_port) ||
				    p > bpf_ntohs(rule->src_port_hi))
					match = 0;
			} else if (rule->src_port != meta->src_port) {
				match = 0;
			}
		}
		if (match && (flags & FILTER_MATCH_ICMP_TYPE) &&
		    rule->icmp_type != meta->icmp_type)
			match = 0;
		if (match && (flags & FILTER_MATCH_ICMP_CODE) &&
		    rule->icmp_code != meta->icmp_code)
			match = 0;

		/* Check TCP flags (all specified flags must be set) */
		if (match && (flags & FILTER_MATCH_TCP_FLAGS) &&
		    (meta->tcp_flags & rule->tcp_flags) != rule->tcp_flags)
			match = 0;

		/* Check IP fragment */
		if (match && (flags & FILTER_MATCH_FRAGMENT) &&
		    !meta->is_fragment)
			match = 0;

		if (match && (flags & FILTER_MATCH_SRC_ADDR)) {
			int src_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->src_ip.v4 &
					*(__be32 *)rule->src_mask;
				if (masked != *(__be32 *)rule->src_addr)
					src_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->src_ip.v6 + j) &
						  *(__u32 *)(rule->src_mask + j);
					if (m != *(__u32 *)(rule->src_addr + j)) {
						src_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_SRC_NEGATE)
				src_hit = !src_hit;
			if (!src_hit)
				match = 0;
		}

		if (match && (flags & FILTER_MATCH_DST_ADDR)) {
			int dst_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->dst_ip.v4 &
					*(__be32 *)rule->dst_mask;
				if (masked != *(__be32 *)rule->dst_addr)
					dst_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->dst_ip.v6 + j) &
						  *(__u32 *)(rule->dst_mask + j);
					if (m != *(__u32 *)(rule->dst_addr + j)) {
						dst_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_DST_NEGATE)
				dst_hit = !dst_hit;
			if (!dst_hit)
				match = 0;
		}

		if (!match)
			continue;

		struct counter_value *fc =
			bpf_map_lookup_elem(&filter_counters, &idx);
		if (fc) { fc->packets++; fc->bytes += meta->pkt_len; }

		if (rule->log_flag) {
			__u8 act = (rule->action == FILTER_ACTION_ACCEPT ||
				    rule->action == FILTER_ACTION_ROUTE)
				   ? ACTION_PERMIT : ACTION_DENY;
			emit_event(meta, EVENT_TYPE_FILTER_LOG, act, 0, 0);
		}

		if (rule->dscp_rewrite != 0xFF)
			meta->dscp_rewrite = rule->dscp_rewrite;

		switch (rule->action) {
		case FILTER_ACTION_ACCEPT:
			return 0;
		case FILTER_ACTION_DISCARD:
		case FILTER_ACTION_REJECT:
			return -1;
		}
	}

	return 0;
}

/* ============================================================
 * TCP MSS clamping
 *
 * Walk TCP options in a SYN packet, find MSS option (kind=2, len=4),
 * and clamp it to the configured maximum.
 * ============================================================ */

/* TCP option kinds */
#define TCPOPT_EOL  0
#define TCPOPT_NOP  1
#define TCPOPT_MSS  2
#define TCPOPT_MSS_LEN 4

/*
 * Clamp TCP MSS option in a SYN packet.
 *
 * The MSS option (kind=2, len=4) in standard SYN packets is found
 * at one of a few well-known positions in the TCP options area.
 * We check the first few positions with constant offsets to keep
 * the verifier happy (avoids loop + variable offset issues).
 *
 * Returns 0 on success/no-op.
 */
static __always_inline int
tcp_mss_clamp(struct xdp_md *ctx, __u16 l4_offset, __u16 max_mss,
	      int csum_partial)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Sanity limit on l4_offset to help verifier */
	if (l4_offset > 200)
		return -1;

	/* Ensure at least TCP header + 40 bytes of options (max) */
	if (data + l4_offset + 60 > data_end)
		return 0;

	/*
	 * Check the first 4 bytes of TCP options (offset 20 from TCP start).
	 * MSS is almost always the first option in SYN packets.
	 * Option format: kind(1) len(1) value(2) = {0x02, 0x04, MSS_HI, MSS_LO}
	 *
	 * Also check a few other common positions (NOP-padded layouts):
	 * - offset 0: MSS first (most common)
	 * - offset 1: after one NOP
	 * - offset 2: after two NOPs
	 *
	 * We use absolute offsets from data to keep the verifier's
	 * packet range valid throughout.
	 */
	__u8 *opt_base = (__u8 *)data + l4_offset + 20;
	__be16 *mss_ptr = 0;
	struct tcphdr *tcp = data + l4_offset;

	/* Position 0: MSS at start of options (most common) */
	if (opt_base[0] == TCPOPT_MSS && opt_base[1] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 2);
	}
	/* Position 1: NOP + MSS */
	else if (opt_base[0] == TCPOPT_NOP &&
		 opt_base[1] == TCPOPT_MSS && opt_base[2] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 3);
	}
	/* Position 2: NOP + NOP + MSS */
	else if (opt_base[0] == TCPOPT_NOP && opt_base[1] == TCPOPT_NOP &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}
	/* Position: after SACK_PERM (kind=4,len=2) + MSS */
	else if (opt_base[0] == 4 && opt_base[1] == 2 &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}

	if (!mss_ptr)
		return 0;
	if ((void *)(mss_ptr + 1) > data_end)
		return 0;

	__u16 cur_mss = bpf_ntohs(*mss_ptr);
	if (cur_mss > max_mss) {
		__be16 old_mss = *mss_ptr;
		__be16 new_mss = bpf_htons(max_mss);
		*mss_ptr = new_mss;

		/* For CHECKSUM_PARTIAL, the MSS is in the L4 data that
		 * the NIC/skb_checksum_help will sum -- skip incremental
		 * update to avoid double-counting the delta. */
		if (!csum_partial) {
			/* Re-read data pointers after packet write for verifier */
			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			if (data + l4_offset + 20 > data_end)
				return 0;
			tcp = data + l4_offset;
			csum_update_2(&tcp->check, old_mss, new_mss);
		}
	}

	return 0;
}

/*
 * TC egress variant of tcp_mss_clamp.
 * Identical logic but takes struct __sk_buff * context.
 */
static __always_inline int
tc_tcp_mss_clamp(struct __sk_buff *skb, __u16 l4_offset, __u16 max_mss,
		 int csum_partial)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (l4_offset > 200)
		return -1;

	if (data + l4_offset + 60 > data_end)
		return 0;

	__u8 *opt_base = (__u8 *)data + l4_offset + 20;
	__be16 *mss_ptr = 0;
	struct tcphdr *tcp = data + l4_offset;

	/* Position 0: MSS at start of options (most common) */
	if (opt_base[0] == TCPOPT_MSS && opt_base[1] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 2);
	}
	/* Position 1: NOP + MSS */
	else if (opt_base[0] == TCPOPT_NOP &&
		 opt_base[1] == TCPOPT_MSS && opt_base[2] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 3);
	}
	/* Position 2: NOP + NOP + MSS */
	else if (opt_base[0] == TCPOPT_NOP && opt_base[1] == TCPOPT_NOP &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}
	/* Position: after SACK_PERM (kind=4,len=2) + MSS */
	else if (opt_base[0] == 4 && opt_base[1] == 2 &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}

	if (!mss_ptr)
		return 0;
	if ((void *)(mss_ptr + 1) > data_end)
		return 0;

	__u16 cur_mss = bpf_ntohs(*mss_ptr);
	if (cur_mss > max_mss) {
		__be16 old_mss = *mss_ptr;
		__be16 new_mss = bpf_htons(max_mss);
		*mss_ptr = new_mss;

		if (!csum_partial) {
			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
			if (data + l4_offset + 20 > data_end)
				return 0;
			tcp = data + l4_offset;
			csum_update_2(&tcp->check, old_mss, new_mss);
		}
	}

	return 0;
}

#endif /* __BPFRX_HELPERS_H__ */
