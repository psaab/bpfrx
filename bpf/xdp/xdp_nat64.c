// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP NAT64 translation stage.
 *
 * Handles IPv6↔IPv4 header translation for NAT64.
 * Called from xdp_nat when SESS_FLAG_NAT64 is set (forward path)
 * or from xdp_conntrack when nat64_state matches (reverse path).
 *
 * Forward path (IPv6→IPv4):
 *   - Shrinks packet by 20 bytes (IPv6 40B header → IPv4 20B header)
 *   - Extracts IPv4 dst from last 32 bits of IPv6 dst
 *   - Applies SNAT (IPv4 source from pool allocated earlier)
 *   - Incrementally updates L4 checksums (pseudo-header swap)
 *   - Creates nat64_state entry for reverse translation
 *   - Forwards via bpf_fib_lookup + redirect
 *
 * Reverse path (IPv4→IPv6):
 *   - Grows packet by 20 bytes (IPv4 20B header → IPv6 40B header)
 *   - Restores original IPv6 src/dst from nat64_state
 *   - Incrementally updates L4 checksums (pseudo-header swap)
 *   - Forwards via bpf_fib_lookup + redirect
 */

#include "../headers/bpfrx_common.h"
#define BPFRX_NAT_POOLS
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_nat.h"

/*
 * Compute IPv4 header checksum from scratch (10 x 16-bit words).
 */
static __always_inline __sum16
ipv4_csum(struct iphdr *iph)
{
	__u32 csum = 0;
	__u16 *p = (__u16 *)iph;

	#pragma unroll
	for (int i = 0; i < 10; i++)
		csum += p[i];

	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += csum >> 16;
	return (__sum16)(~csum);
}

/*
 * Fold a 32-bit checksum accumulator to 16-bit ones-complement.
 */
static __always_inline __u16
csum_fold(__u32 csum)
{
	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += csum >> 16;
	return (__u16)csum;
}

/*
 * Compute checksum of 16 bytes (e.g., an IPv6 address) as a running sum.
 */
static __always_inline __u32
csum_bytes16(const __u8 *p)
{
	const __u16 *w = (const __u16 *)p;
	__u32 s = 0;
	#pragma unroll
	for (int i = 0; i < 8; i++)
		s += w[i];
	return s;
}

/*
 * Adjust L4 checksum when switching from IPv6 to IPv4 pseudo-header.
 * old_csum is the existing L4 checksum (computed over IPv6 pseudo-header).
 * We subtract the IPv6 pseudo-header contribution and add IPv4 pseudo-header.
 *
 * IPv6 pseudo-header: src(16) + dst(16) + upper-layer-len(4) + next-hdr(4)
 * IPv4 pseudo-header: src(4) + dst(4) + zero+proto(2) + len(2)
 *
 * We also need to adjust for any port changes (SNAT source port).
 */
static __always_inline __sum16
csum_v6_to_v4(__sum16 old_csum,
	      const __u8 *old_src_v6, const __u8 *old_dst_v6,
	      __be32 new_src_v4, __be32 new_dst_v4,
	      __u8 proto, __u16 l4_len,
	      __be16 old_sport, __be16 new_sport)
{
	__u32 csum;

	/* Un-fold the existing checksum: ~old_csum gives us the running sum */
	csum = (__u16)~old_csum;

	/* Subtract IPv6 pseudo-header components */
	__u32 v6sum = csum_bytes16(old_src_v6) + csum_bytes16(old_dst_v6);
	/* IPv6 pseudo-header also includes length and next-header as 32-bit */
	v6sum += bpf_htons(l4_len);
	v6sum += bpf_htons((__u16)proto);

	/* Fold v6sum */
	v6sum = csum_fold(v6sum);

	/* Subtract v6 pseudo-header (add its complement) */
	csum += (__u16)~v6sum;

	/* Add IPv4 pseudo-header */
	__u32 v4sum = 0;
	v4sum += (new_src_v4 >> 16) & 0xFFFF;
	v4sum += new_src_v4 & 0xFFFF;
	v4sum += (new_dst_v4 >> 16) & 0xFFFF;
	v4sum += new_dst_v4 & 0xFFFF;

	/* For ICMP: IPv4 ICMP doesn't use pseudo-header, but ICMPv6 does.
	 * Handle this by not adding IPv4 pseudo-header for ICMP. */
	if (proto != PROTO_ICMPV6) {
		v4sum += bpf_htons((__u16)proto);
		v4sum += bpf_htons(l4_len);
	}

	v4sum = csum_fold(v4sum);
	csum += v4sum;

	/* Adjust for port change */
	if (old_sport != new_sport) {
		csum += (__u16)~old_sport;
		csum += new_sport;
	}

	return (__sum16)~csum_fold(csum);
}

/*
 * Adjust L4 checksum when switching from IPv4 to IPv6 pseudo-header.
 */
static __always_inline __sum16
csum_v4_to_v6(__sum16 old_csum,
	      __be32 old_src_v4, __be32 old_dst_v4,
	      const __u8 *new_src_v6, const __u8 *new_dst_v6,
	      __u8 old_proto, __u8 new_proto, __u16 l4_len,
	      __be16 old_dport, __be16 new_dport)
{
	__u32 csum;

	csum = (__u16)~old_csum;

	/* Subtract IPv4 pseudo-header.
	 * For ICMP→ICMPv6: ICMPv4 has no pseudo-header, but ICMPv6 does.
	 * So for ICMP we don't subtract anything. */
	if (old_proto != PROTO_ICMP) {
		__u32 v4sum = 0;
		v4sum += (old_src_v4 >> 16) & 0xFFFF;
		v4sum += old_src_v4 & 0xFFFF;
		v4sum += (old_dst_v4 >> 16) & 0xFFFF;
		v4sum += old_dst_v4 & 0xFFFF;
		v4sum += bpf_htons((__u16)old_proto);
		v4sum += bpf_htons(l4_len);
		v4sum = csum_fold(v4sum);
		csum += (__u16)~v4sum;
	}

	/* Add IPv6 pseudo-header */
	__u32 v6sum = csum_bytes16(new_src_v6) + csum_bytes16(new_dst_v6);
	v6sum += bpf_htons(l4_len);
	v6sum += bpf_htons((__u16)new_proto);
	v6sum = csum_fold(v6sum);
	csum += v6sum;

	/* Adjust for port change */
	if (old_dport != new_dport) {
		csum += (__u16)~old_dport;
		csum += new_dport;
	}

	return (__sum16)~csum_fold(csum);
}

/*
 * Translate ICMPv6 type/code to ICMPv4 equivalents.
 * Returns 0 on success, -1 if not translatable.
 */
static __always_inline int
icmpv6_to_icmpv4(__u8 v6_type, __u8 v6_code, __u8 *v4_type, __u8 *v4_code)
{
	switch (v6_type) {
	case 128: /* Echo Request → 8 */
		*v4_type = 8;
		*v4_code = 0;
		return 0;
	case 129: /* Echo Reply → 0 */
		*v4_type = 0;
		*v4_code = 0;
		return 0;
	default:
		return -1;
	}
}

/*
 * Translate ICMPv4 type/code to ICMPv6 equivalents.
 */
static __always_inline int
icmpv4_to_icmpv6(__u8 v4_type, __u8 v4_code, __u8 *v6_type, __u8 *v6_code)
{
	switch (v4_type) {
	case 8: /* Echo Request → 128 */
		*v6_type = 128;
		*v6_code = 0;
		return 0;
	case 0: /* Echo Reply → 129 */
		*v6_type = 129;
		*v6_code = 0;
		return 0;
	default:
		return -1;
	}
}

/*
 * Forward NAT64 translation: IPv6 → IPv4.
 *
 * meta->nat_flags has SESS_FLAG_NAT64 set.
 * meta->src_ip.v4 has allocated SNAT IPv4 address (set by policy).
 * meta->src_port has allocated SNAT port.
 * meta->dst_ip.v6 last 32 bits contain the embedded IPv4 dest.
 */
static __always_inline int
nat64_xlate_6to4(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Validate offsets */
	if (meta->l3_offset >= 64 || meta->l4_offset >= 128)
		return XDP_DROP;

	struct ipv6hdr *ip6h = data + meta->l3_offset;
	if ((void *)(ip6h + 1) > data_end)
		return XDP_DROP;

	/* Extract IPv4 destination from last 32 bits of IPv6 dst */
	__be32 v4_dst = ip6h->daddr.u6_addr32[3];
	__be32 v4_src = meta->src_ip.v4;  /* SNAT'd v4 address from policy */

	/* Save original IPv6 addresses for nat64_state */
	__u8 orig_src_v6[16], orig_dst_v6[16];
	__builtin_memcpy(orig_src_v6, &ip6h->saddr, 16);
	__builtin_memcpy(orig_dst_v6, &ip6h->daddr, 16);

	/* Calculate L4 length (IPv6 payload, minus any ext headers we skipped) */
	__u16 l4_len = bpf_ntohs(ip6h->payload_len);
	__u16 ext_hdr_len = meta->l4_offset - meta->l3_offset - sizeof(struct ipv6hdr);
	if (ext_hdr_len < l4_len)
		l4_len -= ext_hdr_len;

	__u8 orig_proto = meta->protocol;
	__u8 ip4_proto = orig_proto;

	/* Map ICMPv6 → ICMP */
	if (orig_proto == PROTO_ICMPV6)
		ip4_proto = PROTO_ICMP;

	/* Save the original L4 checksum and port before we modify the packet */
	__be16 old_sport = meta->src_port;
	__be16 new_sport = meta->src_port; /* already set to SNAT port by policy */
	__sum16 orig_l4_csum = 0;

	/* Read original L4 checksum from packet */
	void *old_l4 = data + meta->l4_offset;
	if (orig_proto == PROTO_TCP) {
		struct tcphdr *tcp = old_l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_DROP;
		orig_l4_csum = tcp->check;
		old_sport = tcp->source;
	} else if (orig_proto == PROTO_UDP) {
		struct udphdr *udp = old_l4;
		if ((void *)(udp + 1) > data_end)
			return XDP_DROP;
		orig_l4_csum = udp->check;
		old_sport = udp->source;
	} else if (orig_proto == PROTO_ICMPV6) {
		/* For ICMP echo, meta->src_port was replaced with the
		 * SNAT'd port by policy, but we need the original echo
		 * ID for nat64_state.  meta->dst_port retains it. */
		old_sport = meta->dst_port;
	}

	/* Shrink head by 20 bytes (IPv6→IPv4 header size difference).
	 * MACs are not saved — bpf_fib_lookup below will provide correct ones. */
	if (bpf_xdp_adjust_head(ctx, 20))
		return XDP_DROP;

	/* Re-read pointers */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Write new Ethernet header (MACs will be overwritten by FIB result) */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	eth->h_proto = bpf_htons(ETH_P_IP);

	/* Write IPv4 header */
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	__u16 tot_len = sizeof(struct iphdr) + l4_len;
	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = 0;
	iph->tot_len  = bpf_htons(tot_len);
	iph->id       = 0;
	iph->frag_off = bpf_htons(0x4000); /* DF bit */
	iph->ttl      = meta->ip_ttl;
	iph->protocol = ip4_proto;
	iph->check    = 0;
	iph->saddr    = v4_src;
	iph->daddr    = v4_dst;
	iph->check    = ipv4_csum(iph);

	/* L4 header starts right after IPv4 header */
	void *l4 = (void *)(iph + 1);

	if (ip4_proto == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_DROP;
		tcp->source = new_sport;
		tcp->check = csum_v6_to_v4(orig_l4_csum,
					    orig_src_v6, orig_dst_v6,
					    v4_src, v4_dst,
					    orig_proto, l4_len,
					    old_sport, new_sport);
	} else if (ip4_proto == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return XDP_DROP;
		udp->source = new_sport;
		udp->check = csum_v6_to_v4(orig_l4_csum,
					    orig_src_v6, orig_dst_v6,
					    v4_src, v4_dst,
					    orig_proto, l4_len,
					    old_sport, new_sport);
		if (udp->check == 0)
			udp->check = 0xFFFF;
	} else if (ip4_proto == PROTO_ICMP) {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) > data_end)
			return XDP_DROP;
		/* Translate ICMPv6 type/code → ICMPv4 */
		__u8 v4_type, v4_code;
		if (icmpv6_to_icmpv4(meta->icmp_type, meta->icmp_code,
				     &v4_type, &v4_code) < 0)
			return XDP_DROP;
		icmp->type = v4_type;
		icmp->code = v4_code;

		/* Recompute ICMP checksum from scratch (no pseudo-header).
		 * Zero the field, sum the entire ICMP message with per-access
		 * bounds checks for the verifier. */
		icmp->checksum = 0;
		__u32 icmp_csum = 0;
		__u16 *icmp_w = (__u16 *)icmp;
		/* Sum up to 64 x 16-bit words (128 bytes).  Each access is
		 * individually bounds-checked so the verifier is happy. */
		#pragma unroll
		for (int i = 0; i < 64; i++) {
			if ((void *)(&icmp_w[i] + 1) <= data_end)
				icmp_csum += icmp_w[i];
		}
		icmp->checksum = (__sum16)~csum_fold(icmp_csum);
	}

	/* Insert nat64_state entry for reverse translation.
	 * For ICMP, the echo_id is never rewritten (unlike TCP/UDP ports),
	 * so the reply will carry the original echo_id in both "port" fields.
	 * Use meta->dst_port (= echo_id) for both src/dst port. */
	struct nat64_state_key rkey = {
		.src_ip   = v4_dst,
		.dst_ip   = v4_src,
		.src_port = meta->dst_port,
		.dst_port = (ip4_proto == PROTO_ICMP) ?
			    meta->dst_port : new_sport,
		.protocol = ip4_proto,
	};
	struct nat64_state_value rval = {};
	__builtin_memcpy(rval.orig_src_v6, orig_src_v6, 16);
	__builtin_memcpy(rval.orig_dst_v6, orig_dst_v6, 16);
	rval.orig_src_port = old_sport;
	rval.orig_dst_port = meta->dst_port;

	bpf_map_update_elem(&nat64_state, &rkey, &rval, BPF_NOEXIST);

	inc_counter(GLOBAL_CTR_NAT64_XLATE);

	/* FIB lookup for the new IPv4 destination */
	struct bpf_fib_lookup fib = {};
	fib.family      = AF_INET;
	fib.l4_protocol = ip4_proto;
	fib.tot_len     = tot_len;
	fib.ifindex     = meta->ingress_ifindex;
	fib.tbid        = meta->routing_table;
	fib.ipv4_src    = v4_src;
	fib.ipv4_dst    = v4_dst;

	__u32 fib_flags = meta->routing_table ? BPF_FIB_LOOKUP_TBID : 0;
	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), fib_flags);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_PASS; /* let kernel handle */

	/* Resolve VLAN sub-interface and store in meta for xdp_forward */
	__u32 egress_if = fib.ifindex;
	struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map,
							 &egress_if);
	if (vi) {
		meta->fwd_ifindex = vi->parent_ifindex;
		meta->egress_vlan_id = vi->vlan_id;
	} else {
		meta->fwd_ifindex = egress_if;
		meta->egress_vlan_id = 0;
	}

	__builtin_memcpy(meta->fwd_dmac, fib.dmac, ETH_ALEN);
	__builtin_memcpy(meta->fwd_smac, fib.smac, ETH_ALEN);

	/* Update addr_family so xdp_forward does IPv4 TTL handling */
	meta->addr_family = AF_INET;

	/* Tail-call to xdp_forward for MAC rewrite + redirect */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	/* If we get here, tail-call failed */
	return XDP_PASS;
}

/*
 * Reverse NAT64 translation: IPv4 → IPv6.
 *
 * meta->nat_flags has SESS_FLAG_NAT64 set.
 * The nat64_state entry has been looked up by conntrack and stored:
 *   meta->nat_src_ip.v6 = original client v6 addr (becomes dst)
 *   meta->nat_dst_ip.v6 = original server v6 addr (becomes src)
 *   meta->dst_port = original client port (restore to dst)
 */
static __always_inline int
nat64_xlate_4to6(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Save ingress dst MAC before adjust_head overwrites it.
	 * Needed for NO_NEIGH fallback (XDP_PASS). */
	__u8 saved_dmac[ETH_ALEN];
	struct ethhdr *orig_eth = data;
	if ((void *)(orig_eth + 1) > data_end)
		return XDP_DROP;
	__builtin_memcpy(saved_dmac, orig_eth->h_dest, ETH_ALEN);

	if (meta->l3_offset >= 64)
		return XDP_DROP;

	struct iphdr *iph = data + meta->l3_offset;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	__be32 old_src_v4 = iph->saddr;
	__be32 old_dst_v4 = iph->daddr;
	__u16 ip4_tot_len = bpf_ntohs(iph->tot_len);
	__u16 ip4_hdr_len = iph->ihl * 4;
	__u16 l4_len = 0;
	if (ip4_tot_len > ip4_hdr_len)
		l4_len = ip4_tot_len - ip4_hdr_len;

	__u8 orig_proto = iph->protocol;
	__u8 ip6_proto = orig_proto;

	/* Map ICMP → ICMPv6 */
	if (orig_proto == PROTO_ICMP)
		ip6_proto = PROTO_ICMPV6;

	/* Original IPv6 addresses from nat64_state (set by conntrack):
	 * nat_dst_ip = server v6 (prefix + v4 server) → becomes IPv6 src
	 * nat_src_ip = client v6 (original requester) → becomes IPv6 dst */
	__u8 v6_src[16], v6_dst[16];
	__builtin_memcpy(v6_src, meta->nat_dst_ip.v6, 16);
	__builtin_memcpy(v6_dst, meta->nat_src_ip.v6, 16);

	/* Save L4 checksum and port before modifying */
	__sum16 orig_l4_csum = 0;
	__be16 old_dport = meta->dst_port;
	__be16 new_dport = meta->dst_port; /* restored from nat64_state */

	void *old_l4 = data + meta->l4_offset;
	if (meta->l4_offset >= 128)
		return XDP_DROP;
	if (orig_proto == PROTO_TCP) {
		struct tcphdr *tcp = old_l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_DROP;
		orig_l4_csum = tcp->check;
		old_dport = tcp->dest;
	} else if (orig_proto == PROTO_UDP) {
		struct udphdr *udp = old_l4;
		if ((void *)(udp + 1) > data_end)
			return XDP_DROP;
		orig_l4_csum = udp->check;
		old_dport = udp->dest;
	}

	/* Grow head by 20 bytes (IPv4→IPv6 header size difference). */
	if (bpf_xdp_adjust_head(ctx, -20))
		return XDP_DROP;

	/* Re-read pointers */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Write new Ethernet header. Set saved ingress MAC as dst so
	 * XDP_PASS is accepted by kernel. FIB overwrites on SUCCESS. */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	__builtin_memcpy(eth->h_dest, saved_dmac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Write IPv6 header */
	struct ipv6hdr *ip6h = (void *)(eth + 1);
	if ((void *)(ip6h + 1) > data_end)
		return XDP_DROP;

	ip6h->version     = 6;
	ip6h->priority    = 0;
	ip6h->flow_lbl[0] = 0;
	ip6h->flow_lbl[1] = 0;
	ip6h->flow_lbl[2] = 0;
	ip6h->payload_len = bpf_htons(l4_len);
	ip6h->nexthdr     = ip6_proto;
	ip6h->hop_limit   = meta->ip_ttl;
	__builtin_memcpy(&ip6h->saddr, v6_src, 16);
	__builtin_memcpy(&ip6h->daddr, v6_dst, 16);

	/* L4 header starts right after IPv6 header */
	void *l4 = (void *)(ip6h + 1);

	if (ip6_proto == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_DROP;
		tcp->dest = new_dport;
		tcp->check = csum_v4_to_v6(orig_l4_csum,
					    old_src_v4, old_dst_v4,
					    v6_src, v6_dst,
					    orig_proto, ip6_proto, l4_len,
					    old_dport, new_dport);
	} else if (ip6_proto == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return XDP_DROP;
		udp->dest = new_dport;
		udp->check = csum_v4_to_v6(orig_l4_csum,
					    old_src_v4, old_dst_v4,
					    v6_src, v6_dst,
					    orig_proto, ip6_proto, l4_len,
					    old_dport, new_dport);
		if (udp->check == 0)
			udp->check = 0xFFFF;
	} else if (ip6_proto == PROTO_ICMPV6) {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) > data_end)
			return XDP_DROP;
		__u8 v6_type, v6_code;
		if (icmpv4_to_icmpv6(icmp6->icmp6_type, icmp6->icmp6_code,
				     &v6_type, &v6_code) < 0)
			return XDP_DROP;
		icmp6->icmp6_type = v6_type;
		icmp6->icmp6_code = v6_code;

		/* Compute ICMPv6 checksum from scratch.
		 * ICMPv6 checksum covers IPv6 pseudo-header + full
		 * ICMPv6 message (unlike ICMPv4 which has no pseudo-hdr).
		 */
		icmp6->icmp6_cksum = 0;

		/* IPv6 pseudo-header sum */
		__u32 csum = csum_bytes16(v6_src) + csum_bytes16(v6_dst);
		csum += bpf_htons(l4_len);
		csum += bpf_htons((__u16)PROTO_ICMPV6);

		/* Sum all ICMPv6 16-bit words */
		__u16 *icmp_w = (__u16 *)icmp6;
		#pragma unroll
		for (int i = 0; i < 64; i++) {
			if ((void *)(&icmp_w[i] + 1) <= data_end)
				csum += icmp_w[i];
		}

		icmp6->icmp6_cksum = (__sum16)~csum_fold(csum);
	}

	inc_counter(GLOBAL_CTR_NAT64_XLATE);

	/* FIB lookup for the IPv6 destination (the original client) */
	struct bpf_fib_lookup fib = {};
	fib.family      = AF_INET6;
	fib.l4_protocol = ip6_proto;
	fib.tot_len     = bpf_ntohs(ip6h->payload_len) + 40;
	fib.ifindex     = meta->ingress_ifindex;
	fib.tbid        = meta->routing_table;
	__builtin_memcpy(fib.ipv6_src, v6_src, 16);
	__builtin_memcpy(fib.ipv6_dst, v6_dst, 16);

	__u32 fib_flags = meta->routing_table ? BPF_FIB_LOOKUP_TBID : 0;
	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), fib_flags);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS &&
	    rc != BPF_FIB_LKUP_RET_NO_NEIGH)
		return XDP_PASS;

	/* Update addr_family so xdp_forward does IPv6 hop_limit handling */
	meta->addr_family = AF_INET6;

	if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		/* Route exists but no NDP neighbor entry.
		 * XDP_PASS the translated IPv6 packet so the kernel
		 * resolves NDP and forwards. Push ingress VLAN tag
		 * back for kernel delivery. */
		if (meta->ingress_vlan_id != 0) {
			if (xdp_vlan_tag_push(ctx,
					      meta->ingress_vlan_id) < 0)
				return XDP_DROP;
		}
		return XDP_PASS;
	}

	/* Resolve VLAN sub-interface and store in meta for xdp_forward */
	__u32 egress_if = fib.ifindex;
	struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map,
							 &egress_if);
	if (vi) {
		meta->fwd_ifindex = vi->parent_ifindex;
		meta->egress_vlan_id = vi->vlan_id;
	} else {
		meta->fwd_ifindex = egress_if;
		meta->egress_vlan_id = 0;
	}

	__builtin_memcpy(meta->fwd_dmac, fib.dmac, ETH_ALEN);
	__builtin_memcpy(meta->fwd_smac, fib.smac, ETH_ALEN);

	/* Tail-call to xdp_forward */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	return XDP_PASS;
}

/*
 * NAT64 ICMP error translation: IPv4 ICMP error → IPv6 ICMPv6 error.
 *
 * Called when an intermediate IPv4 router sends an ICMP error (e.g.
 * Time Exceeded) for a packet that was NAT64-translated.  We must
 * translate the entire error packet from IPv4 to IPv6 so the original
 * IPv6 client receives a proper ICMPv6 error.
 *
 * Meta fields set by conntrack embedded handler:
 *   nat_src_ip.v6 = original client IPv6 (outer dst + embedded src)
 *   nat_dst_ip.v6 = original server IPv6 (embedded dst)
 *   nat_src_port  = original client port
 *   dst_port      = original server port
 *   embedded_proto = embedded L4 protocol (TCP/UDP/ICMP→ICMPv6)
 *
 * Packet layout before:
 *   [Eth(14)][IPv4(20)][ICMP(8)][EmbIPv4(20)][EmbL4...]
 * After bpf_xdp_adjust_head(-40):
 *   [+40 new][Eth(14)][IPv4(20)][ICMP(8)][EmbIPv4(20)][EmbL4...]
 * We write:
 *   [Eth(14)][IPv6(40)][ICMPv6(8)][EmbIPv6(40)][EmbL4...]
 * EmbL4 is at offset 102 in both layouts — no copy needed.
 */
static __always_inline int
nat64_icmp_error_4to6(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Read outer IPv4 source (intermediate router) and ICMP type/code
	 * BEFORE adjust_head invalidates all pointers. */
	struct ethhdr *orig_eth = data;
	if ((void *)(orig_eth + 1) > data_end)
		return XDP_DROP;
	__u8 saved_dmac[ETH_ALEN];
	__builtin_memcpy(saved_dmac, orig_eth->h_dest, ETH_ALEN);

	struct iphdr *outer_ip = (void *)(orig_eth + 1);
	if ((void *)(outer_ip + 1) > data_end)
		return XDP_DROP;
	__be32 router_v4 = outer_ip->saddr;
	__u8 outer_ttl = outer_ip->ttl;

	/* ICMP header follows IPv4 (we know IHL=5 for simple packets) */
	struct icmphdr *outer_icmp = (void *)(outer_ip + 1);
	if ((void *)(outer_icmp + 1) > data_end)
		return XDP_DROP;
	__u8 icmp4_type = outer_icmp->type;
	__u8 icmp4_code = outer_icmp->code;

	/* Map ICMPv4 error types to ICMPv6 (RFC 7915) */
	__u8 icmp6_type, icmp6_code;
	if (icmp4_type == 11) {
		/* Time Exceeded → Time Exceeded */
		icmp6_type = 3;
		icmp6_code = icmp4_code;
	} else if (icmp4_type == 3) {
		/* Dest Unreachable → Dest Unreachable */
		icmp6_type = 1;
		/* Map codes per RFC 7915 */
		switch (icmp4_code) {
		case 0: case 1: case 5: case 6: case 7:
		case 8: case 11: case 12:
			icmp6_code = 0; /* No route */
			break;
		case 2:
			icmp6_code = 4; /* Port unreachable */
			break;
		case 3:
			icmp6_code = 4; /* Port unreachable */
			break;
		case 4:
			/* Frag needed → Packet Too Big (type 2) */
			icmp6_type = 2;
			icmp6_code = 0;
			break;
		case 9: case 10: case 13:
			icmp6_code = 1; /* Comm prohibited */
			break;
		default:
			icmp6_code = 0;
			break;
		}
	} else if (icmp4_type == 12) {
		/* Param Problem → Param Problem */
		icmp6_type = 4;
		icmp6_code = 0;
	} else {
		return XDP_DROP; /* Not a translatable error */
	}

	/* Read embedded L4 ports from packet before adjust_head.
	 * Embedded IP header starts at offset 42 (14+20+8), L4 at 62. */
	struct iphdr *emb_ip = (void *)(outer_icmp + 1);
	if ((void *)(emb_ip + 1) > data_end)
		return XDP_DROP;
	__u16 emb_tot_len = bpf_ntohs(emb_ip->tot_len);

	/* Grow packet by 40 bytes for IPv4→IPv6 outer + embedded headers */
	if (bpf_xdp_adjust_head(ctx, -40))
		return XDP_DROP;

	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Write Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	__builtin_memcpy(eth->h_dest, saved_dmac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Write outer IPv6 header */
	struct ipv6hdr *ip6h = (void *)(eth + 1);
	if ((void *)(ip6h + 1) > data_end)
		return XDP_DROP;

	/* Build router IPv6 src: NAT64 prefix + router IPv4.
	 * Extract prefix from nat_dst_ip.v6 (first 12 bytes). */
	__u8 router_v6[16];
	__builtin_memcpy(router_v6, meta->nat_dst_ip.v6, 12);
	__builtin_memcpy(router_v6 + 12, &router_v4, 4);

	/* Payload = ICMPv6(8) + EmbIPv6(40) + embedded L4 data.
	 * Embedded L4 len = original IPv4 tot_len - IPv4 hdr(20). */
	__u16 emb_l4_len = 0;
	if (emb_tot_len > 20)
		emb_l4_len = emb_tot_len - 20;
	/* Cap to avoid oversized payload claims */
	if (emb_l4_len > 1200)
		emb_l4_len = 1200;
	__u16 payload_len = 8 + 40 + emb_l4_len;

	ip6h->version     = 6;
	ip6h->priority    = 0;
	ip6h->flow_lbl[0] = 0;
	ip6h->flow_lbl[1] = 0;
	ip6h->flow_lbl[2] = 0;
	ip6h->payload_len = bpf_htons(payload_len);
	ip6h->nexthdr     = PROTO_ICMPV6;
	ip6h->hop_limit   = outer_ttl > 0 ? outer_ttl : 64;
	__builtin_memcpy(&ip6h->saddr, router_v6, 16);
	__builtin_memcpy(&ip6h->daddr, meta->nat_src_ip.v6, 16);

	/* Write ICMPv6 header at offset 54 */
	struct icmp6hdr *icmp6 = (void *)(ip6h + 1);
	if ((void *)(icmp6 + 1) > data_end)
		return XDP_DROP;
	icmp6->icmp6_type = icmp6_type;
	icmp6->icmp6_code = icmp6_code;
	icmp6->icmp6_cksum = 0;
	/* Unused field (or MTU for Packet Too Big) — zero it */
	icmp6->un.data32[0] = 0;

	/* Write embedded IPv6 header at offset 62.
	 * src = original client v6, dst = original server v6 */
	struct ipv6hdr *emb_ip6 = (void *)(icmp6 + 1);
	if ((void *)(emb_ip6 + 1) > data_end)
		return XDP_DROP;

	__u8 emb_v6_proto = meta->embedded_proto;
	if (emb_v6_proto == PROTO_ICMP)
		emb_v6_proto = PROTO_ICMPV6;

	emb_ip6->version     = 6;
	emb_ip6->priority    = 0;
	emb_ip6->flow_lbl[0] = 0;
	emb_ip6->flow_lbl[1] = 0;
	emb_ip6->flow_lbl[2] = 0;
	emb_ip6->payload_len = bpf_htons(emb_l4_len);
	emb_ip6->nexthdr     = emb_v6_proto;
	emb_ip6->hop_limit   = 1; /* was 0 when error was generated */
	__builtin_memcpy(&emb_ip6->saddr, meta->nat_src_ip.v6, 16);
	__builtin_memcpy(&emb_ip6->daddr, meta->nat_dst_ip.v6, 16);

	/* Embedded L4 ports at offset 102 (=14+40+8+40) are already
	 * in the packet from the original IPv4 embedded data — they
	 * didn't move because the growth exactly fills the gap. But
	 * we need to restore the original (pre-SNAT) ports.
	 * For ICMP echo, restore the echo ID. */
	void *emb_l4 = (void *)(emb_ip6 + 1);
	if (emb_l4 + 4 <= data_end) {
		if (meta->embedded_proto == PROTO_TCP ||
		    meta->embedded_proto == PROTO_UDP) {
			__be16 *ports = (__be16 *)emb_l4;
			ports[0] = meta->nat_src_port; /* src port */
			ports[1] = meta->dst_port;     /* dst port */
		} else if (meta->embedded_proto == PROTO_ICMP) {
			/* ICMP echo embedded: type(1)+code(1)+csum(2)+id(2)
			 * Map type/code to ICMPv6 and restore echo ID */
			__u8 *tc = (__u8 *)emb_l4;
			if (emb_l4 + 6 <= data_end) {
				/* Map echo request type 8→128 */
				tc[0] = 128;
				tc[1] = 0;
				/* Echo ID at offset 4 */
				__be16 *eid = (__be16 *)(emb_l4 + 4);
				*eid = meta->nat_src_port;
			}
		}
	}

	/* NPTv6 reverse: if the original client address was NPTv6-
	 * translated (external prefix), reverse it back to the internal
	 * prefix.  This must happen BEFORE checksum computation since
	 * the ICMPv6 checksum covers the IPv6 pseudo-header. */
	__u8 client_v6[16];
	__builtin_memcpy(client_v6, meta->nat_src_ip.v6, 16);
	/* debug prints merged into existing ones */
	{
		struct nptv6_key nk = {};
		nk.direction = NPTV6_INBOUND;
		nk.prefix_len = 64;
		__builtin_memcpy(nk.prefix, client_v6, 8);
		struct nptv6_value *nv = bpf_map_lookup_elem(
			&nptv6_rules, &nk);
		if (!nv) {
			__builtin_memset(&nk, 0, sizeof(nk));
			nk.direction = NPTV6_INBOUND;
			nk.prefix_len = 48;
			__builtin_memcpy(nk.prefix, client_v6, 6);
			nv = bpf_map_lookup_elem(&nptv6_rules, &nk);
		}
		if (nv) {
			nptv6_translate(client_v6, nv, NPTV6_INBOUND);
			/* Update outer dst and embedded src */
			__builtin_memcpy(&ip6h->daddr, client_v6, 16);
			__builtin_memcpy(&emb_ip6->saddr, client_v6,
					 16);
		}
	}

	/* Compute ICMPv6 checksum from scratch: pseudo-header + payload.
	 * ICMPv6 checksum covers: IPv6 pseudo-hdr + ICMPv6 hdr + body.
	 * Uses client_v6 (post-NPTv6-reverse) for correct pseudo-hdr. */
	{
		__u32 csum = 0;
		/* IPv6 pseudo-header */
		csum += csum_bytes16(router_v6);
		csum += csum_bytes16(client_v6);
		csum += bpf_htons(payload_len);
		csum += bpf_htons((__u16)PROTO_ICMPV6);

		/* Sum ICMPv6 header + embedded IPv6 header + embedded L4.
		 * Everything from icmp6 to end of payload. */
		__u16 *w = (__u16 *)icmp6;
		#pragma unroll
		for (int i = 0; i < 64; i++) {
			if ((void *)(&w[i] + 1) <= data_end)
				csum += w[i];
		}
		icmp6->icmp6_cksum = (__sum16)~csum_fold(csum);
	}

	/* FIB lookup to route toward the original IPv6 client */
	struct bpf_fib_lookup fib = {};
	fib.family      = AF_INET6;
	fib.l4_protocol = PROTO_ICMPV6;
	fib.tot_len     = payload_len + 40;
	fib.ifindex     = meta->ingress_ifindex;
	fib.tbid        = meta->routing_table;
	__builtin_memcpy(fib.ipv6_src, router_v6, 16);
	__builtin_memcpy(fib.ipv6_dst, client_v6, 16);

	__u32 fib_flags = meta->routing_table ? BPF_FIB_LOOKUP_TBID : 0;
	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), fib_flags);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS &&
	    rc != BPF_FIB_LKUP_RET_NO_NEIGH)
		return XDP_PASS;

	meta->addr_family = AF_INET6;
	meta->pkt_len = payload_len + 40;

	if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		if (meta->ingress_vlan_id != 0) {
			if (xdp_vlan_tag_push(ctx,
					      meta->ingress_vlan_id) < 0)
				return XDP_DROP;
		}
		return XDP_PASS;
	}

	/* Resolve VLAN sub-interface */
	__u32 egress_if = fib.ifindex;
	struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map,
							 &egress_if);
	if (vi) {
		meta->fwd_ifindex = vi->parent_ifindex;
		meta->egress_vlan_id = vi->vlan_id;
	} else {
		meta->fwd_ifindex = egress_if;
		meta->egress_vlan_id = 0;
	}
	__builtin_memcpy(meta->fwd_dmac, fib.dmac, ETH_ALEN);
	__builtin_memcpy(meta->fwd_smac, fib.smac, ETH_ALEN);

	/* Clear NAT flags — the packet is fully translated, just forward */
	meta->nat_flags = 0;
	meta->meta_flags = 0;

	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	return XDP_PASS;
}

SEC("xdp")
int xdp_nat64_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* NAT64 ICMP error: translate IPv4 ICMP error → IPv6 ICMPv6 */
	if (meta->meta_flags & META_FLAG_NAT64_ICMP_ERR)
		return nat64_icmp_error_4to6(ctx, meta);

	/*
	 * Direction is determined by the original address family:
	 * - AF_INET6 with NAT64 flag → forward (6→4)
	 * - AF_INET with NAT64 flag  → reverse (4→6)
	 */
	if (meta->addr_family == AF_INET6)
		return nat64_xlate_6to4(ctx, meta);
	else
		return nat64_xlate_4to6(ctx, meta);
}

char _license[] SEC("license") = "GPL";
