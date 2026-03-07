// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP NAT rewriting stage.
 *
 * Reconciles actual packet headers with the desired state in pkt_meta.
 * If meta->src_ip differs from the packet's saddr, rewrite saddr + fix
 * checksums. Same for dst_ip. Then tail-call to forward.
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_nat.h"
#include "../headers/bpfrx_trace.h"

SEC("xdp")
int xdp_nat_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/*
	 * TTL check BEFORE NAT rewrite: if TTL would expire after
	 * decrement, XDP_PASS the *original* packet (unmodified IPs
	 * and MACs) so the kernel generates ICMP Time Exceeded with
	 * the correct source/destination addresses.
	 * Only applies to forwarded packets (fwd_ifindex != 0).
	 */
	if (meta->fwd_ifindex != 0) {
		if (meta->addr_family == AF_INET) {
			struct iphdr *iph = data + sizeof(struct ethhdr);
			if ((void *)(iph + 1) <= data_end && iph->ttl <= 1) {
				/* Push ingress VLAN tag back so kernel
				 * delivers to the correct sub-interface. */
				if (meta->ingress_vlan_id != 0)
					xdp_vlan_tag_push(ctx, meta->ingress_vlan_id);
				return XDP_PASS;
			}
		} else {
			struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
			if ((void *)(ip6h + 1) <= data_end && ip6h->hop_limit <= 1) {
				if (meta->ingress_vlan_id != 0)
					xdp_vlan_tag_push(ctx, meta->ingress_vlan_id);
				return XDP_PASS;
			}
		}
	}

	/*
	 * NAT64: if this packet needs IPv6↔IPv4 header translation,
	 * dispatch to the dedicated nat64 program which handles the
	 * full header rewrite + FIB lookup + redirect.
	 */
	if (meta->nat_flags & SESS_FLAG_NAT64) {
		/* For forward (v6→v4): apply regular SNAT rewrite first
		 * (address + port were set by policy), then nat64 does
		 * the header translation. But since nat64 rebuilds the
		 * entire IPv4 header using meta->src_ip, we just need
		 * to make sure meta->src_ip has the SNAT'd v4 address,
		 * which policy already set. */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_NAT64);
		return XDP_PASS;
	}

	/*
	 * CHECKSUM_PARTIAL handling:
	 *
	 * For CHECKSUM_PARTIAL packets, tcp->check contains the
	 * pseudo-header seed: fold(PH).  NAT rewrite updates this
	 * seed for IP changes (pseudo-header fields) but skips port
	 * changes (L4 data that the NIC/kernel will finalize).
	 *
	 * generic_xdp_tx (devmap redirect) bypasses validate_xmit_skb,
	 * so the NIC must finalize via HW TX checksum offload.
	 */

	/* Resolve deferred IPv6 CHECKSUM_PARTIAL before any rewrite. */
	resolve_csum_partial(data, data_end, meta);

	TRACE_NAT_REWRITE(meta, "xdp-pre");

	if (meta->addr_family == AF_INET) {
		nat_rewrite_v4(data, data_end, meta);
		if (meta->meta_flags & META_FLAG_EMBEDDED_ICMP)
			nat_rewrite_embedded_v4(data, data_end, meta);
	} else {
		nat_rewrite_v6(data, data_end, meta);
		if (meta->meta_flags & META_FLAG_EMBEDDED_ICMP)
			nat_rewrite_embedded_v6(data, data_end, meta);
	}

	TRACE_NAT_REWRITE(meta, "xdp-post");

	/* Continue to forwarding */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
