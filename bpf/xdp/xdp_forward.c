// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP forwarding stage.
 *
 * Rewrites Ethernet MAC addresses based on FIB lookup results,
 * decrements TTL/hop_limit, and redirects the packet to the egress
 * interface via XDP_REDIRECT through the devmap.
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/* host_inbound_flag() is now in bpfrx_helpers.h */

SEC("xdp")
int xdp_forward_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/*
	 * If no egress interface was resolved, the packet is locally
	 * destined. Check host-inbound-traffic policy before passing
	 * to the kernel stack.
	 */
	if (meta->fwd_ifindex == 0) {
		__u32 zone_key = (__u32)meta->ingress_zone;
		struct zone_config *zcfg = bpf_map_lookup_elem(&zone_configs, &zone_key);
		if (zcfg && zcfg->host_inbound_flags != 0) {
			__u32 flag = host_inbound_flag(meta);
			if (flag != 0 && !(zcfg->host_inbound_flags & flag)) {
				inc_counter(GLOBAL_CTR_HOST_INBOUND_DENY);
				return XDP_DROP;
			}
		}
		/* flags==0 means no host-inbound configured → allow all */
		return XDP_PASS;
	}

	/* Push VLAN tag if egress is a VLAN sub-interface */
	if (meta->egress_vlan_id != 0) {
		if (xdp_vlan_tag_push(ctx, meta->egress_vlan_id) < 0)
			return XDP_DROP;
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
	}

	/* Rewrite Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	__builtin_memcpy(eth->h_dest, meta->fwd_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, meta->fwd_smac, ETH_ALEN);

	/* Compute L3 offset: 14 + optional 4-byte VLAN header */
	__u16 l3_off = sizeof(struct ethhdr);
	if (meta->egress_vlan_id != 0)
		l3_off += sizeof(struct vlan_hdr);

	/* Bound l3_offset for verifier */
	if (l3_off >= 64)
		return XDP_DROP;

	if (meta->addr_family == AF_INET) {
		/* IPv4: Decrement TTL + update IP checksum */
		struct iphdr *iph = data + l3_off;
		if ((void *)(iph + 1) > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS; /* Let kernel send ICMP Time Exceeded */

		__u16 old_ttl_proto = *(__u16 *)&iph->ttl;
		iph->ttl--;
		__u16 new_ttl_proto = *(__u16 *)&iph->ttl;

		csum_update_2(&iph->check, old_ttl_proto, new_ttl_proto);
	} else {
		/* IPv6: Decrement hop_limit (no checksum update needed) */
		struct ipv6hdr *ip6h = data + l3_off;
		if ((void *)(ip6h + 1) > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS; /* Let kernel send ICMPv6 Time Exceeded */

		ip6h->hop_limit--;
	}

	/* Increment TX counter and per-interface/zone egress counters */
	inc_counter(GLOBAL_CTR_TX_PACKETS);
	inc_iface_tx(meta->fwd_ifindex, meta->pkt_len);
	inc_zone_egress((__u32)meta->egress_zone, meta->pkt_len);

	/* Redirect via devmap to egress interface */
	return bpf_redirect_map(&tx_ports, meta->fwd_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
