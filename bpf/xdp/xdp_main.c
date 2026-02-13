// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP main entry point.
 *
 * If cpumap is enabled, distributes IP packets across CPUs via
 * BPF_MAP_TYPE_CPUMAP using a 4-tuple hash.  Non-IP traffic and
 * the fallback path (cpumap disabled) are processed locally.
 *
 * The cpumap-attached program (xdp_cpumap.c) performs the full
 * parse-and-pipeline path on the target CPU.
 */

#include "../headers/bpfrx_common.h"
#define BPFRX_NAT_POOLS
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_trace.h"

/*
 * Lightweight 4-tuple hash for CPU selection.
 * Only peeks at IP + L4 port headers — no metadata setup needed.
 */
static __always_inline __u32
hash_packet(void *data, void *data_end, __u16 l3_offset, __u16 eth_proto)
{
	__u32 hash = 0;

	if (eth_proto == ETH_P_IP) {
		struct iphdr *iph = data + l3_offset;
		if ((void *)(iph + 1) > data_end)
			return 0;
		hash = iph->saddr ^ iph->daddr ^ ((__u32)iph->protocol << 16);
		/* Mix in L4 ports for TCP/UDP (non-fragment only) */
		if ((iph->protocol == 6 /* TCP */ ||
		     iph->protocol == 17 /* UDP */) &&
		    !(bpf_ntohs(iph->frag_off) & 0x1FFF)) {
			__u32 *ports = data + l3_offset + (iph->ihl << 2);
			if ((void *)(ports + 1) <= data_end)
				hash ^= *ports;
		}
	} else { /* IPv6 */
		struct ipv6hdr *ip6h = data + l3_offset;
		if ((void *)(ip6h + 1) > data_end)
			return 0;
		hash = ip6h->saddr.u6_addr32[0] ^ ip6h->saddr.u6_addr32[3] ^
		       ip6h->daddr.u6_addr32[0] ^ ip6h->daddr.u6_addr32[3];
		if (ip6h->nexthdr == 6 /* TCP */ ||
		    ip6h->nexthdr == 17 /* UDP */) {
			__u32 *ports = (void *)(ip6h + 1);
			if ((void *)(ports + 1) <= data_end)
				hash ^= *ports;
		}
	}
	return hash;
}

SEC("xdp")
int xdp_main_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 l3_offset, eth_proto, vlan_id = 0;

	/* Parse Ethernet header (extracts VLAN ID if present) */
	if (parse_ethhdr(data, data_end, &l3_offset, &eth_proto, &vlan_id) < 0)
		return XDP_DROP;

	/* ---- cpumap distribution ---- */
	if (eth_proto == ETH_P_IP || eth_proto == 0x86DD) {
		__u32 zero = 0;
		__u32 *ncpus = bpf_map_lookup_elem(&cpumap_available, &zero);
		if (ncpus && *ncpus > 0) {
			__u32 hash = hash_packet(data, data_end,
						 l3_offset, eth_proto);
			__u32 target = hash % *ncpus;
			return bpf_redirect_map(&cpu_map, target, 0);
		}
	}

	/* ---- fallback: cpumap disabled, process locally ---- */

	/* Get per-CPU scratch space for packet metadata */
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Zero from src_port onward — skip src_ip/dst_ip (32 bytes)
	 * which the L3 parser always overwrites. */
	__builtin_memset((__u8 *)meta + 32, 0, sizeof(*meta) - 32);
	meta->direction = 0; /* ingress */
	meta->ingress_ifindex = ctx->ingress_ifindex;
	meta->ingress_vlan_id = vlan_id;
	meta->dscp_rewrite = 0xFF; /* no DSCP rewrite by default */

	/* Strip VLAN tag if present so pipeline sees plain Ethernet */
	if (vlan_id != 0) {
		if (xdp_vlan_tag_pop(ctx) < 0)
			return XDP_DROP;
		/* Re-read pointers after adjust_head */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		l3_offset = sizeof(struct ethhdr);
	}

	meta->l3_offset = l3_offset;

	/* Parse L3 header based on EtherType */
	if (eth_proto == ETH_P_IP) {
		if (parse_iphdr(data, data_end, meta) < 0)
			return XDP_DROP;
	} else if (eth_proto == 0x86DD) { /* ETH_P_IPV6 */
		if (parse_ipv6hdr(data, data_end, meta) < 0)
			return XDP_DROP;
	} else {
		/* Non-IP traffic (ARP, etc.) — pass to kernel.
		 * Restore VLAN tag so kernel delivers to sub-interface. */
		if (vlan_id != 0) {
			if (xdp_vlan_tag_push(ctx, vlan_id) < 0)
				return XDP_DROP;
		}
		return XDP_PASS;
	}

	/* Parse L4 header */
	if (!meta->is_fragment) {
		if (parse_l4hdr(data, data_end, meta) < 0)
			return XDP_DROP;
	}

	/* Evaluate firewall filter (if assigned to this interface) */
	int filt_rc = evaluate_firewall_filter(meta);
	if (filt_rc < 0)
		return XDP_DROP;  /* discard or reject */

	/* Apply DSCP rewrite if filter term set one.
	 * Use constant-offset from eth+1 to satisfy verifier
	 * (variable meta->l3_offset fails range tracking). */
	if (meta->dscp_rewrite != 0xFF) {
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		struct ethhdr *rw_eth = data;
		if ((void *)(rw_eth + 1) > data_end)
			return XDP_DROP;
		if (meta->addr_family == AF_INET) {
			struct iphdr *iph = (void *)(rw_eth + 1);
			if ((void *)(iph + 1) <= data_end) {
				__u8 old_tos = iph->tos;
				__u8 new_tos = (meta->dscp_rewrite << 2) | (old_tos & 0x03);
				if (old_tos != new_tos) {
					__be16 old_w = bpf_htons((__u16)old_tos);
					__be16 new_w = bpf_htons((__u16)new_tos);
					csum_update_2(&iph->check, old_w, new_w);
					iph->tos = new_tos;
					meta->dscp = meta->dscp_rewrite;
				}
			}
		} else {
			/* IPv6: traffic class spans bytes 0-1 of the header */
			struct ipv6hdr *ip6 = (void *)(rw_eth + 1);
			if ((void *)(ip6 + 1) <= data_end) {
				__u8 *hdr = (__u8 *)ip6;
				__u8 old_tc = ((hdr[0] & 0x0F) << 4) | ((hdr[1] & 0xF0) >> 4);
				__u8 new_tc = (meta->dscp_rewrite << 2) | (old_tc & 0x03);
				if (old_tc != new_tc) {
					hdr[0] = (hdr[0] & 0xF0) | ((new_tc >> 4) & 0x0F);
					hdr[1] = (new_tc << 4) | (hdr[1] & 0x0F);
					meta->dscp = meta->dscp_rewrite;
				}
			}
		}
	}

	/* Increment global RX counter and per-interface RX counter */
	inc_counter(GLOBAL_CTR_RX_PACKETS);
	inc_iface_rx(meta->ingress_ifindex, meta->pkt_len);

	TRACE_XDP_MAIN(meta);

	/* Dispatch to pipeline: screen -> zone -> conntrack -> policy -> nat -> forward */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_SCREEN);

	/* Tail call failed -- pass to kernel stack as fallback */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
