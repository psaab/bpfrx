// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP cpumap entry program.
 *
 * Runs on the target CPU after bpf_redirect_map(&cpu_map, ...).
 * Performs the full packet parse and enters the tail-call pipeline
 * (screen -> zone -> conntrack -> policy -> nat -> forward).
 *
 * This is the same logic as xdp_main's local-processing fallback,
 * but executes on a different CPU to parallelise XDP processing.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_trace.h"

SEC("xdp_cpumap/cpumap_entry")
int xdp_cpumap_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 l3_offset, eth_proto, vlan_id = 0;

	/* Parse Ethernet header (extracts VLAN ID if present) */
	if (parse_ethhdr(data, data_end, &l3_offset, &eth_proto, &vlan_id) < 0)
		return XDP_DROP;

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
		/* Non-IP traffic should not arrive via cpumap,
		 * but pass to kernel just in case. */
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
		return XDP_DROP;

	/* Apply DSCP rewrite if filter term set one */
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

	/* Enter the tail-call pipeline on this CPU */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_SCREEN);

	/* Tail call failed -- pass to kernel stack as fallback */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
