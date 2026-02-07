// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP zone classification stage.
 *
 * Maps the ingress interface to a security zone and performs a FIB
 * lookup to determine the egress interface and egress zone.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("xdp")
int xdp_zone_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Look up ingress zone from interface index */
	__u32 ifindex = meta->ingress_ifindex;
	__u16 *zone_id = bpf_map_lookup_elem(&iface_zone_map, &ifindex);
	if (!zone_id) {
		/* Interface not assigned to any zone -- drop */
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	}
	meta->ingress_zone = *zone_id;

	/*
	 * Pre-routing NAT: check dnat_table before FIB lookup.
	 * This handles both static DNAT entries (from config) and
	 * dynamic SNAT return entries (from xdp_policy).
	 */
	struct dnat_key dk = {
		.protocol = meta->protocol,
		.dst_ip   = meta->dst_ip,
		.dst_port = meta->dst_port,
	};
	struct dnat_value *dv = bpf_map_lookup_elem(&dnat_table, &dk);
	if (dv) {
		meta->nat_dst_ip   = meta->dst_ip;    /* save original for session */
		meta->nat_dst_port = meta->dst_port;
		meta->dst_ip       = dv->new_dst_ip;  /* translate for FIB + conntrack */
		meta->dst_port     = dv->new_dst_port;
		meta->nat_flags   |= SESS_FLAG_DNAT;  /* signal pre-routing NAT applied */
	}

	/*
	 * FIB lookup to determine egress interface.
	 * Uses the (possibly translated) dst_ip for routing.
	 */
	struct bpf_fib_lookup fib = {};
	fib.family    = AF_INET;
	fib.l4_protocol = meta->protocol;
	fib.tot_len   = meta->pkt_len;
	fib.ipv4_src  = meta->src_ip;
	fib.ipv4_dst  = meta->dst_ip;
	fib.ifindex   = meta->ingress_ifindex;

	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		/* Store forwarding info */
		meta->fwd_ifindex = fib.ifindex;
		__builtin_memcpy(meta->fwd_dmac, fib.dmac, ETH_ALEN);
		__builtin_memcpy(meta->fwd_smac, fib.smac, ETH_ALEN);

		/* Look up egress zone */
		__u32 egress_if = fib.ifindex;
		__u16 *ez = bpf_map_lookup_elem(&iface_zone_map, &egress_if);
		if (ez)
			meta->egress_zone = *ez;

	} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		/*
		 * Route exists but no neighbor entry (no ARP yet).
		 * Store the ifindex for zone lookup; pass to kernel
		 * to trigger neighbor resolution.
		 */
		meta->fwd_ifindex = fib.ifindex;
		__u32 egress_if = fib.ifindex;
		__u16 *ez = bpf_map_lookup_elem(&iface_zone_map, &egress_if);
		if (ez)
			meta->egress_zone = *ez;

	} else {
		/*
		 * No route or packet is destined locally.
		 * Egress zone stays 0 (unset). Later policy stages
		 * can handle host-inbound traffic.
		 */
		return XDP_PASS;
	}

	/* Tail call to conntrack for session lookup and policy evaluation */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_CONNTRACK);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
