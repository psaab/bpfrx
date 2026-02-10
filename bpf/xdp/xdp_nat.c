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

	if (meta->addr_family == AF_INET)
		nat_rewrite_v4(data, data_end, meta);
	else
		nat_rewrite_v6(data, data_end, meta);

	/* Continue to forwarding */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
