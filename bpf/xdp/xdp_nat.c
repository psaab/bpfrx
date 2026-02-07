// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP NAT rewriting stage.
 *
 * Reconciles actual packet headers with the desired state in pkt_meta.
 * If meta->src_ip differs from the packet's saddr, rewrite saddr + fix
 * IP and L4 checksums. Same for dst_ip. Then tail-call to forward.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Update L4 (TCP/UDP) checksum for a 4-byte pseudo-header field change.
 * TCP checksum is mandatory; UDP checksum of 0 means "no checksum" and
 * should not be updated.
 */
static __always_inline void
nat_update_l4_csum(void *data, void *data_end, struct pkt_meta *meta,
		   __be32 old_ip, __be32 new_ip)
{
	void *l4 = data + meta->l4_offset;

	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_4(&tcp->check, old_ip, new_ip);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		/* UDP checksum of 0 means unused; don't update */
		if (udp->check != 0)
			csum_update_4(&udp->check, old_ip, new_ip);
	}
}

/*
 * Update L4 checksum for a 2-byte port field change.
 */
static __always_inline void
nat_update_l4_port_csum(void *data, void *data_end, struct pkt_meta *meta,
			__be16 old_port, __be16 new_port)
{
	void *l4 = data + meta->l4_offset;

	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_2(&tcp->check, old_port, new_port);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		if (udp->check != 0)
			csum_update_2(&udp->check, old_port, new_port);
	}
}

SEC("xdp")
int xdp_nat_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	struct iphdr *iph = data + meta->l3_offset;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	/* Source IP rewrite */
	if (meta->src_ip != iph->saddr) {
		__be32 old_src = iph->saddr;
		csum_update_4(&iph->check, old_src, meta->src_ip);
		nat_update_l4_csum(data, data_end, meta, old_src, meta->src_ip);
		iph->saddr = meta->src_ip;
	}

	/* Source port rewrite */
	if (meta->src_port != 0) {
		void *l4 = data + meta->l4_offset;
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->source != meta->src_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							tcp->source, meta->src_port);
				tcp->source = meta->src_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->source != meta->src_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							udp->source, meta->src_port);
				udp->source = meta->src_port;
			}
		}
	}

	/* Destination IP rewrite */
	if (meta->dst_ip != iph->daddr) {
		__be32 old_dst = iph->daddr;
		csum_update_4(&iph->check, old_dst, meta->dst_ip);
		nat_update_l4_csum(data, data_end, meta, old_dst, meta->dst_ip);
		iph->daddr = meta->dst_ip;
	}

	/* Destination port rewrite */
	if (meta->dst_port != 0) {
		void *l4 = data + meta->l4_offset;
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->dest != meta->dst_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							tcp->dest, meta->dst_port);
				tcp->dest = meta->dst_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->dest != meta->dst_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							udp->dest, meta->dst_port);
				udp->dest = meta->dst_port;
			}
		}
	}

	/* Continue to forwarding */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
