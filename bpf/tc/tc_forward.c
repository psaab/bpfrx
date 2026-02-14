// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress forward stage.
 *
 * Final TC stage. Increments per-zone egress counters and passes
 * the packet to the network.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("tc")
int tc_forward_prog(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return TC_ACT_OK;

	/* Evaluate output firewall filter before forwarding */
	if (evaluate_firewall_filter_output(meta, skb->ifindex) < 0)
		return TC_ACT_SHOT;

	/* Apply DSCP rewrite from output filter.
	 * Use bpf_skb_load/store_bytes to avoid variable-offset packet
	 * access (meta->l3_offset) which the verifier can't track. */
	if (meta->dscp_rewrite != 0xFF) {
		if (meta->addr_family == AF_INET) {
			__u8 old_tos;
			if (bpf_skb_load_bytes(skb,
			    meta->l3_offset + offsetof(struct iphdr, tos),
			    &old_tos, 1) == 0) {
				__u8 new_tos = (meta->dscp_rewrite << 2) |
					       (old_tos & 0x03);
				if (old_tos != new_tos) {
					bpf_l3_csum_replace(skb,
						meta->l3_offset +
						offsetof(struct iphdr, check),
						bpf_htons((__u16)old_tos),
						bpf_htons((__u16)new_tos), 2);
					bpf_skb_store_bytes(skb,
						meta->l3_offset +
						offsetof(struct iphdr, tos),
						&new_tos, 1, 0);
				}
			}
		} else {
			/* IPv6: traffic class spans bytes 0-1 */
			__u8 hdr2[2];
			if (bpf_skb_load_bytes(skb, meta->l3_offset,
			    hdr2, 2) == 0) {
				__u8 old_tc = ((hdr2[0] & 0x0F) << 4) |
					      ((hdr2[1] & 0xF0) >> 4);
				__u8 new_tc = (meta->dscp_rewrite << 2) |
					      (old_tc & 0x03);
				if (old_tc != new_tc) {
					hdr2[0] = (hdr2[0] & 0xF0) |
						  ((new_tc >> 4) & 0x0F);
					hdr2[1] = (new_tc << 4) |
						  (hdr2[1] & 0x0F);
					bpf_skb_store_bytes(skb,
						meta->l3_offset, hdr2, 2, 0);
				}
			}
		}
	}

	if (meta->egress_zone > 0)
		inc_zone_egress((__u32)meta->egress_zone, meta->pkt_len);

	/*
	 * Port mirroring: if xdp_forward set mirror_ifindex (because
	 * the ingress interface has mirroring configured), clone the
	 * packet to the mirror destination interface.
	 * bpf_clone_redirect is available in TC but not XDP, which is
	 * why mirrored traffic falls back to XDP_PASS → kernel fwd → TC.
	 */
	if (meta->mirror_ifindex != 0) {
		__u32 rate = meta->mirror_rate;
		int do_mirror = 1;

		if (rate > 1) {
			/* Simple 1-in-N sampling using a per-CPU counter */
			__u32 mirror_ctr_key = 0;
			__u64 *cnt = bpf_map_lookup_elem(&mirror_counter, &mirror_ctr_key);
			if (cnt) {
				__u64 cur = *cnt;
				__sync_fetch_and_add(cnt, 1);
				if (cur % rate != 0)
					do_mirror = 0;
			}
		}

		if (do_mirror)
			bpf_clone_redirect(skb, meta->mirror_ifindex, 0);

		/* Reset so subsequent packets don't inherit stale state */
		meta->mirror_ifindex = 0;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
