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
	if (meta && meta->egress_zone > 0)
		inc_zone_egress((__u32)meta->egress_zone, meta->pkt_len);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
