// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress NAT rewriting stage.
 *
 * Applies NAT translations to egress packets using metadata
 * propagated by tc_conntrack. Uses the same shared rewrite helpers
 * as the XDP NAT stage.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_nat.h"

SEC("tc")
int tc_nat_prog(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return TC_ACT_SHOT;

	if (meta->addr_family == AF_INET)
		nat_rewrite_v4(data, data_end, meta);
	else
		nat_rewrite_v6(data, data_end, meta);

	bpf_tail_call(skb, &tc_progs, TC_PROG_FORWARD);
	return TC_ACT_OK; /* fallthrough = pass */
}

char _license[] SEC("license") = "GPL";
