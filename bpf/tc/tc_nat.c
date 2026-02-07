// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress NAT stage (stub).
 *
 * Placeholder for future egress NAT rewriting.
 * Currently just tail-calls to the forward stage.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("tc")
int tc_nat_prog(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &tc_progs, TC_PROG_FORWARD);
	return TC_ACT_OK; /* fallthrough = pass */
}

char _license[] SEC("license") = "GPL";
