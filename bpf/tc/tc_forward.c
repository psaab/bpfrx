// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress forward stage.
 *
 * Final TC stage. Passes the packet to the network.
 * Future phases can add egress screening or counters here.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("tc")
int tc_forward_prog(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
