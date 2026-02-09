// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress main entry point.
 *
 * Parses Ethernet/IPv4/IPv6/L4 headers, populates per-CPU packet metadata,
 * classifies the egress zone, and tail-calls to the TC screen stage.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("tc")
int tc_main_prog(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* Get per-CPU scratch space for packet metadata */
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return TC_ACT_OK;

	__builtin_memset(meta, 0, sizeof(*meta));
	meta->direction = 1; /* egress */

	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	__u16 eth_proto = bpf_ntohs(eth->h_proto);
	meta->l3_offset = sizeof(struct ethhdr);

	/* Handle one level of VLAN */
	if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
		struct vlan_hdr *vlan = data + sizeof(struct ethhdr);
		if ((void *)(vlan + 1) > data_end)
			return TC_ACT_OK;
		eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		meta->l3_offset += sizeof(struct vlan_hdr);
	}

	/* Parse L3 header based on EtherType */
	if (eth_proto == ETH_P_IP) {
		if (parse_iphdr(data, data_end, meta) < 0)
			return TC_ACT_SHOT;
	} else if (eth_proto == 0x86DD) { /* ETH_P_IPV6 */
		if (parse_ipv6hdr(data, data_end, meta) < 0)
			return TC_ACT_SHOT;
	} else {
		return TC_ACT_OK; /* pass non-IP traffic */
	}

	/* Parse L4 header */
	if (!meta->is_fragment) {
		if (parse_l4hdr(data, data_end, meta) < 0)
			return TC_ACT_SHOT;
	}

	/* Increment egress counter and per-interface TX counter */
	inc_counter(GLOBAL_CTR_TC_EGRESS_PACKETS);
	inc_iface_tx(skb->ifindex, meta->pkt_len);

	/* Look up egress zone from outgoing interface */
	__u32 ifindex = skb->ifindex;
	__u16 *zone_ptr = bpf_map_lookup_elem(&iface_zone_map, &ifindex);
	if (zone_ptr)
		meta->egress_zone = *zone_ptr;

	/* Tail call to egress screen */
	bpf_tail_call(skb, &tc_progs, TC_PROG_SCREEN_EGRESS);
	return TC_ACT_OK; /* fallthrough = pass */
}

char _license[] SEC("license") = "GPL";
