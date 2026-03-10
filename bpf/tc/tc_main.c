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
#include "../headers/bpfrx_trace.h"

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

	/* Zero from src_port onward — skip src_ip/dst_ip (32 bytes)
	 * which the L3 parser always overwrites. */
	__builtin_memset((__u8 *)meta + 32, 0, sizeof(*meta) - 32);
	meta->direction = 1; /* egress */
	meta->ingress_ifindex = skb->ingress_ifindex;
	meta->dscp_rewrite = 0xFF; /* no DSCP rewrite by default */
	meta->now_sec = (__u32)(bpf_ktime_get_coarse_ns() / 1000000000ULL);
	meta->ktime_ns = 0;

	/* Parse Ethernet header (extract VLAN ID for zone lookup) */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	__u16 eth_proto = bpf_ntohs(eth->h_proto);
	__u16 vlan_id = 0;
	meta->l3_offset = sizeof(struct ethhdr);

	/* Handle one level of VLAN */
	if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
		struct vlan_hdr *vlan = data + sizeof(struct ethhdr);
		if ((void *)(vlan + 1) > data_end)
			return TC_ACT_OK;
		vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
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

	/* Look up egress zone from {ifindex, vlan_id} composite key */
	struct iface_zone_key zk = {
		.ifindex = skb->ifindex,
		.vlan_id = vlan_id,
	};
	struct iface_zone_value *zone_ptr = bpf_map_lookup_elem(&iface_zone_map, &zk);
	if (zone_ptr)
		meta->egress_zone = zone_ptr->zone_id;

	/* Tunnel egress bypass: when the kernel forwards a packet through
	 * a tunnel (GRE, ip6gre, XFRM), TC egress fires on the tunnel
	 * device with the INNER packet before encapsulation.  The XDP
	 * pipeline already validated, conntracked, and NAT'd this traffic.
	 * TC conntrack won't find a session match (post-NAT IPs don't
	 * match pre-NAT session keys), and the ingress_ifindex != 0 drop
	 * would kill the packet.  Pass it through — kernel handles
	 * encapsulation after TC returns. */
	if (zone_ptr && (zone_ptr->flags & IFACE_FLAG_TUNNEL) &&
	    skb->ingress_ifindex != 0) {
		return TC_ACT_OK;
	}

	/* Suppress outgoing MLDv2 reports on RETH member interfaces.
	 * The kernel's IPv6 stack sends periodic MLDv2 listener reports
	 * for multicast groups joined by VIP addresses — unnecessary noise
	 * on a firewall that manages addresses explicitly.
	 * MLDv2 reports go to ff02::16 → Ethernet 33:33:00:00:00:16. */
	if (zone_ptr && zone_ptr->rg_id > 0 &&
	    eth->h_dest[0] == 0x33 && eth->h_dest[1] == 0x33 &&
	    eth->h_dest[2] == 0x00 && eth->h_dest[3] == 0x00 &&
	    eth->h_dest[4] == 0x00 && eth->h_dest[5] == 0x16) {
		return TC_ACT_SHOT;
	}

	TRACE_TC_MAIN(meta);

	/* Tail call to egress screen */
	bpf_tail_call(skb, &tc_progs, TC_PROG_SCREEN_EGRESS);
	return TC_ACT_OK; /* fallthrough = pass */
}

char _license[] SEC("license") = "GPL";
