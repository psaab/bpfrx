// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP forwarding stage.
 *
 * Rewrites Ethernet MAC addresses based on FIB lookup results,
 * decrements TTL/hop_limit, and redirects the packet to the egress
 * interface via XDP_REDIRECT through the devmap.
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Map a packet's protocol/port to the corresponding host-inbound-traffic
 * flag bit. Returns 0 if the service is not recognized (unknown services
 * are allowed through by default).
 */
static __always_inline __u32
host_inbound_flag(struct pkt_meta *meta)
{
	__u8 proto = meta->protocol;

	/* ICMP/ICMPv6 echo request → HOST_INBOUND_PING */
	if (proto == PROTO_ICMP || proto == PROTO_ICMPV6) {
		if (meta->icmp_type == 8 || meta->icmp_type == 128)
			return HOST_INBOUND_PING;
		return 0; /* other ICMP always allowed */
	}

	/* OSPF is IP protocol 89, not port-based */
	if (proto == 89)
		return HOST_INBOUND_OSPF;

	/* TCP/UDP port-based services */
	__u16 port = bpf_ntohs(meta->dst_port);
	switch (port) {
	case 22:           return HOST_INBOUND_SSH;
	case 53:           return HOST_INBOUND_DNS;
	case 80:           return HOST_INBOUND_HTTP;
	case 443:          return HOST_INBOUND_HTTPS;
	case 67: case 68:  return HOST_INBOUND_DHCP;
	case 123:          return HOST_INBOUND_NTP;
	case 161:          return HOST_INBOUND_SNMP;
	case 179:          return HOST_INBOUND_BGP;
	case 23:           return HOST_INBOUND_TELNET;
	case 21:           return HOST_INBOUND_FTP;
	case 830:          return HOST_INBOUND_NETCONF;
	case 514:          return HOST_INBOUND_SYSLOG;
	case 1812: case 1813: return HOST_INBOUND_RADIUS;
	case 500:          return HOST_INBOUND_IKE;
	}

	/* Traceroute: UDP ports 33434-33523 */
	if (proto == PROTO_UDP && port >= 33434 && port <= 33523)
		return HOST_INBOUND_TRACEROUTE;

	return 0; /* unknown service → allow by default */
}

SEC("xdp")
int xdp_forward_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/*
	 * If no egress interface was resolved, the packet is locally
	 * destined. Check host-inbound-traffic policy before passing
	 * to the kernel stack.
	 */
	if (meta->fwd_ifindex == 0) {
		__u32 zone_key = (__u32)meta->ingress_zone;
		struct zone_config *zcfg = bpf_map_lookup_elem(&zone_configs, &zone_key);
		if (zcfg && zcfg->host_inbound_flags != 0) {
			__u32 flag = host_inbound_flag(meta);
			if (flag != 0 && !(zcfg->host_inbound_flags & flag)) {
				inc_counter(GLOBAL_CTR_HOST_INBOUND_DENY);
				return XDP_DROP;
			}
		}
		/* flags==0 means no host-inbound configured → allow all */
		return XDP_PASS;
	}

	/* Rewrite Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	__builtin_memcpy(eth->h_dest, meta->fwd_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, meta->fwd_smac, ETH_ALEN);

	if (meta->addr_family == AF_INET) {
		/* IPv4: Decrement TTL + update IP checksum */
		struct iphdr *iph = data + meta->l3_offset;
		if ((void *)(iph + 1) > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS; /* Let kernel send ICMP Time Exceeded */

		__u16 old_ttl_proto = *(__u16 *)&iph->ttl;
		iph->ttl--;
		__u16 new_ttl_proto = *(__u16 *)&iph->ttl;

		csum_update_2(&iph->check, old_ttl_proto, new_ttl_proto);
	} else {
		/* IPv6: Decrement hop_limit (no checksum update needed) */
		struct ipv6hdr *ip6h = data + meta->l3_offset;
		if ((void *)(ip6h + 1) > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS; /* Let kernel send ICMPv6 Time Exceeded */

		ip6h->hop_limit--;
	}

	/* Increment TX counter */
	inc_counter(GLOBAL_CTR_TX_PACKETS);

	/* Redirect via devmap to egress interface */
	return bpf_redirect_map(&tx_ports, meta->fwd_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
