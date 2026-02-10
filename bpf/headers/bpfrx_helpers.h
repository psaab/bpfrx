#ifndef __BPFRX_HELPERS_H__
#define __BPFRX_HELPERS_H__

#include "bpfrx_common.h"

/* ============================================================
 * Packet parsing helpers
 * ============================================================ */

/* VLAN header for 802.1Q */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/*
 * Parse Ethernet header, handling one level of VLAN tagging.
 * Returns the EtherType of the inner protocol and updates l3_offset.
 * If vlan_id is non-NULL, writes the extracted VLAN ID (0 if untagged).
 */
static __always_inline int
parse_ethhdr(void *data, void *data_end, __u16 *l3_offset, __u16 *eth_proto,
	     __u16 *vlan_id)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	*eth_proto = bpf_ntohs(eth->h_proto);
	*l3_offset = sizeof(struct ethhdr);
	if (vlan_id)
		*vlan_id = 0;

	/* Handle one level of VLAN */
	if (*eth_proto == ETH_P_8021Q || *eth_proto == ETH_P_8021AD) {
		struct vlan_hdr *vlan = data + sizeof(struct ethhdr);
		if ((void *)(vlan + 1) > data_end)
			return -1;
		if (vlan_id)
			*vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
		*eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		*l3_offset += sizeof(struct vlan_hdr);
	}

	return 0;
}

/*
 * Strip 802.1Q VLAN tag from an XDP packet by shifting the Ethernet
 * header 4 bytes forward and shrinking the head.
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int
xdp_vlan_tag_pop(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Save the original Ethernet src/dst MAC and copy them after the shift */
	__u8 dmac[ETH_ALEN];
	__u8 smac[ETH_ALEN];
	__builtin_memcpy(dmac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(smac, eth->h_source, ETH_ALEN);

	/* Move head forward by 4 bytes (VLAN header size) */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)))
		return -1;

	/* Re-read pointers after adjust */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Restore MACs -- the inner EtherType is already in place
	 * because we shifted past the VLAN header. But the MACs were
	 * in the old position, so copy them into the new eth header. */
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);

	return 0;
}

/*
 * Push an 802.1Q VLAN tag onto an XDP packet by growing the head
 * by 4 bytes and inserting the VLAN header.
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int
xdp_vlan_tag_push(struct xdp_md *ctx, __u16 vid)
{
	/* Grow head by 4 bytes */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
		return -1;

	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* The old Ethernet header is at data + 4. Copy MACs from there. */
	struct ethhdr *old_eth = data + sizeof(struct vlan_hdr);
	if ((void *)(old_eth + 1) > data_end)
		return -1;

	__builtin_memcpy(eth->h_dest, old_eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, old_eth->h_source, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_8021Q);

	/* Write VLAN header between Ethernet and inner EtherType */
	struct vlan_hdr *vhdr = data + sizeof(struct ethhdr);
	if ((void *)(vhdr + 1) > data_end)
		return -1;

	vhdr->h_vlan_TCI = bpf_htons(vid);
	vhdr->h_vlan_encapsulated_proto = old_eth->h_proto;

	return 0;
}

/*
 * Parse IPv4 header. Validates version and IHL.
 * Returns 0 on success, populates meta fields.
 */
static __always_inline int
parse_iphdr(void *data, void *data_end, struct pkt_meta *meta)
{
	struct iphdr *iph = data + meta->l3_offset;

	if ((void *)(iph + 1) > data_end)
		return -1;

	if (iph->version != 4)
		return -1;

	__u32 ihl = iph->ihl * 4;
	if (ihl < 20)
		return -1;
	if ((void *)iph + ihl > data_end)
		return -1;

	/* Zero full ip_addr unions before writing v4 */
	__builtin_memset(&meta->src_ip, 0, sizeof(meta->src_ip));
	__builtin_memset(&meta->dst_ip, 0, sizeof(meta->dst_ip));

	meta->src_ip.v4 = iph->saddr;
	meta->dst_ip.v4 = iph->daddr;
	meta->protocol  = iph->protocol;
	meta->ip_ttl    = iph->ttl;
	meta->l4_offset = meta->l3_offset + ihl;
	meta->pkt_len   = bpf_ntohs(iph->tot_len);
	meta->addr_family = AF_INET;

	/* Fragmentation check */
	__u16 frag_off = bpf_ntohs(iph->frag_off);
	meta->is_fragment = (frag_off & 0x2000) || (frag_off & 0x1FFF);

	return 0;
}

/*
 * Parse IPv6 header with extension header chain walking.
 * Returns 0 on success, populates meta fields.
 */
static __always_inline int
parse_ipv6hdr(void *data, void *data_end, struct pkt_meta *meta)
{
	struct ipv6hdr *ip6h = data + meta->l3_offset;

	if ((void *)(ip6h + 1) > data_end)
		return -1;

	if (ip6h->version != 6)
		return -1;

	/* Copy 128-bit addresses */
	__builtin_memcpy(meta->src_ip.v6, &ip6h->saddr, 16);
	__builtin_memcpy(meta->dst_ip.v6, &ip6h->daddr, 16);

	meta->ip_ttl      = ip6h->hop_limit;
	meta->pkt_len     = bpf_ntohs(ip6h->payload_len) + 40;
	meta->addr_family = AF_INET6;
	meta->is_fragment = 0;

	/* Walk extension header chain to find the upper-layer protocol */
	__u8 nexthdr = ip6h->nexthdr;
	__u16 offset = meta->l3_offset + sizeof(struct ipv6hdr);

	#pragma unroll
	for (int i = 0; i < MAX_EXT_HDRS; i++) {
		switch (nexthdr) {
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST: {
			struct ipv6_opt_hdr *opt = data + offset;
			if ((void *)(opt + 1) > data_end)
				return -1;
			nexthdr = opt->nexthdr;
			offset += (opt->hdrlen + 1) * 8;
			break;
		}
		case NEXTHDR_AUTH: {
			struct ipv6_opt_hdr *opt = data + offset;
			if ((void *)(opt + 1) > data_end)
				return -1;
			nexthdr = opt->nexthdr;
			offset += (opt->hdrlen + 2) * 4;
			break;
		}
		case NEXTHDR_FRAGMENT: {
			struct frag_hdr *frag = data + offset;
			if ((void *)(frag + 1) > data_end)
				return -1;
			nexthdr = frag->nexthdr;
			offset += sizeof(struct frag_hdr);
			/* Check MF bit or fragment offset */
			__u16 frag_off = bpf_ntohs(frag->frag_off);
			if ((frag_off & 0x1) || (frag_off & 0xFFF8))
				meta->is_fragment = 1;
			break;
		}
		case NEXTHDR_NONE:
			/* No next header */
			meta->protocol = nexthdr;
			meta->l4_offset = offset;
			return 0;
		default:
			/* Upper-layer protocol found */
			goto done;
		}
	}

done:
	meta->protocol  = nexthdr;
	meta->l4_offset = offset;
	return 0;
}

/*
 * Parse L4 header (TCP, UDP, ICMP, or ICMPv6).
 * Returns 0 on success.
 */
static __always_inline int
parse_l4hdr(void *data, void *data_end, struct pkt_meta *meta)
{
	void *l4 = data + meta->l4_offset;

	switch (meta->protocol) {
	case PROTO_TCP: {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		meta->src_port = tcp->source;
		meta->dst_port = tcp->dest;
		meta->tcp_flags = ((__u8 *)tcp)[13];
		meta->tcp_seq = tcp->seq;
		meta->tcp_ack_seq = tcp->ack_seq;
		meta->payload_offset = meta->l4_offset + tcp->doff * 4;
		break;
	}
	case PROTO_UDP: {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return -1;
		meta->src_port = udp->source;
		meta->dst_port = udp->dest;
		meta->payload_offset = meta->l4_offset + sizeof(struct udphdr);
		break;
	}
	case PROTO_ICMP: {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) > data_end)
			return -1;
		meta->icmp_type = icmp->type;
		meta->icmp_code = icmp->code;
		meta->icmp_id   = icmp->un.echo.id;
		meta->src_port  = icmp->un.echo.id; /* use as port for CT */
		/* For echo req/reply, set dst_port = echo_id so pre-routing
		 * DNAT lookup works for return traffic */
		meta->dst_port  = (icmp->type == 8 || icmp->type == 0) ?
				  icmp->un.echo.id : 0;
		meta->payload_offset = meta->l4_offset + sizeof(struct icmphdr);
		break;
	}
	case PROTO_ICMPV6: {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) > data_end)
			return -1;
		meta->icmp_type = icmp6->icmp6_type;
		meta->icmp_code = icmp6->icmp6_code;
		meta->icmp_id   = icmp6->un.echo.id;
		meta->src_port  = icmp6->un.echo.id; /* use as port for CT */
		/* For echo req/reply, set dst_port = echo_id */
		meta->dst_port  = (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129) ?
				  icmp6->un.echo.id : 0;
		meta->payload_offset = meta->l4_offset + sizeof(struct icmp6hdr);
		break;
	}
	default:
		meta->payload_offset = meta->l4_offset;
		break;
	}

	return 0;
}

/* ============================================================
 * Checksum helpers
 * ============================================================ */

/*
 * Incremental checksum update (RFC 1624) for a 4-byte field change.
 */
static __always_inline void
csum_update_4(__sum16 *csum, __be32 old_val, __be32 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~bpf_ntohl(old_val) & 0xFFFF;
	sum += ~(bpf_ntohl(old_val) >> 16) & 0xFFFF;
	sum += bpf_ntohl(new_val) & 0xFFFF;
	sum += (bpf_ntohl(new_val) >> 16) & 0xFFFF;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/*
 * Incremental checksum update for a 2-byte field change.
 */
static __always_inline void
csum_update_2(__sum16 *csum, __be16 old_val, __be16 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~((__u32)bpf_ntohs(old_val)) & 0xFFFF;
	sum += (__u32)bpf_ntohs(new_val);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/*
 * Incremental checksum update for a 128-bit (IPv6) address change.
 * Processes the address as four 32-bit words.
 */
static __always_inline void
csum_update_16(__sum16 *csum, const __u8 *old_addr, const __u8 *new_addr)
{
	/* Process as four 32-bit words */
	#pragma unroll
	for (int i = 0; i < 4; i++) {
		__be32 old_word, new_word;
		__builtin_memcpy(&old_word, old_addr + i * 4, 4);
		__builtin_memcpy(&new_word, new_addr + i * 4, 4);
		if (old_word != new_word)
			csum_update_4(csum, old_word, new_word);
	}
}

/* ============================================================
 * IPv6 address comparison helper
 * ============================================================ */

static __always_inline int
ip_addr_eq_v6(const __u8 *a, const __u8 *b)
{
	const __u32 *a32 = (const __u32 *)a;
	const __u32 *b32 = (const __u32 *)b;
	return (a32[0] == b32[0]) && (a32[1] == b32[1]) &&
	       (a32[2] == b32[2]) && (a32[3] == b32[3]);
}

/* ============================================================
 * Configurable session timeout lookup (falls back to defaults)
 * ============================================================ */

static __always_inline __u32
ct_get_timeout(__u8 protocol, __u8 state)
{
	__u32 idx;
	switch (protocol) {
	case PROTO_TCP:
		switch (state) {
		case SESS_STATE_ESTABLISHED:
			idx = FLOW_TIMEOUT_TCP_ESTABLISHED;
			break;
		case SESS_STATE_FIN_WAIT:
		case SESS_STATE_CLOSE_WAIT:
			idx = FLOW_TIMEOUT_TCP_CLOSING;
			break;
		case SESS_STATE_TIME_WAIT:
			idx = FLOW_TIMEOUT_TCP_TIME_WAIT;
			break;
		default:
			idx = FLOW_TIMEOUT_TCP_INITIAL;
			break;
		}
		break;
	case PROTO_UDP:
		idx = FLOW_TIMEOUT_UDP;
		break;
	case PROTO_ICMP:
	case PROTO_ICMPV6:
		idx = FLOW_TIMEOUT_ICMP;
		break;
	default:
		idx = FLOW_TIMEOUT_OTHER;
		break;
	}
	__u32 *val = bpf_map_lookup_elem(&flow_timeouts, &idx);
	if (val && *val > 0)
		return *val;
	return ct_get_timeout_default(protocol, state);
}

/* ============================================================
 * Global counter increment helper
 * ============================================================ */

static __always_inline void
inc_counter(__u32 ctr_idx)
{
	__u64 *ctr = bpf_map_lookup_elem(&global_counters, &ctr_idx);
	if (ctr)
		__sync_fetch_and_add(ctr, 1);
}

static __always_inline void
inc_iface_rx(__u32 ifindex, __u32 pkt_len)
{
	struct iface_counter_value *ic = bpf_map_lookup_elem(&interface_counters, &ifindex);
	if (ic) { ic->rx_packets++; ic->rx_bytes += pkt_len; }
}

static __always_inline void
inc_iface_tx(__u32 ifindex, __u32 pkt_len)
{
	struct iface_counter_value *ic = bpf_map_lookup_elem(&interface_counters, &ifindex);
	if (ic) { ic->tx_packets++; ic->tx_bytes += pkt_len; }
}

static __always_inline void
inc_zone_ingress(__u32 zone_id, __u32 pkt_len)
{
	__u32 idx = zone_id * 2;
	struct counter_value *zc = bpf_map_lookup_elem(&zone_counters, &idx);
	if (zc) { zc->packets++; zc->bytes += pkt_len; }
}

static __always_inline void
inc_zone_egress(__u32 zone_id, __u32 pkt_len)
{
	__u32 idx = zone_id * 2 + 1;
	struct counter_value *zc = bpf_map_lookup_elem(&zone_counters, &idx);
	if (zc) { zc->packets++; zc->bytes += pkt_len; }
}

static __always_inline void
inc_policy_counter(__u32 policy_id, __u32 pkt_len)
{
	struct counter_value *pc = bpf_map_lookup_elem(&policy_counters, &policy_id);
	if (pc) { pc->packets++; pc->bytes += pkt_len; }
}

/* ============================================================
 * Ring buffer event emission helper (shared by policy + screen)
 * ============================================================ */

static __always_inline void
emit_event(struct pkt_meta *meta, __u8 event_type, __u8 action,
	   __u64 packets, __u64 bytes)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();

	/* Copy IP addresses based on address family */
	__builtin_memset(evt->src_ip, 0, 16);
	__builtin_memset(evt->dst_ip, 0, 16);

	if (meta->addr_family == AF_INET) {
		__builtin_memcpy(evt->src_ip, &meta->src_ip.v4, 4);
		__builtin_memcpy(evt->dst_ip, &meta->dst_ip.v4, 4);
	} else {
		__builtin_memcpy(evt->src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(evt->dst_ip, meta->dst_ip.v6, 16);
	}

	evt->src_port = meta->src_port;
	evt->dst_port = meta->dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->addr_family = meta->addr_family;
	evt->session_packets = packets;
	evt->session_bytes = bytes;

	bpf_ringbuf_submit(evt, 0);
}

/* ============================================================
 * Host-inbound traffic flag resolution
 *
 * Maps a packet's protocol/port to the corresponding
 * HOST_INBOUND_* flag bit from bpfrx_common.h.
 * Returns 0 for unrecognized services (allowed by default).
 * ============================================================ */
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
	case 546: case 547: return HOST_INBOUND_DHCPV6;
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

#endif /* __BPFRX_HELPERS_H__ */
