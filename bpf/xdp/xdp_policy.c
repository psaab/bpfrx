// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP policy evaluation stage.
 *
 * Evaluates zone-pair security policies for new connections. On permit,
 * creates dual session entries (forward + reverse) and proceeds to the
 * forward stage. On deny, drops the packet.
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#define BPFRX_NAT_POOLS
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Check whether an IPv4 address matches a policy rule's address_id.
 * address_id == 0 means "any" (always matches).
 */
static __noinline int
addr_matches(__be32 ip, __u32 rule_addr_id)
{
	if (rule_addr_id == 0)
		return 1;

	struct lpm_key_v4 lpm_key = {
		.prefixlen = 32,
		.addr = ip,
	};
	struct addr_value *av = bpf_map_lookup_elem(&address_book_v4, &lpm_key);
	if (!av)
		return 0;

	if (av->address_id == rule_addr_id)
		return 1;

	struct addr_membership_key mkey = {
		.ip = av->address_id,
		.address_id = rule_addr_id,
	};
	if (bpf_map_lookup_elem(&address_membership, &mkey))
		return 1;

	return 0;
}

/*
 * Check whether an IPv6 address matches a policy rule's address_id.
 */
static __noinline int
addr_matches_v6(const __u8 *ip, __u32 rule_addr_id)
{
	if (rule_addr_id == 0)
		return 1;

	struct lpm_key_v6 lpm_key = { .prefixlen = 128 };
	__builtin_memcpy(lpm_key.addr, ip, 16);

	struct addr_value *av = bpf_map_lookup_elem(&address_book_v6, &lpm_key);
	if (!av)
		return 0;

	if (av->address_id == rule_addr_id)
		return 1;

	struct addr_membership_key mkey = {
		.ip = av->address_id,
		.address_id = rule_addr_id,
	};
	if (bpf_map_lookup_elem(&address_membership, &mkey))
		return 1;

	return 0;
}

/*
 * Create dual session entries for a permitted IPv4 connection.
 */
static __always_inline int
create_session(struct pkt_meta *meta, __u32 policy_id, __u8 log,
	       __u8 nat_flags, __be32 nat_src_ip, __be16 nat_src_port,
	       __be32 nat_dst_ip, __be16 nat_dst_port)
{
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;

	struct session_key fwd_key = {};
	fwd_key.src_ip   = meta->src_ip.v4;
	fwd_key.dst_ip   = meta->dst_ip.v4;
	fwd_key.src_port = meta->src_port;
	fwd_key.dst_port = meta->dst_port;
	fwd_key.protocol = meta->protocol;

	struct session_key rev_key;
	ct_reverse_key(&fwd_key, &rev_key);

	__u8 initial_state;
	if (meta->protocol == PROTO_TCP)
		initial_state = SESS_STATE_SYN_SENT;
	else
		initial_state = SESS_STATE_ESTABLISHED;

	__u32 timeout = ct_get_timeout(meta->protocol, initial_state);

	struct session_value fwd_val = {};
	fwd_val.state        = initial_state;
	fwd_val.flags        = nat_flags;
	fwd_val.is_reverse   = 0;
	fwd_val.created      = now;
	fwd_val.last_seen    = now;
	fwd_val.timeout      = timeout;
	fwd_val.policy_id    = policy_id;
	fwd_val.ingress_zone = meta->ingress_zone;
	fwd_val.egress_zone  = meta->egress_zone;
	fwd_val.fwd_packets  = 1;
	fwd_val.fwd_bytes    = meta->pkt_len;
	fwd_val.log_flags    = log;
	fwd_val.reverse_key  = rev_key;
	fwd_val.nat_src_ip   = nat_src_ip;
	fwd_val.nat_src_port = nat_src_port;
	fwd_val.nat_dst_ip   = nat_dst_ip;
	fwd_val.nat_dst_port = nat_dst_port;

	int ret = bpf_map_update_elem(&sessions, &fwd_key, &fwd_val,
				      BPF_NOEXIST);
	if (ret < 0)
		return -1;

	struct session_value rev_val = {};
	rev_val.state        = initial_state;
	rev_val.flags        = nat_flags;
	rev_val.is_reverse   = 1;
	rev_val.created      = now;
	rev_val.last_seen    = now;
	rev_val.timeout      = timeout;
	rev_val.policy_id    = policy_id;
	rev_val.ingress_zone = meta->egress_zone;
	rev_val.egress_zone  = meta->ingress_zone;
	rev_val.log_flags    = log;
	rev_val.reverse_key  = fwd_key;
	rev_val.nat_src_ip   = nat_src_ip;
	rev_val.nat_src_port = nat_src_port;
	rev_val.nat_dst_ip   = nat_dst_ip;
	rev_val.nat_dst_port = nat_dst_port;

	ret = bpf_map_update_elem(&sessions, &rev_key, &rev_val,
				  BPF_NOEXIST);
	if (ret < 0) {
		bpf_map_delete_elem(&sessions, &fwd_key);
		return -1;
	}

	inc_counter(GLOBAL_CTR_SESSIONS_NEW);
	return 0;
}

/*
 * Create dual session entries for a permitted IPv6 connection.
 * Uses session_v6_scratch per-CPU map to avoid stack overflow.
 */
static __always_inline int
create_session_v6(struct pkt_meta *meta, __u32 policy_id, __u8 log,
		  __u8 nat_flags, const __u8 *nat_src_ip, __be16 nat_src_port,
		  const __u8 *nat_dst_ip, __be16 nat_dst_port)
{
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;

	struct session_key_v6 fwd_key = {};
	__builtin_memcpy(fwd_key.src_ip, meta->src_ip.v6, 16);
	__builtin_memcpy(fwd_key.dst_ip, meta->dst_ip.v6, 16);
	fwd_key.src_port = meta->src_port;
	fwd_key.dst_port = meta->dst_port;
	fwd_key.protocol = meta->protocol;

	struct session_key_v6 rev_key;
	ct_reverse_key_v6(&fwd_key, &rev_key);

	__u8 initial_state;
	if (meta->protocol == PROTO_TCP)
		initial_state = SESS_STATE_SYN_SENT;
	else
		initial_state = SESS_STATE_ESTABLISHED;

	__u32 timeout = ct_get_timeout(meta->protocol, initial_state);

	/* Use per-CPU scratch map for fwd_val (index 0) */
	__u32 idx0 = 0;
	struct session_value_v6 *fwd_val = bpf_map_lookup_elem(
		&session_v6_scratch, &idx0);
	if (!fwd_val)
		return -1;

	__builtin_memset(fwd_val, 0, sizeof(*fwd_val));
	fwd_val->state        = initial_state;
	fwd_val->flags        = nat_flags;
	fwd_val->is_reverse   = 0;
	fwd_val->created      = now;
	fwd_val->last_seen    = now;
	fwd_val->timeout      = timeout;
	fwd_val->policy_id    = policy_id;
	fwd_val->ingress_zone = meta->ingress_zone;
	fwd_val->egress_zone  = meta->egress_zone;
	fwd_val->fwd_packets  = 1;
	fwd_val->fwd_bytes    = meta->pkt_len;
	fwd_val->log_flags    = log;
	fwd_val->reverse_key  = rev_key;
	fwd_val->nat_src_port = nat_src_port;
	fwd_val->nat_dst_port = nat_dst_port;
	if (nat_src_ip)
		__builtin_memcpy(fwd_val->nat_src_ip, nat_src_ip, 16);
	if (nat_dst_ip)
		__builtin_memcpy(fwd_val->nat_dst_ip, nat_dst_ip, 16);

	int ret = bpf_map_update_elem(&sessions_v6, &fwd_key, fwd_val,
				      BPF_NOEXIST);
	if (ret < 0)
		return -1;

	/* Use per-CPU scratch map for rev_val (index 1) */
	__u32 idx1 = 1;
	struct session_value_v6 *rev_val = bpf_map_lookup_elem(
		&session_v6_scratch, &idx1);
	if (!rev_val) {
		bpf_map_delete_elem(&sessions_v6, &fwd_key);
		return -1;
	}

	__builtin_memset(rev_val, 0, sizeof(*rev_val));
	rev_val->state        = initial_state;
	rev_val->flags        = nat_flags;
	rev_val->is_reverse   = 1;
	rev_val->created      = now;
	rev_val->last_seen    = now;
	rev_val->timeout      = timeout;
	rev_val->policy_id    = policy_id;
	rev_val->ingress_zone = meta->egress_zone;
	rev_val->egress_zone  = meta->ingress_zone;
	rev_val->log_flags    = log;
	rev_val->reverse_key  = fwd_key;
	rev_val->nat_src_port = nat_src_port;
	rev_val->nat_dst_port = nat_dst_port;
	if (nat_src_ip)
		__builtin_memcpy(rev_val->nat_src_ip, nat_src_ip, 16);
	if (nat_dst_ip)
		__builtin_memcpy(rev_val->nat_dst_ip, nat_dst_ip, 16);

	ret = bpf_map_update_elem(&sessions_v6, &rev_key, rev_val,
				  BPF_NOEXIST);
	if (ret < 0) {
		bpf_map_delete_elem(&sessions_v6, &fwd_key);
		return -1;
	}

	inc_counter(GLOBAL_CTR_SESSIONS_NEW);
	return 0;
}

/*
 * Allocate a NAT IP and port from a pool (IPv4).
 * Returns 0 on success, -1 on failure.
 */
static __noinline int
nat_pool_alloc_v4(__u8 pool_id, __be32 *out_ip, __be16 *out_port)
{
	__u32 pid = pool_id;
	struct nat_pool_config *cfg = bpf_map_lookup_elem(&nat_pool_configs, &pid);
	if (!cfg || cfg->num_ips == 0)
		return -1;

	struct nat_port_counter *ctr = bpf_map_lookup_elem(&nat_port_counters, &pid);
	if (!ctr)
		return -1;

	__u64 val = ctr->counter++;
	__u32 port_range = cfg->port_high - cfg->port_low + 1;
	if (port_range == 0)
		port_range = 1;
	__u16 port = cfg->port_low + (__u16)(val % port_range);
	__u32 ip_idx = (__u32)((val / port_range) % cfg->num_ips);

	__u32 map_idx = pid * MAX_NAT_POOL_IPS_PER_POOL + ip_idx;
	if (map_idx >= MAX_NAT_POOLS * MAX_NAT_POOL_IPS_PER_POOL)
		return -1;
	__be32 *ip = bpf_map_lookup_elem(&nat_pool_ips_v4, &map_idx);
	if (!ip || *ip == 0)
		return -1;

	*out_ip = *ip;
	*out_port = bpf_htons(port);
	return 0;
}

/*
 * Allocate a NAT IP and port from a pool (IPv6).
 * Returns 0 on success, -1 on failure.
 */
static __noinline int
nat_pool_alloc_v6(__u8 pool_id, __u8 *out_ip, __be16 *out_port)
{
	__u32 pid = pool_id;
	struct nat_pool_config *cfg = bpf_map_lookup_elem(&nat_pool_configs, &pid);
	if (!cfg || cfg->num_ips_v6 == 0)
		return -1;

	struct nat_port_counter *ctr = bpf_map_lookup_elem(&nat_port_counters, &pid);
	if (!ctr)
		return -1;

	__u64 val = ctr->counter++;
	__u32 port_range = cfg->port_high - cfg->port_low + 1;
	if (port_range == 0)
		port_range = 1;
	__u16 port = cfg->port_low + (__u16)(val % port_range);
	__u32 ip_idx = (__u32)((val / port_range) % cfg->num_ips_v6);

	__u32 map_idx = pid * MAX_NAT_POOL_IPS_PER_POOL + ip_idx;
	if (map_idx >= MAX_NAT_POOLS * MAX_NAT_POOL_IPS_PER_POOL)
		return -1;
	struct nat_pool_ip_v6 *ip = bpf_map_lookup_elem(&nat_pool_ips_v6, &map_idx);
	if (!ip)
		return -1;

	__builtin_memcpy(out_ip, ip->ip, 16);
	*out_port = bpf_htons(port);
	return 0;
}

/*
 * Send a TCP RST reply for IPv4 REJECT action.
 * Swaps MACs, IPs, ports, sets RST flag, recomputes checksums.
 * Returns XDP_TX to send the packet back out the ingress interface.
 */
static __always_inline int
send_tcp_rst_v4(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Read only MACs from packet (fixed offset, trivial bounds check) */
	if (data + ETH_HLEN > data_end)
		return XDP_DROP;
	__u8 orig_smac[ETH_ALEN], orig_dmac[ETH_ALEN];
	__builtin_memcpy(orig_smac, ((struct ethhdr *)data)->h_source, ETH_ALEN);
	__builtin_memcpy(orig_dmac, ((struct ethhdr *)data)->h_dest, ETH_ALEN);

	/*
	 * Get everything else from meta (map value, no packet access).
	 * For DNAT: use nat_dst_ip (pre-DNAT original) as the RST source.
	 */
	__be32 orig_saddr = meta->src_ip.v4;
	__be32 orig_daddr = (meta->nat_flags & SESS_FLAG_DNAT) ?
		meta->nat_dst_ip.v4 : meta->dst_ip.v4;
	__be16 orig_sport = meta->src_port;
	__be16 orig_dport = (meta->nat_flags & SESS_FLAG_DNAT) ?
		meta->nat_dst_port : meta->dst_port;
	__be32 orig_seq = meta->tcp_seq;
	__be32 orig_ack = meta->tcp_ack_seq;
	int orig_has_ack = meta->tcp_flags & 0x10;
	int orig_has_syn = meta->tcp_flags & 0x02;
	int orig_has_fin = meta->tcp_flags & 0x01;

	/* Payload length from meta offsets (no packet read) */
	__u16 hdr_len = meta->payload_offset - meta->l3_offset;
	__u16 payload_len = 0;
	if (meta->pkt_len > hdr_len)
		payload_len = meta->pkt_len - hdr_len;

	/* Truncate to exactly ETH(14) + IP(20) + TCP(20) = 54 bytes */
	int cur_len = (int)((long)data_end - (long)data);
	int delta = 54 - cur_len;
	if (delta != 0) {
		if (bpf_xdp_adjust_tail(ctx, delta))
			return XDP_DROP;
	}

	/* Re-validate after adjust: single bounds check */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + 54 > data_end)
		return XDP_DROP;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	/* Swap MACs */
	__builtin_memcpy(eth->h_source, orig_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, orig_smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	/* Build IP header on stack, compute checksum, write to packet */
	struct iphdr ip_hdr = {};
	ip_hdr.version  = 4;
	ip_hdr.ihl      = 5;
	ip_hdr.tot_len  = bpf_htons(40);
	ip_hdr.frag_off = bpf_htons(0x4000);
	ip_hdr.ttl      = 64;
	ip_hdr.protocol = PROTO_TCP;
	ip_hdr.saddr    = orig_daddr;
	ip_hdr.daddr    = orig_saddr;

	__u32 csum = 0;
	__u16 *ip16 = (__u16 *)&ip_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		csum += ip16[i];
	csum = (csum >> 16) + (csum & 0xffff);
	csum += csum >> 16;
	ip_hdr.check = ~csum;
	*ip = ip_hdr;

	/* Build TCP header on stack */
	struct tcphdr tcp_hdr = {};
	tcp_hdr.source = orig_dport;
	tcp_hdr.dest   = orig_sport;
	tcp_hdr.doff   = 5;

	if (orig_has_ack) {
		tcp_hdr.rst = 1;
		tcp_hdr.seq = orig_ack;
	} else {
		tcp_hdr.rst = 1;
		tcp_hdr.ack = 1;
		__u32 seg_len = payload_len;
		if (orig_has_syn) seg_len++;
		if (orig_has_fin) seg_len++;
		if (seg_len == 0) seg_len = 1;
		tcp_hdr.ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + seg_len);
	}

	/* TCP checksum from stack */
	struct {
		__be32 saddr;  __be32 daddr;
		__u8 zero;     __u8 proto;   __be16 tcp_len;
	} pseudo = {
		.saddr = ip_hdr.saddr, .daddr = ip_hdr.daddr,
		.proto = PROTO_TCP,    .tcp_len = bpf_htons(20),
	};
	__u32 tcp_csum = 0;
	__u16 *p16 = (__u16 *)&pseudo;
	#pragma unroll
	for (int i = 0; i < 6; i++)
		tcp_csum += p16[i];
	__u16 *t16 = (__u16 *)&tcp_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		tcp_csum += t16[i];
	tcp_csum = (tcp_csum >> 16) + (tcp_csum & 0xffff);
	tcp_csum += tcp_csum >> 16;
	tcp_hdr.check = ~tcp_csum;
	*tcp = tcp_hdr;

	return XDP_TX;
}

/*
 * Send a TCP RST reply for IPv6 REJECT action.
 * Swaps MACs, IPs, ports, sets RST flag, recomputes TCP checksum.
 * Returns XDP_TX to send the packet back out the ingress interface.
 */
static __always_inline int
send_tcp_rst_v6(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Read only MACs from packet */
	if (data + ETH_HLEN > data_end)
		return XDP_DROP;
	__u8 orig_smac[ETH_ALEN], orig_dmac[ETH_ALEN];
	__builtin_memcpy(orig_smac, ((struct ethhdr *)data)->h_source, ETH_ALEN);
	__builtin_memcpy(orig_dmac, ((struct ethhdr *)data)->h_dest, ETH_ALEN);

	/* Get everything from meta (no further packet reads) */
	struct in6_addr orig_saddr, orig_daddr;
	__builtin_memcpy(&orig_saddr, meta->src_ip.v6, 16);
	if (meta->nat_flags & SESS_FLAG_DNAT)
		__builtin_memcpy(&orig_daddr, meta->nat_dst_ip.v6, 16);
	else
		__builtin_memcpy(&orig_daddr, meta->dst_ip.v6, 16);
	__be16 orig_sport = meta->src_port;
	__be16 orig_dport = (meta->nat_flags & SESS_FLAG_DNAT) ?
		meta->nat_dst_port : meta->dst_port;
	__be32 orig_seq = meta->tcp_seq;
	__be32 orig_ack = meta->tcp_ack_seq;
	int orig_has_ack = meta->tcp_flags & 0x10;
	int orig_has_syn = meta->tcp_flags & 0x02;
	int orig_has_fin = meta->tcp_flags & 0x01;

	__u16 hdr_len = meta->payload_offset - meta->l3_offset;
	__u16 payload_len = 0;
	if (meta->pkt_len > hdr_len)
		payload_len = meta->pkt_len - hdr_len;

	/* Truncate to ETH(14) + IPv6(40) + TCP(20) = 74 bytes */
	int cur_len = (int)((long)data_end - (long)data);
	int delta = 74 - cur_len;
	if (delta != 0) {
		if (bpf_xdp_adjust_tail(ctx, delta))
			return XDP_DROP;
	}

	/* Re-validate after adjust */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + 74 > data_end)
		return XDP_DROP;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

	/* Swap MACs + set EtherType */
	__builtin_memcpy(eth->h_source, orig_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, orig_smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Build IPv6 header — write directly, no checksum needed */
	ip6->version = 6;
	ip6->priority = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;
	ip6->payload_len = bpf_htons(20);
	ip6->nexthdr = PROTO_TCP;
	ip6->hop_limit = 64;
	ip6->saddr = orig_daddr;
	ip6->daddr = orig_saddr;

	/* Build TCP header on stack */
	struct tcphdr tcp_hdr = {};
	tcp_hdr.source = orig_dport;
	tcp_hdr.dest   = orig_sport;
	tcp_hdr.doff   = 5;

	if (orig_has_ack) {
		tcp_hdr.rst = 1;
		tcp_hdr.seq = orig_ack;
	} else {
		tcp_hdr.rst = 1;
		tcp_hdr.ack = 1;
		__u32 seg_len = payload_len;
		if (orig_has_syn) seg_len++;
		if (orig_has_fin) seg_len++;
		if (seg_len == 0) seg_len = 1;
		tcp_hdr.ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + seg_len);
	}

	/* TCP checksum: pseudo-header + TCP header, all from stack */
	__u32 tcp_csum = 0;
	__u16 *s16 = (__u16 *)&orig_daddr;
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tcp_csum += s16[i];
	__u16 *d16 = (__u16 *)&orig_saddr;
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tcp_csum += d16[i];
	tcp_csum += bpf_htons(20);
	tcp_csum += bpf_htons(PROTO_TCP);
	__u16 *t16 = (__u16 *)&tcp_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		tcp_csum += t16[i];
	tcp_csum = (tcp_csum >> 16) + (tcp_csum & 0xffff);
	tcp_csum += tcp_csum >> 16;
	tcp_hdr.check = ~tcp_csum;
	*tcp = tcp_hdr;

	return XDP_TX;
}

SEC("xdp")
int xdp_policy_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Build zone-pair key */
	struct zone_pair_key zpk = {
		.from_zone = meta->ingress_zone,
		.to_zone   = meta->egress_zone,
	};

	struct policy_set *ps = bpf_map_lookup_elem(&zone_pair_policies, &zpk);
	if (!ps) {
		/* No zone-pair policy: check global default policy */
		__u32 dp_key = 0;
		__u8 *dp = bpf_map_lookup_elem(&default_policy, &dp_key);
		if (dp && *dp == ACTION_PERMIT) {
			if (meta->addr_family == AF_INET) {
				if (create_session(meta, 0, 0, 0, 0, 0, 0, 0) < 0) {
					inc_counter(GLOBAL_CTR_DROPS);
					return XDP_DROP;
				}
			} else {
				__u8 zero_ip[16] = {};
				if (create_session_v6(meta, 0, 0, 0, zero_ip, 0, zero_ip, 0) < 0) {
					inc_counter(GLOBAL_CTR_DROPS);
					return XDP_DROP;
				}
			}
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
			return XDP_PASS;
		}
		/*
		 * Before denying: check if this is host-inbound traffic.
		 * Host-inbound traffic (DHCP, SSH, ping, etc.) bypasses
		 * zone-pair policies — only the per-zone host-inbound-traffic
		 * flags control what's allowed to the firewall itself.
		 * This handles packets where bpf_fib_lookup routed through
		 * the default gateway instead of recognizing local delivery.
		 */
		{
			__u32 zk = (__u32)meta->ingress_zone;
			struct zone_config *zcfg = bpf_map_lookup_elem(&zone_configs, &zk);
			if (zcfg) {
				__u32 hif = host_inbound_flag(meta);
				if (hif != 0 && (zcfg->host_inbound_flags & hif)) {
					meta->fwd_ifindex = 0;
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
					return XDP_PASS;
				}
			}
		}
		inc_counter(GLOBAL_CTR_POLICY_DENY);
		return XDP_DROP;
	}

	/* Resolve application ID from (protocol, dst_port) */
	__u32 pkt_app_id = 0;
	struct app_key ak = {
		.protocol = meta->protocol,
		.pad = 0,
		.dst_port = meta->dst_port,
	};
	struct app_value *av = bpf_map_lookup_elem(&applications, &ak);
	if (av)
		pkt_app_id = av->app_id;

	/* Iterate policy rules */
	__u32 base_idx = ps->policy_set_id * MAX_RULES_PER_POLICY;
	__u16 num_rules = ps->num_rules;

	#pragma unroll 1
	for (__u32 i = 0; i < MAX_RULES_PER_POLICY; i++) {
		if (i >= num_rules)
			break;

		__u32 rule_idx = base_idx + i;
		struct policy_rule *rule = bpf_map_lookup_elem(
			&policy_rules, &rule_idx);
		if (!rule)
			continue;

		/* Check source address (AF-aware) */
		if (meta->addr_family == AF_INET) {
			if (!addr_matches(meta->src_ip.v4, rule->src_addr_id))
				continue;
		} else {
			if (!addr_matches_v6(meta->src_ip.v6, rule->src_addr_id))
				continue;
		}

		/* Check destination address (AF-aware) */
		if (meta->addr_family == AF_INET) {
			if (!addr_matches(meta->dst_ip.v4, rule->dst_addr_id))
				continue;
		} else {
			if (!addr_matches_v6(meta->dst_ip.v6, rule->dst_addr_id))
				continue;
		}

		/* Check protocol */
		if (rule->protocol != 0 && rule->protocol != meta->protocol)
			continue;

		/* Check destination port range */
		if (rule->dst_port_low != 0 || rule->dst_port_high != 0) {
			__u16 dport = bpf_ntohs(meta->dst_port);
			if (dport < rule->dst_port_low ||
			    dport > rule->dst_port_high)
				continue;
		}

		/* Check application ID */
		if (rule->app_id != 0 && rule->app_id != pkt_app_id)
			continue;

		/* Rule matches! */
		meta->policy_id = rule->rule_id;
		inc_policy_counter(rule->rule_id, meta->pkt_len);

		if (rule->action == ACTION_PERMIT) {
			if (meta->addr_family == AF_INET) {
				/* IPv4 permit path */
				__u8 sess_nat_flags = 0;
				__be32 sess_nat_src_ip = 0, sess_nat_dst_ip = 0;
				__be16 sess_nat_src_port = 0, sess_nat_dst_port = 0;
				__be32 orig_src_ip = meta->src_ip.v4;
				__be16 orig_src_port = meta->src_port;

				/* Static NAT SNAT check (before dynamic SNAT) */
				struct static_nat_key_v4 snk = {
					.ip = meta->src_ip.v4,
					.direction = STATIC_NAT_SNAT,
				};
				__be32 *sn_src = bpf_map_lookup_elem(&static_nat_v4, &snk);
				if (sn_src) {
					sess_nat_flags |= SESS_FLAG_SNAT | SESS_FLAG_STATIC_NAT;
					sess_nat_src_ip = *sn_src;
					sess_nat_src_port = meta->src_port;
				}

				/* Dynamic SNAT (skip if static already matched) */
				if (!(sess_nat_flags & SESS_FLAG_STATIC_NAT)) {
					struct snat_key sk = {
						.from_zone = meta->ingress_zone,
						.to_zone   = meta->egress_zone,
					};
					struct snat_value *sv = NULL;

					/* Iterate SNAT rules for this zone-pair */
					#pragma unroll 1
					for (__u16 ri = 0; ri < MAX_SNAT_RULES_PER_PAIR; ri++) {
						sk.rule_idx = ri;
						struct snat_value *candidate = bpf_map_lookup_elem(&snat_rules, &sk);
						if (!candidate)
							break;
						if (candidate->src_addr_id != 0 &&
						    !addr_matches(meta->src_ip.v4, candidate->src_addr_id))
							continue;
						if (candidate->dst_addr_id != 0 &&
						    !addr_matches(meta->dst_ip.v4, candidate->dst_addr_id))
							continue;
						sv = candidate;
						break;
					}

					if (sv) {
						/*
						 * NAT port collision retry: try dnat_table
						 * insertion first, retry with new allocation
						 * if BPF_NOEXIST fails.
						 */
						int snat_ok = 0;
						__be32 alloc_ip = 0;
						__be16 alloc_port = 0;

						#pragma unroll
						for (int retry = 0; retry < 3; retry++) {
							if (nat_pool_alloc_v4(sv->mode, &alloc_ip, &alloc_port) < 0)
								break;

							struct dnat_key dk = {
								.protocol = meta->protocol,
								.dst_ip   = alloc_ip,
								.dst_port = alloc_port,
							};
							struct dnat_value dv = {
								.new_dst_ip   = orig_src_ip,
								.new_dst_port = orig_src_port,
								.flags        = 0,
							};
							if (bpf_map_update_elem(&dnat_table, &dk, &dv,
										 BPF_NOEXIST) == 0) {
								snat_ok = 1;
								break;
							}
						}

						if (!snat_ok) {
							inc_counter(GLOBAL_CTR_NAT_ALLOC_FAIL);
							return XDP_DROP;
						}

						sess_nat_flags |= SESS_FLAG_SNAT;
						sess_nat_src_ip = alloc_ip;
						sess_nat_src_port = alloc_port;
					}
				}

				/* Check for pre-routing DNAT */
				if (meta->nat_flags & SESS_FLAG_DNAT) {
					sess_nat_flags |= SESS_FLAG_DNAT;
					sess_nat_dst_ip = meta->nat_dst_ip.v4;
					sess_nat_dst_port = meta->nat_dst_port;
				}

				/* Create session with pre-NAT addresses */
				if (create_session(meta, rule->rule_id, rule->log,
						   sess_nat_flags,
						   sess_nat_src_ip, sess_nat_src_port,
						   sess_nat_dst_ip, sess_nat_dst_port) < 0) {
					/* If dynamic SNAT dnat_table entry was created, clean it up */
					if ((sess_nat_flags & SESS_FLAG_SNAT) &&
					    !(sess_nat_flags & SESS_FLAG_STATIC_NAT)) {
						struct dnat_key dk = {
							.protocol = meta->protocol,
							.dst_ip   = sess_nat_src_ip,
							.dst_port = sess_nat_src_port,
						};
						bpf_map_delete_elem(&dnat_table, &dk);
					}
					inc_counter(GLOBAL_CTR_DROPS);
					return XDP_DROP;
				}

				/* Set meta for NAT rewrite (AFTER session creation) */
				if (sess_nat_flags & SESS_FLAG_SNAT) {
					__builtin_memset(&meta->src_ip, 0, sizeof(meta->src_ip));
					meta->src_ip.v4 = sess_nat_src_ip;
					meta->src_port = sess_nat_src_port;
				}

				if (rule->log & LOG_FLAG_SESSION_INIT)
					emit_event(meta, EVENT_TYPE_SESSION_OPEN,
						   ACTION_PERMIT, 0, 0);

				if (sess_nat_flags)
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_NAT);
				else
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
				return XDP_PASS;
			} else {
				/* IPv6 permit path */
				__u8 sess_nat_flags = 0;
				__be16 sess_nat_src_port = 0, sess_nat_dst_port = 0;
				__be16 orig_src_port = meta->src_port;

				/*
				 * NAT64 forward path: allocate IPv4 SNAT address
				 * from the NAT64 source pool and skip regular SNAT.
				 * meta->nat_flags has SESS_FLAG_NAT64 set by xdp_zone.
				 */
				if (meta->nat_flags & SESS_FLAG_NAT64) {
					/* Find the matching NAT64 config to get pool ID */
					__u32 n64_zero = 0;
					__u32 *n64_cnt = bpf_map_lookup_elem(&nat64_count, &n64_zero);
					__u8 pool_id = 0;
					int found_pool = 0;
					if (n64_cnt && *n64_cnt > 0) {
						__u32 cnt = *n64_cnt;
						if (cnt > MAX_NAT64_PREFIXES)
							cnt = MAX_NAT64_PREFIXES;
						__be32 *dst32 = (__be32 *)meta->dst_ip.v6;
						#pragma unroll
						for (__u32 ni = 0; ni < MAX_NAT64_PREFIXES; ni++) {
							if (ni >= cnt) break;
							struct nat64_config *n64 = bpf_map_lookup_elem(&nat64_configs, &ni);
							if (!n64) break;
							if (dst32[0] == n64->prefix[0] &&
							    dst32[1] == n64->prefix[1] &&
							    dst32[2] == n64->prefix[2]) {
								pool_id = n64->snat_pool_id;
								found_pool = 1;
								break;
							}
						}
					}

					if (found_pool) {
						__be32 alloc_v4_ip = 0;
						__be16 alloc_v4_port = 0;
						if (nat_pool_alloc_v4(pool_id, &alloc_v4_ip, &alloc_v4_port) == 0) {
							sess_nat_flags = SESS_FLAG_NAT64 | SESS_FLAG_SNAT;
							sess_nat_src_port = alloc_v4_port;
							/* Store allocated v4 SNAT addr in meta->src_ip
							 * (nat64 stage uses this as the IPv4 source) */
							__builtin_memset(&meta->src_ip, 0, sizeof(meta->src_ip));
							meta->src_ip.v4 = alloc_v4_ip;
							meta->src_port = alloc_v4_port;

							/* Create v6 session with NAT64 flag.
							 * meta->src_ip already has v4 addr in first 4 bytes
							 * (set above), rest zeroed — use it as nat_src. */
							const __u8 *nat_dst_ptr = (meta->nat_flags & SESS_FLAG_DNAT) ?
								meta->nat_dst_ip.v6 : NULL;
							if (create_session_v6(meta, rule->rule_id, rule->log,
									      sess_nat_flags,
									      meta->src_ip.v6, alloc_v4_port,
									      nat_dst_ptr, sess_nat_dst_port) < 0) {
								inc_counter(GLOBAL_CTR_DROPS);
								return XDP_DROP;
							}

							if (rule->log & LOG_FLAG_SESSION_INIT)
								emit_event(meta, EVENT_TYPE_SESSION_OPEN,
									   ACTION_PERMIT, 0, 0);

							bpf_tail_call(ctx, &xdp_progs, XDP_PROG_NAT);
							return XDP_PASS;
						}
						/* Pool alloc failed */
						inc_counter(GLOBAL_CTR_NAT_ALLOC_FAIL);
						return XDP_DROP;
					}
					/* No pool found, drop */
					inc_counter(GLOBAL_CTR_DROPS);
					return XDP_DROP;
				}

				/* Save original src IP */
				__u8 orig_src_ip_save[16];
				__builtin_memcpy(orig_src_ip_save, meta->src_ip.v6, 16);

				/* Allocated SNAT IP for session + dnat_table */
				__u8 alloc_ip_v6[16] = {};
				int have_dynamic_snat = 0;

				/* Static NAT SNAT check (before dynamic SNAT) */
				struct static_nat_key_v6 snk6 = { .direction = STATIC_NAT_SNAT };
				__builtin_memcpy(snk6.ip, meta->src_ip.v6, 16);
				struct static_nat_value_v6 *sn_src6 = bpf_map_lookup_elem(&static_nat_v6, &snk6);
				if (sn_src6) {
					sess_nat_flags |= SESS_FLAG_SNAT | SESS_FLAG_STATIC_NAT;
					__builtin_memcpy(alloc_ip_v6, sn_src6->ip, 16);
					sess_nat_src_port = meta->src_port;
				}

				/* Dynamic SNAT (skip if static already matched) */
				if (!(sess_nat_flags & SESS_FLAG_STATIC_NAT)) {
					struct snat_key sk = {
						.from_zone = meta->ingress_zone,
						.to_zone   = meta->egress_zone,
					};
					struct snat_value_v6 *sv6 = NULL;

					/* Iterate SNAT rules for this zone-pair */
					#pragma unroll 1
					for (__u16 ri = 0; ri < MAX_SNAT_RULES_PER_PAIR; ri++) {
						sk.rule_idx = ri;
						struct snat_value_v6 *candidate = bpf_map_lookup_elem(&snat_rules_v6, &sk);
						if (!candidate)
							break;
						if (candidate->src_addr_id != 0 &&
						    !addr_matches_v6(meta->src_ip.v6, candidate->src_addr_id))
							continue;
						if (candidate->dst_addr_id != 0 &&
						    !addr_matches_v6(meta->dst_ip.v6, candidate->dst_addr_id))
							continue;
						sv6 = candidate;
						break;
					}

					if (sv6) {
						/*
						 * NAT port collision retry with
						 * dnat_table_v6 insertion.
						 */
						int snat_ok = 0;
						__be16 alloc_port = 0;

						#pragma unroll
						for (int retry = 0; retry < 3; retry++) {
							if (nat_pool_alloc_v6(sv6->mode, alloc_ip_v6, &alloc_port) < 0)
								break;

							struct dnat_key_v6 dk6 = {
								.protocol = meta->protocol,
								.dst_port = alloc_port,
							};
							__builtin_memcpy(dk6.dst_ip, alloc_ip_v6, 16);
							struct dnat_value_v6 dv6 = {
								.new_dst_port = orig_src_port,
								.flags        = 0,
							};
							__builtin_memcpy(dv6.new_dst_ip, orig_src_ip_save, 16);
							if (bpf_map_update_elem(&dnat_table_v6, &dk6, &dv6,
										 BPF_NOEXIST) == 0) {
								snat_ok = 1;
								break;
							}
						}

						if (!snat_ok) {
							inc_counter(GLOBAL_CTR_NAT_ALLOC_FAIL);
							return XDP_DROP;
						}

						sess_nat_flags |= SESS_FLAG_SNAT;
						sess_nat_src_port = alloc_port;
						have_dynamic_snat = 1;
					}
				}

				/* Check for pre-routing DNAT */
				if (meta->nat_flags & SESS_FLAG_DNAT) {
					sess_nat_flags |= SESS_FLAG_DNAT;
					sess_nat_dst_port = meta->nat_dst_port;
				}

				/* Pass NAT IPs through alloc_ip_v6 */
				const __u8 *nat_src_ptr = (sess_nat_flags & SESS_FLAG_SNAT) ? alloc_ip_v6 : NULL;
				const __u8 *nat_dst_ptr = (meta->nat_flags & SESS_FLAG_DNAT) ?
					meta->nat_dst_ip.v6 : NULL;

				/* Create session with pre-NAT addresses */
				if (create_session_v6(meta, rule->rule_id, rule->log,
						      sess_nat_flags,
						      nat_src_ptr, sess_nat_src_port,
						      nat_dst_ptr, sess_nat_dst_port) < 0) {
					/* Clean up dnat_table_v6 entry on failure */
					if (have_dynamic_snat) {
						struct dnat_key_v6 dk6 = {
							.protocol = meta->protocol,
							.dst_port = sess_nat_src_port,
						};
						__builtin_memcpy(dk6.dst_ip, alloc_ip_v6, 16);
						bpf_map_delete_elem(&dnat_table_v6, &dk6);
					}
					inc_counter(GLOBAL_CTR_DROPS);
					return XDP_DROP;
				}

				/* Set meta for NAT rewrite (AFTER session creation) */
				if (sess_nat_flags & SESS_FLAG_SNAT) {
					__builtin_memcpy(meta->src_ip.v6, alloc_ip_v6, 16);
					meta->src_port = sess_nat_src_port;
				}

				if (rule->log & LOG_FLAG_SESSION_INIT)
					emit_event(meta, EVENT_TYPE_SESSION_OPEN,
						   ACTION_PERMIT, 0, 0);

				if (sess_nat_flags)
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_NAT);
				else
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
				return XDP_PASS;
			}
		}

		/* DENY or REJECT */
		inc_counter(GLOBAL_CTR_POLICY_DENY);
		if (rule->log)
			emit_event(meta, EVENT_TYPE_POLICY_DENY,
				   rule->action, 0, 0);

		/* REJECT: send TCP RST for TCP traffic */
		if (rule->action == ACTION_REJECT && meta->protocol == PROTO_TCP) {
			if (meta->addr_family == AF_INET)
				return send_tcp_rst_v4(ctx, meta);
			else
				return send_tcp_rst_v6(ctx, meta);
		}
		return XDP_DROP;
	}

	/* No rule matched: apply default action */
	if (ps->default_action == ACTION_PERMIT) {
		if (meta->addr_family == AF_INET) {
			if (create_session(meta, 0, 0, 0, 0, 0, 0, 0) < 0) {
				inc_counter(GLOBAL_CTR_DROPS);
				return XDP_DROP;
			}
		} else {
			__u8 zero_ip[16] = {};
			if (create_session_v6(meta, 0, 0, 0, zero_ip, 0, zero_ip, 0) < 0) {
				inc_counter(GLOBAL_CTR_DROPS);
				return XDP_DROP;
			}
		}
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
		return XDP_PASS;
	}

	/* Default deny */
	inc_counter(GLOBAL_CTR_POLICY_DENY);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
