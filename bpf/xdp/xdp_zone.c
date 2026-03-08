// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP zone classification stage.
 *
 * Maps the ingress interface to a security zone and performs a FIB
 * lookup to determine the egress interface and egress zone.
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_nat.h"
#include "../headers/bpfrx_trace.h"

#define IPV6_FLOW_CACHE_SLOTS      256
#define IPV6_FLOW_CACHE_BATCH_PKTS 256

struct ipv6_flow_cache_key {
	__be32 src_ip[4];
	__be32 dst_ip[4];
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   pad[3];
};

struct ipv6_flow_cache_entry {
	struct ipv6_flow_cache_key key;
	__u64 last_seen;
	__u64 pending_bytes;
	__u32 policy_id;
	__u32 fwd_ifindex;
	__u32 last_flush;
	__u32 pending_packets;
	__u16 egress_vlan_id;
	__u16 egress_zone;
	__u16 fib_gen;
	__u8  valid;
	__u8  ct_direction;
	__u8  next_prog;
	__u8  count_as_fwd;
	__u8  rewrite_src;
	__u8  nat_flags;
	__u8  pad0[2];
	__u8  rewrite_src_ip[16];
	__be16 rewrite_src_port;
	__u8  fwd_dmac[6];
	__u8  fwd_smac[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, IPV6_FLOW_CACHE_SLOTS);
	__type(key, __u32);
	__type(value, struct ipv6_flow_cache_entry);
} ipv6_flow_cache SEC(".maps");

static __always_inline int
ipv6_flow_cacheable_tcp(struct pkt_meta *meta)
{
	if (meta->addr_family != AF_INET6 || meta->protocol != PROTO_TCP)
		return 0;
	if (!(meta->tcp_flags & 0x10))
		return 0;
	if (meta->tcp_flags & 0x07)
		return 0;
	return 1;
}

static __always_inline int
ipv6_session_cacheable(struct session_value_v6 *sess)
{
	if (!sess || sess->state != SESS_STATE_ESTABLISHED)
		return 0;
	if (sess->flags & (SESS_FLAG_NAT64 | SESS_FLAG_ALG | SESS_FLAG_PREDICTED))
		return 0;
	return 1;
}

static __always_inline __u32
ipv6_flow_cache_slot(struct pkt_meta *meta)
{
	__be32 *src = (__be32 *)meta->src_ip.v6;
	__be32 *dst = (__be32 *)meta->dst_ip.v6;
	__u32 hash = ((__u32)meta->src_port << 16) ^ (__u32)meta->dst_port;

	#pragma unroll
	for (int i = 0; i < 4; i++) {
		hash ^= (__u32)src[i];
		hash ^= ((__u32)dst[i] << ((i & 1) ? 1 : 0));
	}
	hash ^= ((__u32)meta->protocol << 24);
	return hash & (IPV6_FLOW_CACHE_SLOTS - 1);
}

static __always_inline void
fill_ipv6_flow_cache_key(struct ipv6_flow_cache_key *key, struct pkt_meta *meta)
{
	__builtin_memcpy(key->src_ip, meta->src_ip.v6, 16);
	__builtin_memcpy(key->dst_ip, meta->dst_ip.v6, 16);
	key->src_port = meta->src_port;
	key->dst_port = meta->dst_port;
	key->protocol = meta->protocol;
}

static __always_inline int
ipv6_flow_cache_match(struct ipv6_flow_cache_entry *entry,
		      struct pkt_meta *meta)
{
	__be32 *src = (__be32 *)meta->src_ip.v6;
	__be32 *dst = (__be32 *)meta->dst_ip.v6;

	if (!entry->valid)
		return 0;
	if (entry->key.src_port != meta->src_port ||
	    entry->key.dst_port != meta->dst_port ||
	    entry->key.protocol != meta->protocol)
		return 0;

	#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (entry->key.src_ip[i] != src[i] ||
		    entry->key.dst_ip[i] != dst[i])
			return 0;
	}

	return 1;
}

static __noinline int
flush_ipv6_flow_cache_entry(struct ipv6_flow_cache_entry *entry)
{
	if (!entry->valid || entry->pending_packets == 0)
		return 0;

	struct session_key_v6 key = {};
	__builtin_memcpy(key.src_ip, entry->key.src_ip, 16);
	__builtin_memcpy(key.dst_ip, entry->key.dst_ip, 16);
	key.src_port = entry->key.src_port;
	key.dst_port = entry->key.dst_port;
	key.protocol = entry->key.protocol;

	struct session_value_v6 *sess = bpf_map_lookup_elem(&sessions_v6, &key);
	if (!sess || sess->state != SESS_STATE_ESTABLISHED ||
	    sess->fib_ifindex != entry->fwd_ifindex ||
	    sess->fib_vlan_id != entry->egress_vlan_id ||
	    sess->fib_gen != entry->fib_gen) {
		entry->valid = 0;
		entry->pending_packets = 0;
		entry->pending_bytes = 0;
		return -1;
	}

	if (entry->count_as_fwd) {
		__sync_fetch_and_add(&sess->fwd_packets, entry->pending_packets);
		__sync_fetch_and_add(&sess->fwd_bytes, entry->pending_bytes);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, entry->pending_packets);
		__sync_fetch_and_add(&sess->rev_bytes, entry->pending_bytes);
	}
	if (sess->last_seen != entry->last_seen)
		sess->last_seen = entry->last_seen;

	entry->pending_packets = 0;
	entry->pending_bytes = 0;
	entry->last_flush = (__u32)entry->last_seen;
	inc_counter(GLOBAL_CTR_FLOW_CACHE_FLUSH);
	return 0;
}

static __always_inline void
populate_ipv6_flow_cache(struct ipv6_flow_cache_entry *entry,
			 struct pkt_meta *meta,
			 struct session_value_v6 *sess,
			 __u8 direction,
			 __u32 fib_gen,
			 __u64 now)
{
	int is_fwd = (direction == sess->is_reverse);

	if (entry->valid)
		flush_ipv6_flow_cache_entry(entry);

	__builtin_memset(entry, 0, sizeof(*entry));
	fill_ipv6_flow_cache_key(&entry->key, meta);
	entry->valid = 1;
	entry->ct_direction = direction;
	entry->nat_flags = sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT);
	entry->next_prog = entry->nat_flags ?
		XDP_PROG_NAT : XDP_PROG_FORWARD;
	entry->count_as_fwd = (direction == sess->is_reverse);
	entry->policy_id = sess->policy_id;
	entry->fwd_ifindex = sess->fib_ifindex;
	entry->egress_vlan_id = sess->fib_vlan_id;
	entry->egress_zone = sess->egress_zone;
	entry->fib_gen = (__u16)fib_gen;
	entry->last_seen = now;
	entry->last_flush = (__u32)now;
	__builtin_memcpy(entry->fwd_dmac, sess->fib_dmac, 6);
	__builtin_memcpy(entry->fwd_smac, sess->fib_smac, 6);

	if ((sess->flags & SESS_FLAG_SNAT) && is_fwd) {
		entry->rewrite_src = 1;
		__builtin_memcpy(entry->rewrite_src_ip, sess->nat_src_ip, 16);
		entry->rewrite_src_port = sess->nat_src_port;
	} else if ((sess->flags & SESS_FLAG_DNAT) && !is_fwd) {
		entry->rewrite_src = 1;
		__builtin_memcpy(entry->rewrite_src_ip, sess->nat_dst_ip, 16);
		entry->rewrite_src_port = sess->nat_dst_port;
	}
}

static __always_inline int
try_ipv6_flow_cache(struct xdp_md *ctx, struct pkt_meta *meta,
		    __u32 fib_gen)
{
	if (!ipv6_flow_cacheable_tcp(meta))
		return -1;

	__u32 slot = ipv6_flow_cache_slot(meta);
	struct ipv6_flow_cache_entry *entry =
		bpf_map_lookup_elem(&ipv6_flow_cache, &slot);
	if (!entry || !ipv6_flow_cache_match(entry, meta)) {
		inc_counter(GLOBAL_CTR_FLOW_CACHE_MISS);
		return -1;
	}

	if (entry->fwd_ifindex == 0 ||
	    entry->fib_gen != (__u16)fib_gen ||
	    !check_egress_rg_active(entry->fwd_ifindex, entry->egress_vlan_id)) {
		flush_ipv6_flow_cache_entry(entry);
		entry->valid = 0;
		inc_counter(GLOBAL_CTR_FLOW_CACHE_INVALIDATE);
		return -1;
	}

	__u64 now = meta->now_sec;
	if (entry->pending_packets >= IPV6_FLOW_CACHE_BATCH_PKTS ||
	    entry->last_flush != (__u32)now) {
		if (flush_ipv6_flow_cache_entry(entry) < 0) {
			inc_counter(GLOBAL_CTR_FLOW_CACHE_INVALIDATE);
			return -1;
		}
	}

	entry->pending_packets++;
	entry->pending_bytes += meta->pkt_len;
	entry->last_seen = now;

	meta->ct_state = SESS_STATE_ESTABLISHED;
	meta->ct_direction = entry->ct_direction;
	meta->policy_id = entry->policy_id;
	meta->nat_flags = entry->nat_flags;
	meta->fwd_ifindex = entry->fwd_ifindex;
	meta->egress_vlan_id = entry->egress_vlan_id;
	meta->egress_zone = entry->egress_zone;
	__builtin_memcpy(meta->fwd_dmac, entry->fwd_dmac, 6);
	__builtin_memcpy(meta->fwd_smac, entry->fwd_smac, 6);

	if (entry->rewrite_src) {
		__builtin_memcpy(meta->src_ip.v6, entry->rewrite_src_ip, 16);
		meta->src_port = entry->rewrite_src_port;
	}

	inc_counter(GLOBAL_CTR_FLOW_CACHE_HIT);
	bpf_tail_call(ctx, &xdp_progs, entry->next_prog);
	return XDP_PASS;
}

static __always_inline void
flush_matching_ipv6_flow_cache(struct pkt_meta *meta)
{
	if (meta->addr_family != AF_INET6 || meta->protocol != PROTO_TCP)
		return;

	__u32 slot = ipv6_flow_cache_slot(meta);
	struct ipv6_flow_cache_entry *entry =
		bpf_map_lookup_elem(&ipv6_flow_cache, &slot);
	if (!entry || !ipv6_flow_cache_match(entry, meta))
		return;

	flush_ipv6_flow_cache_entry(entry);
	entry->valid = 0;
}

/*
 * Fast-path conntrack update for established IPv4 sessions.
 * Called when xdp_zone finds a session (for FIB cache), eliminating
 * the duplicate session lookup that xdp_conntrack would perform.
 */
static __always_inline int
zone_ct_update_v4(struct xdp_md *ctx, struct pkt_meta *meta,
		  struct session_value *sess, __u8 direction,
		  struct flow_config *fc)
{
	__u64 now = meta->now_sec;

	/* Don't update last_seen for CLOSED sessions — retransmits
	 * would prevent GC from ever cleaning up the dead session. */
	if (sess->state != SESS_STATE_CLOSED && sess->last_seen != now)
		sess->last_seen = now;

	if (direction == sess->is_reverse) {
		__sync_fetch_and_add(&sess->fwd_packets, 1);
		__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, 1);
		__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
	}

	/* Compute actual packet direction relative to the session.
	 * See handle_ct_hit_v4 in xdp_conntrack for explanation. */
	int is_fwd = (direction == sess->is_reverse);
	__u8 pkt_dir = direction ^ sess->is_reverse;

	if (meta->protocol == PROTO_TCP) {
		__u8 new_state = ct_tcp_update_state(
			sess->state, meta->tcp_flags, pkt_dir);
		/* Suppress RST→CLOSED for ESTABLISHED sessions.
		 * Same fix as xdp_conntrack handle_ct_hit_v4:
		 * without sequence validation, a single spurious
		 * RST permanently kills the stream (all data
		 * XDP_DROP'd, cwnd collapses to 1 MSS).  Forward
		 * the RST but keep session ESTABLISHED unless
		 * rst-invalidate-session is configured. */
		if (new_state == SESS_STATE_CLOSED &&
		    sess->state == SESS_STATE_ESTABLISHED) {
			if (!fc || !(fc->tcp_flags &
				     FLOW_TCP_RST_INVALIDATE))
				new_state = sess->state;
		}
		if (new_state != sess->state) {
			sess->state = new_state;
			__u32 new_timeout = ct_get_timeout(PROTO_TCP, new_state);
			/* Per-app timeout overrides default for
			 * non-closing states (ESTABLISHED, SYN_RECV). */
			if (sess->app_timeout > 0 &&
			    new_state != SESS_STATE_CLOSED &&
			    new_state != SESS_STATE_FIN_WAIT)
				new_timeout = (__u32)sess->app_timeout;
			sess->timeout = new_timeout;
			/* Sync state to paired entry so both entries
			 * share the same TCP state and timeout. */
			struct session_value *paired =
				bpf_map_lookup_elem(&sessions,
						    &sess->reverse_key);
			if (paired) {
				paired->state = new_state;
				paired->timeout = sess->timeout;
				if (new_state != SESS_STATE_CLOSED &&
				    paired->last_seen != now)
					paired->last_seen = now;
			}
		}
	}

	meta->ct_state = sess->state;
	meta->ct_direction = direction;
	meta->policy_id = sess->policy_id;

	if (sess->flags & SESS_FLAG_SNAT) {
		if (is_fwd) {
			meta->src_ip.v4 = sess->nat_src_ip;
			meta->src_port  = sess->nat_src_port;
		}
	}
	if (sess->flags & SESS_FLAG_DNAT) {
		if (!is_fwd) {
			meta->src_ip.v4 = sess->nat_dst_ip;
			meta->src_port  = sess->nat_dst_port;
		}
	}

	__u32 next_prog = XDP_PROG_FORWARD;
	if (sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT))
		next_prog = XDP_PROG_NAT;

	if (sess->state == SESS_STATE_CLOSED) {
		if (meta->tcp_flags & 0x04) {
			bpf_tail_call(ctx, &xdp_progs, next_prog);
			return XDP_PASS;
		}
		if (sess->log_flags & LOG_FLAG_SESSION_CLOSE)
			emit_event_nat4(meta, EVENT_TYPE_SESSION_CLOSE,
					ACTION_DENY,
					sess->fwd_packets, sess->fwd_bytes,
					sess->nat_src_ip, sess->nat_dst_ip,
					sess->nat_src_port, sess->nat_dst_port,
					(__u32)(sess->created & 0xFFFFFFFF),
					sess->rev_packets, sess->rev_bytes,
					sess->app_id, CLOSE_REASON_TIMEOUT);
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	}

	bpf_tail_call(ctx, &xdp_progs, next_prog);
	return XDP_PASS;
}

/*
 * Fast-path conntrack update for established IPv6 sessions.
 */
static __always_inline int
zone_ct_update_v6(struct xdp_md *ctx, struct pkt_meta *meta,
		  struct session_value_v6 *sess, __u8 direction,
		  struct flow_config *fc)
{
	__u64 now = meta->now_sec;

	/* Don't update last_seen for CLOSED sessions — retransmits
	 * would prevent GC from ever cleaning up the dead session. */
	if (sess->state != SESS_STATE_CLOSED && sess->last_seen != now)
		sess->last_seen = now;

	if (direction == sess->is_reverse) {
		__sync_fetch_and_add(&sess->fwd_packets, 1);
		__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
	} else {
		__sync_fetch_and_add(&sess->rev_packets, 1);
		__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
	}

	/* Compute actual packet direction relative to the session.
	 * See handle_ct_hit_v4 in xdp_conntrack for explanation. */
	int is_fwd = (direction == sess->is_reverse);
	__u8 pkt_dir = direction ^ sess->is_reverse;

	if (meta->protocol == PROTO_TCP) {
		__u8 new_state = ct_tcp_update_state(
			sess->state, meta->tcp_flags, pkt_dir);
		/* Suppress RST→CLOSED for ESTABLISHED sessions
		 * (same fix as zone_ct_update_v4 / xdp_conntrack). */
		if (new_state == SESS_STATE_CLOSED &&
		    sess->state == SESS_STATE_ESTABLISHED) {
			if (!fc || !(fc->tcp_flags &
				     FLOW_TCP_RST_INVALIDATE))
				new_state = sess->state;
		}
		if (new_state != sess->state) {
			sess->state = new_state;
			__u32 new_timeout = ct_get_timeout(PROTO_TCP, new_state);
			/* Per-app timeout overrides default for
			 * non-closing states (ESTABLISHED, SYN_RECV). */
			if (sess->app_timeout > 0 &&
			    new_state != SESS_STATE_CLOSED &&
			    new_state != SESS_STATE_FIN_WAIT)
				new_timeout = (__u32)sess->app_timeout;
			sess->timeout = new_timeout;
			/* Sync state to paired entry so both entries
			 * share the same TCP state and timeout. */
			struct session_value_v6 *paired =
				bpf_map_lookup_elem(&sessions_v6,
						    &sess->reverse_key);
			if (paired) {
				paired->state = new_state;
				paired->timeout = sess->timeout;
				if (new_state != SESS_STATE_CLOSED &&
				    paired->last_seen != now)
					paired->last_seen = now;
			}
		}
	}

	meta->ct_state = sess->state;
	meta->ct_direction = direction;
	meta->policy_id = sess->policy_id;
	meta->nat_flags = sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT);

	if (sess->flags & SESS_FLAG_SNAT) {
		if (is_fwd) {
			__builtin_memcpy(meta->src_ip.v6, sess->nat_src_ip, 16);
			meta->src_port = sess->nat_src_port;
		}
	}
	if (sess->flags & SESS_FLAG_DNAT) {
		if (!is_fwd) {
			__builtin_memcpy(meta->src_ip.v6, sess->nat_dst_ip, 16);
			meta->src_port = sess->nat_dst_port;
		}
	}

	/* Propagate NAT64 flag so xdp_nat dispatches to xdp_nat64. */
	if (sess->flags & SESS_FLAG_NAT64)
		meta->nat_flags |= SESS_FLAG_NAT64;

	/* Dispatch to xdp_nat when ANY NAT flag is set — not just when
	 * meta was modified.  Reverse SNAT/DNAT rely on pre-routing
	 * dnat_table rewrites (meta->dst_ip already changed) so
	 * nat_rewrite_v6 must run even though conntrack didn't modify meta.
	 */
	__u32 next_prog = XDP_PROG_FORWARD;
	if (sess->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT))
		next_prog = XDP_PROG_NAT;

	if (sess->state == SESS_STATE_CLOSED) {
		if (meta->tcp_flags & 0x04) {
			bpf_tail_call(ctx, &xdp_progs, next_prog);
			return XDP_PASS;
		}
		if (sess->log_flags & LOG_FLAG_SESSION_CLOSE)
			emit_event_nat6(meta, EVENT_TYPE_SESSION_CLOSE,
					ACTION_DENY,
					sess->fwd_packets, sess->fwd_bytes,
					sess->nat_src_ip, sess->nat_dst_ip,
					sess->nat_src_port, sess->nat_dst_port,
					(__u32)(sess->created & 0xFFFFFFFF),
					sess->rev_packets, sess->rev_bytes,
					sess->app_id, CLOSE_REASON_TIMEOUT);
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	}

	bpf_tail_call(ctx, &xdp_progs, next_prog);
	return XDP_PASS;
}

/*
 * Apply pre-routing DNAT translation to packet headers before
 * fabric redirect.  Pre-routing DNAT (dnat_table lookup) updates
 * meta->dst_ip/port but defers packet header rewrite to xdp_nat.
 * When we fabric-redirect before reaching xdp_nat, the peer
 * receives a packet with post-NAT destination that it can't
 * de-NAT.  This function rewrites the packet destination to
 * match meta so the peer receives the correct addresses
 * matching the synced session.  (dnat_table entries ARE synced
 * via session sync, but the rewrite is still needed because
 * pre-routing DNAT only updates meta, not the packet.)
 */

/* IPv6 path is __noinline to avoid inline code explosion from
 * csum_update_16 (#pragma unroll 4×csum_update_4) × protocol
 * branches × 2 call sites.  Inlining this added +56KB to the
 * object and broke the surrounding IPv4 fast-path codegen. */
static __noinline void
apply_dnat_before_fabric_redirect_v6(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Use parsed offsets — sizeof(struct ethhdr) is wrong for
	 * VLAN-tagged packets (l3 at 18 instead of 14), and ip6h+1
	 * is wrong when IPv6 extension headers are present. */
	if (meta->l3_offset >= 64 || meta->l4_offset >= 192)
		return;
	struct ipv6hdr *ip6h = data + meta->l3_offset;
	if ((void *)(ip6h + 1) > data_end)
		return;
	void *l4 = data + meta->l4_offset;

	/* Don't short-circuit solely on dst IP equality — port-only
	 * DNAT (same IP, different port) still needs L4 rewrite. */
	int need_addr = !ip_addr_eq_v6(meta->dst_ip.v6,
				       (__u8 *)&ip6h->daddr);

	if (need_addr) {
		__u8 old_dst[16];
		__builtin_memcpy(old_dst, &ip6h->daddr, 16);
		nat_update_l4_csum_v6(l4, data_end, meta,
				      old_dst, meta->dst_ip.v6);
		__builtin_memcpy(&ip6h->daddr, meta->dst_ip.v6, 16);
	}

	/* Update L4 destination port.  Skip incremental port checksum
	 * when csum_partial — matches nat_rewrite_v6 behavior. */
	__be16 new_dport = meta->dst_port;
	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) <= data_end && tcp->dest != new_dport) {
			if (!meta->csum_partial)
				csum_update_2(&tcp->check,
					      tcp->dest, new_dport);
			tcp->dest = new_dport;
		}
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) <= data_end && udp->dest != new_dport) {
			if (!meta->csum_partial)
				csum_update_2(&udp->check,
					      udp->dest, new_dport);
			udp->dest = new_dport;
		}
	} else if (meta->protocol == PROTO_ICMPV6) {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) <= data_end &&
		    (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129) &&
		    icmp6->un.echo.id != new_dport) {
			if (!meta->csum_partial)
				csum_update_2(&icmp6->icmp6_cksum,
					      icmp6->un.echo.id,
					      new_dport);
			icmp6->un.echo.id = new_dport;
		}
	}
}

static __always_inline void
apply_dnat_before_fabric_redirect(struct xdp_md *ctx, struct pkt_meta *meta)
{
	if (!(meta->nat_flags & SESS_FLAG_DNAT))
		return;

	/* Resolve deferred IPv6 CHECKSUM_PARTIAL before packet mods. */
	void *rd = (void *)(long)ctx->data;
	void *rde = (void *)(long)ctx->data_end;
	resolve_csum_partial(rd, rde, meta);

	if (meta->addr_family == AF_INET6) {
		apply_dnat_before_fabric_redirect_v6(ctx, meta);
		return;
	}
	if (meta->addr_family != AF_INET)
		return;

	void *_d = (void *)(long)ctx->data;
	void *_de = (void *)(long)ctx->data_end;

	/* Use parsed offsets — sizeof(struct ethhdr) is wrong for
	 * VLAN-tagged packets (l3 at 18 instead of 14), and iph+1
	 * is wrong when IPv4 options are present.
	 * Mask with & 0x3F to narrow var_off for BPF verifier. */
	if (meta->l3_offset >= 64 || meta->l4_offset >= 192)
		return;
	struct iphdr *iph = _d + (meta->l3_offset & 0x3F);
	if ((void *)(iph + 1) > _de)
		return;
	void *l4 = _d + (meta->l4_offset & 0xFF);

	/* Don't short-circuit solely on dst IP equality — port-only
	 * DNAT (same IP, different port) still needs L4 rewrite. */
	int need_addr = (iph->daddr != meta->dst_ip.v4);

	if (need_addr) {
		__be32 old_dst = iph->daddr;
		csum_update_4(&iph->check, old_dst, meta->dst_ip.v4);
		iph->daddr = meta->dst_ip.v4;

		if (!meta->csum_partial) {
			if (meta->protocol == PROTO_TCP) {
				struct tcphdr *tcp = l4;
				if ((void *)(tcp + 1) <= _de)
					csum_update_4(&tcp->check, old_dst,
						      meta->dst_ip.v4);
			} else if (meta->protocol == PROTO_UDP) {
				struct udphdr *udp = l4;
				if ((void *)(udp + 1) <= _de &&
				    udp->check != 0)
					csum_update_4(&udp->check,
						      old_dst,
						      meta->dst_ip.v4);
			}
		}
	}

	/* Update L4 destination port.  Skip incremental L4 port
	 * checksum when csum_partial — matches nat_rewrite_v4(). */
	__be16 new_dport = meta->dst_port;

	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) <= _de && tcp->dest != new_dport) {
			if (!meta->csum_partial)
				csum_update_2(&tcp->check,
					      tcp->dest, new_dport);
			tcp->dest = new_dport;
		}
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) <= _de && udp->dest != new_dport) {
			if (!meta->csum_partial && udp->check != 0)
				csum_update_2(&udp->check,
					      udp->dest,
					      new_dport);
			udp->dest = new_dport;
		}
	} else if (meta->protocol == PROTO_ICMP) {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) <= _de &&
		    icmp->un.echo.id != new_dport) {
			if (!meta->csum_partial)
				csum_update_2(&icmp->checksum,
					      icmp->un.echo.id,
					      new_dport);
			icmp->un.echo.id = new_dport;
		}
	}
}

/*
 * Set up a bpf_fib_lookup struct for a main-table (254) re-lookup.
 * Used by fabric transit paths that need to re-FIB after the initial
 * lookup hit the wrong VRF table.
 */
static __always_inline void
setup_main_table_fib(struct bpf_fib_lookup *fib, struct pkt_meta *meta,
		     struct fabric_fwd_info *ff0,
		     struct fabric_fwd_info *ff1)
{
	__builtin_memset(fib, 0, sizeof(*fib));
	fib->l4_protocol = meta->protocol;
	fib->tot_len     = meta->pkt_len;
	fib->tbid        = 254; /* RT_TABLE_MAIN */
	fib->ifindex     = meta->ingress_ifindex;
	struct fabric_fwd_info *ff_main = fabric_main_fib_peer(ff0, ff1);
	if (ff_main)
		fib->ifindex = ff_main->fib_ifindex;
	if (meta->addr_family == AF_INET) {
		fib->family   = AF_INET;
		fib->ipv4_src = meta->src_ip.v4;
		fib->ipv4_dst = meta->dst_ip.v4;
	} else {
		fib->family = AF_INET6;
		__builtin_memcpy(fib->ipv6_src, meta->src_ip.v6, 16);
		__builtin_memcpy(fib->ipv6_dst, meta->dst_ip.v6, 16);
	}
}

/*
 * Resolve FIB result: translate ifindex to physical interface + VLAN,
 * populate meta forwarding fields, and look up egress zone.
 * Returns the iface_zone_value pointer (NULL if zone not found).
 */
static __always_inline struct iface_zone_value *
resolve_fib_result(struct pkt_meta *meta, struct bpf_fib_lookup *fib)
{
	__u32 egress_if = fib->ifindex;
	__u16 egress_vlan = 0;
	struct vlan_iface_info *vi =
		bpf_map_lookup_elem(&vlan_iface_map, &egress_if);
	if (vi) {
		egress_if = vi->parent_ifindex;
		egress_vlan = vi->vlan_id;
	}
	meta->fwd_ifindex = egress_if;
	meta->egress_vlan_id = egress_vlan;
	__builtin_memcpy(meta->fwd_dmac, fib->dmac, ETH_ALEN);
	__builtin_memcpy(meta->fwd_smac, fib->smac, ETH_ALEN);

	struct iface_zone_key ezk = {
		.ifindex = egress_if,
		.vlan_id = egress_vlan,
	};
	struct iface_zone_value *ezv =
		bpf_map_lookup_elem(&iface_zone_map, &ezk);
	if (ezv)
		meta->egress_zone = ezv->zone_id;
	return ezv;
}

SEC("xdp")
int xdp_zone_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Single flow_config lookup: passed to zone_ct_update and
	 * reused for allow_embedded_icmp check below. */
	struct flow_config *fc = bpf_map_lookup_elem(&flow_config_map, &zero);

	/* Cache fabric_fwd_info once: reused for zone-encoded MAC check,
	 * fabric ingress detection, and re-FIB non-VRF ifindex overrides. */
	struct fabric_fwd_info *ff_cached =
		bpf_map_lookup_elem(&fabric_fwd, &zero);
	__u32 ff_one = 1;
	struct fabric_fwd_info *ff1_cached =
		bpf_map_lookup_elem(&fabric_fwd, &ff_one);
	int ingress_is_fabric =
		fabric_ingress_match(ctx->ingress_ifindex,
				     ff_cached, ff1_cached);

	/*
	 * VRRP multicast (224.0.0.18, proto 112) — pass to host before zone
	 * lookup.  xdp_main already stripped the VLAN tag for pipeline use;
	 * push it back so the kernel delivers the frame on the correct VLAN
	 * sub-interface (the parent may lack IPv4 config and would silently
	 * drop the multicast).
	 */
	if (meta->addr_family == AF_INET && meta->protocol == PROTO_VRRP &&
	    meta->dst_ip.v4 == bpf_htonl(0xE0000012)) {
		if (meta->ingress_vlan_id != 0)
			xdp_vlan_tag_push(ctx, meta->ingress_vlan_id);
		return XDP_PASS;
	}

	/* Fabric zone-encoded MAC: peer sent a new connection with zone
	 * encoded in source MAC (02:bf:72:fe:00:ZZ).  Decode and use as
	 * ingress zone, skip iface_zone_map lookup. */
	{
		void *zd = (void *)(long)ctx->data;
		void *zde = (void *)(long)ctx->data_end;
		struct ethhdr *zeth = zd;
		if ((void *)(zeth + 1) <= zde &&
		    zeth->h_source[0] == 0x02 &&
		    zeth->h_source[1] == 0xbf &&
		    zeth->h_source[2] == 0x72 &&
		    zeth->h_source[3] == FABRIC_ZONE_MAC_MAGIC) {
			if (ingress_is_fabric) {
				meta->ingress_zone = zeth->h_source[5];
				/* Force main routing table — fabric is
				 * in vrf-mgmt, but the decoded zone's
				 * traffic uses the main table. */
				meta->routing_table = 254; /* RT_TABLE_MAIN */
				inc_zone_ingress(
					(__u32)meta->ingress_zone,
					meta->pkt_len);
				goto zone_resolved;
			}
		}
	}

	/* Zone, tunnel flag, and routing table were already resolved
	 * by xdp_screen (which always runs before xdp_zone).  Skip the
	 * duplicate iface_zone_map HASH lookup; just increment counter. */
	inc_zone_ingress((__u32)meta->ingress_zone, meta->pkt_len);

	/* Mark fabric-ingress traffic so later stages can bypass
	 * policy for sessionless return traffic (the peer already
	 * validated via its policy; session sync hasn't propagated yet).
	 *
	 * Do NOT override routing_table here — locally-destined fabric
	 * traffic (session sync, heartbeat, management) needs the VRF
	 * routing table to resolve correctly (NOT_FWDED).  The routing
	 * table override to main (254) is applied after the session
	 * lookup, only when a synced session exists (forwarded traffic).
	 * Zone-encoded packets already set routing_table=254 above. */
	if (ingress_is_fabric)
		meta->meta_flags |= META_FLAG_FABRIC_FWD;

zone_resolved:
	;

	/*
	 * Pre-routing NAT: check dnat_table before FIB lookup.
	 * This handles both static DNAT entries (from config) and
	 * dynamic SNAT return entries (from xdp_policy).
	 */
	if (meta->addr_family == AF_INET) {
		struct dnat_key dk = {
			.protocol = meta->protocol,
			.dst_ip   = meta->dst_ip.v4,
			.dst_port = meta->dst_port,
		};
		struct dnat_value *dv = bpf_map_lookup_elem(&dnat_table, &dk);
		/* Fallback: try wildcard port (port=0) for IP-only DNAT rules.
		 * Skip when dst_port is already 0 — the lookup would be
		 * identical to the one that just failed. */
		if (!dv && meta->dst_port != 0) {
			struct dnat_key dk_wild = {
				.protocol = meta->protocol,
				.dst_ip   = meta->dst_ip.v4,
				.dst_port = 0,
			};
			dv = bpf_map_lookup_elem(&dnat_table, &dk_wild);
		}
		if (dv) {
			meta->nat_dst_ip.v4 = meta->dst_ip.v4;
			meta->nat_dst_port  = meta->dst_port;
			meta->dst_ip.v4     = dv->new_dst_ip;
			meta->dst_port      = dv->new_dst_port;
			meta->nat_flags    |= SESS_FLAG_DNAT;
			/* ICMP: echo ID is symmetric, set src_port so
			 * conntrack finds session using original echo ID */
			if (meta->protocol == PROTO_ICMP ||
			    meta->protocol == PROTO_ICMPV6)
				meta->src_port = meta->dst_port;
		} else {
			/* Static 1:1 NAT DNAT lookup */
			struct static_nat_key_v4 snk = {
				.ip = meta->dst_ip.v4,
				.direction = STATIC_NAT_DNAT,
			};
			__be32 *sn_dst = bpf_map_lookup_elem(&static_nat_v4, &snk);
			if (sn_dst) {
				meta->nat_dst_ip.v4 = meta->dst_ip.v4;
				meta->nat_dst_port  = meta->dst_port;
				meta->dst_ip.v4     = *sn_dst;
				meta->nat_flags    |= SESS_FLAG_DNAT;
			}
		}
	} else {
		struct dnat_key_v6 dk6 = { .protocol = meta->protocol };
		__builtin_memcpy(dk6.dst_ip, meta->dst_ip.v6, 16);
		dk6.dst_port = meta->dst_port;

		struct dnat_value_v6 *dv6 = bpf_map_lookup_elem(&dnat_table_v6, &dk6);
		/* Fallback: try wildcard port (port=0) for IP-only DNAT rules.
		 * Skip when dst_port is already 0. */
		if (!dv6 && meta->dst_port != 0) {
			struct dnat_key_v6 dk6_wild = { .protocol = meta->protocol };
			__builtin_memcpy(dk6_wild.dst_ip, meta->dst_ip.v6, 16);
			dk6_wild.dst_port = 0;
			dv6 = bpf_map_lookup_elem(&dnat_table_v6, &dk6_wild);
		}
		if (dv6) {
			__builtin_memcpy(meta->nat_dst_ip.v6, meta->dst_ip.v6, 16);
			meta->nat_dst_port = meta->dst_port;
			__builtin_memcpy(meta->dst_ip.v6, dv6->new_dst_ip, 16);
			meta->dst_port     = dv6->new_dst_port;
			meta->nat_flags   |= SESS_FLAG_DNAT;
			/* ICMP: echo ID symmetry for conntrack */
			if (meta->protocol == PROTO_ICMP ||
			    meta->protocol == PROTO_ICMPV6)
				meta->src_port = meta->dst_port;
		} else {
			/* Static 1:1 NAT DNAT lookup (v6) */
			struct static_nat_key_v6 snk6 = { .direction = STATIC_NAT_DNAT };
			__builtin_memcpy(snk6.ip, meta->dst_ip.v6, 16);
			struct static_nat_value_v6 *sn_dst6 = bpf_map_lookup_elem(&static_nat_v6, &snk6);
			if (sn_dst6) {
				__builtin_memcpy(meta->nat_dst_ip.v6, meta->dst_ip.v6, 16);
				meta->nat_dst_port = meta->dst_port;
				__builtin_memcpy(meta->dst_ip.v6, sn_dst6->ip, 16);
				meta->nat_flags |= SESS_FLAG_DNAT;
			} else {
				/* NPTv6 (RFC 6296) inbound: external → internal prefix translation.
				 * Stateless, no L4 checksum update.  Try /64 then /48. */
				struct nptv6_key nk = {};
				nk.direction = NPTV6_INBOUND;
				nk.prefix_len = 64;
				__builtin_memcpy(nk.prefix, meta->dst_ip.v6, 8);
				struct nptv6_value *nv = bpf_map_lookup_elem(&nptv6_rules, &nk);
				if (!nv) {
					__builtin_memset(&nk, 0, sizeof(nk));
					nk.direction = NPTV6_INBOUND;
					nk.prefix_len = 48;
					__builtin_memcpy(nk.prefix, meta->dst_ip.v6, 6);
					nv = bpf_map_lookup_elem(&nptv6_rules, &nk);
				}
				if (nv) {
					__builtin_memcpy(meta->nat_dst_ip.v6, meta->dst_ip.v6, 16);
					meta->nat_dst_port = meta->dst_port;
					nptv6_translate(meta->dst_ip.v6, nv, NPTV6_INBOUND);
					meta->nat_flags |= SESS_FLAG_DNAT | SESS_FLAG_NPTV6;
				}
			}
		}
	}

	/*
	 * Broadcast / multicast → host-bound traffic.
	 * Skip the zone-pair policy pipeline and jump directly to the
	 * forward stage which applies host-inbound-traffic filtering.
	 * Without this, bpf_fib_lookup may match the default route and
	 * send the packet through the policy pipeline where deny-all
	 * would drop it (e.g. DHCP OFFER to 255.255.255.255).
	 */
	if (meta->addr_family == AF_INET) {
		if (meta->dst_ip.v4 == (__be32)0xFFFFFFFF) {
			meta->fwd_ifindex = 0;
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
			return XDP_PASS;
		}
		/* IPv4 multicast: first byte 0xE0-0xEF (224.0.0.0/4) */
		__u8 *ip4b = (__u8 *)&meta->dst_ip.v4;
		if ((ip4b[0] & 0xF0) == 0xE0) {
			meta->fwd_ifindex = 0;
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
			return XDP_PASS;
		}
	} else {
		/* IPv6 multicast: ff00::/8 */
		__u8 *ip6b = (__u8 *)meta->dst_ip.v6;
		if (ip6b[0] == 0xFF) {
			meta->fwd_ifindex = 0;
			bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
			return XDP_PASS;
		}
	}

	/*
	 * DHCP/DHCPv6 unicast responses bypass FIB lookup.
	 * When the zone allows DHCP host-inbound, unicast DHCP replies
	 * (e.g. DHCPOFFER to the offered IP before it's configured)
	 * must reach the host. Without this, bpf_fib_lookup matches
	 * the default route, sending the packet through the policy
	 * pipeline where deny-all drops it.
	 */
	{
		__u32 zone_key = (__u32)meta->ingress_zone;
		struct zone_config *zcfg = bpf_map_lookup_elem(&zone_configs, &zone_key);
		if (zcfg) {
			if (meta->protocol == PROTO_UDP) {
				__u16 dp = bpf_ntohs(meta->dst_port);
				if ((dp == 68 && (zcfg->host_inbound_flags & HOST_INBOUND_DHCP)) ||
				    (dp == 546 && (zcfg->host_inbound_flags & HOST_INBOUND_DHCPV6))) {
					meta->fwd_ifindex = 0;
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
					return XDP_PASS;
				}
			}
		}
	}

	/*
	 * Session lookup for FIB cache + conntrack fast-path.
	 * For established sessions, the egress interface + next-hop MAC
	 * are stable.  When cached, we also perform conntrack updates
	 * here (counters, TCP state, NAT propagation), eliminating the
	 * duplicate session lookup that xdp_conntrack would do.
	 *
	 * Skip for TCP SYN (new connections) — no session exists yet.
	 */
	int is_tcp_syn = (meta->protocol == PROTO_TCP &&
			  (meta->tcp_flags & 0x12) == 0x02);

	struct session_value *sv4 = NULL;
	struct session_value_v6 *sv6 = NULL;
	__u8 ct_direction = 0;
	int skip_cache_v4 = 0;
	int skip_cache_v6 = 0;

	/* Read global FIB generation counter for cache validation */
	__u32 fib_gen = 0;
	__u32 *fib_gen_ptr = bpf_map_lookup_elem(&fib_gen_map, &zero);
	if (fib_gen_ptr)
		fib_gen = *fib_gen_ptr;

	if (!is_tcp_syn && try_ipv6_flow_cache(ctx, meta, fib_gen) >= 0)
		return XDP_PASS;
	if (!is_tcp_syn && meta->addr_family == AF_INET6 &&
	    meta->protocol == PROTO_TCP && !ipv6_flow_cacheable_tcp(meta))
		flush_matching_ipv6_flow_cache(meta);

	if (!is_tcp_syn && meta->addr_family == AF_INET) {
		struct session_key sk = {};
		sk.src_ip   = meta->src_ip.v4;
		sk.dst_ip   = meta->dst_ip.v4;
		sk.src_port = meta->src_port;
		sk.dst_port = meta->dst_port;
		sk.protocol = meta->protocol;

		sv4 = bpf_map_lookup_elem(&sessions, &sk);
		if (!sv4) {
			struct session_key rk;
			ct_reverse_key(&sk, &rk);
			sv4 = bpf_map_lookup_elem(&sessions, &rk);
			if (sv4) ct_direction = 1;
		}
		/* Active/active per-RG: check egress RG BEFORE FIB gen.
		 * When a VIP moves to the peer, routes are removed and
		 * bpf_fib_lookup will fail.  The session's cached egress
		 * interface tells us which RG the traffic belongs to —
		 * if that RG is inactive, redirect to fabric immediately
		 * without needing a (doomed) FIB lookup. */
		if (sv4 && sv4->fib_ifindex != 0 &&
		    !check_egress_rg_active(sv4->fib_ifindex,
					    sv4->fib_vlan_id)) {
			apply_dnat_before_fabric_redirect(ctx, meta);
			int fab_rc = try_fabric_redirect_cached(
				ctx, meta, ff_cached, ff1_cached);
			if (fab_rc >= 0)
				return fab_rc;
			/* Fabric-forwarded + anti-loop: both nodes have
			 * this RG inactive during transition. Don't let
			 * cached fast-path bypass downstream FABRIC_FWD
			 * safety checks; drop cleanly. */
			if (meta->meta_flags & META_FLAG_FABRIC_FWD)
				return XDP_DROP;
			/* Redirect failed (anti-loop/no fabric): force
			 * full FIB path below; cached FIB may point to
			 * an inactive RG and bypass failover guards. */
			skip_cache_v4 = 1;
		}
		if (!skip_cache_v4 && sv4 && sv4->fib_ifindex != 0 &&
		    sv4->fib_gen == (__u16)fib_gen) {
			meta->fwd_ifindex    = sv4->fib_ifindex;
			meta->egress_vlan_id = sv4->fib_vlan_id;
			__builtin_memcpy(meta->fwd_dmac, sv4->fib_dmac, 6);
			__builtin_memcpy(meta->fwd_smac, sv4->fib_smac, 6);
			meta->egress_zone    = sv4->egress_zone;
			return zone_ct_update_v4(ctx, meta, sv4,
						 ct_direction, fc);
		}
	} else if (!is_tcp_syn) {
		struct session_key_v6 sk6 = {};
		__builtin_memcpy(sk6.src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(sk6.dst_ip, meta->dst_ip.v6, 16);
		sk6.src_port = meta->src_port;
		sk6.dst_port = meta->dst_port;
		sk6.protocol = meta->protocol;

		sv6 = bpf_map_lookup_elem(&sessions_v6, &sk6);
		if (!sv6) {
			struct session_key_v6 rk6;
			ct_reverse_key_v6(&sk6, &rk6);
			sv6 = bpf_map_lookup_elem(&sessions_v6, &rk6);
			if (sv6) ct_direction = 1;
		}
		if (sv6 && sv6->fib_ifindex != 0 &&
		    !check_egress_rg_active(sv6->fib_ifindex,
					    sv6->fib_vlan_id)) {
			apply_dnat_before_fabric_redirect(ctx, meta);
			int fab_rc = try_fabric_redirect_cached(
				ctx, meta, ff_cached, ff1_cached);
			if (fab_rc >= 0)
				return fab_rc;
			if (meta->meta_flags & META_FLAG_FABRIC_FWD)
				return XDP_DROP;
			skip_cache_v6 = 1;
		}
		if (!skip_cache_v6 && sv6 && sv6->fib_ifindex != 0 &&
		    sv6->fib_gen == (__u16)fib_gen) {
			if (ipv6_flow_cacheable_tcp(meta) &&
			    ipv6_session_cacheable(sv6)) {
				__u32 slot = ipv6_flow_cache_slot(meta);
				struct ipv6_flow_cache_entry *entry =
					bpf_map_lookup_elem(&ipv6_flow_cache,
							    &slot);
				if (entry)
					populate_ipv6_flow_cache(entry, meta,
								 sv6,
								 ct_direction,
								 fib_gen,
								 meta->now_sec);
			}
			meta->fwd_ifindex    = sv6->fib_ifindex;
			meta->egress_vlan_id = sv6->fib_vlan_id;
			__builtin_memcpy(meta->fwd_dmac, sv6->fib_dmac, 6);
			__builtin_memcpy(meta->fwd_smac, sv6->fib_smac, 6);
			meta->egress_zone    = sv6->egress_zone;
			return zone_ct_update_v6(ctx, meta, sv6,
						 ct_direction, fc);
		}
	}

	/* Fabric-forwarded sessions: override VRF routing table to main (254).
	 * fab0 is in vrf-mgmt (table 999), but forwarded traffic must use
	 * the main table where WAN/LAN routes exist.  Only apply when we
	 * found a synced session — locally-destined fabric traffic (session
	 * sync, heartbeat) must use the VRF table so FIB correctly returns
	 * NOT_FWDED for local addresses.
	 *
	 * NOTE: separate NULL checks — NEVER OR two BPF pointers (verifier
	 * rejects bitwise OR on pointer regs). */
	if (meta->meta_flags & META_FLAG_FABRIC_FWD) {
		if (sv4 != NULL)
			meta->routing_table = 254; /* RT_TABLE_MAIN */
		if (sv6 != NULL)
			meta->routing_table = 254;
	}

	/*
	 * FIB lookup to determine egress interface.
	 * Uses the (possibly translated) dst_ip for routing.
	 */
	struct bpf_fib_lookup fib = {};
	fib.l4_protocol = meta->protocol;
	fib.tot_len     = meta->pkt_len;
	fib.ifindex     = meta->ingress_ifindex;

	/* Use VRF routing table if set by firewall filter (policy-based routing).
	 * Only set tbid if routing_table is non-zero to avoid touching fib
	 * fields unnecessarily. */
	fib.tbid = meta->routing_table;

	/* Zone-decoded packets arrived on fabric (VRF slave).  The kernel's
	 * bpf_fib_lookup still honors l3mdev rules even with BPF_FIB_LOOKUP_TBID,
	 * so using the fabric ifindex as input device causes the lookup to hit
	 * the VRF table instead of the requested main table.  Override with a
	 * non-VRF data-plane ifindex stored in fabric_fwd. */
	if (meta->routing_table == 254) {
		if (ff_cached && ff_cached->fib_ifindex)
			fib.ifindex = ff_cached->fib_ifindex;
		else if (ff1_cached && ff1_cached->fib_ifindex)
			fib.ifindex = ff1_cached->fib_ifindex;
	}

	if (meta->addr_family == AF_INET) {
		fib.family   = AF_INET;
		fib.ipv4_src = meta->src_ip.v4;
		fib.ipv4_dst = meta->dst_ip.v4;
	} else {
		fib.family = AF_INET6;
		__builtin_memcpy(fib.ipv6_src, meta->src_ip.v6, 16);
		__builtin_memcpy(fib.ipv6_dst, meta->dst_ip.v6, 16);
	}

	__u32 fib_flags = 0;
	if (meta->routing_table)
		fib_flags = BPF_FIB_LOOKUP_TBID;
	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), fib_flags);
	TRACE_FIB_RESULT(rc, fib.ifindex);

	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		struct iface_zone_value *ezv = resolve_fib_result(meta, &fib);

		/* Fabric transit auto-forward: post-NAT packets from
		 * peer that went through KERNEL_ROUTE + NAT reversal +
		 * fabric redirect.  These don't match any local session
		 * (addresses are post-NAT) and don't need policy or
		 * conntrack — the peer already validated the traffic.
		 *
		 * DO NOT forward here with the initial FIB result.
		 * When routing_table is not set to 254 (no synced
		 * session), the initial FIB uses the fabric interface's
		 * VRF (vrf-mgmt).  If vrf-mgmt has a default route
		 * (e.g. from DHCP), the FIB resolves to the management
		 * interface — WRONG egress for cross-RG traffic.
		 * Fall through to the re-FIB in table 254 below
		 * (after session handlers) which uses a non-VRF
		 * ifindex for correct main-table resolution. */

		/* Active/active per-RG check: if the egress interface's
		 * RG is not locally active, redirect to fabric peer.
		 * Existing sessions use plain redirect (peer has synced
		 * session with zone info).  New connections use zone-
		 * encoded redirect (peer needs ingress zone for policy). */
		if (ezv && ezv->rg_id > 0) {
			__u32 rg_key = ezv->rg_id;
			__u8 *active = bpf_map_lookup_elem(&rg_active, &rg_key);
			if (!active || !*active) {
				/* Use volatile bool — NEVER let compiler
				 * merge pointer NULL checks into |= on
				 * pointer regs (verifier rejects). */
				volatile int has_session = 0;
				if (sv4 != NULL)
					has_session = 1;
				if (sv6 != NULL)
					has_session = 1;
				if (has_session) {
					apply_dnat_before_fabric_redirect(
						ctx, meta);
					int fab_rc =
						try_fabric_redirect_cached(
							ctx, meta,
							ff_cached, ff1_cached);
					if (fab_rc >= 0)
						return fab_rc;
					/* Fabric-forwarded + anti-loop:
					 * both nodes have this RG inactive
					 * (failback transition window).
					 * KERNEL_ROUTE would SNAT and leak
					 * to kernel, causing TCP damage
					 * (RSTs, cwnd collapse). Drop
					 * cleanly — TCP retransmits recover
					 * after the ~30ms window. */
					if (meta->meta_flags &
					    META_FLAG_FABRIC_FWD)
						return XDP_DROP;
					meta->meta_flags |=
						META_FLAG_KERNEL_ROUTE;
					bpf_tail_call(ctx, &xdp_progs,
						      XDP_PROG_CONNTRACK);
					return XDP_PASS;
				}
				/* New connection: zone-encoded fabric
				 * redirect so peer applies correct
				 * security policy. */
				{
					int fab_rc =
						try_fabric_redirect_with_zone_cached(
							ctx, meta,
							ff_cached, ff1_cached);
					if (fab_rc >= 0)
						return fab_rc;
					/* Anti-loop (arrived on fabric)
					 * — process locally. */
				}
			}
		}

		/*
		 * Hairpin detection for active/active per-RG:
		 * If FIB routes an existing session back out the same
		 * interface it arrived on (e.g. return traffic on WAN
		 * routed back to WAN via default route because the LAN
		 * connected route is missing), try fabric redirect.
		 * The peer has the correct connected route.
		 *
		 * Only check for existing sessions — new connections
		 * don't have this routing mismatch issue.
		 * Skip if packet arrived on fabric (anti-loop covered
		 * by try_fabric_redirect, but avoid the overhead).
		 */
		if (meta->fwd_ifindex == meta->ingress_ifindex &&
		    meta->egress_vlan_id == meta->ingress_vlan_id) {
			if (sv4 != NULL) {
				apply_dnat_before_fabric_redirect(ctx, meta);
				int fab_rc =
					try_fabric_redirect_cached(
						ctx, meta,
						ff_cached, ff1_cached);
				if (fab_rc >= 0)
					return fab_rc;
			}
			if (sv6 != NULL) {
				apply_dnat_before_fabric_redirect(ctx, meta);
				int fab_rc =
					try_fabric_redirect_cached(
						ctx, meta,
						ff_cached, ff1_cached);
				if (fab_rc >= 0)
					return fab_rc;
			}
		}

		/* Populate FIB cache + conntrack fast-path using session
		 * pointer from FIB cache check above (avoids duplicate
		 * session lookup in xdp_conntrack). */
		if (sv4) {
			sv4->fib_ifindex = meta->fwd_ifindex;
			sv4->fib_vlan_id = meta->egress_vlan_id;
			__builtin_memcpy(sv4->fib_dmac, meta->fwd_dmac, 6);
			__builtin_memcpy(sv4->fib_smac, meta->fwd_smac, 6);
			sv4->fib_gen = (__u16)fib_gen;
			return zone_ct_update_v4(ctx, meta, sv4, ct_direction, fc);
		}
		if (sv6) {
			sv6->fib_ifindex = meta->fwd_ifindex;
			sv6->fib_vlan_id = meta->egress_vlan_id;
			__builtin_memcpy(sv6->fib_dmac, meta->fwd_dmac, 6);
			__builtin_memcpy(sv6->fib_smac, meta->fwd_smac, 6);
			sv6->fib_gen = (__u16)fib_gen;
			return zone_ct_update_v6(ctx, meta, sv6, ct_direction, fc);
		}

		/* Plain fabric redirect without local session: the peer
		 * already validated this traffic (e.g. return traffic
		 * for a session not yet synced, or active/active NAT-
		 * reversed replies).  Bypass conntrack + policy — the
		 * peer's pipeline already did full security validation.
		 *
		 * The first FIB lookup used the VRF mgmt table (because
		 * fab0 is a VRF member and no session triggered the
		 * routing_table=254 override).  The VRF mgmt default
		 * route may have matched, giving the wrong egress.
		 * Re-do FIB in the main table (254) for correct routing.
		 * If the re-lookup succeeds, tail-call xdp_forward with
		 * the correct result.  On failure, fall through to
		 * XDP_PASS (kernel handles locally).
		 *
		 * Zone-encoded packets do NOT set FABRIC_FWD, so they
		 * still go through the full conntrack/policy pipeline. */
		if (meta->meta_flags & META_FLAG_FABRIC_FWD) {
			struct bpf_fib_lookup fib2 = {};
			setup_main_table_fib(&fib2, meta,
					     ff_cached, ff1_cached);
			int rc2 = bpf_fib_lookup(ctx, &fib2,
				sizeof(fib2), BPF_FIB_LOOKUP_TBID);
			if (rc2 == BPF_FIB_LKUP_RET_SUCCESS) {
				resolve_fib_result(meta, &fib2);
				bpf_tail_call(ctx, &xdp_progs,
					      XDP_PROG_FORWARD);
			}
			/* Main table FIB failed — drop transit packets
			 * rather than leaking to kernel via XDP_PASS.
			 * Transient route state during RG movement is
			 * expected; retransmit will succeed once routes
			 * converge. */
			inc_counter(GLOBAL_CTR_FABRIC_FWD_DROP);
			return XDP_DROP;
		}

	} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		/*
		 * Route exists but no ARP/NDP entry for the next hop.
		 *
		 * Existing sessions: try fabric redirect — the peer
		 * has the synced session and may have the ARP/NDP entry.
		 * Falls back to conntrack + kernel routing if fabric
		 * is unavailable.
		 *
		 * New connections: XDP_PASS so the kernel resolves
		 * ARP/NDP.  Do NOT fabric-redirect new connections
		 * for NO_NEIGH — the peer also won't have the ARP
		 * entry, and fabric-transit packets with NO_NEIGH
		 * are dropped (anti-loop).  The kernel queues the
		 * packet while ARP resolves, and subsequent packets
		 * (or retransmits) go through the full BPF pipeline
		 * with the ARP entry populated.
		 */
		{
			volatile int nn_has_session = 0;
			if (sv4 != NULL)
				nn_has_session = 1;
			if (sv6 != NULL)
				nn_has_session = 1;
			if (nn_has_session) {
				/* Only fabric-redirect when the egress
				 * RG is NOT locally active.  When active,
				 * the local kernel can resolve ARP/NDP
				 * via KERNEL_ROUTE — the peer likely has
				 * the same NO_NEIGH issue and fabric
				 * redirect just wastes a round-trip. */
				/* Resolve VLAN context for RG active check */
				__u32 nn_egress_if = fib.ifindex;
				__u16 nn_egress_vlan = 0;
				struct vlan_iface_info *nn_vi =
					bpf_map_lookup_elem(&vlan_iface_map,
							    &nn_egress_if);
				if (nn_vi) {
					nn_egress_if = nn_vi->parent_ifindex;
					nn_egress_vlan = nn_vi->vlan_id;
				}
				int nn_egress_active =
					check_egress_rg_active(
						nn_egress_if,
						nn_egress_vlan);
				if (!nn_egress_active) {
					apply_dnat_before_fabric_redirect(
						ctx, meta);
					int fab_rc =
						try_fabric_redirect_cached(
							ctx, meta,
							ff_cached, ff1_cached);
					if (fab_rc >= 0)
						return fab_rc;
				}
			}
		}
		if (sv4 != NULL) {
			if (meta->meta_flags & META_FLAG_FABRIC_FWD)
				return XDP_DROP;
			meta->meta_flags |= META_FLAG_KERNEL_ROUTE;
			bpf_tail_call(ctx, &xdp_progs,
				      XDP_PROG_CONNTRACK);
			return XDP_PASS;
		}
		if (sv6 != NULL) {
			if (meta->meta_flags & META_FLAG_FABRIC_FWD)
				return XDP_DROP;
			meta->meta_flags |= META_FLAG_KERNEL_ROUTE;
			bpf_tail_call(ctx, &xdp_progs,
				      XDP_PROG_CONNTRACK);
			return XDP_PASS;
		}
		/* FABRIC_FWD transit: fabric redirects that failed both
		 * zone-encoded and plain redirect (anti-loop) and have
		 * no local session.  Drop rather than leaking transit
		 * traffic to kernel host path. */
		if (meta->meta_flags & META_FLAG_FABRIC_FWD) {
			inc_counter(GLOBAL_CTR_FABRIC_FWD_DROP);
			return XDP_DROP;
		}
		TRACE_ZONE(meta);
		inc_counter(GLOBAL_CTR_HOST_INBOUND);
		if (meta->ingress_vlan_id != 0) {
			if (xdp_vlan_tag_push(ctx, meta->ingress_vlan_id) < 0)
				return XDP_DROP;
		}
		return XDP_PASS;

	} else {
		/*
		 * FIB lookup failed with a non-SUCCESS, non-NO_NEIGH code.
		 *
		 * NOT_FWDED (rc=4) means packet is locally destined
		 * (heartbeat, control plane) — must XDP_PASS for local
		 * delivery, never fabric-redirect.
		 *
		 * UNREACHABLE/BLACKHOLE/PROHIBIT mean no route exists.
		 * Active/active per-RG: the local node may lack routes
		 * because its WAN/LAN VIP was moved to the peer.
		 * Try fabric cross-chassis redirect for these cases.
		 * Anti-loop: try_fabric_redirect() returns -1 if the
		 * packet arrived on the fabric interface.
		 */
		if (rc == BPF_FIB_LKUP_RET_UNREACHABLE ||
		    rc == BPF_FIB_LKUP_RET_BLACKHOLE ||
		    rc == BPF_FIB_LKUP_RET_PROHIBIT) {
			/* When an existing session is present, skip
			 * fabric redirect here — the packet may need
			 * NAT reversal first (e.g. SNAT reply with
			 * pre-routing dnat_table rewrite in meta but
			 * not yet in the packet header).  Let the
			 * session handler below route through
			 * conntrack → NAT → forward, where xdp_forward
			 * re-checks FIB on the rewritten packet and
			 * does fabric redirect with correct headers. */
			volatile int bh_has_session = 0;
			if (sv4 != NULL)
				bh_has_session = 1;
			if (sv6 != NULL)
				bh_has_session = 1;
			if (!bh_has_session) {
				/* New connection: zone-encoded redirect
				 * preserves ingress zone for policy on
				 * the peer. */
				int fab_rc =
					try_fabric_redirect_with_zone_cached(
						ctx, meta,
						ff_cached, ff1_cached);
				if (fab_rc >= 0)
					return fab_rc;
				/* Plain redirect fallback. */
				fab_rc =
					try_fabric_redirect_cached(
						ctx, meta,
						ff_cached, ff1_cached);
				if (fab_rc >= 0)
					return fab_rc;

				/* Fabric transit forward: the peer
				 * NAT-reversed this traffic and plain-
				 * fabric-redirected it here.  No local
				 * session (not synced yet).  The first
				 * FIB used vrf-mgmt (fab0's VRF — no
				 * routing_table=254 override without a
				 * session) and returned UNREACHABLE.
				 * Re-FIB in main table to find the
				 * correct egress for the de-NAT'd
				 * destination address. */
				if (meta->meta_flags &
				    META_FLAG_FABRIC_FWD) {
					struct bpf_fib_lookup fib3 = {};
					setup_main_table_fib(
						&fib3, meta,
						ff_cached, ff1_cached);
					int rc3 = bpf_fib_lookup(
						ctx, &fib3, sizeof(fib3),
						BPF_FIB_LOOKUP_TBID);
					if (rc3 ==
					    BPF_FIB_LKUP_RET_SUCCESS) {
						resolve_fib_result(
							meta, &fib3);
						bpf_tail_call(
							ctx,
							&xdp_progs,
							XDP_PROG_FORWARD);
					}
					/* Re-FIB failed — drop transit
					 * FABRIC_FWD packets, same as
					 * the SUCCESS path handler. */
					inc_counter(
						GLOBAL_CTR_FABRIC_FWD_DROP);
					return XDP_DROP;
				}
			}
		}
		if (sv4 != NULL) {
			if (meta->meta_flags & META_FLAG_FABRIC_FWD)
				return XDP_DROP;
			meta->meta_flags |= META_FLAG_KERNEL_ROUTE;
			bpf_tail_call(ctx, &xdp_progs,
				      XDP_PROG_CONNTRACK);
			return XDP_PASS;
		}
		if (sv6 != NULL) {
			if (meta->meta_flags & META_FLAG_FABRIC_FWD)
				return XDP_DROP;
			meta->meta_flags |= META_FLAG_KERNEL_ROUTE;
			bpf_tail_call(ctx, &xdp_progs,
				      XDP_PROG_CONNTRACK);
			return XDP_PASS;
		}

		/*
		 * NAT64 reverse: IPv4 return traffic destined to the
		 * firewall's SNAT pool address (a local IP).  Check
		 * nat64_state before treating as host-inbound.
		 */
		if (meta->addr_family == AF_INET) {
			struct nat64_state_key n64k = {
				.src_ip   = meta->src_ip.v4,
				.dst_ip   = meta->dst_ip.v4,
				.src_port = meta->src_port,
				.dst_port = meta->dst_port,
				.protocol = meta->protocol,
			};
			if (bpf_map_lookup_elem(&nat64_state, &n64k)) {
				/* Route through conntrack which sets up
				 * meta for nat64 4→6 translation. */
				bpf_tail_call(ctx, &xdp_progs,
					      XDP_PROG_CONNTRACK);
				return XDP_PASS;
			}
		}

		/*
		 * NAT64 forward: IPv6 packet whose destination matches
		 * a configured NAT64 prefix (e.g. 64:ff9b::/96).
		 * No IPv6 route exists for the prefix so FIB failed.
		 * Do an IPv4 FIB lookup for the embedded v4 address
		 * to resolve the egress interface and zone, then
		 * continue to conntrack (which sets SESS_FLAG_NAT64).
		 */
		if (meta->addr_family == AF_INET6) {
			struct nat64_config *n64 =
				bpf_map_lookup_elem(
					&nat64_prefix_map,
					meta->dst_ip.v6);
			if (n64) {
				/* Extract embedded IPv4 dst from
				 * last 32 bits of the v6 address */
				__be32 *dst32 =
					(__be32 *)meta->dst_ip.v6;
				__be32 v4_dst = dst32[3];

				/* IPv4 FIB lookup for egress zone */
				__builtin_memset(&fib, 0, sizeof(fib));
				fib.family      = AF_INET;
				fib.l4_protocol = meta->protocol;
				fib.tot_len     = meta->pkt_len;
				fib.ifindex     = meta->ingress_ifindex;
				fib.ipv4_dst    = v4_dst;

				rc = bpf_fib_lookup(ctx, &fib,
						    sizeof(fib), 0);
				if (rc == BPF_FIB_LKUP_RET_SUCCESS ||
				    rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
					resolve_fib_result(meta, &fib);
					bpf_tail_call(ctx, &xdp_progs,
						XDP_PROG_CONNTRACK);
					return XDP_PASS;
				}
			}
		}

		/*
		 * ICMP error packets (Dest Unreachable, Time Exceeded,
		 * Param Problem) with a locally-destined outer IP may
		 * relate to a forwarded session whose original packet
		 * was SNAT'd.  Route through conntrack for embedded
		 * packet matching so the error reaches the client.
		 */
		if ((meta->protocol == PROTO_ICMP &&
		     (meta->icmp_type == 3 || meta->icmp_type == 11 ||
		      meta->icmp_type == 12)) ||
		    (meta->protocol == PROTO_ICMPV6 &&
		     (meta->icmp_type == 1 || meta->icmp_type == 3 ||
		      meta->icmp_type == 4))) {
			if (fc && fc->allow_embedded_icmp) {
				bpf_tail_call(ctx, &xdp_progs,
					      XDP_PROG_CONNTRACK);
				return XDP_PASS;
			}
		}

		/* Send to xdp_forward which handles host-inbound
		 * checks and VLAN tag restoration for sub-interfaces. */
		meta->fwd_ifindex = 0;
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
		return XDP_PASS;
	}

	TRACE_ZONE(meta);

	/* Tail call to conntrack for session lookup and policy evaluation */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_CONNTRACK);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
