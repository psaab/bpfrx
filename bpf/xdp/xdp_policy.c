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

				/* Check for source NAT rule */
				struct snat_key sk = {
					.from_zone = meta->ingress_zone,
					.to_zone   = meta->egress_zone,
				};
				struct snat_value *sv = bpf_map_lookup_elem(&snat_rules, &sk);
				if (sv) {
					/* Allocate IP + port from NAT pool */
					__be32 alloc_ip;
					__be16 alloc_port;
					if (nat_pool_alloc_v4(sv->mode, &alloc_ip, &alloc_port) < 0) {
						inc_counter(GLOBAL_CTR_NAT_ALLOC_FAIL);
						return XDP_DROP;
					}
					__builtin_memset(&meta->src_ip, 0, sizeof(meta->src_ip));
					meta->src_ip.v4 = alloc_ip;
					meta->src_port = alloc_port;
					sess_nat_flags |= SESS_FLAG_SNAT;
					sess_nat_src_ip = alloc_ip;
					sess_nat_src_port = alloc_port;
				}

				/* Check for pre-routing DNAT */
				if (meta->nat_flags & SESS_FLAG_DNAT) {
					sess_nat_flags |= SESS_FLAG_DNAT;
					sess_nat_dst_ip = meta->nat_dst_ip.v4;
					sess_nat_dst_port = meta->nat_dst_port;
				}

				if (create_session(meta, rule->rule_id, rule->log,
						   sess_nat_flags,
						   sess_nat_src_ip, sess_nat_src_port,
						   sess_nat_dst_ip, sess_nat_dst_port) < 0) {
					inc_counter(GLOBAL_CTR_DROPS);
					return XDP_DROP;
				}

				/* For SNAT: insert dnat_table entry for return traffic */
				if (sess_nat_flags & SESS_FLAG_SNAT) {
					struct dnat_key dk = {
						.protocol = meta->protocol,
						.dst_ip   = sess_nat_src_ip,
						.dst_port = sess_nat_src_port,
					};
					struct dnat_value dv = {
						.new_dst_ip   = orig_src_ip,
						.new_dst_port = orig_src_port,
						.flags        = 0,
					};
					bpf_map_update_elem(&dnat_table, &dk, &dv,
							    BPF_NOEXIST);
				}

				if (rule->log)
					emit_event(meta, EVENT_TYPE_SESSION_OPEN,
						   ACTION_PERMIT, 0, 0);

				if (sess_nat_flags)
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_NAT);
				else
					bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
				return XDP_PASS;
			} else {
				/* IPv6 permit path -- use nat_* fields in meta
				 * to pass NAT info, avoiding large stack buffers.
				 */
				__u8 sess_nat_flags = 0;
				__be16 sess_nat_src_port = 0, sess_nat_dst_port = 0;
				__be16 orig_src_port = meta->src_port;

				/* Save original src IP */
				__u8 orig_src_ip_save[16];
				__builtin_memcpy(orig_src_ip_save, meta->src_ip.v6, 16);

				/* Allocated SNAT IP for session + dnat_table */
				__u8 alloc_ip_v6[16] = {};

				/* Check for source NAT rule (v6) */
				struct snat_key sk = {
					.from_zone = meta->ingress_zone,
					.to_zone   = meta->egress_zone,
				};
				struct snat_value_v6 *sv6 = bpf_map_lookup_elem(&snat_rules_v6, &sk);
				if (sv6) {
					/* Allocate IP + port from NAT pool */
					__be16 alloc_port;
					if (nat_pool_alloc_v6(sv6->mode, alloc_ip_v6, &alloc_port) < 0) {
						inc_counter(GLOBAL_CTR_NAT_ALLOC_FAIL);
						return XDP_DROP;
					}
					__builtin_memcpy(meta->src_ip.v6, alloc_ip_v6, 16);
					meta->src_port = alloc_port;
					sess_nat_flags |= SESS_FLAG_SNAT;
					sess_nat_src_port = alloc_port;
				}

				/* Check for pre-routing DNAT */
				if (meta->nat_flags & SESS_FLAG_DNAT) {
					sess_nat_flags |= SESS_FLAG_DNAT;
					sess_nat_dst_port = meta->nat_dst_port;
				}

				/* Pass NAT IPs through meta fields */
				const __u8 *nat_src_ptr = sv6 ? alloc_ip_v6 : NULL;
				const __u8 *nat_dst_ptr = (meta->nat_flags & SESS_FLAG_DNAT) ?
					meta->nat_dst_ip.v6 : NULL;

				if (create_session_v6(meta, rule->rule_id, rule->log,
						      sess_nat_flags,
						      nat_src_ptr, sess_nat_src_port,
						      nat_dst_ptr, sess_nat_dst_port) < 0) {
					inc_counter(GLOBAL_CTR_DROPS);
					return XDP_DROP;
				}

				/* For SNAT: insert dnat_table_v6 entry for return traffic */
				if ((sess_nat_flags & SESS_FLAG_SNAT) && sv6) {
					struct dnat_key_v6 dk6 = {
						.protocol = meta->protocol,
						.dst_port = sess_nat_src_port,
					};
					__builtin_memcpy(dk6.dst_ip, alloc_ip_v6, 16);
					struct dnat_value_v6 dv6 = {
						.new_dst_port = orig_src_port,
						.flags        = 0,
					};
					__builtin_memcpy(dv6.new_dst_ip, orig_src_ip_save, 16);
					bpf_map_update_elem(&dnat_table_v6, &dk6, &dv6,
							    BPF_NOEXIST);
				}

				if (rule->log)
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
