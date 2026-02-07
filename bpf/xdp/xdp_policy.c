// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP policy evaluation stage.
 *
 * Evaluates zone-pair security policies for new connections. On permit,
 * creates dual session entries (forward + reverse) and proceeds to the
 * forward stage. On deny, drops the packet.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Check whether an IP address matches a policy rule's address_id.
 * address_id == 0 means "any" (always matches).
 */
static __always_inline int
addr_matches(__be32 ip, __u32 rule_addr_id)
{
	if (rule_addr_id == 0)
		return 1;

	/* LPM trie lookup: find the most specific prefix matching this IP */
	struct lpm_key_v4 lpm_key = {
		.prefixlen = 32,
		.addr = ip,
	};
	struct addr_value *av = bpf_map_lookup_elem(&address_book_v4, &lpm_key);
	if (!av)
		return 0;

	/* Direct match */
	if (av->address_id == rule_addr_id)
		return 1;

	/* Check address-set membership: (resolved_id, rule_addr_id) */
	struct addr_membership_key mkey = {
		.ip = av->address_id,  /* reuse ip field for resolved_id */
		.address_id = rule_addr_id,
	};
	if (bpf_map_lookup_elem(&address_membership, &mkey))
		return 1;

	return 0;
}

/*
 * Emit an event to the ring buffer.
 */
static __always_inline void
emit_event(struct pkt_meta *meta, __u8 event_type, __u8 action,
	   __u64 packets, __u64 bytes)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();
	evt->src_ip = meta->src_ip;
	evt->dst_ip = meta->dst_ip;
	evt->src_port = meta->src_port;
	evt->dst_port = meta->dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->pad = 0;
	evt->session_packets = packets;
	evt->session_bytes = bytes;

	bpf_ringbuf_submit(evt, 0);
}

/*
 * Create dual session entries for a permitted connection.
 * nat_flags, nat_src_ip/port, nat_dst_ip/port carry NAT state.
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int
create_session(struct pkt_meta *meta, __u32 policy_id, __u8 log,
	       __u8 nat_flags, __be32 nat_src_ip, __be16 nat_src_port,
	       __be32 nat_dst_ip, __be16 nat_dst_port)
{
	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;

	/* Build forward key */
	struct session_key fwd_key = {};
	fwd_key.src_ip   = meta->src_ip;
	fwd_key.dst_ip   = meta->dst_ip;
	fwd_key.src_port = meta->src_port;
	fwd_key.dst_port = meta->dst_port;
	fwd_key.protocol = meta->protocol;

	/* Build reverse key */
	struct session_key rev_key;
	ct_reverse_key(&fwd_key, &rev_key);

	/* Initial state: TCP starts at SYN_SENT, others start ESTABLISHED */
	__u8 initial_state;
	if (meta->protocol == PROTO_TCP)
		initial_state = SESS_STATE_SYN_SENT;
	else
		initial_state = SESS_STATE_ESTABLISHED;

	__u32 timeout = ct_get_timeout(meta->protocol, initial_state);

	/* Forward entry */
	struct session_value fwd_val = {};
	fwd_val.state        = initial_state;
	fwd_val.flags        = nat_flags;
	fwd_val.tcp_state    = 0;
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

	/* Reverse entry -- carries same NAT info */
	struct session_value rev_val = {};
	rev_val.state        = initial_state;
	rev_val.flags        = nat_flags;
	rev_val.tcp_state    = 0;
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
		/* Clean up forward entry */
		bpf_map_delete_elem(&sessions, &fwd_key);
		return -1;
	}

	inc_counter(GLOBAL_CTR_SESSIONS_NEW);
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

	/* Look up policy set for this zone pair */
	struct policy_set *ps = bpf_map_lookup_elem(&zone_pair_policies, &zpk);
	if (!ps) {
		/* No policy set: implicit deny */
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

		/* Check source address */
		if (!addr_matches(meta->src_ip, rule->src_addr_id))
			continue;

		/* Check destination address */
		if (!addr_matches(meta->dst_ip, rule->dst_addr_id))
			continue;

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

		if (rule->action == ACTION_PERMIT) {
			__u8 sess_nat_flags = 0;
			__be32 sess_nat_src_ip = 0, sess_nat_dst_ip = 0;
			__be16 sess_nat_src_port = 0, sess_nat_dst_port = 0;
			__be32 orig_src_ip = meta->src_ip;
			__be16 orig_src_port = meta->src_port;

			/* Check for source NAT rule */
			struct snat_key sk = {
				.from_zone = meta->ingress_zone,
				.to_zone   = meta->egress_zone,
			};
			struct snat_value *sv = bpf_map_lookup_elem(&snat_rules, &sk);
			if (sv) {
				/* Apply SNAT: translate source IP */
				meta->src_ip = sv->snat_ip;
				/* Port preserved (no port allocation) */
				sess_nat_flags |= SESS_FLAG_SNAT;
				sess_nat_src_ip = sv->snat_ip;
				sess_nat_src_port = meta->src_port;
			}

			/* Check for pre-routing DNAT (set by xdp_zone) */
			if (meta->nat_flags & SESS_FLAG_DNAT) {
				sess_nat_flags |= SESS_FLAG_DNAT;
				sess_nat_dst_ip = meta->nat_dst_ip;
				sess_nat_dst_port = meta->nat_dst_port;
			}

			/* Create session entries */
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
					.dst_ip   = sv->snat_ip,
					.dst_port = orig_src_port,
				};
				struct dnat_value dv = {
					.new_dst_ip   = orig_src_ip,
					.new_dst_port = orig_src_port,
					.flags        = 0, /* dynamic */
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
		}

		/* DENY or REJECT (REJECT treated as deny in Phase 2) */
		inc_counter(GLOBAL_CTR_POLICY_DENY);
		if (rule->log)
			emit_event(meta, EVENT_TYPE_POLICY_DENY,
				   rule->action, 0, 0);
		return XDP_DROP;
	}

	/* No rule matched: apply default action */
	if (ps->default_action == ACTION_PERMIT) {
		if (create_session(meta, 0, 0, 0, 0, 0, 0, 0) < 0) {
			inc_counter(GLOBAL_CTR_DROPS);
			return XDP_DROP;
		}
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
		return XDP_PASS;
	}

	/* Default deny */
	inc_counter(GLOBAL_CTR_POLICY_DENY);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
