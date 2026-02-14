/* SPDX-License-Identifier: GPL-2.0-or-later
 * policy.c — Zone-pair policy matching (replaces xdp_policy).
 *
 * Two-level lookup: (from_zone, to_zone) -> policy_set, then iterate
 * rules in the policy_set for first match. Supports address book
 * matching via LPM, application matching, and NAT rule association.
 */

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_byteorder.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * lpm_lookup_addr_id — Look up an address in the LPM and then check membership.
 * Returns the address_id if matched, 0 if not.
 */
static inline uint32_t
lpm_lookup_addr_id(struct pipeline_ctx *ctx, struct pkt_meta *meta,
                   int is_src, uint32_t required_id)
{
	uint32_t next_hop = 0;
	int rc;

	if (meta->addr_family == AF_INET) {
		if (!ctx->shm->address_book_v4)
			return 0;
		rc = rte_lpm_lookup(ctx->shm->address_book_v4,
		                    rte_be_to_cpu_32(is_src ? meta->src_ip.v4 : meta->dst_ip.v4),
		                    &next_hop);
	} else {
		if (!ctx->shm->address_book_v6)
			return 0;
		uint8_t *addr = is_src ? meta->src_ip.v6 : meta->dst_ip.v6;
		rc = rte_lpm6_lookup(ctx->shm->address_book_v6, addr, &next_hop);
	}

	if (rc != 0)
		return 0;

	/* Check address membership: does this resolved IP belong to the required address set? */
	if (ctx->shm->address_membership) {
		struct addr_membership_key mk = {
			.ip = next_hop,
			.address_id = required_id,
		};
		int pos = rte_hash_lookup(ctx->shm->address_membership, &mk);
		if (pos >= 0)
			return required_id;
	}

	/* Direct match: next_hop IS the address_id */
	return (next_hop == required_id) ? required_id : 0;
}

/**
 * policy_check — Check zone-pair policies for this packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (ingress_zone, egress_zone set)
 * @ctx:  Pipeline context
 *
 * Returns the action: ACTION_PERMIT, ACTION_DENY, or ACTION_REJECT.
 *
 * On ACTION_PERMIT, meta->policy_id and NAT fields are populated.
 */
int
policy_check(struct rte_mbuf *pkt, struct pkt_meta *meta,
             struct pipeline_ctx *ctx)
{
	/* Global policy: zone pair key 0xFFFF/0xFFFF */
	#define GLOBAL_ZONE 0xFFFF

	struct zone_pair_key zpk = {
		.from_zone = meta->ingress_zone,
		.to_zone = meta->egress_zone,
	};

	struct policy_set *ps = NULL;

	if (ctx->shm->zone_pair_policies) {
		int pos = rte_hash_lookup(ctx->shm->zone_pair_policies, &zpk);
		if (pos >= 0 && ctx->shm->zone_pair_values)
			ps = &ctx->shm->zone_pair_values[pos];
	}

	/* Fall back to global policy if no zone-pair policy found */
	if (!ps && ctx->shm->zone_pair_policies) {
		struct zone_pair_key gk = { .from_zone = GLOBAL_ZONE, .to_zone = GLOBAL_ZONE };
		int pos = rte_hash_lookup(ctx->shm->zone_pair_policies, &gk);
		if (pos >= 0 && ctx->shm->zone_pair_values)
			ps = &ctx->shm->zone_pair_values[pos];
	}

	/* No policy at all — use default */
	if (!ps) {
		uint8_t def = ctx->shm->default_policy ? *ctx->shm->default_policy : ACTION_DENY;
		if (def != ACTION_PERMIT)
			ctr_global_inc(ctx, GLOBAL_CTR_POLICY_DENY);
		return def;
	}

	/* Iterate rules */
	for (uint16_t i = 0; i < ps->num_rules; i++) {
		uint32_t rule_idx = ps->policy_set_id * MAX_RULES_PER_POLICY + i;
		if (rule_idx >= MAX_POLICIES * MAX_RULES_PER_POLICY)
			break;

		struct policy_rule *rule = &ctx->shm->policy_rules[rule_idx];
		if (!rule->active)
			continue;

		/* Source address match */
		if (rule->src_addr_id != 0) {
			if (lpm_lookup_addr_id(ctx, meta, 1, rule->src_addr_id) == 0)
				continue;
		}

		/* Destination address match */
		if (rule->dst_addr_id != 0) {
			if (lpm_lookup_addr_id(ctx, meta, 0, rule->dst_addr_id) == 0)
				continue;
		}

		/* Protocol match */
		if (rule->protocol != 0 && rule->protocol != meta->protocol)
			continue;

		/* Destination port range match */
		if (rule->dst_port_low != 0) {
			uint16_t port = rte_be_to_cpu_16(meta->dst_port);
			uint16_t lo = rte_be_to_cpu_16(rule->dst_port_low);
			uint16_t hi = rule->dst_port_high ? rte_be_to_cpu_16(rule->dst_port_high) : lo;
			if (port < lo || port > hi)
				continue;
		}

		/* Application match */
		if (rule->app_id != 0 && ctx->shm->applications) {
			struct app_key ak = {
				.protocol = meta->protocol,
				.dst_port = meta->dst_port,
			};
			int apos = rte_hash_lookup(ctx->shm->applications, &ak);
			if (apos < 0 || !ctx->shm->app_values ||
			    ctx->shm->app_values[apos].app_id != rule->app_id)
				continue;

			/* Store app timeout if set */
			if (ctx->shm->app_values[apos].timeout > 0)
				meta->app_timeout = ctx->shm->app_values[apos].timeout;
		}

		/* Match found */
		meta->policy_id = rule->rule_id;

		/* Counter */
		if (rule->counter_id != 0)
			ctr_policy_add(ctx, rule->counter_id, rte_pktmbuf_pkt_len(pkt));

		/* Log */
		if (rule->log) {
			/* TODO: emit event to event_ring */
		}

		if (rule->action != ACTION_PERMIT)
			ctr_global_inc(ctx, GLOBAL_CTR_POLICY_DENY);

		return rule->action;
	}

	/* No rule matched — default action from policy set */
	if (ps->default_action != ACTION_PERMIT)
		ctr_global_inc(ctx, GLOBAL_CTR_POLICY_DENY);
	return ps->default_action;
}
