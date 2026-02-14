/* SPDX-License-Identifier: GPL-2.0-or-later
 * policy.c — Zone-pair policy matching (replaces xdp_policy).
 *
 * Two-level lookup: (from_zone, to_zone) -> policy_set, then iterate
 * rules in the policy_set for first match. Supports address book
 * matching via LPM, application matching, and NAT rule association.
 */

#include <string.h>

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_byteorder.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"
#include "events.h"

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
		rc = rte_lpm6_lookup(ctx->shm->address_book_v6,
		                     (const struct rte_ipv6_addr *)addr, &next_hop);
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
			if (apos < 0 || !ctx->shm->app_values)
				continue;
			struct app_value *av = &ctx->shm->app_values[apos];
			/* Check source port range if specified */
			if (av->src_port_low != 0 || av->src_port_high != 0) {
				uint16_t sp = meta->src_port;
				if (sp < av->src_port_low || sp > av->src_port_high)
					continue;
			}
			if (av->app_id != rule->app_id)
				continue;

			/* Store app timeout if set */
			if (av->timeout > 0)
				meta->app_timeout = av->timeout;
		}

		/* Match found */
		meta->policy_id = rule->rule_id;
		meta->log_flags = rule->log;

		/* Counter */
		if (rule->counter_id != 0)
			ctr_policy_add(ctx, rule->counter_id, rte_pktmbuf_pkt_len(pkt));

		/* Log */
		if (rule->log)
			emit_event(ctx, meta, EVENT_TYPE_FILTER_LOG, rule->action);

		/* Emit deny event for non-permit actions */
		if (rule->action != ACTION_PERMIT) {
			ctr_global_inc(ctx, GLOBAL_CTR_POLICY_DENY);
			emit_event(ctx, meta, EVENT_TYPE_POLICY_DENY, rule->action);
			return rule->action;
		}

		/* ---- SNAT for PERMIT actions ---- */

		/* Static 1:1 NAT SNAT check (highest priority) */
		if (meta->addr_family == AF_INET && ctx->shm->static_nat_v4) {
			struct static_nat_key_v4 snk = {
				.ip = meta->src_ip.v4,
				.direction = STATIC_NAT_SNAT,
			};
			void *sn_data = NULL;
			if (rte_hash_lookup_data(ctx->shm->static_nat_v4,
			                         &snk, &sn_data) >= 0) {
				meta->nat_src_ip.v4 = (uint32_t)(uintptr_t)sn_data;
				meta->nat_src_port = meta->src_port;
				meta->nat_flags |= SESS_FLAG_SNAT | SESS_FLAG_STATIC_NAT;
			}
		}

		/* Dynamic SNAT pool allocation (skip if static already matched) */
		if (!(meta->nat_flags & SESS_FLAG_STATIC_NAT)) {
			if (meta->addr_family == AF_INET &&
			    ctx->shm->snat_rules && ctx->shm->snat_values_v4) {
				struct snat_key sk = {
					.from_zone = meta->ingress_zone,
					.to_zone = meta->egress_zone,
				};

				for (uint16_t ri = 0; ri < MAX_SNAT_RULES_PER_PAIR; ri++) {
					sk.rule_idx = ri;
					int spos = rte_hash_lookup(ctx->shm->snat_rules, &sk);
					if (spos < 0)
						break;

					struct snat_value *sv = &ctx->shm->snat_values_v4[spos];

					if (sv->src_addr_id != 0 &&
					    lpm_lookup_addr_id(ctx, meta, 1, sv->src_addr_id) == 0)
						continue;
					if (sv->dst_addr_id != 0 &&
					    lpm_lookup_addr_id(ctx, meta, 0, sv->dst_addr_id) == 0)
						continue;

					if (sv->counter_id > 0)
						ctr_nat_rule_add(ctx, sv->counter_id,
						                 rte_pktmbuf_pkt_len(pkt));

					if (sv->mode != SNAT_MODE_OFF &&
					    ctx->shm->nat_pool_configs &&
					    ctx->shm->nat_pool_ips_v4) {
						uint32_t pool_id = sv->mode;
						if (pool_id < MAX_NAT_POOLS) {
							struct nat_pool_config *cfg =
								&ctx->shm->nat_pool_configs[pool_id];
							if (cfg->num_ips > 0) {
								uint32_t port_range =
									cfg->port_high - cfg->port_low + 1;
								if (port_range == 0)
									port_range = 1;

								uint64_t val = ctx->snat_port_counter++
									* MAX_LCORES + ctx->lcore_id;
								uint16_t port = cfg->port_low +
									(uint16_t)(val % port_range);

								uint32_t ip_idx;
								if (cfg->addr_persistent)
									ip_idx = meta->src_ip.v4 % cfg->num_ips;
								else
									ip_idx = (uint32_t)(
										(val / port_range) % cfg->num_ips);

								uint32_t map_idx =
									pool_id * MAX_NAT_POOL_IPS_PER_POOL + ip_idx;
								if (map_idx < MAX_NAT_POOL_IPS) {
									uint32_t alloc_ip =
										ctx->shm->nat_pool_ips_v4[map_idx];
									if (alloc_ip != 0) {
										meta->nat_src_ip.v4 = alloc_ip;
										meta->nat_src_port =
											rte_cpu_to_be_16(port);
										meta->nat_flags |= SESS_FLAG_SNAT;
										ctr_nat_port_alloc(ctx, pool_id);

										/* Insert return-path DNAT entry so
										 * zone_lookup translates return packets
										 * back to the original src IP/port */
										if (ctx->shm->dnat_table &&
										    ctx->shm->dnat_values) {
											struct dnat_key rdk = {
												.protocol = meta->protocol,
												.dst_ip = alloc_ip,
												.dst_port = rte_cpu_to_be_16(port),
											};
											int rdpos = rte_hash_add_key(
												ctx->shm->dnat_table, &rdk);
											if (rdpos >= 0) {
												struct dnat_value *rdv =
													&ctx->shm->dnat_values[rdpos];
												rdv->new_dst_ip = meta->src_ip.v4;
												rdv->new_dst_port = meta->src_port;
												rdv->flags = 0;
											}
										}
									}
								}
							}
						}
					}
					break;
				}
			} else if (meta->addr_family == AF_INET6 &&
			           ctx->shm->snat_rules_v6 && ctx->shm->snat_values_v6) {
				/* IPv6 SNAT pool allocation */
				struct snat_key sk = {
					.from_zone = meta->ingress_zone,
					.to_zone = meta->egress_zone,
				};

				for (uint16_t ri = 0; ri < MAX_SNAT_RULES_PER_PAIR; ri++) {
					sk.rule_idx = ri;
					int spos = rte_hash_lookup(ctx->shm->snat_rules_v6, &sk);
					if (spos < 0)
						break;

					struct snat_value_v6 *sv6 = &ctx->shm->snat_values_v6[spos];

					if (sv6->src_addr_id != 0 &&
					    lpm_lookup_addr_id(ctx, meta, 1, sv6->src_addr_id) == 0)
						continue;
					if (sv6->dst_addr_id != 0 &&
					    lpm_lookup_addr_id(ctx, meta, 0, sv6->dst_addr_id) == 0)
						continue;

					if (sv6->counter_id > 0)
						ctr_nat_rule_add(ctx, sv6->counter_id,
						                 rte_pktmbuf_pkt_len(pkt));

					if (sv6->mode != SNAT_MODE_OFF &&
					    ctx->shm->nat_pool_configs &&
					    ctx->shm->nat_pool_ips_v6) {
						uint32_t pool_id = sv6->mode;
						if (pool_id < MAX_NAT_POOLS) {
							struct nat_pool_config *cfg =
								&ctx->shm->nat_pool_configs[pool_id];
							if (cfg->num_ips_v6 > 0) {
								uint32_t port_range =
									cfg->port_high - cfg->port_low + 1;
								if (port_range == 0)
									port_range = 1;

								uint64_t val = ctx->snat_port_counter++
									* MAX_LCORES + ctx->lcore_id;
								uint16_t port = cfg->port_low +
									(uint16_t)(val % port_range);

								uint32_t ip_idx;
								if (cfg->addr_persistent) {
									uint32_t hash = 0;
									for (int i = 0; i < 4; i++)
										hash ^= ((uint32_t *)meta->src_ip.v6)[i];
									ip_idx = hash % cfg->num_ips_v6;
								} else {
									ip_idx = (uint32_t)(
										(val / port_range) % cfg->num_ips_v6);
								}

								uint32_t map_idx =
									pool_id * MAX_NAT_POOL_IPS_PER_POOL + ip_idx;
								if (map_idx < MAX_NAT_POOL_IPS) {
									struct nat_pool_ip_v6 *pip6 =
										&ctx->shm->nat_pool_ips_v6[map_idx];
									uint8_t zero[16] = {0};
									if (memcmp(pip6->ip, zero, 16) != 0) {
										memcpy(meta->nat_src_ip.v6, pip6->ip, 16);
										meta->nat_src_port =
											rte_cpu_to_be_16(port);
										meta->nat_flags |= SESS_FLAG_SNAT;
										ctr_nat_port_alloc(ctx, pool_id);

										/* Insert return-path DNAT v6 entry */
										if (ctx->shm->dnat_table_v6 &&
										    ctx->shm->dnat_values_v6) {
											struct dnat_key_v6 rdk6 = {
												.protocol = meta->protocol,
												.dst_port = rte_cpu_to_be_16(port),
											};
											memcpy(rdk6.dst_ip, pip6->ip, 16);
											int rdpos = rte_hash_add_key(
												ctx->shm->dnat_table_v6, &rdk6);
											if (rdpos >= 0) {
												struct dnat_value_v6 *rdv6 =
													&ctx->shm->dnat_values_v6[rdpos];
												memcpy(rdv6->new_dst_ip,
												       meta->src_ip.v6, 16);
												rdv6->new_dst_port = meta->src_port;
												rdv6->flags = 0;
											}
										}
									}
								}
							}
						}
					}
					break;
				}
			}
		}

		return ACTION_PERMIT;
	}

	/* No rule matched — default action from policy set */
	if (ps->default_action != ACTION_PERMIT)
		ctr_global_inc(ctx, GLOBAL_CTR_POLICY_DENY);
	return ps->default_action;
}
