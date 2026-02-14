/* SPDX-License-Identifier: GPL-2.0-or-later
 * filter.c — Firewall filter evaluation (replaces BPF filter programs).
 *
 * Evaluates per-interface firewall filters (input/output direction)
 * with support for address matching, port ranges, DSCP, protocol,
 * ICMP type/code, and negate flags.
 */

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_byteorder.h>
#include <string.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * addr_match — Check if an address matches a filter rule's address/mask.
 */
static inline int
addr_match(const uint8_t *addr, const uint8_t *rule_addr,
           const uint8_t *rule_mask, uint8_t family)
{
	int len = (family == AF_INET) ? 4 : 16;

	for (int i = 0; i < len; i++) {
		if ((addr[i] & rule_mask[i]) != (rule_addr[i] & rule_mask[i]))
			return 0;
	}
	return 1;
}

/**
 * evaluate_filter — Evaluate firewall filter rules for this packet.
 *
 * @pkt:       Packet mbuf
 * @meta:      Parsed packet metadata
 * @ctx:       Pipeline context
 * @direction: 0 = input (ingress), 1 = output (egress)
 *
 * Returns the filter action:
 *   FILTER_ACTION_ACCEPT  — Allow packet
 *   FILTER_ACTION_DISCARD — Drop packet
 *   FILTER_ACTION_REJECT  — Drop and send ICMP unreachable
 *   FILTER_ACTION_ROUTE   — Accept with routing-instance override
 *
 * If no filter is assigned to the interface+direction, returns ACCEPT.
 */
int
evaluate_filter(struct rte_mbuf *pkt, struct pkt_meta *meta,
                struct pipeline_ctx *ctx, uint8_t direction)
{
	if (!ctx->shm->iface_filter_map)
		return FILTER_ACTION_ACCEPT;

	/* Build filter key */
	struct iface_filter_key fk = {
		.ifindex = (direction == 0) ? meta->ingress_ifindex : meta->fwd_ifindex,
		.vlan_id = (direction == 0) ? meta->ingress_vlan_id : meta->egress_vlan_id,
		.family = meta->addr_family,
		.direction = direction,
	};

	int pos = rte_hash_lookup(ctx->shm->iface_filter_map, &fk);
	if (pos < 0)
		return FILTER_ACTION_ACCEPT;  /* No filter assigned */

	/* The value stored at the hash position is the filter_id.
	 * For now, assume filter_id = pos (need a value array). */
	/* TODO: need iface_filter_values array — use pos as filter_id for now */
	uint32_t filter_id = (uint32_t)pos;

	if (filter_id >= MAX_FILTER_CONFIGS || !ctx->shm->filter_configs)
		return FILTER_ACTION_ACCEPT;

	struct filter_config *fc = &ctx->shm->filter_configs[filter_id];
	if (fc->num_rules == 0)
		return FILTER_ACTION_ACCEPT;

	/* Iterate rules */
	for (uint32_t i = 0; i < fc->num_rules; i++) {
		uint32_t ridx = fc->rule_start + i;
		if (ridx >= MAX_FILTER_RULES || !ctx->shm->filter_rules)
			break;

		struct filter_rule *r = &ctx->shm->filter_rules[ridx];

		/* Match family */
		if (r->family != 0 && r->family != meta->addr_family)
			continue;

		/* Match DSCP */
		if ((r->match_flags & FILTER_MATCH_DSCP) && r->dscp != meta->dscp)
			continue;

		/* Match protocol */
		if ((r->match_flags & FILTER_MATCH_PROTOCOL) &&
		    r->protocol != meta->protocol)
			continue;

		/* Match source address (with optional negate) */
		if (r->match_flags & FILTER_MATCH_SRC_ADDR) {
			uint8_t *addr = (meta->addr_family == AF_INET) ?
				(uint8_t *)&meta->src_ip.v4 : meta->src_ip.v6;
			int match = addr_match(addr, r->src_addr, r->src_mask,
			                       meta->addr_family);
			if (r->match_flags & FILTER_MATCH_SRC_NEGATE)
				match = !match;
			if (!match)
				continue;
		}

		/* Match destination address (with optional negate) */
		if (r->match_flags & FILTER_MATCH_DST_ADDR) {
			uint8_t *addr = (meta->addr_family == AF_INET) ?
				(uint8_t *)&meta->dst_ip.v4 : meta->dst_ip.v6;
			int match = addr_match(addr, r->dst_addr, r->dst_mask,
			                       meta->addr_family);
			if (r->match_flags & FILTER_MATCH_DST_NEGATE)
				match = !match;
			if (!match)
				continue;
		}

		/* Match destination port range */
		if (r->match_flags & FILTER_MATCH_DST_PORT) {
			uint16_t port = rte_be_to_cpu_16(meta->dst_port);
			uint16_t lo = rte_be_to_cpu_16(r->dst_port);
			uint16_t hi = r->dst_port_hi ? rte_be_to_cpu_16(r->dst_port_hi) : lo;
			if (port < lo || port > hi)
				continue;
		}

		/* Match source port range */
		if (r->match_flags & FILTER_MATCH_SRC_PORT) {
			uint16_t port = rte_be_to_cpu_16(meta->src_port);
			uint16_t lo = rte_be_to_cpu_16(r->src_port);
			uint16_t hi = r->src_port_hi ? rte_be_to_cpu_16(r->src_port_hi) : lo;
			if (port < lo || port > hi)
				continue;
		}

		/* Match ICMP type/code */
		if ((r->match_flags & FILTER_MATCH_ICMP_TYPE) &&
		    r->icmp_type != meta->icmp_type)
			continue;
		if ((r->match_flags & FILTER_MATCH_ICMP_CODE) &&
		    r->icmp_code != meta->icmp_code)
			continue;

		/* Rule matched */
		ctr_filter_add(ctx, ridx, rte_pktmbuf_pkt_len(pkt));

		/* DSCP rewrite */
		if (r->dscp_rewrite != 0xFF)
			meta->dscp_rewrite = r->dscp_rewrite;

		/* Routing instance override */
		if (r->action == FILTER_ACTION_ROUTE)
			meta->routing_table = r->routing_table;

		return r->action;
	}

	/* No rule matched — implicit accept */
	return FILTER_ACTION_ACCEPT;
}
