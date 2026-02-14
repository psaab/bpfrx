/* SPDX-License-Identifier: GPL-2.0-or-later
 * zone.c — Zone lookup + FIB-based egress zone determination.
 *
 * Looks up the security zone for the ingress interface + VLAN,
 * performs FIB lookup to determine egress interface, resolves
 * egress zone, and populates forwarding metadata.
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
 * zone_lookup — Determine ingress zone + FIB lookup for egress zone.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (ingress_ifindex, ingress_vlan_id set)
 * @ctx:  Pipeline context (shared memory with zone tables)
 *
 * Sets:
 *   meta->ingress_zone, meta->routing_table (from iface_zone_map)
 *   meta->fwd_ifindex, meta->fwd_dmac, meta->fwd_smac (from FIB)
 *   meta->egress_zone, meta->egress_vlan_id (from egress iface zone lookup)
 */
void
zone_lookup(struct rte_mbuf *pkt, struct pkt_meta *meta,
            struct pipeline_ctx *ctx)
{
	(void)pkt;

	if (!ctx->shm->iface_zone_map)
		return;

	/* ---- Ingress zone lookup ---- */
	struct iface_zone_key zk = {
		.ifindex = meta->ingress_ifindex,
		.vlan_id = meta->ingress_vlan_id,
		.pad = 0,
	};

	int pos = rte_hash_lookup(ctx->shm->iface_zone_map, &zk);
	if (pos >= 0 && ctx->shm->iface_zone_values) {
		struct iface_zone_value *zv = &ctx->shm->iface_zone_values[pos];
		meta->ingress_zone = zv->zone_id;
		meta->routing_table = zv->routing_table;
	}

	/* ---- Static 1:1 NAT DNAT lookup (before FIB) ---- */
	if (meta->addr_family == AF_INET && ctx->shm->static_nat_v4) {
		struct static_nat_key_v4 snk = {
			.ip = meta->dst_ip.v4,
			.direction = STATIC_NAT_DNAT,
		};
		void *sn_data = NULL;
		if (rte_hash_lookup_data(ctx->shm->static_nat_v4,
		                         &snk, &sn_data) >= 0) {
			meta->nat_dst_ip.v4 = meta->dst_ip.v4;
			meta->nat_dst_port = meta->dst_port;
			meta->dst_ip.v4 = (uint32_t)(uintptr_t)sn_data;
			meta->nat_flags |= SESS_FLAG_DNAT | SESS_FLAG_STATIC_NAT;
		}
	}

	/* ---- FIB lookup for egress determination ---- */
	uint32_t nexthop_id = 0;
	int fib_rc = -1;

	if (meta->addr_family == AF_INET && ctx->shm->fib_v4) {
		/* IPv4 FIB lookup */
		uint32_t dst = rte_be_to_cpu_32(meta->dst_ip.v4);
		fib_rc = rte_lpm_lookup(ctx->shm->fib_v4, dst, &nexthop_id);
	} else if (meta->addr_family == AF_INET6 && ctx->shm->fib_v6) {
		/* IPv6 FIB lookup */
		fib_rc = rte_lpm6_lookup(ctx->shm->fib_v6, meta->dst_ip.v6,
		                         &nexthop_id);
	}

	if (fib_rc == 0 && nexthop_id < MAX_NEXTHOPS && ctx->shm->nexthops) {
		struct fib_nexthop *nh = &ctx->shm->nexthops[nexthop_id];

		meta->fwd_ifindex = nh->port_id;
		meta->egress_vlan_id = nh->vlan_id;
		memcpy(meta->fwd_dmac, nh->dmac, 6);
		memcpy(meta->fwd_smac, nh->smac, 6);

		/* Look up egress zone using {ifindex, vlan_id} */
		struct iface_zone_key ezk = {
			.ifindex = nh->ifindex,
			.vlan_id = nh->vlan_id,
			.pad = 0,
		};
		int epos = rte_hash_lookup(ctx->shm->iface_zone_map, &ezk);
		if (epos >= 0 && ctx->shm->iface_zone_values)
			meta->egress_zone = ctx->shm->iface_zone_values[epos].zone_id;
	}
}
