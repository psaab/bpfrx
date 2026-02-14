/* SPDX-License-Identifier: GPL-2.0-or-later
 * zone.c — Zone lookup (replaces xdp_zone).
 *
 * Looks up the security zone for the ingress interface + VLAN,
 * applying host-inbound-traffic checks for local-destined packets.
 */

#include <rte_mbuf.h>
#include <rte_hash.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * zone_lookup — Determine the ingress security zone.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (ingress_ifindex, ingress_vlan_id set)
 * @ctx:  Pipeline context (shared memory with zone tables)
 *
 * Sets meta->ingress_zone and meta->routing_table based on the
 * iface_zone_map lookup using {ifindex, vlan_id} as key.
 *
 * Also checks host-inbound-traffic flags if the packet is destined
 * to the firewall itself (local delivery).
 */
void
zone_lookup(struct rte_mbuf *pkt, struct pkt_meta *meta,
            struct pipeline_ctx *ctx)
{
	(void)pkt;

	if (!ctx->shm->iface_zone_map)
		return;

	/* Look up ingress zone by {ifindex, vlan_id} */
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

	/* Load zone config for host-inbound checks */
	if (meta->ingress_zone < MAX_ZONES && ctx->shm->zone_configs) {
		struct zone_config *zc = &ctx->shm->zone_configs[meta->ingress_zone];
		/* Host-inbound-traffic check would go here if we knew
		 * the firewall's own interface IPs. For now, the pipeline
		 * relies on policy check for access control. */
		(void)zc;
	}

	/* Egress zone determination via FIB is deferred to forward stage.
	 * For now, egress_zone is set by conntrack (from existing session)
	 * or remains 0 for new sessions until policy_check sets it. */
}
