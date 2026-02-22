/* SPDX-License-Identifier: GPL-2.0-or-later
 * zone.c — Zone lookup + FIB-based egress zone determination.
 *
 * Looks up the security zone for the ingress interface + VLAN,
 * performs FIB lookup to determine egress interface, resolves
 * egress zone, and populates forwarding metadata.
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

	/* ---- Pre-routing NAT: check dnat_table before FIB lookup.
	 * This handles both port-based DNAT entries (from config) and
	 * static 1:1 NAT as fallback.  Must run before FIB so the
	 * translated destination is used for egress zone determination. ---- */
	if (meta->addr_family == AF_INET) {
		int dnat_found = 0;

		/* DNAT table lookup (port-based) */
		if (ctx->shm->dnat_table && ctx->shm->dnat_values) {
			struct dnat_key dk = {
				.protocol = meta->protocol,
				.dst_ip = meta->dst_ip.v4,
				.dst_port = meta->dst_port,
			};
			int dpos = rte_hash_lookup(ctx->shm->dnat_table, &dk);
			/* Fallback: wildcard port (port=0) for IP-only DNAT rules */
			if (dpos < 0) {
				struct dnat_key dk_wild = {
					.protocol = meta->protocol,
					.dst_ip = meta->dst_ip.v4,
					.dst_port = 0,
				};
				dpos = rte_hash_lookup(ctx->shm->dnat_table, &dk_wild);
			}
			if (dpos >= 0) {
				struct dnat_value *dv = &ctx->shm->dnat_values[dpos];
				meta->nat_dst_ip.v4 = meta->dst_ip.v4;
				meta->nat_dst_port = meta->dst_port;
				meta->dst_ip.v4 = dv->new_dst_ip;
				meta->dst_port = dv->new_dst_port;
				meta->nat_flags |= SESS_FLAG_DNAT;
				/* ICMP: echo ID is symmetric — set src_port so
				 * conntrack finds session using original echo ID */
				if (meta->protocol == PROTO_ICMP)
					meta->src_port = meta->dst_port;
				dnat_found = 1;
			}
		}

		/* Static 1:1 NAT DNAT lookup (fallback when no port-based DNAT matched) */
		if (!dnat_found && ctx->shm->static_nat_v4) {
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
	} else if (meta->addr_family == AF_INET6) {
		int dnat_found = 0;

		/* DNAT v6 table lookup */
		if (ctx->shm->dnat_table_v6 && ctx->shm->dnat_values_v6) {
			struct dnat_key_v6 dk6 = { .protocol = meta->protocol };
			memcpy(dk6.dst_ip, meta->dst_ip.v6, 16);
			dk6.dst_port = meta->dst_port;

			int dpos = rte_hash_lookup(ctx->shm->dnat_table_v6, &dk6);
			/* Fallback: wildcard port */
			if (dpos < 0) {
				struct dnat_key_v6 dk6_wild = { .protocol = meta->protocol };
				memcpy(dk6_wild.dst_ip, meta->dst_ip.v6, 16);
				dk6_wild.dst_port = 0;
				dpos = rte_hash_lookup(ctx->shm->dnat_table_v6, &dk6_wild);
			}
			if (dpos >= 0) {
				struct dnat_value_v6 *dv6 = &ctx->shm->dnat_values_v6[dpos];
				memcpy(meta->nat_dst_ip.v6, meta->dst_ip.v6, 16);
				meta->nat_dst_port = meta->dst_port;
				memcpy(meta->dst_ip.v6, dv6->new_dst_ip, 16);
				meta->dst_port = dv6->new_dst_port;
				meta->nat_flags |= SESS_FLAG_DNAT;
				if (meta->protocol == PROTO_ICMPV6)
					meta->src_port = meta->dst_port;
				dnat_found = 1;
			}
		}

		/* Static 1:1 NAT DNAT v6 lookup (fallback) */
		if (!dnat_found && ctx->shm->static_nat_v6) {
			struct static_nat_key_v6 snk6 = { .direction = STATIC_NAT_DNAT };
			memcpy(snk6.ip, meta->dst_ip.v6, 16);
			void *sn_data = NULL;
			if (rte_hash_lookup_data(ctx->shm->static_nat_v6,
			                         &snk6, &sn_data) >= 0) {
				struct static_nat_value_v6 *sv6 =
					(struct static_nat_value_v6 *)sn_data;
				memcpy(meta->nat_dst_ip.v6, meta->dst_ip.v6, 16);
				meta->nat_dst_port = meta->dst_port;
				memcpy(meta->dst_ip.v6, sv6->ip, 16);
				meta->nat_flags |= SESS_FLAG_DNAT | SESS_FLAG_STATIC_NAT;
			}
		}
	}

	/* ---- VRRP multicast (224.0.0.18, proto 112) — host-bound for native VRRP daemon ---- */
	if (meta->addr_family == AF_INET && meta->protocol == PROTO_VRRP &&
	    meta->dst_ip.v4 == rte_cpu_to_be_32(0xE0000012)) {
		meta->fwd_ifindex = 0;
		return;
	}

	/* ---- Broadcast / multicast — host-bound, skip FIB + policy ----
	 * Without this, the FIB default route would send broadcast/multicast
	 * through the policy pipeline where deny-all would drop it
	 * (e.g. DHCP OFFER to 255.255.255.255). */
	if (meta->addr_family == AF_INET) {
		if (meta->dst_ip.v4 == 0xFFFFFFFF) {
			meta->fwd_ifindex = 0;
			return;
		}
		uint8_t *ip4b = (uint8_t *)&meta->dst_ip.v4;
		if ((ip4b[0] & 0xF0) == 0xE0) {  /* 224.0.0.0/4 multicast */
			meta->fwd_ifindex = 0;
			return;
		}
	} else {
		if (meta->dst_ip.v6[0] == 0xFF) {  /* ff00::/8 multicast */
			meta->fwd_ifindex = 0;
			return;
		}
	}

	/* ---- DHCP/DHCPv6 unicast responses — host-bound, skip FIB ----
	 * DHCP replies to an address not yet configured won't match FIB.
	 * If the ingress zone allows DHCP host-inbound, bypass FIB. */
	if (meta->protocol == PROTO_UDP &&
	    meta->ingress_zone < MAX_ZONES && ctx->shm->zone_configs) {
		struct zone_config *zcfg = &ctx->shm->zone_configs[meta->ingress_zone];
		uint16_t dp = rte_be_to_cpu_16(meta->dst_port);
		if ((dp == 68 && (zcfg->host_inbound_flags & HOST_INBOUND_DHCP)) ||
		    (dp == 546 && (zcfg->host_inbound_flags & HOST_INBOUND_DHCPV6))) {
			meta->fwd_ifindex = 0;
			return;
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
		fib_rc = rte_lpm6_lookup(ctx->shm->fib_v6,
		                         (const struct rte_ipv6_addr *)meta->dst_ip.v6,
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
