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

SEC("xdp")
int xdp_zone_prog(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Look up ingress zone from {ifindex, vlan_id} composite key */
	struct iface_zone_key izk = {
		.ifindex = meta->ingress_ifindex,
		.vlan_id = meta->ingress_vlan_id,
	};
	__u16 *zone_id = bpf_map_lookup_elem(&iface_zone_map, &izk);
	if (!zone_id) {
		/* Interface not assigned to any zone -- drop */
		inc_counter(GLOBAL_CTR_DROPS);
		return XDP_DROP;
	}
	meta->ingress_zone = *zone_id;
	inc_zone_ingress((__u32)*zone_id, meta->pkt_len);

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
		/* Fallback: try wildcard port (port=0) for IP-only DNAT rules */
		if (!dv) {
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
		/* Fallback: try wildcard port (port=0) for IP-only DNAT rules */
		if (!dv6) {
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
			}
		}
	}

	/*
	 * VRRP multicast (224.0.0.18, proto 112) — allow to host for keepalived.
	 * Must be checked before the generic multicast pass-through so it
	 * reaches the host even with zone-pair deny-all.
	 */
	if (meta->addr_family == AF_INET && meta->protocol == PROTO_VRRP &&
	    meta->dst_ip.v4 == bpf_htonl(0xE0000012)) {
		meta->fwd_ifindex = 0;
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
		return XDP_PASS;
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

	if (meta->addr_family == AF_INET) {
		fib.family   = AF_INET;
		fib.ipv4_src = meta->src_ip.v4;
		fib.ipv4_dst = meta->dst_ip.v4;
	} else {
		fib.family = AF_INET6;
		__builtin_memcpy(fib.ipv6_src, meta->src_ip.v6, 16);
		__builtin_memcpy(fib.ipv6_dst, meta->dst_ip.v6, 16);
	}

	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		/* Store forwarding info -- resolve VLAN sub-interface */
		__u32 egress_if = fib.ifindex;
		__u16 egress_vlan = 0;
		__u32 egress_phys_if = egress_if;
		struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map, &egress_if);
		if (vi) {
			egress_phys_if = vi->parent_ifindex;
			egress_vlan = vi->vlan_id;
		}
		meta->fwd_ifindex = egress_phys_if;
		meta->egress_vlan_id = egress_vlan;
		__builtin_memcpy(meta->fwd_dmac, fib.dmac, ETH_ALEN);
		__builtin_memcpy(meta->fwd_smac, fib.smac, ETH_ALEN);

		/* Look up egress zone using {physical_ifindex, vlan_id} */
		struct iface_zone_key ezk = { .ifindex = egress_phys_if, .vlan_id = egress_vlan };
		__u16 *ez = bpf_map_lookup_elem(&iface_zone_map, &ezk);
		if (ez)
			meta->egress_zone = *ez;

	} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		/*
		 * Route exists but no neighbor entry (no ARP/NDP yet).
		 * Store the ifindex for zone lookup; pass to kernel
		 * to trigger neighbor resolution.
		 */
		__u32 egress_if = fib.ifindex;
		__u16 egress_vlan = 0;
		__u32 egress_phys_if = egress_if;
		struct vlan_iface_info *vi = bpf_map_lookup_elem(&vlan_iface_map, &egress_if);
		if (vi) {
			egress_phys_if = vi->parent_ifindex;
			egress_vlan = vi->vlan_id;
		}
		meta->fwd_ifindex = egress_phys_if;
		meta->egress_vlan_id = egress_vlan;

		struct iface_zone_key ezk = { .ifindex = egress_phys_if, .vlan_id = egress_vlan };
		__u16 *ez = bpf_map_lookup_elem(&iface_zone_map, &ezk);
		if (ez)
			meta->egress_zone = *ez;

	} else {
		/*
		 * No route or packet is destined locally.
		 * Egress zone stays 0 (unset). Later policy stages
		 * can handle host-inbound traffic.
		 */
		return XDP_PASS;
	}

	/* Tail call to conntrack for session lookup and policy evaluation */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_CONNTRACK);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
