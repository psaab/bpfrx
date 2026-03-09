// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP userspace entry point.
 *
 * This is the first-stage handoff program for the planned AF_XDP userspace
 * dataplane. It preserves the existing eBPF firewall as the safe fallback:
 *
 * - parse packet and run cheap ingress filter work
 * - resolve ingress zone and decide whether screen can be skipped
 * - if userspace redirection is enabled for this ingress interface + RX queue,
 *   stamp metadata and redirect to the XSKMAP
 * - otherwise tail-call into the existing XDP pipeline
 *
 * Redirect remains disabled until a userspace worker installs AF_XDP sockets
 * and marks the binding ready via userspace_ctrl/userspace_bindings.
 */

#include "../headers/bpfrx_common.h"
#define BPFRX_NAT_POOLS
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_trace.h"

#define USERSPACE_META_MAGIC   0x42505553 /* "BPUS" */
#define USERSPACE_META_VERSION 2

struct userspace_ctrl {
	__u32 enabled;
	__u32 metadata_version;
	__u32 workers;
	__u32 flags;
	__u64 config_generation;
	__u32 fib_generation;
	__u32 reserved;
};

struct userspace_dp_meta {
	__u32 magic;
	__u16 version;
	__u16 length;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u16 ingress_vlan_id;
	__u16 ingress_zone;
	__u32 routing_table;
	__u16 l3_offset;
	__u16 l4_offset;
	__u16 payload_offset;
	__u16 pkt_len;
	__u8  addr_family;
	__u8  protocol;
	__u8  tcp_flags;
	__u8  meta_flags;
	__u8  dscp;
	__u8  dscp_rewrite;
	__u16 reserved;
	__u64 config_generation;
	__u32 fib_generation;
	__u32 reserved2;
};

struct userspace_binding_key {
	__u32 ifindex;
	__u32 queue_id;
};

struct userspace_binding_value {
	__u32 slot;
	__u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct userspace_ctrl);
} userspace_ctrl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct userspace_binding_key);
	__type(value, struct userspace_binding_value);
} userspace_bindings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u32);
} userspace_xsk_map SEC(".maps");

static __always_inline void
apply_dscp_rewrite(void *data, void *data_end, struct pkt_meta *meta)
{
	struct ethhdr *rw_eth = data;

	if ((void *)(rw_eth + 1) > data_end)
		return;

	if (meta->addr_family == AF_INET) {
		struct iphdr *iph = (void *)(rw_eth + 1);
		if ((void *)(iph + 1) <= data_end) {
			__u8 old_tos = iph->tos;
			__u8 new_tos = (meta->dscp_rewrite << 2) | (old_tos & 0x03);
			if (old_tos != new_tos) {
				__be16 old_w = bpf_htons((__u16)old_tos);
				__be16 new_w = bpf_htons((__u16)new_tos);
				csum_update_2(&iph->check, old_w, new_w);
				iph->tos = new_tos;
				meta->dscp = meta->dscp_rewrite;
			}
		}
		return;
	}

	/* IPv6 traffic class spans bytes 0-1 of the header. */
	struct ipv6hdr *ip6 = (void *)(rw_eth + 1);
	if ((void *)(ip6 + 1) <= data_end) {
		__u8 *hdr = (__u8 *)ip6;
		__u8 old_tc = ((hdr[0] & 0x0F) << 4) | ((hdr[1] & 0xF0) >> 4);
		__u8 new_tc = (meta->dscp_rewrite << 2) | (old_tc & 0x03);
		if (old_tc != new_tc) {
			hdr[0] = (hdr[0] & 0xF0) | ((new_tc >> 4) & 0x0F);
			hdr[1] = (new_tc << 4) | (hdr[1] & 0x0F);
			meta->dscp = meta->dscp_rewrite;
		}
	}
}

static __always_inline int
try_userspace_redirect(struct xdp_md *ctx, struct pkt_meta *meta)
{
	__u32 zero = 0;
	struct userspace_ctrl *ctrl = bpf_map_lookup_elem(&userspace_ctrl, &zero);
	__u32 q = ctx->rx_queue_index;
	struct userspace_binding_key binding_key = {
		.ifindex = meta->ingress_ifindex,
		.queue_id = q,
	};
	struct userspace_binding_value *binding;
	struct userspace_dp_meta *umeta;
	void *data_meta;
	void *data;
	int rc;

	if (!ctrl || ctrl->enabled == 0 || ctrl->metadata_version != USERSPACE_META_VERSION)
		return 0;

	binding = bpf_map_lookup_elem(&userspace_bindings, &binding_key);
	if (!binding || !(binding->flags & 1))
		return 0;

	if (bpf_xdp_adjust_meta(ctx, 0 - (__s32)sizeof(*umeta)) < 0)
		return 0;

	data_meta = (void *)(long)ctx->data_meta;
	data = (void *)(long)ctx->data;
	if (data_meta + sizeof(*umeta) > data)
		return 0;

	umeta = data_meta;
	__builtin_memset(umeta, 0, sizeof(*umeta));
	umeta->magic = USERSPACE_META_MAGIC;
	umeta->version = USERSPACE_META_VERSION;
	umeta->length = sizeof(*umeta);
	umeta->ingress_ifindex = meta->ingress_ifindex;
	umeta->rx_queue_index = q;
	umeta->ingress_vlan_id = meta->ingress_vlan_id;
	umeta->ingress_zone = meta->ingress_zone;
	umeta->routing_table = meta->routing_table;
	umeta->l3_offset = meta->l3_offset;
	umeta->l4_offset = meta->l4_offset;
	umeta->payload_offset = meta->payload_offset;
	umeta->pkt_len = meta->pkt_len;
	umeta->addr_family = meta->addr_family;
	umeta->protocol = meta->protocol;
	umeta->tcp_flags = meta->tcp_flags;
	umeta->meta_flags = meta->meta_flags;
	umeta->dscp = meta->dscp;
	umeta->dscp_rewrite = meta->dscp_rewrite;
	umeta->config_generation = ctrl->config_generation;
	umeta->fib_generation = ctrl->fib_generation;

	rc = bpf_redirect_map(&userspace_xsk_map, binding->slot, 0);
	if (rc == XDP_REDIRECT)
		return rc;

	return 0;
}

SEC("xdp")
int xdp_userspace_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 l3_offset, eth_proto, vlan_id = 0;
	__u32 zero = 0;
	struct pkt_meta *meta;
	int fast_rc, filt_rc, target, redirect_rc;

	if (parse_ethhdr(data, data_end, &l3_offset, &eth_proto, &vlan_id) < 0)
		return XDP_DROP;

	meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Skip the v4/v6 addresses: parse_iphdr()/parse_ipv6hdr() always rewrite them. */
	__builtin_memset((__u8 *)meta + 32, 0, sizeof(*meta) - 32);
	meta->direction = 0;
	meta->ingress_ifindex = ctx->ingress_ifindex;
	meta->ingress_vlan_id = vlan_id;
	meta->dscp_rewrite = 0xFF;
	meta->now_sec = (__u32)(bpf_ktime_get_coarse_ns() / 1000000000ULL);
	meta->ktime_ns = 0;

	if (vlan_id != 0) {
		if (xdp_vlan_tag_pop(ctx) < 0)
			return XDP_DROP;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		l3_offset = sizeof(struct ethhdr);
	}

	meta->l3_offset = l3_offset;

	if (eth_proto == ETH_P_IP) {
		fast_rc = parse_ipv4_l4_fast(data, data_end, meta);
		if (fast_rc < 0)
			return XDP_DROP;
		if (fast_rc == 0) {
			if (parse_iphdr(data, data_end, meta) < 0)
				return XDP_DROP;
			if (!meta->is_fragment &&
			    parse_l4hdr(data, data_end, meta) < 0)
				return XDP_DROP;
		}
	} else if (eth_proto == ETH_P_IPV6) {
		fast_rc = parse_ipv6_l4_fast(data, data_end, meta);
		if (fast_rc < 0)
			return XDP_DROP;
		if (fast_rc == 0) {
			if (parse_ipv6hdr(data, data_end, meta) < 0)
				return XDP_DROP;
			if (!meta->is_fragment &&
			    parse_l4hdr(data, data_end, meta) < 0)
				return XDP_DROP;
		}
	} else {
		if (vlan_id != 0) {
			if (xdp_vlan_tag_push(ctx, vlan_id) < 0)
				return XDP_DROP;
		}
		return XDP_PASS;
	}

	filt_rc = evaluate_firewall_filter(meta);
	if (filt_rc < 0)
		return XDP_DROP;

	inc_counter(GLOBAL_CTR_RX_PACKETS);
	inc_iface_rx(meta->ingress_ifindex, meta->pkt_len);

	TRACE_XDP_MAIN(meta);

	target = resolve_ingress_xdp_target(meta);
	if (target < 0)
		return XDP_DROP;

	/*
	 * Only hand off the common path that already skips screen. Packets that
	 * still need the XDP screen stage continue through the existing pipeline.
	 */
	if (target == XDP_PROG_ZONE) {
		redirect_rc = try_userspace_redirect(ctx, meta);
		if (redirect_rc == XDP_REDIRECT)
			return redirect_rc;
	}

	if (meta->dscp_rewrite != 0xFF) {
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		apply_dscp_rewrite(data, data_end, meta);
	}

	bpf_tail_call(ctx, &xdp_progs, target);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
