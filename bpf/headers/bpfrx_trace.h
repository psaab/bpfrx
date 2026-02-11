#ifndef __BPFRX_TRACE_H__
#define __BPFRX_TRACE_H__

/*
 * BPF pipeline tracing via bpf_printk.
 *
 * Enable by setting BPFRX_TRACE to 1 below.
 * Output goes to /sys/kernel/debug/tracing/trace_pipe
 *
 * Read with:
 *   cat /sys/kernel/debug/tracing/trace_pipe
 *   # or on the VM:
 *   incus exec bpfrx-fw -- cat /sys/kernel/debug/tracing/trace_pipe
 */

/* Toggle tracing: set to 1 to enable, 0 to disable */
#define BPFRX_TRACE 0

/* Optional: set to specific protocol number to filter (0 = trace all) */
#define BPFRX_TRACE_PROTO 6  /* TCP only */

#if BPFRX_TRACE

/* Check if we should trace this packet (protocol filter) */
#define TRACE_FILTER(proto) \
	(BPFRX_TRACE_PROTO == 0 || (proto) == BPFRX_TRACE_PROTO)

/* Compact IPv4 address printing: print as hex u32 (use inet_ntoa to decode).
 * bpf_printk format: 0x%08x where the value is in network byte order.
 * Example: 10.0.1.100 = 0x640100a, 1.1.1.1 = 0x01010101 */

#define TRACE_XDP_MAIN(meta) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE xdp_main: proto=%d src=%x dst=%x", \
			   meta->protocol, meta->src_ip.v4, meta->dst_ip.v4); \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("  sport=%d dport=%d csum_partial=%d", \
			   bpf_ntohs(meta->src_port), bpf_ntohs(meta->dst_port), \
			   meta->csum_partial); \
} while (0)

#define TRACE_ZONE(meta) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE zone: in_zone=%d out_zone=%d fwd_if=%d", \
			   meta->ingress_zone, meta->egress_zone, \
			   meta->fwd_ifindex); \
	if (TRACE_FILTER(meta->protocol) && (meta->nat_flags & SESS_FLAG_DNAT)) \
		bpf_printk("  pre-DNAT: dst->%x:%d flags=0x%x", \
			   meta->dst_ip.v4, bpf_ntohs(meta->dst_port), \
			   meta->nat_flags); \
} while (0)

#define TRACE_CT_MISS(meta) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE ct: MISS proto=%d src=%x:%d", \
			   meta->protocol, meta->src_ip.v4, \
			   bpf_ntohs(meta->src_port)); \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("  dst=%x:%d -> POLICY", \
			   meta->dst_ip.v4, bpf_ntohs(meta->dst_port)); \
} while (0)

#define TRACE_CT_HIT(meta, direction, sess_flags) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE ct: HIT dir=%d state=%d flags=0x%x", \
			   direction, meta->ct_state, sess_flags); \
} while (0)

#define TRACE_POLICY(meta, action, rule_id) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE policy: action=%d rule=%d nat_flags=0x%x", \
			   action, rule_id, meta->nat_flags); \
} while (0)

#define TRACE_SNAT(meta, old_ip, new_ip, new_port) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE snat: %x -> %x port=%d", \
			   old_ip, new_ip, bpf_ntohs(new_port)); \
} while (0)

#define TRACE_NAT_REWRITE(meta, tag) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE nat[%s]: src=%x:%d dst=%x:%d csum_p=%d", \
			   tag, meta->src_ip.v4, bpf_ntohs(meta->src_port), \
			   meta->dst_ip.v4, bpf_ntohs(meta->dst_port), \
			   meta->csum_partial); \
} while (0)

#define TRACE_NAT_V4_REWRITE(iph, tag) do { \
	bpf_printk("TRACE nat[%s] pkt: src=%x dst=%x", \
		   tag, iph->saddr, iph->daddr); \
} while (0)

#define TRACE_FORWARD(meta) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE fwd: if=%d vlan=%d proto=%d", \
			   meta->fwd_ifindex, meta->egress_vlan_id, \
			   meta->protocol); \
} while (0)

#define TRACE_TC_MAIN(meta) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE tc_main: proto=%d src=%x dst=%x", \
			   meta->protocol, meta->src_ip.v4, meta->dst_ip.v4); \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("  sport=%d dport=%d egress_zone=%d", \
			   bpf_ntohs(meta->src_port), bpf_ntohs(meta->dst_port), \
			   meta->egress_zone); \
} while (0)

#define TRACE_TC_CT(meta, hit, direction) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE tc_ct: hit=%d dir=%d nat_flags=0x%x", \
			   hit, direction, meta->nat_flags); \
} while (0)

#define TRACE_TC_NAT(meta) do { \
	if (TRACE_FILTER(meta->protocol)) \
		bpf_printk("TRACE tc_nat: src=%x:%d dst=%x:%d", \
			   meta->src_ip.v4, bpf_ntohs(meta->src_port), \
			   meta->dst_ip.v4, bpf_ntohs(meta->dst_port)); \
} while (0)

#define TRACE_REDIRECT_RESULT(ifindex, ret) do { \
	bpf_printk("TRACE redirect: if=%d ret=%d", ifindex, ret); \
} while (0)

#define TRACE_MSS_CLAMP(mss, cur_mss) do { \
	bpf_printk("TRACE mss_clamp: max=%d cur=%d", mss, cur_mss); \
} while (0)

#define TRACE_FIB_RESULT(rc, fib_ifindex) do { \
	bpf_printk("TRACE fib: rc=%d ifindex=%d", rc, fib_ifindex); \
} while (0)

#define TRACE_CHECKSUM(tag, csum_val) do { \
	bpf_printk("TRACE csum[%s]: 0x%04x", tag, (__u16)(csum_val)); \
} while (0)

#else /* !BPFRX_TRACE */

#define TRACE_XDP_MAIN(meta) do {} while (0)
#define TRACE_ZONE(meta) do {} while (0)
#define TRACE_CT_MISS(meta) do {} while (0)
#define TRACE_CT_HIT(meta, direction, sess_flags) do {} while (0)
#define TRACE_POLICY(meta, action, rule_id) do {} while (0)
#define TRACE_SNAT(meta, old_ip, new_ip, new_port) do {} while (0)
#define TRACE_NAT_REWRITE(meta, tag) do {} while (0)
#define TRACE_NAT_V4_REWRITE(iph, tag) do {} while (0)
#define TRACE_FORWARD(meta) do {} while (0)
#define TRACE_TC_MAIN(meta) do {} while (0)
#define TRACE_TC_CT(meta, hit, direction) do {} while (0)
#define TRACE_TC_NAT(meta) do {} while (0)
#define TRACE_REDIRECT_RESULT(ifindex, ret) do {} while (0)
#define TRACE_MSS_CLAMP(mss, cur_mss) do {} while (0)
#define TRACE_FIB_RESULT(rc, fib_ifindex) do {} while (0)
#define TRACE_CHECKSUM(tag, csum_val) do {} while (0)

#endif /* BPFRX_TRACE */

#endif /* __BPFRX_TRACE_H__ */
