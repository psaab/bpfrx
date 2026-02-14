/* SPDX-License-Identifier: GPL-2.0-or-later
 * pipeline.c — Top-level per-packet and per-burst dispatch.
 *
 * Replaces the 14 BPF tail-call programs with a single function-call
 * pipeline: parse -> filter -> screen -> zone -> conntrack -> policy
 * -> nat -> nat64 -> forward.
 */

#include <rte_mbuf.h>
#include <rte_ether.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/* Pipeline stage forward declarations */
extern int  parse_packet(struct rte_mbuf *pkt, struct pkt_meta *meta);
extern int  evaluate_filter(struct rte_mbuf *pkt, struct pkt_meta *meta,
                            struct pipeline_ctx *ctx, uint8_t direction);
extern int  screen_check(struct rte_mbuf *pkt, struct pkt_meta *meta,
                         struct pipeline_ctx *ctx);
extern void zone_lookup(struct rte_mbuf *pkt, struct pkt_meta *meta,
                        struct pipeline_ctx *ctx);
extern int  conntrack_lookup(struct rte_mbuf *pkt, struct pkt_meta *meta,
                             struct pipeline_ctx *ctx);
extern void tcp_mss_clamp(struct rte_mbuf *pkt, struct pkt_meta *meta,
                           struct pipeline_ctx *ctx);
extern int  conntrack_create(struct rte_mbuf *pkt, struct pkt_meta *meta,
                             struct pipeline_ctx *ctx);
extern int  policy_check(struct rte_mbuf *pkt, struct pkt_meta *meta,
                         struct pipeline_ctx *ctx);
extern int  nat_rewrite(struct rte_mbuf *pkt, struct pkt_meta *meta,
                        struct pipeline_ctx *ctx);
extern void nat64_translate(struct rte_mbuf *pkt, struct pkt_meta *meta,
                            struct pipeline_ctx *ctx);
extern void forward_packet(struct rte_mbuf *pkt, struct pkt_meta *meta,
                           struct pipeline_ctx *ctx);

/* Rejection forward declarations (reject.c) */
extern void send_tcp_rst_v4(struct rte_mbuf *pkt, struct pkt_meta *meta,
                            struct pipeline_ctx *ctx);
extern void send_tcp_rst_v6(struct rte_mbuf *pkt, struct pkt_meta *meta,
                            struct pipeline_ctx *ctx);
extern void send_icmp_unreach_v4(struct rte_mbuf *pkt, struct pkt_meta *meta,
                                 struct pipeline_ctx *ctx);
extern void send_icmp_unreach_v6(struct rte_mbuf *pkt, struct pkt_meta *meta,
                                 struct pipeline_ctx *ctx);

/* Conntrack result codes */
#define CT_NEW         0
#define CT_ESTABLISHED 1
#define CT_INVALID     2
#define CT_DNS_REPLY   3

/**
 * process_packet — Main per-packet processing function.
 *
 * Replaces the 14 BPF programs (xdp_main -> xdp_screen -> xdp_zone ->
 * xdp_conntrack -> xdp_policy -> xdp_nat -> xdp_nat64 -> xdp_forward)
 * with direct function calls. No tail calls, no per-CPU scratch map —
 * pkt_meta lives on the stack.
 */
static inline void
process_packet(struct rte_mbuf *pkt, struct pipeline_ctx *ctx)
{
	struct pkt_meta meta;
	int ct_result;

	memset(&meta, 0, sizeof(meta));

	ctr_global_inc(ctx, GLOBAL_CTR_RX_PACKETS);

	/* 1. Parse (replaces xdp_main) */
	if (parse_packet(pkt, &meta) < 0)
		goto drop;

	ctr_iface_rx_add(ctx, meta.ingress_ifindex, rte_pktmbuf_pkt_len(pkt));

	/* 2. Ingress filter (replaces xdp_main filter check) */
	if (evaluate_filter(pkt, &meta, ctx, 0) == FILTER_ACTION_DISCARD)
		goto drop;

	/* 3. Screen/IDS (replaces xdp_screen) */
	if (screen_check(pkt, &meta, ctx) < 0)
		goto drop;

	/* 4. Zone lookup (replaces xdp_zone) */
	zone_lookup(pkt, &meta, ctx);

	ctr_zone_add(ctx, meta.ingress_zone, 0, rte_pktmbuf_pkt_len(pkt));

	/* 5. Conntrack (replaces xdp_conntrack) */
	ct_result = conntrack_lookup(pkt, &meta, ctx);

	/* TCP MSS clamping on SYN packets (before session creation) */
	if (meta.protocol == PROTO_TCP && (meta.tcp_flags & 0x02))
		tcp_mss_clamp(pkt, &meta, ctx);

	if (ct_result == CT_ESTABLISHED &&
	    !(meta.nat_flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT)))
		goto forward;  /* Fast path: established, no NAT */

	/* allow-dns-reply: bypass policy for unsolicited DNS responses */
	if (ct_result == CT_DNS_REPLY)
		goto forward;

	/* 6. Policy (replaces xdp_policy, only for new sessions) */
	if (ct_result == CT_NEW) {
		int action = policy_check(pkt, &meta, ctx);
		if (action == ACTION_REJECT) {
			if (meta.protocol == PROTO_TCP) {
				if (meta.addr_family == AF_INET)
					send_tcp_rst_v4(pkt, &meta, ctx);
				else
					send_tcp_rst_v6(pkt, &meta, ctx);
			} else {
				if (meta.addr_family == AF_INET)
					send_icmp_unreach_v4(pkt, &meta, ctx);
				else
					send_icmp_unreach_v6(pkt, &meta, ctx);
			}
			rte_pktmbuf_free(pkt);
			ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
			return;
		}
		if (action != ACTION_PERMIT)
			goto drop;
		conntrack_create(pkt, &meta, ctx);
		ctr_global_inc(ctx, GLOBAL_CTR_SESSIONS_NEW);
	}

	/* 7. NAT (replaces xdp_nat) */
	if (meta.nat_flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT)) {
		if (nat_rewrite(pkt, &meta, ctx) < 0)
			return;  /* TTL expired — already freed */
	}

	/* 8. NAT64 (replaces xdp_nat64) */
	if (meta.nat_flags & SESS_FLAG_NAT64) {
		nat64_translate(pkt, &meta, ctx);
		ctr_global_inc(ctx, GLOBAL_CTR_NAT64_XLATE);
	}

forward:
	/* 9. Egress filter */
	if (evaluate_filter(pkt, &meta, ctx, 1) == FILTER_ACTION_DISCARD)
		goto drop;

	/* 10. Forward (replaces xdp_forward) */
	forward_packet(pkt, &meta, ctx);
	ctr_global_inc(ctx, GLOBAL_CTR_TX_PACKETS);
	return;

drop:
	rte_pktmbuf_free(pkt);
	ctr_global_inc(ctx, GLOBAL_CTR_DROPS);
}

/**
 * process_burst — Process a burst of packets.
 *
 * Called from the RX loop after rte_eth_rx_burst(). Processes each
 * packet through the full pipeline sequentially.
 *
 * TODO: Consider prefetching next packet headers while processing
 * current packet for better cache behavior.
 */
void
process_burst(struct rte_mbuf **pkts, uint16_t nb_pkts,
              struct pipeline_ctx *ctx)
{
	for (uint16_t i = 0; i < nb_pkts; i++) {
		/* Prefetch next packet's header data */
		if (i + 1 < nb_pkts)
			rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 1], void *));

		process_packet(pkts[i], ctx);
	}
}
