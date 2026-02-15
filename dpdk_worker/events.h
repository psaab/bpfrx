/* SPDX-License-Identifier: GPL-2.0-or-later
 * events.h — Event emission helpers for DPDK pipeline.
 *
 * Allocates events via rte_malloc (hugepage-backed so both DPDK primary
 * and Go secondary process can access them), fills from pkt_meta, and
 * enqueues to the shared event_ring.  The Go side dequeues and frees
 * with rte_free.
 */

#ifndef DPDK_EVENTS_H
#define DPDK_EVENTS_H

#include <string.h>

#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include "shared_mem.h"
#include "tables.h"

/**
 * emit_event — Enqueue an event to the shared event ring.
 *
 * @ctx:        Pipeline context (provides shm->event_ring)
 * @meta:       Parsed packet metadata
 * @event_type: EVENT_TYPE_* constant
 * @action:     ACTION_* or FILTER_ACTION_* result
 *
 * For SESSION_CLOSE events that carry counters, use emit_event_with_stats().
 * If the ring is full or event_ring is NULL, the event is silently dropped.
 */
static inline void
emit_event(struct pipeline_ctx *ctx, struct pkt_meta *meta,
           uint8_t event_type, uint8_t action)
{
	if (!ctx->shm->event_ring)
		return;

	struct event *ev = rte_malloc(NULL, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->timestamp = rte_rdtsc();
	ev->src_port = meta->src_port;
	ev->dst_port = meta->dst_port;
	ev->policy_id = meta->policy_id;
	ev->ingress_zone = meta->ingress_zone;
	ev->egress_zone = meta->egress_zone;
	ev->event_type = event_type;
	ev->protocol = meta->protocol;
	ev->action = action;
	ev->addr_family = meta->addr_family;
	ev->session_packets = 0;
	ev->session_bytes = 0;

	/* Copy IP addresses — full 16 bytes covers both v4 and v6 */
	memcpy(ev->src_ip, meta->src_ip.v6, 16);
	memcpy(ev->dst_ip, meta->dst_ip.v6, 16);

	/* Zero NAT fields for non-session events */
	memset(ev->nat_src_ip, 0, 16);
	memset(ev->nat_dst_ip, 0, 16);
	ev->nat_src_port = 0;
	ev->nat_dst_port = 0;
	ev->created = 0;

	if (rte_ring_enqueue(ctx->shm->event_ring, ev) != 0)
		rte_free(ev);  /* Ring full — drop silently */
}

/**
 * emit_event_with_stats — Enqueue an event with session packet/byte counters.
 *
 * Used for SESSION_CLOSE events where we want to report final counters.
 */
static inline void
emit_event_with_stats(struct pipeline_ctx *ctx, struct pkt_meta *meta,
                      uint8_t event_type, uint8_t action,
                      uint64_t packets, uint64_t bytes)
{
	if (!ctx->shm->event_ring)
		return;

	struct event *ev = rte_malloc(NULL, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->timestamp = rte_rdtsc();
	ev->src_port = meta->src_port;
	ev->dst_port = meta->dst_port;
	ev->policy_id = meta->policy_id;
	ev->ingress_zone = meta->ingress_zone;
	ev->egress_zone = meta->egress_zone;
	ev->event_type = event_type;
	ev->protocol = meta->protocol;
	ev->action = action;
	ev->addr_family = meta->addr_family;
	ev->session_packets = packets;
	ev->session_bytes = bytes;

	memcpy(ev->src_ip, meta->src_ip.v6, 16);
	memcpy(ev->dst_ip, meta->dst_ip.v6, 16);

	/* Zero NAT fields — DPDK pipeline doesn't have session NAT info here */
	memset(ev->nat_src_ip, 0, 16);
	memset(ev->nat_dst_ip, 0, 16);
	ev->nat_src_port = 0;
	ev->nat_dst_port = 0;
	ev->created = 0;

	if (rte_ring_enqueue(ctx->shm->event_ring, ev) != 0)
		rte_free(ev);
}

#endif /* DPDK_EVENTS_H */
