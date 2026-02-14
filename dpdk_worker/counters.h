/* SPDX-License-Identifier: GPL-2.0-or-later
 * counters.h — Per-lcore counter arrays and aggregation functions.
 *
 * Each lcore maintains its own counter arrays (no locks needed for updates).
 * The Go control plane aggregates across lcores via CGo calls.
 */

#ifndef DPDK_COUNTERS_H
#define DPDK_COUNTERS_H

#include <stdint.h>
#include <rte_cycles.h>
#include "tables.h"
#include "shared_mem.h"

/* ============================================================
 * Per-lcore counter storage
 *
 * Allocated per-lcore in NUMA-local memory. Each lcore's pipeline_ctx
 * points to its own instance. Cache-line aligned to avoid false sharing.
 * ============================================================ */

/* Latency histogram: 16 log2 buckets (0-1us, 1-2us, 2-4us, ..., 32ms+) */
#define LATENCY_BUCKETS 16

struct lcore_counters {
	struct counter_value       policy_counters[MAX_POLICIES]
		__attribute__((aligned(64)));
	struct counter_value       zone_counters[MAX_ZONES * 2]
		__attribute__((aligned(64)));
	struct iface_counter_value interface_counters[MAX_INTERFACES]
		__attribute__((aligned(64)));
	uint64_t                   global_counters[GLOBAL_CTR_MAX]
		__attribute__((aligned(64)));
	struct counter_value       filter_counters[MAX_FILTER_RULES]
		__attribute__((aligned(64)));
	struct counter_value       nat_rule_counters[MAX_NAT_RULE_COUNTERS]
		__attribute__((aligned(64)));
	struct flood_state         flood_states[MAX_ZONES]
		__attribute__((aligned(64)));
	uint64_t                   nat_port_allocs[MAX_NAT_POOLS]
		__attribute__((aligned(64)));
	uint64_t                   latency_histogram[LATENCY_BUCKETS]
		__attribute__((aligned(64)));
};

/* Global array of per-lcore counters (indexed by lcore_id) */
extern struct lcore_counters *lcore_counter_array[MAX_LCORES];

/* ============================================================
 * Counter increment helpers (called from pipeline hot path)
 * ============================================================ */

static inline void
ctr_global_inc(struct pipeline_ctx *ctx, uint32_t idx)
{
	ctx->global_counters[idx]++;
}

static inline void
ctr_policy_add(struct pipeline_ctx *ctx, uint32_t policy_id,
               uint64_t bytes)
{
	if (policy_id < MAX_POLICIES) {
		ctx->policy_counters[policy_id].packets++;
		ctx->policy_counters[policy_id].bytes += bytes;
	}
}

static inline void
ctr_zone_add(struct pipeline_ctx *ctx, uint32_t zone_id,
             uint8_t direction, uint64_t bytes)
{
	uint32_t idx = zone_id * 2 + direction;
	if (idx < MAX_ZONES * 2) {
		ctx->zone_counters[idx].packets++;
		ctx->zone_counters[idx].bytes += bytes;
	}
}

static inline void
ctr_iface_rx_add(struct pipeline_ctx *ctx, uint32_t ifindex,
                 uint64_t bytes)
{
	if (ifindex < MAX_INTERFACES) {
		ctx->interface_counters[ifindex].rx_packets++;
		ctx->interface_counters[ifindex].rx_bytes += bytes;
	}
}

static inline void
ctr_iface_tx_add(struct pipeline_ctx *ctx, uint32_t ifindex,
                 uint64_t bytes)
{
	if (ifindex < MAX_INTERFACES) {
		ctx->interface_counters[ifindex].tx_packets++;
		ctx->interface_counters[ifindex].tx_bytes += bytes;
	}
}

static inline void
ctr_filter_add(struct pipeline_ctx *ctx, uint32_t rule_idx,
               uint64_t bytes)
{
	if (rule_idx < MAX_FILTER_RULES) {
		ctx->filter_counters[rule_idx].packets++;
		ctx->filter_counters[rule_idx].bytes += bytes;
	}
}

static inline void
ctr_nat_rule_add(struct pipeline_ctx *ctx, uint32_t counter_id,
                 uint64_t bytes)
{
	if (counter_id < MAX_NAT_RULE_COUNTERS) {
		ctx->nat_rule_counters[counter_id].packets++;
		ctx->nat_rule_counters[counter_id].bytes += bytes;
	}
}

static inline void
ctr_nat_port_alloc(struct pipeline_ctx *ctx, uint32_t pool_id)
{
	if (pool_id < MAX_NAT_POOLS)
		ctx->nat_port_allocs[pool_id]++;
}

static inline void
ctr_latency_record(struct pipeline_ctx *ctx, uint64_t start_tsc)
{
	uint64_t delta = rte_rdtsc() - start_tsc;
	uint64_t us = delta / ctx->tsc_per_us;
	unsigned bucket;
	if (us == 0)
		bucket = 0;
	else {
		bucket = 64 - __builtin_clzll(us);
		if (bucket >= LATENCY_BUCKETS)
			bucket = LATENCY_BUCKETS - 1;
	}
	ctx->latency_histogram[bucket]++;
}

/* ============================================================
 * Aggregation functions (called from Go via CGo)
 *
 * These sum counters across all lcores. Safe to call while workers
 * are running — individual reads are atomic on x86_64.
 * ============================================================ */

/**
 * Aggregate global counter across all lcores.
 */
uint64_t counters_aggregate_global(uint32_t idx);

/**
 * Aggregate policy counter across all lcores.
 */
void counters_aggregate_policy(uint32_t policy_id,
                               uint64_t *packets, uint64_t *bytes);

/**
 * Aggregate zone counter across all lcores.
 */
void counters_aggregate_zone(uint32_t zone_id, uint8_t direction,
                             uint64_t *packets, uint64_t *bytes);

/**
 * Aggregate interface counter across all lcores.
 */
void counters_aggregate_iface(uint32_t ifindex,
                              uint64_t *rx_pkts, uint64_t *rx_bytes,
                              uint64_t *tx_pkts, uint64_t *tx_bytes);

/**
 * Aggregate filter rule counter across all lcores.
 */
void counters_aggregate_filter(uint32_t rule_idx,
                               uint64_t *packets, uint64_t *bytes);

/**
 * Aggregate NAT rule counter across all lcores.
 */
void counters_aggregate_nat_rule(uint32_t counter_id,
                                 uint64_t *packets, uint64_t *bytes);

/**
 * Clear all counters on all lcores.
 */
void counters_clear_all(void);

/**
 * Selective counter clearing functions.
 * Each clears only the specified counter category across all lcores.
 */
void counters_clear_global(void);
void counters_clear_interface(void);
void counters_clear_zone(void);
void counters_clear_policy(void);
void counters_clear_filter(void);
void counters_clear_nat_rule(void);

/**
 * Aggregate SNAT port allocation counter across all lcores (all pools).
 */
uint64_t counters_aggregate_snat_port(void);

/**
 * Aggregate SNAT port allocation counter for a specific pool.
 */
void counters_aggregate_nat_port(uint32_t pool_id, uint64_t *allocs);

/**
 * Aggregate latency histogram across all lcores.
 * Output array must have LATENCY_BUCKETS elements.
 */
void counters_aggregate_latency(uint64_t *out);

/**
 * Clear latency histograms on all lcores.
 */
void counters_clear_latency(void);

/**
 * Aggregate flood counters for a zone across all lcores.
 */
void counters_aggregate_flood(uint32_t zone_id,
                              uint64_t *syn, uint64_t *icmp, uint64_t *udp);

#endif /* DPDK_COUNTERS_H */
