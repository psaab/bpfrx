/* SPDX-License-Identifier: GPL-2.0-or-later
 * tables.h — Table size constants and DPDK data structure declarations.
 *
 * Max sizes match BPF constants from bpf/headers/bpfrx_common.h.
 * DPDK equivalents: BPF HASH -> rte_hash, BPF ARRAY -> C array,
 * BPF LPM_TRIE -> rte_lpm/rte_lpm6, BPF PERCPU_ARRAY -> per-lcore array.
 */

#ifndef DPDK_TABLES_H
#define DPDK_TABLES_H

#include <rte_hash.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ring.h>

#include "shared_mem.h"

/* ============================================================
 * Table size constants (match bpfrx_common.h)
 * ============================================================ */

#define MAX_ZONES              64
#define MAX_INTERFACES         256
#define MAX_LOGICAL_INTERFACES 512
#define MAX_POLICIES           4096
#define MAX_RULES_PER_POLICY   256
#define MAX_SESSIONS           1048576  /* 1M sessions */
#define MAX_NAT_POOLS          32
#define MAX_NAT_POOL_IPS       256
#define MAX_NAT_RULE_COUNTERS  256
#define MAX_ADDRESSES          8192
#define MAX_APPLICATIONS       1024
#define MAX_SCREEN_PROFILES    64
#define MAX_PORT_SCAN_TRACK    65536
#define MAX_FILTER_CONFIGS     64
#define MAX_FILTER_RULES       512
#define MAX_FILTER_RULES_PER_FILTER 32
#define MAX_NAT64_PREFIXES     4
#define MAX_STATIC_NAT_ENTRIES 2048

/* Flow timeout indices */
#define FLOW_TIMEOUT_TCP_ESTABLISHED 0
#define FLOW_TIMEOUT_TCP_INITIAL     1
#define FLOW_TIMEOUT_TCP_CLOSING     2
#define FLOW_TIMEOUT_TCP_TIME_WAIT   3
#define FLOW_TIMEOUT_UDP             4
#define FLOW_TIMEOUT_ICMP            5
#define FLOW_TIMEOUT_OTHER           6
#define FLOW_TIMEOUT_MAX             7

/* Global counter indices */
#define GLOBAL_CTR_RX_PACKETS          0
#define GLOBAL_CTR_TX_PACKETS          1
#define GLOBAL_CTR_DROPS               2
#define GLOBAL_CTR_SESSIONS_NEW        3
#define GLOBAL_CTR_SESSIONS_CLOSED     4
#define GLOBAL_CTR_SCREEN_DROPS        5
#define GLOBAL_CTR_POLICY_DENY         6
#define GLOBAL_CTR_NAT_ALLOC_FAIL      7
#define GLOBAL_CTR_HOST_INBOUND_DENY   8
#define GLOBAL_CTR_TC_EGRESS_PACKETS   9
#define GLOBAL_CTR_NAT64_XLATE        10
#define GLOBAL_CTR_HOST_INBOUND       11
#define GLOBAL_CTR_SCREEN_SYN_FLOOD   12
#define GLOBAL_CTR_SCREEN_ICMP_FLOOD  13
#define GLOBAL_CTR_SCREEN_UDP_FLOOD   14
#define GLOBAL_CTR_SCREEN_PORT_SCAN   15
#define GLOBAL_CTR_SCREEN_IP_SWEEP    16
#define GLOBAL_CTR_SCREEN_LAND_ATTACK 17
#define GLOBAL_CTR_SCREEN_PING_DEATH  18
#define GLOBAL_CTR_SCREEN_TEAR_DROP   19
#define GLOBAL_CTR_SCREEN_TCP_SYN_FIN 20
#define GLOBAL_CTR_SCREEN_TCP_NO_FLAG 21
#define GLOBAL_CTR_SCREEN_TCP_FIN_NO_ACK 22
#define GLOBAL_CTR_SCREEN_WINNUKE     23
#define GLOBAL_CTR_SCREEN_IP_SRC_ROUTE 24
#define GLOBAL_CTR_SCREEN_SYN_FRAG    25
#define GLOBAL_CTR_MAX                26

/* ============================================================
 * RX mode constants
 * ============================================================ */

#define RX_MODE_POLL      0
#define RX_MODE_INTERRUPT 1
#define RX_MODE_ADAPTIVE  2

/* ============================================================
 * Pipeline constants
 * ============================================================ */

#define BURST_SIZE       32
#define RING_SIZE        4096
#define EVENT_RING_SIZE  (1 << 16)  /* 64K events */

/* ============================================================
 * Per-lcore configuration
 * ============================================================ */

#define MAX_LCORES       64
#define MAX_PORTS        16
#define MAX_QUEUES_PER_PORT 16

struct port_queue_conf {
	uint16_t port_id;
	uint16_t queue_id;
};

struct lcore_conf {
	uint16_t             n_ports;
	struct port_queue_conf ports[MAX_PORTS];
	uint32_t             rx_mode;       /* RX_MODE_* */
	struct pipeline_ctx  *ctx;
};

/* ============================================================
 * Pipeline context — per-lcore working state
 * ============================================================ */

struct pipeline_ctx {
	struct shared_memory *shm;
	unsigned             lcore_id;

	/* Per-lcore counter arrays (cache-line aligned, no locks) */
	struct counter_value       *policy_counters;      /* [MAX_POLICIES] */
	struct counter_value       *zone_counters;        /* [MAX_ZONES * 2] */
	struct iface_counter_value *interface_counters;   /* [MAX_INTERFACES] */
	uint64_t                   *global_counters;      /* [GLOBAL_CTR_MAX] */
	struct counter_value       *filter_counters;      /* [MAX_FILTER_RULES] */
	struct counter_value       *nat_rule_counters;    /* [MAX_NAT_RULE_COUNTERS] */
	struct flood_state         *flood_states;         /* [MAX_ZONES] */

	/* Mode-switch counter (adaptive mode) */
	uint64_t mode_switches;

	/* Per-lcore SNAT port allocation counter */
	uint64_t snat_port_counter;
};

/* ============================================================
 * Table creation helpers (implemented in main.c)
 * ============================================================ */

/**
 * Allocate and initialize all shared memory tables.
 * Returns 0 on success, -1 on failure.
 */
int tables_init(struct shared_memory *shm);

/**
 * Allocate per-lcore counter arrays for the given pipeline context.
 * Returns 0 on success, -1 on failure.
 */
int counters_alloc(struct pipeline_ctx *ctx);

#endif /* DPDK_TABLES_H */
