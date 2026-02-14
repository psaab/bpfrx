/* SPDX-License-Identifier: GPL-2.0-or-later
 * rx_poll.c — Pure poll-mode RX loop.
 *
 * Lowest latency, highest CPU usage (100% per core even at idle).
 * Best for data center / high-throughput deployments (40G/100G).
 */

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_cycles.h>

#include "shared_mem.h"
#include "tables.h"

/* Defined in pipeline.c */
extern void process_burst(struct rte_mbuf **pkts, uint16_t nb_pkts,
                          struct pipeline_ctx *ctx);

/* Heartbeat update interval (~1 second in TSC ticks) */
#define HEARTBEAT_INTERVAL_TSC (rte_get_tsc_hz())

/**
 * rx_loop_poll — Simple poll-mode RX loop.
 *
 * Continuously polls all assigned ports/queues for packets.
 * Never sleeps — always burning CPU cycles. Provides the absolute
 * lowest latency path from NIC to processing.
 *
 * @conf: Per-lcore configuration (ports, queues, pipeline context)
 */
void
rx_loop_poll(struct lcore_conf *conf)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	uint16_t nb_rx;
	uint64_t next_heartbeat = rte_rdtsc() + HEARTBEAT_INTERVAL_TSC;

	printf("lcore %u: entering poll-mode RX loop (%u ports)\n",
	       rte_lcore_id(), conf->n_ports);

	while (!conf->ctx->shm->shutdown) {
		for (uint16_t i = 0; i < conf->n_ports; i++) {
			uint16_t port_id = conf->ports[i].port_id;
			uint16_t queue_id = conf->ports[i].queue_id;

			nb_rx = rte_eth_rx_burst(port_id, queue_id,
			                         pkts, BURST_SIZE);
			if (nb_rx > 0)
				process_burst(pkts, nb_rx, conf->ctx);
		}

		/* Periodic heartbeat update (~1/s) */
		uint64_t now = rte_rdtsc();
		if (now >= next_heartbeat) {
			conf->ctx->shm->worker_heartbeat[conf->ctx->lcore_id] = now;
			next_heartbeat = now + HEARTBEAT_INTERVAL_TSC;
		}
	}

	printf("lcore %u: poll-mode RX loop exiting\n", rte_lcore_id());
}
