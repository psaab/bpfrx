/* SPDX-License-Identifier: GPL-2.0-or-later
 * rx_interrupt.c — Interrupt-driven RX loop.
 *
 * Uses DPDK's rte_eth_dev_rx_intr_* API to sleep on an epoll fd
 * until the NIC signals new packets. Lowest power usage but higher
 * latency (5-50us from interrupt coalescing).
 *
 * Best for edge, branch, or VM deployments where power matters.
 */

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_epoll.h>
#include <rte_cycles.h>

#include "shared_mem.h"
#include "tables.h"

/* Defined in pipeline.c */
extern void process_burst(struct rte_mbuf **pkts, uint16_t nb_pkts,
                          struct pipeline_ctx *ctx);

/* Defined in power.c */
extern void power_init(unsigned lcore_id);
extern void power_scale_down(unsigned lcore_id);
extern void power_scale_up(unsigned lcore_id);

#define INTR_TIMEOUT_MS 1000  /* Max sleep time before checking shutdown */

/**
 * rx_loop_interrupt — Interrupt-driven RX loop.
 *
 * Sleeps when no packets are available, waking on NIC interrupt.
 * CPU enters C-state during sleep (near-zero power).
 *
 * Flow:
 *   1. rte_eth_rx_burst() — check for packets
 *   2. If packets: process and loop back to step 1
 *   3. If no packets: arm interrupt, sleep on epoll, disable interrupt
 *
 * @conf: Per-lcore configuration
 */
void
rx_loop_interrupt(struct lcore_conf *conf)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	uint16_t nb_rx;
	uint64_t next_heartbeat = rte_rdtsc() + rte_get_tsc_hz();

	printf("lcore %u: entering interrupt-mode RX loop (%u ports)\n",
	       rte_lcore_id(), conf->n_ports);

	/* Initialize power management for this core */
	power_init(rte_lcore_id());

	while (!conf->ctx->shm->shutdown) {
		int had_packets = 0;

		for (uint16_t i = 0; i < conf->n_ports; i++) {
			uint16_t port_id = conf->ports[i].port_id;
			uint16_t queue_id = conf->ports[i].queue_id;

			nb_rx = rte_eth_rx_burst(port_id, queue_id,
			                         pkts, BURST_SIZE);
			if (nb_rx > 0) {
				process_burst(pkts, nb_rx, conf->ctx);
				had_packets = 1;
			}
		}

		/* Periodic heartbeat update (~1/s) */
		uint64_t now = rte_rdtsc();
		if (now >= next_heartbeat) {
			conf->ctx->shm->worker_heartbeat[conf->ctx->lcore_id] = now;
			next_heartbeat = now + rte_get_tsc_hz();
		}

		if (had_packets)
			continue;  /* Keep draining without sleeping */

		/* No packets — arm interrupts and sleep */
		power_scale_down(rte_lcore_id());

		for (uint16_t i = 0; i < conf->n_ports; i++) {
			rte_eth_dev_rx_intr_enable(conf->ports[i].port_id,
			                           conf->ports[i].queue_id);
		}

		/* Sleep until NIC raises interrupt or timeout */
		struct rte_epoll_event ev;
		rte_epoll_wait(RTE_EPOLL_PER_THREAD, &ev, 1, INTR_TIMEOUT_MS);

		/* Disable interrupts before resuming poll */
		for (uint16_t i = 0; i < conf->n_ports; i++) {
			rte_eth_dev_rx_intr_disable(conf->ports[i].port_id,
			                            conf->ports[i].queue_id);
		}

		power_scale_up(rte_lcore_id());
	}

	printf("lcore %u: interrupt-mode RX loop exiting\n", rte_lcore_id());
}
