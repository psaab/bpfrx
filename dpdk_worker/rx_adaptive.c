/* SPDX-License-Identifier: GPL-2.0-or-later
 * rx_adaptive.c — Adaptive poll/interrupt RX loop.
 *
 * Dynamically switches between poll-mode and interrupt-mode based on
 * traffic load. Provides poll-mode performance under load and
 * interrupt-mode efficiency at idle.
 *
 * Recommended as the default RX mode for general-purpose deployments.
 */

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_epoll.h>
#include <rte_cycles.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/* Defined in pipeline.c */
extern void process_burst(struct rte_mbuf **pkts, uint16_t nb_pkts,
                          struct pipeline_ctx *ctx);

/* Defined in power.c */
extern void power_init(unsigned lcore_id);
extern void power_scale_down(unsigned lcore_id);
extern void power_scale_up(unsigned lcore_id);

/* Adaptive mode thresholds (can be overridden via shared memory config) */
#define POLL_IDLE_THRESHOLD   256   /* Empty polls before switching to interrupt */
#define POLL_RESUME_BURST     32    /* Packets in interrupt wakeup to resume polling */
#define ADAPTIVE_TIMEOUT_MS   100   /* Max sleep ms in interrupt mode */

enum rx_state { RX_POLL, RX_INTERRUPT };

/**
 * rx_loop_adaptive — Adaptive poll/interrupt RX loop.
 *
 * Starts in poll mode. After POLL_IDLE_THRESHOLD consecutive empty
 * polls, switches to interrupt mode. On receiving a burst >=
 * POLL_RESUME_BURST packets from an interrupt wakeup, switches
 * back to poll mode.
 *
 * @conf: Per-lcore configuration
 */
void
rx_loop_adaptive(struct lcore_conf *conf)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	enum rx_state state = RX_POLL;
	uint32_t idle_polls = 0;
	uint64_t next_heartbeat = rte_rdtsc() + rte_get_tsc_hz();

	printf("lcore %u: entering adaptive RX loop (%u ports)\n",
	       rte_lcore_id(), conf->n_ports);

	/* Initialize power management for this core */
	power_init(rte_lcore_id());

	while (!conf->ctx->shm->shutdown) {
		int had_packets = 0;

		for (uint16_t i = 0; i < conf->n_ports; i++) {
			uint16_t port_id = conf->ports[i].port_id;
			uint16_t queue_id = conf->ports[i].queue_id;

			uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id,
			                                   pkts, BURST_SIZE);
			if (nb_rx > 0) {
				process_burst(pkts, nb_rx, conf->ctx);
				had_packets = 1;
				idle_polls = 0;

				/* If in interrupt mode and got a big burst,
				 * switch back to polling for lower latency */
				if (state == RX_INTERRUPT &&
				    nb_rx >= POLL_RESUME_BURST) {
					state = RX_POLL;
					conf->ctx->mode_switches++;
					power_scale_up(rte_lcore_id());
				}
			}
		}

		/* Periodic heartbeat update (~1/s) */
		uint64_t now = rte_rdtsc();
		if (now >= next_heartbeat) {
			conf->ctx->shm->worker_heartbeat[conf->ctx->lcore_id] = now;
			next_heartbeat = now + rte_get_tsc_hz();
		}

		if (had_packets)
			continue;

		/* No packets received */
		idle_polls++;

		if (state == RX_POLL && idle_polls > POLL_IDLE_THRESHOLD) {
			/* Too many empty polls — switch to interrupt mode */
			state = RX_INTERRUPT;
			conf->ctx->mode_switches++;
			power_scale_down(rte_lcore_id());
		}

		if (state == RX_INTERRUPT) {
			/* Arm interrupts and sleep */
			for (uint16_t i = 0; i < conf->n_ports; i++) {
				rte_eth_dev_rx_intr_enable(
					conf->ports[i].port_id,
					conf->ports[i].queue_id);
			}

			struct rte_epoll_event ev;
			rte_epoll_wait(RTE_EPOLL_PER_THREAD, &ev, 1,
			               ADAPTIVE_TIMEOUT_MS);

			for (uint16_t i = 0; i < conf->n_ports; i++) {
				rte_eth_dev_rx_intr_disable(
					conf->ports[i].port_id,
					conf->ports[i].queue_id);
			}

			idle_polls = 0;  /* Reset after wakeup */
		}
	}

	printf("lcore %u: adaptive RX loop exiting (mode_switches=%lu)\n",
	       rte_lcore_id(), conf->ctx->mode_switches);
}
