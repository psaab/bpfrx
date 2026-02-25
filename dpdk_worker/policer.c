/* SPDX-License-Identifier: GPL-2.0-or-later
 * policer.c — Token bucket policer evaluation for DPDK pipeline.
 *
 * Ports evaluate_policer() from BPF helpers (bpfrx_helpers.h:977-1066)
 * using rte_rdtsc() / rte_get_tsc_hz() for timing instead of ktime_ns.
 *
 * Returns: 0=conform, 1=exceed, 2=violate
 */

#include <rte_cycles.h>
#include "shared_mem.h"

#define POLICER_MODE_SINGLE_RATE  0
#define POLICER_MODE_TWO_RATE     1
#define POLICER_MODE_SR3C         2

/**
 * evaluate_policer_dpdk — Token bucket policer (single-rate, two-rate, SR3C).
 *
 * @policer_id: Index into policer_configs/policer_states arrays.
 * @pkt_len:    Packet length in bytes.
 * @ctx:        Pipeline context (for shared memory access).
 *
 * Returns 0 (conform/green), 1 (exceed/yellow), 2 (violate/red).
 */
static inline int
evaluate_policer_dpdk(uint32_t policer_id, uint32_t pkt_len,
                      struct pipeline_ctx *ctx)
{
	struct policer_config *cfg = &ctx->shm->policer_configs[policer_id];
	if (!cfg || cfg->rate_bytes_sec == 0)
		return 0; /* no policer or unconfigured, pass */

	struct policer_state *state = &ctx->shm->policer_states[policer_id];
	if (!state)
		return 0;

	uint64_t now = rte_rdtsc();
	uint64_t elapsed = now - state->last_refill_ns;
	uint64_t hz = rte_get_tsc_hz();

	/* Refill committed tokens: elapsed_ticks * rate_bytes_sec / hz */
	uint64_t c_tokens = state->tokens +
		(elapsed / 1000) * cfg->rate_bytes_sec / (hz / 1000);
	if (c_tokens > cfg->burst_bytes)
		c_tokens = cfg->burst_bytes;

	if (cfg->color_mode == POLICER_MODE_SINGLE_RATE) {
		/* Single-rate two-color (original behavior) */
		if (c_tokens < pkt_len) {
			state->last_refill_ns = now;
			state->tokens = c_tokens;
			return 1; /* exceeded */
		}
		state->tokens = c_tokens - pkt_len;
		state->last_refill_ns = now;
		return 0; /* conforming */
	}

	if (cfg->color_mode == POLICER_MODE_TWO_RATE) {
		/* Two-rate three-color (RFC 2698) */
		uint64_t p_tokens = state->peak_tokens +
			(elapsed / 1000) * cfg->peak_rate / (hz / 1000);
		if (p_tokens > cfg->peak_burst)
			p_tokens = cfg->peak_burst;

		state->last_refill_ns = now;

		if (p_tokens < pkt_len) {
			/* Red: exceeds peak rate */
			state->tokens = c_tokens;
			state->peak_tokens = p_tokens;
			return 2; /* violate */
		}
		if (c_tokens < pkt_len) {
			/* Yellow: within peak but exceeds committed */
			state->tokens = c_tokens;
			state->peak_tokens = p_tokens - pkt_len;
			return 1; /* exceed */
		}
		/* Green: within both rates */
		state->tokens = c_tokens - pkt_len;
		state->peak_tokens = p_tokens - pkt_len;
		return 0; /* conform */
	}

	/* Single-rate three-color (RFC 2697): CIR fills C, C overflow fills E */
	uint64_t e_tokens = state->peak_tokens;
	if (c_tokens > cfg->burst_bytes) {
		uint64_t overflow = c_tokens - cfg->burst_bytes;
		e_tokens += overflow;
		c_tokens = cfg->burst_bytes;
		if (e_tokens > cfg->peak_burst)
			e_tokens = cfg->peak_burst;
	}

	state->last_refill_ns = now;

	if (c_tokens >= pkt_len) {
		/* Green: fits in committed bucket */
		state->tokens = c_tokens - pkt_len;
		state->peak_tokens = e_tokens;
		return 0;
	}
	if (e_tokens >= pkt_len) {
		/* Yellow: fits in excess bucket */
		state->tokens = c_tokens;
		state->peak_tokens = e_tokens - pkt_len;
		return 1;
	}
	/* Red: exceeds both */
	state->tokens = c_tokens;
	state->peak_tokens = e_tokens;
	return 2;
}
