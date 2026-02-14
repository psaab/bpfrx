/* SPDX-License-Identifier: GPL-2.0-or-later
 * gc.c — Session garbage collection (expired session cleanup).
 *
 * Runs on the main lcore (not a data-plane lcore) during idle time.
 * Scans a batch of session entries per call, deleting expired ones
 * along with their reverse entries and any dynamic SNAT DNAT entries.
 *
 * Design: Called periodically from the main lcore wait loop.
 * Scans BATCH_SIZE entries per call to avoid stalling the main lcore.
 * Iterates v4 then v6 sessions using rte_hash_iterate().
 */

#include <string.h>

#include <rte_hash.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>

#include "shared_mem.h"
#include "tables.h"
#include "events.h"

/* How many entries to scan per gc_sweep() call */
#define GC_BATCH_SIZE 4096

/* Sweep interval in seconds */
#define GC_INTERVAL_SEC 1

/* Maximum entries to delete per sweep (prevent stalling) */
#define GC_MAX_DELETES 512

struct gc_state {
	uint32_t v4_iter;      /* rte_hash_iterate position for v4 */
	uint32_t v6_iter;      /* rte_hash_iterate position for v6 */
	int      v4_done;      /* 1 = finished v4 scan this cycle */
	uint64_t last_sweep;   /* TSC of last sweep start */
};

static struct gc_state g_gc;

/**
 * gc_cleanup_snat_dnat — Remove dynamic DNAT entry created for SNAT sessions.
 *
 * When SNAT pool allocates (ip, port), it inserts a return-path DNAT entry
 * so return traffic gets translated back. When the session expires, we must
 * clean up that DNAT entry.
 */
static void
gc_cleanup_snat_dnat(struct shared_memory *shm, struct session_value *sv)
{
	if (!(sv->flags & SESS_FLAG_SNAT) || (sv->flags & SESS_FLAG_STATIC_NAT))
		return;
	if (sv->is_reverse)
		return;  /* Only forward entry has the canonical NAT info */
	if (sv->nat_src_ip == 0)
		return;

	if (shm->dnat_table) {
		struct dnat_key dk = {
			.protocol = sv->reverse_key.protocol,
			.dst_ip = sv->nat_src_ip,
			.dst_port = sv->nat_src_port,
		};
		rte_hash_del_key(shm->dnat_table, &dk);
	}
}

/**
 * gc_cleanup_snat_dnat_v6 — Remove dynamic DNAT v6 entry for SNAT sessions.
 */
static void
gc_cleanup_snat_dnat_v6(struct shared_memory *shm, struct session_value_v6 *sv)
{
	if (!(sv->flags & SESS_FLAG_SNAT) || (sv->flags & SESS_FLAG_STATIC_NAT))
		return;
	if (sv->is_reverse)
		return;

	uint8_t zero[16] = {0};
	if (memcmp(sv->nat_src_ip, zero, 16) == 0)
		return;

	if (shm->dnat_table_v6) {
		struct dnat_key_v6 dk6;
		memset(&dk6, 0, sizeof(dk6));
		dk6.protocol = sv->reverse_key.protocol;
		memcpy(dk6.dst_ip, sv->nat_src_ip, 16);
		dk6.dst_port = sv->nat_src_port;
		rte_hash_del_key(shm->dnat_table_v6, &dk6);
	}
}

/**
 * gc_sweep — Scan a batch of sessions and delete expired ones.
 *
 * @shm: Shared memory (contains session tables)
 *
 * Returns the number of sessions deleted this call.
 *
 * Thread safety: This function modifies session hash tables.
 * rte_hash is configured with RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
 * which allows concurrent reads (data plane) and writes (GC) safely.
 */
int
gc_sweep(struct shared_memory *shm)
{
	if (!shm)
		return 0;

	uint64_t now_tsc = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();
	if (hz == 0)
		return 0;

	/* Rate limit: don't sweep more than once per GC_INTERVAL_SEC */
	if (g_gc.last_sweep != 0 &&
	    (now_tsc - g_gc.last_sweep) < (uint64_t)GC_INTERVAL_SEC * hz)
		return 0;

	g_gc.last_sweep = now_tsc;
	uint64_t now_sec = now_tsc / hz;

	int deleted = 0;

	/* --- IPv4 sessions --- */
	if (shm->sessions_v4 && shm->session_values_v4) {
		void *key_ptr;
		void *data_ptr;
		int scanned = 0;

		while (scanned < GC_BATCH_SIZE && deleted < GC_MAX_DELETES) {
			int32_t pos = rte_hash_iterate(shm->sessions_v4,
				(const void **)&key_ptr, &data_ptr, &g_gc.v4_iter);
			if (pos < 0) {
				/* Wrapped around — reset iterator */
				g_gc.v4_iter = 0;
				g_gc.v4_done = 1;
				break;
			}
			scanned++;
			shm->gc_sessions_scanned++;

			struct session_value *sv = &shm->session_values_v4[pos];

			/* Check expiry */
			if (sv->last_seen + sv->timeout > now_sec)
				continue;

			/* Expired — clean up SNAT DNAT entry */
			gc_cleanup_snat_dnat(shm, sv);

			/* Delete reverse entry first */
			rte_hash_del_key(shm->sessions_v4, &sv->reverse_key);

			/* Delete this entry */
			rte_hash_del_key(shm->sessions_v4, key_ptr);

			deleted++;
			shm->gc_sessions_expired++;
		}
	}

	/* --- IPv6 sessions --- */
	if (shm->sessions_v6 && shm->session_values_v6 &&
	    deleted < GC_MAX_DELETES) {
		void *key_ptr;
		void *data_ptr;
		int scanned = 0;

		while (scanned < GC_BATCH_SIZE && deleted < GC_MAX_DELETES) {
			int32_t pos = rte_hash_iterate(shm->sessions_v6,
				(const void **)&key_ptr, &data_ptr, &g_gc.v6_iter);
			if (pos < 0) {
				g_gc.v6_iter = 0;
				break;
			}
			scanned++;
			shm->gc_sessions_scanned++;

			struct session_value_v6 *sv = &shm->session_values_v6[pos];

			if (sv->last_seen + sv->timeout > now_sec)
				continue;

			gc_cleanup_snat_dnat_v6(shm, sv);

			rte_hash_del_key(shm->sessions_v6, &sv->reverse_key);
			rte_hash_del_key(shm->sessions_v6, key_ptr);

			deleted++;
			shm->gc_sessions_expired++;
		}
	}

	return deleted;
}

/**
 * gc_stats — Return GC statistics from shared memory.
 */
void
gc_stats(struct shared_memory *shm, uint64_t *expired, uint64_t *scanned)
{
	*expired = shm->gc_sessions_expired;
	*scanned = shm->gc_sessions_scanned;
}
