// #1349: per-queue status-row accumulator extracted from
// `build_worker_cos_statuses_from_maps`. Owns the queue-scoped fields
// of a `CoSQueueStatus` row.
//
// What this DOES own:
//   * The first-worker `priority` gate (cos.rs:602-604 pre-#1349) —
//     `status.priority` is set only when `status.worker_instances ==
//     0`, BEFORE the saturating_add at the bottom of the helper bumps
//     the counter. This is the one ordering-coupled field write in
//     the block; every other field is an independent saturating-add /
//     MAX slot.
//   * Standard accumulators: `exact`, `guarantee_enabled`,
//     `transmit_rate_bytes` (MAX), `buffer_bytes`, `worker_instances`,
//     `queued_packets`, `queued_bytes`, `runnable_instances`,
//     `parked_instances`, `next_wakeup_tick` (MIN over non-zero),
//     `surplus_deficit_bytes`.
//   * `forwarding_class` first-non-empty (clones the config string;
//     no new allocation beyond what the inline block did pre-#1349).
//   * #784 `active_flow_buckets_peak` (MAX across worker instances,
//     not sum — see comment in original).
//   * #784 `flow_fair` propagation.
//   * #710 / #718 drop-counter aggregation (`admission_flow_share_drops`,
//     `admission_buffer_drops`, `admission_ecn_marked`,
//     `root_token_starvation_parks`, `queue_token_starvation_parks`,
//     `tx_ring_full_submit_stalls`).
//   * #751 per-queue drain telemetry, sourced from
//     `queue.telemetry.owner_profile.*` atomics (Relaxed loads, single
//     writer + cross-thread read). `drain_latency_hist` is resized to
//     `DRAIN_HIST_BUCKETS` only when `drain_invocations > 0` so
//     untouched queues stay serialized as an empty array.
//   * #760 overshoot-hunt counters: `drain_sent_bytes`,
//     `drain_guarantee_sent_bytes`, `drain_surplus_sent_bytes`,
//     `drain_nonexact_sent_bytes_while_exact_backlogged`,
//     `drain_park_root_tokens`, `drain_park_queue_tokens`.
//
// What this does NOT own:
//   * `status.queue_id` — set by the orchestrator before this helper
//     runs (the BTreeMap key matches the queue ID, but the orchestrator
//     mirrors it onto the value too).
//   * The #709/#748/#751 binding-scoped owner-profile merge (gated on
//     "is this the unambiguous owner-local exact queue row?"). That
//     merge lives inline in the orchestrator immediately after this
//     helper returns. Folding it in here would require taking the
//     binding profile + `owner_profile_row` target as parameters,
//     exactly the round-1 Gemini PLAN-KILL counter-example.

use super::*;

#[inline]
pub(super) fn accumulate_queue_row(
    status: &mut crate::protocol::CoSQueueStatus,
    queue: &CoSQueueRuntime,
    queue_config: Option<&CoSQueueConfig>,
) {
    if let Some(config) = queue_config {
        if status.forwarding_class.is_empty() {
            status.forwarding_class = config.forwarding_class.clone();
        }
    }
    // CRITICAL: read `worker_instances` BEFORE the saturating_add at
    // the bottom of the helper. The original at cos.rs:602-604 sets
    // `priority` only on the first worker's visit (the bump comes
    // later at cos.rs:612). Re-ordering would corrupt the "first
    // worker wins" semantic.
    if status.worker_instances == 0 {
        status.priority = queue.config.priority;
    }
    status.exact = queue.config.exact;
    status.guarantee_enabled = queue.config.guarantee_enabled;
    status.transmit_rate_bytes = status.transmit_rate_bytes.max(queue.transmit_rate_bytes());
    status.buffer_bytes = status
        .buffer_bytes
        .saturating_add(queue.config.buffer_bytes);
    status.worker_instances = status.worker_instances.saturating_add(1);
    status.queued_packets = status
        .queued_packets
        .saturating_add(cos_queue_len(queue) as u64);
    status.queued_bytes = status.queued_bytes.saturating_add(queue.hot.queued_bytes);
    if queue.hot.runnable {
        status.runnable_instances = status.runnable_instances.saturating_add(1);
    }
    if queue.hot.parked {
        status.parked_instances = status.parked_instances.saturating_add(1);
    }
    if status.next_wakeup_tick == 0
        || (queue.hot.next_wakeup_tick > 0
            && queue.hot.next_wakeup_tick < status.next_wakeup_tick)
    {
        status.next_wakeup_tick = queue.hot.next_wakeup_tick;
    }
    status.surplus_deficit_bytes = status
        .surplus_deficit_bytes
        .saturating_add(queue.hot.surplus_deficit);
    // #784: use MAX across worker instances (not sum) — the peak is
    // per-worker observed; aggregating by max gives the worst-case
    // collision visibility without inflating the number by
    // double-counting.
    let peak = queue
        .flow_fair_state
        .as_ref()
        .map_or(0, |ff| u64::from(ff.active_flow_buckets_peak));
    if peak > status.active_flow_buckets_peak {
        status.active_flow_buckets_peak = peak;
    }
    // #784: surface flow_fair so we can detect queues that were
    // expected to run SFQ but aren't.
    if queue.flow_fair() {
        status.flow_fair = true;
    }
    // #710: aggregate drop-reason counters across worker instances
    // for this queue. Each worker's per-queue runtime is single-writer
    // (only the owner worker increments the counter for its own
    // queue), so summing across workers gives cluster-wide totals.
    status.admission_flow_share_drops = status
        .admission_flow_share_drops
        .saturating_add(queue.telemetry.drop_counters.admission_flow_share_drops);
    status.admission_buffer_drops = status
        .admission_buffer_drops
        .saturating_add(queue.telemetry.drop_counters.admission_buffer_drops);
    // #718: aggregate ECN CE-mark counter across workers. Same
    // single-writer invariant as the other admission counters —
    // owner worker only.
    status.admission_ecn_marked = status
        .admission_ecn_marked
        .saturating_add(queue.telemetry.drop_counters.admission_ecn_marked);
    status.root_token_starvation_parks = status
        .root_token_starvation_parks
        .saturating_add(queue.telemetry.drop_counters.root_token_starvation_parks);
    status.queue_token_starvation_parks = status
        .queue_token_starvation_parks
        .saturating_add(queue.telemetry.drop_counters.queue_token_starvation_parks);
    status.tx_ring_full_submit_stalls = status
        .tx_ring_full_submit_stalls
        .saturating_add(queue.telemetry.drop_counters.tx_ring_full_submit_stalls);
    // #751: per-queue drain telemetry (drain_latency_hist +
    // drain_invocations) now lives on `CoSQueueTelemetry.owner_profile`
    // — each exact queue gets its OWN histogram populated directly
    // from its own atomics, with no eligibility gate. Pre-#751 these
    // came from a binding-wide rollup that was only surfaced on the
    // single "unambiguous owner-local exact queue" row; as a result
    // #732 showed every queue row of a multi-queue binding with
    // identical values.
    //
    // HFT notes on the atomic loads below:
    //   * Single-writer (owner worker thread) + cross-thread read
    //     (snapshot path). Relaxed is the correct ordering: the
    //     reader tolerates ~1 count of tearing between the hist
    //     buckets and drain_invocations, and Prometheus scrape
    //     semantics are "best effort at scrape time".
    //   * The owner_profile atomics sit alongside the plain u64
    //     fields in CoSQueueRuntime that the same owner also mutates
    //     each tick, so there is no false-sharing cost internal to
    //     the worker. The snapshot reader pulls the cache line once
    //     per scrape — negligible.
    //   * Load invocations first so an untouched queue (zero counter)
    //     skips the histogram walk and keeps the on-wire status
    //     vector empty — saves the resize + 16 bucket copies plus the
    //     128 bytes of serde overhead on queues that never drained.
    //     The writer always bumps both hist and invocations under
    //     Relaxed, so invocations==0 ⇒ all buckets are zero; the
    //     reverse may briefly be false due to tearing, but a ~1-count
    //     under-report from a single reader is within the tolerance
    //     documented on CoSQueueOwnerProfile.
    let queue_invocations = queue
        .telemetry
        .owner_profile
        .drain_invocations
        .load(Ordering::Relaxed);
    if queue_invocations > 0 {
        if status.drain_latency_hist.len() < DRAIN_HIST_BUCKETS {
            status.drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0);
        }
        for i in 0..DRAIN_HIST_BUCKETS {
            let bucket_count =
                queue.telemetry.owner_profile.drain_latency_hist[i].load(Ordering::Relaxed);
            status.drain_latency_hist[i] =
                status.drain_latency_hist[i].saturating_add(bucket_count);
        }
        status.drain_invocations = status.drain_invocations.saturating_add(queue_invocations);
    }
    // #760 overshoot-hunt instrumentation. Same Relaxed load pattern
    // as drain_invocations — single writer (owner worker, at the
    // queue-token decrement sites in tx.rs) + single reader (this
    // snapshot path). drain_sent_bytes is the authoritative per-queue
    // "bytes the scheduler actually shaped out"; pair it with
    // `queue.transmit_rate_bytes` over a scrape window to detect a
    // direct cap bypass on this row. The guarantee/surplus split and
    // non-exact/exact-backlog counter diagnose whether root surplus or
    // non-exact guarantee service is stealing service from exact
    // queues. drain_park_root_tokens / drain_park_queue_tokens both
    // rising with drain_sent_bytes sustaining above configured rate
    // would mean the gate fires but refill/accounting is wrong; both
    // near zero with drain_sent_bytes above rate means the gate never
    // ran for this queue.
    status.drain_sent_bytes = status.drain_sent_bytes.saturating_add(
        queue
            .telemetry
            .owner_profile
            .drain_sent_bytes
            .load(Ordering::Relaxed),
    );
    status.drain_guarantee_sent_bytes = status.drain_guarantee_sent_bytes.saturating_add(
        queue
            .telemetry
            .owner_profile
            .drain_guarantee_sent_bytes
            .load(Ordering::Relaxed),
    );
    status.drain_surplus_sent_bytes = status.drain_surplus_sent_bytes.saturating_add(
        queue
            .telemetry
            .owner_profile
            .drain_surplus_sent_bytes
            .load(Ordering::Relaxed),
    );
    status.drain_nonexact_sent_bytes_while_exact_backlogged = status
        .drain_nonexact_sent_bytes_while_exact_backlogged
        .saturating_add(
            queue
                .telemetry
                .owner_profile
                .drain_nonexact_sent_bytes_while_exact_backlogged
                .load(Ordering::Relaxed),
        );
    status.drain_park_root_tokens = status.drain_park_root_tokens.saturating_add(
        queue
            .telemetry
            .owner_profile
            .drain_park_root_tokens
            .load(Ordering::Relaxed),
    );
    status.drain_park_queue_tokens = status.drain_park_queue_tokens.saturating_add(
        queue
            .telemetry
            .owner_profile
            .drain_park_queue_tokens
            .load(Ordering::Relaxed),
    );
}
