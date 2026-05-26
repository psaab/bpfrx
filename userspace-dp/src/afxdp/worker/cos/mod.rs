// Empirical per-worker sustained exact throughput ceiling in bytes/sec. A
// single owner worker can reliably drive an exact queue up to about this rate
// before the drain loop backs up and throughput collapses (the collapse case
// that motivated shared-worker execution in PR #680). This is the sole
// shared-exact threshold: a queue at or above this rate shards across every
// eligible worker; a queue below it runs under a single owner.
//
// Evidence basis (#698):
// - Drain-path userspace micro-bench `cos_exact_drain_throughput_micro_bench`
//   (in `afxdp::tx::tests`, run with
//   `cargo test --release -- --ignored --nocapture`; debug-build numbers are
//   not meaningful for this baseline) measures the inner
//   `drain_exact_local_fifo_items_to_scratch` +
//   `settle_exact_local_fifo_submission` loop in isolation with setup work
//   excluded from the timed region. Baseline on the development host is
//   comfortably above MIN (order of a few Mpps / tens of Gbps at 1500 B);
//   drain alone is not the limiter there.
// - This bench only rules out the inner drain loop as the immediate
//   limiter on the development host. It does NOT by itself validate MIN
//   on other deployment hardware, and it does not fully attribute the
//   remaining ceiling to non-drain work without a live single-worker
//   measurement.
// - The 2.5 Gbps figure is best read as a per-worker *aggregate* budget
//   threshold consistent with the PR #680 collapse shape: there the drain
//   loop failed to absorb 10g line-rate despite drain alone being able
//   to go much faster, because non-drain per-packet work (RX, forwarding,
//   NAT, session-lookup, conntrack) consumed the per-packet cycle budget
//   that drain+completion needed to keep up.
// - The ceiling is a property of the full per-worker pipeline, not of
//   the interface shaper — it does not scale with iface rate.
pub(in crate::afxdp) const COS_SHARED_EXACT_MIN_RATE_BYTES: u64 = 2_500_000_000 / 8;

/// #709: snapshot the owner-profile counter set from a `BindingLiveState`
/// into a struct-local copy. Histograms are fixed-cap arrays on both
/// sides; copying into an owned value lets the caller attribute the
/// same snapshot to multiple queues without re-reading the atomics
/// (which would tear across queues in the same scrape).
pub(crate) struct OwnerProfileSnapshot {
    pub(crate) drain_latency_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(crate) drain_invocations: u64,
    pub(crate) drain_noop_invocations: u64,
    pub(crate) redirect_acquire_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(crate) owner_pps: u64,
    pub(crate) peer_pps: u64,
    /// #760 instrumentation, binding-scoped. Bytes delivered via
    /// the post-CoS backup transmit paths in `drain_pending_tx`
    /// — these never passed a queue's token gate. Surfaced on
    /// the same "unambiguous owner-local exact queue" row the
    /// other binding-scoped fields use.
    pub(crate) post_drain_backup_bytes: u64,
    /// #760 instrumentation, binding-scoped. Bytes observed at the
    /// three `apply_*` tx_bytes sites, incremented unconditionally.
    /// Compare against the sum of per-queue `drain_sent_bytes`; any
    /// gap is shaped traffic that bypassed the per-queue write via
    /// an `apply_*` early-return.
    pub(crate) drain_sent_bytes_shaped_unconditional: u64,
}

use super::*;

// Worker-side CoS runtime helpers split out of `worker/mod.rs` per #957.
// All fns operate on per-binding CoS state; none touch the XSK fast
// path or HA reconciliation directly.

// #1349: per-row accumulators and the orchestrator for the
// `build_worker_cos_statuses_*` status RPC path live in sibling
// submodules. The 268-LOC orchestrator body that previously lived
// here as `build_worker_cos_statuses_from_maps` now lives in
// `status.rs`, with the per-interface / per-queue accumulation
// delegated to `interface_row.rs` / `queue_row.rs`.
mod interface_row;
mod queue_row;
mod status;

pub(in crate::afxdp::worker) use status::build_worker_cos_statuses;

// Test-only re-export of the orchestrator entry. Tests live in the
// sibling `tests.rs` submodule (post-#1349 layout) and use the
// `use super::*;` pattern, so reaching into `status::` directly would
// require modifying every test call site. Keeping the re-export
// preserves the test bodies as pure-code-motion.
#[cfg(test)]
pub(in crate::afxdp::worker) use status::build_worker_cos_statuses_from_maps;

pub(super) fn build_worker_cos_owner_live_by_tx_ifindex<I>(
    bindings: I,
) -> FastMap<i32, Arc<BindingLiveState>>
where
    I: IntoIterator<Item = (i32, Arc<BindingLiveState>)>,
{
    let mut out = FastMap::default();
    for (ifindex, live) in bindings {
        out.entry(ifindex).or_insert(live);
    }
    out
}

/// Decide whether an exact queue runs under shared-worker execution.
///
/// Policy:
/// - Non-exact queues are never shared (they run through the non-exact
///   guarantee batch path regardless).
/// - Exact queues below `COS_SHARED_EXACT_MIN_RATE_BYTES` route to a single
///   owner worker (one FIFO arbitration domain, SFQ inside). See issue
///   #690 for why low-rate exact queues want one arbitration domain rather
///   than N racing worker-local FIFOs.
/// - Exact queues at or above the threshold run sharded across every
///   eligible worker with shared root/queue leases, avoiding the single-
///   worker throughput collapse from PR #680.
///
/// Before PR #697 the threshold was `max(iface_rate / 4, MIN)`. That scaled
/// the threshold up with iface rate, which is the wrong direction: the
/// single-worker drain ceiling is an absolute property of the loop, not a
/// fraction of the iface. Once `iface_rate / 4` exceeded `MIN`, the policy
/// would classify a genuinely high-rate queue (e.g. a 10g exact queue on a
/// 100g iface) as single-owner — routing it straight back into the PR #680
/// collapse shape. The `/ 4` term is now gone; the threshold is just the
/// absolute per-worker ceiling.
///
/// The old and new policies classify queues identically whenever
/// `iface_rate / 4 <= COS_SHARED_EXACT_MIN_RATE_BYTES` (both evaluate to
/// `MIN`). Behavior diverges only in the `iface_rate / 4 > MIN` regime,
/// which is the regime that previously mis-classified mid/high-rate exact
/// queues as single-owner.
#[inline]
fn queue_uses_shared_exact_service(_iface: &CoSInterfaceConfig, queue: &CoSQueueConfig) -> bool {
    if !queue.exact {
        return false;
    }
    queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES
}

pub(super) fn build_worker_cos_fast_interfaces(
    forwarding: &ForwardingState,
    current_worker_id: u32,
    tx_owner_live_by_tx_ifindex: &FastMap<i32, Arc<BindingLiveState>>,
    owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
    shared_root_leases: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
    shared_exact_backlogs: &BTreeMap<i32, Arc<SharedCoSExactBacklog>>,
    shared_queue_leases: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
    shared_queue_vtime_floors: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    let mut out = FastMap::default();
    for (&egress_ifindex, iface) in &forwarding.cos.interfaces {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
        let mut queue_fast_path = Vec::with_capacity(iface.queues.len());
        for (queue_idx, queue) in iface.queues.iter().enumerate() {
            queue_index_by_id[usize::from(queue.queue_id)] = queue_idx as u16;
            let queue_key = (egress_ifindex, queue.queue_id);
            let shared_exact = queue_uses_shared_exact_service(iface, queue);
            queue_fast_path.push(WorkerCoSQueueFastPath {
                shared_exact,
                owner_worker_id: owner_worker_by_queue
                    .get(&queue_key)
                    .copied()
                    .unwrap_or(current_worker_id),
                owner_live: owner_live_by_queue.get(&queue_key).cloned(),
                shared_queue_lease: queue
                    .exact
                    .then(|| shared_queue_leases.get(&queue_key).cloned())
                    .flatten(),
                // #917 Phase 2b: V_min coordination Arc, allocated
                // once per shared_exact CoS queue by the coordinator
                // (per `build_shared_cos_queue_vtime_floors_reusing_existing`
                // in coordinator.rs). Cloned to every worker servicing
                // this queue. Single-owner / non-shared queues get
                // None — V_min sync only applies to shared_exact.
                vtime_floor: shared_queue_vtime_floors.get(&queue_key).cloned(),
            });
        }
        let default_queue_index = match queue_index_by_id[usize::from(iface.default_queue)] {
            COS_FAST_QUEUE_INDEX_MISS => 0,
            idx => idx as usize,
        };
        out.insert(
            egress_ifindex,
            WorkerCoSInterfaceFastPath {
                tx_ifindex,
                default_queue_index,
                queue_index_by_id,
                tx_owner_live: tx_owner_live_by_tx_ifindex.get(&tx_ifindex).cloned(),
                shared_root_lease: shared_root_leases.get(&egress_ifindex).cloned(),
                shared_exact_backlog: shared_exact_backlogs.get(&egress_ifindex).cloned(),
                queue_fast_path,
            },
        );
    }
    out
}

/// Return the single `(ifindex, queue_id)` that can truthfully inherit
/// a binding-scoped owner-profile snapshot, scanning **all** interfaces
/// on the binding's `cos_map`.
///
/// The snapshot source is `BindingLiveState`, which is binding-local,
/// not queue-local. A binding can drain multiple interfaces (via
/// `drain_shaped_tx` round-robining `binding.cos.cos_interface_order`), so
/// attribution has to be unambiguous at the BINDING level, not the
/// interface level: if two interfaces on the same binding each have
/// one owner-local exact queue, the binding-wide snapshot still has
/// no single queue to land on, and the whole export must stay zero.
///
/// We return `Some((ifindex, queue_id))` only when exactly one queue
/// across the whole binding is owner-local exact. Shared-exact,
/// non-exact, and any multi-owner-local shape — whether within one
/// interface or spread across interfaces — keep the binding silent.
fn unique_owner_profile_row(
    cos_map: &FastMap<i32, CoSInterfaceRuntime>,
    forwarding: &ForwardingState,
) -> Option<(i32, u8)> {
    let mut eligible = None;
    for (&ifindex, root) in cos_map {
        let iface = match forwarding.cos.interfaces.get(&ifindex) {
            Some(iface) => iface,
            None => {
                // Missing config for a runtime is ambiguous — we can't
                // confirm the queue is exact from the config side, so
                // if the runtime claims any exact queues we silence
                // the whole binding.
                if root.queues.iter().any(|q| q.config.exact) {
                    return None;
                }
                continue;
            }
        };
        for queue in &root.queues {
            if !queue.config.exact {
                continue;
            }
            let Some(config) = iface
                .queues
                .iter()
                .find(|cfg| cfg.queue_id == queue.queue_id())
            else {
                return None;
            };
            if !config.exact {
                return None;
            }
            if queue_uses_shared_exact_service(iface, config) {
                continue;
            }
            if eligible.replace((ifindex, queue.queue_id())).is_some() {
                return None;
            }
        }
    }
    eligible
}

pub(super) fn cos_runtime_config_changed(
    current: &ForwardingState,
    next: &ForwardingState,
) -> bool {
    current.cos != next.cos
}

/// #941 Work item C: vacate every shared_exact V_min slot owned by
/// this worker across all bindings' CoS interfaces. Called from two
/// paths: (1) the worker poll loop on
/// `WorkerCommand::VacateAllSharedExactSlots` (HA-demotion), and
/// (2) `reset_binding_cos_runtime` before clearing `cos_interfaces`
/// (config-reload reset-epoch). Single-writer invariant: this worker
/// owns its slots; race-free against peer Acquire reads.
pub(super) fn vacate_all_shared_exact_slots_for_binding(binding: &BindingWorker) {
    for root in binding.cos.cos_interfaces.values() {
        for queue in &root.queues {
            if !queue.shared_exact() {
                continue;
            }
            if let Some(floor) = queue.v_min.vtime_floor.as_ref() {
                if let Some(slot) = floor.slots.get(queue.v_min.worker_id as usize) {
                    slot.vacate();
                }
            }
        }
    }
}

pub(super) fn reset_binding_cos_runtime(
    binding: &mut BindingWorker,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) {
    release_all_cos_root_leases(binding);
    release_all_cos_queue_leases(binding);
    let mut dropped_local = 0u64;
    let mut dropped_prepared = Vec::new();
    for root in binding.cos.cos_interfaces.values_mut() {
        for queue in &mut root.queues {
            // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer
            // LOW: teardown drains the whole queue without a
            // matching push_front rollback, so no snapshots are
            // ever consumed. Use the no-snapshot pop variant so
            // we don't grow pop_snapshot_stack past its documented
            // TX_BATCH_SIZE bound (the queue may hold more items
            // than that). The runtime is replaced below anyway.
            while let Some(item) = cos_queue_pop_front_no_snapshot(queue) {
                match item {
                    CoSPendingTxItem::Local(_) => {
                        dropped_local = dropped_local.saturating_add(1);
                    }
                    CoSPendingTxItem::Prepared(req) => dropped_prepared.push(req),
                }
            }
            queue.hot.queued_bytes = 0;
            queue.hot.runnable = false;
            queue.hot.parked = false;
            queue.hot.next_wakeup_tick = 0;
        }
        root.nonempty_queues = 0;
        root.runnable_queues = 0;
    }
    // #941 Work item C (reset-epoch path): vacate any V_min slots
    // owned by this worker before clearing cos_interfaces. The
    // coordinator's `build_shared_cos_queue_vtime_floors_reusing_existing`
    // reuses an existing floor Arc when the (ifindex, queue_id,
    // worker_count) tuple matches across rebuilds. After this clear,
    // the next runtime starts with queue_vtime=0 but the floor's
    // slot for this worker would still hold the OLD high vtime
    // without this vacate — peers reading the slot would use the
    // stale value in their V_min calculation, throttling them
    // unnecessarily until the first post-reset post-settle publish.
    vacate_all_shared_exact_slots_for_binding(binding);
    clear_all_cos_exact_backlogs_for_binding(binding);
    binding.cos.cos_interfaces.clear();
    binding.cos.cos_interface_order.clear();
    binding.cos.cos_interface_rr = 0;
    binding.cos.cos_nonempty_interfaces = 0;

    let dropped_total = dropped_local.saturating_add(dropped_prepared.len() as u64);
    if dropped_total > 0 {
        // Keep the CoS subset counter lifetime-matched with tx_errors:
        // reset-time queue drains are CoS-owned TX drops too.
        binding
            .live
            .tx_errors
            .fetch_add(dropped_total, Ordering::Relaxed);
        binding
            .live
            .dbg_cos_queue_overflow
            .fetch_add(dropped_total, Ordering::Relaxed);
    }
    for req in dropped_prepared {
        recycle_prepared_immediately_with_shared(binding, &req, shared_recycles.as_deref_mut());
    }
}

pub(super) fn reset_worker_cos_runtimes(
    bindings: &mut [BindingWorker],
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    for binding in bindings {
        reset_binding_cos_runtime(binding, Some(shared_recycles));
    }
}

#[inline]
pub(in crate::afxdp) fn owner_profile_snapshot(live: &BindingLiveState) -> OwnerProfileSnapshot {
    // #746: atomics now live on cacheline-isolated `owner_profile_owner`
    // / `owner_profile_peer` nested structs. This snapshot reads from
    // both but the shape it produces is byte-identical to pre-refactor.
    OwnerProfileSnapshot {
        drain_latency_hist: std::array::from_fn(|i| {
            live.owner_profile_owner.drain_latency_hist[i].load(Ordering::Relaxed)
        }),
        drain_invocations: live
            .owner_profile_owner
            .drain_invocations
            .load(Ordering::Relaxed),
        drain_noop_invocations: live
            .owner_profile_owner
            .drain_noop_invocations
            .load(Ordering::Relaxed),
        redirect_acquire_hist: std::array::from_fn(|i| {
            live.owner_profile_peer.redirect_acquire_hist[i].load(Ordering::Relaxed)
        }),
        owner_pps: live.owner_profile_owner.owner_pps.load(Ordering::Relaxed),
        peer_pps: live.owner_profile_peer.peer_pps.load(Ordering::Relaxed),
        post_drain_backup_bytes: live
            .owner_profile_owner
            .post_drain_backup_bytes
            .load(Ordering::Relaxed),
        drain_sent_bytes_shaped_unconditional: live
            .owner_profile_owner
            .drain_sent_bytes_shaped_unconditional
            .load(Ordering::Relaxed),
    }
}

/// #709: sum-merge the owner-profile fields of one `CoSQueueStatus`
/// into another. Used by `coordinator::aggregate_cos_statuses_across_workers`
/// to fold per-worker snapshots into the operator-facing view while
/// preserving the histogram invariant that
/// `sum(drain_latency_hist) == drain_invocations`.
///
/// `max` across workers is wrong for histograms and counters: it can
/// synthesize a profile no worker actually observed (bucket 0 from one
/// worker, bucket 7 from another) while leaving `drain_invocations` at
/// only the larger side's count. Summation preserves a coherent queue-
/// level view for both owner-local and shared-exact service.
/// Signature mirrors `merge_owner_profile_sum` so both layers share the
/// same contract.
pub(crate) fn merge_cos_queue_owner_profile_sum(
    dst: &mut crate::protocol::CoSQueueStatus,
    src: &crate::protocol::CoSQueueStatus,
) {
    if dst.drain_latency_hist.len() < DRAIN_HIST_BUCKETS {
        dst.drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    if dst.redirect_acquire_hist.len() < DRAIN_HIST_BUCKETS {
        dst.redirect_acquire_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    for i in 0..DRAIN_HIST_BUCKETS {
        let src_drain = src.drain_latency_hist.get(i).copied().unwrap_or(0);
        dst.drain_latency_hist[i] = dst.drain_latency_hist[i].saturating_add(src_drain);
        let src_redirect = src.redirect_acquire_hist.get(i).copied().unwrap_or(0);
        dst.redirect_acquire_hist[i] = dst.redirect_acquire_hist[i].saturating_add(src_redirect);
    }
    dst.drain_invocations = dst.drain_invocations.saturating_add(src.drain_invocations);
    dst.drain_noop_invocations = dst
        .drain_noop_invocations
        .saturating_add(src.drain_noop_invocations);
    dst.owner_pps = dst.owner_pps.saturating_add(src.owner_pps);
    dst.peer_pps = dst.peer_pps.saturating_add(src.peer_pps);
    // #760 sum-merge the new per-queue + binding-scoped counters
    // across workers. Same saturating-add discipline as the rest of
    // this function — a single queue can be owned by at most one
    // worker per scrape, so cross-worker aggregation is almost
    // always sum-of-single-non-zero, but saturating_add keeps us
    // safe if the ownership ever shifts mid-scrape.
    dst.drain_sent_bytes = dst.drain_sent_bytes.saturating_add(src.drain_sent_bytes);
    dst.drain_guarantee_sent_bytes = dst
        .drain_guarantee_sent_bytes
        .saturating_add(src.drain_guarantee_sent_bytes);
    dst.drain_surplus_sent_bytes = dst
        .drain_surplus_sent_bytes
        .saturating_add(src.drain_surplus_sent_bytes);
    dst.drain_nonexact_sent_bytes_while_exact_backlogged = dst
        .drain_nonexact_sent_bytes_while_exact_backlogged
        .saturating_add(src.drain_nonexact_sent_bytes_while_exact_backlogged);
    dst.drain_park_root_tokens = dst
        .drain_park_root_tokens
        .saturating_add(src.drain_park_root_tokens);
    dst.drain_park_queue_tokens = dst
        .drain_park_queue_tokens
        .saturating_add(src.drain_park_queue_tokens);
    dst.post_drain_backup_bytes = dst
        .post_drain_backup_bytes
        .saturating_add(src.post_drain_backup_bytes);
    dst.drain_sent_bytes_shaped_unconditional = dst
        .drain_sent_bytes_shaped_unconditional
        .saturating_add(src.drain_sent_bytes_shaped_unconditional);
}

/// #709: sum-merge a binding's owner-profile snapshot into a per-queue
/// `CoSQueueStatus`.
///
/// For owner-local exact queues, only one binding contributes non-zero
/// values so sum and max are equivalent. For shared-exact queues or any
/// future topology where multiple bindings contribute to the same queue,
/// summation preserves a coherent aggregate distribution and keeps
/// `sum(histogram) == invocations` intact. A per-bucket `max` breaks
/// that invariant and can manufacture an impossible mixed profile.
///
/// Post-#751: this still merges the full owner profile into the
/// destination status. It's retained for call sites that snapshot a
/// binding wholesale (tests, the coordinator fold-across-workers path).
/// Production `build_worker_cos_statuses_from_maps` no longer uses this
/// for drain_latency_hist / drain_invocations — those are now populated
/// per-queue from the per-queue atomics — but it still applies to the
/// binding-scoped fields (owner_pps, peer_pps, redirect_acquire_hist,
/// drain_noop_invocations) via `merge_binding_scoped_owner_profile`.
pub(in crate::afxdp) fn merge_owner_profile_sum(
    status: &mut crate::protocol::CoSQueueStatus,
    profile: &OwnerProfileSnapshot,
) {
    // Lazily size the histogram vectors on first touch; every queue
    // serialised with #709 fields populated has exactly
    // DRAIN_HIST_BUCKETS entries. A queue that was never merged stays
    // `Vec::new()` and serialises as an empty array — readers gate
    // on `owner_pps || drain_invocations` being > 0 before
    // interpreting the histogram.
    if status.drain_latency_hist.len() < DRAIN_HIST_BUCKETS {
        status.drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    for i in 0..DRAIN_HIST_BUCKETS {
        status.drain_latency_hist[i] =
            status.drain_latency_hist[i].saturating_add(profile.drain_latency_hist[i]);
    }
    status.drain_invocations = status
        .drain_invocations
        .saturating_add(profile.drain_invocations);
    merge_binding_scoped_owner_profile(status, profile);
}

/// #751: merge only the binding-scoped fields from a binding's
/// owner-profile snapshot into a per-queue status. The fields
/// covered — `redirect_acquire_hist`, `owner_pps`, `peer_pps`,
/// `drain_noop_invocations` — are inherently per-binding: producers
/// do not know the target queue at redirect time (so
/// `redirect_acquire_hist` and `peer_pps` cannot be queue-scoped),
/// `owner_pps` measures binding-wide TX arrivals, and
/// `drain_noop_invocations` counts drain calls that made no
/// progress on *any* queue (so no queue to attribute them to).
///
/// The per-queue drain fields (`drain_latency_hist`,
/// `drain_invocations`) are populated separately from the queue's
/// own atomics — see `build_worker_cos_statuses_from_maps`.
pub(in crate::afxdp) fn merge_binding_scoped_owner_profile(
    status: &mut crate::protocol::CoSQueueStatus,
    profile: &OwnerProfileSnapshot,
) {
    if status.redirect_acquire_hist.len() < DRAIN_HIST_BUCKETS {
        status.redirect_acquire_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    for i in 0..DRAIN_HIST_BUCKETS {
        status.redirect_acquire_hist[i] =
            status.redirect_acquire_hist[i].saturating_add(profile.redirect_acquire_hist[i]);
    }
    status.drain_noop_invocations = status
        .drain_noop_invocations
        .saturating_add(profile.drain_noop_invocations);
    status.owner_pps = status.owner_pps.saturating_add(profile.owner_pps);
    status.peer_pps = status.peer_pps.saturating_add(profile.peer_pps);
    // #760 smoking gun. Surfaced once per binding on the same
    // unambiguous owner-local exact queue row the other
    // binding-scoped fields ride on, so we don't multiply-count
    // the same binding-wide atomic across several queues of a
    // shared-exact shape.
    status.post_drain_backup_bytes = status
        .post_drain_backup_bytes
        .saturating_add(profile.post_drain_backup_bytes);
    status.drain_sent_bytes_shaped_unconditional = status
        .drain_sent_bytes_shaped_unconditional
        .saturating_add(profile.drain_sent_bytes_shaped_unconditional);
}
#[cfg(test)]
mod tests;
