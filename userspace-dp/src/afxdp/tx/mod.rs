use super::*;

// #984 P2a: TX latency-histogram + completion-sidecar helpers
// extracted to sibling module `tx/stats.rs`. The re-export below is
// load-bearing: `umem.rs::tests` (umem.rs:950+) reaches the three fns
// through `crate::afxdp::tx::{stamp_submits,
// record_tx_completions_with_stamp, record_kick_latency}` and that
// path resolves through this `pub(in crate::afxdp) use`.
pub(super) mod stats;
pub(in crate::afxdp) use stats::stamp_submits;
// `record_kick_latency` and `record_tx_completions_with_stamp` are
// reached only by `umem.rs::tests` via `crate::afxdp::tx::*` (see
// umem.rs:966/1077/1124/1188 — all `#[cfg(test)]`). Production callers
// inside `tx/rings.rs` import them directly from `super::stats::*`.
#[cfg(test)]
pub(in crate::afxdp) use stats::{record_kick_latency, record_tx_completions_with_stamp};

// #984 P2b: XSK kernel-ring discipline (TX completion drain, fill ring
// submit, RX/TX kernel wake) extracted to sibling module `tx/rings.rs`.
// External callers (cos/queue_service.rs uses reap_tx_completions and
// maybe_wake_tx; afxdp.rs / frame_tx.rs use drain_pending_fill and
// maybe_wake_rx) reach the moved fns through these re-exports at the
// same `crate::afxdp::tx::*` paths they used pre-move.
pub(super) mod rings;
pub(in crate::afxdp) use rings::{maybe_wake_tx, reap_tx_completions};
pub(super) use rings::{drain_pending_fill, maybe_wake_rx};

// #984 P2c: TX-ring submit + per-frame recycle cluster (transmit_batch,
// transmit_prepared_queue, recycle_*, TxError) extracted to sibling
// module `tx/transmit.rs`. External callers (cos/queue_service.rs
// imports recycle_cancelled_prepared_offset, remember_prepared_recycle,
// transmit_batch, transmit_prepared_queue, TxError;
// cos/cross_binding.rs and worker.rs:1974 import recycle_prepared_immediately)
// reach the moved items via the re-export below.
pub(super) mod transmit;
pub(in crate::afxdp) use transmit::{
    recycle_cancelled_prepared_offset, recycle_prepared_immediately,
    remember_prepared_recycle, transmit_batch, transmit_prepared_queue, TxError,
};
// transmit_prepared_batch is sibling-internal (only caller in tx/mod.rs);
// this private import keeps it available within this module.
use transmit::transmit_prepared_batch;

// #984 P2c2: drain dispatch + queue-bound + pending-queue helpers
// extracted to sibling module `tx/drain.rs`. cos/queue_service.rs
// imports the 4 quantum/guarantee constants via crate::afxdp::tx::*,
// so that re-export is load-bearing.
pub(super) mod drain;
pub(super) use drain::{
    bound_pending_tx_local, bound_pending_tx_prepared, drain_pending_tx,
    drain_pending_tx_local_owner, pending_tx_capacity,
};
pub(in crate::afxdp) use drain::{
    COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES,
    COS_GUARANTEE_VISIT_NS, COS_SURPLUS_ROUND_QUANTUM_BYTES,
};

// #984 P2d (FINAL): CoS classify + enqueue + cached-selection cluster
// extracted to sibling module `tx/cos_classify.rs`. Closes #984.
pub(super) mod cos_classify;

// #984 P3 follow-up: shared test helpers hoisted out of the inline
// `mod tests` so per-file test modules in `tx/*.rs` and `cos/*.rs`
// siblings can reuse them via `crate::afxdp::tx::test_support::*`.
#[cfg(test)]
pub(in crate::afxdp) mod test_support;

pub(super) use cos_classify::{
    CoSTxSelection, enqueue_local_into_cos, resolve_cached_cos_tx_selection,
    resolve_cos_queue_id, resolve_cos_tx_selection,
};
pub(in crate::afxdp) use cos_classify::cos_queue_dscp_rewrite;
// Private import (NOT re-export — E0364 if pub(super) re-export of
// pub(super) source): drain.rs reaches it via `use super::*;`.
use cos_classify::enqueue_prepared_into_cos;
// cfg-test imports for 2 helpers still pinned in tx/mod.rs::tests
// (the other 3 cos_classify helper tests moved to
// cos_classify.rs::tests in #984 P3 phase 2a).
#[cfg(test)]
use cos_classify::{
    };





















// #956: cos/ submodule imports.
//
// Phase 1 (PR #976) extracted ECN marking into cos/ecn.rs.
// Phase 2 (PR #977) extracted the flow-hash helpers into
// cos/flow_hash.rs. Phase 3 (PR #978) extracted admission policy +
// flow-fair promotion into cos/admission.rs. Phase 4 (PR #979)
// extracted token-bucket lease/refill into cos/token_bucket.rs.
// Phase 5 (this PR) extracts queue ops + MQFQ ordering bookkeeping
// + V-min slot lifecycle into cos/queue_ops.rs.
//
// Production code uses the entry points re-exported from
// cos/mod.rs (marker fns + flow-hash + admission gates +
// flow-fair promotion entry + token-bucket helpers + queue-ops
// fns). The remaining ECN constants/thresholds are referenced
// only by admission tests in `tx::tests`; the ECN parser and
// per-family ECN helpers (`ethernet_l3`, `mark_ecn_ce_*`) moved
// with their unit tests to `cos/ecn.rs` in #984 P3 phase 2c.
// Imports are gated behind `#[cfg(test)]` to avoid
// `unused_imports` warnings in non-test builds.
use super::cos::{
    apply_cos_admission_ecn_policy, cos_flow_aware_buffer_limit, cos_flow_bucket_index,
    cos_item_flow_key, cos_queue_drain_all, cos_queue_flow_share_limit,
    cos_queue_is_empty, cos_queue_push_back, cos_queue_restore_front,
    drain_shaped_tx, ensure_cos_interface_runtime, mark_cos_queue_runnable,
    publish_committed_queue_vtime, redirect_prepared_cos_request_to_owner,
    redirect_prepared_cos_request_to_owner_binding,
    resolve_local_routing_decision, LocalRoutingDecision, Step1Action,
};
#[cfg(test)]
use super::cos::{
    apply_cos_queue_flow_fair_promotion, redirect_local_cos_request_to_owner_binding,
    ExactCoSScratchBuild, COS_MIN_BURST_BYTES,
    drain_exact_local_fifo_items_to_scratch, drain_exact_local_items_to_scratch_flow_fair,
    select_cos_guarantee_batch, select_exact_cos_guarantee_queue_with_fast_path,
    settle_exact_local_fifo_submission,
    settle_exact_local_scratch_submission_flow_fair, };
// #956 P1: TX-completion + timer-wheel items reached by
// `mod tests { use super::*; }` at the bottom of this file.
// (After the #984 P3 cross_binding test colocation, the
// `redirect_local_cos_request_to_owner` and
// `prepared_cos_request_stays_on_current_tx_binding` test pins
// moved to `cos/cross_binding.rs::tests`.)
#[cfg(test)]
use super::cos::{
    advance_cos_timer_wheel, park_cos_queue,
    COS_TIMER_WHEEL_TICK_NS,
};

























#[cfg(test)]
mod tests {
    use super::*;
    use super::test_support::*;


























    #[test]
    fn redirect_local_exact_cos_request_to_owner_binding_pushes_owner_live_queue() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(
                    true,
                    7,
                    None,
                    Some(Arc::new(SharedCoSQueueLease::new(
                        1_000_000,
                        COS_MIN_BURST_BYTES,
                        2,
                    ))),
                ),
            )],
            Some(owner_live.clone()),
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        let redirected =
            redirect_local_cos_request_to_owner_binding(&current_live, &cos_fast_interfaces, req);

        assert!(redirected.is_ok());
        let mut queued = VecDeque::new();
        owner_live.take_pending_tx_into(&mut queued);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
        let mut current_queued = VecDeque::new();
        current_live.take_pending_tx_into(&mut current_queued);
        assert!(current_queued.is_empty());
    }



































































    // ---------------------------------------------------------------------
    // #785 Phase 3 — MQFQ virtual-finish-time mechanism pins.
    // ---------------------------------------------------------------------










































    // ---------------------------------------------------------------------
    // #698 — per-worker exact-drain micro-bench
    //
    // Purpose: establish an in-tree, reproducible measurement of the
    // userspace drain-path cost per packet. The value of
    // `COS_SHARED_EXACT_COS_SHARED_EXACT_MIN_RATE_BYTES` (2.5 Gbps) is cited in commit
    // history as "the single-worker sustained exact throughput ceiling";
    // before this harness existed there was no checked-in data supporting
    // that number.
    //
    // Scope (what this measures):
    //   - `drain_exact_local_fifo_items_to_scratch`
    //       VecDeque indexed read, pattern match, free-frame pop, UMEM
    //       `slice_mut_unchecked` + `copy_from_slice` (the 1500-byte
    //       memcpy that dominates `memmove` in the live profile),
    //       scratch Vec push, running root/secondary budget decrement.
    //   - `settle_exact_local_fifo_submission`
    //       queue.items.pop_front per sent packet, scratch Vec pop.
    //   - Re-prime between iterations — simulates a steady inflow of
    //       new items from the upstream CoS enqueue path.
    //
    // Scope (what this does NOT measure):
    //   - TX ring insert + commit (no XDP socket in unit tests; this
    //     is a ring-buffer write + release store on the producer index,
    //     ~20 ns combined on x86-64, amortized away at TX_BATCH_SIZE).
    //   - The `sendto()` syscall used for kernel TX wakeup (amortized
    //     over TX_BATCH_SIZE packets — ~2–4 ns per packet at the
    //     pre-#920 batch of 256; ~10–15 ns per packet at the new
    //     batch of 64).
    //   - Completion ring reap (`reap_tx_completions`) — ~20–50 ns per
    //     completion, mostly ring-buffer read + VecDeque push-back.
    //   - All non-drain per-worker cost: RX, forwarding, NAT, session
    //     lookup, conntrack. Measured in the live cluster profile, not
    //     here. Those costs dominate in production and are the real
    //     gate on per-worker aggregate throughput.
    //
    // What this tells us about the MIN constant:
    //   - If drain-path Gbps is >> 2.5 Gbps, the constant is NOT gated
    //     by drain speed. MIN reflects "what's left after RX + forward
    //     + NAT consume 80%+ of the per-worker budget" — consistent
    //     with the PR #680 collapse shape where the drain loop couldn't
    //     absorb aggregate line-rate because of *other* per-packet work.
    //   - If drain-path Gbps is < 2.5 Gbps, MIN is provably too high
    //     and must drop. (Unlikely — drain is tightly bounded by a
    //     1500-byte memcpy and a few VecDeque ops.)
    //
    // Running (release is mandatory — debug build numbers are not
    // meaningful for this baseline):
    //   cargo test --release --manifest-path userspace-dp/Cargo.toml \
    //       cos_exact_drain_throughput_micro_bench -- --ignored --nocapture
    //
    // The bench reports two separate timings:
    //   - "drain+settle (measured)" — the inner loop only. Setup work
    //     (VecDeque priming, packet cloning, free-frame pool rebuild)
    //     is excluded.
    //   - "setup (per batch, unmeasured)" — setup cost printed for
    //     reference so future changes to the setup path are visible.
    //
    // Hardware and noise: numbers depend on the box's core frequency
    // and L1/L2 cache state. Run on quiet hardware; the published
    // baseline in this commit's message was captured under those
    // conditions. A repeat run after a refactor should stay within
    // ~15% of the baseline on the same host — larger deltas warrant
    // investigation. A single development-host measurement does NOT
    // validate the MIN constant on other deployment hardware; it only
    // rules out the inner drain loop as the limiter on this host.
    // ---------------------------------------------------------------------
    #[test]
    #[ignore]
    fn cos_exact_drain_throughput_micro_bench() {
        use std::time::Instant;

        // Single source of truth — `worker::COS_SHARED_EXACT_MIN_RATE_BYTES`
        // is `pub(super)` so the bench asserts against the production
        // constant directly rather than carrying a mirror that could drift.
        use super::super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;
        const PACKET_LEN: usize = 1500;
        const BATCHES: usize = 10_000;
        // Each drain call takes TX_BATCH_SIZE items. Prime enough items
        // for one batch; after each iteration we repopulate the queue
        // and free-frame pool so the measurement reflects steady state,
        // not a cold-start transient.
        const ITEMS_PER_BATCH: usize = TX_BATCH_SIZE;

        // UMEM: 2 MB is the hugepage-aligned minimum in MmapArea. That
        // fits TX_BATCH_SIZE * 4096 = 1 MB of frame slots with headroom.
        let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 4 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        root.tokens = u64::MAX;
        root.queues[0].tokens = u64::MAX;
        root.queues[0].runnable = true;

        let packet_bytes = vec![0xABu8; PACKET_LEN];
        let mut scratch = Vec::with_capacity(ITEMS_PER_BATCH);
        let mut free_frames: VecDeque<u64> =
            (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();

        // Prime: one full batch of items. Each iteration below drains
        // them all and then re-primes both the items and the free frames
        // to the same initial state.
        let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
            queue.items.clear();
            queue.queued_bytes = 0;
            for _ in 0..ITEMS_PER_BATCH {
                queue.items.push_back(CoSPendingTxItem::Local(TxRequest {
                    bytes: packet.to_vec(),
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: 80,
                    cos_queue_id: Some(5),
                    dscp_rewrite: None,
                }));
                queue.queued_bytes += packet.len() as u64;
            }
        };

        // Warmup: 1000 batches to settle caches and branch predictors.
        for _ in 0..1000 {
            prime_queue(&mut root.queues[0], &packet_bytes);
            scratch.clear();
            free_frames = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
            let build = drain_exact_local_fifo_items_to_scratch(
                &mut root.queues[0],
                &mut free_frames,
                &mut scratch,
                &area,
                u64::MAX,
                u64::MAX,
                None,
            );
            assert!(matches!(build, ExactCoSScratchBuild::Ready));
            let inserted = scratch.len();
            settle_exact_local_fifo_submission(
                Some(&mut root.queues[0]),
                &mut free_frames,
                &mut scratch,
                inserted,
            );
        }

        // Measurement. Setup (priming, packet cloning, free-frame pool
        // rebuild) happens outside the `iter_start.elapsed()` window so
        // the reported ns/packet reflects only drain+settle. Setup cost
        // is separately accumulated and printed for reference.
        use std::time::Duration;
        let mut measured = Duration::ZERO;
        let mut setup_time = Duration::ZERO;
        let mut total_packets = 0u64;
        let mut total_bytes = 0u64;
        for _ in 0..BATCHES {
            let setup_start = Instant::now();
            prime_queue(&mut root.queues[0], &packet_bytes);
            scratch.clear();
            free_frames.clear();
            free_frames.extend((0..ITEMS_PER_BATCH as u64).map(|i| i * 4096));
            setup_time += setup_start.elapsed();

            let iter_start = Instant::now();
            let build = drain_exact_local_fifo_items_to_scratch(
                &mut root.queues[0],
                &mut free_frames,
                &mut scratch,
                &area,
                u64::MAX,
                u64::MAX,
                None,
            );
            let inserted = scratch.len();
            let (sent_pkts, sent_bytes) = settle_exact_local_fifo_submission(
                Some(&mut root.queues[0]),
                &mut free_frames,
                &mut scratch,
                inserted,
            );
            measured += iter_start.elapsed();

            assert!(matches!(build, ExactCoSScratchBuild::Ready));
            total_packets += sent_pkts;
            total_bytes += sent_bytes;
        }

        let ns_per_packet = measured.as_nanos() as f64 / total_packets as f64;
        let mpps = total_packets as f64 / measured.as_secs_f64() / 1.0e6;
        let gbps = (total_bytes as f64 * 8.0) / measured.as_secs_f64() / 1.0e9;
        let setup_ns_per_packet = setup_time.as_nanos() as f64 / total_packets as f64;

        eprintln!(
            "\n=== #698 exact-drain userspace micro-bench ===\n\
             packet len              : {} B\n\
             batches                 : {}\n\
             packets per batch       : {}\n\
             total packets           : {}\n\
             total bytes             : {} ({:.2} MB)\n\
             drain+settle (measured) : {:?}\n\
             setup (per batch, unmeasured): {:?}\n\
             ns/packet (drain+settle): {:.2}\n\
             ns/packet (setup only)  : {:.2}\n\
             throughput (pps)        : {:.3} Mpps\n\
             throughput (line rate)  : {:.3} Gbps\n\
             min-constant gate       : {:.3} Gbps (COS_SHARED_EXACT_MIN_RATE_BYTES)\n\
             verdict (this host)     : {}\n\
             scope note              : userspace drain path only; excludes TX\n\
                                       ring insert/commit, kernel wakeup, and\n\
                                       completion ring reap. Single-host number\n\
                                       only — does not validate MIN on other\n\
                                       deployment hardware.\n\
             ================================================\n",
            PACKET_LEN,
            BATCHES,
            ITEMS_PER_BATCH,
            total_packets,
            total_bytes,
            total_bytes as f64 / (1024.0 * 1024.0),
            measured,
            setup_time,
            ns_per_packet,
            setup_ns_per_packet,
            mpps,
            gbps,
            (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9,
            if gbps > (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9 {
                "drain alone exceeds MIN on this host — rules out drain as \
                 the immediate limiter here"
            } else {
                "drain alone below MIN on this host — constant is TOO HIGH, \
                 lower it and re-validate live"
            },
        );

        assert!(
            total_packets as usize == BATCHES * ITEMS_PER_BATCH,
            "every batch must fully drain: {} != {}",
            total_packets,
            BATCHES * ITEMS_PER_BATCH
        );
    }



    #[test]
    fn timer_wheel_wakes_short_parked_queue() {
        let mut root = test_cos_interface_runtime(0);
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        park_cos_queue(&mut root, 0, 5);

        assert!(root.queues[0].parked);
        assert!(!root.queues[0].runnable);
        assert_eq!(root.runnable_queues, 0);

        advance_cos_timer_wheel(&mut root, 4 * COS_TIMER_WHEEL_TICK_NS);
        assert!(root.queues[0].parked);
        assert!(!root.queues[0].runnable);

        advance_cos_timer_wheel(&mut root, 5 * COS_TIMER_WHEEL_TICK_NS);
        assert!(!root.queues[0].parked);
        assert!(root.queues[0].runnable);
        assert_eq!(root.runnable_queues, 1);
    }

    #[test]
    fn timer_wheel_cascades_long_parked_queue() {
        let mut root = test_cos_interface_runtime(0);
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let wake_tick = COS_TIMER_WHEEL_L0_SLOTS as u64 + 10;
        park_cos_queue(&mut root, 0, wake_tick);

        assert_eq!(root.queues[0].wheel_level, 1);
        assert!(root.queues[0].parked);

        advance_cos_timer_wheel(&mut root, (wake_tick - 1) * COS_TIMER_WHEEL_TICK_NS);
        assert!(root.queues[0].parked);
        assert!(!root.queues[0].runnable);

        advance_cos_timer_wheel(&mut root, wake_tick * COS_TIMER_WHEEL_TICK_NS);
        assert!(!root.queues[0].parked);
        assert!(root.queues[0].runnable);
        assert_eq!(root.runnable_queues, 1);
    }




    // ---------------------------------------------------------------------
    // #710 drop-reason counter tests. Each test drives the exact code
    // path that should tick the named counter, and asserts:
    //   (a) the expected counter advances by the expected amount
    //   (b) no other counter on the same queue advances
    // Byte-precise so a future refactor that accidentally re-attributes a
    // drop to the wrong reason is caught on CI.
    // ---------------------------------------------------------------------


    #[test]
    fn park_counter_root_token_starvation_ticks_only_its_reason() {
        let mut root = test_cos_runtime_with_exact(true);
        root.tokens = 0;
        root.queues[0].tokens = 0;
        root.queues[0].runnable = true;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let before = snapshot_counters(&root.queues[0]);
        // Drive a selector that will park on root-token starvation.
        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        let after = snapshot_counters(&root.queues[0]);

        assert_eq!(
            after.root_token_starvation_parks,
            before.root_token_starvation_parks + 1,
            "root-token park counter must advance by 1"
        );
        assert_eq!(
            after.queue_token_starvation_parks,
            before.queue_token_starvation_parks
        );
        assert_eq!(
            after.admission_flow_share_drops,
            before.admission_flow_share_drops
        );
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
        assert_eq!(
            after.tx_ring_full_submit_stalls,
            before.tx_ring_full_submit_stalls
        );
    }

    #[test]
    fn park_counter_queue_token_starvation_ticks_only_its_reason_on_exact() {
        let mut root = test_cos_runtime_with_exact(true);
        // Root has headroom; per-queue tokens do not. Forces the
        // queue-token park branch on the exact selector.
        root.tokens = 1_000_000;
        root.queues[0].tokens = 0;
        root.queues[0].last_refill_ns = 1; // skip the first-refill init path
        root.queues[0].runnable = true;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let before = snapshot_counters(&root.queues[0]);
        let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
        assert!(
            selection.is_none(),
            "exact selector must park, not return a queue"
        );
        let after = snapshot_counters(&root.queues[0]);

        assert_eq!(
            after.queue_token_starvation_parks,
            before.queue_token_starvation_parks + 1,
            "queue-token park counter must advance by 1"
        );
        assert_eq!(
            after.root_token_starvation_parks,
            before.root_token_starvation_parks
        );
        assert_eq!(
            after.admission_flow_share_drops,
            before.admission_flow_share_drops
        );
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
        assert_eq!(
            after.tx_ring_full_submit_stalls,
            before.tx_ring_full_submit_stalls
        );
    }







    // `admission_does_not_mark_prepared_variant` was removed in #727:
    // the Prepared variant is now handled by
    // `maybe_mark_ecn_ce_prepared`, and the positive-behaviour pins
    // for the Prepared hot path live in the
    // `admission_ecn_marks_prepared_*` tests below.

    // ---------------------------------------------------------------------
    // #722 per-flow ECN threshold. #718 landed ECN CE marking keyed off
    // aggregate queue depth. Live validation on the 16-flow / 1 Gbps
    // exact-queue workload showed the aggregate threshold never fires
    // (queue sat at ~31% vs the 50% threshold) because drops came from
    // the per-flow fair-share cap. These tests drive the per-flow arm
    // directly, recreate the live failure mode, and include a counter-
    // factual assertion that proves the pre-#722 aggregate-only formula
    // would have missed this case.
    // ---------------------------------------------------------------------








    // ---------------------------------------------------------------------
    // #785 SFQ promotion. `ensure_cos_interface_runtime` calls
    // `apply_cos_queue_flow_fair_promotion` on a freshly-built
    // `CoSInterfaceRuntime`, which in turn calls
    // `promote_cos_queue_flow_fair` per queue.
    //
    // Current policy:
    //   * SFQ (flow-fair) runs on owner-local-exact queues only.
    //   * Shared_exact (>= `COS_SHARED_EXACT_MIN_RATE_BYTES` =
    //     2.5 Gbps) queues stay on the single-FIFO-per-worker drain.
    //   * `promote_cos_queue_flow_fair` caches the live
    //     `WorkerCoSQueueFastPath.shared_exact` bit onto the runtime
    //     as `CoSQueueRuntime.shared_exact` so the admission hot
    //     paths (or future cross-worker fairness work) can branch
    //     on it without another iface_fast lookup.
    //
    // Why shared_exact is held back: issue #785 tried two paths to
    // land SFQ on the high-rate service path. Both regressed and
    // were rolled back:
    //
    //   1. Naïve SFQ (flow_fair=queue.exact, no admission change).
    //      iperf3 -P 12 on the 25 Gbps iperf-c cap regressed from
    //      22.3 Gbps / 0 retrans to 16.3 Gbps / 25k+ retrans. Root
    //      cause: per-flow share cap + per-flow ECN arm are
    //      rate-unaware (24 KB floor); on 25 Gbps / 12 flows that
    //      is ≪ 5 MB BDP so admission drops and ECN fire on every
    //      packet.
    //
    //   2. SFQ + aggregate-only admission on shared_exact. Throughput
    //      preserved (22-23 Gbps) but per-flow CoV went UP from
    //      ~33 % to ~40-51 % over three runs. Per-worker SFQ cannot
    //      equalise flows distributed unevenly across workers by NIC
    //      RSS — which is the dominant imbalance source at P=12.
    //
    // The architecturally-correct lever is cross-worker flow
    // steering (or a single shared SFQ across workers), tracked in
    // the follow-up issue.
    //
    // Adversarial review posture (post-#914): the historical
    // `!shared_exact` gate is no longer in policy. shared_exact
    // now runs MQFQ flow-fair AND a rate-aware admission cap
    // (`max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)` —
    // see `cos_queue_flow_share_limit`). Reviewers should reject
    // PRs that re-introduce the rate-unaware MIN-floor cap on
    // shared_exact without also re-validating
    // `iperf3 -P 12 -p 5203` ≥ 22 Gbps AND per-flow CoV ≤ 20 %
    // (the regression Attempt A hit). The tests below drive the
    // full production promotion path (via
    // `apply_cos_queue_flow_fair_promotion` with hand-authored
    // `WorkerCoSQueueFastPath` vectors) so breaking the zip alignment
    // at the `ensure_cos_interface_runtime` call site — or feeding
    // the wrong `shared_exact` bit — is caught.
    // ---------------------------------------------------------------------






    // ---------------------------------------------------------------------
    // #727 Prepared-variant ECN marking. The #718 / #722 marker was
    // dormant on the XSK-RX→XSK-TX zero-copy hot path because the
    // admission policy only handled `CoSPendingTxItem::Local`. These
    // tests pin the Prepared branch byte-precisely: pre-state is
    // ECT(0/1), post-state is CE, counter bumps exactly once, and
    // the IPv4 checksum is still valid from scratch. A NOT-ECT
    // counterfactual and an out-of-range-offset counterfactual are
    // included so a regression that short-circuits either arm fails
    // loudly.
    // ---------------------------------------------------------------------









    // ---------------------------------------------------------------------
    // #940 + #942 V_min correctness sweep tests
    // ---------------------------------------------------------------------








    // ---------------------------------------------------------------------
    // #940 microbenchmark: pop + commit + settle + publish
    //
    // Per Gemini adversarial review: measure the FULL pop+commit+settle
    // cycle so we capture the publish cost relocation (publish moved
    // from pop time to post-settle).
    //
    // Run: cargo test --release -p xpf-userspace-dp -- bench_pop_commit_settle_publish --nocapture --ignored
    // ---------------------------------------------------------------------
    #[test]
    #[ignore]
    fn bench_pop_commit_settle_publish() {
        use std::time::Instant;
        const PACKET_LEN: usize = 1500;
        const BATCHES: usize = 10_000;
        const ITEMS_PER_BATCH: usize = TX_BATCH_SIZE;

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 4 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        root.tokens = u64::MAX;
        // Promote to flow_fair + shared_exact + attach floor to
        // exercise the V_min publish path.
        let queue = &mut root.queues[0];
        queue.tokens = u64::MAX;
        queue.flow_fair = true;
        queue.exact = true;
        queue.shared_exact = true;
        let _floor = attach_test_vtime_floor(queue, 4, 0);
        queue.runnable = true;

        let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");
        let packet_bytes = vec![0xABu8; PACKET_LEN];
        let mut scratch: Vec<(u64, TxRequest)> = Vec::with_capacity(ITEMS_PER_BATCH);
        let mut free_frames: VecDeque<u64> =
            (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();

        let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
            queue.items.clear();
            queue.queued_bytes = 0;
            queue.queue_vtime = 0;
            queue.flow_bucket_bytes = [0; COS_FLOW_FAIR_BUCKETS];
            queue.flow_bucket_head_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
            queue.flow_bucket_tail_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
            queue.flow_rr_buckets = FlowRrRing::default();
            queue.flow_bucket_items = std::array::from_fn(|_| VecDeque::new());
            queue.active_flow_buckets = 0;
            queue.local_item_count = 0;
            queue.pop_snapshot_stack.clear();
            for i in 0..ITEMS_PER_BATCH {
                let mut req = TxRequest {
                    bytes: packet.to_vec(),
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: Some(test_session_key((1000 + i) as u16, 5201)),
                    egress_ifindex: 80,
                    cos_queue_id: Some(0),
                    dscp_rewrite: None,
                };
                let _ = req.bytes.len();
                cos_queue_push_back(queue, CoSPendingTxItem::Local(req));
            }
        };

        // Warmup.
        for _ in 0..1000 {
            prime_queue(&mut root.queues[0], &packet_bytes);
            scratch.clear();
            free_frames = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
            let _ = drain_exact_local_items_to_scratch_flow_fair(
                &mut root.queues[0],
                &mut free_frames,
                &mut scratch,
                &area,
                u64::MAX,
                u64::MAX,
                None,
            );
            let inserted = scratch.len();
            settle_exact_local_scratch_submission_flow_fair(
                Some(&mut root.queues[0]),
                &mut free_frames,
                &mut scratch,
                inserted,
            );
            publish_committed_queue_vtime(Some(&root.queues[0]));
        }

        let mut measured = std::time::Duration::ZERO;
        let mut total_packets = 0u64;
        for _ in 0..BATCHES {
            prime_queue(&mut root.queues[0], &packet_bytes);
            scratch.clear();
            free_frames.clear();
            free_frames.extend((0..ITEMS_PER_BATCH as u64).map(|i| i * 4096));

            let iter_start = Instant::now();
            let _ = drain_exact_local_items_to_scratch_flow_fair(
                &mut root.queues[0],
                &mut free_frames,
                &mut scratch,
                &area,
                u64::MAX,
                u64::MAX,
                None,
            );
            let inserted = scratch.len();
            settle_exact_local_scratch_submission_flow_fair(
                Some(&mut root.queues[0]),
                &mut free_frames,
                &mut scratch,
                inserted,
            );
            publish_committed_queue_vtime(Some(&root.queues[0]));
            measured += iter_start.elapsed();
            total_packets += inserted as u64;
        }

        let ns_per_pkt = measured.as_nanos() as f64 / total_packets as f64;
        eprintln!(
            "bench_pop_commit_settle_publish: {} packets in {:?} = {:.1} ns/pkt",
            total_packets, measured, ns_per_pkt
        );
    }

    // ---------------------------------------------------------------------
    // #941 V_min vacate + hard-cap-with-suspension tests (Work items A/C/D)
    // ---------------------------------------------------------------------












}
