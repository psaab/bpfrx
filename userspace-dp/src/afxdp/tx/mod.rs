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
#[cfg(test)]
use rings::apply_prepared_recycle;

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
// cfg-test imports for 5 helpers directly pinned in tx/mod.rs::tests.
#[cfg(test)]
use cos_classify::{
    clone_prepared_request_for_cos, cos_queue_accepts_prepared,
    demote_prepared_cos_queue_to_local, prepare_local_request_for_cos,
    resolve_cos_queue_idx,
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
// fns). The codepoint masks + ECN parser + per-family ECN helpers
// are referenced only by `tx::tests` (admission tests + ECN unit
// tests that stay here for Phase 1). Their imports are gated
// behind `#[cfg(test)]` to avoid `unused_imports` warnings in
// non-test builds (Copilot review on PR #976).
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
use super::cos::ecn::{ethernet_l3, mark_ecn_ce_ipv4, mark_ecn_ce_ipv6, EthernetL3};
#[cfg(test)]
use super::cos::{
    account_cos_queue_flow_dequeue, account_cos_queue_flow_enqueue,
    apply_cos_queue_flow_fair_promotion, assign_local_dscp_rewrite, bdp_floor_bytes,
    build_cos_interface_runtime, cos_batch_tx_made_progress, cos_flow_hash_seed_from_os, redirect_local_cos_request_to_owner_binding,
    cos_guarantee_quantum_bytes, cos_queue_clear_orphan_snapshot_after_drop,
    cos_queue_pop_front, cos_queue_prospective_active_flows,
    cos_queue_v_min_consume_suspension, cos_queue_v_min_continue, count_park_reason,
    maybe_top_up_cos_queue_lease, CoSBatch, ExactCoSScratchBuild, COS_MIN_BURST_BYTES,
    drain_exact_local_fifo_items_to_scratch, drain_exact_local_items_to_scratch_flow_fair,
    drain_exact_prepared_fifo_items_to_scratch,
    drain_exact_prepared_items_to_scratch_flow_fair, estimate_cos_queue_wakeup_tick,
    maybe_mark_ecn_ce, release_exact_local_scratch_frames, release_exact_prepared_scratch,
    select_cos_guarantee_batch, select_cos_guarantee_batch_with_fast_path,
    select_cos_surplus_batch, select_exact_cos_guarantee_queue_with_fast_path,
    select_nonexact_cos_guarantee_batch, settle_exact_local_fifo_submission,
    settle_exact_local_scratch_submission_flow_fair, settle_exact_prepared_fifo_submission,
    ParkReason, COS_ECN_MARK_THRESHOLD_DEN, COS_ECN_MARK_THRESHOLD_NUM,
    COS_FLOW_FAIR_MIN_SHARE_BYTES, ECN_CE, ECN_ECT_0, ECN_ECT_1, ECN_MASK, ECN_NOT_ECT,
    V_MIN_CONSECUTIVE_SKIP_HARD_CAP, V_MIN_SUSPENSION_BATCHES,
};
// #956 P1: TX-completion + timer-wheel items reached by
// `mod tests { use super::*; }` at the bottom of this file, plus
// `redirect_local_cos_request_to_owner` which is also test-only after
// the cross_binding extraction in #956 Phase 8.
#[cfg(test)]
use super::cos::{
    advance_cos_timer_wheel, cos_queue_push_front, maybe_top_up_cos_root_lease,
    normalize_cos_queue_state, park_cos_queue,
    prepared_cos_request_stays_on_current_tx_binding, redirect_local_cos_request_to_owner,
    restore_cos_local_items_inner, restore_cos_prepared_items_inner,
    CoSServicePhase, COS_TIMER_WHEEL_TICK_NS,
};

























#[cfg(test)]
mod tests {
    use super::*;
    use super::test_support::*;
    use crate::{
        ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
        CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot,
        CoSIEEE8021ClassifierSnapshot, CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot,
        CoSSchedulerSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    };




    #[test]
    fn cos_batch_tx_made_progress_requires_real_send_progress() {
        assert!(!cos_batch_tx_made_progress(Ok((0, 0))));
        assert!(cos_batch_tx_made_progress(Ok((1, 0))));
        assert!(cos_batch_tx_made_progress(Ok((0, 1500))));
    }

    #[test]
    fn cos_batch_tx_made_progress_yields_on_retry_and_drop() {
        assert!(!cos_batch_tx_made_progress(Err(TxError::Retry(
            "no free TX frame available".to_string()
        ))));
        assert!(!cos_batch_tx_made_progress(Err(TxError::Drop(
            "tx ring insert failed".to_string()
        ))));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_pushes_worker_command() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            None,
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

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        let pending = commands.lock().unwrap();
        assert_eq!(pending.len(), 1);
        match pending.front() {
            Some(WorkerCommand::EnqueueShapedLocal(req)) => {
                assert_eq!(req.egress_ifindex, 80);
                assert_eq!(req.cos_queue_id, Some(4));
            }
            other => panic!("unexpected command queued: {other:?}"),
        }
    }

    #[test]
    fn redirect_local_cos_request_to_owner_uses_interface_default_queue_owner_when_unset() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(5, test_queue_fast_path(false, 7, None, None))],
            None,
            None,
        );
        let req = TxRequest {
            bytes: vec![1, 2, 3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: None,
            dscp_rewrite: None,
        };

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        let pending = commands.lock().unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn redirect_local_cos_request_to_owner_rejects_explicit_queue_miss() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(5, test_queue_fast_path(false, 7, None, None))],
            None,
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

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_err());
        assert!(commands.lock().unwrap().is_empty());
    }

    #[test]
    fn resolve_cos_queue_idx_rejects_explicit_queue_miss() {
        let root = test_cos_runtime_with_queues(
            10_000_000,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );

        assert_eq!(resolve_cos_queue_idx(&root, Some(4)), None);
        assert_eq!(resolve_cos_queue_idx(&root, None), Some(0));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_keeps_exact_queue_on_eligible_worker() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let tx_owner_live = Arc::new(BindingLiveState::new());
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
            Some(tx_owner_live),
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

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_err());
        assert!(commands.lock().unwrap().is_empty());
    }

    #[test]
    fn shared_cos_root_lease_bounds_total_outstanding_credit() {
        let lease = SharedCoSRootLease::new(400_000_000, 256 * 1024, 2);
        let lease_bytes = lease.lease_bytes();

        let first = lease.acquire(1, lease_bytes);
        let second = lease.acquire(1, lease_bytes);
        let third = lease.acquire(1, lease_bytes);

        assert_eq!(first, lease_bytes);
        assert_eq!(second, lease_bytes);
        assert_eq!(third, 0);

        lease.release_unused(lease_bytes);
        let fourth = lease.acquire(1, lease_bytes);
        assert_eq!(fourth, lease_bytes);
    }

    #[test]
    fn shared_cos_queue_lease_bounds_total_outstanding_credit() {
        let lease = SharedCoSQueueLease::new(10_000_000, 128 * 1024, 2);
        let request = 2500;

        let first = lease.acquire(1, request);
        let second = lease.acquire(1, request);
        let third = lease.acquire(1, request);
        let fourth = lease.acquire(1, request);
        let fifth = lease.acquire(1, 1);

        assert_eq!(first, request);
        assert_eq!(second, request);
        assert_eq!(third, request);
        assert_eq!(
            first + second + third + fourth,
            (tx_frame_capacity() as u64) * 2
        );
        assert_eq!(fifth, 0);

        lease.release_unused(request);
        let sixth = lease.acquire(1, request);
        assert_eq!(sixth, request);
    }

    #[test]
    fn maybe_top_up_cos_root_lease_unblocks_large_frame_exceeding_lease_bytes() {
        // Pick a shaping rate low enough that lease_bytes() floors to COS_ROOT_LEASE_MIN_BYTES
        // (1500) and stays below tx_frame_capacity() (4096).  At 50 Mbps / 256 KB burst / 1 shard
        // the raw target lease is rate*TARGET_US/1e6 = 1250 bytes, which floors up to 1500.
        // Without the .max(tx_frame_capacity()) fix in maybe_top_up_cos_root_lease, root.tokens
        // could never exceed 1500 and any frame with len > 1500 would deadlock the CoS queue.
        let rate_bytes = 50_000_000u64 / 8;
        let lease = Arc::new(SharedCoSRootLease::new(rate_bytes, 256 * 1024, 1));
        assert!(
            lease.lease_bytes() < tx_frame_capacity() as u64,
            "precondition: lease_bytes must be below tx_frame_capacity for this regression"
        );

        let mut root = test_cos_runtime_with_queues(
            rate_bytes,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: rate_bytes,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let frame_len = tx_frame_capacity();
        root.queues[0].tokens = 64 * 1024;
        root.queues[0].runnable = true;
        root.queues[0].items.push_back(test_cos_item(frame_len));
        root.queues[0].queued_bytes = frame_len as u64;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        maybe_top_up_cos_root_lease(&mut root, &lease, 1_000_000_000);

        assert!(
            root.tokens >= frame_len as u64,
            "root tokens ({}) must cover frame len ({}) after lease top-up",
            root.tokens,
            frame_len
        );
        let batch = select_cos_guarantee_batch(&mut root, 1_000_000_000);
        assert!(
            batch.is_some(),
            "large frame must be dequeued after lease top-up"
        );
    }

    #[test]
    fn maybe_top_up_cos_queue_lease_unblocks_local_exact_queue_without_tokens() {
        let mut root = test_cos_runtime_with_queues(
            400_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 400_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 1500;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;
        let shared_queue_lease = Arc::new(SharedCoSQueueLease::new(
            400_000_000 / 8,
            COS_MIN_BURST_BYTES,
            2,
        ));
        let queue_fast_path = vec![test_queue_fast_path(
            true,
            0,
            None,
            Some(shared_queue_lease.clone()),
        )];

        maybe_top_up_cos_queue_lease(
            &mut root.queues[0],
            Some(&shared_queue_lease),
            1_000_000_000,
        );

        assert!(
            root.queues[0].tokens >= 1500,
            "shared exact queue lease must replenish local queue tokens"
        );
        assert!(
            select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000,)
                .is_some()
        );
    }

    #[test]
    fn exact_queue_without_shared_lease_does_not_locally_refill() {
        let mut root = test_cos_runtime_with_queues(
            400_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 1500;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;
        let queue_fast_path = vec![test_queue_fast_path(true, 0, None, None)];

        let batch =
            select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000);

        assert!(
            batch.is_none(),
            "exact queues must not locally refill when the shared queue lease is unavailable"
        );
        assert_eq!(root.queues[0].tokens, 0);
        assert_eq!(root.queues[0].last_refill_ns, 0);
    }

    #[test]
    fn build_cos_interface_runtime_starts_exact_queue_with_zero_local_tokens() {
        let runtime = build_cos_interface_runtime(
            &CoSInterfaceConfig {
                shaping_rate_bytes: 25_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 5,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                }],
            },
            1_000_000_000,
        );

        assert_eq!(runtime.queues[0].tokens, 0);
        assert_eq!(runtime.queues[0].last_refill_ns, 0);
    }

    /// #780 / Codex adversarial review: verify the decision DAG
    /// inside `resolve_local_routing_decision` exactly mirrors
    /// the pre-#780 three-step cascade across every quadrant
    /// flagged. The decision now carries BOTH Step 1 and Step 2
    /// independently so the ingest loop can fall through on Err.
    #[test]
    fn resolve_local_routing_decision_step1_routes_via_arc() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(false, 7, Some(owner_live.clone()), None),
            )],
            None,
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        match decision.step1 {
            Some(Step1Action::Arc(ref arc)) => {
                assert!(Arc::ptr_eq(arc, &owner_live));
            }
            _ => panic!("expected Step1 Arc"),
        }
        assert!(decision.step2.is_none());
    }

    #[test]
    fn resolve_local_routing_decision_step1_routes_via_command_when_no_arc() {
        let current_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            None,
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        match decision.step1 {
            Some(Step1Action::Command(w)) => assert_eq!(w, 7),
            _ => panic!("expected Step1 Command"),
        }
        assert!(decision.step2.is_none());
    }

    /// Codex round 2 missing-test flag: Step1Command path where
    /// iface has tx_owner_live set but queue is not shared_exact
    /// and owner_live is None. Step 1 must route via command
    /// (because queue's own owner_live is None), AND Step 2
    /// should ALSO be set so the cascade falls through on Err.
    #[test]
    fn resolve_local_routing_decision_step1_command_with_iface_tx_owner_live_populates_both_steps() {
        let current_live = Arc::new(BindingLiveState::new());
        let iface_owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            Some(iface_owner_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        match decision.step1 {
            Some(Step1Action::Command(w)) => assert_eq!(w, 7),
            _ => panic!("expected Step1 Command"),
        }
        // Step 2 must also be populated — cascade fallthrough.
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &iface_owner_live)),
            None => panic!("expected Step2 populated for cascade fallthrough"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_step2_routes_when_owner_worker_is_current() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(false, 3, Some(owner_live.clone()), None),
            )],
            Some(owner_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        // Step 1 bails (owner == current), Step 2 routes.
        assert!(decision.step1.is_none());
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
            None => panic!("expected Step2 Arc"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_step2_routes_when_shared_exact_bails_step1() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(
                    true,
                    3,
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
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        assert!(decision.step1.is_none());
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
            None => panic!("expected Step2 Arc"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_enqueue_local_when_both_bail() {
        let current_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(false, 3, Some(current_live.clone()), None),
            )],
            Some(current_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        assert!(decision.step1.is_none());
        assert!(decision.step2.is_none());
    }

    #[test]
    fn resolve_local_routing_decision_step2_routes_when_queue_absent() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let ifaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
            Some(owner_live.clone()),
            None,
        );
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(99), 3, &current_live);
        assert!(decision.step1.is_none());
        match decision.step2 {
            Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
            None => panic!("expected Step2 Arc"),
        }
    }

    #[test]
    fn resolve_local_routing_decision_enqueue_local_when_iface_absent() {
        let current_live = Arc::new(BindingLiveState::new());
        let ifaces: FastMap<i32, WorkerCoSInterfaceFastPath> = FastMap::default();
        let decision =
            resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
        assert!(decision.step1.is_none());
        assert!(decision.step2.is_none());
    }

    #[test]
    fn redirect_local_cos_request_to_owner_binding_pushes_owner_live_queue() {
        let current_live = Arc::new(BindingLiveState::new());
        let owner_live = Arc::new(BindingLiveState::new());
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(4, test_queue_fast_path(false, 7, None, None))],
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

    #[test]
    fn prepared_cos_request_stays_on_current_tx_binding_for_exact_queue() {
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(
                5,
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
            Some(Arc::new(BindingLiveState::new())),
            None,
        );
        let iface_fast = cos_fast_interfaces.get(&80).unwrap();
        let queue_fast = iface_fast.queue_fast_path(Some(5)).unwrap();

        assert!(prepared_cos_request_stays_on_current_tx_binding(
            12, iface_fast, queue_fast,
        ));
        assert!(!prepared_cos_request_stays_on_current_tx_binding(
            13, iface_fast, queue_fast,
        ));
    }

    #[test]
    fn prepared_cos_request_stays_on_current_tx_binding_only_for_exact_queue() {
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            5,
            vec![(5, test_queue_fast_path(false, 7, None, None))],
            Some(Arc::new(BindingLiveState::new())),
            None,
        );
        let iface_fast = cos_fast_interfaces.get(&80).unwrap();
        let queue_fast = iface_fast.queue_fast_path(Some(5)).unwrap();

        assert!(!prepared_cos_request_stays_on_current_tx_binding(
            12, iface_fast, queue_fast,
        ));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_uses_owner_live_queue_when_available() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let owner_live = Arc::new(BindingLiveState::new());
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(false, 7, Some(owner_live.clone()), None),
            )],
            None,
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

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        assert!(commands.lock().unwrap().is_empty());
        let mut queued = VecDeque::new();
        owner_live.take_pending_tx_into(&mut queued);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
        assert_eq!(queued.front().map(|req| req.cos_queue_id), Some(Some(4)));
    }

    #[test]
    fn redirect_local_cos_request_to_owner_redirects_low_rate_exact_queue() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
        let cos_fast_interfaces = test_cos_fast_interfaces(
            80,
            12,
            4,
            vec![(
                4,
                test_queue_fast_path(
                    false,
                    7,
                    None,
                    Some(Arc::new(SharedCoSQueueLease::new(
                        1_000_000_000 / 8,
                        COS_MIN_BURST_BYTES,
                        4,
                    ))),
                ),
            )],
            Some(Arc::new(BindingLiveState::new())),
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

        let redirected = redirect_local_cos_request_to_owner(
            &cos_fast_interfaces,
            req,
            2,
            &worker_commands_by_id,
        );

        assert!(redirected.is_ok());
        let pending = commands.lock().unwrap();
        assert_eq!(pending.len(), 1);
        match pending.front() {
            Some(WorkerCommand::EnqueueShapedLocal(req)) => {
                assert_eq!(req.egress_ifindex, 80);
                assert_eq!(req.cos_queue_id, Some(4));
            }
            other => panic!("unexpected command queued: {other:?}"),
        }
    }


    #[test]
    fn remember_prepared_recycle_tracks_only_shared_fill_recycles() {
        let mut in_flight_prepared_recycles = FastMap::default();

        remember_prepared_recycle(
            &mut in_flight_prepared_recycles,
            &PreparedTxRequest {
                offset: 41,
                len: 64,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 0,
                cos_queue_id: None,
                dscp_rewrite: None,
            },
        );
        remember_prepared_recycle(
            &mut in_flight_prepared_recycles,
            &PreparedTxRequest {
                offset: 42,
                len: 64,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 0,
                cos_queue_id: None,
                dscp_rewrite: None,
            },
        );

        assert_eq!(in_flight_prepared_recycles.len(), 1);
        assert_eq!(
            in_flight_prepared_recycles.get(&42),
            Some(&PreparedTxRecycle::FillOnSlot(7))
        );
        assert!(!in_flight_prepared_recycles.contains_key(&41));
    }

    #[test]
    fn clone_prepared_request_for_cos_returns_local_copy_with_metadata() {
        let mut area = MmapArea::new(4096).expect("mmap");
        let payload = [0xde, 0xad, 0xbe, 0xef];
        area.slice_mut(128, payload.len())
            .expect("slice")
            .copy_from_slice(&payload);
        let req = PreparedTxRequest {
            offset: 128,
            len: payload.len() as u32,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: Some((1111, 2222)),
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                src_port: 1111,
                dst_port: 2222,
            }),
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: Some(46),
        };

        let local = clone_prepared_request_for_cos(&area, &req).expect("local copy");

        assert_eq!(local.bytes, payload);
        assert_eq!(local.expected_ports, Some((1111, 2222)));
        assert_eq!(local.expected_addr_family, libc::AF_INET6 as u8);
        assert_eq!(local.expected_protocol, PROTO_TCP);
        assert_eq!(local.egress_ifindex, 80);
        assert_eq!(local.cos_queue_id, Some(4));
        assert_eq!(local.dscp_rewrite, Some(46));
        assert_eq!(
            local
                .flow_key
                .as_ref()
                .map(|key| (key.src_port, key.dst_port)),
            Some((1111, 2222))
        );
    }

    #[test]
    fn clone_prepared_request_for_cos_rejects_out_of_range_offset() {
        let area = MmapArea::new(256).expect("mmap");
        let req = PreparedTxRequest {
            offset: 1024,
            len: 64,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };

        assert!(clone_prepared_request_for_cos(&area, &req).is_none());
    }

    #[test]
    fn prepare_local_request_for_cos_materializes_prepared_frame() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut free_tx_frames = VecDeque::from([128]);
        let req = TxRequest {
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
            expected_ports: Some((1111, 2222)),
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                src_port: 1111,
                dst_port: 2222,
            }),
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: Some(46),
        };

        let prepared =
            prepare_local_request_for_cos(&area, &mut free_tx_frames, req).expect("prepared");

        assert_eq!(prepared.offset, 128);
        assert_eq!(prepared.len, 4);
        assert_eq!(prepared.recycle, PreparedTxRecycle::FreeTxFrame);
        assert_eq!(prepared.expected_ports, Some((1111, 2222)));
        assert_eq!(prepared.egress_ifindex, 80);
        assert_eq!(prepared.cos_queue_id, Some(5));
        assert_eq!(prepared.dscp_rewrite, Some(46));
        assert!(free_tx_frames.is_empty());
        assert_eq!(area.slice(128, 4).expect("slice"), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn prepare_local_request_for_cos_falls_back_when_no_free_tx_frame_exists() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut free_tx_frames = VecDeque::new();
        let req = TxRequest {
            bytes: vec![1, 2, 3, 4],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
        };

        let req = match prepare_local_request_for_cos(&area, &mut free_tx_frames, req) {
            Ok(_) => panic!("must fall back to local"),
            Err(req) => req,
        };

        assert_eq!(req.bytes, [1, 2, 3, 4]);
        assert!(free_tx_frames.is_empty());
    }

    #[test]
    fn cos_queue_accepts_prepared_when_queue_is_prepared_only() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        assert!(cos_queue_accepts_prepared(&root, Some(5)));
    }

    #[test]
    fn cos_queue_rejects_prepared_once_local_items_enter_queue() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        // #774: use cos_queue_push_back so local_item_count
        // stays in sync. Previously this test poked queue.items
        // directly, which bypassed the counter maintenance.
        cos_queue_push_back(
            &mut root.queues[0],
            CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }),
        );
        cos_queue_push_back(
            &mut root.queues[0],
            CoSPendingTxItem::Local(TxRequest {
                bytes: vec![0; 1500],
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }),
        );

        assert!(!cos_queue_accepts_prepared(&root, Some(5)));
    }

    #[test]
    fn demote_prepared_cos_queue_to_local_recycles_frames_and_blocks_prepared_appends() {
        let area = MmapArea::new(4096).expect("mmap");
        unsafe { area.slice_mut_unchecked(64, 4) }
            .expect("frame")
            .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        unsafe { area.slice_mut_unchecked(128, 4) }
            .expect("frame")
            .copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: Some((1111, 5202)),
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 4,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: Some((1112, 5202)),
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::from([512]);
        let mut pending_fill_frames = VecDeque::new();
        assert!(demote_prepared_cos_queue_to_local(
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            &mut root,
            Some(5),
        ));

        let items = root.queues[0]
            .items
            .iter()
            .map(|item| match item {
                CoSPendingTxItem::Local(req) => req.bytes.clone(),
                CoSPendingTxItem::Prepared(_) => panic!("prepared item should be demoted"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            items,
            vec![vec![0xde, 0xad, 0xbe, 0xef], vec![0xca, 0xfe, 0xba, 0xbe]]
        );
        assert_eq!(free_tx_frames, VecDeque::from([512, 64]));
        assert_eq!(pending_fill_frames, VecDeque::from([128]));
        assert!(!cos_queue_accepts_prepared(&root, Some(5)));
    }

    /// #926: regression test for the success-path
    /// queue_vtime / head-finish preservation. Prepared items
    /// across multiple flows are queued, demoted to Local, and
    /// the MQFQ frontier (queue_vtime + per-bucket head/tail
    /// finish-times) MUST be unchanged. A new flow Y enqueued
    /// immediately after demotion MUST anchor at a finish-time
    /// that respects the demoted backlog's frontier — i.e. Y
    /// cannot jump ahead of the demoted backlog.
    #[test]
    fn demote_prepared_cos_queue_to_local_preserves_mqfq_frontier() {
        let area = MmapArea::new(4096).expect("mmap");
        unsafe { area.slice_mut_unchecked(64, 4) }
            .expect("frame")
            .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        unsafe { area.slice_mut_unchecked(128, 4) }
            .expect("frame")
            .copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Two distinct flows, each one Prepared item. Bucket
        // indices computed under flow_hash_seed=0 for use in
        // post-demote frontier assertions.
        let key_a = test_session_key(8001, 5201);
        let key_b = test_session_key(8002, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
        let bucket_b = cos_flow_bucket_index(0, Some(&key_b));
        assert_ne!(
            bucket_a, bucket_b,
            "test setup: ports 8001/8002 must hash to distinct buckets"
        );

        cos_queue_push_back(
            queue,
            CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: Some(key_a.clone()),
                egress_ifindex: 42,
                cos_queue_id: Some(4),
                dscp_rewrite: None,
            }),
        );
        cos_queue_push_back(
            queue,
            CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: Some(key_b.clone()),
                egress_ifindex: 42,
                cos_queue_id: Some(4),
                dscp_rewrite: None,
            }),
        );

        // Snapshot pre-demote MQFQ frontier.
        let pre_vtime = queue.queue_vtime;
        let pre_head_a = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_head_b = queue.flow_bucket_head_finish_bytes[bucket_b];
        let pre_tail_a = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_tail_b = queue.flow_bucket_tail_finish_bytes[bucket_b];
        assert!(pre_head_a > 0);
        assert!(pre_head_b > 0);

        // Demote (success path).
        let mut free_tx_frames = VecDeque::from([512]);
        let mut pending_fill_frames = VecDeque::new();
        assert!(demote_prepared_cos_queue_to_local(
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            &mut root,
            Some(4),
        ));

        let queue = &mut root.queues[0];

        // Frontier MUST be unchanged across the success path.
        assert_eq!(
            queue.queue_vtime, pre_vtime,
            "#926 regression: queue_vtime must be preserved across \
             demote success path. Pre={pre_vtime} post={}",
            queue.queue_vtime
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_head_a,
            "#926: head_finish[A] must be preserved (pre={pre_head_a})"
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], pre_head_b,
            "#926: head_finish[B] must be preserved (pre={pre_head_b})"
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_tail_a,
            "#926: tail_finish[A] must be preserved"
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], pre_tail_b,
            "#926: tail_finish[B] must be preserved"
        );

        // Items now Local. flow_fair=true stores items in
        // per-bucket VecDeques at `flow_bucket_items[bucket]`,
        // not in `queue.items`.
        let mut total_items = 0;
        for bucket in [bucket_a, bucket_b] {
            for item in queue.flow_bucket_items[bucket].iter() {
                assert!(
                    matches!(item, CoSPendingTxItem::Local(_)),
                    "demote should convert Prepared → Local"
                );
                total_items += 1;
            }
        }
        assert_eq!(total_items, 2);

        // The frontier-preservation assertions above are the
        // load-bearing test (Codex code review caught that an
        // earlier "Y does not jump ahead" assertion was
        // logically muddled — without the fix, the four
        // assert_eq calls already FAIL at the queue_vtime / head /
        // tail checks; demote_prepared without snapshot/restore
        // leaves queue_vtime=3000 and head_a=head_b=4500, all
        // mismatching the captured pre-state). The Y-anchor
        // behavior at this scenario is identical with-or-without
        // the fix (Y is small enough to anchor below A/B in
        // both cases) so it's not a useful gate.
    }

    #[test]
    fn demote_prepared_cos_queue_to_local_skips_non_exact_queue() {
        let area = MmapArea::new(4096).expect("mmap");
        unsafe { area.slice_mut_unchecked(64, 4) }
            .expect("frame")
            .copy_from_slice(&[1, 2, 3, 4]);

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET6 as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();
        assert!(!demote_prepared_cos_queue_to_local(
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            &mut root,
            Some(5),
        ));
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(_))
        ));
        assert!(free_tx_frames.is_empty());
        assert!(pending_fill_frames.is_empty());
    }

    #[test]
    fn drain_exact_local_fifo_items_to_scratch_keeps_queue_until_commit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1, 2, 3, 4],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![5, 6, 7, 8],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 256,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::from([64, 128, 192]);
        let mut scratch_local_tx = Vec::new();

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_local_tx.len(), 2);
        assert_eq!(free_tx_frames, VecDeque::from([192]));
        assert_eq!(area.slice(64, 4).expect("first frame"), &[1, 2, 3, 4]);
        assert_eq!(area.slice(128, 4).expect("second frame"), &[5, 6, 7, 8]);
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(_))
        ));
        assert!(matches!(
            root.queues[0].items.get(2),
            Some(CoSPendingTxItem::Prepared(_))
        ));
    }

    #[test]
    fn release_exact_local_scratch_frames_preserves_queue_after_failed_submit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![2],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let mut free_tx_frames = VecDeque::from([64, 128]);
        let mut scratch_local_tx = Vec::new();

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        release_exact_local_scratch_frames(&mut free_tx_frames, &mut scratch_local_tx);
        assert!(scratch_local_tx.is_empty());
        assert_eq!(free_tx_frames, VecDeque::from([64, 128]));
        assert_eq!(root.queues[0].items.len(), 2);
        match root.queues[0].items.pop_front().expect("first queued") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![1]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
        }
        match root.queues[0].items.pop_front().expect("second queued") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
        }
    }

    #[test]
    fn settle_exact_local_fifo_submission_pops_only_committed_prefix() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![2],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![3],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let mut free_tx_frames = VecDeque::new();
        let mut scratch_local_tx = vec![
            ExactLocalScratchTxRequest { offset: 64, len: 1 },
            ExactLocalScratchTxRequest {
                offset: 128,
                len: 1,
            },
            ExactLocalScratchTxRequest {
                offset: 192,
                len: 1,
            },
        ];

        let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_tx_frames,
            &mut scratch_local_tx,
            1,
        );

        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert!(scratch_local_tx.is_empty());
        assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
        assert_eq!(root.queues[0].items.len(), 2);
        match root.queues[0].items.pop_front().expect("first restored") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
        }
        match root.queues[0].items.pop_front().expect("second restored") {
            CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![3]),
            CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
        }
    }

    #[test]
    fn exact_local_fifo_boundary_survives_partial_commit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![1],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![2],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 256,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut free_tx_frames = VecDeque::from([64, 128, 192]);
        let mut scratch_local_tx = Vec::new();

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_local_tx.len(), 2);

        let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_tx_frames,
            &mut scratch_local_tx,
            1,
        );
        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
        ));

        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_tx_frames,
            &mut scratch_local_tx,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_local_tx.len(), 1);
        assert_eq!(scratch_local_tx[0].offset, 128);
        assert_eq!(free_tx_frames, VecDeque::from([192]));
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
        ));
    }

    #[test]
    fn drain_exact_prepared_items_to_scratch_recycles_dropped_prepared_frame() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: (tx_frame_capacity() + 1) as u32,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut scratch_prepared_tx = Vec::new();
        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );

        match build {
            ExactCoSScratchBuild::Drop { dropped_bytes, .. } => {
                assert_eq!(dropped_bytes, (tx_frame_capacity() + 1) as u64);
            }
            ExactCoSScratchBuild::Ready => panic!("oversized prepared frame must drop"),
        }
        assert!(scratch_prepared_tx.is_empty());
        assert!(free_tx_frames.is_empty());
        assert_eq!(pending_fill_frames, VecDeque::from([64]));
        assert!(root.queues[0].items.is_empty());
    }

    #[test]
    fn release_exact_prepared_scratch_preserves_queue_after_failed_submit() {
        let area = MmapArea::new(4096).expect("mmap");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 4,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let frame = unsafe { area.slice_mut_unchecked(64, 4) }.expect("frame");
        frame.copy_from_slice(&[1, 2, 3, 4]);
        let mut scratch_prepared_tx = Vec::new();
        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        release_exact_prepared_scratch(&mut scratch_prepared_tx);
        assert!(scratch_prepared_tx.is_empty());
        assert_eq!(root.queues[0].items.len(), 1);
        match root.queues[0].items.front().expect("queued prepared") {
            CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 64),
            CoSPendingTxItem::Local(_) => panic!("unexpected local item"),
        }
    }

    #[test]
    fn settle_exact_prepared_fifo_submission_pops_only_committed_prefix() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1,
                recycle: PreparedTxRecycle::FillOnSlot(7),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 192,
                len: 1,
                recycle: PreparedTxRecycle::FillOnSlot(9),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        let mut scratch_prepared_tx = vec![
            ExactPreparedScratchTxRequest { offset: 64, len: 1 },
            ExactPreparedScratchTxRequest {
                offset: 128,
                len: 1,
            },
            ExactPreparedScratchTxRequest {
                offset: 192,
                len: 1,
            },
        ];
        let mut in_flight_prepared_recycles = FastMap::default();

        let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
            Some(&mut root.queues[0]),
            &mut scratch_prepared_tx,
            &mut in_flight_prepared_recycles,
            1,
        );

        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert!(scratch_prepared_tx.is_empty());
        assert_eq!(
            in_flight_prepared_recycles.get(&64),
            Some(&PreparedTxRecycle::FillOnSlot(7))
        );
        assert!(!in_flight_prepared_recycles.contains_key(&128));
        assert!(!in_flight_prepared_recycles.contains_key(&192));
        assert_eq!(root.queues[0].items.len(), 2);
        match root.queues[0].items.pop_front().expect("first restored") {
            CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 128),
            CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
        }
        match root.queues[0].items.pop_front().expect("second restored") {
            CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 192),
            CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
        }
    }

    #[test]
    fn exact_prepared_fifo_boundary_survives_partial_commit() {
        let area = MmapArea::new(4096).expect("mmap");
        unsafe { area.slice_mut_unchecked(64, 1) }
            .expect("prepared frame 1")
            .copy_from_slice(&[1]);
        unsafe { area.slice_mut_unchecked(128, 1) }
            .expect("prepared frame 2")
            .copy_from_slice(&[2]);

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 64,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset: 128,
                len: 1,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));
        root.queues[0]
            .items
            .push_back(CoSPendingTxItem::Local(TxRequest {
                bytes: vec![9],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 80,
                cos_queue_id: Some(5),
                dscp_rewrite: None,
            }));

        let mut scratch_prepared_tx = Vec::new();
        let mut free_tx_frames = VecDeque::new();
        let mut pending_fill_frames = VecDeque::new();

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_prepared_tx.len(), 2);

        let mut in_flight_prepared_recycles = FastMap::default();
        let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
            Some(&mut root.queues[0]),
            &mut scratch_prepared_tx,
            &mut in_flight_prepared_recycles,
            1,
        );
        assert_eq!(sent_packets, 1);
        assert_eq!(sent_bytes, 1);
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
        ));

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_prepared_tx.len(), 1);
        assert_eq!(scratch_prepared_tx[0].offset, 128);
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
        ));
    }

    #[test]
    fn resolve_cos_queue_id_prefers_egress_output_filter_forwarding_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    filter_output_v4: "wan-classify".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![
                FirewallFilterSnapshot {
                    name: "cos-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "best-effort".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "wan-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "expedited-forwarding".into(),
                        ..Default::default()
                    }],
                },
            ],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(1));
    }

    #[test]
    fn resolve_cached_cos_tx_selection_prefers_egress_output_filter_and_keeps_counter() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    filter_output_v4: "wan-classify".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![
                FirewallFilterSnapshot {
                    name: "cos-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "best-effort".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "wan-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        count: "wan-hits".into(),
                        forwarding_class: "expedited-forwarding".into(),
                        ..Default::default()
                    }],
                },
            ],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let cached = resolve_cached_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(cached.queue_id, Some(1));
        assert_eq!(cached.dscp_rewrite, None);
        assert!(cached.filter_counter.is_some());
    }

    #[test]
    fn resolve_cos_queue_id_uses_ingress_input_filter_when_no_output_filter_exists() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(1));
    }

    #[test]
    fn resolve_cached_cos_tx_selection_uses_ingress_input_filter_when_no_output_exists() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "lan-hits".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let cached = resolve_cached_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(cached.queue_id, Some(1));
        assert_eq!(cached.dscp_rewrite, None);
        assert!(cached.filter_counter.is_some());
    }

    #[test]
    fn resolve_cached_cos_tx_selection_keeps_counter_only_output_filter_hits() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-count".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "wan-count".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "count-only".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "wan-hits".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let cached = resolve_cached_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(cached.queue_id, Some(0));
        assert_eq!(cached.dscp_rewrite, None);
        assert!(cached.filter_counter.is_some());
    }

    #[test]
    fn resolve_cos_tx_selection_counts_counter_only_output_filter_hits() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-count".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "wan-count".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "count-only".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "wan-hits".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                pkt_len: 1514,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(0));
        assert_eq!(selection.dscp_rewrite, None);

        let filter = forwarding
            .filter_state
            .filters
            .get("inet:wan-count")
            .expect("inet output filter");
        let term = filter.terms.first().expect("first term");
        assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
        assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1514);
    }

    #[test]
    fn resolve_cos_tx_selection_uses_ingress_filter_dscp_rewrite_when_no_output_filter_exists() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    dscp_rewrite: Some(0),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 46,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(1));
        assert_eq!(selection.dscp_rewrite, Some(0));
    }

    #[test]
    fn resolve_cos_tx_selection_skips_ingress_filter_without_tx_selection_effects() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "sfmix-pbr".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![FirewallFilterSnapshot {
                name: "sfmix-pbr".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "sfmix-route".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "tx-duplicate".into(),
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                pkt_len: 1500,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(7));
        assert_eq!(selection.dscp_rewrite, None);
        let filter = forwarding
            .filter_state
            .filters
            .get("inet:sfmix-pbr")
            .expect("filter");
        assert_eq!(
            filter.terms[0]
                .counter
                .packets
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn resolve_cos_tx_selection_returns_none_when_no_cos_or_tx_selection_filters_exist() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "sfmix-pbr".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "sfmix-pbr".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "sfmix-route".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "tx-duplicate".into(),
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                pkt_len: 1500,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, None);
        assert_eq!(selection.dscp_rewrite, None);
        let filter = forwarding
            .filter_state
            .filters
            .get("inet:sfmix-pbr")
            .expect("filter");
        assert_eq!(
            filter.terms[0]
                .counter
                .packets
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn resolve_cos_queue_id_falls_back_to_default_queue_without_filter_match() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                ..Default::default()
            },
            None,
        );

        assert_eq!(queue_id, Some(7));
    }

    #[test]
    fn resolve_cos_queue_id_uses_dscp_classifier_when_filters_do_not_set_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                cos_dscp_classifier: "wan-classifier".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "voice".into(),
                        queue: 5,
                    },
                ],
                dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                    name: "wan-classifier".into(),
                    entries: vec![CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![46],
                    }],
                }],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "voice".into(),
                            scheduler: "voice-sched".into(),
                        },
                    ],
                }],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "voice-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 46,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(5));
    }

    #[test]
    fn resolve_cos_queue_id_uses_ieee8021_classifier_when_filters_do_not_set_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                cos_ieee8021_classifier: "wan-pcp".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "voice".into(),
                        queue: 5,
                    },
                ],
                ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                    name: "wan-pcp".into(),
                    entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        code_points: vec![5],
                    }],
                }],
                dscp_rewrite_rules: vec![],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "voice".into(),
                            scheduler: "voice-sched".into(),
                        },
                    ],
                }],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "voice-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 64_000,
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_vlan_id: 100,
                ingress_pcp: 5,
                ingress_vlan_present: 1,
                addr_family: libc::AF_INET as u8,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(5));
    }

    #[test]
    fn resolve_cos_queue_id_does_not_use_ieee8021_classifier_for_untagged_packets() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                cos_ieee8021_classifier: "wan-pcp".into(),
                ..Default::default()
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 0,
                    },
                    CoSForwardingClassSnapshot {
                        name: "bulk".into(),
                        queue: 3,
                    },
                ],
                ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                    name: "wan-pcp".into(),
                    entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        loss_priority: "low".into(),
                        code_points: vec![0],
                    }],
                }],
                dscp_rewrite_rules: vec![],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "bulk".into(),
                            scheduler: "bulk-sched".into(),
                        },
                    ],
                }],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 4_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "bulk-sched".into(),
                        transmit_rate_bytes: 6_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 999,
                ingress_pcp: 0,
                ingress_vlan_present: 0,
                addr_family: libc::AF_INET as u8,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(queue_id, Some(0));
    }

    // Note on invariant change (replaces the pre-a15a6120 "defaults to iface default" behavior):
    // The original shape of this test asserted that an output filter with NO tx-side effect (no
    // forwarding_class, no counter) would still shadow the ingress input filter's classification
    // and leave egress at the interface default queue.  Commit a15a6120 changed the gating so the
    // output filter is skipped entirely when it has neither forwarding_class, dscp_rewrite, nor
    // counter terms — matching Junos semantics, where a classify-only output filter that does not
    // classify does not clobber upstream classification.  The new invariant asserted below: when
    // the output filter has no tx-side effect, ingress input-filter classification is preserved.
    #[test]
    fn resolve_cos_queue_id_preserves_ingress_classification_when_output_filter_has_no_forwarding_class()
     {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".into(),
                    ifindex: 101,
                    parent_ifindex: 5,
                    vlan_id: 0,
                    hardware_addr: "02:bf:72:00:61:01".into(),
                    filter_input_v4: "cos-classify".into(),
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.0".into(),
                    ifindex: 202,
                    hardware_addr: "02:bf:72:00:80:08".into(),
                    filter_output_v4: "wan-classify".into(),
                    cos_shaping_rate_bytes_per_sec: 10_000_000,
                    cos_shaping_burst_bytes: 256_000,
                    cos_scheduler_map: "wan-map".into(),
                    ..Default::default()
                },
            ],
            filters: vec![
                FirewallFilterSnapshot {
                    name: "cos-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "voice".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        forwarding_class: "expedited-forwarding".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "wan-classify".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "allow".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        ..Default::default()
                    }],
                },
            ],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![
                    CoSForwardingClassSnapshot {
                        name: "best-effort".into(),
                        queue: 7,
                    },
                    CoSForwardingClassSnapshot {
                        name: "expedited-forwarding".into(),
                        queue: 1,
                    },
                ],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![
                    CoSSchedulerSnapshot {
                        name: "be-sched".into(),
                        transmit_rate_bytes: 10_000_000,
                        transmit_rate_exact: false,
                        priority: "low".into(),
                        buffer_size_bytes: 128_000,
                    },
                    CoSSchedulerSnapshot {
                        name: "ef-sched".into(),
                        transmit_rate_bytes: 10_000_000,
                        transmit_rate_exact: false,
                        priority: "strict-high".into(),
                        buffer_size_bytes: 128_000,
                    },
                ],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "best-effort".into(),
                            scheduler: "be-sched".into(),
                        },
                        CoSSchedulerMapEntrySnapshot {
                            forwarding_class: "expedited-forwarding".into(),
                            scheduler: "ef-sched".into(),
                        },
                    ],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let queue_id = resolve_cos_queue_id(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        // cos-classify on reth1.0 maps expedited-forwarding -> queue 1.  The output filter
        // wan-classify on reth0.0 has no tx-side effect (no forwarding_class, no dscp_rewrite,
        // no counter), so post-a15a6120 it is bypassed and the ingress classification is
        // preserved.  Pre-a15a6120 this was expected to fall through to the iface default queue
        // (best-effort = 7); that contract no longer holds and is captured by this test.
        assert_eq!(queue_id, Some(1));
    }

    #[test]
    fn resolve_cos_tx_selection_preserves_output_filter_dscp_rewrite_without_forwarding_class() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-rewrite".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            }],
            filters: vec![FirewallFilterSnapshot {
                name: "wan-rewrite".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "rewrite".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    dscp_rewrite: Some(46),
                    ..Default::default()
                }],
            }],
            class_of_service: Some(ClassOfServiceSnapshot {
                forwarding_classes: vec![CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                }],
                dscp_classifiers: vec![],
                ieee8021_classifiers: vec![],
                dscp_rewrite_rules: vec![],
                schedulers: vec![CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                }],
                scheduler_maps: vec![CoSSchedulerMapSnapshot {
                    name: "wan-map".into(),
                    entries: vec![CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    }],
                }],
            }),
            ..Default::default()
        };

        let forwarding = build_forwarding_state(&snapshot);
        let selection = resolve_cos_tx_selection(
            &forwarding,
            202,
            UserspaceDpMeta {
                ingress_ifindex: 5,
                ingress_vlan_id: 0,
                addr_family: libc::AF_INET as u8,
                dscp: 0,
                ..Default::default()
            },
            Some(&SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 443,
            }),
        );

        assert_eq!(selection.queue_id, Some(7));
        assert_eq!(selection.dscp_rewrite, Some(46));
    }

    #[test]
    fn assign_local_dscp_rewrite_preserves_existing_filter_rewrite() {
        let mut items = VecDeque::from([
            TxRequest {
                bytes: vec![0; 64],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 42,
                cos_queue_id: Some(0),
                dscp_rewrite: None,
            },
            TxRequest {
                bytes: vec![0; 64],
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: None,
                egress_ifindex: 42,
                cos_queue_id: Some(0),
                dscp_rewrite: Some(0),
            },
        ]);

        assign_local_dscp_rewrite(&mut items, Some(46));

        assert_eq!(items[0].dscp_rewrite, Some(46));
        assert_eq!(items[1].dscp_rewrite, Some(0));
    }








    #[test]
    fn flow_fair_exact_queue_limits_dominant_flow_share() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        let flow_a = test_session_key(1111, 5201);
        let flow_b = test_session_key(1112, 5201);
        let bucket_a = cos_flow_bucket_index(queue.flow_hash_seed, Some(&flow_a));
        let bucket_b = cos_flow_bucket_index(queue.flow_hash_seed, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b);

        assert_eq!(
            cos_queue_flow_share_limit(queue, buffer_limit, bucket_a),
            buffer_limit
        );
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 64 * 1024);
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 32 * 1024);
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 96 * 1024);

        account_cos_queue_flow_enqueue(queue, Some(&flow_b), 16 * 1024);
        assert_eq!(queue.active_flow_buckets, 2);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 16 * 1024);

        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, bucket_a);
        assert_eq!(share_cap, buffer_limit / 2);
        assert!(queue.flow_bucket_bytes[bucket_a].saturating_add(16 * 1024) > share_cap);

        account_cos_queue_flow_dequeue(queue, Some(&flow_b), 16 * 1024);
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 0);
    }

    #[test]
    fn cos_flow_aware_buffer_limit_scales_with_prospective_active_flow_count() {
        // #707 + #716 review: at the 1 Gbps/16-flow workload a fixed
        // 125 KB buffer divided across 16 flows gives each flow a 7.8
        // KB share, below the TCP fast-retransmit floor of 16 MSS =
        // 24 KB. The flow-aware buffer limit grows the aggregate cap
        // so the per-flow floor can be honoured. "Prospective" count
        // means the same denominator the per-flow clamp uses: current
        // `active_flow_buckets + (target bucket empty ? 1 : 0)`, so
        // the two gates never disagree about whether a new flow's
        // first packet has room.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB — the admission-boundary math must
                // use the same units as the live system.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Base floor wins when prospective flow count × min share is
        // small. `flow_bucket = 0` is empty → prospective_active += 1.
        queue.active_flow_buckets = 0;
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "zero active (+1 prospective) flows must stay at the operator-configured base"
        );
        queue.active_flow_buckets = 2;
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "3 prospective × 24 KB = 72 KB stays below the 125 KB configured base, so base wins"
        );

        // Flow-aware floor wins past the break-even point. Now mark 16
        // buckets populated so prospective = 16 (target bucket already
        // non-empty).
        queue.active_flow_buckets = 16;
        for bucket in 0..16 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            16 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "16 × 24 KB = 384 KB exceeds the 125 KB base and becomes the cap"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_matches_share_limit_at_new_flow_boundary() {
        // #716 review: the aggregate cap and the per-flow clamp must
        // use the SAME denominator. Before the review fix the
        // aggregate cap used the current `active_flow_buckets` while
        // the per-flow clamp used `active + (target bucket empty ? 1 :
        // 0)`, so the first packet of a newly arriving flow could
        // pass the per-flow gate and fail the aggregate one right at
        // the boundary. This test drives the queue to the *actual*
        // admission boundary so the assertion exercises the old
        // failure mode rather than trivial 0-bytes arithmetic.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB — the admission-boundary math must
                // use the same units as the live system.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // 15 active flows filled to 24 KB each. Target bucket empty →
        // prospective_active = 16. Both caps must key off 16, not 15.
        queue.active_flow_buckets = 15;
        for bucket in 0..15 {
            queue.flow_bucket_bytes[bucket] = COS_FLOW_FAIR_MIN_SHARE_BYTES;
        }
        // Aggregate queued equals the pre-fix aggregate cap exactly —
        // this is the value that made the bug observable: under the
        // old formula the aggregate cap was `15 × min-share` and the
        // check `queued + 1500 > cap` tripped; under the fix the cap
        // is `16 × min-share` and the packet fits.
        queue.queued_bytes = 15 * COS_FLOW_FAIR_MIN_SHARE_BYTES;

        let new_flow_bucket = 100;
        assert_eq!(queue.flow_bucket_bytes[new_flow_bucket], 0);

        let buffer_limit = cos_flow_aware_buffer_limit(queue, new_flow_bucket);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, new_flow_bucket);

        // Fixed caps: aggregate = 16 × min-share, per-flow = min-share.
        assert_eq!(buffer_limit, 16 * COS_FLOW_FAIR_MIN_SHARE_BYTES);
        assert_eq!(share_cap, COS_FLOW_FAIR_MIN_SHARE_BYTES);

        // Per-flow gate: new bucket is empty, so +1500 is well below cap.
        assert!(
            queue.flow_bucket_bytes[new_flow_bucket].saturating_add(1500) <= share_cap,
            "per-flow share must admit the new flow's first packet"
        );

        // Aggregate gate: queued is at the pre-fix cap. Fix makes
        // +1500 still fit; without the fix this was a drop.
        assert!(
            queue.queued_bytes.saturating_add(1500) <= buffer_limit,
            "aggregate cap must admit the new flow's first packet at the near-cap boundary \
             (queued_bytes = {}, +1500 must fit within buffer_limit = {})",
            queue.queued_bytes,
            buffer_limit,
        );

        // Counter-factual: prove the pre-fix formula (non-prospective)
        // would have rejected the same packet. Guards against a future
        // refactor silently reverting to `active_flow_buckets` without
        // the `+1` bump.
        let non_prospective_cap = u64::from(queue.active_flow_buckets)
            .max(1)
            .saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES)
            .max(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
        assert!(
            queue.queued_bytes.saturating_add(1500) > non_prospective_cap,
            "without prospective-active, the same queued state would reject the new flow \
             (queued_bytes + 1500 = {}, non-prospective cap = {})",
            queue.queued_bytes + 1500,
            non_prospective_cap,
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_respects_non_flow_fair_queues() {
        // Pure rate-limited (non-flow-fair) queues must keep the
        // operator's configured buffer. The flow-aware scaling only
        // applies when SFQ-style per-flow accounting is active.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = false;
        queue.active_flow_buckets = 64; // should be ignored

        // `flow_bucket` argument is irrelevant when flow_fair=false; use 0.
        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "flow_fair=false must bypass the flow-count multiplier"
        );
    }

    /// #914: shared_exact rate-aware cap — verify the formula
    /// `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`
    /// scales correctly with `transmit_rate_bytes` and active flows
    /// rather than collapsing to the rate-unaware MIN floor.
    #[test]
    fn flow_share_limit_shared_exact_scales_with_rate() {
        // 10 Gbps shared_exact queue at N=128 → per_flow_rate = 9.77 MB/s,
        // bdp_floor = 9.77 MB/s × 10 ms = 97.6 KB. Buffer_limit ≫ that,
        // so the cap should follow bdp_floor.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.active_flow_buckets = 128;
        for bucket in 0..128 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // bdp_floor = (1.25 GB/s / 128) × 10 ms = 97_656 bytes (rounded).
        let expected_bdp = bdp_floor_bytes(queue.transmit_rate_bytes, 128);
        assert_eq!(
            share, expected_bdp,
            "shared_exact cap should follow bdp_floor at N=128 (cap={share}, bdp={expected_bdp})"
        );
        assert!(
            share > COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "rate-aware cap ({share}) must exceed the rate-unaware MIN floor ({COS_FLOW_FAIR_MIN_SHARE_BYTES})"
        );
        assert!(
            share <= buffer_limit,
            "cap ({share}) must not exceed buffer_limit ({buffer_limit})"
        );
    }

    /// #914: at low N, `bdp_floor` exceeds `buffer_limit`; the formula
    /// must clamp to buffer_limit and degenerate to today's behavior
    /// rather than capping below per-flow BDP (which would collapse
    /// TCP cwnd).
    #[test]
    fn flow_share_limit_shared_exact_caps_at_aggregate_for_single_flow() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.active_flow_buckets = 1;
        queue.flow_bucket_bytes[0] = 1_000;
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // At N=1 the bdp_floor (~12.5 MB) is way above buffer_limit,
        // so we clamp to buffer_limit.
        assert_eq!(
            share, buffer_limit,
            "single-flow shared_exact cap must clamp to buffer_limit (no regression vs current)"
        );
    }

    /// #914 (Codex review): at moderate N where `bdp_floor` exceeds
    /// `buffer_limit` (the degeneration regime per plan §3.2), the
    /// cap must clamp to `buffer_limit` rather than below it. Pins
    /// the low-N behavior so a future regression where the formula
    /// caps below buffer_limit fails this test rather than slipping
    /// through.
    #[test]
    fn flow_share_limit_shared_exact_clamps_to_buffer_at_low_n() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        // N = 8: per-flow rate = 156 MB/s, bdp_floor = 1.56 MB,
        // far above buffer_limit (which at default base = 96 KB and
        // 8 × MIN_SHARE = 192 KB clamps to ~192 KB).
        queue.active_flow_buckets = 8;
        for bucket in 0..8 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let bdp = bdp_floor_bytes(queue.transmit_rate_bytes, 8);
        assert!(
            bdp > buffer_limit,
            "test premise: bdp_floor ({bdp}) must exceed buffer_limit ({buffer_limit}) at N=8"
        );
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        assert_eq!(
            share, buffer_limit,
            "low-N shared_exact must clamp to buffer_limit, not below"
        );
    }

    /// #914: at high N where bdp_floor < buffer_limit, the cap is
    /// active and protects mice from elephant starvation (the actual
    /// design goal).
    #[test]
    fn flow_share_limit_shared_exact_protects_against_dominant_flow() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 0,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.active_flow_buckets = 128;
        for bucket in 0..128 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // The cap must be strictly less than buffer_limit at N=128 —
        // i.e. one flow cannot fill the entire queue.
        assert!(
            share < buffer_limit,
            "rate-aware cap ({share}) must split the buffer at N=128 (buffer_limit={buffer_limit})"
        );
        // And strictly greater than buffer_limit / N (the rate-unaware
        // arithmetic share) because of the bdp_floor and 2× headroom.
        assert!(
            share >= buffer_limit / 128,
            "cap ({share}) must be at least buffer_limit/N ({})",
            buffer_limit / 128
        );
    }

    /// #914: owner-local-exact queues (NOT shared_exact) keep the
    /// legacy `buffer_limit / prospective_active` arithmetic share.
    /// Verify the new shared_exact branch does not affect them.
    #[test]
    fn flow_share_limit_owner_local_exact_unchanged() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = false; // owner-local-exact
        queue.active_flow_buckets = 12;
        for bucket in 0..12 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        // Legacy formula: buffer_limit / prospective_active, clamped to
        // [MIN_SHARE, buffer_limit]. With 12 buckets and the prospective
        // +1 for empty target bucket, the divisor is 13 (or 12 if the
        // target bucket is non-empty).
        let prospective = cos_queue_prospective_active_flows(queue, 0);
        let expected = buffer_limit
            .div_ceil(prospective)
            .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit);
        assert_eq!(
            share, expected,
            "owner-local-exact cap must use the legacy aggregate/N formula"
        );
    }

    #[test]
    fn cos_queue_flow_share_limit_never_drops_below_fast_retransmit_floor() {
        // At 16 flows with a 125 KB buffer, the naive arithmetic share
        // is 7.8 KB — a single packet drop yields < 3 dupacks, forcing
        // RTO. The clamp to `COS_FLOW_FAIR_MIN_SHARE_BYTES` must hold
        // the per-flow cap at 24 KB no matter the denominator.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB — the admission-boundary math must
                // use the same units as the live system.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Simulate 16 distinct populated flow buckets.
        queue.active_flow_buckets = 16;
        for bucket in 0..16 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }

        let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
        assert_eq!(
            buffer_limit,
            16 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "flow-aware cap must expand to accommodate 16 × min-share"
        );

        let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
        assert!(
            share >= COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "per-flow cap ({share}) must stay ≥ {COS_FLOW_FAIR_MIN_SHARE_BYTES} (16 MTU-sized packets)"
        );
        assert_eq!(
            share, COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "with buffer_limit == active × min-share, per-flow cap equals the floor"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_clamps_high_flow_count_to_max_delay() {
        // #717: at the architectural maximum of 1024 active buckets
        // the pre-clamp flow-aware expansion reaches
        // 1024 × COS_FLOW_FAIR_MIN_SHARE_BYTES ≈ 24 MB. On a 1 Gbps
        // queue that is ~190 ms of queue residence — far outside the
        // scheduler's predictable regime. The latency-envelope clamp
        // caps the aggregate at
        // `transmit_rate_bytes × COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS / 1e9`
        // so the tail stays bounded.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                // 1 Gbps → 125_000_000 bytes/s (decimal, matches
                // operator `transmit-rate 1g` semantics).
                transmit_rate_bytes: 125_000_000,
                exact: true,
                surplus_weight: 1,
                // Decimal KB to match the operator `buffer-size 125k`
                // config, not KiB.
                buffer_bytes: 125_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Drive to the architectural maximum: 1024 populated buckets.
        queue.active_flow_buckets = COS_FLOW_FAIR_BUCKETS as u16;
        for bucket in 0..COS_FLOW_FAIR_BUCKETS {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }

        let cap = cos_flow_aware_buffer_limit(queue, 0);

        // Expected delay cap: 125_000_000 B/s × 5 ms = 625_000 B.
        let expected_delay_cap = 625_000u64;
        assert_eq!(
            cap, expected_delay_cap,
            "flow-aware cap must be clamped to the 5 ms delay envelope, not the ~24 MB \
             unclamped expansion"
        );

        // Counter-factual: prove the pre-clamp formula would have
        // returned 24 MB. Guards against a future refactor silently
        // deleting the clamp.
        let unclamped = u64::from(queue.active_flow_buckets)
            .max(1)
            .saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES)
            .max(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
        assert_eq!(
            unclamped,
            COS_FLOW_FAIR_BUCKETS as u64 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
            "unclamped formula baseline: 1024 × 24 KB = ~24 MB"
        );
        assert!(
            cap < unclamped,
            "clamp must shrink the flow-aware expansion (cap = {cap}, unclamped = {unclamped})"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_honours_operator_base_above_delay_cap() {
        // #717: the clamp is `.min(delay_cap.max(base))` — if the
        // operator explicitly configured a buffer larger than
        // `delay_cap`, we honour their intent. The clamp must never
        // shrink below the operator's `buffer-size`. On a 1 Gbps queue
        // the delay cap is 625_000 B; a 100 MiB operator base is well
        // above that.
        let operator_base: u64 = 100 * 1024 * 1024;
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 125_000_000,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: operator_base,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;

        // Use a middling flow count so prospective × min-share sits
        // between delay_cap and operator_base. That exercises the
        // branch where delay_cap < base < flow-aware expansion.
        queue.active_flow_buckets = 16;
        for bucket in 0..16 {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }

        let cap = cos_flow_aware_buffer_limit(queue, 0);
        assert_eq!(
            cap, operator_base,
            "operator base ({operator_base}) must survive the clamp even when it exceeds \
             delay_cap (625_000) — the clamp is .min(delay_cap.max(base))"
        );

        // Counter-factual: a naive `.min(delay_cap)` (without
        // `.max(base)`) would have clamped the operator's explicit
        // 100 MiB down to 625 KB. Pin that this is NOT what we do.
        let naive_delay_cap = 625_000u64;
        assert!(
            cap > naive_delay_cap,
            "naive delay-only clamp would shrink operator intent to {naive_delay_cap}; the \
             `.max(base)` guard must preserve {operator_base}"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_preserves_non_flow_fair_path_after_clamp() {
        // #717: the latency clamp must not leak into the non-flow-fair
        // path. Pure rate-limited queues bypass both the floor and the
        // clamp and return the raw `buffer_bytes.max(COS_MIN_BURST_BYTES)`.
        // This is the companion to
        // `cos_flow_aware_buffer_limit_respects_non_flow_fair_queues`
        // but exercises the config shape where the delay cap *would*
        // have been tighter than the operator base, to catch a future
        // refactor that moves the clamp above the `flow_fair` early
        // return.
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                // 1 Gbps → delay_cap = 625 KB.
                transmit_rate_bytes: 125_000_000,
                exact: true,
                surplus_weight: 1,
                // Operator configured 10 MB — well above delay_cap.
                // If the clamp leaks into this path, the returned cap
                // would be 625 KB, not 10 MB.
                buffer_bytes: 10 * 1_000_000,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = false;
        queue.active_flow_buckets = 64; // should be ignored

        assert_eq!(
            cos_flow_aware_buffer_limit(queue, 0),
            queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
            "flow_fair=false must bypass both the flow-aware floor and the latency clamp"
        );
    }

    #[test]
    fn cos_flow_aware_buffer_limit_delay_cap_scales_linearly_with_rate() {
        // #717: pin the delay-cap formula's linearity. Same active
        // flow count and same COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS, but
        // 10 Gbps vs 1 Gbps — the delay-cap-driven return must be 10×
        // larger. Catches future refactors that accidentally clamp
        // the rate (e.g. saturating at a hardcoded byte count) or
        // swap the product for a divide.
        fn run_at_rate(rate_bytes: u64) -> u64 {
            let mut root = test_cos_runtime_with_queues(
                25_000_000_000 / 8,
                vec![CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: rate_bytes,
                    exact: true,
                    surplus_weight: 1,
                    // Small operator base so the delay cap dominates.
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                }],
            );
            let queue = &mut root.queues[0];
            queue.flow_fair = true;
            // Populate all buckets so prospective_active × min-share
            // blows past the delay cap at both rates — the clamp is
            // what's being measured.
            queue.active_flow_buckets = COS_FLOW_FAIR_BUCKETS as u16;
            for bucket in 0..COS_FLOW_FAIR_BUCKETS {
                queue.flow_bucket_bytes[bucket] = 1_000;
            }
            cos_flow_aware_buffer_limit(queue, 0)
        }

        // 1 Gbps decimal: 125_000_000 B/s × 5 ms = 625_000 B.
        let cap_1g = run_at_rate(125_000_000);
        // 10 Gbps decimal: 1_250_000_000 B/s × 5 ms = 6_250_000 B.
        let cap_10g = run_at_rate(1_250_000_000);

        assert_eq!(cap_1g, 625_000);
        assert_eq!(cap_10g, 6_250_000);
        assert_eq!(
            cap_10g,
            cap_1g * 10,
            "delay cap must scale linearly with transmit_rate_bytes \
             (1 Gbps → {cap_1g}, 10 Gbps → {cap_10g})"
        );
    }

    #[test]
    fn cos_queue_push_and_pop_track_flow_bucket_bytes() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let req_a = TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(test_session_key(1111, 5201)),
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        let req_b = TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(test_session_key(1112, 5201)),
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        let bucket_a = cos_flow_bucket_index(queue.flow_hash_seed, req_a.flow_key.as_ref());
        let bucket_b = cos_flow_bucket_index(queue.flow_hash_seed, req_b.flow_key.as_ref());
        assert_ne!(bucket_a, bucket_b);

        cos_queue_push_back(queue, CoSPendingTxItem::Local(req_a));
        cos_queue_push_back(queue, CoSPendingTxItem::Local(req_b));
        assert_eq!(queue.active_flow_buckets, 2);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 1500);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 1500);

        let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) else {
            panic!("expected first queued local request");
        };
        assert_eq!(req.flow_key.as_ref().map(|flow| flow.src_port), Some(1111));
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 1500);
    }

    /// #785 Phase 3 — head-keyed MQFQ ordering with equal-byte
    /// packets. Three flows, equal 1500-byte packets, 1111 has
    /// two packets, 1112 and 1113 have one each.
    ///
    /// Post-enqueue HEAD finish times (the selection key):
    ///   bucket(1111) head=1500 tail=3000 (head unchanged when
    ///     second packet arrives at tail of active bucket)
    ///   bucket(1112) head=tail=1500
    ///   bucket(1113) head=tail=1500
    ///
    /// All heads tie at 1500. Ties broken by ring insertion
    /// order (1111 enqueued first, wins). After pop of 1111
    /// pkt1, bucket 1111 is still active; head advances to
    /// `old_head + bytes(new head packet) = 1500 + 1500 = 3000`.
    /// Now 1112 and 1113 lead at head=1500, so they drain before
    /// 1111 pkt2.
    ///
    /// For equal-byte packets, MQFQ produces the SAME service
    /// order as DRR — they're byte-rate equivalent when all
    /// packets are the same size. The MQFQ divergence from DRR
    /// shows up on mixed-size packets (see
    /// `flow_fair_queue_mqfq_bytes_rate_fair_on_mixed_packet_sizes`).
    ///
    /// This test's value is pinning the head-finish mechanism's
    /// internal correctness: head advances on non-drain pop,
    /// tail advances on enqueue, tie-break = insertion order.
    /// Codex HIGH on the first revision keyed selection off TAIL
    /// finish, which broke this equivalence and produced an
    /// A,A,B,B burst pattern.
    #[test]
    fn flow_fair_queue_pops_in_virtual_finish_order_local() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1112, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1113, 1500));

        let mut order = Vec::new();
        while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
            order.push(req.flow_key.expect("flow key").src_port);
        }

        // Equal-byte packets: MQFQ order matches DRR round-robin.
        // After popping 1111 pkt1, bucket 1111's head advances to
        // 3000; 1112 and 1113 still sit at 1500 and drain next.
        assert_eq!(
            order,
            vec![1111, 1112, 1113, 1111],
            "#785 Phase 3: with equal-byte packets the head-keyed \
             MQFQ order matches DRR round-robin — both are byte-\
             rate fair on uniform packet sizes. Regression here = \
             MQFQ ordering is broken (e.g. TAIL-keyed selection \
             produces the A,A,B,B burst [1111, 1111, 1112, 1113]).",
        );
        assert_eq!(queue.active_flow_buckets, 0);
        assert!(queue.flow_rr_buckets.is_empty());
        // #913 — MQFQ served-finish semantics: vtime tracks the
        // finish time of the last served packet, not the
        // aggregate bytes drained. With pop order
        // [1111, 1112, 1113, 1111] each picking a bucket whose
        // head_finish=1500 (and the last pop seeing head_finish=
        // 3000 after head-advance), `max(0,1500,1500,1500,3000)
        // = 3000`. Pre-#913 (aggregate-bytes) would have given
        // Σbytes = 6000.
        assert_eq!(
            queue.queue_vtime, 3000,
            "vtime tracks last served packet's finish-time \
             (MQFQ served-finish), not aggregate bytes drained \
             (pre-#913 SFQ V(t))"
        );
    }

    /// #785 Phase 3 — MQFQ byte-rate fairness on MIXED packet sizes.
    /// This is where MQFQ actually diverges from DRR.
    ///
    /// Flow 1111: one 3000-byte packet (e.g. GSO-coalesced).
    /// Flow 1112: one 1500-byte packet.
    /// Flow 1113: one 1500-byte packet.
    ///
    /// DRR (packet-count fair) order: [1111, 1112, 1113] — one
    /// packet per round. Flow 1111 gets 3000 bytes drained while
    /// flows 1112/1113 get only 1500 each → NOT byte-rate fair.
    ///
    /// MQFQ (byte-rate fair) order: [1112, 1113, 1111] — 1111's
    /// finish is 3000 (byte count) while 1112/1113 sit at 1500,
    /// so 1111 drains LAST. Over 6000 bytes of drain, every flow
    /// gets exactly 1/3 = 2000 bytes of virtual time budget, not
    /// 1/3 of the packet count.
    ///
    /// This is the property that closes the #785 CoV gap under TCP
    /// pacing: a flow with smaller cwnd sends fewer/smaller packets
    /// per RTT; DRR lets the busier flow sweep its polls, while
    /// MQFQ reserves drain slots proportional to byte rate.
    #[test]
    fn flow_fair_queue_mqfq_bytes_rate_fair_on_mixed_packet_sizes() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        cos_queue_push_back(queue, test_flow_cos_item(1111, 3000));
        cos_queue_push_back(queue, test_flow_cos_item(1112, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1113, 1500));

        // Head finishes: 1111=3000, 1112=1500, 1113=1500.
        // MQFQ pops smallest: 1112, then 1113 (tie-break on ring
        // insertion order), then 1111 last.
        let mut order = Vec::new();
        while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
            order.push(req.flow_key.expect("flow key").src_port);
        }

        assert_eq!(
            order,
            vec![1112, 1113, 1111],
            "#785 Phase 3: MQFQ MUST pop the larger-byte packet \
             LAST so all three flows get equal byte share over the \
             test window. DRR order [1111, 1112, 1113] is packet-\
             count fair but NOT byte-rate fair — flow 1111 gets 2× \
             the bytes of the others. Regression here collapses \
             MQFQ to DRR and re-opens the #785 CoV gap.",
        );
    }

    /// #785 Phase 3 Rust reviewer MEDIUM #3 — golden-vector table
    /// pinning MQFQ pop order across a small matrix of mixed-size
    /// inputs. Each row encodes (packet_sizes_per_flow,
    /// expected_mqfq_pop_order_by_src_port,
    /// reference_drr_pop_order_by_src_port).
    ///
    /// The DRR reference column is a static assertion of "what
    /// packet-count-fair DRR would produce" for the same input —
    /// kept as a golden vector rather than executed against a live
    /// DRR implementation (the old DRR path has been removed from
    /// this tree). The value of the table is regression-testing
    /// the tie-break rule in `cos_queue_min_finish_bucket` and
    /// locking the MQFQ-vs-DRR divergence into the test surface.
    ///
    /// Flow-to-bucket hashing depends on `flow_hash_seed=0` and
    /// the current `cos_flow_bucket_index` formula; if that hash
    /// changes, `insertion_port_order` below may need updating —
    /// test will fail with a clear "bucket collision" or
    /// "wrong port drains first" message.
    #[test]
    fn mqfq_golden_vector_pop_order_vs_drr() {
        struct GoldenRow {
            name: &'static str,
            // (src_port, bytes) tuples in push_back order.
            packets: &'static [(u16, usize)],
            // Expected MQFQ pop order (by src_port).
            mqfq_order: &'static [u16],
            // Reference DRR order (documented, not asserted against
            // live DRR).
            drr_order: &'static [u16],
        }

        const TABLE: &[GoldenRow] = &[
            // All packets same size: MQFQ and DRR produce identical
            // orderings (both are byte-rate fair on uniform sizes).
            GoldenRow {
                name: "equal-1500-two-flows",
                packets: &[(2001, 1500), (2001, 1500), (2002, 1500), (2002, 1500)],
                mqfq_order: &[2001, 2002, 2001, 2002],
                drr_order: &[2001, 2002, 2001, 2002],
            },
            // 2x size disparity, two flows. MQFQ pops the smaller
            // packet first (head=1500 vs 3000). After that pop,
            // flow B's second packet becomes its head at
            // head=1500+1500=3000 (active-bucket head advance on
            // non-drain pop). Flow A's head is still 3000. Tie on
            // head — insertion-order tie-break picks A (its bucket
            // was added to the ring first). Then B's last packet
            // drains. Order: B, A, B.
            //
            // DRR rotation would be A, B, B (larger inserted first;
            // DRR walks ring insertion order per round, not finish
            // time). Orders differ → this row proves MQFQ's
            // tie-break and non-drain-head-advance invariants
            // diverge from DRR on size-disparate traffic.
            GoldenRow {
                name: "mixed-3000-1500-two-flows",
                packets: &[(2101, 3000), (2102, 1500), (2102, 1500)],
                mqfq_order: &[2102, 2101, 2102],
                drr_order: &[2101, 2102, 2102],
            },
            // 3-way mixed: 2000 vs 1000 vs 500. MQFQ orders by
            // head finish (500, 1000, 2000) and then catches up.
            // DRR rotates insertion order (2201, 2202, 2203, ...).
            GoldenRow {
                name: "mixed-three-flows-progressive-sizes",
                packets: &[(2201, 2000), (2202, 1000), (2203, 500)],
                mqfq_order: &[2203, 2202, 2201],
                drr_order: &[2201, 2202, 2203],
            },
        ];

        for row in TABLE {
            let mut root = test_cos_runtime_with_queues(
                25_000_000_000 / 8,
                vec![CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                }],
            );
            let queue = &mut root.queues[0];
            queue.flow_fair = true;
            queue.flow_hash_seed = 0;

            for (src_port, bytes) in row.packets {
                cos_queue_push_back(queue, test_flow_cos_item(*src_port, *bytes));
            }

            let mut mqfq_order = Vec::with_capacity(row.packets.len());
            while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
                mqfq_order.push(req.flow_key.expect("flow key").src_port);
            }

            assert_eq!(
                mqfq_order, row.mqfq_order,
                "#785 Phase 3 golden vector '{}': MQFQ pop order \
                 mismatch. Expected {:?} (byte-rate fair), got \
                 {:?}. DRR reference would be {:?} — if the actual \
                 matches DRR, MQFQ has collapsed to packet-count \
                 fairness and the #785 CoV gap has reopened.",
                row.name, row.mqfq_order, mqfq_order, row.drr_order,
            );
        }

        // Separately assert that AT LEAST ONE row in the table
        // diverges MQFQ from DRR — otherwise the golden vector
        // isn't demonstrating the MQFQ advantage at all (equal-
        // size rows are expected to match; mixed-size rows are
        // the discriminating cases). A regression that collapses
        // MQFQ to DRR flips at least one mixed-size row's output
        // to the drr_order column, failing the assert_eq above.
        let any_divergent = TABLE.iter().any(|row| row.mqfq_order != row.drr_order);
        assert!(
            any_divergent,
            "#785 Phase 3 golden vector table must include at \
             least one row where MQFQ diverges from DRR; otherwise \
             the table is not demonstrating byte-rate fairness vs. \
             packet-count fairness.",
        );
    }

    /// #785 Phase 3 Rust reviewer LOW — idle-return anchor pin.
    /// Complements `mqfq_queue_vtime_advances_by_drained_bytes`
    /// and `mqfq_bucket_drain_resets_finish_time` by asserting the
    /// CONSEQUENCE of those invariants: a flow that idles while
    /// others drain must re-anchor at `queue_vtime + bytes`, NOT
    /// sweep past established flows by re-entering at 0.
    ///
    /// Without the idle re-anchor, a bursty flow that goes silent
    /// and returns would drain all its packets before the active
    /// flow got another slot (anchor=0+bytes wins every min-scan
    /// for several rounds). With it, the returning flow competes
    /// at the current frontier and interleaves correctly.
    #[test]
    fn mqfq_idle_flow_reanchors_at_frontier_not_zero() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let flow_a = test_session_key(3301, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(3302, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        // Drain flow A for 3 x 1500 = 4500 bytes. vtime reaches
        // 4500.
        for _ in 0..3 {
            cos_queue_push_back(queue, test_flow_cos_item(3301, 1500));
        }
        for _ in 0..3 {
            let _ = cos_queue_pop_front(queue);
        }
        assert_eq!(queue.queue_vtime, 4500);

        // Flow B was idle the whole time. It now returns with a
        // 1200-byte packet. It MUST anchor at queue_vtime+bytes =
        // 4500+1200 = 5700, NOT at 0+1200 = 1200.
        cos_queue_push_back(queue, test_flow_cos_item(3302, 1200));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], 5700,
            "#785 Phase 3: idle-returning bucket MUST re-anchor at \
             current queue_vtime, not 0. Anchoring at 0 lets the \
             returning flow sweep past all established flows for \
             several rounds (#785 CoV regression).",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_b], 5700);
    }

    /// #785 Phase 3 — same mixed-size byte-rate ordering on the
    /// Prepared (zero-copy) path. Both Local and Prepared variants
    /// must share MQFQ ordering; the pop path picks by finish time
    /// regardless of item kind.
    #[test]
    fn flow_fair_queue_pops_in_virtual_finish_order_prepared() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // 3000-byte packet on 1111, 1500-byte packets on 1112.
        cos_queue_push_back(queue, test_flow_prepared_cos_item(1111, 3000, 64));
        cos_queue_push_back(queue, test_flow_prepared_cos_item(1112, 1500, 192));

        let mut order = Vec::new();
        while let Some(CoSPendingTxItem::Prepared(req)) = cos_queue_pop_front(queue) {
            order.push(req.flow_key.expect("flow key").src_port);
        }

        assert_eq!(
            order,
            vec![1112, 1111],
            "Prepared-path MQFQ ordering must match Local-path: \
             smaller-finish drains first regardless of variant.",
        );
    }

    // ---------------------------------------------------------------------
    // #785 Phase 3 — MQFQ virtual-finish-time mechanism pins.
    // ---------------------------------------------------------------------

    /// Pin the enqueue-side VFT formula:
    /// `finish[b] = max(finish[b], queue.vtime) + bytes`.
    ///
    /// Three sub-properties:
    /// 1. On first packet of a newly-active bucket, finish = vtime + bytes.
    /// 2. Subsequent packets on the same bucket advance finish by bytes.
    /// 3. Different flow sizes produce proportional finish-time deltas.
    ///
    /// Regression: if the formula loses either the `max(finish, vtime)`
    /// anchor (idle bucket re-anchor) or the `+ bytes` step (cumulative
    /// byte accounting), ordering silently mis-sorts under TCP pacing.
    #[test]
    fn mqfq_enqueue_bumps_finish_time_by_byte_count() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;
        // Simulate the queue having already drained to vtime=5000.
        queue.queue_vtime = 5000;

        let flow_a = test_session_key(1111, 5201);
        let flow_b = test_session_key(2222, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "fixture flow keys must not collide");

        // Packet 1 of flow A — bucket was idle (finish=0). Re-anchor
        // to queue.vtime (5000) then + 1500.
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 6500,
            "first packet on an idle bucket re-anchors to queue.vtime \
             + bytes (5000 + 1500 = 6500)",
        );

        // Packet 2 of flow A — already-active. finish advances by bytes.
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 8000,
            "subsequent packet on the same active bucket advances by \
             exactly bytes (6500 + 1500 = 8000)",
        );

        // Packet 1 of flow B — independent bucket, same re-anchor.
        account_cos_queue_flow_enqueue(queue, Some(&flow_b), 500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], 5500,
            "different-sized packet produces proportional finish \
             delta (5000 + 500 = 5500)",
        );
    }

    /// Pin that a bucket's finish-time is RESET to 0 when the last
    /// packet drains from it. Without this reset, a bucket that goes
    /// idle and later re-activates would inherit its stale lifetime
    /// finish-time — the enqueue-side `max(finish, vtime)` anchor
    /// would be no-op'd (finish >> vtime), letting the returning flow
    /// skip ahead of all established flows in bounded rounds.
    #[test]
    fn mqfq_bucket_drain_resets_finish_time() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let flow = test_session_key(3333, 5201);
        let bucket = cos_flow_bucket_index(0, Some(&flow));

        cos_queue_push_back(queue, test_flow_cos_item(3333, 1500));
        assert!(queue.flow_bucket_head_finish_bytes[bucket] > 0);
        assert!(queue.flow_bucket_tail_finish_bytes[bucket] > 0);

        // Drain the only packet. Bucket is now empty.
        let _ = cos_queue_pop_front(queue);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket], 0,
            "bucket drain to 0 MUST reset head-finish-time",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket], 0,
            "bucket drain to 0 MUST reset tail-finish-time so the \
             next enqueue re-anchors at queue.vtime, not the stale \
             lifetime finish",
        );
    }

    /// #913 — Pin the `queue.vtime` semantics: MQFQ served-finish.
    /// Vtime advances to track the served packet's finish time
    /// (which equals the smallest head_finish across active
    /// buckets at pop time, since MQFQ pops min-finish-first).
    /// This is the "system frontier" — re-enqueued idle buckets
    /// compare against it in `max(bucket_finish, queue_vtime) +
    /// bytes` so a returning flow starts at the current
    /// frontier, not back at 0.
    ///
    /// In this single-flow test, served_finish progresses
    /// 1500 → 3000 → 4500 (head advances by next-packet bytes
    /// after each pop). vtime = max(prev, served) tracks the
    /// progression — same numerical result as the pre-#913
    /// aggregate-bytes formulation, by coincidence in the
    /// single-flow case. The cross-flow test
    /// `mqfq_vtime_does_not_accumulate_across_flows` (below)
    /// shows where the two semantics actually diverge.
    #[test]
    fn mqfq_queue_vtime_tracks_served_finish_time() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Three packets on one flow. After enqueue, bucket_finish
        // = 4500 (the 3rd packet's finish). But queue.vtime should
        // advance by 1500 per pop, not jump to 4500 on the first.
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));

        assert_eq!(queue.queue_vtime, 0);

        let _ = cos_queue_pop_front(queue);
        assert_eq!(
            queue.queue_vtime, 1500,
            "first pop: vtime tracks served packet's finish_time \
             (1500 = head_finish of the 1st packet)",
        );
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 3000);
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 4500);
    }

    /// #913 — Distinguishing test: vtime must NOT accumulate
    /// across flows. This test would FAIL under the pre-#913
    /// aggregate-bytes formulation and PASS under the new MQFQ
    /// served-finish formulation. It's the bug-trip that would
    /// have caught the original SFQ-V(t) implementation if it
    /// had existed at the time the original code landed.
    ///
    /// Setup: 10 distinct flows, one 1500-byte packet each. Pop
    /// one packet from each flow in MQFQ order (10 pops). Every
    /// flow's bucket has head_finish=1500 at enqueue (vtime=0).
    ///
    /// Pre-#913 (aggregate-bytes): vtime advances by 1500 per
    /// pop → final = 10 × 1500 = 15000.
    ///
    /// New (MQFQ served-finish): each pop sees served_finish=
    /// 1500 (every flow's first packet); `vtime = max(prev,
    /// 1500)` never advances past the first round → final =
    /// 1500.
    ///
    /// Why this matters for #911: under the old semantics, a
    /// mouse arriving after N rounds of elephant draining
    /// anchored at vtime + bytes = N × MTU + small ≫ active
    /// buckets' head_finish, so MQFQ served the mouse LAST.
    /// Under new semantics, vtime tracks the served frontier
    /// and the mouse interleaves with elephants.
    #[test]
    fn mqfq_vtime_does_not_accumulate_across_flows() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Enqueue one 1500-byte packet on each of 10 distinct
        // flows. After enqueue, every bucket has head=tail=1500.
        // Copilot review: select flow IDs dynamically so the test
        // doesn't couple to a specific hash distribution. We
        // sweep candidate IDs and accept the first 10 that land
        // in distinct buckets.
        let mut buckets: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let mut accepted: Vec<u16> = Vec::with_capacity(10);
        for flow_id in 1000u16..2000u16 {
            let key = test_session_key(flow_id, 5201);
            let bucket = cos_flow_bucket_index(0, Some(&key));
            if buckets.insert(bucket) {
                accepted.push(flow_id);
                if accepted.len() == 10 {
                    break;
                }
            }
        }
        assert_eq!(
            accepted.len(),
            10,
            "test setup: 10 distinct buckets must be selectable in [1000, 2000)"
        );
        for flow_id in accepted {
            cos_queue_push_back(queue, test_flow_cos_item(flow_id, 1500));
        }
        assert_eq!(queue.queue_vtime, 0);
        assert_eq!(queue.active_flow_buckets, 10);

        // Pop all 10 items via MQFQ (min head_finish first).
        for _ in 0..10 {
            assert!(cos_queue_pop_front(queue).is_some());
        }

        assert_eq!(
            queue.queue_vtime, 1500,
            "#913 MQFQ: vtime tracks served-packet finish, \
             not aggregate bytes drained. Each pop sees the \
             same head_finish=1500 across the 10 distinct \
             flows; max(0,1500,1500,...,1500) = 1500. \
             Pre-#913 aggregate-bytes would have given \
             10 × 1500 = 15000."
        );
        assert_eq!(queue.active_flow_buckets, 0);
    }

    /// #913 — Codex code review HIGH regression. Scratch-builder
    /// Drop must preserve the dropped item's vtime contribution
    /// across multi-survivor restore, otherwise a new idle flow
    /// can jump ahead of the restored active buckets — exactly
    /// the temporal-inversion class of bug #913 was supposed to
    /// fix.
    ///
    /// Setup: 3 distinct flows X (head 1500), Y (head 2000), Z
    /// (head 3000). Pop in MQFQ order (X→Y→Z); `queue_vtime`
    /// advances 0 → 1500 → 2000 → 3000.
    ///
    /// Simulate Z dropped: invoke
    /// `cos_queue_clear_orphan_snapshot_after_drop` (the helper
    /// the four scratch-builder Drop sites call). Z's snapshot is
    /// removed and remaining (X, Y) snapshots get clamped so
    /// their `pre_pop_queue_vtime` ≥ 3000.
    ///
    /// Restore Y, then X via `cos_queue_push_front`. After both
    /// restores, `queue_vtime` MUST be ≥ 3000 (Z's commit
    /// preserved). Bucket heads/tails restored exactly.
    ///
    /// Then enqueue a new idle flow W (small bytes) and assert
    /// W's head_finish ≥ X/Y's head_finish so W cannot jump the
    /// restored active set.
    #[test]
    fn mqfq_scratch_drop_preserves_vtime_for_multi_survivor_restore() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Distinct buckets X / Y / Z with mixed packet sizes so
        // each has a unique head_finish (avoids the "all-equal"
        // numeric-coincidence case). Copilot review: select flow
        // IDs dynamically so the test doesn't couple to a
        // specific hash distribution.
        let mut seen: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let mut picks: Vec<u16> = Vec::with_capacity(3);
        for flow_id in 7001u16..8001u16 {
            let bucket = cos_flow_bucket_index(
                0,
                Some(&test_session_key(flow_id, 5201)),
            );
            if seen.insert(bucket) {
                picks.push(flow_id);
                if picks.len() == 3 {
                    break;
                }
            }
        }
        assert_eq!(
            picks.len(),
            3,
            "test setup: 3 distinct buckets must be selectable in [7001, 8001)"
        );
        let (flow_x_id, flow_y_id, flow_z_id) = (picks[0], picks[1], picks[2]);
        cos_queue_push_back(queue, test_flow_cos_item(flow_x_id, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(flow_y_id, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(flow_z_id, 3000));
        let key_x = test_session_key(flow_x_id, 5201);
        let key_y = test_session_key(flow_y_id, 5201);
        let key_z = test_session_key(flow_z_id, 5201);
        let bucket_x = cos_flow_bucket_index(0, Some(&key_x));
        let bucket_y = cos_flow_bucket_index(0, Some(&key_y));
        let bucket_z = cos_flow_bucket_index(0, Some(&key_z));

        let pre_batch_head_x = queue.flow_bucket_head_finish_bytes[bucket_x];
        let pre_batch_head_y = queue.flow_bucket_head_finish_bytes[bucket_y];
        let pre_batch_head_z = queue.flow_bucket_head_finish_bytes[bucket_z];
        assert_eq!(pre_batch_head_x, 1500);
        assert_eq!(pre_batch_head_y, 2000);
        assert_eq!(pre_batch_head_z, 3000);

        // Pop X, Y, Z in MQFQ order.
        let popped_x = cos_queue_pop_front(queue).expect("pop X");
        let popped_y = cos_queue_pop_front(queue).expect("pop Y");
        let _popped_z = cos_queue_pop_front(queue).expect("pop Z");
        assert_eq!(
            queue.queue_vtime, 3000,
            "after X→Y→Z pops, vtime tracks served-finish frontier (max=3000)"
        );
        assert_eq!(queue.pop_snapshot_stack.len(), 3);

        // Simulate Z dropped (e.g., frame too big in scratch builder).
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);
        assert_eq!(
            queue.queue_vtime, 3000,
            "Drop preserves the committed vtime advance"
        );

        // Restore Y first (LIFO), then X.
        cos_queue_push_front(queue, popped_y);
        assert!(
            queue.queue_vtime >= 3000,
            "after Y restore, vtime must NOT regress below Z's commit \
             (got {})",
            queue.queue_vtime
        );
        cos_queue_push_front(queue, popped_x);
        assert!(
            queue.queue_vtime >= 3000,
            "after X restore, vtime must NOT regress below Z's commit \
             (got {})",
            queue.queue_vtime
        );
        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "all snapshots consumed by restore"
        );

        // X and Y bucket head_finish restored to pre-pop values.
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_x], pre_batch_head_x);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_y], pre_batch_head_y);

        // Now enqueue a new idle flow W with a small packet. Pick
        // its flow ID dynamically so its bucket is distinct from
        // the restored X and Y buckets.
        let mut flow_w_id: u16 = 0;
        for candidate in 8001u16..9001u16 {
            let bucket = cos_flow_bucket_index(
                0,
                Some(&test_session_key(candidate, 5201)),
            );
            if bucket != bucket_x && bucket != bucket_y && bucket != bucket_z {
                flow_w_id = candidate;
                break;
            }
        }
        assert_ne!(flow_w_id, 0, "test setup: distinct W bucket selectable");
        cos_queue_push_back(queue, test_flow_cos_item(flow_w_id, 100));
        let key_w = test_session_key(flow_w_id, 5201);
        let bucket_w = cos_flow_bucket_index(0, Some(&key_w));
        let w_head = queue.flow_bucket_head_finish_bytes[bucket_w];

        // CORE ASSERTION: W cannot jump ahead of the restored
        // active buckets X/Y. Pre-#913 (or pre-Drop-vtime-fix),
        // vtime would have regressed to 0 and W would anchor at
        // max(0,0)+100 = 100, jumping ahead of X (1500) and Y
        // (2000). With Drop's vtime preserved at ≥ 3000, W
        // anchors at max(0, 3000) + 100 = 3100, which is past
        // X and Y.
        assert!(
            w_head >= pre_batch_head_x,
            "Codex regression: new idle flow W (head={}) must NOT \
             jump ahead of restored bucket X (head={}) — \
             dropped Z's vtime contribution must be preserved",
            w_head, pre_batch_head_x
        );
        assert!(
            w_head >= pre_batch_head_y,
            "Codex regression: new idle flow W (head={}) must NOT \
             jump ahead of restored bucket Y (head={})",
            w_head, pre_batch_head_y
        );
    }

    /// #913 — Codex code review R8/R9 regression. Same-bucket
    /// multi-pop with intermediate Drop: under MQFQ
    /// "drops consume virtual service" semantics, the dropped
    /// item's contribution must be preserved so that surviving
    /// packets in the same bucket retain their original
    /// finish-time positions.
    ///
    /// Setup: bucket A has 3 packets [1000, 2000, 1500].
    /// Initial state at enqueue: head_A=1000, tail_A=4500.
    /// Original finish times: A1=1000, A2=3000, A3=4500.
    ///
    /// Pop A1 (1000-byte): head advances to 3000 (bytes(A2)).
    /// Pop A2 (2000-byte): head advances to 4500 (bytes(A3)).
    /// Drop A2 (frame too big). Orphan-cleanup helper pops
    /// snap_2 and clamps snap_1.pre_pop_queue_vtime.
    ///
    /// Restore A1 via push_front. Bucket has [A3] at this point
    /// (was_empty=false), so the active-bucket arithmetic runs:
    /// `head -= bytes(current_head=A3=1500) = 4500-1500 = 3000`.
    ///
    /// THIS IS CORRECT under MQFQ drops-consume semantics:
    /// head=3000 means "the bucket's frontier is at 3000 (post-
    /// A2's virtual service)." When A1 is then popped:
    /// `head += bytes(A3=1500) = 4500`. A3 ends up at finish=4500
    /// — its ORIGINAL position — preserving A2's contribution.
    /// Competing buckets with finish 3000-4500 correctly drain
    /// before A3, no scheduling inversion.
    ///
    /// (Naive alternative: restore head from snap.pre_pop_head=1000
    /// would lose A2's contribution. After pop A1: head=1000+1500=
    /// 2500; A3 ends up at 2500 instead of 4500. Competing buckets
    /// at finish 2500-4500 would unfairly drain after A3 — that's
    /// the scheduling inversion Codex R9 flagged.)
    #[test]
    fn mqfq_same_bucket_multipop_drop_preserves_dropped_item_finish() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Single bucket A, 3 packets with mixed sizes.
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1500));
        let key_a = test_session_key(8001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&key_a));

        // Pop A1 (1000B). head_finish advances to 3000.
        let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 3000);

        // Pop A2 (2000B). head_finish advances to 4500.
        let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 4500);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);

        // Simulate A2 dropped via the scratch-builder Drop helper.
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 1);

        // Restore A1 via push_front. Active-bucket arithmetic:
        // head=4500 - bytes(A3=1500) = 3000. This is the
        // post-A2-pop value; A2's "virtual service" is preserved.
        cos_queue_push_front(queue, popped_a1);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3000,
            "post-restore head_finish should be 3000 (post-A2-pop \
             value, preserving A2's virtual-service contribution)"
        );

        // Critical Codex R9 assertion: pop A1 again, then verify
        // A3 lands at its original finish=4500, NOT 2500.
        // This is the scheduling-correctness gate — A3 must NOT
        // jump ahead of competing buckets that were originally
        // scheduled between A2's and A3's finish times.
        let _popped_a1_again = cos_queue_pop_front(queue).expect("pop A1 again");
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 4500,
            "Codex R9 regression: after dropping A2 and re-popping \
             A1, A3 must remain at its original finish=4500 (not \
             2500). Otherwise A3 jumps ahead of competing buckets \
             that were originally scheduled in the [3000, 4500) \
             window — exactly the temporal inversion #913 was \
             supposed to prevent."
        );
    }

    /// #927: drained-bucket scenario. Bucket A holds [A1=1000B,
    /// A2=2000B], bucket C holds [C=2500B]. Scratch builder pops
    /// A1+C+A2 in that order. A2's pop drains bucket A (last item).
    /// A2 is then dropped (frame too big, etc.). The orphan-cleanup
    /// helper must preserve A2's served_finish = 3000 across the
    /// restore so that A1's restored frontier is ≥ 3000. Otherwise
    /// the `was_empty` snapshot path in `cos_queue_push_front`
    /// would restore A.head=1000 (the snap_1.pre_pop_head_finish
    /// captured before A2's pop), and MQFQ would pop A1 BEFORE
    /// C — inverting their original scheduling order.
    #[test]
    fn mqfq_drained_bucket_orphan_drop_preserves_served_finish() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Bucket A: [A1=1000, A2=2000]. Bucket C: [C=2500].
        // Two distinct flow keys so they hash to distinct buckets.
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(8002, 2500));
        let key_a = test_session_key(8001, 5201);
        let key_c = test_session_key(8002, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
        let bucket_c = cos_flow_bucket_index(0, Some(&key_c));
        assert_ne!(
            bucket_a, bucket_c,
            "test setup: ports 8001/8002 must hash to distinct buckets"
        );

        // Pre-pop frontier:
        //   A.head=1000 (A1 finish), A.tail=3000 (A2 finish).
        //   C.head=C.tail=2500.
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 1000);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 3000);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 2500);

        // Pop A1: head_finish[A] advances to 3000 (A2 finish-time).
        let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 3000);

        // Pop C: MQFQ picks min-finish-first; with A.head=3000
        // and C.head=2500, C.head < A.head so C is the next pop.
        // After pop: bucket C empty; C.head_finish reset to 0.
        let popped_c = cos_queue_pop_front(queue).expect("pop C");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 0);

        // Pop A2 (last in A): bucket A drains, A.head_finish reset
        // to 0. queue_vtime reflects all three pops.
        let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.pop_snapshot_stack.len(), 3);

        // Simulate A2 dropped (e.g., frame too big to transmit).
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);

        // Restore C via push_front: bucket C is empty so the
        // `was_empty` snapshot path applies. C.head should restore
        // to snap_C.pre_pop_head_finish = 2500.
        cos_queue_push_front(queue, popped_c);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 2500);

        // Restore A1 via push_front: bucket A is empty so the
        // `was_empty` snapshot path applies. WITHOUT #927, A.head
        // would restore to snap_1.pre_pop_head_finish = 1000 —
        // inverting MQFQ order vs C (1000 < 2500). WITH #927, the
        // orphan-cleanup helper bumped snap_1.pre_pop_head_finish
        // up to A2's served_finish = 3000, so the restored A.head
        // = 3000 > C.head = 2500 — MQFQ correctly picks C first.
        cos_queue_push_front(queue, popped_a1);
        assert!(
            queue.flow_bucket_head_finish_bytes[bucket_a]
                > queue.flow_bucket_head_finish_bytes[bucket_c],
            "#927 regression: A.head ({}) must be strictly greater than \
             C.head ({}) so MQFQ picks C first. Without the orphan-cleanup \
             same-bucket frontier bump, A.head would restore to 1000 and \
             A1 would pop before C — inverting their original schedule.",
            queue.flow_bucket_head_finish_bytes[bucket_a],
            queue.flow_bucket_head_finish_bytes[bucket_c],
        );
    }

    /// Pin that `FlowRrRing::remove` correctly de-registers a bucket
    /// from an arbitrary position. The MQFQ pop path calls this when
    /// a bucket at non-head position (determined by finish-time, not
    /// ring order) drains to empty.
    #[test]
    fn flow_rr_ring_remove_from_middle() {
        let mut ring = FlowRrRing::default();
        ring.push_back(10);
        ring.push_back(20);
        ring.push_back(30);
        ring.push_back(40);
        assert_eq!(ring.len(), 4);

        // Remove from the middle.
        assert!(ring.remove(20));
        assert_eq!(ring.len(), 3);
        let ids: Vec<u16> = ring.iter().collect();
        assert_eq!(ids, vec![10, 30, 40]);

        // Remove head-adjacent.
        assert!(ring.remove(10));
        assert_eq!(ring.len(), 2);
        let ids: Vec<u16> = ring.iter().collect();
        assert_eq!(ids, vec![30, 40]);

        // Remove missing (no-op).
        assert!(!ring.remove(999));
        assert_eq!(ring.len(), 2);

        // Remove tail.
        assert!(ring.remove(40));
        assert_eq!(ring.len(), 1);
        let ids: Vec<u16> = ring.iter().collect();
        assert_eq!(ids, vec![30]);

        // Remove last.
        assert!(ring.remove(30));
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
    }

    /// Pin that on a shared_exact flow-fair queue, the admission
    /// gates downgrade to aggregate-only — rate-unaware per-flow
    /// cap would tail-drop TCP at the 24 KB floor on a 25 Gbps
    /// queue with 12 flows. Retrospective Attempt A measured 8 Gbps
    /// throughput regression when this downgrade was absent.
    #[test]
    fn mqfq_shared_exact_admission_downgrades_to_aggregate() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.flow_hash_seed = 0;

        let target = 0usize;
        seed_sixteen_flow_buckets(queue, target, 1);
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);

        assert_eq!(
            share_cap, buffer_limit,
            "#785 Phase 3: shared_exact + flow_fair queues MUST use \
             aggregate-only admission (share_cap == buffer_limit). \
             Regression re-introduces the 24 KB per-flow floor that \
             tail-drops TCP at multi-Gbps per-flow rates.",
        );
    }

    /// #785 Phase 3 Codex round-2 HIGH: push_front onto an active
    /// bucket must be finish-time-neutral — a pop-and-restore
    /// round-trip must leave the queue in the same state it started.
    ///
    /// Without this invariant, TX-ring-full restoration paths
    /// (every flow-fair drain has one) corrupt the MQFQ selection
    /// key: push_front leaves head stale, subsequent non-drain pops
    /// advance head off the stale base, and bucket ordering drifts
    /// arbitrarily. Codex traced it with a three-packet bucket
    /// where a push_front mid-drain produced a 500-byte discrepancy
    /// on a 1500-byte packet's finish time.
    ///
    /// Round-3 extension (Codex HIGH): also pin `queue_vtime`
    /// neutrality. The prior revision advanced `queue_vtime` on
    /// pop-time but never rewound on push_front, biasing newly-
    /// active flows behind a phantom amount of drained bytes
    /// whenever TX-ring-full rolled a pop back onto the queue.
    ///
    /// Test: pop the head, observe advanced head-finish and vtime,
    /// push_front the popped item back, observe ALL of head-finish,
    /// tail-finish, bucket-bytes, AND queue_vtime returned to their
    /// pre-pop values.
    #[test]
    fn mqfq_push_front_is_finish_time_neutral_on_active_bucket() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Enqueue three packets on one flow.
        cos_queue_push_back(queue, test_flow_cos_item(4444, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(4444, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(4444, 1500));

        let flow = test_session_key(4444, 5201);
        let bucket = cos_flow_bucket_index(0, Some(&flow));

        // Bucket state: head=1000, tail=4500.
        let pre_pop_head = queue.flow_bucket_head_finish_bytes[bucket];
        let pre_pop_tail = queue.flow_bucket_tail_finish_bytes[bucket];
        let pre_pop_bytes = queue.flow_bucket_bytes[bucket];
        let pre_pop_vtime = queue.queue_vtime;
        assert_eq!(pre_pop_head, 1000);
        assert_eq!(pre_pop_tail, 4500);
        assert_eq!(pre_pop_bytes, 4500);
        assert_eq!(pre_pop_vtime, 0);

        // Pop head (the 1000-byte packet). Head advances to 3000
        // (= pre_pop_head + bytes(new head = 2000)). vtime += 1000.
        let popped = cos_queue_pop_front(queue).expect("pop");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket], 3000);
        assert_eq!(queue.queue_vtime, 1000);

        // Push the same item back onto the front. Head-finish MUST
        // return to the pre-pop value (1000), AND queue_vtime MUST
        // return to its pre-pop value (0) — Codex round-3 HIGH.
        cos_queue_push_front(queue, popped);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket], pre_pop_head,
            "#785 Phase 3 Codex HIGH: push_front must be finish-\
             time-neutral on active buckets. Regression re-opens \
             the MQFQ ordering corruption on TX-ring-full retry.",
        );
        // Tail unchanged — we didn't add at tail.
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket], pre_pop_tail);
        assert_eq!(queue.flow_bucket_bytes[bucket], pre_pop_bytes);
        assert_eq!(
            queue.queue_vtime, pre_pop_vtime,
            "#785 Phase 3 Codex round-3 HIGH: queue_vtime must be \
             round-trip neutral on pop→push_front. Without this, \
             newly-active flows inherit an inflated vtime anchor \
             and start behind established traffic even though zero \
             bytes were actually transmitted during the rollback.",
        );
    }

    /// #785 Phase 3 Codex round-3 HIGH — companion pin for the
    /// DRAINED-bucket case (Rust reviewer MEDIUM #1). When the
    /// popped item is the SOLE packet in its bucket, the pop
    /// path's `account_cos_queue_flow_dequeue` resets head=tail=0
    /// AND the bucket deregisters from the active set. A naive
    /// push_front would hit the `was_empty` branch and re-anchor
    /// head=tail=`max(0, queue_vtime) + bytes`, which overshoots
    /// the pre-pop head by up to one packet and leaves the
    /// bucket competing at the wrong virtual-time.
    ///
    /// Fix: the last-pop snapshot records pre-pop head/tail at
    /// pop time; push_front restores them exactly when the
    /// snapshot's bucket matches.
    #[test]
    fn mqfq_push_front_is_neutral_on_drained_bucket_round_trip() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Simulate a vtime that's already advanced (as it would
        // be mid-stream when other flows have drained), then
        // enqueue a single packet on flow A. The idle-bucket
        // re-anchor writes head=tail=max(tail=0, vtime=5000)+1500
        // = 6500.
        queue.queue_vtime = 5000;
        let flow_a = test_session_key(7777, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        cos_queue_push_back(queue, test_flow_cos_item(7777, 1500));

        let pre_pop_head = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_pop_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_pop_bytes = queue.flow_bucket_bytes[bucket_a];
        let pre_pop_vtime = queue.queue_vtime;
        let pre_pop_active = queue.active_flow_buckets;
        assert_eq!(pre_pop_head, 6500);
        assert_eq!(pre_pop_tail, 6500);
        assert_eq!(pre_pop_bytes, 1500);
        assert_eq!(pre_pop_vtime, 5000);

        // Pop the sole item. Bucket drains: head=tail=0, active
        // count -=1, vtime advances to 6500.
        let popped = cos_queue_pop_front(queue).expect("pop");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 0);
        assert_eq!(queue.queue_vtime, pre_pop_vtime + 1500);
        assert!(queue.flow_bucket_items[bucket_a].is_empty());

        // Restore it via push_front. Without the snapshot fix this
        // re-anchors to vtime+bytes = 6500+1500 = 8000 — one packet
        // past the pre-pop head of 6500. With the fix, head/tail
        // restore to 6500 exactly.
        cos_queue_push_front(queue, popped);

        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_pop_head,
            "#785 Phase 3 Codex round-3 HIGH / Rust MEDIUM #1: \
             push_front on a drained bucket must restore pre-pop \
             head exactly, not re-anchor one packet past it.",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], pre_pop_tail);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], pre_pop_bytes);
        assert_eq!(
            queue.queue_vtime, pre_pop_vtime,
            "#785 Phase 3: queue_vtime must rewind to pre-pop on \
             drained-bucket round-trip too.",
        );
        assert_eq!(queue.active_flow_buckets, pre_pop_active);
        assert_eq!(queue.flow_bucket_items[bucket_a].len(), 1);
    }

    /// #785 Phase 3 Codex round-2 NEW-1 — batched rollback on a
    /// SINGLE bucket must restore every pre-pop snapshot exactly,
    /// not just the most recent one.
    ///
    /// Scenario: N (=4) items enqueued on one flow, drained into
    /// scratch in one batch (simulating the TX-ring-full drain
    /// path), then rolled back in LIFO order via push_front.
    /// After rollback, every per-bucket field and `queue_vtime`
    /// must equal its pre-batch value.
    ///
    /// Prior revision kept a single `Option<CoSQueuePopSnapshot>`
    /// that each pop overwrote. On rollback only the FIRST
    /// push_front (matching the LAST pop) got its snapshot; all
    /// earlier restorations fell back to the idle-bucket
    /// `max(tail, queue_vtime) + bytes` re-anchor. For this
    /// single-bucket case the earlier restorations' ACTIVE branch
    /// did happen to produce the right answer (the restored item
    /// took over as the new head via `head -= bytes(front)`), BUT
    /// the drained-bucket case in the cross-bucket pin below
    /// overshoots without a per-pop stack. Both pins together
    /// cover single-bucket and multi-bucket correctness.
    #[test]
    fn mqfq_batched_rollback_restores_queue_vtime() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Advance `queue_vtime` so that later flows anchor ahead
        // of zero (stresses the cross-bucket bug — an earlier pop
        // whose bucket drains resets head/tail to 0, then
        // `max(0, queue_vtime) + bytes` on re-enqueue overshoots
        // the pre-pop head).
        queue.queue_vtime = 3000;

        let flow_a = test_session_key(5555, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

        cos_queue_push_back(queue, test_flow_cos_item(5555, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 1200));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 800));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 1400));

        let pre_batch_head = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_batch_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_batch_bytes = queue.flow_bucket_bytes[bucket_a];
        let pre_batch_vtime = queue.queue_vtime;
        let pre_batch_active = queue.active_flow_buckets;
        let pre_batch_peak = queue.active_flow_buckets_peak;
        let pre_batch_items = queue.flow_bucket_items[bucket_a].len();
        assert_eq!(pre_batch_items, 4);

        // Drain all 4 into scratch. Stack grows to 4 snapshots.
        let mut scratch: Vec<CoSPendingTxItem> = Vec::with_capacity(4);
        while let Some(item) = cos_queue_pop_front(queue) {
            scratch.push(item);
        }
        assert_eq!(scratch.len(), 4);
        assert_eq!(
            queue.pop_snapshot_stack.len(),
            4,
            "NEW-1: every pop must push its own snapshot onto the \
             per-queue LIFO stack",
        );

        // Roll back all 4 in LIFO order (scratch.pop()). This
        // mirrors `restore_exact_local_scratch_to_queue_head_flow_fair`.
        while let Some(item) = scratch.pop() {
            cos_queue_push_front(queue, item);
        }

        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-1: snapshot stack must be fully consumed after a \
             complete rollback",
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_batch_head,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket HEAD finish exactly (single-bucket case)",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_batch_tail,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket TAIL finish exactly (single-bucket case)",
        );
        assert_eq!(
            queue.flow_bucket_bytes[bucket_a], pre_batch_bytes,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket byte count exactly",
        );
        assert_eq!(
            queue.queue_vtime, pre_batch_vtime,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             queue_vtime exactly — symmetric per-item rewind",
        );
        assert_eq!(
            queue.active_flow_buckets, pre_batch_active,
            "#785 Phase 3 NEW-1: batched rollback must leave \
             active_flow_buckets unchanged",
        );
        assert_eq!(
            queue.active_flow_buckets_peak, pre_batch_peak,
            "#785 Phase 3 NEW-1: peak counter is monotonic — \
             rollback must not bump it (no fresh high-water mark)",
        );
        assert_eq!(queue.flow_bucket_items[bucket_a].len(), pre_batch_items);
    }

    /// #785 Phase 3 Codex round-2 NEW-1 — batched rollback across
    /// MULTIPLE buckets. This is the case the prior single-
    /// `Option<CoSQueuePopSnapshot>` implementation got wrong:
    /// earlier drained buckets (i.e. not the MOST-recently-popped
    /// one) had no snapshot at rollback time and fell back to the
    /// idle re-anchor `max(tail=0, queue_vtime) + bytes`, which
    /// overshoots the pre-pop head whenever `queue_vtime` has
    /// advanced past the bucket's original enqueue point.
    ///
    /// Scenario construction:
    ///   1. Pre-advance `queue_vtime=100`; enqueue A (1500) and B
    ///      (900) at that frontier. pre-pop head[A]=1600,
    ///      head[B]=1000.
    ///   2. Force-advance `queue_vtime=5000` to simulate a long
    ///      period of other-flow drain activity between enqueue
    ///      and batch.
    ///   3. Drain both: pop B (head 1000 < 1600), then pop A.
    ///      vtime goes 5000 → 5900 → 7400. Both buckets drain,
    ///      head/tail=0.
    ///   4. Roll back LIFO. scratch.pop() returns A first, then B.
    ///
    /// With per-pop snapshots: A's restore pops snap_A from the
    /// stack and writes head[A]=1600. B's restore pops snap_B and
    /// writes head[B]=1000.
    ///
    /// Without per-pop snapshots (old single-`Option` impl):
    /// snapshot held {A, 1600, 1600} (last overwrote). A's restore
    /// uses it and succeeds. B's restore finds snapshot=None,
    /// falls through to `account_cos_queue_flow_enqueue`:
    /// head[B] = max(0, vtime_at_that_point=5000) + 900 = 5900,
    /// overshooting the pre-pop head of 1000 by 4900. THIS PIN
    /// TRIPS: without the fix the assertion on B's head-finish
    /// fails at 5900 != 1000.
    #[test]
    fn mqfq_batched_rollback_across_multiple_buckets() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Step 1: low vtime so A and B anchor near 0.
        queue.queue_vtime = 100;

        let flow_a = test_session_key(6001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(6002, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        cos_queue_push_back(queue, test_flow_cos_item(6001, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(6002, 900));
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 1600);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_b], 1000);

        // Step 2: simulate other-flow drain activity. vtime
        // advances past both buckets' head finish times. This is
        // the condition that makes the old single-Option rollback
        // overshoot on the earlier-popped bucket.
        queue.queue_vtime = 5000;

        let pre_batch_head_a = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_batch_tail_a = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_batch_bytes_a = queue.flow_bucket_bytes[bucket_a];
        let pre_batch_head_b = queue.flow_bucket_head_finish_bytes[bucket_b];
        let pre_batch_tail_b = queue.flow_bucket_tail_finish_bytes[bucket_b];
        let pre_batch_bytes_b = queue.flow_bucket_bytes[bucket_b];
        let pre_batch_vtime = queue.queue_vtime;
        let pre_batch_active = queue.active_flow_buckets;
        let pre_batch_peak = queue.active_flow_buckets_peak;
        assert_eq!(pre_batch_head_a, 1600);
        assert_eq!(pre_batch_head_b, 1000);
        assert_eq!(pre_batch_vtime, 5000);
        assert_eq!(pre_batch_active, 2);

        // Drain both into scratch. MQFQ picks min-finish-first;
        // B's head (1400) < A's head (2000), so pop order is B
        // then A. Both buckets drain to head=tail=0.
        let mut scratch: Vec<CoSPendingTxItem> = Vec::with_capacity(2);
        while let Some(item) = cos_queue_pop_front(queue) {
            scratch.push(item);
        }
        assert_eq!(scratch.len(), 2);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_b], 0);
        assert_eq!(queue.active_flow_buckets, 0);

        // Roll back LIFO. scratch.pop() returns A (popped second)
        // first, then B. Each push_front consumes its own
        // snapshot off the stack.
        while let Some(item) = scratch.pop() {
            cos_queue_push_front(queue, item);
        }

        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-1: snapshot stack must be fully consumed after a \
             complete cross-bucket rollback",
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_batch_head_a,
            "#785 Phase 3 NEW-1: cross-bucket rollback — A's HEAD \
             must restore from A's OWN per-pop snapshot, not re- \
             anchor off the rewound vtime (that overshoots).",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_batch_tail_a,
            "#785 Phase 3 NEW-1: cross-bucket rollback — A's TAIL \
             must restore exactly.",
        );
        assert_eq!(queue.flow_bucket_bytes[bucket_a], pre_batch_bytes_a);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], pre_batch_head_b,
            "#785 Phase 3 NEW-1: cross-bucket rollback — B's HEAD \
             must restore exactly (this is the 'most recent pop' \
             case that worked with the single-snapshot impl too).",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], pre_batch_tail_b,
        );
        assert_eq!(queue.flow_bucket_bytes[bucket_b], pre_batch_bytes_b);
        assert_eq!(
            queue.queue_vtime, pre_batch_vtime,
            "#785 Phase 3 NEW-1: vtime must rewind symmetrically \
             across a cross-bucket batch rollback.",
        );
        assert_eq!(
            queue.active_flow_buckets, pre_batch_active,
            "#785 Phase 3 NEW-1: cross-bucket rollback must re- \
             activate both buckets.",
        );
        assert_eq!(queue.active_flow_buckets_peak, pre_batch_peak);
    }

    /// #785 Phase 3 Codex round-3 NEW-2 / Rust reviewer LOW —
    /// pop-snapshot stack must remain bounded by `TX_BATCH_SIZE`
    /// across a committed-only drain (no push_front rollback).
    ///
    /// Setup:
    ///   * Flow-fair queue with `TX_BATCH_SIZE + 64` items enqueued
    ///     (spread across two buckets so MQFQ selection gets
    ///     meaningful coverage).
    ///   * First "drain batch": pop TX_BATCH_SIZE items via direct
    ///     `cos_queue_pop_front`, never call push_front — this is
    ///     the committed-submit pattern where every scratch item
    ///     was accepted by the TX ring. The snapshot stack should
    ///     never exceed `TX_BATCH_SIZE` during the drain.
    ///   * Second "drain batch": drain the remaining 64 items.
    ///     Before the second batch starts, simulate the helper
    ///     contract by clearing the stack (what
    ///     `drain_exact_*_flow_fair` does at batch start). The
    ///     stack must then stay bounded through the second batch
    ///     too.
    ///
    /// Without the fix, every committed pop would leave a stale
    /// snapshot on the stack and the second batch would grow it
    /// past `TX_BATCH_SIZE` (reallocating on each push and
    /// violating the documented bound).
    ///
    /// This pin validates (1) the bound during a single batch,
    /// (2) the bound across batches once the drain-start clear
    /// runs, and (3) that no realloc grows capacity past the
    /// pre-allocated `TX_BATCH_SIZE`.
    #[test]
    fn mqfq_pop_snapshot_stack_bounded_to_tx_batch_size() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 8 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let pre_cap = queue.pop_snapshot_stack.capacity();
        assert_eq!(
            pre_cap, TX_BATCH_SIZE,
            "stack must be preallocated to TX_BATCH_SIZE",
        );

        // Enqueue TX_BATCH_SIZE + 64 items across two flows so the
        // MQFQ min-finish scan exercises real selection, not a
        // single-bucket shortcut.
        let total = TX_BATCH_SIZE + 64;
        for i in 0..total {
            let src_port = if i % 2 == 0 { 9001u16 } else { 9002u16 };
            cos_queue_push_back(queue, test_flow_cos_item(src_port, 100));
        }

        // Batch 1: committed drain — pop TX_BATCH_SIZE items and
        // DROP them (simulates the "TX ring accepted all of them"
        // path where scratch is cleared with no push_front).
        for _ in 0..TX_BATCH_SIZE {
            let popped = cos_queue_pop_front(queue);
            assert!(popped.is_some(), "queue still has items");
            assert!(
                queue.pop_snapshot_stack.len() <= TX_BATCH_SIZE,
                "NEW-2: pop_snapshot_stack must never exceed \
                 TX_BATCH_SIZE during a single drain batch",
            );
        }
        assert_eq!(
            queue.pop_snapshot_stack.len(),
            TX_BATCH_SIZE,
            "full-batch commit should leave exactly TX_BATCH_SIZE \
             snapshots (no push_front rollback consumed any)",
        );

        // Simulate what `drain_exact_*_flow_fair` does at batch
        // start: clear the stack before the next batch drains.
        // This is the fix point.
        queue.pop_snapshot_stack.clear();

        // Batch 2: drain the remaining 64 items. Stack must stay
        // bounded; without the batch-start clear this would grow
        // from TX_BATCH_SIZE → TX_BATCH_SIZE + 64 and realloc.
        for _ in 0..64 {
            let popped = cos_queue_pop_front(queue);
            assert!(popped.is_some());
            assert!(
                queue.pop_snapshot_stack.len() <= TX_BATCH_SIZE,
                "NEW-2: cross-batch drain must stay bounded after \
                 the drain-start clear",
            );
        }

        // No realloc: capacity must equal the preallocated
        // TX_BATCH_SIZE exactly. A realloc would prove the bound
        // was violated at some point.
        assert_eq!(
            queue.pop_snapshot_stack.capacity(),
            pre_cap,
            "NEW-2: stack must not realloc past TX_BATCH_SIZE",
        );
    }

    /// #785 Phase 3 Codex round-3 NEW-2 / Rust reviewer LOW —
    /// teardown/reconfigure drain path (`reset_binding_cos_runtime`
    /// style) must not grow the pop-snapshot stack past its bound
    /// and must leave the stack cleared afterwards.
    ///
    /// We exercise `cos_queue_drain_all` directly — it's the shared
    /// teardown helper used by `demote_prepared_cos_queue_to_local`
    /// and mirrors the direct-`cos_queue_pop_front_no_snapshot` loop
    /// in `reset_binding_cos_runtime`. Both paths drain all items
    /// without a matching push_front rollback.
    ///
    /// Pre-fix: drain-all pushed a snapshot per pop and never
    /// cleared them; with a queue holding > TX_BATCH_SIZE items
    /// the stack would realloc past its preallocated capacity
    /// (the documented-and-preallocated bound) and leave stale
    /// snapshots resident until the next push_back cleared them.
    ///
    /// Post-fix: drain-all uses `cos_queue_pop_front_no_snapshot`
    /// so the stack is never grown. Teardown leaves the stack at
    /// its pre-drain state (empty in this test).
    #[test]
    fn mqfq_drain_all_teardown_clears_stack() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 8 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let pre_cap = queue.pop_snapshot_stack.capacity();
        assert_eq!(pre_cap, TX_BATCH_SIZE);

        // Enqueue more items than the snapshot stack could hold
        // under the old always-push-snapshot policy.
        let total = TX_BATCH_SIZE + 300;
        for i in 0..total {
            let src_port = if i % 3 == 0 {
                9101u16
            } else if i % 3 == 1 {
                9102u16
            } else {
                9103u16
            };
            cos_queue_push_back(queue, test_flow_cos_item(src_port, 100));
        }
        // push_back clears the stack; confirm pre-condition.
        assert!(queue.pop_snapshot_stack.is_empty());

        // Drain via the teardown helper. Must NOT grow the stack
        // and must NOT trip the pop_front debug_assert on overflow.
        let drained = cos_queue_drain_all(queue);
        assert_eq!(
            drained.len(),
            total,
            "drain_all must yield every enqueued item",
        );
        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-2: teardown drain path must leave the snapshot \
             stack empty — no stale snapshots resident",
        );
        assert_eq!(
            queue.pop_snapshot_stack.capacity(),
            pre_cap,
            "NEW-2: teardown must not realloc past TX_BATCH_SIZE",
        );
    }

    /// #785 Phase 3 Codex round-2 MEDIUM — brief-idle re-entry pin.
    /// Previous pins covered the LARGE-idle case (bucket drains,
    /// lots of other traffic flows, bucket re-enqueues far in the
    /// future). This pin covers the BRIEF-idle case where a bucket
    /// drains, another bucket drains advancing vtime modestly, the
    /// first bucket re-enqueues — the `max(tail_finish, queue_vtime)
    /// + bytes` anchor formula must exercise BOTH arms of the max
    /// over the lifetime of this bucket:
    ///
    ///   * First re-enqueue after drain: tail_finish was reset to 0,
    ///     queue_vtime > 0 → max picks queue_vtime, anchor =
    ///     queue_vtime + bytes.
    ///   * Second enqueue (to now-active bucket): tail_finish >
    ///     queue_vtime, max picks tail_finish, anchor =
    ///     tail_finish + bytes.
    #[test]
    fn mqfq_brief_idle_reentry_exercises_both_max_arms() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let flow_a = test_session_key(1001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(1002, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        // Flow A: single packet. Enqueue + drain fully. Bucket A
        // goes idle with head/tail=0.
        cos_queue_push_back(queue, test_flow_cos_item(1001, 1500));
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 0);
        assert_eq!(queue.queue_vtime, 1500);

        // Flow B: one packet, drain it. Advances queue_vtime to
        // 1500 + 800 = 2300 (small amount vs. flow A's lifetime).
        cos_queue_push_back(queue, test_flow_cos_item(1002, 800));
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 2300);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_b], 0);

        // Flow A returns with a 1200-byte packet. tail_finish[A]=0,
        // queue_vtime=2300 → max picks vtime → head = tail = 2300
        // + 1200 = 3500. This is the "brief-idle" re-anchor.
        cos_queue_push_back(queue, test_flow_cos_item(1001, 1200));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3500,
            "#785 Phase 3 brief-idle re-entry: first arm of max \
             (tail_finish=0 < queue_vtime=2300) must anchor at \
             queue_vtime + bytes",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 3500);

        // Flow A appends a second 900-byte packet on its now-
        // active bucket. tail_finish=3500 > queue_vtime=2300 →
        // max picks tail_finish → tail = 3500 + 900 = 4400. Head
        // unchanged (head packet is still the first one, 3500).
        cos_queue_push_back(queue, test_flow_cos_item(1001, 900));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3500,
            "#785 Phase 3 brief-idle re-entry: active-bucket \
             enqueue must NOT alter head (head packet didn't \
             change)",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 4400,
            "#785 Phase 3 brief-idle re-entry: second arm of max \
             (tail_finish=3500 > queue_vtime=2300) must anchor at \
             tail_finish + bytes",
        );
    }

    /// Pin the overflow bound on `flow_bucket_{head,tail}_finish_bytes`
    /// by driving the ACTUAL runtime field near `u64::MAX` and
    /// exercising the real enqueue path through
    /// `cos_queue_push_back`/`account_cos_queue_flow_enqueue`.
    ///
    /// Rust reviewer MEDIUM #2 (round-2): the prior revision
    /// recomputed the wrap-interval math in the test body and
    /// asserted `years_to_wrap > 40`. That is a calculator, not a
    /// pin — a regression that narrowed the field to u32, or swapped
    /// `saturating_add` for `+`, would have left this test green
    /// because the test never touched the field. This revision:
    ///
    ///   1. Drives `queue.queue_vtime` to `u64::MAX - 10_000`.
    ///   2. Enqueues a 9000-byte packet (MTU-size upper bound).
    ///   3. Asserts the bucket's head/tail finish DID NOT wrap AND
    ///      landed at exactly `u64::MAX - 10_000 + 9_000`.
    ///   4. Enqueues again at u64::MAX-adjacent vtime and asserts
    ///      the saturating_add path keeps the field bounded.
    ///
    /// A regression that changes the accumulator type to u32,
    /// replaces `saturating_add` with `+`, or widens the per-enqueue
    /// delta (e.g. by dividing by a small weight) will fail THIS
    /// test, not a recomputed calculator.
    #[test]
    fn mqfq_finish_time_u64_has_decades_of_headroom() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Largest plausible single enqueue: MTU 9000 at weight 1.
        const MAX_SINGLE_DELTA: usize = 9_000;
        const SLACK: u64 = 10_000;
        let near_wrap = u64::MAX - SLACK;

        // Drive the runtime field near wrap by setting queue_vtime
        // (the re-anchor source for idle-bucket enqueue). The first
        // enqueue re-anchors head=tail=max(0, near_wrap)+9000 =
        // near_wrap + 9000 — well within u64 and exactly one delta
        // past queue_vtime.
        queue.queue_vtime = near_wrap;

        let flow_a = test_session_key(9999, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

        cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
        let expected_first = near_wrap + MAX_SINGLE_DELTA as u64;
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], expected_first,
            "first enqueue near u64 wrap must anchor at queue_vtime \
             + bytes; regression to u32 or non-saturating add would \
             fail here with a wrapped or truncated value",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], expected_first,
        );
        assert!(
            queue.flow_bucket_head_finish_bytes[bucket_a] > near_wrap,
            "finish time did not advance past pre-enqueue vtime — \
             type narrowed or wrap occurred",
        );

        // Second enqueue onto the ACTIVE bucket: tail advances by
        // MAX_SINGLE_DELTA, but saturating_add caps at u64::MAX.
        // With near_wrap + 2*9000 = u64::MAX - 10_000 + 18_000 =
        // u64::MAX + 8_000 — this SHOULD saturate to u64::MAX.
        cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
        let new_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        assert!(
            new_tail >= expected_first,
            "tail must monotonically advance; got {} < {}",
            new_tail,
            expected_first,
        );
        assert_eq!(
            new_tail,
            u64::MAX,
            "second enqueue must saturate at u64::MAX (input was \
             near_wrap + 2*9000 > u64::MAX); regression that replaces \
             saturating_add with `+` would panic on overflow in debug \
             builds or wrap in release builds",
        );

        // Head unchanged on active-bucket enqueue (head packet is
        // still the first one).
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], expected_first,
            "active-bucket enqueue must not alter head",
        );

        // Sanity-check the original calculator claim — 40+ years at
        // 100 Gbps — is still true. Kept alongside the real-field
        // pin above; the pin above is what would fail on regression.
        const WRAP_BYTES: u128 = 1u128 << 64;
        let bytes_per_sec: u128 = 100_000_000_000u128 / 8;
        let years_to_wrap = WRAP_BYTES / bytes_per_sec / 60 / 60 / 24 / 365;
        assert!(
            years_to_wrap > 40,
            "u64 finish-time headroom at 100 Gbps should exceed 40 \
             years of uptime, got {} years",
            years_to_wrap,
        );
    }

    #[test]
    fn exact_cos_flow_bucket_is_stable_for_same_seed_and_flow() {
        // Required property (#693): determinism inside one runtime instance.
        // Enqueue/dequeue bucket accounting would break if the same flow key
        // hashed to different buckets between push and pop. One random seed
        // drawn from the OS, same 5-tuple in, same bucket out, every time.
        let flow = test_session_key(9000, 5201);
        let seed = cos_flow_hash_seed_from_os();
        let first = cos_flow_bucket_index(seed, Some(&flow));
        for _ in 0..4096 {
            assert_eq!(first, cos_flow_bucket_index(seed, Some(&flow)));
        }
    }

    #[test]
    fn exact_cos_flow_bucket_diverges_across_seeds_for_same_flow() {
        // Required property (#693): the bucket mapping is not an externally-
        // probeable pure function of the 5-tuple. Two queues with different
        // seeds must be able to send the same flow into different buckets.
        // A deterministic hash would make this test a tautology that always
        // fails, so we scan seeds until we find a divergence; with a 64-bucket
        // output, collision rate is ~1/64 per seed pair, so 8192 attempts is
        // well below any reasonable flake tolerance (collision probability
        // ≈ (1/64)^8192 if the hash were uniform).
        let flow = test_session_key(9000, 5201);
        let reference = cos_flow_bucket_index(0, Some(&flow));
        let mut saw_divergence = false;
        for seed in 1u64..8192u64 {
            if cos_flow_bucket_index(seed, Some(&flow)) != reference {
                saw_divergence = true;
                break;
            }
        }
        assert!(
            saw_divergence,
            "hash must diverge across seeds; seed is not being mixed into the bucket function"
        );
    }

    #[test]
    fn exact_cos_flow_bucket_preserves_legacy_behavior_at_zero_seed() {
        // Required property (#693): preserve existing behavior for queues
        // with a zero seed. The pre-seed hash initialized `seed = protocol ^
        // (addr_family << 8)`; the seeded hash initializes `seed = queue_seed
        // ^ protocol ^ (addr_family << 8)`. At `queue_seed = 0` the two are
        // byte-identical. Pin this so a future refactor that reorders the
        // mix cannot silently change the bucket mapping under zero seed.
        let flow_v4 = test_session_key(1111, 5201);
        let mut flow_v6 = test_session_key(2222, 5201);
        flow_v6.src_ip = IpAddr::V6("2001:db8::1".parse().unwrap());
        flow_v6.dst_ip = IpAddr::V6("2001:db8::2".parse().unwrap());
        flow_v6.addr_family = libc::AF_INET6 as u8;
        let b_v4 = cos_flow_bucket_index(0, Some(&flow_v4));
        let b_v6 = cos_flow_bucket_index(0, Some(&flow_v6));
        // #711: hash-mix regression pins, updated for the bucket-count
        // grow from 64 → 1024. The hash function itself is unchanged
        // at seed=0; the values moved only because the mask widened
        // from 6 bits (0x3F) to 10 bits (0x3FF). Under the previous
        // 6-bit mask these values were 26 (v4) and 4 (v6); the
        // low 10 bits of the same hash output give the new pins below.
        // A refactor that reorders the mix or adds a term still fails
        // here and becomes an explicit decision. Update baselines only
        // after live re-validation of 5201 fairness on the loss HA
        // cluster.
        // Sanity: low 6 bits of the new pins equal the old pins
        // (26 and 4 respectively), confirming the mask-widening
        // interpretation above.
        assert_eq!(b_v4 & 0x3F, 26);
        assert_eq!(b_v6 & 0x3F, 4);
        assert_eq!(b_v4, 410);
        assert_eq!(b_v6, 260);
    }

    #[test]
    fn exact_cos_flow_bucket_handles_missing_flow_key() {
        // An item without a flow_key (e.g. a non-TCP/UDP frame, or a
        // pre-session packet) must still produce a valid bucket. Pick
        // bucket 0 deterministically so these items share one SFQ lane
        // rather than splaying across the ring and inflating
        // active_flow_buckets.
        assert_eq!(cos_flow_bucket_index(0, None), 0);
        assert_eq!(cos_flow_bucket_index(0x1234_5678_9abc_def0, None), 0);
    }

    #[test]
    fn exact_cos_flow_bucket_distribution_at_1024_keeps_collisions_below_budget() {
        // #711 correctness pin. The whole point of growing buckets
        // 64 → 1024 is collision reduction. A hash-mix regression can
        // produce acceptable distribution on one seed while clustering
        // badly under others; a single-seed test is too easy to
        // accidentally satisfy. Exercise multiple deterministic seeds
        // and mix v4/v6 tuples so the guarantee covers a realistic
        // traffic shape.
        //
        // Theoretical baseline for 64 uniform flows into 1024 buckets:
        // E[colliding pairs] ≈ 64·63/(2·1024) ≈ 1.97 — so ~62-63
        // distinct buckets on average. A budget of 58/64 per seed is
        // ~2 sigma conservative under a uniform-hash null hypothesis;
        // if this test fires, the hash function has become materially
        // non-uniform and the fairness guarantee is silently gone.
        use std::collections::BTreeSet;

        let seeds: [u64; 3] = [0, 0xA5A5_0000_C3C3_FFFF, 0x0123_4567_89AB_CDEF];
        for &seed in &seeds {
            let mut buckets = BTreeSet::new();
            for i in 0..64u16 {
                let mut flow = test_session_key(10_000 + i, 5201);
                // Alternate between v4 and v6 tuples so the test
                // exercises both address-family branches of the hash.
                if i & 1 == 1 {
                    flow.addr_family = libc::AF_INET6 as u8;
                    let v6 = format!("2001:db8::{i:x}")
                        .parse::<std::net::Ipv6Addr>()
                        .expect("v6 literal");
                    flow.src_ip = IpAddr::V6(v6);
                    flow.dst_ip = IpAddr::V6(
                        "2001:db8::5201"
                            .parse::<std::net::Ipv6Addr>()
                            .expect("v6 literal"),
                    );
                }
                buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
            }
            assert!(
                buckets.len() >= 58,
                "seed={:#x}: 64 flows landed in only {} distinct buckets — \
                 hash distribution regressed",
                seed,
                buckets.len()
            );
            assert!(
                buckets.iter().all(|&b| b < COS_FLOW_FAIR_BUCKETS),
                "bucket index out of range after mask: seed={seed:#x}"
            );
        }
    }

    /// #784 regression pin: narrow-input flow distribution.
    ///
    /// The iperf3-style workload hits an SFQ bucket collision
    /// cliff that the mixed-v4/v6 distribution test above misses:
    /// 12 flows to the same (src_ip, dst_ip, dst_port, proto,
    /// addr_family) differing only in src_port (consecutive
    /// ephemeral range, all v4 TCP). Real-world iperf3 reports
    /// 3 flows at ~145 Mbps with 0 retrans and 9 flows at
    /// ~60 Mbps with thousands of retrans each — caused by
    /// multiple flows landing on the same SFQ bucket and having
    /// their flow_share caps shrunk (each bucket's share = total
    /// buffer / prospective_active_flows, halved/thirded if a
    /// bucket holds 2-3 flows).
    ///
    /// Budget: for 12 narrow-input flows in 1024 buckets under a
    /// good hash, E[colliding pairs] ≈ 12*11/(2*1024) ≈ 0.06 —
    /// essentially always 12 distinct buckets. Under the prior
    /// boost-style hash_combine, narrow inputs observably collapse
    /// to 3-6 distinct buckets across most seeds. Demand >=11
    /// distinct buckets (allowing one pair collision worst-case
    /// under uniform null).
    ///
    /// Adversarial review posture: if this test ever weakens to
    /// accept fewer distinct buckets, or drops the all-v4 shape,
    /// the iperf3 fairness regression WILL return silently.
    #[test]
    fn exact_cos_flow_bucket_distribution_narrow_inputs_all_v4() {
        use std::collections::BTreeSet;

        // Production-like ephemeral port range. Linux kernel's
        // default ephemeral range is 32768-60999; 12 consecutive
        // ports starting at 39754 matches the actual iperf3
        // capture that motivated this test.
        let ports: Vec<u16> = (39754..39754 + 12).collect();
        // Test multiple seeds so a hash-mix fix cannot pass by
        // accident on a lucky seed. Including 0 pins the
        // pre-flow-fair default.
        let seeds: [u64; 5] = [
            0,
            0xA5A5_0000_C3C3_FFFF,
            0x0123_4567_89AB_CDEF,
            0xFFFF_FFFF_FFFF_FFFF,
            0xDEAD_BEEF_CAFE_BABE,
        ];
        for &seed in &seeds {
            let mut buckets = BTreeSet::new();
            for port in &ports {
                let flow = test_session_key(*port, 5201);
                // Explicitly v4 TCP — no mixed-family shortcut.
                assert_eq!(flow.addr_family, libc::AF_INET as u8);
                buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
            }
            assert!(
                buckets.len() >= 11,
                "seed={:#x}: 12 all-v4 iperf3-style flows landed in only {} distinct \
                 buckets — SFQ fairness regression. This is the flow-spread bug from #784; \
                 if this fires, the hash function is not spreading narrow-variance inputs \
                 (identical src_ip/dst_ip/dst_port/proto/family, only src_port differs).",
                seed,
                buckets.len()
            );
        }
    }

    /// #784 companion: also pin the wider 12-flow case with
    /// non-consecutive src_ports (simulating a different
    /// ephemeral-port allocator or long-running connections
    /// from different source processes).
    #[test]
    fn exact_cos_flow_bucket_distribution_narrow_inputs_scattered_ports() {
        use std::collections::BTreeSet;
        // 12 src_ports scattered across the ephemeral range.
        let ports: [u16; 12] = [
            33000, 35719, 38112, 41003, 43517, 46281, 48907, 51214, 53841, 56118, 58792, 60999,
        ];
        let seeds: [u64; 3] = [0, 0xA5A5_0000_C3C3_FFFF, 0x0123_4567_89AB_CDEF];
        for &seed in &seeds {
            let mut buckets = BTreeSet::new();
            for port in &ports {
                let flow = test_session_key(*port, 5201);
                buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
            }
            assert!(
                buckets.len() >= 11,
                "seed={:#x}: 12 scattered all-v4 flows landed in only {} distinct \
                 buckets — SFQ hash regression on non-consecutive src_ports",
                seed,
                buckets.len()
            );
        }
    }

    #[test]
    fn build_cos_interface_runtime_leaves_flow_hash_seed_zero_until_promotion() {
        // The seed is drawn in `ensure_cos_interface_runtime`, not in
        // `build_cos_interface_runtime`. Pin this so a refactor that
        // accidentally moves the getrandom call into the builder is
        // caught: builder-time seeding would burn a syscall per non-
        // flow-fair queue and would also drift the struct doc invariant
        // that non-flow-fair queues keep seed=0.
        let root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        for queue in &root.queues {
            assert!(!queue.flow_fair);
            assert_eq!(queue.flow_hash_seed, 0);
        }
    }

    #[test]
    fn cos_flow_hash_seed_from_os_draws_nonzero_entropy() {
        // Regression guard for the degenerate "seed is always 0" case.
        // Does NOT distinguish getrandom(2) from the fallback path — either
        // source is acceptable to satisfy the not-all-zero invariant. The
        // fallback path's own quality is exercised indirectly by the
        // diverges-across-seeds test; here we only catch "seeding is wired
        // up end-to-end and produces non-zero output most of the time". A
        // single zero draw is possible, just astronomically unlikely for
        // four independent draws, so four-trial not-all-zero is a safe
        // floor.
        let mut any_nonzero = false;
        for _ in 0..4 {
            if cos_flow_hash_seed_from_os() != 0 {
                any_nonzero = true;
                break;
            }
        }
        assert!(any_nonzero, "seed source returned 0 on four draws in a row");
    }

    #[test]
    fn estimate_cos_queue_wakeup_tick_uses_token_deficits() {
        let mut root = test_cos_interface_runtime(0);
        root.tokens = 0;
        root.queues[0].tokens = 0;

        let wake_tick = estimate_cos_queue_wakeup_tick(
            root.tokens,
            root.shaping_rate_bytes,
            root.queues[0].tokens,
            root.queues[0].transmit_rate_bytes,
            1500,
            0,
            true,
        )
        .expect("wake tick");

        assert_eq!(wake_tick, 30);
    }

    #[test]
    fn estimate_cos_queue_wakeup_tick_ignores_queue_deficit_for_surplus() {
        let mut root = test_cos_interface_runtime(0);
        root.tokens = 0;
        root.queues[0].tokens = 0;

        let wake_tick = estimate_cos_queue_wakeup_tick(
            root.tokens,
            root.shaping_rate_bytes,
            root.queues[0].tokens,
            root.queues[0].transmit_rate_bytes,
            1500,
            0,
            false,
        )
        .expect("wake tick");

        assert_eq!(wake_tick, 30);
    }

    #[test]
    fn surplus_phase_selects_non_exact_queue_without_guarantee_tokens() {
        let mut root = test_cos_runtime_with_exact(false);
        root.tokens = 1500;
        root.queues[0].last_refill_ns = 1;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        let batch = select_cos_surplus_batch(&mut root, 1);

        assert!(matches!(
            batch,
            Some(CoSBatch::Local {
                phase: CoSServicePhase::Surplus,
                ..
            })
        ));
    }

    #[test]
    fn surplus_phase_skips_exact_queue_without_guarantee_tokens() {
        let mut root = test_cos_runtime_with_exact(true);
        root.tokens = 1500;
        root.queues[0].last_refill_ns = 1;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        assert!(select_cos_surplus_batch(&mut root, 1).is_none());
    }

    #[test]
    fn guarantee_phase_parks_non_exact_queue_on_root_only_wakeup() {
        let mut root = test_cos_runtime_with_exact(false);
        root.tokens = 0;
        root.queues[0].last_refill_ns = 1;
        root.queues[0].tokens = 0;
        root.queues[0].items.push_back(test_cos_item(1500));
        root.queues[0].queued_bytes = 1500;
        root.queues[0].runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        assert!(root.queues[0].parked);
        assert_eq!(root.queues[0].next_wakeup_tick, 30);
    }

    #[test]
    fn guarantee_phase_limits_service_to_visit_quantum() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 64 * 1024;
        root.queues[0].tokens = 64 * 1024;
        root.queues[0].runnable = true;
        for _ in 0..4 {
            root.queues[0].items.push_back(test_cos_item(1500));
        }
        root.queues[0].queued_bytes = 4 * 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
        match batch {
            CoSBatch::Local { items, .. } => assert_eq!(items.len(), 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(root.queues[0].items.len(), 3);
    }

    #[test]
    fn guarantee_phase_allows_larger_high_rate_visit_quantum() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000u64 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000u64 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 256 * 1024,
                dscp_rewrite: None,
            }],
        );
        root.tokens = 256 * 1024;
        root.queues[0].tokens = 256 * 1024;
        root.queues[0].runnable = true;
        for _ in 0..200 {
            root.queues[0].items.push_back(test_cos_item(1500));
        }
        root.queues[0].queued_bytes = 200 * 1500;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;

        // #920: TX_BATCH_SIZE lowered 256 → 64 caps a single visit at
        // 64 items even when token budget would permit more (~166).
        // The remaining tokens stay with the queue for the next visit;
        // throughput is preserved across multiple shorter visits, with
        // the trade-off that mouse packets get an interleave point
        // every 64 packets instead of every 256.
        let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
        match batch {
            CoSBatch::Local { items, .. } => assert_eq!(items.len(), TX_BATCH_SIZE),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(root.queues[0].items.len(), 200 - TX_BATCH_SIZE);
    }

    /// #920: separate from the batch-cap test above. Asserts the
    /// rate-quantum invariant guarded by the original test name —
    /// a 10 Gbps queue gets a strictly larger byte-budget visit
    /// quantum than a 100 Mbps queue, regardless of TX_BATCH_SIZE.
    /// Guards against silent regression if `cos_guarantee_quantum_bytes`
    /// stops scaling with `transmit_rate_bytes`.
    #[test]
    fn guarantee_phase_quantum_scales_with_rate() {
        // cos_guarantee_quantum_bytes is already imported at the top of tx.rs (cfg(test) block).
        let high_rate = test_cos_runtime_with_queues(
            10_000_000_000u64 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000u64 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 256 * 1024,
                dscp_rewrite: None,
            }],
        );
        let low_rate = test_cos_runtime_with_queues(
            100_000_000u64 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-low".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000u64 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 256 * 1024,
                dscp_rewrite: None,
            }],
        );
        let high_q = cos_guarantee_quantum_bytes(&high_rate.queues[0]);
        let low_q = cos_guarantee_quantum_bytes(&low_rate.queues[0]);
        assert!(
            high_q > low_q,
            "high-rate quantum ({high_q}) must exceed low-rate quantum ({low_q})"
        );
    }

    #[test]
    fn guarantee_phase_rotates_between_backlogged_queues() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        root.tokens = 64 * 1024;
        for queue in &mut root.queues {
            queue.tokens = 64 * 1024;
            queue.runnable = true;
            queue.items.push_back(test_cos_item(1500));
            queue.items.push_back(test_cos_item(1500));
            queue.queued_bytes = 2 * 1500;
        }
        root.nonempty_queues = 2;
        root.runnable_queues = 2;

        let first = select_cos_guarantee_batch(&mut root, 1).expect("first guarantee batch");
        let second = select_cos_guarantee_batch(&mut root, 1).expect("second guarantee batch");

        match first {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 0),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        match second {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
    }


    #[test]
    fn exact_and_nonexact_guarantee_rr_cursors_advance_independently() {
        // #689 regression. Prior to the cursor split, serving an exact
        // queue advanced the shared `guarantee_rr` and could cause the
        // non-exact pass to skip a waiting queue on its next run. Pin
        // that the exact pass does not touch `nonexact_guarantee_rr`
        // and vice versa.
        let mut root = test_mixed_class_root_with_primed_queues();
        assert_eq!(root.exact_guarantee_rr, 0);
        assert_eq!(root.nonexact_guarantee_rr, 0);

        // Serving an exact queue must not disturb the non-exact cursor.
        let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
            .expect("exact queue selection");
        assert_eq!(selection.queue_idx, 0);
        assert_eq!(
            root.exact_guarantee_rr, 1,
            "exact cursor must advance past the served queue"
        );
        assert_eq!(
            root.nonexact_guarantee_rr, 0,
            "serving an exact queue must not advance the non-exact cursor"
        );

        // Serving a non-exact queue must not disturb the exact cursor.
        let batch =
            select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact queue batch");
        match batch {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(
            root.exact_guarantee_rr, 1,
            "non-exact service must not advance the exact cursor"
        );
        assert_eq!(
            root.nonexact_guarantee_rr, 2,
            "non-exact cursor must advance past the served queue"
        );
    }

    #[test]
    fn exact_guarantee_rr_walks_exact_queues_in_order_independent_of_nonexact() {
        // Exact queues must rotate exact-0 -> exact-2 -> exact-0 -> exact-2
        // regardless of non-exact activity between calls. #689 before-fix
        // behavior under the shared cursor was: exact-0 served (rr=1),
        // then a non-exact service would bump rr past exact-2's position,
        // so the next exact call would skip exact-2 and loop back to
        // exact-0. This test pins that the split cursor rotates exact
        // queues deterministically without regard for non-exact service.
        // Helper primes eight 1500-byte items and sets `queued_bytes`
        // to match; no additional priming needed here. Only bump
        // queue.tokens on the exact queues to make sure they never hit
        // token-starvation during the four interleaved rounds below —
        // the exact selector does not refill exact-queue tokens itself
        // (that is done by the shared-lease path), so this test bypasses
        // that machinery by handing the queues a large local budget.
        let mut root = test_mixed_class_root_with_primed_queues();
        for queue in &mut root.queues {
            if queue.exact {
                queue.tokens = 128 * 1024;
            }
        }

        let mut exact_order = Vec::new();
        for _ in 0..4 {
            // Interleave a non-exact service between exact calls; the exact
            // rotation must not notice.
            let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
                .expect("exact queue");
            exact_order.push(selection.queue_idx);
            // Service a non-exact queue to simulate concurrent class activity;
            // ignore the result.
            let _ = select_nonexact_cos_guarantee_batch(&mut root, 1);
        }
        assert_eq!(exact_order, vec![0, 2, 0, 2]);
    }

    #[test]
    fn nonexact_guarantee_rr_walks_nonexact_queues_in_order_independent_of_exact() {
        // Symmetric to the exact test: non-exact rotation is 1 -> 3 -> 1 -> 3
        // regardless of exact-queue activity between calls. Helper primes
        // eight 1500-byte items per queue with `queued_bytes` already
        // consistent; no additional priming needed.
        let mut root = test_mixed_class_root_with_primed_queues();

        let mut nonexact_order = Vec::new();
        for _ in 0..4 {
            let batch = select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact batch");
            let queue_idx = match batch {
                CoSBatch::Local { queue_idx, .. } => queue_idx,
                CoSBatch::Prepared { queue_idx, .. } => queue_idx,
            };
            nonexact_order.push(queue_idx);
            // Interleave an exact service; must not disturb non-exact rotation.
            let _ = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
        }
        assert_eq!(nonexact_order, vec![1, 3, 1, 3]);
    }

    #[test]
    fn legacy_guarantee_rr_does_not_advance_class_cursors() {
        // The entire reason `legacy_guarantee_rr` exists as a third cursor
        // (instead of the legacy unified selector reusing one of the
        // production cursors) is to keep the legacy walk isolated from the
        // production exact/nonexact rotation state. Pin that contract:
        // a call through the legacy selector must advance only its own
        // cursor, never the two production cursors.
        let mut root = test_mixed_class_root_with_primed_queues();
        let batch = select_cos_guarantee_batch(&mut root, 1).expect("legacy guarantee batch");
        // Served something, so `legacy_guarantee_rr` advanced.
        match batch {
            CoSBatch::Local { queue_idx, .. } => {
                assert_eq!(queue_idx, 0, "legacy walk starts at index 0");
            }
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        assert_eq!(root.legacy_guarantee_rr, 1);
        // Production cursors untouched — this is the isolation guarantee
        // that justifies the extra field over reusing either production
        // cursor for the legacy walk.
        assert_eq!(
            root.exact_guarantee_rr, 0,
            "legacy selector must not advance exact production cursor"
        );
        assert_eq!(
            root.nonexact_guarantee_rr, 0,
            "legacy selector must not advance nonexact production cursor"
        );
    }

    #[test]
    fn guarantee_rr_cursors_start_at_zero_after_runtime_build() {
        // Pin the invariant that a fresh runtime starts with both cursors
        // at 0. `build_cos_interface_runtime` is the one production init
        // site; any refactor that accidentally leaves a cursor uninitialized
        // or drops one of the fields fails here.
        let root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "q0".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        assert_eq!(root.exact_guarantee_rr, 0);
        assert_eq!(root.nonexact_guarantee_rr, 0);
        assert_eq!(root.legacy_guarantee_rr, 0);
    }

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
    fn surplus_phase_prefers_higher_priority_queue() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "bulk".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "voice".into(),
                    priority: 0,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        root.tokens = 64 * 1024;
        for queue in &mut root.queues {
            queue.last_refill_ns = 1;
            queue.tokens = 0;
            queue.runnable = true;
            queue.items.push_back(test_cos_item(1500));
            queue.queued_bytes = 1500;
        }
        root.nonempty_queues = 2;
        root.runnable_queues = 2;

        assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
        let batch = select_cos_surplus_batch(&mut root, 1).expect("surplus batch");
        match batch {
            CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
    }

    #[test]
    fn surplus_phase_applies_weighted_same_priority_sharing() {
        let mut root = test_cos_runtime_with_queues(
            100_000_000,
            vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "small".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "large".into(),
                    priority: 5,
                    transmit_rate_bytes: 4_000_000,
                    exact: false,
                    surplus_weight: 4,
                    buffer_bytes: COS_MIN_BURST_BYTES,
                    dscp_rewrite: None,
                },
            ],
        );
        root.tokens = 64 * 1024;
        for queue in &mut root.queues {
            queue.last_refill_ns = 1;
            queue.tokens = 0;
            queue.runnable = true;
            for _ in 0..8 {
                queue.items.push_back(test_cos_item(1500));
            }
            queue.queued_bytes = 8 * 1500;
        }
        root.nonempty_queues = 2;
        root.runnable_queues = 2;

        let first = select_cos_surplus_batch(&mut root, 1).expect("first surplus batch");
        let second = select_cos_surplus_batch(&mut root, 1).expect("second surplus batch");

        match first {
            CoSBatch::Local {
                queue_idx, items, ..
            } => {
                assert_eq!(queue_idx, 0);
                assert_eq!(items.len(), 1);
            }
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
        match second {
            CoSBatch::Local {
                queue_idx, items, ..
            } => {
                assert_eq!(queue_idx, 1);
                assert_eq!(items.len(), 4);
            }
            CoSBatch::Prepared { .. } => panic!("expected local batch"),
        }
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

    #[test]
    fn normalize_cos_queue_state_repairs_nonempty_unparked_queue_to_runnable() {
        let mut queue = CoSQueueRuntime {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            exact: true,
            flow_fair: false,
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 1500,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::from([test_cos_item(1500)]),
            local_item_count: 0,

            vtime_floor: None,

            worker_id: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
        };

        normalize_cos_queue_state(&mut queue);

        assert!(queue.runnable);
        assert!(!queue.parked);
        assert_eq!(queue.next_wakeup_tick, 0);
    }

    #[test]
    fn restore_cos_local_items_marks_queue_runnable_after_retry() {
        let mut queue = CoSQueueRuntime {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            exact: true,
            flow_fair: false,
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,

            vtime_floor: None,

            worker_id: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
        };
        let retry = VecDeque::from([TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
        }]);

        let retry_bytes = restore_cos_local_items_inner(&mut queue, retry);

        assert_eq!(queue.items.len(), 1);
        assert_eq!(retry_bytes, 1500);
        assert!(queue.runnable);
        assert!(!queue.parked);
    }

    #[test]
    fn restore_cos_prepared_items_marks_queue_runnable_after_retry() {
        let mut queue = CoSQueueRuntime {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            exact: true,
            flow_fair: false,
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,

            vtime_floor: None,

            worker_id: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
        };
        let retry = VecDeque::from([PreparedTxRequest {
            offset: 64,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
        }]);

        let retry_bytes = restore_cos_prepared_items_inner(&mut queue, retry);

        assert_eq!(queue.items.len(), 1);
        assert_eq!(retry_bytes, 1500);
        assert!(queue.runnable);
        assert!(!queue.parked);
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

    #[test]
    fn count_park_reason_helper_advances_exact_counter() {
        // Low-level test of the helper itself — paranoia pin against a
        // refactor that accidentally writes to the wrong field.
        let mut root = test_cos_runtime_with_exact(true);
        let before = snapshot_counters(&root.queues[0]);

        count_park_reason(&mut root, 0, ParkReason::RootTokenStarvation);
        let mid = snapshot_counters(&root.queues[0]);
        assert_eq!(
            mid.root_token_starvation_parks,
            before.root_token_starvation_parks + 1
        );
        assert_eq!(
            mid.queue_token_starvation_parks,
            before.queue_token_starvation_parks
        );

        count_park_reason(&mut root, 0, ParkReason::QueueTokenStarvation);
        let after = snapshot_counters(&root.queues[0]);
        assert_eq!(
            after.queue_token_starvation_parks,
            before.queue_token_starvation_parks + 1
        );
        assert_eq!(
            after.root_token_starvation_parks,
            mid.root_token_starvation_parks
        );

        // Out-of-range queue_idx is a no-op, not a panic.
        count_park_reason(&mut root, 999, ParkReason::RootTokenStarvation);
        assert_eq!(
            snapshot_counters(&root.queues[0]).root_token_starvation_parks,
            after.root_token_starvation_parks
        );
    }

    // ---------------------------------------------------------------------
    // #718 ECN CE-marking. The markers are the load-bearing helpers;
    // the admission-path tests exercise `apply_cos_admission_ecn_policy`
    // which is what `enqueue_cos_item` calls in-line. Keep the marker
    // tests byte-precise so a future refactor that flips an endian /
    // offset / masks a different bit fails loudly.
    // ---------------------------------------------------------------------





    #[test]
    fn mark_ecn_ce_ipv4_converts_ect0_to_ce_and_updates_checksum() {
        // ECT(0) = 0b10 in the low 2 bits of the TOS byte. Pick a
        // non-zero DSCP (0x28 = CS5 = expedited forwarding) to verify
        // the upper 6 bits survive the mark. TOS before = 0xa2.
        let tos = (0x28u8 << 2) | ECN_ECT_0;
        let mut pkt = build_ipv4_test_packet(tos);
        assert_eq!(ipv4_tos(&pkt), 0xa2);
        let csum_before = ipv4_checksum(&pkt);

        assert!(mark_ecn_ce_ipv4(&mut pkt, 14));

        // Low 2 bits now CE, upper 6 bits (DSCP) unchanged.
        assert_eq!(ipv4_tos(&pkt) & ECN_MASK, ECN_CE);
        assert_eq!(ipv4_tos(&pkt) >> 2, 0x28);
        // Checksum must differ from the before-state (ECN flipped one
        // bit in the low byte) AND be valid from scratch.
        assert_ne!(
            ipv4_checksum(&pkt),
            csum_before,
            "ECN bit flip must change the IP checksum",
        );
        assert_eq!(
            ipv4_checksum(&pkt),
            compute_ipv4_header_checksum(&pkt[14..34]),
            "incremental checksum must match a from-scratch recompute",
        );
    }

    #[test]
    fn mark_ecn_ce_ipv4_converts_ect1_to_ce_and_updates_checksum() {
        // ECT(1) = 0b01. DSCP = 0, so TOS starts at 0x01 — stresses
        // the case where the high nibble is zero and only the low
        // bits mutate.
        let tos = ECN_ECT_1;
        let mut pkt = build_ipv4_test_packet(tos);

        assert!(mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(ipv4_tos(&pkt), ECN_CE);
        assert_eq!(
            ipv4_checksum(&pkt),
            compute_ipv4_header_checksum(&pkt[14..34]),
        );
    }

    #[test]
    fn mark_ecn_ce_ipv4_leaves_not_ect_untouched() {
        // NOT-ECT packet must be left entirely alone — RFC 3168 6.1.1.1
        // forbids forcing ECN on flows that did not negotiate it.
        let tos = 0xb8; // DSCP 46 (EF), ECN = 00
        let mut pkt = build_ipv4_test_packet(tos);
        let before = pkt.clone();

        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(pkt, before, "NOT-ECT packet must be byte-identical");
    }

    #[test]
    fn mark_ecn_ce_ipv4_leaves_ce_untouched() {
        // CE already — idempotent: function reports "not marked" but
        // also doesn't re-write the checksum, so bytes stay identical.
        let tos = 0xb8 | ECN_CE;
        let mut pkt = build_ipv4_test_packet(tos);
        let before = pkt.clone();

        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(pkt, before, "CE packet must be byte-identical");
    }

    #[test]
    fn mark_ecn_ce_ipv4_rejects_short_buffer() {
        // Buffer too short to hold a full 20-byte IPv4 header starting
        // at l3_offset=14 (only 33 bytes — one short). Must return
        // false and not panic.
        let mut pkt = vec![0u8; 33];
        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));

        // Also exercise the case where `l3_offset` itself pushes past
        // the buffer end.
        let mut pkt = vec![0u8; 16];
        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
    }



    #[test]
    fn mark_ecn_ce_ipv6_converts_ect0_to_ce() {
        // DSCP 46 (EF) + ECT(0) → full tclass 0xba.
        let tclass = (0x2eu8 << 2) | ECN_ECT_0;
        let mut pkt = build_ipv6_test_packet(tclass);
        assert_eq!(ipv6_tclass(&pkt), 0xba);
        // Preserve flow label / version bits for the round-trip check.
        let version_nibble_before = pkt[14] & 0xf0;
        let flow_label_low_before = pkt[15] & 0x0f;

        assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(ipv6_tclass(&pkt) & ECN_MASK, ECN_CE);
        assert_eq!(ipv6_tclass(&pkt) >> 2, 0x2e);
        // Version + flow-label bits must not drift.
        assert_eq!(pkt[14] & 0xf0, version_nibble_before);
        assert_eq!(pkt[15] & 0x0f, flow_label_low_before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_converts_ect1_to_ce() {
        let tclass = ECN_ECT_1;
        let mut pkt = build_ipv6_test_packet(tclass);
        assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(ipv6_tclass(&pkt), ECN_CE);
    }

    #[test]
    fn mark_ecn_ce_ipv6_leaves_not_ect_untouched() {
        let tclass = 0xb8; // DSCP 46, ECN 00
        let mut pkt = build_ipv6_test_packet(tclass);
        let before = pkt.clone();
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(pkt, before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_leaves_ce_untouched() {
        let tclass = 0xb8 | ECN_CE;
        let mut pkt = build_ipv6_test_packet(tclass);
        let before = pkt.clone();
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(pkt, before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_rejects_short_buffer() {
        let mut pkt = vec![0u8; 15];
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
    }

    #[test]
    fn maybe_mark_ecn_ce_dispatches_by_addr_family() {
        // IPv4 dispatch: ECT(0) → CE.
        let tos = ECN_ECT_0;
        let bytes = build_ipv4_test_packet(tos);
        let mut req = TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(maybe_mark_ecn_ce(&mut req));
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE);

        // IPv6 dispatch: ECT(1) → CE.
        let tclass = ECN_ECT_1;
        let bytes = build_ipv6_test_packet(tclass);
        let mut req = TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(maybe_mark_ecn_ce(&mut req));
        assert_eq!(ipv6_tclass(&req.bytes), ECN_CE);

        // Unknown address family: no-op (and no panic).
        let mut req = TxRequest {
            bytes: vec![0u8; 64],
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(!maybe_mark_ecn_ce(&mut req));
    }

    /// Regression pin for the VLAN-tagged admission path discovered in
    /// the #727 live validation: a single 802.1Q tag (ethertype 0x8100)
    /// pushes L3 four bytes deeper. `maybe_mark_ecn_ce` must detect
    /// that via `ethernet_l3_offset` and still mark the ECN bits at
    /// the correct offset rather than stamping into the VLAN TCI.
    #[test]
    fn maybe_mark_ecn_ce_handles_single_vlan_tagged_frame() {
        // Build a standard IPv4 test packet, then splice a 4-byte VLAN
        // tag between the MAC addresses and the ethertype. The result
        // is: 6 dst + 6 src + TPID(0x8100) + TCI(VID=80, prio=5) +
        //     EthType(0x0800) + <20-byte IPv4 header>.
        let tos = ECN_ECT_0;
        let base = build_ipv4_test_packet(tos);
        let mut tagged = Vec::with_capacity(base.len() + 4);
        tagged.extend_from_slice(&base[..12]); // dst + src MAC
        tagged.extend_from_slice(&[0x81, 0x00]); // TPID
        // TCI: priority 5 << 13 | DEI 0 | VID 80.
        let tci: u16 = (5 << 13) | 80;
        tagged.extend_from_slice(&tci.to_be_bytes());
        tagged.extend_from_slice(&[0x08, 0x00]); // inner ethertype (IPv4)
        tagged.extend_from_slice(&base[14..]); // IPv4 header + payload

        // Confirm `ethernet_l3` parses IPv4 at offset 18 for this frame.
        assert_eq!(ethernet_l3(&tagged), Some(EthernetL3::Ipv4(18)));

        let mut req = TxRequest {
            bytes: tagged,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        assert!(
            maybe_mark_ecn_ce(&mut req),
            "VLAN-tagged ECT(0) frame must be marked at the VLAN-shifted L3 offset"
        );
        // TOS byte sits at l3_offset + 1 = 19 in the tagged frame.
        assert_eq!(req.bytes[19] & ECN_MASK, ECN_CE);
        // And critically: the VLAN TCI bytes must NOT have been
        // mutated — if the old hardcoded offset 14 had hit, the "ECN
        // bits" we'd have touched are inside the VLAN priority nibble
        // at byte 15, which we assert stayed intact.
        let tci_after = u16::from_be_bytes([req.bytes[14], req.bytes[15]]);
        assert_eq!(
            tci_after, tci,
            "VLAN TCI must be untouched by ECN marking"
        );
    }

    /// Counter-factual: ethertype 0 (or anything we don't understand)
    /// returns `None` from `ethernet_l3`, so marking is a no-op.
    /// Guards against a regression that defaults to offset 14 on
    /// unknown frames.
    #[test]
    fn maybe_mark_ecn_ce_rejects_unknown_ethertype() {
        let mut req = TxRequest {
            bytes: {
                let mut b = build_ipv4_test_packet(ECN_ECT_0);
                b[12] = 0x12;
                b[13] = 0x34;
                b
            },
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert_eq!(ethernet_l3(&req.bytes), None);
        assert!(!maybe_mark_ecn_ce(&mut req));
        // ECT(0) bits at the would-have-been-wrong-offset untouched.
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
    }

    /// QinQ (0x88A8 outer + 0x8100 inner) must be rejected rather than
    /// guessed at, because L3 actually lives at offset 22 on those
    /// frames and a default to 18 would stamp into the inner VLAN TCI.
    /// #728 review pin: once we've paid to parse the outer ethertype,
    /// the parse must be the source of truth.
    #[test]
    fn ethernet_l3_rejects_qinq_until_explicitly_supported() {
        let base = build_ipv4_test_packet(ECN_ECT_0);
        let mut qinq = Vec::with_capacity(base.len() + 8);
        qinq.extend_from_slice(&base[..12]); // MACs
        // Outer 802.1ad: TPID 0x88A8, TCI with an outer VID 100.
        qinq.extend_from_slice(&[0x88, 0xA8]);
        let outer_tci: u16 = 100;
        qinq.extend_from_slice(&outer_tci.to_be_bytes());
        // Inner 802.1Q: TPID 0x8100 at the "inner ethertype" position.
        qinq.extend_from_slice(&[0x81, 0x00]);
        let inner_tci: u16 = 80;
        qinq.extend_from_slice(&inner_tci.to_be_bytes());
        qinq.extend_from_slice(&[0x08, 0x00]); // IPv4 (well beyond where we care)
        qinq.extend_from_slice(&base[14..]);

        assert_eq!(
            ethernet_l3(&qinq),
            None,
            "QinQ (0x88A8 → 0x8100) must be rejected — inner VLAN tag not yet supported"
        );

        // And the marker refuses such a frame — no ECN bits are flipped.
        let mut req = TxRequest {
            bytes: qinq,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        assert!(!maybe_mark_ecn_ce(&mut req));
    }

    /// A VLAN-tagged frame whose inner ethertype is ARP / MPLS / etc.
    /// must be rejected too, matching the `refuse to guess` contract.
    /// Without this check we'd treat offset 18 as an IPv4 TOS byte and
    /// stamp the low 2 bits of whatever is there (ARP's hardware type
    /// in this case), corrupting the frame.
    #[test]
    fn ethernet_l3_rejects_vlan_tagged_non_ip_payload() {
        let base = build_ipv4_test_packet(ECN_ECT_0);
        let mut tagged = Vec::with_capacity(base.len() + 4);
        tagged.extend_from_slice(&base[..12]);
        tagged.extend_from_slice(&[0x81, 0x00]); // outer 802.1Q
        let tci: u16 = 80;
        tagged.extend_from_slice(&tci.to_be_bytes());
        tagged.extend_from_slice(&[0x08, 0x06]); // inner = ARP (0x0806)
        tagged.extend_from_slice(&base[14..]);
        assert_eq!(
            ethernet_l3(&tagged),
            None,
            "VLAN-tagged non-IP payload must not dispatch to an IP marker",
        );
    }



    #[test]
    fn admission_ecn_marked_counter_increments_when_marking_above_threshold() {
        // Drive the queue to >50% of buffer_limit with an ECT(0) packet
        // incoming. The mark must fire; the counter must advance by
        // exactly one; no drop counters advance; the packet is "admitted"
        // (we run the decision in isolation, so we just assert `marked`).
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        // Half + 1 byte — strictly above the 50% threshold.
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        // Non-flow-fair queue: share_cap == buffer_limit, so both
        // thresholds collapse onto the aggregate one. `flow_bucket=0`
        // is unused beyond the (constant-returning) share-limit call.
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

        assert!(marked);
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
            "ECN counter must advance by 1",
        );
        assert_eq!(after.admission_flow_share_drops, before.admission_flow_share_drops);
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
        // Packet bytes now carry CE.
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE);
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_does_not_mark_below_threshold() {
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        // Exactly at the mark threshold — `>` comparison must not fire.
        // Written against the constants so retuning NUM/DEN doesn't
        // silently break this pin; at any fraction < 1, an at-threshold
        // queue must stay unmarked by the `>` comparison in
        // `apply_cos_admission_ecn_policy`.
        queue.queued_bytes =
            buffer_limit * COS_ECN_MARK_THRESHOLD_NUM / COS_ECN_MARK_THRESHOLD_DEN;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

        assert!(!marked, "at-threshold must not mark");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        // Packet bytes unchanged.
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_does_not_mark_non_ect_packets() {
        // Queue above threshold, but packet is NOT-ECT. Mark must not
        // fire and counter must not advance — RFC 3168 compliance.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_NOT_ECT);
        let umem = test_admission_umem();
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

        assert!(!marked);
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_NOT_ECT);
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_does_not_mark_when_drop_is_imminent() {
        // Queue above threshold AND flow-share/buffer exceeded: don't
        // burn the mark on a packet that's about to be dropped.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        // Signal that the caller already decided this packet will drop.
        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, true, false, &mut item, &umem);
        assert!(!marked, "flow_share_exceeded path must skip marking");
        let after_share = snapshot_counters(queue);
        assert_eq!(after_share.admission_ecn_marked, before.admission_ecn_marked);

        let marked =
            apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, true, &mut item, &umem);
        assert!(!marked, "buffer_exceeded path must skip marking");
        let after_buf = snapshot_counters(queue);
        assert_eq!(after_buf.admission_ecn_marked, before.admission_ecn_marked);

        // Packet bytes unchanged through both calls.
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
        } else {
            panic!("item must stay Local variant");
        }
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



    #[test]
    fn admission_ecn_marks_when_per_flow_above_threshold_aggregate_below() {
        // Live failure mode from #722: queue sits at ~31% utilisation
        // so the aggregate 50% threshold never trips, but a dominant
        // flow's bucket is past the per-flow 50% threshold and is
        // about to be dropped by the flow-share cap.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        // buffer_limit at 16 active flows: 16 × 24 KB = 384 KB (clamped
        // by delay_cap = 625 KB on a 1 Gbps queue @ 5 ms). share_cap =
        // 384000 / 16 = 24000. At the current NUM/DEN = 1/3 (33%) per
        // #754, the thresholds are aggregate = 384000 / 3 = 128_000 and
        // per-flow = 24000 / 3 = 8_000. If NUM/DEN is retuned, both
        // derived values move together — the asserts below are written
        // against concrete numbers (not the constants) so a future
        // retune fails the pin loudly, which is the whole point.
        let target_bucket_bytes = 15_000; // > 8 000 per-flow threshold with a generous margin
        let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        queue.queued_bytes = queued_bytes;
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        assert_eq!(buffer_limit, 384_000);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
        assert_eq!(share_cap, 24_000);
        let aggregate_ecn_threshold =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let flow_ecn_threshold =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        // Concrete expected values at NUM/DEN = 1/3: aggregate =
        // 384_000 / 3 = 128_000 and per-flow = 24_000 / 3 = 8_000.
        assert_eq!(
            aggregate_ecn_threshold, 128_000,
            "aggregate threshold must remain pinned for this fixture",
        );
        assert_eq!(
            flow_ecn_threshold, 8_000,
            "per-flow threshold must remain pinned for this fixture",
        );

        // Counter-factual: reconstruct the pre-#722 aggregate-only
        // formula and assert that on this exact state it would NOT
        // fire. This is what #718 did and why it missed the live
        // workload — keep this pin live so a future refactor that
        // drops the per-flow arm fails here loudly.
        assert!(
            queue.queued_bytes <= aggregate_ecn_threshold,
            "aggregate-only formula must fall below threshold on the #722 live state",
        );
        // And the per-flow arm must be above its threshold.
        assert!(queue.flow_bucket_bytes[target] > flow_ecn_threshold);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(marked, "per-flow arm must fire when aggregate is below");
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
            "ECN counter must advance by exactly 1",
        );
        assert_eq!(
            after.admission_flow_share_drops, before.admission_flow_share_drops,
            "mark is not a drop",
        );
        assert_eq!(
            after.admission_buffer_drops, before.admission_buffer_drops,
            "mark is not a drop",
        );
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE, "CE bit must be set");
        } else {
            panic!("item must stay Local variant");
        }
    }

    /// #784: SFQ fairness regression pin. The former behavior of
    /// the aggregate-above ECN arm actively broke per-flow fairness
    /// on iperf3 -P 12 against a 1 Gbps cap (3 winners at 145 Mbps
    /// with 0 retrans, 9 losers at 50-75 Mbps with thousands of
    /// retrans each). Removing the aggregate arm restored fairness
    /// because flows that hadn't filled their bucket no longer got
    /// penalised for OTHER flows' bursts.
    ///
    /// If this test ever flips to assert `marked` is true, the
    /// aggregate arm has been reintroduced and the iperf3 fairness
    /// regression in #784 WILL come back. Do not weaken this test.
    #[test]
    fn admission_ecn_does_not_mark_when_only_aggregate_above_threshold() {
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        let target_bucket_bytes = 500; // << per-flow threshold (8 000 B at 1/3)
        let _ = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
        let aggregate_ecn_threshold =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let flow_ecn_threshold =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        queue.queued_bytes = aggregate_ecn_threshold + 1; // strictly above

        assert!(queue.queued_bytes > aggregate_ecn_threshold);
        assert!(queue.flow_bucket_bytes[target] <= flow_ecn_threshold);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(
            !marked,
            "#784: aggregate arm must NOT fire — only per-flow threshold triggers marks. \
             If this assertion ever flips, the SFQ iperf3 -P 12 fairness regression returns."
        );
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    }

    #[test]
    fn admission_ecn_does_not_mark_when_both_thresholds_below() {
        // Both below — no congestion signal. Mark must stay off and
        // the counter unchanged. Packet bytes untouched.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        let target_bucket_bytes = 500; // < 8 000 (per-flow threshold at NUM/DEN = 1/3)
        let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        queue.queued_bytes = queued_bytes; // ≪ 128 000 (aggregate threshold at 1/3)
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
        let aggregate_ecn_threshold =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let flow_ecn_threshold =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        assert!(queue.queued_bytes <= aggregate_ecn_threshold);
        assert!(queue.flow_bucket_bytes[target] <= flow_ecn_threshold);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "no threshold tripped — no mark");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(
                req.bytes[15] & ECN_MASK,
                ECN_ECT_0,
                "packet bytes must be byte-identical below threshold",
            );
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_ecn_does_not_mark_when_flow_share_already_exceeded() {
        // Per-flow above threshold BUT the caller has also decided the
        // packet will drop (flow_share_exceeded = true). Preserves the
        // #718 invariant that we don't burn marks on doomed packets —
        // a marked-then-dropped packet wastes both the mark and the
        // bandwidth the mark was trying to steer.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        let target_bucket_bytes = 15_000; // > 8 000 per-flow threshold (NUM/DEN = 1/3)
        let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
        queue.queued_bytes = queued_bytes;
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);

        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            true,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "flow_share_exceeded must suppress the mark");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        if let CoSPendingTxItem::Local(req) = &item {
            assert_eq!(
                req.bytes[15] & ECN_MASK,
                ECN_ECT_0,
                "doomed packet must not be rewritten",
            );
        } else {
            panic!("item must stay Local variant");
        }
    }

    #[test]
    fn admission_ecn_per_flow_threshold_matches_share_cap_denominator() {
        // Pin that the per-flow threshold uses the SAME
        // NUM/DEN fraction as the aggregate threshold. If a future
        // refactor changes the constants (e.g. drops the aggregate
        // arm to 33%) without updating the per-flow arm, both arms
        // drift out of lockstep and this test fails. Computed from
        // the state as `share_cap × NUM / DEN` independently — no
        // internal call into the policy function.
        //
        // #784: seed with `target_bytes > 0` so prospective_active
        // stays at 16 both in the test's computed threshold and in
        // the policy's live recompute. Earlier revision seeded
        // target=0 and set the bucket above threshold later, which
        // shifted prospective_active from 17 → 16 between compute
        // and policy call and silently passed on the aggregate arm.
        let mut root = test_flow_fair_exact_queue_16_flows();
        let queue = &mut root.queues[0];
        let target = 0usize;

        seed_sixteen_flow_buckets(queue, target, 1);
        let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);

        let expected_aggregate =
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
        let expected_flow =
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;

        // Ratio check: both thresholds must be exactly NUM/DEN of their
        // respective caps, i.e. `threshold × DEN == cap × NUM`. Stated
        // as multiplications so integer truncation does not mask drift.
        assert_eq!(
            expected_aggregate.saturating_mul(COS_ECN_MARK_THRESHOLD_DEN),
            buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM),
            "aggregate threshold must be NUM/DEN of buffer_limit",
        );
        assert_eq!(
            expected_flow.saturating_mul(COS_ECN_MARK_THRESHOLD_DEN),
            share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM),
            "per-flow threshold must be NUM/DEN of share_cap",
        );

        // Drive the policy at a state that trips BOTH arms and
        // verify the mark fires — proves the live code path uses
        // the same fractions we computed by hand.
        queue.queued_bytes = expected_aggregate + 1;
        queue.flow_bucket_bytes[target] = expected_flow + 1;
        let before = snapshot_counters(queue);
        let mut item = test_local_ipv4_item(ECN_ECT_0);
        let umem = test_admission_umem();
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            target,
            false,
            false,
            &mut item,
            &umem,
        );
        assert!(marked);
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked + 1);
    }

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


    /// #785 Phase 3 — pin that a high-rate exact queue
    /// (shared_exact=true) IS promoted onto the flow-fair path AND
    /// has its `shared_exact` shadow cached. The shadow drives the
    /// admission-gate downgrade (aggregate-only) in
    /// `cos_queue_flow_share_limit` and
    /// `apply_cos_admission_ecn_policy`. The MQFQ VFT ordering in
    /// `cos_queue_pop_front` is what actually enforces per-flow
    /// fairness on this queue — the share cap + per-flow ECN arm
    /// are rate-unaware (24 KB floor) and would tail-drop TCP at
    /// 25 Gbps. Retrospective Attempt A measured 22.3 → 16.3 Gbps +
    /// 25 k retrans when the cap was enforced on shared_exact;
    /// Phase 3 replaces the cap's fairness role with VFT ordering.
    #[test]
    fn queue_flow_fair_enabled_on_shared_exact() {
        use super::super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

        let high_rate_bytes = 25_000_000_000u64 / 8;
        assert!(
            high_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES,
            "fixture must be above the shared_exact threshold or the \
             test does not exercise the regression surface",
        );

        let mut runtime = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: high_rate_bytes,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        assert!(!runtime.queues[0].flow_fair);
        assert!(!runtime.queues[0].shared_exact);

        // Drive the full ensure_cos_interface_runtime promotion loop.
        let fast_path = vec![test_queue_fast_path_for_promotion(true)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

        assert!(
            runtime.queues[0].flow_fair,
            "#785 Phase 3: shared_exact queue MUST be promoted onto \
             the flow-fair path so MQFQ virtual-finish-time ordering \
             runs in the dequeue path. Regression here re-opens the \
             CoV gap we just measured closed.",
        );
        assert!(
            runtime.queues[0].shared_exact,
            "#785 Phase 3: shared_exact shadow MUST be cached onto \
             the runtime so the admission gates in \
             cos_queue_flow_share_limit and \
             apply_cos_admission_ecn_policy downgrade to \
             aggregate-only. Per-flow admission gates are rate-\
             unaware (24 KB floor) and would tail-drop TCP at \
             multi-Gbps per-flow rates.",
        );
        assert_ne!(
            runtime.queues[0].flow_hash_seed, 0,
            "seed must be drawn on flow-fair promotion so MQFQ \
             bucket assignment is not an externally-probeable \
             pure function of the 5-tuple",
        );
    }

    /// Pin that a low-rate exact queue (shared_exact=false) IS
    /// promoted onto the SFQ path AND has `shared_exact=false` on
    /// its runtime. The #784 fairness fix on the 1 Gbps iperf-a
    /// queue depends on BOTH halves: flow_fair=true so DRR orders
    /// per-flow, and shared_exact=false so the per-flow share cap
    /// + per-flow ECN arm still run (at 1 Gbps / 12 flows the cap is
    /// ~24 KB which matches TCP cwnd at 77 Mbps flows cleanly).
    #[test]
    fn queue_flow_fair_enabled_on_owner_local_exact() {
        use super::super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

        let low_rate_bytes = 1_000_000_000u64 / 8;
        assert!(
            low_rate_bytes < COS_SHARED_EXACT_MIN_RATE_BYTES,
            "fixture must be below the shared_exact threshold to \
             exercise the owner-local-exact path",
        );

        let mut runtime = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: low_rate_bytes,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let fast_path = vec![test_queue_fast_path_for_promotion(false)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

        assert!(
            runtime.queues[0].flow_fair,
            "owner-local-exact queue MUST be promoted onto the SFQ \
             path — #784 fairness fix depends on it",
        );
        assert!(
            !runtime.queues[0].shared_exact,
            "owner-local-exact queue MUST keep shared_exact=false so \
             the per-flow share cap and per-flow ECN arm continue to \
             run — #784 depends on the per-flow cap firing at 1 Gbps",
        );
        assert_ne!(
            runtime.queues[0].flow_hash_seed, 0,
            "seed must be drawn on flow-fair promotion — otherwise \
             every binding hashes flows identically and one flow's \
             RSS bucket collides across the whole deployment",
        );
    }

    /// Pin that a non-exact (best-effort) queue is NOT promoted onto
    /// the flow-fair path. SFQ would be wasted work on these queues:
    /// there is no per-flow rate contract, so per-flow isolation is
    /// meaningless, and drawing an OS random seed for every
    /// non-exact queue on every runtime build would add a syscall
    /// per queue for zero benefit. This pin also doubles as a sanity
    /// check that the gate did not collapse to
    /// `queue.flow_fair = true` unconditionally.
    #[test]
    fn queue_flow_fair_disabled_on_non_exact() {
        let mut runtime = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 3,
                transmit_rate_bytes: 0,
                exact: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );

        // Drive the production loop with shared_exact=false first,
        // then again with shared_exact=true — both MUST leave a
        // non-exact queue off the flow-fair path, because the gate's
        // LHS (`queue.exact`) fails regardless of the fast-path bit.
        let fast_path_owner_local = vec![test_queue_fast_path_for_promotion(false)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_owner_local, 0);
        assert!(
            !runtime.queues[0].flow_fair,
            "non-exact queues must stay off the flow-fair path: SFQ \
             has no rate contract to enforce there, and draws an OS \
             random seed per queue",
        );

        let fast_path_shared = vec![test_queue_fast_path_for_promotion(true)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_shared, 0);
        assert!(
            !runtime.queues[0].flow_fair,
            "non-exact queues must stay off the flow-fair path \
             regardless of the shared_exact signal",
        );
    }

    /// Pin that `apply_cos_queue_flow_fair_promotion` propagates the
    /// per-queue `shared_exact` bits correctly when the interface
    /// has a mix of shared_exact and owner-local-exact queues — the
    /// common production shape (a low-rate iperf-a queue next to a
    /// high-rate iperf-c queue on the same interface). Breaking the
    /// zip alignment between `runtime.queues` and
    /// `iface_fast.queue_fast_path` at the
    /// `ensure_cos_interface_runtime` call site would swap the two
    /// queues' `shared_exact` shadows and their `flow_fair` bits,
    /// silently routing both to the wrong admission branch and
    /// turning off SFQ on the iperf-a queue (re-breaking #784).
    #[test]
    fn apply_promotion_pairs_queues_with_their_fast_path_entries() {
        let mut runtime = test_cos_runtime_with_queues(
            100_000_000_000 / 8,
            vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-c".into(),
                    priority: 5,
                    transmit_rate_bytes: 25_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
            ],
        );

        // Position 0 -> owner-local-exact; position 1 -> shared_exact.
        let fast_path = vec![
            test_queue_fast_path_for_promotion(false),
            test_queue_fast_path_for_promotion(true),
        ];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

        assert!(
            runtime.queues[0].flow_fair,
            "queue at position 0 (iperf-a, shared_exact=false) must \
             be on the flow-fair path — #784 fairness fix depends on it",
        );
        assert!(
            !runtime.queues[0].shared_exact,
            "queue at position 0 must get position-0's shared_exact=false",
        );
        assert!(
            runtime.queues[1].flow_fair,
            "#785 Phase 3: queue at position 1 (iperf-c, \
             shared_exact=true) must also be on the flow-fair path \
             so MQFQ VFT ordering enforces per-flow fairness. The \
             admission gates (cos_queue_flow_share_limit, \
             apply_cos_admission_ecn_policy) separately downgrade to \
             aggregate-only on shared_exact queues.",
        );
        assert!(
            runtime.queues[1].shared_exact,
            "queue at position 1 must get position-1's shared_exact=true \
             — zip misalignment would silently mis-route admission policy",
        );
    }

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


    #[test]
    fn admission_ecn_marks_prepared_ipv4_ect0_packet_above_threshold() {
        // Pre: queue above aggregate threshold, Prepared IPv4 ECT(0)
        // packet lives at UMEM offset 0. Counter-factual pins that
        // make this robust against partial regressions:
        //   1. Before the call: TOS byte has ECN = ECT(0).
        //   2. After the call: TOS byte has ECN = CE.
        //   3. Counter bumped by exactly 1.
        //   4. IP checksum recomputed-from-scratch matches what's in
        //      the UMEM bytes.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let tos = (0x28u8 << 2) | ECN_ECT_0;
        let packet = build_ipv4_test_packet(tos);
        let mut umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);

        // Pin (1): pre-state is ECT(0).
        let pre_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();
        assert_eq!(pre_bytes[15] & ECN_MASK, ECN_ECT_0);

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(marked, "Prepared variant must be marked");
        // Pin (3): counter bumped by exactly 1.
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
            "ECN counter must advance by exactly 1",
        );
        assert_eq!(after.admission_flow_share_drops, before.admission_flow_share_drops);
        assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);

        // Pin (2): UMEM bytes now carry CE and preserve DSCP.
        let post_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();
        assert_eq!(post_bytes[15] & ECN_MASK, ECN_CE, "ECN bits must be CE");
        assert_eq!(post_bytes[15] >> 2, 0x28, "DSCP must survive marking");

        // Pin (4): IP checksum recomputed from scratch matches what's
        // actually sitting in UMEM. If the incremental update were
        // off-by-one or skipped a word, this would fail.
        let stored_csum = ((post_bytes[24] as u16) << 8) | post_bytes[25] as u16;
        let from_scratch = compute_ipv4_header_checksum(&post_bytes[14..34]);
        assert_eq!(
            stored_csum, from_scratch,
            "incremental IP checksum must match a from-scratch recompute",
        );
    }

    #[test]
    fn admission_ecn_marks_prepared_ipv6_ect0_packet_above_threshold() {
        // IPv6 Prepared packet at a non-zero UMEM offset. IPv6 has no
        // header checksum, so the pins are:
        //   1. Pre-state tclass has ECN = ECT(0).
        //   2. Post-state tclass has ECN = CE.
        //   3. Version + flow-label untouched.
        //   4. Counter bumped by exactly 1.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let tclass = (0x2eu8 << 2) | ECN_ECT_0;
        let packet = build_ipv6_test_packet(tclass);
        // Pick a non-zero offset to prove that `slice_mut` is
        // honouring `req.offset` rather than always slicing from 0.
        let offset: u64 = 128;
        let mut umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&mut umem, offset, &packet, libc::AF_INET6 as u8);

        let pre_bytes = umem
            .slice(offset as usize, packet.len())
            .expect("slice readback")
            .to_vec();
        let pre_version_nibble = pre_bytes[14] & 0xf0;
        let pre_flow_label_low = pre_bytes[15] & 0x0f;
        assert_eq!(
            ((pre_bytes[14] & 0x0f) << 4) | ((pre_bytes[15] >> 4) & 0x0f),
            tclass,
        );

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(marked, "Prepared IPv6 must be marked");
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 1,
        );

        let post_bytes = umem
            .slice(offset as usize, packet.len())
            .expect("slice readback")
            .to_vec();
        let post_tclass = ((post_bytes[14] & 0x0f) << 4) | ((post_bytes[15] >> 4) & 0x0f);
        assert_eq!(post_tclass & ECN_MASK, ECN_CE);
        assert_eq!(post_tclass >> 2, 0x2e, "DSCP must survive marking");
        assert_eq!(
            post_bytes[14] & 0xf0,
            pre_version_nibble,
            "version nibble must not drift",
        );
        assert_eq!(
            post_bytes[15] & 0x0f,
            pre_flow_label_low,
            "flow-label low nibble must not drift",
        );
    }

    #[test]
    fn admission_ecn_leaves_prepared_not_ect_packet_untouched() {
        // Queue above threshold, but the Prepared packet is NOT-ECT.
        // RFC 3168 §6.1.1.1: never mark a flow that did not negotiate
        // ECN. Counter must stay put and UMEM bytes byte-identical.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let tos = 0xb8; // DSCP 46 (EF), ECN = 00 (NOT-ECT)
        let packet = build_ipv4_test_packet(tos);
        let mut umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
        let pre_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "NOT-ECT packet must not be marked");
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
        let post_bytes = umem
            .slice(0, packet.len())
            .expect("slice readback")
            .to_vec();
        assert_eq!(
            post_bytes, pre_bytes,
            "NOT-ECT packet bytes must be byte-identical",
        );
        assert_eq!(post_bytes[15] & ECN_MASK, ECN_NOT_ECT);
    }

    #[test]
    fn admission_ecn_skips_prepared_when_umem_slice_out_of_range() {
        // Constructed `PreparedTxRequest` points past the end of the
        // UMEM (`offset` > umem.len()). `slice_mut_unchecked` returns
        // None, the marker returns false, and the admission policy
        // must neither panic nor bump the counter. Guards the
        // out-of-range None-handling path — a regression that removed
        // the `let Some(...) = ... else { return false }` shape would
        // fail here without needing to catch a UB-flavoured panic.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let umem = test_admission_umem();
        // Offset deliberately past the UMEM len. `len: 1` so we do
        // not trip the internal `checked_add` overflow path — we want
        // the `end > self.len` check in `slice_mut_unchecked` to be
        // what returns None.
        let mut item = CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: u64::MAX / 2,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        });

        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );

        assert!(!marked, "out-of-range slice must not be marked");
        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked, before.admission_ecn_marked,
            "counter must stay put when the slice is out of range",
        );
    }

    #[test]
    fn admission_ecn_counter_increments_for_both_local_and_prepared_in_same_queue() {
        // Drive the queue above threshold and pass ONE Local + ONE
        // Prepared, both ECT(0). The single `admission_ecn_marked`
        // counter must advance by exactly 2 — proves neither variant
        // is double-counting or under-counting, and that both paths
        // share the same counter. Counter-factual for a refactor
        // that accidentally split the counter: this test would drop
        // to +1.
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;
        let before = snapshot_counters(queue);

        let mut umem = test_admission_umem();

        // Local variant first.
        let mut local_item = test_local_ipv4_item(ECN_ECT_0);
        let marked_local = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut local_item,
            &umem,
        );
        assert!(marked_local, "Local variant must mark");

        // Prepared variant next.
        let packet = build_ipv4_test_packet(ECN_ECT_0);
        let mut prepared_item =
            test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
        let marked_prepared = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut prepared_item,
            &umem,
        );
        assert!(marked_prepared, "Prepared variant must mark");

        let after = snapshot_counters(queue);
        assert_eq!(
            after.admission_ecn_marked,
            before.admission_ecn_marked + 2,
            "single counter must reflect both Local and Prepared marks",
        );
    }


    /// #728 review pin: the Prepared (zero-copy) path has its own
    /// slice/offset plumbing on top of the L3-offset helper. The VLAN
    /// regression on the Local path is necessary but not sufficient —
    /// Local could stay correct while Prepared silently regressed to
    /// stamping the wrong byte. This drives a single-802.1Q ECT(0)
    /// frame through `apply_cos_admission_ecn_policy` at a *non-zero*
    /// UMEM offset and pins that:
    ///   - CE lands at `l3_offset + 1` relative to the frame start
    ///     (i.e. at `frame_offset + 19` inside the UMEM),
    ///   - the VLAN TCI bytes at frame-offset 14..16 are unchanged,
    ///   - the IPv4 header checksum still validates from scratch.
    /// A revert to a hardcoded 14 would stamp byte 15 (inside the TCI)
    /// and this test would fail on the checksum validate as well as
    /// on the TCI-untouched assertion.
    #[test]
    fn admission_ecn_marks_prepared_single_vlan_tagged_ipv4_packet() {
        let mut root = test_cos_runtime_with_exact(false);
        let queue = &mut root.queues[0];
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.queued_bytes = (buffer_limit / 2) + 1;

        let packet = build_ipv4_test_packet(ECN_ECT_0);
        let vid: u16 = 80;
        let priority: u8 = 5;
        let tci: u16 = ((priority as u16) << 13) | vid;
        let tagged = insert_single_vlan_tag(packet, vid, priority);

        // Non-zero UMEM offset so we also prove offset arithmetic
        // (slice_mut + l3_offset) composes correctly on a
        // non-head frame.
        let frame_offset: u64 = 128;
        let mut umem = test_admission_umem();
        let mut item =
            test_prepared_item_in_umem(&mut umem, frame_offset, &tagged, libc::AF_INET as u8);

        let before = snapshot_counters(queue);
        let marked = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            0,
            false,
            false,
            &mut item,
            &umem,
        );
        assert!(
            marked,
            "VLAN-tagged ECT(0) Prepared frame must be marked at the VLAN-shifted offset",
        );
        let after = snapshot_counters(queue);
        assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked + 1);

        // Read back the UMEM bytes for the frame and verify ECN = CE
        // at frame_offset + 19 (= l3_offset + 1 = 18 + 1).
        let post = umem
            .slice(frame_offset as usize, tagged.len())
            .expect("umem slice readback")
            .to_vec();
        assert_eq!(
            post[19] & ECN_MASK,
            ECN_CE,
            "CE must land at VLAN-shifted l3_offset + 1",
        );
        // VLAN TCI at bytes 14..16 must be byte-identical. A revert to
        // hardcoded offset 14 would corrupt these bytes.
        assert_eq!(
            u16::from_be_bytes([post[14], post[15]]),
            tci,
            "VLAN TCI must be untouched by ECN marking on the Prepared path",
        );
        // IP checksum recomputed from scratch over the post-mark
        // IPv4 header must equal the 16-bit value in the frame.
        let iphdr_start = 18;
        let iphdr = &post[iphdr_start..iphdr_start + 20];
        let expected_csum = compute_ipv4_header_checksum(iphdr);
        let actual_csum = u16::from_be_bytes([post[iphdr_start + 10], post[iphdr_start + 11]]);
        assert_eq!(
            actual_csum, expected_csum,
            "incremental checksum update must match a from-scratch recomputation",
        );
    }

    // ---------------------------------------------------------------------
    // #940 + #942 V_min correctness sweep tests
    // ---------------------------------------------------------------------


    /// #940: speculative pop (snapshot variant) must NOT publish to the
    /// V_min slot. The slot stays at NOT_PARTICIPATING throughout the
    /// snapshot pop. Rolling back via `cos_queue_push_front` republishes
    /// the post-rollback vtime via the existing rollback hook.
    #[test]
    fn vmin_pop_snapshot_does_not_publish() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);

        // Sanity: slot starts at NOT_PARTICIPATING.
        assert_eq!(
            floor.slots[1].read(),
            None,
            "fresh slot should be NOT_PARTICIPATING"
        );

        // Push an item and pop with snapshot. With #940, this must
        // NOT publish — slot stays at NOT_PARTICIPATING.
        cos_queue_push_back(queue, test_cos_item(1500));
        let _popped = cos_queue_pop_front(queue);
        assert_eq!(
            floor.slots[1].read(),
            None,
            "snapshot pop must not publish to V_min slot (#940)",
        );

        // Now roll back — push_front republishes the rolled-back vtime
        // via the existing rollback hook in cos_queue_push_front.
        if let Some(item) = _popped {
            cos_queue_push_front(queue, item);
        }
        // After rollback, queue_vtime is back to 0; the rollback hook
        // publishes that. Slot should now reflect a value (0 — the
        // pre-pop state).
        assert_eq!(
            floor.slots[1].read(),
            Some(0),
            "rollback path republishes corrected vtime",
        );
    }

    /// #940: post-settle publish on the Local-flow-fair commit site.
    /// After a successful drain + insert + settle, the slot reflects
    /// the committed queue_vtime.
    ///
    /// This test exercises the `publish_committed_queue_vtime` helper
    /// directly (the helper is the publish primitive). The full
    /// scratch-builder + commit + settle path is exercised by the
    /// existing `cos_exact_drain_throughput_micro_bench` and the
    /// integration tests; this pin asserts the helper's contract.
    #[test]
    fn vmin_post_settle_publish_writes_committed_vtime() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 2);

        // Set queue_vtime as if a drain has just committed.
        queue.queue_vtime = 12345;
        publish_committed_queue_vtime(Some(&*queue));
        assert_eq!(
            floor.slots[2].read(),
            Some(12345),
            "post-settle publish must write committed queue_vtime to the slot",
        );

        // Calling again with a higher vtime advances the slot
        // (idempotent / monotonic in normal flow).
        queue.queue_vtime = 23456;
        publish_committed_queue_vtime(Some(&*queue));
        assert_eq!(
            floor.slots[2].read(),
            Some(23456),
            "subsequent publish must overwrite",
        );
    }

    /// #940 F4: `publish_committed_queue_vtime` is a no-op when
    /// `vtime_floor = None`. Existing tests rely on this — non-V_min
    /// queues must not publish anywhere.
    #[test]
    fn vmin_publish_helper_noop_when_floor_none() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "q0".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        // No floor attached; default state.
        assert!(queue.vtime_floor.is_none());
        queue.queue_vtime = 99999;
        // Must not panic and must not publish anywhere.
        publish_committed_queue_vtime(Some(&*queue));
        // Sanity: still no floor, no observable effect.
        assert!(queue.vtime_floor.is_none());
    }

    /// #942 (deferred): pin the cos_queue_v_min_continue throttle
    /// behavior in isolation. The Prepared flow-fair scratch builder
    /// does NOT actually call this in production yet — wiring it
    /// caused a severe shared_exact regression that bisection traced
    /// to this exact wiring (see plan.md "#942 deferred"). The
    /// underlying cos_queue_v_min_continue function still works
    /// correctly when called directly, as this test confirms.
    #[test]
    fn vmin_throttle_function_fires_on_lag_breach() {
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
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);

        // Peer worker 0 pegged at vtime 0. Local worker 1 has
        // queue_vtime well past LAG_THRESHOLD (~1.25 MB at 10 Gb/s).
        floor.slots[0].publish(0);
        queue.queue_vtime = 100 * 1024 * 1024; // 100 MB ahead

        // V_min check at pop_count==1 must throttle (return false).
        assert!(
            !cos_queue_v_min_continue(queue, 1),
            "throttle MUST fire when local vtime >> peer V_min + LAG",
        );

        // Reset queue_vtime to within LAG and confirm the check passes.
        queue.queue_vtime = 0;
        assert!(
            cos_queue_v_min_continue(queue, 1),
            "throttle MUST NOT fire when local vtime <= V_min + LAG",
        );
    }

    /// #940: full pop → push_front (rollback) → re-pop → publish-via-
    /// post-settle sequence. Pins that the rollback hook in
    /// `cos_queue_push_front` and the new post-settle publish compose
    /// correctly under partial-rollback workloads. Per Gemini
    /// adversarial review.
    #[test]
    fn vmin_pop_rollback_repop_postsettle_compose() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);

        // Push 2 items.
        cos_queue_push_back(queue, test_cos_item(1500));
        cos_queue_push_back(queue, test_cos_item(1500));
        let v0 = queue.queue_vtime;
        assert_eq!(floor.slots[1].read(), None, "fresh slot");

        // Pop 1: snapshot variant (NO publish).
        let popped1 = cos_queue_pop_front(queue);
        let v1 = queue.queue_vtime;
        assert!(v1 > v0, "pop must advance vtime");
        assert_eq!(
            floor.slots[1].read(),
            None,
            "snapshot pop must not publish"
        );

        // Roll back via push_front: republishes via existing rollback
        // hook. Slot now holds the rolled-back vtime (back to v0).
        if let Some(item) = popped1 {
            cos_queue_push_front(queue, item);
        }
        let v_after_rollback = queue.queue_vtime;
        assert_eq!(v_after_rollback, v0, "rollback must restore vtime");
        assert_eq!(
            floor.slots[1].read(),
            Some(v0),
            "rollback hook must publish corrected vtime",
        );

        // Re-pop (snapshot). queue_vtime advances again. Slot stays at
        // v0 because the snapshot pop doesn't publish.
        let _popped2 = cos_queue_pop_front(queue);
        assert!(
            queue.queue_vtime > v_after_rollback,
            "re-pop advances vtime"
        );
        assert_eq!(
            floor.slots[1].read(),
            Some(v0),
            "re-pop snapshot must not publish",
        );

        // Post-settle publish: slot reflects the new committed vtime.
        publish_committed_queue_vtime(Some(&*queue));
        assert_eq!(
            floor.slots[1].read(),
            Some(queue.queue_vtime),
            "post-settle publish broadcasts the new committed vtime",
        );
    }

    /// #940: demote_prepared_cos_queue_to_local must not publish to
    /// V_min during drain_all. Reframed per Gemini review: assert slot
    /// value before demote == slot value after demote completes the
    /// internal save/restore but BEFORE the new explicit post-restore
    /// publish call... well actually the publish happens at the end of
    /// demote_prepared_cos_queue_to_local now, so we observe:
    ///
    ///   1. Pre-demote: slot at SOME_PRE_VTIME (set explicitly).
    ///   2. Build a queue with prepared items.
    ///   3. Run demote (which drains internally with no-snapshot
    ///      pops, advances queue_vtime by drained bytes,
    ///      converts items to Local, then RESTORES queue_vtime
    ///      from the saved value, then publishes).
    ///   4. Post-demote: slot at SOME_PRE_VTIME (== restored value
    ///      since demote saves+restores symmetrically).
    ///
    /// The test cannot observe the transient drain-time queue_vtime
    /// from a single thread; the assertion is "slot value at start ==
    /// slot value at end" which proves no transient leaked.
    #[test]
    fn vmin_demote_no_drain_all_leak() {
        // demote_prepared_cos_queue_to_local takes &MmapArea and
        // operates on Prepared items. We need a real MmapArea and
        // a queue with Prepared items. Start with a small UMEM.
        let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");

        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 4 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 0);
        // Set a non-zero "prior committed" vtime so we can detect
        // accidental publishes-of-zero from drain_all.
        queue.queue_vtime = 7777;
        floor.slots[0].publish(7777);
        let pre_slot = floor.slots[0].read();
        assert_eq!(pre_slot, Some(7777), "fixture sanity");

        // Push a Prepared item.
        let prep = PreparedTxRequest {
            offset: 0,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            dscp_rewrite: None,
            cos_queue_id: Some(0),
            flow_key: None,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            egress_ifindex: 80,
        };
        cos_queue_push_back(queue, CoSPendingTxItem::Prepared(prep));

        let mut free_tx = VecDeque::new();
        let mut pending_fill = VecDeque::new();
        let _ok = demote_prepared_cos_queue_to_local(
            &area,
            &mut free_tx,
            &mut pending_fill,
            0,
            &mut root,
            Some(0),
        );

        // Re-borrow queue and floor (root was reborrowed by demote).
        let queue = &root.queues[0];
        let post_slot = queue
            .vtime_floor
            .as_ref()
            .and_then(|f| f.slots.get(0))
            .and_then(|s| s.read());

        // Slot at end MUST equal slot at start: demote saves+restores
        // queue_vtime (#926) and the new post-restore publish writes
        // the SAME (saved) value back. drain_all's internal vtime
        // inflation never reaches the slot because the pop-time
        // publish has been removed (#940).
        assert_eq!(
            post_slot, pre_slot,
            "demote must not leak drain_all vtime to V_min slot — \
             the saved+restored vtime must round-trip cleanly (#940)",
        );
    }

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

    /// #941 Work item A: when the worker's last active bucket on a
    /// shared_exact queue empties, the V_min slot is vacated to
    /// NOT_PARTICIPATING. Without vacate, the slot would hold the
    /// stale-low queue_vtime — phantom-participating — and peers would
    /// throttle against it indefinitely.
    #[test]
    fn vmin_vacate_on_bucket_empty() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);

        // Establish participation: enqueue + drain + publish so slot
        // has a non-NOT_PARTICIPATING value.
        let item = test_flow_cos_item(1234, 1500);
        cos_queue_push_back(queue, item);
        let _ = cos_queue_pop_front(queue);
        publish_committed_queue_vtime(Some(&*queue));
        assert!(
            floor.slots[1].read().is_some(),
            "slot should be participating after publish",
        );

        // active_flow_buckets is now 0 because pop drained the only bucket.
        // Enqueue + dequeue another item with the SAME flow_key to retrigger
        // the bucket-empty vacate path. Must use account_cos_queue_flow_*
        // helpers explicitly — push_back/pop_front delegate to them but
        // we want to exercise the dequeue accounting that holds the
        // vacate hook.
        let key = test_session_key(1234, 5201);
        account_cos_queue_flow_enqueue(queue, Some(&key), 1500);
        // Now dequeue: should fire the bucket-empty path AND vacate.
        account_cos_queue_flow_dequeue(queue, Some(&key), 1500);
        assert_eq!(queue.active_flow_buckets, 0, "bucket count drained to 0");
        assert!(
            floor.slots[1].read().is_none(),
            "Work item A: slot must be vacated to NOT_PARTICIPATING when the last bucket empties",
        );
    }

    /// #941 Work item A: the vacate fires ONLY when active_flow_buckets
    /// transitions to 0. If two flows hash to two buckets, dequeueing
    /// the first bucket should NOT vacate (the second is still active).
    #[test]
    fn vmin_vacate_only_when_last_bucket_empties() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        // Pick keys that map to different buckets — try several until
        // we find two with distinct hashes.
        let mut keys: Vec<SessionKey> = Vec::new();
        let mut buckets = std::collections::HashSet::new();
        for src in 1000u16..2000 {
            let k = test_session_key(src, 5201);
            let bkt = cos_flow_bucket_index(queue.flow_hash_seed, Some(&k));
            if buckets.insert(bkt) {
                keys.push(k);
                if keys.len() == 2 {
                    break;
                }
            }
        }
        assert_eq!(keys.len(), 2, "need two distinct buckets");
        // Enqueue both flows; active_flow_buckets becomes 2.
        account_cos_queue_flow_enqueue(queue, Some(&keys[0]), 1500);
        account_cos_queue_flow_enqueue(queue, Some(&keys[1]), 1500);
        assert_eq!(queue.active_flow_buckets, 2);
        // Establish participation by publishing.
        publish_committed_queue_vtime(Some(&*queue));
        assert!(floor.slots[1].read().is_some());
        // Dequeue first flow's bucket. active_flow_buckets goes 2→1; no vacate.
        account_cos_queue_flow_dequeue(queue, Some(&keys[0]), 1500);
        assert_eq!(queue.active_flow_buckets, 1);
        assert!(
            floor.slots[1].read().is_some(),
            "vacate must NOT fire when other buckets are still active",
        );
        // Dequeue second flow's bucket. active_flow_buckets goes 1→0 → vacate.
        account_cos_queue_flow_dequeue(queue, Some(&keys[1]), 1500);
        assert_eq!(queue.active_flow_buckets, 0);
        assert!(
            floor.slots[1].read().is_none(),
            "vacate must fire when the last bucket empties",
        );
    }

    /// #941 Work item D: hard-cap activation. After
    /// V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttle decisions,
    /// the function force-continues AND arms suspension.
    #[test]
    fn vmin_hard_cap_force_continue_activates_suspension() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        // Peer 0 publishes a tiny vtime — guarantees the throttle path.
        floor.slots[0].publish(0);
        queue.queue_vtime = 100 * 1024 * 1024; // 100 MB ahead, way past lag.
        // Each call returns false (throttle) until consecutive_v_min_skips
        // reaches HARD_CAP. The Nth call returns true (force-continue) and
        // arms suspension.
        for n in 1..V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
            let cont = cos_queue_v_min_continue(queue, 1);
            assert!(!cont, "throttle must fire on call {} of {}", n, V_MIN_CONSECUTIVE_SKIP_HARD_CAP);
        }
        // The Nth call hits the hard-cap.
        let final_cont = cos_queue_v_min_continue(queue, 1);
        assert!(final_cont, "hard-cap activation must force-continue");
        assert_eq!(
            queue.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
            "hard-cap must arm suspension to V_MIN_SUSPENSION_BATCHES",
        );
        assert_eq!(
            queue.consecutive_v_min_skips, 0,
            "hard-cap must reset consecutive skips to 0",
        );
        assert_eq!(
            queue.v_min_hard_cap_overrides_scratch, 1,
            "hard-cap activation must increment the override counter",
        );
    }

    /// #941 Work item D: `cos_queue_v_min_consume_suspension` decrements
    /// the counter once per call and returns the suspension state.
    #[test]
    fn vmin_consume_suspension_decrements_once() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let _floor = attach_test_vtime_floor(queue, 4, 1);
        // No suspension active initially — returns false, no change.
        assert!(!cos_queue_v_min_consume_suspension(queue));
        assert_eq!(queue.v_min_suspended_remaining, 0);
        // Arm suspension manually (simulating hard-cap).
        queue.v_min_suspended_remaining = 5;
        // Each call decrements by 1 and returns true.
        for expected_remaining in (0..5).rev() {
            assert!(cos_queue_v_min_consume_suspension(queue));
            assert_eq!(queue.v_min_suspended_remaining, expected_remaining);
        }
        // Drained — next call returns false.
        assert!(!cos_queue_v_min_consume_suspension(queue));
        assert_eq!(queue.v_min_suspended_remaining, 0);
    }

    /// #941 Work item D + Gemini Q6: the drain-call preflight must NOT
    /// burn a suspension slot when free_tx_frames is empty (no work
    /// can be done). Validates `cos_queue_v_min_consume_suspension`
    /// is called AFTER the preflight, not before.
    #[test]
    fn vmin_suspension_not_decremented_on_empty_tx_frames() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let _floor = attach_test_vtime_floor(queue, 4, 1);
        // Arm suspension at a known value.
        queue.v_min_suspended_remaining = 100;
        let initial = queue.v_min_suspended_remaining;
        let area = MmapArea::new(2 * 1024 * 1024).expect("mmap");
        let mut empty_free: VecDeque<u64> = VecDeque::new();
        let mut scratch: Vec<(u64, TxRequest)> = Vec::new();
        // Call drain with empty free_tx_frames. The function should
        // return early WITHOUT consuming a suspension slot.
        let _ = drain_exact_local_items_to_scratch_flow_fair(
            queue,
            &mut empty_free,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert_eq!(
            queue.v_min_suspended_remaining, initial,
            "drain with empty free_tx_frames must NOT consume a suspension slot",
        );
    }

    /// #941 Work item D: hard-cap counter increments and is reset on a
    /// successful pop (V_min returns true with no peers participating).
    #[test]
    fn vmin_hard_cap_counter_resets_on_success() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        floor.slots[0].publish(0);
        queue.queue_vtime = 100 * 1024 * 1024;
        // 3 throttles increment the counter to 3.
        for _ in 0..3 {
            assert!(!cos_queue_v_min_continue(queue, 1));
        }
        assert_eq!(queue.consecutive_v_min_skips, 3);
        // Now make the check succeed: vacate the peer, so participating==0.
        floor.slots[0].vacate();
        assert!(cos_queue_v_min_continue(queue, 1));
        assert_eq!(
            queue.consecutive_v_min_skips, 0,
            "successful V_min check must reset consecutive_v_min_skips",
        );
    }

    /// #941: confirms Work item B was correctly dropped. After Work
    /// item A vacates, the slot stays NOT_PARTICIPATING until the next
    /// post-settle publish (#940's hook). No first-enqueue publish.
    #[test]
    fn vmin_no_first_enqueue_publish() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        // Establish slot at NOT_PARTICIPATING (initial state from
        // SharedCoSQueueVtimeFloor::new()).
        assert!(floor.slots[1].read().is_none());
        // Enqueue an item — Work item A's hook does NOT fire on enqueue,
        // and Work item B was dropped so no first-enqueue publish either.
        let key = test_session_key(1234, 5201);
        account_cos_queue_flow_enqueue(queue, Some(&key), 1500);
        assert!(
            floor.slots[1].read().is_none(),
            "no first-enqueue publish: slot must remain NOT_PARTICIPATING after enqueue (Work item B was DROPPED)",
        );
    }

    /// #942: Prepared flow-fair drain MUST honor the V_min throttle.
    /// Mirrors Local-flow's `vmin_throttle_function_fires_on_lag_breach`
    /// pattern: synthetic peer slot pegged at 0; local qvtime well past
    /// LAG_THRESHOLD; cos_queue_v_min_continue must return false. Then
    /// the suspended path: when v_min_suspended_remaining is non-zero,
    /// the drain consumes one slot and skips V_min entirely.
    #[test]
    fn vmin_prepared_flow_fair_throttle_and_suspension() {
        let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        floor.slots[0].publish(0);
        queue.queue_vtime = 100 * 1024 * 1024;

        // Push a Prepared item so the preflight passes.
        let packet = vec![0u8; 1500];
        let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
        cos_queue_push_back(queue, prepared);

        let mut scratch: Vec<PreparedTxRequest> = Vec::new();
        let mut free_tx: VecDeque<u64> = VecDeque::new();
        let mut pending_fill: VecDeque<u64> = VecDeque::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(
            scratch.is_empty(),
            "V_min throttle must break Prepared drain before any item is committed",
        );
        assert_eq!(queue.consecutive_v_min_skips, 1);

        // Arm suspension; next drain consumes one slot and skips V_min,
        // draining the pending Prepared item.
        queue.v_min_suspended_remaining = 5;
        let mut scratch2: Vec<PreparedTxRequest> = Vec::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch2,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert_eq!(
            queue.v_min_suspended_remaining, 4,
            "drain MUST consume one suspension slot",
        );
        assert!(
            !scratch2.is_empty(),
            "with suspension active, drain must NOT throttle; Prepared item must reach scratch",
        );
    }

    /// #942: preflight returns early without consuming suspension when
    /// queue head is Local (not Prepared). Mirrors Local-flow's
    /// `vmin_suspension_not_decremented_on_empty_tx_frames`.
    #[test]
    fn vmin_prepared_no_suspension_burn_when_head_is_local() {
        let umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let _floor = attach_test_vtime_floor(queue, 4, 1);
        queue.v_min_suspended_remaining = 100;
        let initial = queue.v_min_suspended_remaining;

        // Queue head is Local — preflight returns Ready early.
        cos_queue_push_back(queue, test_cos_item(1500));

        let mut scratch: Vec<PreparedTxRequest> = Vec::new();
        let mut free_tx: VecDeque<u64> = VecDeque::new();
        let mut pending_fill: VecDeque<u64> = VecDeque::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert_eq!(
            queue.v_min_suspended_remaining, initial,
            "Prepared drain with non-Prepared head MUST NOT consume a suspension slot",
        );
    }

    /// #942 (Codex/Gemini Q4): hard-cap arms via the Prepared drain
    /// itself, not just via direct `cos_queue_v_min_continue` calls.
    /// After V_MIN_CONSECUTIVE_SKIP_HARD_CAP repeated drain attempts
    /// under throttle conditions, the next drain force-continues, arms
    /// suspension, and successfully commits the head Prepared item.
    #[test]
    fn vmin_prepared_drain_arms_hard_cap_after_repeated_throttle() {
        let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        floor.slots[0].publish(0);
        queue.queue_vtime = 100 * 1024 * 1024;

        let packet = vec![0u8; 1500];
        let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
        cos_queue_push_back(queue, prepared);

        let mut free_tx: VecDeque<u64> = VecDeque::new();
        let mut pending_fill: VecDeque<u64> = VecDeque::new();

        // First (HARD_CAP - 1) drain calls each throttle and bump
        // consecutive_v_min_skips. The head Prepared item must NOT be
        // committed during these calls.
        for n in 1..V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
            let mut scratch: Vec<PreparedTxRequest> = Vec::new();
            let _ = drain_exact_prepared_items_to_scratch_flow_fair(
                queue,
                &mut scratch,
                &umem,
                &mut free_tx,
                &mut pending_fill,
                0,
                u64::MAX,
                u64::MAX,
                None,
            );
            assert!(
                scratch.is_empty(),
                "drain {} of {}: throttle must keep scratch empty",
                n,
                V_MIN_CONSECUTIVE_SKIP_HARD_CAP,
            );
            assert_eq!(
                queue.consecutive_v_min_skips, n,
                "drain {}: consecutive_v_min_skips must increment",
                n,
            );
            assert_eq!(
                queue.v_min_suspended_remaining, 0,
                "drain {}: suspension must NOT yet be armed",
                n,
            );
        }

        // The HARD_CAP-th drain hits the cap: force-continues at
        // pop_count=1, arms suspension, drains the item.
        let mut scratch: Vec<PreparedTxRequest> = Vec::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(
            !scratch.is_empty(),
            "hard-cap drain must commit the head Prepared item",
        );
        assert_eq!(
            queue.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
            "hard-cap drain must arm suspension to V_MIN_SUSPENSION_BATCHES",
        );
        assert_eq!(
            queue.consecutive_v_min_skips, 0,
            "hard-cap drain must reset consecutive_v_min_skips",
        );
        assert_eq!(
            queue.v_min_hard_cap_overrides_scratch, 1,
            "hard-cap drain must increment the override counter",
        );
    }

    /// #942 (Gemini Q6 missing test): when a peer slot vacates to
    /// NOT_PARTICIPATING mid-drain, the next V_min check observes the
    /// vacated state through the `Arc<AtomicU64>` and stops throttling.
    /// This is the dynamic-correctness counterpart to
    /// `vmin_throttle_function_fires_on_lag_breach`.
    #[test]
    fn vmin_prepared_drain_unblocks_when_peer_slot_vacates() {
        let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        // Peer 0 publishes a tiny vtime — guarantees throttle.
        floor.slots[0].publish(0);
        queue.queue_vtime = 100 * 1024 * 1024;

        let packet = vec![0u8; 1500];
        let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
        cos_queue_push_back(queue, prepared);

        // First drain: throttle fires, nothing committed.
        let mut scratch: Vec<PreparedTxRequest> = Vec::new();
        let mut free_tx: VecDeque<u64> = VecDeque::new();
        let mut pending_fill: VecDeque<u64> = VecDeque::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(
            scratch.is_empty(),
            "throttle must hold the Prepared item before vacate",
        );

        // Peer 0 vacates (Work item A path: bucket-empty transition).
        // The Arc<AtomicU64> publishes immediately to all readers.
        floor.slots[0].vacate();

        // Second drain: peer is NOT_PARTICIPATING, V_min returns true,
        // the head item drains.
        let mut scratch2: Vec<PreparedTxRequest> = Vec::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch2,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(
            !scratch2.is_empty(),
            "peer vacate must clear the throttle and let drain proceed",
        );
        assert_eq!(
            queue.v_min_suspended_remaining, 0,
            "vacate-then-drain must NOT arm suspension (no hard-cap path)",
        );
    }

    /// #942 (Codex Q4): suspension state is queue-level, not per-drain-
    /// function. If the Local drain arms suspension via hard-cap, the
    /// subsequent Prepared drain on the same queue MUST see and consume
    /// that suspension (rather than re-throttling). Validates the
    /// shared `queue.v_min_suspended_remaining` lifecycle across both
    /// drain entry points.
    #[test]
    fn vmin_local_hard_cap_suspension_carries_into_prepared_drain() {
        let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        let floor = attach_test_vtime_floor(queue, 4, 1);
        floor.slots[0].publish(0);
        queue.queue_vtime = 100 * 1024 * 1024;

        // Simulate Local hard-cap firing: arm consecutive_v_min_skips
        // to one short of cap, then call cos_queue_v_min_continue
        // directly (matching what Local drain would do at pop_count=1).
        queue.consecutive_v_min_skips = V_MIN_CONSECUTIVE_SKIP_HARD_CAP - 1;
        let _ = cos_queue_v_min_continue(queue, 1);
        assert_eq!(
            queue.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
            "Local hard-cap path must arm queue-level suspension",
        );

        // Now call Prepared drain. With suspension active, V_min check
        // is skipped (no throttle), and the item drains. Suspension is
        // consumed once at drain entry.
        let packet = vec![0u8; 1500];
        let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
        cos_queue_push_back(queue, prepared);
        let suspension_before = queue.v_min_suspended_remaining;

        let mut scratch: Vec<PreparedTxRequest> = Vec::new();
        let mut free_tx: VecDeque<u64> = VecDeque::new();
        let mut pending_fill: VecDeque<u64> = VecDeque::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(
            !scratch.is_empty(),
            "Prepared drain under inherited Local-armed suspension must drain",
        );
        assert_eq!(
            queue.v_min_suspended_remaining,
            suspension_before - 1,
            "Prepared drain must consume exactly one queue-level suspension slot",
        );
    }
}
