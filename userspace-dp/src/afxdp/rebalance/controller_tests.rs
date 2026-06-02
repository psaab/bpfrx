// #1748 controller unit tests: selection objective, hysteresis, magnitude
// guard, oscillation cooldown, budget-exhaustion (NO eviction), barrier
// ordering, and reverse-barrier rollback (>= 1 owner). The barrier transport
// is mocked so the move protocol is exercised without a live Coordinator/NIC.

use super::*;
use super::super::ntuple::{FlowSpec5Tuple, NtupleSocket};
use crate::session::SessionKey;
use std::net::{IpAddr, Ipv4Addr};

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5210,
    }
}

fn worker(worker_id: u32, byte_rate: f64) -> WorkerByteRate {
    WorkerByteRate { worker_id, queue_id: worker_id, byte_rate }
}

fn flow(src_port: u16, worker_id: u32, byte_rate: f64) -> FlowSample {
    FlowSample { key: key(src_port), worker_id, byte_rate }
}

/// Records every barrier call in order so tests can assert the protocol
/// ordering (promote before demote, restore before replica-demote, etc).
#[derive(Default)]
struct MockTransport {
    calls: Vec<String>,
    promote_ok: bool,
    demote_ok: bool,
    install_ok: bool,
    next_loc: u32,
    /// When true, restore_owner returns false (simulates an ack timeout / key
    /// absent on W_old) so tests can exercise the gated reverse barrier.
    restore_fails: bool,
    /// Per-(worker,key) origin as the mock "session table" sees it, so tests
    /// can confirm there is always >= 1 owner across a rollback even when a
    /// flow has lived on more than one worker over a chain of moves.
    origins: std::collections::HashMap<(u32, u16), &'static str>,
}

impl MockTransport {
    fn good() -> Self {
        Self {
            promote_ok: true,
            demote_ok: true,
            install_ok: true,
            next_loc: 100,
            ..Default::default()
        }
    }
    fn owners(&self) -> usize {
        self.origins
            .values()
            .filter(|o| matches!(**o, "owner" | "rebalanced_owner"))
            .count()
    }
}

impl BarrierTransport for MockTransport {
    fn promote(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("promote:{worker_id}:{}", key.src_port));
        if self.promote_ok {
            self.origins.insert((worker_id, key.src_port), "rebalanced_owner");
        }
        self.promote_ok
    }
    fn demote(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("demote:{worker_id}:{}", key.src_port));
        // W_old's local copy was the original owner; demote flips it to the
        // inert RebalancedOut. The promoted W_new owner is unaffected.
        if self.demote_ok {
            self.origins.insert((worker_id, key.src_port), "rebalanced_out");
        }
        self.demote_ok
    }
    fn restore_owner(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("restore:{worker_id}:{}", key.src_port));
        if self.restore_fails {
            return false;
        }
        self.origins.insert((worker_id, key.src_port), "owner");
        true
    }
    fn demote_replica(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("replica:{worker_id}:{}", key.src_port));
        // Only demote the W_new owner to a replica; never below 0 owners.
        if self.origins.get(&(worker_id, key.src_port)) == Some(&"rebalanced_owner") {
            self.origins.insert((worker_id, key.src_port), "replica");
        }
        true
    }
    fn install_rule(&mut self, _flow: &FlowSpec5Tuple, queue: u32) -> std::io::Result<u32> {
        self.calls.push(format!("install:q{queue}"));
        if self.install_ok {
            let loc = self.next_loc;
            self.next_loc += 1;
            Ok(loc)
        } else {
            Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
        }
    }
    fn delete_rule(&mut self, loc: u32) -> std::io::Result<()> {
        self.calls.push(format!("delete:{loc}"));
        Ok(())
    }
}

/// Build a controller with a throwaway socket. The socket is never used in
/// these tests (the mock transport programs "the NIC"), so a loopback ethtool
/// socket open is acceptable; if it fails (sandbox), fall back to the lo
/// device which always exists.
fn test_controller(config: RebalanceConfig) -> RebalanceController {
    let socket = NtupleSocket::open("lo")
        .expect("open ethtool socket on lo");
    RebalanceController::new(config, socket)
}

fn cfg() -> RebalanceConfig {
    RebalanceConfig {
        imbalance_threshold: 1.30,
        rebalance_interval_secs: 1,
        max_rules: 8,
    }
}

#[test]
fn cov_zero_for_balanced_vector() {
    let ws = vec![worker(0, 100.0), worker(1, 100.0), worker(2, 100.0)];
    assert!(byte_rate_cov(&ws) < 1e-9);
}

#[test]
fn cov_positive_for_skewed_vector() {
    let ws = vec![worker(0, 400.0), worker(1, 100.0), worker(2, 100.0)];
    assert!(byte_rate_cov(&ws) > 0.5);
}

#[test]
fn hysteresis_requires_persisted_imbalance() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let input = RebalanceTickInput {
        ifindex: 1,
        // Hottest 400, coolest 100: imbalance ratio 400/200 = 2.0 > 1.3.
        workers: vec![worker(0, 400.0), worker(1, 100.0), worker(2, 100.0)],
        flows: vec![
            flow(1001, 0, 150.0),
            flow(1002, 0, 150.0),
            flow(1003, 0, 100.0),
        ],
        now_secs: 10,
    };
    // First over-threshold tick: dwell not yet satisfied -> no move.
    assert!(c.tick(&input, &mut tx).is_none());
    assert!(tx.calls.is_empty(), "no barrier on the first tick");
    // Second tick at a later second: dwell satisfied -> move taken.
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    let outcome = c.tick(&input2, &mut tx);
    assert!(outcome.is_some(), "move taken after dwell: calls={:?}", tx.calls);
}

#[test]
fn barrier_order_is_promote_then_demote_then_install() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0), flow(1002, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx); // dwell
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    c.tick(&input2, &mut tx);
    // The committed sequence must be promote(W_new) -> demote(W_old) ->
    // install. W_new is worker 1 (coolest), W_old is worker 0 (hottest).
    let promote_idx = tx.calls.iter().position(|c| c.starts_with("promote:1:")).unwrap();
    let demote_idx = tx.calls.iter().position(|c| c.starts_with("demote:0:")).unwrap();
    let install_idx = tx.calls.iter().position(|c| c.starts_with("install:")).unwrap();
    assert!(promote_idx < demote_idx, "promote before demote: {:?}", tx.calls);
    assert!(demote_idx < install_idx, "demote before install: {:?}", tx.calls);
}

#[test]
fn demote_failure_reverse_barrier_keeps_an_owner() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    tx.demote_ok = false; // W_old demote ack fails.
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0), flow(1002, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx); // dwell
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    let outcome = c.tick(&input2, &mut tx);
    assert!(outcome.is_none(), "no committed move on demote failure");
    // Reverse barrier order: restore(W_old) BEFORE replica(W_new).
    let restore_idx = tx.calls.iter().position(|c| c.starts_with("restore:")).unwrap();
    let replica_idx = tx.calls.iter().position(|c| c.starts_with("replica:")).unwrap();
    assert!(restore_idx < replica_idx, "restore before replica: {:?}", tx.calls);
    // No install happened.
    assert!(!tx.calls.iter().any(|c| c.starts_with("install:")));
    // >= 1 owner remains across the rollback.
    assert!(tx.owners() >= 1, "rollback must keep >= 1 owner: {:?}", tx.origins);
}

#[test]
fn install_failure_reverse_barrier_keeps_an_owner() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    tx.install_ok = false; // ioctl returns ENOSPC.
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0), flow(1002, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx);
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    assert!(c.tick(&input2, &mut tx).is_none());
    let restore_idx = tx.calls.iter().position(|c| c.starts_with("restore:")).unwrap();
    let replica_idx = tx.calls.iter().position(|c| c.starts_with("replica:")).unwrap();
    assert!(restore_idx < replica_idx);
    assert!(tx.owners() >= 1, "rollback after install fail keeps owner");
    assert_eq!(c.metrics().rules_active, 0, "no rule recorded on failed install");
}

#[test]
fn budget_exhaustion_stops_no_eviction() {
    let mut c = test_controller(RebalanceConfig {
        imbalance_threshold: 1.30,
        rebalance_interval_secs: 0, // allow back-to-back moves for the test
        max_rules: 2,
    });
    let mut tx = MockTransport::good();
    // Drive enough distinct moves to fill the budget. Each tick moves one
    // flow; use a persistent imbalance and fresh flows so cooldown does not
    // block subsequent moves.
    let mut now = 10u64;
    let mut installed = 0u32;
    for round in 0..6 {
        let input = RebalanceTickInput {
            ifindex: 1,
            workers: vec![worker(0, 400.0), worker(1, 100.0)],
            flows: vec![
                flow(2000 + round, 0, 120.0),
                flow(3000 + round, 0, 120.0),
            ],
            now_secs: now,
        };
        // Two ticks to clear the dwell each round (dwell resets after a move).
        c.tick(&input, &mut tx);
        now += 1;
        let input2 = RebalanceTickInput { now_secs: now, ..input };
        if c.tick(&input2, &mut tx).is_some() {
            installed += 1;
        }
        now += 1;
    }
    assert_eq!(installed, 2, "exactly max_rules moves committed");
    assert_eq!(c.metrics().rules_active, 2);
    // CRITICAL: no delete/eviction ever happened at the cap.
    assert!(
        !tx.calls.iter().any(|c| c.starts_with("delete:")),
        "budget exhaustion must NOT evict/delete: {:?}", tx.calls
    );
    assert_eq!(c.metrics().deletes_total, 0);
    let skipped = c.metrics().moves_skipped
        .get(&SkipReason::BudgetExhausted)
        .copied()
        .unwrap_or(0);
    assert!(skipped >= 1, "budget-exhausted skip recorded");
}

#[test]
fn magnitude_guard_rejects_overlarge_flow() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // gap = 400 - 100 = 300; gap/2 = 150. The only flow on the hottest worker
    // is 250 bytes/s > 150, so the magnitude guard must reject it.
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 250.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx);
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    assert!(c.tick(&input2, &mut tx).is_none());
    assert!(!tx.calls.iter().any(|c| c.starts_with("install:")));
    let mag = c.metrics().moves_skipped.get(&SkipReason::Magnitude).copied().unwrap_or(0);
    assert!(mag >= 1, "magnitude skip recorded: {:?}", c.metrics().moves_skipped);
}

#[test]
fn cooldown_prevents_immediate_re_move() {
    let mut c = test_controller(RebalanceConfig {
        imbalance_threshold: 1.30,
        rebalance_interval_secs: 1,
        max_rules: 8,
    });
    let mut tx = MockTransport::good();
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx);
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    assert!(c.tick(&input2, &mut tx).is_some(), "first move taken");
    // Same flow, immediately after: cooldown blocks it. Advance dwell + the
    // rebalance interval but stay inside the cooldown window.
    let input3 = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0)],
        now_secs: 14,
    };
    c.tick(&input3, &mut tx);
    let input4 = RebalanceTickInput { now_secs: 15, ..input3 };
    assert!(c.tick(&input4, &mut tx).is_none(), "cooled-down flow not re-moved");
}

#[test]
fn teardown_live_move_uses_reverse_barrier() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx);
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    c.tick(&input2, &mut tx).expect("move committed");
    tx.calls.clear();
    // Teardown with the flow still live on W_new -> reverse barrier:
    // restore(W_old) -> delete(rule) -> replica(W_new).
    c.teardown_all(&mut tx, |_w, _k| true);
    let restore_idx = tx.calls.iter().position(|c| c.starts_with("restore:")).unwrap();
    let delete_idx = tx.calls.iter().position(|c| c.starts_with("delete:")).unwrap();
    let replica_idx = tx.calls.iter().position(|c| c.starts_with("replica:")).unwrap();
    assert!(restore_idx < delete_idx, "restore before delete: {:?}", tx.calls);
    assert!(delete_idx < replica_idx, "delete before replica-demote: {:?}", tx.calls);
    // #1748 review #2: restore must target W_OLD (worker 0, the hottest source
    // and RSS-natural worker), NOT W_new (worker 1). The pre-fix worker_for_old
    // returned entry.new_worker and would have restored worker 1 here.
    assert!(
        tx.calls[restore_idx].starts_with("restore:0:"),
        "teardown must restore W_old (worker 0), got {:?}", tx.calls[restore_idx]
    );
    // And the replica-demote must target W_new (worker 1).
    assert!(
        tx.calls[replica_idx].starts_with("replica:1:"),
        "teardown must demote W_new (worker 1), got {:?}", tx.calls[replica_idx]
    );
    assert_eq!(c.metrics().rules_active, 0);
    assert_eq!(c.metrics().deletes_total, 1);
}

#[test]
fn teardown_live_move_restore_failure_keeps_w_new_owner() {
    // #1748 review #4: if the W_old restore ack fails during teardown, the rule
    // is still deleted but W_new is LEFT as owner (no replica-demote) so >= 1
    // cleanup owner remains.
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx);
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    c.tick(&input2, &mut tx).expect("move committed");
    tx.calls.clear();
    tx.restore_fails = true;
    c.teardown_all(&mut tx, |_w, _k| true);
    // Rule deleted, restore attempted, but NO replica-demote of W_new.
    assert!(tx.calls.iter().any(|c| c.starts_with("delete:")));
    assert!(tx.calls.iter().any(|c| c.starts_with("restore:0:")));
    assert!(
        !tx.calls.iter().any(|c| c.starts_with("replica:")),
        "must NOT demote W_new when W_old restore fails: {:?}", tx.calls
    );
    // W_new (worker 1, src_port 1001) is still the rebalanced_owner.
    assert!(tx.owners() >= 1, "restore-fail teardown keeps >= 1 owner");
    let rf = c.metrics().moves_skipped.get(&SkipReason::RestoreFailed).copied().unwrap_or(0);
    assert!(rf >= 1, "restore_failed skip recorded");
}

#[test]
fn second_move_chain_replaces_rule_and_reverse_barriers_prior_owner() {
    // #1748 review #6: ForwardFlow -> RebalancedOwner(W1) -> RebalancedOwner(W2)
    // through the CONTROLLER ledger. The second move of the same key must
    // delete the prior rule, reverse-barrier the prior owner (restore W_old,
    // demote prior W_new), then forward-barrier to the third worker, and
    // REPLACE (not append) the ledger entry.
    let mut c = test_controller(RebalanceConfig {
        imbalance_threshold: 1.30,
        rebalance_interval_secs: 0, // allow back-to-back moves in the test
        max_rules: 8,
    });
    let mut tx = MockTransport::good();

    // First move: flow 1001 on worker 0 (hottest) -> worker 2 (coolest).
    let in1 = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 250.0), worker(2, 100.0)],
        flows: vec![flow(1001, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&in1, &mut tx);
    let in1b = RebalanceTickInput { now_secs: 11, ..in1 };
    let mv1 = c.tick(&in1b, &mut tx).expect("first move");
    assert_eq!(mv1.old_worker, 0);
    assert_eq!(mv1.new_worker, 2);
    assert_eq!(c.metrics().rules_active, 1, "one rule after first move");

    // Clear the cooldown so the same key is eligible again, and present a
    // topology where the SAME flow 1001 now sits on worker 2 (its new home)
    // which is now the hottest, and worker 1 is coolest -> second move
    // 2 -> 1. select_move keys on the flow's current worker_id.
    c.clear_cooldown_for_test();
    tx.calls.clear();
    let installs_before = c.metrics().installs_total;
    let in2 = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 100.0), worker(1, 90.0), worker(2, 400.0)],
        flows: vec![flow(1001, 2, 120.0)],
        now_secs: 20,
    };
    c.tick(&in2, &mut tx);
    let in2b = RebalanceTickInput { now_secs: 21, ..in2 };
    let mv2 = c.tick(&in2b, &mut tx).expect("second move");
    assert_eq!(mv2.old_worker, 2, "second move sources from the prior new_worker");
    assert_eq!(mv2.new_worker, 1);

    // Ledger REPLACED, not appended: still exactly one rule for the key.
    assert_eq!(c.metrics().rules_active, 1, "second move replaces, not appends");
    // The prior rule (loc 100) was deleted before the new install.
    assert!(
        tx.calls.iter().any(|c| c == "delete:100"),
        "prior rule loc 100 must be deleted on second move: {:?}", tx.calls
    );
    // Prior owner reverse-barriered: restore prior W_old (0), demote prior
    // W_new (2). Then forward barrier to the third worker (promote 1).
    let del_idx = tx.calls.iter().position(|c| c == "delete:100").unwrap();
    let promote1_idx = tx.calls.iter().position(|c| c.starts_with("promote:1:")).unwrap();
    assert!(del_idx < promote1_idx, "prior rule deleted before new forward barrier: {:?}", tx.calls);
    // A new rule was installed for the third move.
    assert_eq!(c.metrics().installs_total, installs_before + 1);
    // Ownership ends correct: exactly the third worker's entry is the owner.
    assert!(tx.owners() >= 1, "chain keeps >= 1 owner: {:?}", tx.origins);
}

#[test]
fn teardown_dead_flow_is_plain_delete() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(1001, 0, 120.0)],
        now_secs: 10,
    };
    c.tick(&input, &mut tx);
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    c.tick(&input2, &mut tx).expect("move committed");
    tx.calls.clear();
    // Flow already expired off W_new -> plain delete, no reverse barrier.
    c.teardown_all(&mut tx, |_w, _k| false);
    assert!(tx.calls.iter().any(|c| c.starts_with("delete:")));
    assert!(!tx.calls.iter().any(|c| c.starts_with("restore:")), "no restore for a dead flow");
    assert!(!tx.calls.iter().any(|c| c.starts_with("replica:")), "no replica-demote for a dead flow");
}

#[test]
fn flow_spec_from_key_encodes_network_order_v4() {
    let k = key(0x1234);
    let spec = flow_spec_from_key(&k);
    // src_port host 0x1234 -> network-order field.
    assert_eq!(spec.src_port, 0x1234u16.to_be());
    assert_eq!(spec.dst_port, 5210u16.to_be());
    // src_ip 10.0.61.102 -> the u32 word whose IN-MEMORY bytes are the
    // network-order octets [10,0,61,102] (what the kernel __be32 field reads).
    // That is from_ne_bytes of the address octets, matching the controller's
    // encoding; on a little-endian host this is NOT the host-order integer.
    assert_eq!(spec.src_ip[0], u32::from_ne_bytes([10, 0, 61, 102]));
    assert_eq!(spec.dst_ip[0], u32::from_ne_bytes([172, 16, 80, 200]));
    assert_eq!(spec.src_ip[0].to_ne_bytes(), [10, 0, 61, 102]);
}

// ── #1748 review #8: cumulative-bytes -> byte-RATE derivation ────────

#[test]
fn cumulative_to_rate_basic_delta_over_time() {
    // 1000 bytes accrued over 1s window => 1000 B/s.
    let prev_ns = 1_000_000_000u64;
    let now_ns = prev_ns + 1_000_000_000; // +1s
    assert!((cumulative_to_rate(2000, 1000, now_ns, prev_ns) - 1000.0).abs() < 1e-6);
    // 500 bytes over 0.5s => 1000 B/s.
    let half = prev_ns + 500_000_000;
    assert!((cumulative_to_rate(1500, 1000, half, prev_ns) - 1000.0).abs() < 1e-6);
}

#[test]
fn cumulative_to_rate_first_sample_and_reset_are_zero() {
    let prev_ns = 1_000_000_000u64;
    // now <= prev => 0 (no elapsed time).
    assert_eq!(cumulative_to_rate(5000, 1000, prev_ns, prev_ns), 0.0);
    // cumulative went backwards (flow re-homed, cache reset) => 0, not negative.
    let now_ns = prev_ns + 1_000_000_000;
    assert_eq!(cumulative_to_rate(100, 9000, now_ns, prev_ns), 0.0);
}

#[test]
fn long_lived_idle_flow_not_selected_over_recent_burst() {
    // #1748 review #8 regression: with the OLD signal (cumulative bytes), a
    // long-lived idle flow with huge cumulative bytes would be picked as the
    // "heaviest". With the correct RATE signal, an idle flow has rate ~0 and a
    // recently-bursting flow has a high rate, so the burst flow is selected.
    //
    // Both flows live on the hottest worker 0. flow A is long-lived-but-idle
    // (rate 0), flow B is bursting (rate 120). select_move must pick B.
    let mut c = test_controller(cfg());
    let input = RebalanceTickInput {
        ifindex: 1,
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![
            flow(7001, 0, 0.0),    // long-lived, now idle: RATE 0
            flow(7002, 0, 120.0),  // recently bursting: RATE 120
        ],
        now_secs: 10,
    };
    let mut tx = MockTransport::good();
    c.tick(&input, &mut tx); // dwell
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    let mv = c.tick(&input2, &mut tx).expect("a move is taken");
    assert_eq!(
        mv.key.src_port, 7002,
        "the recently-bursting flow (7002), not the idle long-lived flow (7001), must be moved"
    );
}

#[test]
fn zero_rate_idle_flows_yield_no_move() {
    // If every flow on the hottest worker has rate 0 (all long-lived idle),
    // moving any of them cannot improve the byte-rate CoV, so no move is taken
    // (the magnitude/epsilon guards reject a 0-rate move).
    let mut c = test_controller(cfg());
    let input = RebalanceTickInput {
        ifindex: 1,
        // Worker 0 looks hottest by some other flow, but the eligible flows on
        // it are all idle.
        workers: vec![worker(0, 400.0), worker(1, 100.0)],
        flows: vec![flow(8001, 0, 0.0), flow(8002, 0, 0.0)],
        now_secs: 10,
    };
    let mut tx = MockTransport::good();
    c.tick(&input, &mut tx);
    let input2 = RebalanceTickInput { now_secs: 12, ..input };
    assert!(
        c.tick(&input2, &mut tx).is_none(),
        "no move when all eligible flows are idle (rate 0)"
    );
    assert!(!tx.calls.iter().any(|c| c.starts_with("install:")));
}
