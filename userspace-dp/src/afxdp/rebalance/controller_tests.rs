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
    /// Per-key origin as the mock "session table" sees it, so tests can
    /// confirm there is always >= 1 owner across a rollback.
    origins: std::collections::HashMap<u16, &'static str>,
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
            self.origins.insert(key.src_port, "rebalanced_owner");
        }
        self.promote_ok
    }
    fn demote(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("demote:{worker_id}:{}", key.src_port));
        // W_old's local copy was the original owner; demote flips it to the
        // inert RebalancedOut. The promoted W_new owner is unaffected.
        self.demote_ok
    }
    fn restore_owner(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("restore:{worker_id}:{}", key.src_port));
        self.origins.insert(key.src_port, "owner");
        true
    }
    fn demote_replica(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("replica:{worker_id}:{}", key.src_port));
        // Only demote the W_new owner to a replica; never below 0 owners.
        if self.origins.get(&key.src_port) == Some(&"rebalanced_owner") {
            self.origins.insert(key.src_port, "replica");
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
    assert_eq!(c.metrics().rules_active, 0);
    assert_eq!(c.metrics().deletes_total, 1);
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
