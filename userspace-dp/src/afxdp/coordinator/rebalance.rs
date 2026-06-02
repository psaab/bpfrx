// #1748: Coordinator-side glue for the reactive ntuple rebalance controller.
//
// The controller logic + ioctl module live in `afxdp/rebalance/`. This file
// connects them to the live Coordinator: it translates the wire config into a
// RebalanceConfig, drives one controller tick per status cadence (~1 Hz), and
// implements the barriered ownership-transfer transport against the worker
// command queues + structured ack slots + the per-interface ntuple socket.
//
// Default-OFF invariant: when `rebalance_config` is None, `tick_rebalance` is
// a single `Option::is_none()` early-return — zero ioctl sockets, zero rules,
// no per-tick allocation.

use super::*;
use crate::afxdp::rebalance::{
    BarrierTransport, FlowSample, RebalanceConfig, RebalanceController, RebalanceTickInput,
    WorkerByteRate, flow_spec_from_key, NtupleSocket,
};
use crate::afxdp::rebalance::ntuple::FlowSpec5Tuple;
use crate::afxdp::RebalanceAck;
use crate::protocol::CoSFlowRebalanceSnapshot;
use crate::session::{SessionKey, SessionOrigin};
use std::time::{Duration, Instant};

/// Translate the wire snapshot into the controller config, filling zero
/// sub-fields with the controller's built-in defaults.
pub(super) fn rebalance_config_from_snapshot(
    snap: CoSFlowRebalanceSnapshot,
) -> RebalanceConfig {
    let defaults = RebalanceConfig::default();
    let imbalance_threshold = if snap.imbalance_threshold_percent == 0 {
        defaults.imbalance_threshold
    } else {
        snap.imbalance_threshold_percent as f64 / 100.0
    };
    let rebalance_interval_secs = if snap.rebalance_interval_secs == 0 {
        defaults.rebalance_interval_secs
    } else {
        snap.rebalance_interval_secs as u64
    };
    let max_rules = if snap.max_rules == 0 {
        defaults.max_rules
    } else {
        snap.max_rules
    };
    RebalanceConfig {
        imbalance_threshold,
        rebalance_interval_secs,
        max_rules,
    }
}

/// Per-worker ack-barrier timeout. Mirrors the session-export ack deadline
/// shape (`ha.rs`) but shorter — a move must commit within one cadence.
const REBALANCE_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const REBALANCE_ACK_POLL: Duration = Duration::from_millis(2);

impl super::Coordinator {
    /// Reconcile the rebalance config on a snapshot apply. On disable, tear
    /// down every live controller first (reverse-barrier any still-live move,
    /// then delete its HW rule) so no orphan rule survives the config change.
    pub(in crate::afxdp) fn reconcile_rebalance_config(
        &mut self,
        new_config: Option<RebalanceConfig>,
    ) {
        let now_changed = self.rebalance_config != new_config;
        if new_config.is_none() && !self.rebalance_controllers.is_empty() {
            // Disabled: drain + tear down every controller.
            let ifindexes: Vec<i32> = self.rebalance_controllers.keys().copied().collect();
            for ifindex in ifindexes {
                self.teardown_rebalance_controller(ifindex);
            }
        }
        self.rebalance_config = new_config;
        if now_changed {
            // Config churn (threshold/interval/budget) rebuilds controllers
            // lazily on the next tick with the new config; tear the old ones
            // down so they pick up the new budget/threshold cleanly.
            if new_config.is_some() && !self.rebalance_controllers.is_empty() {
                let ifindexes: Vec<i32> =
                    self.rebalance_controllers.keys().copied().collect();
                for ifindex in ifindexes {
                    self.teardown_rebalance_controller(ifindex);
                }
            }
        }
        // Reset the byte-rate sampling window so the first tick after a config
        // change does not see a bogus huge delta.
        self.rebalance_last_tx_bytes.clear();
    }

    /// Tear down one interface's controller: reverse-barrier its live moves,
    /// delete its rules, drop the socket. `is_live_on_new` cannot be known
    /// cheaply here, so we conservatively treat every ledger entry as live
    /// (the reverse barrier is idempotent and safe for an already-dead flow).
    fn teardown_rebalance_controller(&mut self, ifindex: i32) {
        let Some(mut controller) = self.rebalance_controllers.remove(&ifindex) else {
            return;
        };
        let socket_ptr: *const NtupleSocket = controller.socket();
        // SAFETY: the controller owns the socket for the duration of teardown;
        // we only read it through the transport. `self` (for the barrier) and
        // the socket do not alias mutably.
        let mut tx = CoordinatorBarrierTransport {
            coord: self,
            socket: unsafe { &*socket_ptr },
        };
        controller.teardown_all(&mut tx, |_w, _k| true);
    }

    /// #1748: shutdown teardown — delete every installed ntuple rule with no
    /// barrier. Safe only at process/dataplane shutdown (no live flow to hand
    /// back). Uses the controller's own ledger via a plain-delete teardown.
    pub(in crate::afxdp) fn teardown_all_rebalance_rules_plain(&mut self) {
        let ifindexes: Vec<i32> = self.rebalance_controllers.keys().copied().collect();
        for ifindex in ifindexes {
            let Some(mut controller) = self.rebalance_controllers.remove(&ifindex) else {
                continue;
            };
            let socket_ptr: *const NtupleSocket = controller.socket();
            // SAFETY: controller owns the socket for the teardown; the no-op
            // barrier transport only reads it.
            let mut tx = CoordinatorBarrierTransport {
                coord: self,
                socket: unsafe { &*socket_ptr },
            };
            // is_live_on_new = false => plain delete for every entry.
            controller.teardown_all(&mut tx, |_w, _k| false);
        }
        self.rebalance_last_tx_bytes.clear();
    }

    /// Drive one controller tick at the status cadence. Default-OFF fast path:
    /// a single None check. When enabled, samples per-worker byte-rate over
    /// the window, groups workers + flows by ifindex, lazily constructs the
    /// per-ifindex controller (opening its ntuple socket once), and runs the
    /// barriered move.
    pub fn tick_rebalance(&mut self) {
        let Some(config) = self.rebalance_config else {
            return;
        };
        let now_ns = monotonic_nanos();
        let now_secs = now_ns / 1_000_000_000;

        // 1. Per-worker byte-rate over the window, grouped by the ifindex each
        //    worker's binding is bound to.
        let mut per_iface_workers: BTreeMap<i32, Vec<WorkerByteRate>> = BTreeMap::new();
        let mut worker_ifindex: BTreeMap<u32, i32> = BTreeMap::new();
        for (&worker_id, live) in &self.workers.live {
            let ifindex = live.socket_ifindex();
            if ifindex <= 0 {
                continue;
            }
            let queue_id = live.socket_queue_id();
            let tx_bytes = live.tx_bytes();
            let rate = match self.rebalance_last_tx_bytes.get(&worker_id) {
                Some(&(prev_bytes, prev_ns)) if now_ns > prev_ns => {
                    let dt = (now_ns - prev_ns) as f64 / 1_000_000_000.0;
                    if dt > 0.0 {
                        (tx_bytes.saturating_sub(prev_bytes)) as f64 / dt
                    } else {
                        0.0
                    }
                }
                _ => 0.0,
            };
            self.rebalance_last_tx_bytes
                .insert(worker_id, (tx_bytes, now_ns));
            worker_ifindex.insert(worker_id, ifindex);
            per_iface_workers
                .entry(ifindex)
                .or_default()
                .push(WorkerByteRate { worker_id, queue_id, byte_rate: rate });
        }

        // 2. Per-flow samples (5-tuple key + worker + byte-rate) grouped by
        //    ifindex, from the flow-worker map telemetry.
        let mut per_iface_flows: BTreeMap<i32, Vec<FlowSample>> = BTreeMap::new();
        let (rows, _truncated) = self.flow_worker_map();
        for row in rows {
            // Only forward-direction flows on the steered ifindex with a
            // resolvable 5-tuple. The flow-worker row carries observed_bytes
            // over the window for byte-rate-aware selection.
            let ifindex = row.ifindex;
            if ifindex <= 0 || !per_iface_workers.contains_key(&ifindex) {
                continue;
            }
            let Some(key) = session_key_from_tuple(&row.session_key) else {
                continue;
            };
            per_iface_flows.entry(ifindex).or_default().push(FlowSample {
                key,
                worker_id: row.worker_id,
                byte_rate: row.observed_bytes as f64,
            });
        }

        // 3. Tick each steered interface's controller.
        let ifindexes: Vec<i32> = per_iface_workers.keys().copied().collect();
        for ifindex in ifindexes {
            let workers = per_iface_workers.remove(&ifindex).unwrap_or_default();
            let flows = per_iface_flows.remove(&ifindex).unwrap_or_default();
            if workers.len() < 2 {
                continue;
            }
            if !self.rebalance_controllers.contains_key(&ifindex) {
                // Lazily construct the controller + open the ntuple socket the
                // first time we see a steerable interface. Failure to open is
                // non-fatal: log once and skip (the NIC may not support flow
                // steering — the default path is unaffected).
                // The interface's current kernel netdev name. xpfd renames
                // interfaces to their vSRX names at startup, so `ifindex_to_name`
                // is the live kernel name ethtool ioctls address.
                let Some(ifname) = self.forwarding.ifindex_to_name.get(&ifindex).cloned()
                else {
                    continue;
                };
                match NtupleSocket::open(&ifname) {
                    Ok(sock) => {
                        self.rebalance_controllers
                            .insert(ifindex, RebalanceController::new(config, sock));
                    }
                    Err(e) => {
                        eprintln!(
                            "xpf-rebalance: cannot open ntuple socket on {ifname} (ifindex {ifindex}): {e} — skipping"
                        );
                        continue;
                    }
                }
            }

            let input = RebalanceTickInput { ifindex, workers, flows, now_secs };
            // Take the controller out so the barrier transport can borrow
            // `self` mutably without aliasing the controller. Put it back.
            let mut controller = self.rebalance_controllers.remove(&ifindex).unwrap();
            let socket_ptr: *const NtupleSocket = controller.socket();
            let outcome = {
                // SAFETY: the controller (and its socket) is owned here for the
                // tick; the transport borrows `self` for command queues + the
                // socket by shared ref. They do not alias mutably.
                let mut tx = CoordinatorBarrierTransport {
                    coord: self,
                    socket: unsafe { &*socket_ptr },
                };
                controller.tick(&input, &mut tx)
            };
            if let Some(mv) = outcome {
                slog_debug_rebalance_move(ifindex, &mv);
            }
            self.rebalance_controllers.insert(ifindex, controller);
        }
    }

    /// Snapshot the per-interface rebalance metrics for the Prometheus
    /// collector. Returns (ifindex, metrics) for every live controller.
    pub(in crate::afxdp) fn rebalance_metrics(
        &self,
    ) -> Vec<(i32, crate::afxdp::rebalance::RebalanceMetrics)> {
        self.rebalance_controllers
            .iter()
            .map(|(&ifindex, c)| (ifindex, c.metrics().clone()))
            .collect()
    }

    /// Build the wire status rows for the Prometheus collector. Empty when no
    /// controller is live (knob off).
    pub fn flow_rebalance_status(&self) -> Vec<crate::protocol::FlowRebalanceStatus> {
        self.rebalance_controllers
            .iter()
            .map(|(&ifindex, c)| {
                let m = c.metrics();
                let moves_skipped = m
                    .moves_skipped
                    .iter()
                    .map(|(reason, count)| (reason.as_str().to_string(), *count))
                    .collect();
                crate::protocol::FlowRebalanceStatus {
                    ifindex,
                    rules_active: m.rules_active,
                    installs_total: m.installs_total,
                    deletes_total: m.deletes_total,
                    moves_skipped,
                    worker_byterate_cov: m.worker_byterate_cov,
                }
            })
            .collect()
    }

    /// Send a single rebalance WorkerCommand to `worker_id` and block until
    /// its structured ack confirms the EXACT key reached `expected` (or until
    /// the deadline). Returns the ack's `result && origin == expected`.
    fn barrier_command(
        &self,
        worker_id: u32,
        key: &SessionKey,
        expected: SessionOrigin,
        make_cmd: impl FnOnce(u64, SessionKey) -> WorkerCommand,
    ) -> bool {
        let Some(handle) = self.workers.handles.get(&worker_id) else {
            return false;
        };
        // Monotonic per-worker seq: reuse the rebalance_ack_seq as the
        // generator base + 1 so each command has a strictly-increasing seq the
        // worker echoes back.
        let seq = handle.rebalance_ack_seq.load(Ordering::Acquire).saturating_add(1);
        {
            let Ok(mut pending) = handle.commands.lock() else {
                return false;
            };
            pending.push_back(make_cmd(seq, key.clone()));
        }
        let deadline = Instant::now() + REBALANCE_ACK_TIMEOUT;
        loop {
            if handle.rebalance_ack_seq.load(Ordering::Acquire) >= seq {
                // Read the structured slot and confirm key + origin.
                if let Ok(slot) = handle.rebalance_ack.lock() {
                    if let Some(ack) = slot.as_ref() {
                        if ack.seq >= seq {
                            return ack_confirms(ack, key, expected);
                        }
                    }
                }
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(REBALANCE_ACK_POLL);
        }
    }
}

/// Confirm a structured ack matches the expected key + origin.
fn ack_confirms(ack: &RebalanceAck, key: &SessionKey, expected: SessionOrigin) -> bool {
    ack.result && &ack.key == key && ack.origin == Some(expected)
}

/// The Coordinator-backed BarrierTransport: drives the worker command queues
/// + ack slots for the ownership-transfer barrier, and programs the NIC via
/// the per-interface ntuple socket.
struct CoordinatorBarrierTransport<'a> {
    coord: &'a super::Coordinator,
    socket: &'a NtupleSocket,
}

impl BarrierTransport for CoordinatorBarrierTransport<'_> {
    fn promote(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.coord.barrier_command(
            worker_id,
            key,
            SessionOrigin::RebalancedOwner,
            |seq, key| WorkerCommand::PromoteRebalanced { seq, key },
        )
    }
    fn demote(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.coord.barrier_command(
            worker_id,
            key,
            SessionOrigin::RebalancedOut,
            |seq, key| WorkerCommand::DemoteRebalanced { seq, key },
        )
    }
    fn restore_owner(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.coord.barrier_command(
            worker_id,
            key,
            SessionOrigin::ForwardFlow,
            |seq, key| WorkerCommand::RestoreRebalancedOwner { seq, key },
        )
    }
    fn demote_replica(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.coord.barrier_command(
            worker_id,
            key,
            SessionOrigin::WorkerLocalImport,
            |seq, key| WorkerCommand::DemoteRebalancedReplica { seq, key },
        )
    }
    fn install_rule(&mut self, flow: &FlowSpec5Tuple, queue: u32) -> std::io::Result<u32> {
        self.socket.insert_rule(flow, queue)
    }
    fn delete_rule(&mut self, loc: u32) -> std::io::Result<()> {
        self.socket.delete_rule(loc)
    }
}

/// Translate a `FlowTupleStatus` (the flow-worker map's serialized 5-tuple)
/// back into a `SessionKey`. Returns None if the addresses don't parse.
fn session_key_from_tuple(t: &crate::protocol::FlowTupleStatus) -> Option<SessionKey> {
    use std::net::IpAddr;
    let src_ip: IpAddr = t.src_ip.parse().ok()?;
    let dst_ip: IpAddr = t.dst_ip.parse().ok()?;
    Some(SessionKey {
        addr_family: t.addr_family,
        protocol: t.protocol,
        src_ip,
        dst_ip,
        src_port: t.src_port,
        dst_port: t.dst_port,
    })
}

/// Per-move debug log (slog.Debug-equivalent — fires only on the rare event
/// of an actual move, never per-tick). Goes to journald via stderr.
fn slog_debug_rebalance_move(
    ifindex: i32,
    mv: &crate::afxdp::rebalance::MoveOutcome,
) {
    eprintln!(
        "xpf-rebalance: moved flow {:?} ifindex={ifindex} worker {} -> {} (rule loc {})",
        flow_spec_from_key(&mv.key),
        mv.old_worker,
        mv.new_worker,
        mv.loc,
    );
}
