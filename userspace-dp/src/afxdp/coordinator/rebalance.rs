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
    WorkerByteRate, cumulative_to_rate, flow_spec_from_key, NtupleSocket,
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
        self.rebalance_last_flow_bytes.clear();
    }

    /// Tear down one interface's controller: reverse-barrier its live moves,
    /// delete its rules, drop the socket. `is_live_on_new` cannot be known
    /// cheaply here, so we conservatively treat every ledger entry as live
    /// (the reverse barrier is idempotent and safe for an already-dead flow).
    fn teardown_rebalance_controller(&mut self, ifindex: i32) {
        let Some(mut controller) = self.rebalance_controllers.remove(&ifindex) else {
            return;
        };
        // #1748 review-r3 (soundness): take the socket OUT of its separate map
        // so it is an owned local, independent of `self`. The transport borrows
        // the local socket + `&self` for the barrier; the controller is a
        // separate owned local. No aliasing, no raw pointer.
        let Some(socket) = self.rebalance_sockets.remove(&ifindex) else {
            return;
        };
        let mut tx = CoordinatorBarrierTransport {
            coord: self,
            socket: &socket,
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
            // #1748 review-r3 (soundness): owned-local socket, separate from the
            // owned-local controller — no aliasing / raw pointer.
            let Some(socket) = self.rebalance_sockets.remove(&ifindex) else {
                continue;
            };
            let mut tx = CoordinatorBarrierTransport {
                coord: self,
                socket: &socket,
            };
            // is_live_on_new = false => plain delete for every entry.
            controller.teardown_all(&mut tx, |_w, _k| false);
        }
        // Any sockets without a controller (shouldn't happen — maps are kept in
        // lockstep) are still dropped here so no fd leaks across a teardown.
        self.rebalance_sockets.clear();
        self.rebalance_last_tx_bytes.clear();
        self.rebalance_last_flow_bytes.clear();
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
                Some(&(prev_bytes, prev_ns)) => {
                    cumulative_to_rate(tx_bytes, prev_bytes, now_ns, prev_ns)
                }
                None => 0.0,
            };
            self.rebalance_last_tx_bytes
                .insert(worker_id, (tx_bytes, now_ns));
            worker_ifindex.insert(worker_id, ifindex);
            per_iface_workers
                .entry(ifindex)
                .or_default()
                .push(WorkerByteRate { worker_id, queue_id, byte_rate: rate });
        }

        // 2. Per-flow samples (5-tuple key + worker + byte-RATE) grouped by
        //    ifindex, from the flow-worker map telemetry.
        //
        // #1748 review #8: row.observed_bytes is CUMULATIVE bytes for the
        // cached flow, NOT a per-window rate. Using cumulative bytes as the
        // selection signal makes a long-lived but now-idle flow look "hottest"
        // forever, so the controller would pick the wrong flow to move and the
        // magnitude<=gap/2 guard (which compares against per-worker rates)
        // would be meaningless. Derive an actual byte-RATE = (current_cumulative
        // - last_sample_cumulative) / elapsed, maintaining a per-flow previous
        // sample across ticks (the controller runs at a fixed cadence).
        let mut per_iface_flows: BTreeMap<i32, Vec<FlowSample>> = BTreeMap::new();
        let (rows, _truncated) = self.flow_worker_map();
        let mut seen_flow_keys: std::collections::HashSet<SessionKey> =
            std::collections::HashSet::new();
        for row in rows {
            // Only forward-direction flows on the steered ifindex with a
            // resolvable 5-tuple.
            let ifindex = row.ifindex;
            if ifindex <= 0 || !per_iface_workers.contains_key(&ifindex) {
                continue;
            }
            let Some(key) = session_key_from_tuple(&row.session_key) else {
                continue;
            };
            // ntuple rules only support TCP and UDP; skip other protocols
            // (e.g. ICMP) so flow_spec_from_key never misencodes them as UDP
            // and we never transfer ownership without a matching HW rule.
            if key.protocol != super::super::PROTO_TCP
                && key.protocol != super::super::PROTO_UDP
            {
                continue;
            }
            let cumulative = row.observed_bytes;
            // First observation of this flow => no rate yet (a brand-new flow's
            // first-tick cumulative is not a window rate). cumulative_to_rate
            // also handles a cumulative reset on re-home via saturating_sub.
            let rate = match self.rebalance_last_flow_bytes.get(&key) {
                Some(&(prev_bytes, prev_ns)) => {
                    cumulative_to_rate(cumulative, prev_bytes, now_ns, prev_ns)
                }
                None => 0.0,
            };
            self.rebalance_last_flow_bytes
                .insert(key.clone(), (cumulative, now_ns));
            seen_flow_keys.insert(key.clone());
            per_iface_flows.entry(ifindex).or_default().push(FlowSample {
                key,
                worker_id: row.worker_id,
                byte_rate: rate,
            });
        }
        // Prune previous-sample entries for flows that disappeared this tick so
        // the map does not grow unbounded across the daemon's lifetime.
        self.rebalance_last_flow_bytes
            .retain(|k, _| seen_flow_keys.contains(k));

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
                        // #1748 AGY minor: clear any orphan ntuple rules left
                        // by a previous (crashed) daemon run on this interface
                        // before we start installing fresh ones, so stale HW
                        // rules cannot accumulate or exhaust the rule-table cap.
                        match sock.reconcile_orphans() {
                            Ok(0) => {}
                            Ok(n) => eprintln!(
                                "xpf-rebalance: cleared {n} orphan ntuple rule(s) on {ifname} (ifindex {ifindex}) at startup"
                            ),
                            Err(e) => eprintln!(
                                "xpf-rebalance: startup orphan reconcile on {ifname} (ifindex {ifindex}) failed: {e}"
                            ),
                        }
                        // Keep the two maps in lockstep: socket in
                        // rebalance_sockets, ledger/metrics in
                        // rebalance_controllers.
                        self.rebalance_sockets.insert(ifindex, sock);
                        self.rebalance_controllers
                            .insert(ifindex, RebalanceController::new(config));
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
            // #1748 review-r3 (soundness): take BOTH the controller and its
            // socket out as independent owned locals, run the tick (transport
            // borrows the local socket + `&self`; controller is borrowed `&mut`
            // separately — no aliasing, no raw pointer), then put both back.
            let mut controller = self.rebalance_controllers.remove(&ifindex).unwrap();
            let socket = self
                .rebalance_sockets
                .remove(&ifindex)
                .expect("rebalance_sockets kept in lockstep with rebalance_controllers");
            let outcome = {
                let mut tx = CoordinatorBarrierTransport {
                    coord: self,
                    socket: &socket,
                };
                controller.tick(&input, &mut tx)
            };
            self.rebalance_sockets.insert(ifindex, socket);
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
        // Use the dedicated coordinator-side command seq generator (not the
        // ack seq) so each command gets a unique, strictly-increasing seq
        // even if a previous command timed out without being acked (in which
        // case rebalance_ack_seq would not have advanced, causing a collision
        // if we derived the new seq from it).
        // Relaxed is sufficient: we only need uniqueness across barrier_command
        // calls, which are always made from the same coordinator thread. The
        // seq is delivered to the worker via the command queue (Mutex), which
        // establishes the necessary happens-before for the worker's ack.
        let seq = handle.rebalance_cmd_seq.fetch_add(1, Ordering::Relaxed) + 1;
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
                        // ack.seq == seq → exact match; return the result.
                        // ack.seq > seq  → slot overwritten by a later command
                        //   before we polled; keep waiting until the deadline
                        //   rather than returning the wrong ack's result.
                        // ack.seq < seq  → stale ack from a prior command;
                        //   keep polling until the worker writes our seq.
                        if ack.seq == seq {
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
