// #1748: reactive cross-worker ntuple rebalance controller.
//
// Ticked at the coordinator status cadence (~1 Hz, NOT per-packet, NOT
// per-poll). On each tick it derives per-worker byte-rate over the window,
// and — only when the imbalance has persisted past the dwell — moves the
// single flow whose relocation most flattens the per-worker byte-rate
// vector, subject to a magnitude guard (<= gap/2), a per-flow cooldown, an
// epsilon improvement band, and a hard rule budget with STOP-on-exhaustion
// (NO eviction). The move itself is a barriered ownership transfer
// (`promote W_new -> ack -> demote W_old -> ack -> install rule`); rollback
// and teardown-of-a-live-move use the reverse barrier.
//
// Default-OFF: when the knob is unset the Coordinator never constructs a
// controller, so there is zero extra per-tick work and zero ioctl sockets.

use std::collections::HashMap;
use std::net::IpAddr;

use super::ntuple::{FlowProto, FlowSpec5Tuple, NtupleSocket};
use crate::session::SessionKey;

/// Operator-tunable knobs compiled from the `class-of-service flow-rebalance`
/// config leaf. Absent leaf => `None` controller => default path untouched.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::afxdp) struct RebalanceConfig {
    /// `max_worker_rate / mean_rate` must exceed this to consider a move.
    pub imbalance_threshold: f64,
    /// Minimum seconds between rule installs (dwell / one-move-per-interval).
    pub rebalance_interval_secs: u64,
    /// Hard cap on concurrently-installed xpf rules per interface.
    pub max_rules: u32,
}

impl Default for RebalanceConfig {
    fn default() -> Self {
        Self {
            imbalance_threshold: 1.30,
            rebalance_interval_secs: 1,
            max_rules: 64,
        }
    }
}

impl RebalanceConfig {
    /// A config is meaningful only with a positive threshold and budget.
    pub(in crate::afxdp) fn is_enabled(&self) -> bool {
        self.imbalance_threshold > 1.0 && self.max_rules > 0
    }
}

/// Reason a candidate move was skipped — exported as the
/// `moves_skipped_total{reason}` metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(in crate::afxdp) enum SkipReason {
    /// Imbalance below threshold or not yet persisted past the dwell.
    Balanced,
    /// Within the per-flow cooldown window.
    Cooldown,
    /// Moving the flow would make the destination the new hottest worker.
    Magnitude,
    /// Projected byte-rate CoV improvement did not exceed epsilon.
    Epsilon,
    /// Rule budget exhausted (STOP — no eviction).
    BudgetExhausted,
    /// Barrier failed (ack timeout / key absent / ioctl error) — rolled back.
    BarrierFailed,
    /// One move already happened this interval.
    Dwell,
    /// Reverse-barrier restore of W_old failed (timeout / key absent) during
    /// rollback or teardown — W_new is intentionally LEFT as owner so >= 1
    /// cleanup owner remains (#1748 review #4). Operator-visible: a non-zero
    /// rate here means worker command acks are stalling under load.
    RestoreFailed,
}

impl SkipReason {
    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Cooldown => "cooldown",
            Self::Magnitude => "magnitude",
            Self::Epsilon => "epsilon",
            Self::BudgetExhausted => "budget_exhausted",
            Self::BarrierFailed => "barrier_failed",
            Self::Dwell => "dwell",
            Self::RestoreFailed => "restore_failed",
        }
    }
}

/// Per-interface controller metrics (exported as
/// `xpf_userspace_flow_rebalance_*{ifindex}`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(in crate::afxdp) struct RebalanceMetrics {
    pub rules_active: u32,
    pub installs_total: u64,
    pub deletes_total: u64,
    pub moves_skipped: HashMap<SkipReason, u64>,
    /// Coefficient of variation of the per-worker byte-rate at the last tick.
    pub worker_byterate_cov: f64,
}

impl RebalanceMetrics {
    fn record_skip(&mut self, reason: SkipReason) {
        *self.moves_skipped.entry(reason).or_insert(0) += 1;
    }
}

/// One worker's byte-rate sample for the current tick.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct WorkerByteRate {
    pub worker_id: u32,
    pub queue_id: u32,
    /// Bytes/sec over the observation window.
    pub byte_rate: f64,
}

/// One live flow eligible to move: its 5-tuple key, current worker, and
/// observed byte-rate over the window.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct FlowSample {
    pub key: SessionKey,
    pub worker_id: u32,
    pub byte_rate: f64,
}

/// Per-tick input snapshot the Coordinator assembles from existing
/// telemetry (umem `tx_bytes` deltas keyed by worker + the flow-worker map).
pub(in crate::afxdp) struct RebalanceTickInput {
    pub ifindex: i32,
    pub workers: Vec<WorkerByteRate>,
    pub flows: Vec<FlowSample>,
    /// Monotonic seconds (for cooldown / dwell timing).
    pub now_secs: u64,
}

/// The transport the controller uses to drive the barriered move and program
/// the NIC. The Coordinator implements this against its worker command queues
/// + ack slots + the per-interface `NtupleSocket`. Abstracted so the
/// selection/barrier logic is unit-testable with a mock.
pub(in crate::afxdp) trait BarrierTransport {
    /// Promote W_new's replica to RebalancedOwner; block until acked. Returns
    /// true iff the worker confirmed the key reached `RebalancedOwner`.
    fn promote(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Demote W_old's entry to RebalancedOut; block until acked. Returns true
    /// iff the worker confirmed the key reached `RebalancedOut`.
    fn demote(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Reverse-barrier: restore W_old to a local owner; block until acked.
    fn restore_owner(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Reverse-barrier: demote W_new back to a worker-local replica; block
    /// until acked.
    fn demote_replica(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Install the exact-5-tuple rule steering the flow to `queue`. Returns
    /// the rule location on success.
    fn install_rule(&mut self, flow: &FlowSpec5Tuple, queue: u32) -> std::io::Result<u32>;
    /// Delete the rule at `loc`.
    fn delete_rule(&mut self, loc: u32) -> std::io::Result<()>;
}

/// A live move record in the controller's in-memory ledger.
#[derive(Clone, Debug)]
struct LedgerEntry {
    key: SessionKey,
    /// The worker the flow was steered AWAY from (W_old). #1748 review #2:
    /// the reverse barrier on teardown/rollback must restore THIS worker to
    /// owner, not `new_worker`. The RSS-natural worker for the flow once the
    /// rule is gone IS the original source worker (RSS hashing is
    /// deterministic on the 5-tuple), so restoring `old_worker` hands
    /// ownership to exactly the worker that will receive the packets.
    old_worker: u32,
    /// The worker the flow now lives on (W_new).
    new_worker: u32,
    /// The driver-assigned ntuple rule location.
    loc: u32,
}

/// Persistent controller state for one interface. Owns the NtupleSocket only
/// when the knob is enabled.
pub(in crate::afxdp) struct RebalanceController {
    config: RebalanceConfig,
    socket: NtupleSocket,
    ledger: Vec<LedgerEntry>,
    /// Per-flow cooldown: key -> monotonic secs until which it is ineligible.
    cooldown: HashMap<SessionKey, u64>,
    /// Monotonic secs of the last install (dwell gate).
    last_move_secs: u64,
    /// Ticks the imbalance has persisted above threshold (hysteresis).
    dwell_ticks: u32,
    metrics: RebalanceMetrics,
}

/// Number of consecutive over-threshold ticks required before the first move
/// (hysteresis floor — avoids reacting to a single noisy sample).
const DWELL_TICKS_REQUIRED: u32 = 2;

/// Minimum fractional CoV improvement a move must project to be worth doing.
const EPSILON_COV_IMPROVEMENT: f64 = 0.02;

impl RebalanceController {
    pub(in crate::afxdp) fn new(
        config: RebalanceConfig,
        socket: NtupleSocket,
    ) -> Self {
        Self {
            config,
            socket,
            ledger: Vec::new(),
            cooldown: HashMap::new(),
            last_move_secs: 0,
            dwell_ticks: 0,
            metrics: RebalanceMetrics::default(),
        }
    }

    pub(in crate::afxdp) fn metrics(&self) -> &RebalanceMetrics {
        &self.metrics
    }

    /// Borrow the owned NtupleSocket as a BarrierTransport rule programmer.
    pub(in crate::afxdp) fn socket(&self) -> &NtupleSocket {
        &self.socket
    }

    /// Test-only: clear the per-flow cooldown so a unit test can drive a
    /// second move of the same key without waiting out the cooldown window.
    #[cfg(test)]
    pub(in crate::afxdp) fn clear_cooldown_for_test(&mut self) {
        self.cooldown.clear();
    }

    /// One controller tick. Pure decision + barriered move. `tx` drives the
    /// worker barrier and NIC programming. Returns the move outcome for the
    /// caller's logging (None = no move attempted/taken this tick).
    pub(in crate::afxdp) fn tick<T: BarrierTransport>(
        &mut self,
        input: &RebalanceTickInput,
        tx: &mut T,
    ) -> Option<MoveOutcome> {
        // Always refresh the CoV gauge so operators see the live imbalance
        // even when no move is taken.
        let cov = byte_rate_cov(&input.workers);
        self.metrics.worker_byterate_cov = cov;
        self.expire_cooldowns(input.now_secs);

        // Hysteresis: count consecutive over-threshold ticks.
        let over_threshold = self.is_over_threshold(&input.workers);
        if over_threshold {
            self.dwell_ticks = self.dwell_ticks.saturating_add(1);
        } else {
            self.dwell_ticks = 0;
            self.metrics.record_skip(SkipReason::Balanced);
            return None;
        }
        if self.dwell_ticks < DWELL_TICKS_REQUIRED {
            self.metrics.record_skip(SkipReason::Balanced);
            return None;
        }

        // One move per rebalance_interval (dwell gate on install cadence).
        if input.now_secs.saturating_sub(self.last_move_secs)
            < self.config.rebalance_interval_secs
        {
            self.metrics.record_skip(SkipReason::Dwell);
            return None;
        }

        // Budget gate: STOP at the cap, never evict.
        if self.ledger.len() as u32 >= self.config.max_rules {
            self.metrics.record_skip(SkipReason::BudgetExhausted);
            return None;
        }

        let Some(mut candidate) = self.select_move(input) else {
            // select_move records the precise skip reason.
            return None;
        };

        // #1748 review #6: SECOND MOVE of a key already in the ledger. The
        // flow currently lives on its prior W_new (the ledger's `new_worker`)
        // under a still-installed rule. Moving it to a third worker must first
        // unwind that prior move at the CONTROLLER level — delete the old rule
        // and reverse-barrier the prior owner back — so the flow is RSS-placed
        // again before the new forward barrier re-pins it. Without this the
        // controller just appends a second ledger entry and a second rule for
        // the same 5-tuple (the second rule may never even take effect, and
        // the prior owner is left RebalancedOwner forever). We replace, not
        // append.
        let prior_idx = self
            .ledger
            .iter()
            .position(|e| e.key == candidate.key);
        if let Some(idx) = prior_idx {
            let prior = self.ledger[idx].clone();
            // #1748 review-r2 MAJOR: `old_worker` is the RSS-natural worker for
            // the 5-tuple — the worker the flow lands on when NO rebalance rule
            // exists. RSS is deterministic on the tuple, so this is INVARIANT
            // across moves. On a second move `candidate.old_worker` is the prior
            // W_new (the flow's *current* worker mid-move), NOT the RSS-natural
            // worker. Carry the prior entry's `old_worker` forward so (a) the
            // forward-barrier demote below targets the correct worker and (b)
            // the replacement ledger entry records the RSS-natural worker, so a
            // later teardown restores it (not the prior W_new).
            candidate.old_worker = prior.old_worker;
            // Reverse barrier on the prior move: restore the prior W_old to
            // owner, delete the prior rule, demote the prior W_new to replica.
            // Gate the W_new demote on a successful restore ack (#1748 #4): if
            // the restore times out we must NOT demote the only owner.
            if !tx.restore_owner(prior.old_worker, &prior.key) {
                // Could not hand ownership back to the prior W_old. Abort the
                // second move and leave the prior move intact (>= 1 owner is
                // still the prior W_new). Do not append a second rule.
                // #1748 review-r2 MINOR: this is a restore-ack failure — record
                // RestoreFailed, matching the other three restore-fail sites.
                self.metrics.record_skip(SkipReason::RestoreFailed);
                return None;
            }
            // #1748 review-r2 MINOR: handle the prior-rule delete failure. If
            // the delete fails we must NOT proceed to install a new rule for
            // the same 5-tuple — that re-creates the duplicate-HW-rule hazard
            // #6 fixed. Abort the move this tick and KEEP the prior ledger
            // entry (the prior rule is still installed and still steering to
            // the prior W_new). We restored W_old above, but restore_owner is
            // an idempotent tag flip and the prior W_new is still
            // RebalancedOwner, so >= 1 owner holds; the next tick retries the
            // delete. Do NOT demote the prior W_new here (its rule still
            // routes traffic to it).
            if tx.delete_rule(prior.loc).is_err() {
                self.metrics.record_skip(SkipReason::BarrierFailed);
                return None;
            }
            tx.demote_replica(prior.new_worker, &prior.key);
            self.metrics.deletes_total += 1;
            self.ledger.remove(idx);
            self.metrics.rules_active = self.ledger.len() as u32;
        }

        // Forward barrier: promote W_new BEFORE the rule, then demote W_old,
        // then install. Both before the rule so a racing GC on either side
        // sees a safe origin (the applied-command ack serializes promote
        // before demote so there is always >= 1 cleanup owner).
        if !tx.promote(candidate.new_worker, &candidate.key) {
            self.metrics.record_skip(SkipReason::BarrierFailed);
            // Nothing to roll back: the only mutation attempted was the
            // promote, which failed to commit. Reverse it defensively.
            tx.demote_replica(candidate.new_worker, &candidate.key);
            return None;
        }
        if !tx.demote(candidate.old_worker, &candidate.key) {
            self.metrics.record_skip(SkipReason::BarrierFailed);
            // Reverse barrier: restore W_old to owner FIRST, and only demote
            // W_new back to a replica if that restore is acked (#1748 #4). If
            // the restore fails (timeout / key absent on W_old), keep W_new as
            // the owner — demoting it would lose the only cleanup owner.
            if tx.restore_owner(candidate.old_worker, &candidate.key) {
                tx.demote_replica(candidate.new_worker, &candidate.key);
            } else {
                self.metrics.record_skip(SkipReason::RestoreFailed);
            }
            return None;
        }
        // Only after BOTH acks: install the rule.
        let spec = flow_spec_from_key(&candidate.key);
        match tx.install_rule(&spec, candidate.new_queue) {
            Ok(loc) => {
                self.ledger.push(LedgerEntry {
                    key: candidate.key.clone(),
                    old_worker: candidate.old_worker,
                    new_worker: candidate.new_worker,
                    loc,
                });
                self.cooldown.insert(
                    candidate.key.clone(),
                    input.now_secs
                        + self.config.rebalance_interval_secs
                            * COOLDOWN_INTERVAL_MULTIPLIER,
                );
                self.last_move_secs = input.now_secs;
                self.dwell_ticks = 0;
                self.metrics.installs_total += 1;
                self.metrics.rules_active = self.ledger.len() as u32;
                Some(MoveOutcome {
                    key: candidate.key,
                    old_worker: candidate.old_worker,
                    new_worker: candidate.new_worker,
                    loc,
                })
            }
            Err(_) => {
                self.metrics.record_skip(SkipReason::BarrierFailed);
                // Rule install failed: reverse the ownership transfer with the
                // reverse barrier so >= 1 cleanup owner remains. Gate the W_new
                // demote on the W_old restore ack (#1748 #4).
                if tx.restore_owner(candidate.old_worker, &candidate.key) {
                    tx.demote_replica(candidate.new_worker, &candidate.key);
                } else {
                    self.metrics.record_skip(SkipReason::RestoreFailed);
                }
                None
            }
        }
    }

    /// Tear down ALL installed rules (controller disable / daemon shutdown).
    /// A still-live move must reverse the ownership transfer BEFORE the rule
    /// is removed (reverse barrier): restore W_old -> owner + ack, delete the
    /// rule, then demote W_new -> replica + ack. Only a flow already expired
    /// off W_new is a plain rule delete — but the controller cannot prove
    /// that here, so it conservatively reverse-barriers every live ledger
    /// entry. The caller passes the set of keys still present on W_new (live)
    /// vs gone (dead); empty `live_keys` => all plain deletes.
    pub(in crate::afxdp) fn teardown_all<T: BarrierTransport, F>(
        &mut self,
        tx: &mut T,
        mut is_live_on_new: F,
    ) where
        F: FnMut(u32, &SessionKey) -> bool,
    {
        let entries = std::mem::take(&mut self.ledger);
        for entry in entries {
            if is_live_on_new(entry.new_worker, &entry.key) {
                // Reverse barrier: hand ownership back to the REAL W_old
                // (entry.old_worker — #1748 review #2), which is the
                // RSS-natural worker that will receive the flow once the rule
                // is gone, BEFORE removing the rule. Gate the W_new demote on
                // the restore ack (#1748 #4): if W_old cannot be restored, keep
                // W_new as the owner rather than demoting the only owner away.
                if tx.restore_owner(entry.old_worker, &entry.key) {
                    let _ = tx.delete_rule(entry.loc);
                    tx.demote_replica(entry.new_worker, &entry.key);
                } else {
                    self.metrics.record_skip(SkipReason::RestoreFailed);
                    // Delete the rule anyway (RSS will re-hash to W_old which
                    // keeps the packets via origin-agnostic last_seen refresh),
                    // but leave W_new as RebalancedOwner so >= 1 cleanup owner
                    // remains until its own GC.
                    let _ = tx.delete_rule(entry.loc);
                }
            } else {
                // Flow already expired off W_new — no live ownership to hand
                // back; plain rule delete.
                let _ = tx.delete_rule(entry.loc);
            }
            self.metrics.deletes_total += 1;
        }
        self.metrics.rules_active = 0;
    }

    fn is_over_threshold(&self, workers: &[WorkerByteRate]) -> bool {
        let (max, mean) = max_and_mean(workers);
        mean > 0.0 && (max / mean) > self.config.imbalance_threshold
    }

    fn expire_cooldowns(&mut self, now_secs: u64) {
        self.cooldown.retain(|_, &mut until| until > now_secs);
    }

    /// Byte-rate-aware selection: among flows on the hottest worker, pick the
    /// one whose move to the least-loaded worker most reduces the per-worker
    /// byte-rate CoV, subject to magnitude guard + cooldown + epsilon band.
    /// Records the precise skip reason on the no-move paths.
    fn select_move(&mut self, input: &RebalanceTickInput) -> Option<MoveCandidate> {
        if input.workers.len() < 2 {
            self.metrics.record_skip(SkipReason::Balanced);
            return None;
        }
        // Hottest (source) and least-loaded (destination) workers.
        let hottest = input
            .workers
            .iter()
            .max_by(|a, b| a.byte_rate.total_cmp(&b.byte_rate))?;
        let coolest = input
            .workers
            .iter()
            .min_by(|a, b| a.byte_rate.total_cmp(&b.byte_rate))?;
        if hottest.worker_id == coolest.worker_id {
            self.metrics.record_skip(SkipReason::Balanced);
            return None;
        }
        let gap = hottest.byte_rate - coolest.byte_rate;
        let baseline_cov = byte_rate_cov(&input.workers);

        // Candidate flows: those currently on the hottest worker, heaviest
        // first, not in cooldown.
        let mut candidates: Vec<&FlowSample> = input
            .flows
            .iter()
            .filter(|f| f.worker_id == hottest.worker_id)
            .collect();
        candidates.sort_by(|a, b| b.byte_rate.total_cmp(&a.byte_rate));

        let mut had_cooldown_skip = false;
        let mut had_magnitude_skip = false;
        let mut best: Option<(MoveCandidate, f64)> = None;
        for flow in candidates {
            if self.cooldown.contains_key(&flow.key) {
                had_cooldown_skip = true;
                continue;
            }
            // Magnitude guard: moving it must not make the destination the new
            // hottest worker (flow rate <= gap/2).
            if flow.byte_rate > gap / 2.0 {
                had_magnitude_skip = true;
                continue;
            }
            // Project the post-move byte-rate vector and its CoV.
            let projected = project_move(
                &input.workers,
                hottest.worker_id,
                coolest.worker_id,
                flow.byte_rate,
            );
            let projected_cov = byte_rate_cov(&projected);
            let improvement = baseline_cov - projected_cov;
            if improvement <= EPSILON_COV_IMPROVEMENT {
                continue;
            }
            let cand = MoveCandidate {
                key: flow.key.clone(),
                old_worker: hottest.worker_id,
                new_worker: coolest.worker_id,
                new_queue: coolest.queue_id,
            };
            match &best {
                Some((_, best_imp)) if *best_imp >= improvement => {}
                _ => best = Some((cand, improvement)),
            }
        }

        if let Some((cand, _)) = best {
            return Some(cand);
        }
        // No winning move — attribute the dominant skip reason.
        let reason = if had_magnitude_skip {
            SkipReason::Magnitude
        } else if had_cooldown_skip {
            SkipReason::Cooldown
        } else {
            SkipReason::Epsilon
        };
        self.metrics.record_skip(reason);
        None
    }
}

/// Cooldown is several rebalance intervals so a flow re-pinned cannot
/// immediately thrash back (oscillation guard, research §4 R6).
const COOLDOWN_INTERVAL_MULTIPLIER: u64 = 5;

#[derive(Clone, Debug)]
struct MoveCandidate {
    key: SessionKey,
    old_worker: u32,
    new_worker: u32,
    new_queue: u32,
}

/// The outcome of a committed move, for caller-side logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct MoveOutcome {
    pub key: SessionKey,
    pub old_worker: u32,
    pub new_worker: u32,
    pub loc: u32,
}

/// Compute the max and mean of a per-worker byte-rate vector.
fn max_and_mean(workers: &[WorkerByteRate]) -> (f64, f64) {
    if workers.is_empty() {
        return (0.0, 0.0);
    }
    let sum: f64 = workers.iter().map(|w| w.byte_rate).sum();
    let max = workers
        .iter()
        .map(|w| w.byte_rate)
        .fold(0.0_f64, f64::max);
    (max, sum / workers.len() as f64)
}

/// Coefficient of variation (stddev / mean) of the per-worker byte-rates.
/// Returns 0 for a degenerate (empty / zero-mean) vector.
pub(in crate::afxdp) fn byte_rate_cov(workers: &[WorkerByteRate]) -> f64 {
    if workers.is_empty() {
        return 0.0;
    }
    let n = workers.len() as f64;
    let mean = workers.iter().map(|w| w.byte_rate).sum::<f64>() / n;
    if mean <= 0.0 {
        return 0.0;
    }
    let var = workers
        .iter()
        .map(|w| {
            let d = w.byte_rate - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    var.sqrt() / mean
}

/// #1748 review #8: derive a byte-RATE from two CUMULATIVE byte-count samples
/// taken at `prev_ns` and `now_ns`. Single source of truth for both the
/// per-worker (tx_bytes) and per-flow (observed_bytes) rate derivation in the
/// Coordinator tick. Returns 0 when there is no prior sample, no elapsed time,
/// or the cumulative counter went backwards (a flow re-homing to a different
/// worker's cache entry resets its cumulative to ~0 — saturating_sub yields 0).
pub(in crate::afxdp) fn cumulative_to_rate(
    cumulative: u64,
    prev_cumulative: u64,
    now_ns: u64,
    prev_ns: u64,
) -> f64 {
    if now_ns <= prev_ns {
        return 0.0;
    }
    let dt = (now_ns - prev_ns) as f64 / 1_000_000_000.0;
    if dt <= 0.0 {
        return 0.0;
    }
    cumulative.saturating_sub(prev_cumulative) as f64 / dt
}

/// Project the per-worker byte-rate vector after moving `flow_rate` from
/// `from` to `to`. Returns a fresh vector (cheap — ~6 workers).
fn project_move(
    workers: &[WorkerByteRate],
    from: u32,
    to: u32,
    flow_rate: f64,
) -> Vec<WorkerByteRate> {
    workers
        .iter()
        .map(|w| {
            let mut nw = *w;
            if w.worker_id == from {
                nw.byte_rate = (w.byte_rate - flow_rate).max(0.0);
            } else if w.worker_id == to {
                nw.byte_rate = w.byte_rate + flow_rate;
            }
            nw
        })
        .collect()
}

/// Translate a SessionKey to the ethtool 5-tuple, converting host-order ports
/// and `IpAddr` into the network-order words the kernel UAPI expects.
pub(in crate::afxdp) fn flow_spec_from_key(key: &SessionKey) -> FlowSpec5Tuple {
    let (proto, src_ip, dst_ip) = match (key.src_ip, key.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let proto = if key.protocol == super::super::PROTO_TCP {
                FlowProto::Tcp4
            } else {
                FlowProto::Udp4
            };
            (
                proto,
                [u32::from_ne_bytes(s.octets()), 0, 0, 0],
                [u32::from_ne_bytes(d.octets()), 0, 0, 0],
            )
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let proto = if key.protocol == super::super::PROTO_TCP {
                FlowProto::Tcp6
            } else {
                FlowProto::Udp6
            };
            (proto, v6_words(s), v6_words(d))
        }
        // Mixed families never form a real session key; default to v4 TCP so
        // the spec is well-formed (the move would simply never match).
        _ => (FlowProto::Tcp4, [0; 4], [0; 4]),
    };
    FlowSpec5Tuple {
        proto,
        src_ip,
        dst_ip,
        // SessionKey ports are host order; the kernel field is __be16.
        src_port: key.src_port.to_be(),
        dst_port: key.dst_port.to_be(),
    }
}

/// IPv6 address -> four network-order u32 words (matching `__be32[4]`).
fn v6_words(addr: std::net::Ipv6Addr) -> [u32; 4] {
    let o = addr.octets();
    [
        u32::from_ne_bytes([o[0], o[1], o[2], o[3]]),
        u32::from_ne_bytes([o[4], o[5], o[6], o[7]]),
        u32::from_ne_bytes([o[8], o[9], o[10], o[11]]),
        u32::from_ne_bytes([o[12], o[13], o[14], o[15]]),
    ]
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;
