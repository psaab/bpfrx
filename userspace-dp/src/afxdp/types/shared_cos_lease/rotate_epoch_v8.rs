// Issue #1329 / PR #1588: maybe_rotate_epoch_v8 extracted from
// shared_cos_lease/mod.rs as a pure code-motion split. The function
// body is byte-identical to the pre-split form (see PR #1588 for the
// move diff); atomic memory orderings, branch structure, and
// stack-scratch arrays are preserved exactly.
//
// Visibility widens from inherent-private to `pub(super)` so the
// rotation tick path in `mod.rs` continues to find it. `#[inline]`
// hints the single-call-site inlining decision the compiler made
// implicitly on master.
//
// Calls `publish_equal_flow_epoch_v8` (sibling submodule) when the
// lease is in EqualFlowSuppress rate mode; the explicit `use`
// below brings the symbol into lexical scope after pub(super)
// widening.

use super::*;
use std::sync::atomic::Ordering;

use super::publish_equal_flow_epoch_v8::publish_equal_flow_epoch_v8;

impl SharedCoSQueueLease {
    /// #1229 Phase 6 v8: rotate epoch when current epoch has expired.
    /// Seqlock pattern: CAS seq EVEN→ODD claims rotation; updates
    /// state; CAS seq ODD→EVEN publishes completion.
    #[inline]
    pub(super) fn maybe_rotate_epoch_v8(&self, now_ns: u64) {
        let Some(v8) = self.v8.as_ref() else {
            return;
        };
        let seq = v8.epoch.epoch_seq.load(Ordering::Acquire);
        if seq & 1 == 1 {
            return; // peer rotating; acquirers will spin in snapshot
        }
        let start = v8.epoch.epoch_start_ns.load(Ordering::Acquire);
        // First-rotation special case: start==0 means lease was just
        // created; we always rotate immediately to publish initial
        // (cap, fair_share, grace).
        if start != 0 && now_ns < start.saturating_add(EPOCH_DURATION_NS) {
            return;
        }
        // Try EVEN→ODD CAS to claim rotation. Only one winner per cycle.
        if v8
            .epoch
            .epoch_seq
            .compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // peer claimed first
        }

        // We are the rotation winner; seq is now ODD.
        let new_tag = ((seq >> 1) + 1) as u32;
        let new_packed_zero = PackedEpochGrant::pack(new_tag, 0);

        // #1231 v5 STEP 1: ATOMIC-SWAP packed_granted to capture
        // prior-epoch grant AND publish new-tag/0 reset in one
        // operation. Old-tag CAS after this swap fails (tag mismatch);
        // old-tag CAS before this swap is captured in the returned
        // old value. This is the linearization point for prev_granted.
        let prev_packed_granted = v8
            .epoch
            .packed_granted
            .0
            .swap(new_packed_zero, Ordering::AcqRel);
        let (_prev_class_tag, prev_granted_u32) = PackedEpochGrant::unpack(prev_packed_granted);
        let prev_granted = prev_granted_u32 as u64;
        let prev_cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Acquire);

        // #1231 v5.5 stack scratch for per-worker swap captures.
        const MAX_WORKERS_SCRATCH: usize = 32;
        let n_workers = v8.worker_grants.len().min(MAX_WORKERS_SCRATCH);
        debug_assert!(v8.worker_grants.len() <= MAX_WORKERS_SCRATCH);
        let mut signaled_by_worker = [false; MAX_WORKERS_SCRATCH];
        let mut demanded_by_worker = [false; MAX_WORKERS_SCRATCH];
        let mut prev_grants = [0u32; MAX_WORKERS_SCRATCH];
        let mut active_by_worker = [false; MAX_WORKERS_SCRATCH];
        let mut active_flows_by_worker = [0u32; MAX_WORKERS_SCRATCH];
        let mut active_outside_scratch = false;

        // STEP 2: swap event slots, track per-worker signal/demand flags.
        let mut any_active_worker_signaled = false;
        for id in 0..v8.worker_starvation_events.len() {
            let old_starvation = v8.worker_starvation_events[id]
                .0
                .swap(new_packed_zero, Ordering::AcqRel);
            let (_old_starvation_tag, old_starvation_count) =
                PackedEpochGrant::unpack(old_starvation);
            let old_demand = v8.worker_demand_events[id]
                .0
                .swap(new_packed_zero, Ordering::AcqRel);
            let (_old_demand_tag, old_demand_count) = PackedEpochGrant::unpack(old_demand);
            let active = v8
                .worker_active_flow_buckets
                .get(id)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            if id < n_workers {
                active_by_worker[id] = active > 0;
                active_flows_by_worker[id] = active;
                demanded_by_worker[id] = old_demand_count > 0;
                if active > 0 && old_starvation_count > 0 {
                    signaled_by_worker[id] = true;
                    any_active_worker_signaled = true;
                }
            } else if active > 0 {
                active_outside_scratch = true;
                if old_starvation_count > 0 {
                    any_active_worker_signaled = true;
                }
            }
        }

        // STEP 3: swap worker_grants, capture prev_grant for peer-util.
        for (id, grant) in v8.worker_grants.iter().enumerate() {
            let old = grant.0.swap(new_packed_zero, Ordering::AcqRel);
            if id < n_workers {
                let (_, prev) = PackedEpochGrant::unpack(old);
                prev_grants[id] = prev;
            }
        }

        if v8.rate_mode == V8RateMode::EqualFlowSuppress {
            publish_equal_flow_epoch_v8(
                v8,
                new_tag,
                n_workers,
                active_outside_scratch,
                &active_by_worker,
                &active_flows_by_worker,
                &demanded_by_worker,
                &prev_grants,
            );
        } else {
            v8.equal_flow.disable_for_epoch(new_tag);
        }

        // #1231 v5.5 + #1290 round-2 STEP 3.5: peer-utilization
        // gate. iperf-c saturation has CPU-bound peers consuming
        // <60% of share; iperf-e shaper-bound peers consume ~90%.
        // #1290 adds the demand flag so a naturally quiet peer whose
        // active-flow counter is merely nonzero cannot be mistaken
        // for a CPU-bound peer with stranded capacity.
        let mut any_peer_cpu_bound_under_util = false;
        for id in 0..n_workers {
            if !active_by_worker[id] || signaled_by_worker[id] {
                continue;
            }
            if !demanded_by_worker[id] {
                continue;
            }
            let share = v8
                .worker_fair_share
                .get(id)
                .map(|s| s.load(Ordering::Relaxed))
                .unwrap_or(0);
            if share == 0 {
                continue;
            }
            // util < 60%: 5 * prev_grant < 3 * share. Empirical
            // sweep:
            // - 75% threshold (v5.6) caused iperf-d 5-flow worker
            //   to drop to 770 Mbps/flow (other workers claimed its
            //   surplus too aggressively, starving its 5 flows).
            // - 60% threshold (v5.5) leaves moderately-utilized
            //   peers alone; only fires on CPU-bound regimes.
            if (prev_grants[id] as u64).saturating_mul(5) < share.saturating_mul(3) {
                any_peer_cpu_bound_under_util = true;
                break;
            }
        }

        // #1231 v5.1 STEP 4: aggregate-underuse condition. Tightened
        // from 5% to 14% slack (cap / 7) per empirical comparison:
        // - iperf-e at ~89% of cap (14.2G/16G) → 11% under cap →
        //   does NOT fire (margin 3pp).
        // - iperf-c push at ~80% of cap (20.2G/25G) → 20% under cap →
        //   fires (margin 6pp).
        let underuse_slack = prev_cap / 7;
        let aggregate_underuse = prev_granted.saturating_add(underuse_slack) < prev_cap;

        // #1231 v5 + #1290 round-2 STEP 5: arm or decay bypass.
        // All conditions must hold: some active worker hit its
        // primary share while class room remained, aggregate grants
        // were materially sub-cap, and at least one active
        // non-signaling peer both requested queue-lease credit and
        // consumed <60% of its primary share.
        if any_active_worker_signaled && aggregate_underuse && any_peer_cpu_bound_under_util {
            v8.epoch
                .bypass_grace_rotations_remaining
                .store(5, Ordering::Release);
            v8.epoch
                .bypass_grace_arm_count
                .fetch_add(1, Ordering::Relaxed);
        } else {
            let curr = v8
                .epoch
                .bypass_grace_rotations_remaining
                .load(Ordering::Acquire);
            if curr > 0 {
                v8.epoch
                    .bypass_grace_rotations_remaining
                    .store(curr - 1, Ordering::Release);
            }
        }

        // STEP 6: existing publication of total_flows / fair_share /
        // cap / grace_expires_ns / start_ns / seq EVEN bump.
        let total_flows: u64 = v8
            .worker_active_flow_buckets
            .iter()
            .map(|c| c.load(Ordering::Relaxed) as u64)
            .sum::<u64>()
            .max(1);
        // #1630 (cause-1): bounded rotation credit carry. The cap this
        // rotation grants is `rate × elapsed + carry_draw`, where:
        //   * `elapsed` is the wall-clock lag bounded by `K × EPOCH`
        //     (`MAX_ROTATION_LAG_EPOCHS`) — recovers the rate credit the
        //     old `.min(EPOCH)` clamp discarded for a low-rate class that
        //     is only visited intermittently, while keeping the per-class
        //     post-stall burst hard-bounded to `K × rate × EPOCH`;
        //   * `carry_draw` releases a bounded slice of the banked deficit
        //     accrued when a single lag exceeded `K × EPOCH`.
        //
        // Three regimes (DECOUPLED stall cutoff so a legitimate heavy-tail
        // visit lag is never penalised as a stall):
        //   1. lag ≤ K          — normal recovery: grant raw lag, drain a
        //                         bounded carry slice.
        //   2. K < lag ≤ STALL  — bank-residual: grant the K-epoch ceiling
        //                         now, bank `rate × (lag − K×EPOCH)` into
        //                         carry (clamped) for the next visit.
        //   3. lag > STALL or
        //      start == 0       — cold-resume: grant exactly one epoch and
        //                         DROP carry. Bounds the post-stall /
        //                         post-failback burst to `rate × EPOCH` and
        //                         prevents carry leaking across an HA
        //                         demote→promote gap on a reused lease.
        //
        // `epoch_carry_bytes` is rotation-private (single-writer, inside
        // the seqlock ODD section); the Acquire/Release on it are redundant
        // with the surrounding CAS fence but self-documenting. See the
        // struct doc-comment for the enforced reader-private invariant.
        let rate_bytes = self.config.rate_bytes as u128;
        let carry_max = ((rate_bytes
            * CARRY_MAX_EPOCHS as u128
            * EPOCH_DURATION_NS as u128)
            / 1_000_000_000u128) as u64;
        let carry_drain_max = ((rate_bytes
            * CARRY_DRAIN_MAX_EPOCHS as u128
            * EPOCH_DURATION_NS as u128)
            / 1_000_000_000u128) as u64;

        let raw_elapsed_ns = now_ns.saturating_sub(start);
        let lag_epochs = if start == 0 {
            0
        } else {
            raw_elapsed_ns / EPOCH_DURATION_NS
        };

        let (elapsed_ns, carry_draw) = if start == 0 || lag_epochs > STALL_THRESHOLD_EPOCHS {
            // REGIME 3 — cold-resume. One epoch, drop any stale carry.
            if start != 0 {
                v8.epoch.epoch_carry_bytes.store(0, Ordering::Release);
            }
            (EPOCH_DURATION_NS, 0u64)
        } else if lag_epochs > MAX_ROTATION_LAG_EPOCHS {
            // REGIME 2 — bank residual beyond the K-epoch ceiling.
            let k_window_ns = EPOCH_DURATION_NS * MAX_ROTATION_LAG_EPOCHS;
            let overshoot_ns = raw_elapsed_ns.saturating_sub(k_window_ns) as u128;
            let new_owed = ((rate_bytes * overshoot_ns) / 1_000_000_000u128) as u64;
            let prev_carry = v8.epoch.epoch_carry_bytes.load(Ordering::Acquire);
            let carry = prev_carry.saturating_add(new_owed).min(carry_max);
            v8.epoch.epoch_carry_bytes.store(carry, Ordering::Release);
            (k_window_ns, 0u64)
        } else {
            // REGIME 1 — normal recovery. Grant the raw lag (bounded by K
            // here) and drain a bounded carry slice.
            let prev_carry = v8.epoch.epoch_carry_bytes.load(Ordering::Acquire);
            let draw = prev_carry.min(carry_drain_max);
            v8.epoch
                .epoch_carry_bytes
                .store(prev_carry - draw, Ordering::Release);
            (raw_elapsed_ns, draw)
        };

        let base_cap =
            ((self.config.rate_bytes as u128) * (elapsed_ns as u128) / 1_000_000_000u128) as u64;
        let new_cap = base_cap.saturating_add(carry_draw).min(u32::MAX as u64);
        // #1643: payload store downgraded to Relaxed — the single Release
        // on `epoch_seq` below is the sole publish the fenced-Acquire reader
        // synchronizes-with (matching the cold_path_hist reference writer).
        v8.epoch
            .epoch_total_grant_cap
            .store(new_cap, Ordering::Relaxed);
        let grace_ns = now_ns.saturating_add(EPOCH_DURATION_NS / 2);
        v8.epoch
            .epoch_grace_expires_ns
            .store(grace_ns, Ordering::Relaxed);
        for (id, count_atom) in v8.worker_active_flow_buckets.iter().enumerate() {
            let my_count = count_atom.load(Ordering::Relaxed) as u64;
            let my_share = ((new_cap as u128) * (my_count as u128) / (total_flows as u128)) as u64;
            if let Some(share_atom) = v8.worker_fair_share.get(id) {
                share_atom.store(my_share, Ordering::Relaxed);
            }
        }
        v8.epoch.epoch_start_ns.store(now_ns, Ordering::Relaxed);
        // Publish completion: seq ODD→EVEN. This Release is the seqlock
        // publish that synchronizes-with the reader's fenced-Acquire
        // re-read (#1643); all payload stores above happen-before it in
        // this single rotation-winner thread's program order.
        v8.epoch.epoch_seq.store(seq + 2, Ordering::Release);
    }
}
