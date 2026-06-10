// Issue #1329 / PR #1588: publish_equal_flow_epoch_v8 extracted from
// shared_cos_lease/mod.rs as a pure code-motion split. The function
// body is byte-identical to the pre-split form (see PR #1588 for the
// move diff); atomic orderings, fail_open branch wiring,
// smoothed-target math, and streak gating are preserved exactly.
//
// Visibility widens from file-private to `pub(super)` so the
// rotation path in `rotate_epoch_v8.rs` can call this helper.
// `#[inline]` is added as a hint; the function is a hot
// conditional branch of the per-tick rotation.
//
// #1830 (e) dropped the `active_outside_scratch` parameter (the
// rotation scratch is now heap-sized to the full worker array, so no
// worker can sit outside it). Folding the remaining parameters into a
// context struct is still tracked as a follow-up.

use super::*;
use std::sync::atomic::Ordering;

#[inline]
pub(super) fn publish_equal_flow_epoch_v8(
    v8: &V8State,
    new_tag: u32,
    n_workers: usize,
    active_by_worker: &[bool],
    sampled_active_flows_by_worker: &[u32],
    demanded_by_worker: &[bool],
    prev_grants: &[u32],
) {
    // #1830 (e): the former `active_outside_scratch` parameter (and its
    // unconditional `UnsampledActiveWorker` fail-open) is gone — the
    // rotation scratch is now heap-sized to the lease's full worker
    // array at construction, so every worker is inside the scratch by
    // construction and >32-worker hosts no longer fail open every epoch.

    // #1745: derive the equal-flow sample set from the acquire-time
    // sticky-max active-flow samples, NOT the rotation-instant
    // worker_active_flow_buckets read. A worker is in the set iff it has a
    // usable sample (nonzero acquire-time active-flow sample) AND it both
    // demanded lease credit and was granted bytes this epoch.
    //
    // Three cases per active worker:
    //   - usable sample + demanded + granted  -> in the sample set
    //   - participated (demanded OR granted) but no usable sample
    //     -> a real participant we failed to sample: keep the safety
    //        fail-open (UnsampledActiveWorker)
    //   - active flow-bucket nonzero but no demand AND no grants AND no
    //     sample -> genuinely idle-at-rotation worker (the banked-worker
    //     case this fix targets): EXCLUDE from the set, do NOT fail open.
    //       Per the #1745 sufficiency proof, a worker carrying real
    //       traffic cannot stay banked across a whole epoch (exact queues
    //       have no autonomous refill; any sent byte drops the bucket
    //       below the watermark and forces acquire_v8), so such a worker
    //       legitimately sent nothing this epoch.
    let mut active_workers = 0u32;
    let mut sampled_workers = 0u32;
    for id in 0..n_workers {
        if !active_by_worker[id] {
            continue;
        }
        active_workers = active_workers.saturating_add(1);
        let has_sample =
            sampled_active_flows_by_worker[id] > 0 && demanded_by_worker[id] && prev_grants[id] > 0;
        if has_sample {
            sampled_workers = sampled_workers.saturating_add(1);
        } else if demanded_by_worker[id] || prev_grants[id] > 0 {
            // Real participant we could not sample cleanly: fail open
            // rather than set the class target from an incomplete set.
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::UnsampledActiveWorker);
            return;
        }
        // else: idle-at-rotation worker — excluded, no fail-open.
    }

    if active_workers == 0 {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::NoActiveFlows);
        return;
    }
    if sampled_workers < 2 {
        v8.equal_flow.fail_open(
            new_tag,
            V8EqualFlowFailOpenReason::InsufficientSampledWorkers,
        );
        return;
    }

    let mut candidate_target = u64::MAX;
    let mut max_worker_cap = 0u64;

    for id in 0..n_workers {
        if !active_by_worker[id] {
            continue;
        }
        // Only the sampled set contributes to the target / cap math.
        let active_flows = sampled_active_flows_by_worker[id] as u64;
        if active_flows == 0 || !demanded_by_worker[id] || prev_grants[id] == 0 {
            continue;
        }
        let per_flow = (prev_grants[id] as u64) / active_flows;
        if per_flow == 0 {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::ZeroTarget);
            return;
        }
        let prior_share = v8
            .worker_fair_share
            .get(id)
            .map(|share| share.load(Ordering::Acquire))
            .unwrap_or(0);
        if prior_share == 0 {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::UnsampledActiveWorker);
            return;
        }
        // Equal-flow suppression is safe only when the sample is demand
        // saturated enough to represent a real slow per-flow rate. A
        // quiet worker, or a rotation-boundary worker-grant sample that
        // missed enough old-epoch grants, must fail open instead of
        // dragging the whole queue down to an artificial low target.
        if (prev_grants[id] as u64).saturating_mul(EQUAL_FLOW_MIN_WORKER_UTIL_DEN)
            < prior_share.saturating_mul(EQUAL_FLOW_MIN_WORKER_UTIL_NUM)
        {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::LowDemandWorker);
            return;
        }
        candidate_target = candidate_target.min(per_flow);
    }

    if candidate_target == u64::MAX || candidate_target == 0 {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::ZeroTarget);
        return;
    }

    let prev_smoothed = v8
        .equal_flow
        .smoothed_target_per_flow
        .load(Ordering::Acquire);
    let smoothed = if prev_smoothed == 0 {
        candidate_target
    } else {
        prev_smoothed
            .saturating_mul(3)
            .saturating_add(candidate_target)
            / 4
    };
    if smoothed == 0 {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::ZeroTarget);
        return;
    }
    // #1745: cap is derived over the SAMPLED set, using the same
    // sticky-max sample that produced the target, so the published cap is
    // internally consistent with the published per-flow target.
    for id in 0..n_workers {
        if !active_by_worker[id] {
            continue;
        }
        let sample = sampled_active_flows_by_worker[id] as u64;
        if sample == 0 || !demanded_by_worker[id] || prev_grants[id] == 0 {
            continue;
        }
        let Some(worker_cap) = smoothed.checked_mul(sample) else {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::ArithmeticInvalid);
            return;
        };
        max_worker_cap = max_worker_cap.max(worker_cap);
    }

    let streak = v8
        .equal_flow
        .valid_streak
        .load(Ordering::Acquire)
        .saturating_add(1);
    v8.equal_flow.valid_streak.store(streak, Ordering::Release);
    v8.equal_flow
        .smoothed_target_per_flow
        .store(smoothed, Ordering::Release);

    if streak < EQUAL_FLOW_VALID_STREAK_REQUIRED {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::NotEnoughValidStreak);
        return;
    }

    v8.equal_flow
        .enforce_epoch(new_tag, smoothed, max_worker_cap);
}
