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

// #1746: the `candidate_target` reduction is policy-driven
// (`v8.equal_flow_target_policy`). `Slowest` (the default) keeps the
// pre-#1746 `candidate_target.min(per_flow)` math byte-for-byte; `Mean`
// and `IdealShare` choose a different statistic over the SAME sampled
// `(prev_grants[id], active_flows[id])` pairs. The fail-open guards,
// EWMA smoothing, valid-streak gate, and `max_worker_cap` telemetry are
// identical for all three policies. `nominal_epoch_bytes` is the TRUE
// byte budget the current rotation grants (`new_cap` = rate x elapsed
// + carry draw — lag-recovered, Codex r1 F1), threaded from the
// rotation because this helper only sees `V8State`, not the lease
// config; it is read by the `IdealShare` policy only, so the nominal
// share scales with the same budget the cap consumer is gated by.
#[inline]
pub(super) fn publish_equal_flow_epoch_v8(
    v8: &V8State,
    new_tag: u32,
    n_workers: usize,
    active_by_worker: &[bool],
    sampled_active_flows_by_worker: &[u32],
    demanded_by_worker: &[bool],
    prev_grants: &[u32],
    nominal_epoch_bytes: u64,
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
    // #9117: workers excluded because they woke mid-epoch and so carry only a
    // partial-epoch sample. Counted rather than silently dropped: if every
    // sampled worker is a newcomer the set is empty, and the existing
    // empty-set handling below must be the thing that decides, not this loop.
    let mut newly_active_excluded = 0u32;
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
            // #9117: TWO different situations reach here and only one of them
            // justifies disarming the whole class.
            //
            // A worker whose share was published as 0 at the last rotation had
            // NO flow buckets then — it went idle -> active MID-EPOCH, after the
            // sampler snapshot was taken. It participated (demanded, granted)
            // and legitimately has no sample, because there was nothing to
            // sample when the sample was taken. That is a FOURTH shape, absent
            // from the three-case enumeration above: not "a participant we
            // failed to sample" but "a participant that did not exist yet".
            //
            // EXCLUDE it for one epoch, exactly as the idle-at-rotation case on
            // the next line already does, and for the same reason: a worker we
            // cannot fairly compare is left OUT of the comparison rather than
            // used to disarm it. Its next epoch is fully sampled and it rejoins.
            //
            // What the old behaviour cost: fail_open resets `valid_streak` and
            // `smoothed_target_per_flow`, and EQUAL_FLOW_VALID_STREAK_REQUIRED
            // is 2, so ONE mid-epoch activation suppressed enforcement for ~3
            // epochs ACROSS THE WHOLE CLASS — one lease serves every worker on
            // it. Bounded (~600 us at EPOCH_DURATION_NS = 200_000, and opt-in
            // via `equal-flow-enforcement`) but entirely avoidable.
            //
            // MEASURED HERE, not inferred: the originating issue located this
            // fail-open at the `prior_share == 0` check further down and a fix
            // placed there did nothing — the probe reported
            // `reason=UnsampledActiveWorker excluded=0`, i.e. the class was
            // disarmed before that check was ever reached. This is the site.
            //
            // A worker whose share is genuinely MISSING (id outside the
            // published vector) is not this case: that is an inconsistency
            // between the worker set and the share table, and it still fails
            // open below.
            let published_share = v8
                .worker_fair_share
                .get(id)
                .map(|share| share.load(Ordering::Acquire));
            if published_share == Some(0) {
                newly_active_excluded += 1;
                v8.equal_flow
                    .newly_active_excluded_count
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
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
    // #1746 `Mean` policy accumulators over the sampled set. Two
    // saturating adds per sampled worker per rotation (≥200 µs cadence,
    // EqualFlowSuppress mode only) — not a hot path.
    let mut sum_sampled_grants = 0u64;
    let mut sum_sampled_flows = 0u64;

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
        // #9117: `.get(id)` returning None and `Some(0)` were collapsed by
        // `unwrap_or(0)`. None means the id is outside the published vector — an
        // inconsistency between the worker set and the share table, where
        // failing open is honest. Some(0) is the mid-epoch newcomer, and it is
        // handled at its real site in the FIRST loop above; a worker reaching
        // here with a published 0 AND a usable sample is neither, so it keeps
        // the original fail-open.
        let prior_share = match v8.worker_fair_share.get(id).map(|s| s.load(Ordering::Acquire)) {
            Some(share) if share > 0 => share,
            _ => {
                v8.equal_flow
                    .fail_open(new_tag, V8EqualFlowFailOpenReason::UnsampledActiveWorker);
                return;
            }
        };
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
        sum_sampled_grants = sum_sampled_grants.saturating_add(prev_grants[id] as u64);
        sum_sampled_flows = sum_sampled_flows.saturating_add(active_flows);
    }

    // #1746: policy-driven reduction. The loop above ran identically for
    // all three policies (same fail-open guards, same `min` fold, same
    // sums); only the candidate selected here differs.
    //   - Slowest (default): the `min` fold — byte-identical to the
    //     pre-#1746 behavior.
    //   - Mean: aggregate-weighted mean achieved per-flow rate over the
    //     sampled set. `sum_sampled_flows > 0` is guaranteed here: the
    //     `sampled_workers >= 2` gate passed, and every sampled worker
    //     contributed `active_flows > 0`.
    //   - IdealShare: the literal nominal share. A zero quotient (e.g.
    //     huge flow count) falls into the ZeroTarget fail-open below.
    let candidate_target = match v8.equal_flow_target_policy {
        EqualFlowTargetPolicy::Slowest => candidate_target,
        EqualFlowTargetPolicy::Mean => {
            if sum_sampled_flows == 0 {
                0
            } else {
                sum_sampled_grants / sum_sampled_flows
            }
        }
        EqualFlowTargetPolicy::IdealShare => {
            // Total active flows across ALL workers (not just the
            // sampled set): the nominal share divides the class rate
            // among every active flow, mirroring the rotation's
            // `total_flows` fair-share denominator.
            let total_flows: u64 = v8
                .worker_active_flow_buckets
                .iter()
                .map(|c| c.0.load(Ordering::Relaxed) as u64)
                .sum::<u64>()
                .max(1);
            nominal_epoch_bytes / total_flows
        }
    };

    if candidate_target == u64::MAX || candidate_target == 0 {
        // #9117: a target of "nothing" when the only thing that emptied the
        // sample set was mid-epoch newcomers is a DIFFERENT fact from a genuine
        // zero target, and the reason code should not claim otherwise. Both
        // fail open — the class has no comparable sample either way — but the
        // reason names which, so an operator reading a fail-open storm can tell
        // "workers keep waking" from "the arithmetic collapsed".
        let reason = if newly_active_excluded > 0 && sampled_workers == 0 {
            V8EqualFlowFailOpenReason::UnsampledActiveWorker
        } else {
            V8EqualFlowFailOpenReason::ZeroTarget
        };
        v8.equal_flow.fail_open(new_tag, reason);
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
