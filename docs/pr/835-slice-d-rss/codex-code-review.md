# Codex code review — #786 Slice D (#835)

## Round 1 — MERGE NO

Findings:

- **HIGH FA2** — `BumpRSSConfigGen()` ran BEFORE `publishRSSState()`,
  so a reader observing the new generation could still see stale
  `(enabled, workers, allowed)` values. Same-state reapply would
  let stale rebalance writes pass the post-lock guard.
- **MED FA4** — `currentWeights` only seeded inside the
  epoch-mismatch branch. An idempotent boot/reapply that didn't
  bump Epoch (table already matched target) left
  `currentWeights == nil`, with the per-iface guard
  `len(currentWeights) < 2` then permanently skipping the loop.
- **LOW FA5** — when `computeWeightShift` returned the unchanged
  vector (hot ring at MIN_WEIGHT), the loop still issued an
  `ethtool -X` call and logged a fake `rss rebalance applied`.
- **LOW FA7** — `TestGuard_ManagedDomainLessThan2SkipsRatio` set
  `rssWorkers = 1`, so the early-return at the top of the tick
  fired before reaching the actual guard being pinned.

## Round 2 — MERGE NO

Round 1 fixes verified: FA5 (no-op skip + back-off) and FA7 (test
now drives the actual guard) closed. Two carry-overs:

- **HIGH FA2 (still racy)** — fixed the publish order, but a new
  window opened: `Epoch` bumps only on successful write, and the
  rebalance loop only re-checks `ConfigGen` under the lock. A
  successful control-plane apply that completes during the
  rebalance loop's compute / lock-wait window bumps Epoch but
  the post-lock `ConfigGen` re-check still passes (gen matches
  the tick-start snapshot). Stale weights overwrite the apply.
- **MED FA4 (partial)** — first-creation seed fixed, but worker-
  count change via the idempotent reapply path (no Epoch bump)
  still leaves `currentWeights` at the old size.

## Round 3 — MERGE YES

R2 fixes:

- **FA2 closed** — added per-iface `tickEpochSnapshot` taken
  right after the reconcile branch (before sampling), and a
  post-lock Epoch re-check that abandons on mismatch. Test
  `TestConcurrency_AbandonsWhenEpochBumpsBetweenSnapshotAndLock`
  pins via `epochBumpingExecutor` stub.
- **FA4 closed** — reconcile now triggers re-seed when
  `len(currentWeights) != computeRingCount(workers, queueCount)`,
  catching the no-Epoch-bump worker-count change. Test
  `TestLiveReload_WorkerCountChangeWithoutEpochBumpReseeds` pins.
- LOW polish: `publishRSSState` doc updated to "**MUST be called
  BEFORE BumpRSSConfigGen**". Added `TestRebalance_NoOpWeightsSkipsEthtoolCall`
  and `TestRebalance_FirstCreationSeedsCurrentWeights` regression
  pins.

Codex R3 verdict: **MERGE YES**. FA2 + FA4 cleanly closed; no new
regressions; tickEpochSnapshot / reconcile interaction correct.

Test results: `go test ./pkg/daemon/...` — all green (0.376s).
