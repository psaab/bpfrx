# AGY adversarial review — #1750 r3 (convergence)

Job: adversarial-review-mpxdmsds-5k0kxu (read-only).

## VERDICT: PLAN-NEEDS-MINOR

The bounded snapshot-age defer successfully resolves the livelock risk from
non-steerable traffic and covers transient telemetry publish lag. However, the
plan incorrectly stated the controller is the sole consumer of
`flow_worker_map()`, which would cause a build failure in the REST server status
helper (`helpers.rs:118/124`) if the API signature is changed without updating
that caller.

## Confirmations (verbatim summary)
- **Bounded snapshot-age defer is livelock-free.** Fresh snapshot (age < N×65ms)
  with zero steerable candidates bypasses the defer → terminal `NoEligibleFlow`
  (cause C). Stale/hung worker grows past threshold → bounded by M consecutive
  stale defers then terminal skip + diagnostic.
- **Transient lag covered.** Startup `published_ns = 0` detected stale → defer
  until first publish. Steady-state eviction/insert lag (≤65 ms) stays inside a
  fresh snapshot (age < 325 ms) → terminal skip this tick, captured next tick
  (rebalance interval ≥ 1 s).
- **Open MINOR:** `server/helpers.rs:118` is a second public consumer of
  `flow_worker_map()`; the API change must preserve/update it.

## Resolution
Folded into v4 §5 + §6.1 (two-consumer note + preserve the status/wire path).
r3 MINOR closed.
