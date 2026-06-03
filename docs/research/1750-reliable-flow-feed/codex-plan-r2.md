# Codex hostile plan review — #1750 r2

Session id: 019e8b09-490a-7451-bd41-c8d37fcafa1e (gpt-5.5, read-only).

## VERDICT: PLAN-NEEDS-MAJOR

The two r1 majors are substantially addressed, but v2 adds an unbounded
`StaleFlowSnapshot` defer that can mask persistent candidate loss and keep
installs at zero. The plan also needs to specify the controller snapshot API
change because the current path returns rows only. Side-table deferral is fine
for the current homogeneous live gate.

## Findings (verbatim summary)
1. Atomic bundle closes the r1 publish-skew in design intent, but the current
   controller API is incompatible as-is: `status.rs:168`
   `pub fn flow_worker_map(&self) -> (Vec<...>, bool)` and `rebalance.rs:273`
   `let (rows, _truncated) = self.flow_worker_map();`. The controller reads NO
   count at all; the plan must explicitly change this read path to return the
   bundled per-binding/per-worker counts.
2. worker_id is reachable but NOT from `BindingLiveState`. `worker_manager.rs:6-8`
   says `live`/`identities` are slot-keyed; `BindingIdentity` carries
   `worker_id`. The branch ALREADY demonstrates the right fix:
   `rebalance.rs:224-255` joins `live` by slot to `identities.get(slot)` and
   builds `WorkerByteRate{worker_id,...}`. Plan's "available on the live state /
   identities" is imprecise — it is identities, not live state.
3. MAJOR: `StaleFlowSnapshot` is not livelock-safe as written. After bundling,
   raw count>0 with raw rows empty should NOT happen for non-truncated snapshots
   (`flow_cache.rs:478-493` increments active and pushes rows in the same loop).
   So the likely trigger is persistent post-filter candidate loss, and a
   stateless defer can repeat forever.
4. Deferring the eviction side-table is acceptable for the stated live P12
   homogeneous CoV gate (branch already has the worker-rate fallback,
   `controller.rs:529-552`; acceptance is installs>0 + CoV<=10%, not
   heterogeneous correctness). If heterogeneous fairness becomes an acceptance
   gate, Path 2 stops being optional.
