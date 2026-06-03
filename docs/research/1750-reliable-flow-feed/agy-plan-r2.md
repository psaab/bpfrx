# AGY adversarial plan review — #1750 r2

Job: adversarial-review-mpxdevby-5iqxdy (read-only).

## VERDICT: PLAN-NEEDS-MINOR

All three r1 MAJORs verified CLOSED in v2 (atomic-publish→bundle; §6.3 dead-code
replaced with cold-path side-table; cause D keying called out + the rate
aggregation correctly keys by `worker_id` via the `identities` slot join).
Only the `StaleFlowSnapshot` defer needs a minor refinement before PLAN-READY.

## Findings (verbatim summary)
- **(a) Atomic read:** bundling makes the controller's decision read atomic
  (one `ArcSwap::load`), but Prometheus / status JSON (`umem/snapshot.rs:67`)
  still read `active_flow_count` out-of-band — fine, that no longer affects the
  rebalance loop. Worker rates (`live.tx_bytes()`) are still read separately
  from the rows, so a transient rate-vs-rows skew remains (the staleness guard's
  job).
- **(b) worker_id plumbing:** fully available, no deeper plumbing.
  `BindingIdentity` (`types/forwarding.rs:342-348`) carries `slot`,`queue_id`,
  `worker_id`; `identities` is slot-keyed; the branch joins `live`↔`identities`
  on slot (`rebalance.rs:224-238`) and keys by `(ifindex, worker_id)`.
- **(c) StaleFlowSnapshot LIVELOCK (the one defect):** if the guard checks the
  FILTERED list, a worker processing only non-steerable traffic (ICMP, unsteered
  ports) has `active_flow_count > 0` but an empty candidate list → defers EVERY
  tick → permanently blocks rebalancing of legitimate steerable flows. If it
  checks the RAW snapshot, after bundling `count>0 && rows.empty` never happens
  (same scan) → dead code. **Fix: make staleness a snapshot-AGE/timestamp check,
  not count-vs-rows.**
- **(d) Side-table deferral correct:** the live gate is homogeneous `-P12`; the
  worker-rate fallback is physically accurate there (R1: 16.8%→3.8%). Side-table
  is a heterogeneous-only optimization, out of scope for the blocker-clearing
  increment.
