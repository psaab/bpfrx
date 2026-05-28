**Verdict: CONCEPTUAL PLAN-NEEDS-MAJOR**

I could not inspect the plan doc or quote line numbers. The command runner rejected reads before filesystem access, including `/`, `/home`, and the target worktree, so this is a conceptual adversarial review.

**Blocking Findings**

- The wire omission story is not credible unless the exact field types support it. In Go, `omitempty` does not omit a fixed `[16][24]uint64` because its length is nonzero. If the plan literally uses fixed arrays, `cold_path_hist` will always serialize, including all-zero status. That breaks the “empty Vec -> omitted -> None -> empty Vec” claim and inflates every status response. Use nil/empty slices, pointers, or custom zero-suppression, and test absent/empty/all-zero/nonzero fixtures.

- The cross-binding merge contract is probably wrong as stated. `saturating_add + OR(alias_seen) + first-non-zero(first_key)` does not detect this case: binding A has `first_key=A`, binding B has `first_key=B`, both local `alias_seen=false`. The aggregate must set `alias_seen=true` when two nonzero first keys differ. Zero should be skipped, but nonzero mismatch must be treated as collision.

- Prometheus bucket labels using `bucket_hi_ns` are not histogram-compatible. `histogram_quantile()` needs cumulative `_bucket{le="..."}` series, plus `_sum` and `_count`, normally in base units. If the emitter exports raw per-bucket counts with `bucket_hi_ns`, call it a custom heatmap/counter grid, not a Prometheus histogram. This must be fixed before #1622 consumes the metric names.

- `cold_path_ns_per_tsc_q32` needs a metric. Shipping it on the wire but omitting it from Prometheus leaves operators unable to validate calibration sanity across workers. Add a worker-level gauge or info-style metric; do not hide calibration behind JSON-only status.

- Snapshot `None` cannot be silently equivalent to “no samples.” A 128-spin retry can still fail if the publisher is preempted while holding the seqlock/odd generation, under cgroup throttling, CPU starvation, or unlucky scrape/publish phase alignment. Operator experience would be missing series or empty cold-path fields for a scrape. Add either last-good snapshot behavior, `snapshot_retry_exhausted_total`, or an explicit `snapshot_available` metric/status bit.

**Required Verification**

- Wire tests must cover all 10 fields both directions: absent, zero, nonzero, unknown-field ignore, and same-daemon reserialize. `cold_path_clock_source` also needs future/unknown value behavior if it is an enum.

- Cardinality is probably acceptable at ~2.6k series per 6-worker node, but the “documented Prometheus cardinality budget” claim must point to an actual repo doc. If it does not exist, the plan needs to add one or drop the claim.

- JSON status size is acceptable only if empty snapshots omit the histogram. Worst-case long-running counters are much larger than the ~8-byte estimate, but still likely tolerable for unary status if bounded by worker count.

- HA validation is mandatory before merge-ready. The worker-loop publish call changes timing in an HA-sensitive path even if `worker_runtime.rs::publish()` is unchanged.

This is not a kill. The shape is salvageable, but the current plan needs major fixes before implementation or downstream dashboard work should proceed.

Codex session ID: 019e6f5b-54e2-7ee0-bfee-f6f2b043c0ec
Resume in Codex: codex resume 019e6f5b-54e2-7ee0-bfee-f6f2b043c0ec
