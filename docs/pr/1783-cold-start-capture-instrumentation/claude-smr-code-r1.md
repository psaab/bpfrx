# Claude SMR hostile code review — PR #1783 r1 (`3b5a2960f`)

**Verdict: MERGE-NEEDS-MINOR**

Reviewed the diff end-to-end. Hot path, behavior preservation, and plumbing are
clean; one design reservation on the membership-gauge surface.

## Verified clean
- **Hot-path perf-neutrality:** `neg_neigh_fast_fail` is a single `Relaxed
  fetch_add` on the *existing* neg-cache discard path (`poll_descriptor:2054`);
  `pending_neigh_duplicate_drops` likewise on the existing admission path. No
  new alloc, lock, syscall, or branch on the warm-forward path. Honors the
  plan's non-blocking constraint (PR-1 adds no syscall at all).
- **Behavior preservation (the risky bit):** the admission split
  `if contains_key { count } else if len<MAX { insert }` is byte-equivalent to
  the prior `if !contains_key && len<MAX { insert }` — insert happens iff (key
  absent AND room); the capacity-drop case (absent key, len≥MAX) falls through
  to the existing recycle and is NOT counted as a duplicate. Correct.
- **Attribution:** the dup counter counts ONLY the key-already-pending (H5)
  case, distinct from the capacity case — exactly what the capture needs.
- **Accessors:** `neg_neigh_fast_fail_total` / `pending_neigh_duplicate_drops_total`
  mirror `cos_no_owner_binding_drops_total` (sum across workers.live) exactly.
- **`dynamic_neighbor_keys()`:** bounded ≤4096, `with_all_shards` once (≈`len()`
  cost), immutable `each_shard_ref`. Fine on the 1/s status path.
- **Go plumbing + #1726 canary:** mirrors `emitNeighborWarmCounters`; counters
  are CounterValue; descriptors declared + registered; canary passes.
- **`neighbor_pending_dwell` (H3 signal) already exposed** (#1772) — PR-1
  correctly does not re-add it.

## Finding 1 (MINOR) — `dynamic_neighbor_present{ifindex,ip}` is a high-cardinality always-on metric for an occasional-capture aid
The membership gauge emits one ip-labeled series per `dynamic_neighbors` key on
the always-scraped `/metrics` (≤4096). For a surface only the overnight capture
harness reads, a permanent continuously-scraped high-cardinality metric is
disproportionate. Prefer one of: (a) a one-shot debug query (CLI/gRPC/HTTP)
the harness calls at t0′, or (b) gate the gauge behind a debug env/feature so
it is off by default. Acceptable to ship as-is **only** if the panel agrees the
≤4096 bound + small real-world cardinality makes it a fine debug surface. I
defer to Codex/AGY/Copilot consensus rather than block unilaterally.

No other findings. PR-1 is otherwise a clean, perf-neutral observability change.
