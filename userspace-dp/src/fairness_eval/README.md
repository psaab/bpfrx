# userspace-dp/src/fairness_eval/

Orchestration library for the `fairness-eval` binary.

The binary is intentionally a thin CLI shell. This module owns the
evaluation pipeline from parsed args and loaded inputs through steady-state
windowing, per-worker active-flow aggregation, RSS expectation checks,
verdict construction, and JSON report emission.

Keep behavior compatible with `userspace-dp/tests/fairness_eval_blackbox.rs`:
CLI flags, exit codes, TSV parsing, JSON fields, and failure-reason ordering
are the public contract.

## Input robustness (ps-038-A1 F1/F2)

This is a merge gate for the CoS fairness contract (#1630/#1614), so a
malformed input must never silently produce a PASS/FAIL on wrong data:

- **Numeric CLI args fail fast.** A mistyped or overflowing value for
  `--warmup-secs`, `--final-burst-secs`, `--n-workers`, or `--shaper-rate-bps`
  now exits 2 (arg-validation error) instead of silently reverting to the
  default. `--n-workers 0` is rejected unconditionally (a zero worker count
  yields an empty per-worker distribution → a verdict on no data). The
  parsing core is `args::parse_args_from`, tested directly in `args.rs`.
- **Malformed TSV rows are counted and warned.** `parse_binding_flows_tsv` /
  `parse_cos_flows_tsv` still skip a non-numeric or wrong-column-count row
  (lenient by design), but now count the skips and print
  `skipped N malformed row(s)` to stderr so a truncated/corrupted Prometheus
  scrape is visible rather than silently undercounting a worker's samples.
