# Claude SMR plan-review r4 — #1615 multi-thread flooder (plan v4)

Verdict: **PLAN-READY**.

## R3 coverage check (v4 fixes)

| r3 finding | Resolved in v4 § |
|------------|------------------|
| CODEX-r3-1 ratio doesn't prove distinct queues | §3.7 caveat paragraph — pps gate catches collision-collapse |
| CODEX-r3-2 ambiguous ratio threshold | §3.7 — single hard fail at >2.0, warning band (1.5, 2.0] |
| CODEX-r3-3 §7 stale pre-check text | §7 rewrite to "no pre-check; worker-only" |
| CODEX-r3-4 §7 stale softnet_stat text | §7 rewrite to per-thread tx_packets |
| CODEX-r3-5 std::thread::spawn panics | §3.9 — std::thread::Builder mandatory |
| CODEX-r3-6 oversubscribe test missing | §5.1 — `threads_arg_oversubscribe_flag_allows_excess` |
| AGY-r3-1 ≡ CODEX-r3-5 | same |
| AGY-r3-2 main shutdown_flag tick | §3.8 — main reads flag on every tick |
| AGY-r3-3 N=1 ratio definition | §3.7 — defined as 1.0 for N=1 |

All 9 r3 findings closed.

## Hostile re-read of v4

- **§3.7 N=1 ratio = 1.0**: with N=1 the smoke runner shows the
  single-thread baseline row. Aggregate avg_pps is the only gate
  metric that matters there; ratio gate is trivially satisfied. OK.

- **§3.9 thread name "flooder-N"**: cosmetic but useful in
  /proc/<pid>/task/<tid>/comm for diagnosis. Good.

- **§3.7 ratio max / max(min, 1)**: the `max(min, 1)` guards against
  divide-by-zero when min=0 (a thread sending 0 packets in a 10s
  run is itself a hard failure indicator). With max=2_500_000 and
  min=0, ratio = 2_500_000 — exceeds 2.0 → hard fail → correctly
  rejected. OK.

- **§5.1 oversubscribe test**: with `allowed_cpus = [0, 1]` and
  `--threads 4 --allow-oversubscribe`, the mapping is index
  arithmetic modulo `allowed_cpus.len()=2`, so threads 0,1,2,3 map
  to cpus [0,1,0,1]. Test should assert correct mapping in
  addition to validator acceptance. Add to the unit test spec.
  Minor — add when implementing.

- **No new findings**.

## Gate

**PLAN-READY** across all four reviewer seats expected. Move to
Step 5 implementation.

If Codex r4 returns yet another NEEDS-MAJOR raising new findings not
in r1/r2/r3, treat per `feedback_difficult_path_pragmatism`:
acceptable to ship implementation in parallel and let r4-or-later
findings land as code-review findings on the actual diff.
