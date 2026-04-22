# #821 P1 — Angle 2 (Python/shell craft) code review

Reviewer: Claude (Opus 4.7). Commit: `1fa2f913` on `worktree-agent-a9c94e15`.
Angle: Python idioms, shell hygiene, test quality, error handling, operator
clarity, hot-path allocation, jq escape, argparse ergonomics, surprises,
V8 non-regression. Codex covers correctness/plan-adherence.

Round 1.

## Findings

### MEDIUM

- **M1. `step2-sched-switch-capture.sh` has no `trap` for SIGINT/SIGTERM.**
  If the operator Ctrl-C's the foreground script, the backgrounded
  `step1-capture.sh` (`STEP1_PID`, line 150) and `perf record` (`PERF_PID`,
  line 205) continue running inside the guest and on the host — leaving
  orphaned processes plus a live `perf record` writing to
  `/tmp/sched-switch.perf.data` on `xpf-userspace-fw0`. Spec is 60 s per
  run, but a botched cell would hit this every time. Add:
  `trap 'kill $STEP1_PID $PERF_PID 2>/dev/null; incus exec "$FW" -- pkill -TERM perf 2>/dev/null; exit 130' INT TERM`
  near the top (parity with kill -0 bail at line 173). **Note:** existing
  `step1-capture.sh` also lacks a trap, so this is consistent project
  style — call it MED not HIGH.
  File: `test/incus/step2-sched-switch-capture.sh:27-54`.

- **M2. Misplaced "docstring" in `reduce_events` is dead code.** Line 347
  `"""Consume `events` and emit 12 JSONL blocks..."""` is placed *after*
  the `if out_stream is None` late-binding block (lines 341-346). Per
  PEP 257 a docstring must be the first statement in the function body —
  this string literal is just discarded, so `help(reduce_events)` and IDE
  tooltips show nothing. Move the docstring to immediately after the
  `def` signature; move the late-binding comment+code after it.
  File: `test/incus/step2-sched-switch-reduce.py:340-351`.

### LOW

- **L1. Unused import `Iterable` in classifier.** `from typing import
  Iterable` at line 37 is never referenced. Remove.
  File: `test/incus/step2-sched-switch-classify.py:37`.

- **L2. `LINE_HEADER_RE` fails on `perf script` rows whose `comm` contains
  a space.** `(?P<comm>\S+)` assumes no whitespace in comm; real
  threadnames like `Isolated Web Co` or `kworker/u8:0-ev` (truncated at
  16) can include spaces. For the `xpf-userspace-w` worker target this
  never fires in practice (confirmed comm is whitespace-free), but a
  single errant non-worker event on the same CPU — which perf emits even
  with `-t` TID pinning for wakeup-target events — gets silently dropped.
  Defensive fix: parse with `.rsplit()` or widen to
  `(?P<comm>.+?)\s+(?P<tid>\d+)\s+` with a non-greedy match. Not
  blocking; note in a TODO if left unfixed.
  File: `test/incus/step2-sched-switch-reduce.py:133-148`.

- **L3. jq `_sample_ts` stamp assumes `$PRE_STATUS` is JSON.** Line 234
  of step1-capture.sh pipes `$PRE_STATUS` through `jq -c --arg ts "$ts"
  '. + {_sample_ts: $ts}'`. If `ctl_status` ever returns non-JSON (e.g.
  an error banner that the existing `halt_with_dump` guard on line 196
  misses), `jq` fails and `set -euo pipefail` aborts — which is actually
  the correct behavior. The `--arg ts "$ts"` is properly quoted and safe
  against injection; `$ts` is always a `date +%s` integer. No fix
  needed; noting as checked.
  File: `test/incus/step1-capture.sh:233-234`.

- **L4. Test `test_verdict_INCONCLUSIVE_midrange_rho` hand-computes rho
  and then asserts on scipy's output.** Lines 188-214 of the classifier
  test compute the expected rho manually (`expected_rho = 1.0 - 6 *
  sum_d2 / (12 * (12 * 12 - 1))` yields ~0.5), but the test never
  asserts against `expected_rho` — it only asserts the *verdict bucket*.
  If someone tweaks `off_pattern` and breaks the hand-tuned bucketing,
  the bespoke rho computation becomes stale cargo-cult code. Either
  delete lines 190-194, or add
  `self.assertAlmostEqual(rho, expected_rho, places=4)`.
  File: `test/incus/step2-sched-switch-classify_test.py:188-194`.

- **L5. Argparse: `--block-size-s` and `--n-blocks` retained for
  "backward compat with the plan interface but currently unused" per the
  comment at line 514. Dead flags accepted silently are a trap — an SRE
  setting `--block-size-s=1` thinks they changed behavior, nothing
  happens. Either remove now (no caller uses them) or emit
  `WARN: --block-size-s is ignored (boundaries come from step1)` when
  set to non-default.
  File: `test/incus/step2-sched-switch-reduce.py:514-516`.

- **L6. Operator clarity — INCONCLUSIVE reason string only names one
  leg.** Line 128-130 of the classifier returns reason
  `f"rho={rho:.3f} in ({RHO_OUT}, {RHO_IN}); duty={duty_cycle_pct:.3f}"`
  which is good — it says both values. But degenerate rho INCONCLUSIVE
  (line 117-120) says only "Spearman rho undefined (degenerate input:
  constant on one side or too few blocks)" without naming which side.
  An SRE staring at meta.json wants to know whether shape or off_cpu
  was flat. Add `len(set(T_D1))=N` and `len(set(off_times))=M` to the
  reason string.
  File: `test/incus/step2-sched-switch-classify.py:116-120`.

- **L7. `parse_perf_script` uses `errors="replace"` silently.** Line 164
  opens perf-script.txt with `errors="replace"` — any UTF-8 decode error
  is masked. If perf ever emits binary garbage into the text stream
  (corrupted capture), the regex just won't match that line and it's
  silently dropped. Consider `errors="strict"` and letting the reducer
  HALT loudly — forensic captures are the whole point. Non-blocking.
  File: `test/incus/step2-sched-switch-reduce.py:164`.

## Positive observations

- Type hints consistent with the step1 codebase (`Path`, `list[int]`,
  `dict[int, int]`, `tuple[...]`) — no `from __future__ import`
  required since targets are Python 3.9+.
- `pathlib.Path` used throughout; `argparse` uses `type=Path` and
  `type=int` correctly.
- Reducer streams perf-script line-by-line (`for raw in f:` at 165) —
  no `.readlines()` slurp. 100 MB captures handled fine.
- `bucket_index_for_ns` port is pinned against 15 boundary cases
  including 0, 1, 1023/1024, 2048, 4096, 2^24-1, 2^24, 2^64-1. All pass.
- Tests use `tempfile.mkstemp` + `Path.unlink` in `finally`, and swap
  `sys.stdout`/`sys.stderr` with `io.StringIO` for capture. Clean.
- Late-binding of `out_stream`/`warn_stream` defaults to
  `sys.stdout`/`sys.stderr` (not def-time) so tests can redirect via
  monkey-patching. Good call.
- `shell set -euo pipefail` present on line 27; variables quoted
  throughout; `"${VAR:-default}"` not needed because all positional args
  are validated with explicit `usage` paths.
- V8 non-regression verified: when `--only-cell is None` the control
  flow in `step1-histogram-classify.py` enters the `else` branch
  (lines 332-352) executing the *original* baseline gather + H-STOP-5
  + pool JSONL write unchanged; `cell_iter = list(POOL_BY_CELL.items())`
  is equivalent to the old `for rel_dir, pool in POOL_BY_CELL.items()`;
  the two `if args.only_cell is not None` gates (371, 407) short-circuit
  only when set. Default mode is byte-identical in behavior. Confirmed
  by inspection.
- Both test suites execute green (10 + 8 tests pass in <1 s on this
  host).

## Verdict

ROUND 1: MERGE YES — subject to M1 (add a `trap`) and M2 (move
docstring) before merge. L1-L7 are follow-ups and not blocking.

The M1/M2 items are 3 lines of shell and one 5-line move; trivial to
fix in-place. If the author declines M1 on "step1 has no trap either"
grounds, accept and close — this is a consistency/parity choice.

## Round 2 verification

ROUND 2: MERGE YES.

Commit `7c1821d4` verified against Round 1 MEDIUMs:

- **M1 closed.** `test/incus/step2-sched-switch-capture.sh` adds
  `cleanup_on_signal()` + `trap cleanup_on_signal INT TERM` right after
  the `log()` helper. Function guards `${STEP1_PID:-}` / `${PERF_PID:-}`
  with `2>/dev/null || true`, then `incus exec "$FW" -- pkill -TERM
  perf` to stop the remote `perf record` (host-side `incus exec` kill
  alone does NOT propagate), and `exit 130`. Matches my suggested fix.
- **M2 closed.** `test/incus/step2-sched-switch-reduce.py:338` —
  `reduce_events` docstring is now the first statement in the function
  body (PEP 257), with the late-binding of `out_stream`/`warn_stream`
  moved below it. Docstring also extended to document the new
  `suspect_reason` kwarg from HIGH-2.

L1-L7 unchanged per original non-blocking classification. No new
Python/shell concerns in the diff.
