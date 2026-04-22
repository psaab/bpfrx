# PR #821 Code Review

## Findings

- [HIGH] Stale `worker-tids.txt` race on reruns. `test/incus/step2-sched-switch-capture.sh:148-180` launches `step1-capture.sh` and immediately accepts any pre-existing `"$STEP1_OUTDIR/worker-tids.txt"` via `[[ -s ... ]]`; `test/incus/step1-capture.sh:257-259` only rewrites that file later in the new run. Plan §3.1 step 3 says the rendezvous file is the single source of truth for this capture (`docs/pr/821-p1-sched-switch-capture/plan.md:67-68`). In a reused evidence dir, the harness can attach `perf record -t` to stale TIDs and capture the wrong threads.

- [HIGH] The drift hard-stop is MISSING end-to-end. `test/incus/step2-sched-switch-reduce.py:529-540` prints `HALT:` when `|PERF_START_NS - STEP1_START_NS| >= 5 s` but still emits JSONL and returns success; `test/incus/step2-sched-switch-classify.py:104-130,271-289` has no `SUSPECT` verdict/meta path; `test/incus/step2-sched-switch-capture.sh:276-281` only reports whatever normal verdict lands in `.meta.json`. Plan §11 says this case is capture-invalid and the classifier emits `SUSPECT` (`docs/pr/821-p1-sched-switch-capture/plan.md:420-421`). Code does not implement that contract.

- [HIGH] Block assignment still depends on a synthetic `PERF_START_NS` anchor, not just step1 boundaries. `test/incus/step2-sched-switch-reduce.py:119-131` defines `event_wall_ns = PERF_START_NS + (perf_ts - first_perf_ts)` and `:363-386` applies it before `block_for_timestamp()`. Plan §3.2 / §10 says block boundaries are anchored by `STEP1_START_NS` / `boundaries[]` and `PERF_START_NS` is diagnostic only (`docs/pr/821-p1-sched-switch-capture/plan.md:154-166,411-412`). Because the first traced worker event can arrive arbitrarily after perf attaches, this shifts every event by the first-event latency and can mis-bin boundary-adjacent samples even though `block_for_timestamp()` itself uses the right `[boundaries[b], boundaries[b+1])` test.

- [MEDIUM] `stat_runtime_check` semantics diverge from the canonical schema. `test/incus/step2-sched-switch-reduce.py:447-463` explicitly replaces the plan’s “within ±1% of expected” check with “any positive runtime => PASS, zero => WARN.” Plan §4.1 defines `stat_runtime_check` as an accounting check, not mere tracepoint presence (`docs/pr/821-p1-sched-switch-capture/plan.md:289-295`). This materially weakens WARN-block reporting and anything downstream that trusts `warn_blocks`.

- [LOW] `correlation-report.meta.json` is not the specified minimal schema. `test/incus/step2-sched-switch-classify.py:271-289` emits many extra keys (`cell`, `reason`, `T_D1`, thresholds, totals, etc.), and `test/incus/step2-sched-switch-classify_test.py:217-245` locks those extras in. The review brief’s plan contract called for `{verdict, rho, pvalue, duty_cycle_pct, warn_blocks}`; code does not emit that exact object.

- [LOW] G8 preflight is close but not spec-exact. `test/incus/step2-sched-switch-capture.sh:93-99` does use a per-tracepoint loop, but it uses `grep -qF '$tp'` instead of the required `grep -qE '${tp//:/\\s*:\\s*}'`; `:104-120` also suppresses failing `perf record` stderr with `>/dev/null 2>&1`, so command 3 cannot print perf stderr as plan §5 requires (`docs/pr/821-p1-sched-switch-capture/plan.md:322-343`). The four commands do run, and `--smoke-only` exit behavior is otherwise correct.

- [LOW] The reducer unit test named for plan §3.4 case 4 does not exercise the wake-path `delta_ns < 0` branch. `test/incus/step2-sched-switch-reduce_test.py:264-291` rewinds the raw perf timestamp and only hits the earlier “out-of-order perf ts” guard; the actual monotonicity-skip code under review is `test/incus/step2-sched-switch-reduce.py:401-410`. Plan §3.4 case 4 called for a negative-delta wake sample specifically (`docs/pr/821-p1-sched-switch-capture/plan.md:239`).

## Confirmed Checks

- CONFIRMED: boundary-list binning is implemented as `boundaries = [cold] + 12 warm` and `boundaries[b] <= t < boundaries[b+1]`; no fixed-5s arithmetic in `block_for_timestamp()`. See `test/incus/step2-sched-switch-reduce.py:227-327`.
- CONFIRMED: `bucket_index_for_ns` matches the plan pins, and the 8 required pin cases are covered by unit tests. See `test/incus/step2-sched-switch-reduce.py:75-100` and `test/incus/step2-sched-switch-reduce_test.py:52-77`.
- CONFIRMED: emit-time invariant `sum(buckets[3:7]) == off_cpu_time_3to6` is asserted. See `test/incus/step2-sched-switch-reduce.py:473-476`.
- CONFIRMED: `prev_state.startswith("R")` is used, so `R+` is treated as involuntary. See `test/incus/step2-sched-switch-reduce.py:415-421`.
- CONFIRMED: the wake-path `delta_ns < 0` handler warns and skips before any bucket mutation. See `test/incus/step2-sched-switch-reduce.py:398-410`.
- CONFIRMED: perf-script parsing is streaming line-by-line; it does not slurp the whole file. See `test/incus/step2-sched-switch-reduce.py:157-206`.
- CONFIRMED: `--only-cell` skips baseline gather and `summary-table.csv`, while default mode keeps the original baseline/classification path. See `test/incus/step1-histogram-classify.py:319-352,371-419`.
- CONFIRMED: the cold-stamp change is the specified `jq -c --arg ts` rewrite and is correct when `$PRE_STATUS` is valid JSON. See `test/incus/step1-capture.sh:231-237`.
- CONFIRMED: all four G8 commands are present, and `--smoke-only` exits 0 only after `g8_preflight` succeeds. See `test/incus/step2-sched-switch-capture.sh:79-139`.
- CONFIRMED: T3 verdict logic matches the stated precedence: `IN` on `rho >= 0.8 && duty >= 1`, `OUT` on `rho <= 0.3 || duty < 1`, else `INCONCLUSIVE`. See `test/incus/step2-sched-switch-classify.py:104-130`.
- CONFIRMED: local unit-test spot-checks passed as advertised: reducer `Ran 10 tests ... OK`; classifier `Ran 8 tests ... OK`.

## Open Issues That Must Be Fixed

1. Remove the stale-rendezvous race so `worker-tids.txt` is guaranteed to come from the current run before `perf record -t` starts.
2. Implement the plan’s drift hard-stop contract end-to-end: invalid drift must surface as `SUSPECT`, not a normal IN/OUT/INCONCLUSIVE verdict.
3. Stop using `PERF_START_NS` + first-event latency as the effective block anchor, or document and implement a time-mapping scheme that actually satisfies the plan’s “diagnostic only” constraint.
4. Restore the plan-defined `stat_runtime_check` semantics instead of treating any non-zero runtime as PASS.

## Round 2 verification

- HIGH-1 stale worker-tids: CONFIRMED. `rm -f "$STEP1_OUTDIR/worker-tids.txt"` was added before the new step1 launch and before the rendezvous poll loop, so a reused evidence dir cannot satisfy the poll from an old file. See `test/incus/step2-sched-switch-capture.sh:176-192`.

- HIGH-2 drift hard-stop E2E: CONFIRMED. The reducer stamps every emitted JSONL line with `suspect_reason` when `|drift_ns| >= 5 s` and returns exit 5 (`test/incus/step2-sched-switch-reduce.py:489-500,557-596`); the capture harness treats reducer rc=5 as intentional drift halt and later surfaces `suspect_reason` from meta in the summary line (`test/incus/step2-sched-switch-capture.sh:301-319,332-344`); the classifier short-circuits to `SUSPECT` on reducer sentinel or `--drift-halt-marker` (`test/incus/step2-sched-switch-classify.py:108-146,236-246,271-292,329-351`). The new reducer and classifier SUSPECT tests exist at `test/incus/step2-sched-switch-reduce_test.py:562-613` and `test/incus/step2-sched-switch-classify_test.py:302-371`.

- HIGH-3 synthetic PERF_START_NS anchor (option a): CONFIRMED. Code path: capture now records with `perf record -k CLOCK_REALTIME` and renders with `perf script --ns` (`test/incus/step2-sched-switch-capture.sh:225-245,278-284`); the reducer parses the printed timestamp directly to integer ns (`test/incus/step2-sched-switch-reduce.py:164-213`), bins `ts_ns` directly (`test/incus/step2-sched-switch-reduce.py:394-452`), and does not use `perf_start_ns` on the hot path (`test/incus/step2-sched-switch-reduce.py:370-373`). Local doc evidence supports the semantics: `perf-record(1)` `-k, --clockid` says the flag sets the clock id used for record time fields and points to `clock_gettime()`; `perf_event_open(2)` `use_clockid` / `clockid` says the selected clock is used for time fields and explicitly allows `CLOCK_REALTIME`; `clock_gettime(2)` `CLOCK_REALTIME` says it is wall-clock time in seconds/nanoseconds since the Epoch; `perf-script(1)` `--ns` says it only increases displayed precision, while `--reltime` / `--deltatime` are the options that rebase timestamps. Inference from those docs: with `-k CLOCK_REALTIME` and no `--reltime` / `--deltatime`, `perf script --ns` prints epoch-based wall-clock seconds.nanoseconds, so direct `ts_ns` binning is correct. The boundary-domain regression check is also clear: step1 stamps `_sample_ts` with `date +%s` in both cold and warm snapshots (`test/incus/step1-capture.sh:236-237,292-303`), and the reducer converts those epoch seconds to epoch ns (`test/incus/step2-sched-switch-reduce.py:298-299`), so the new direct perf timestamps and `boundaries[]` remain in the same wall-clock domain.

- MED-4 stat_runtime_check: CONFIRMED. The reducer restored `expected_on_cpu_ns = block_duration_ns * n_workers - total_off_cpu_by_block[b]`, computes `rel_err`, and emits WARN when `rel_err > 0.01`. See `test/incus/step2-sched-switch-reduce.py:469-487`.

- LOW-5 meta.json schema: OPEN. The non-SUSPECT path moved extras under `diagnostic`, but SUSPECT still adds top-level `suspect_reason`, so the top-level object is not always exactly `{verdict, rho, pvalue, duty_cycle_pct, warn_blocks}` as claimed. See `test/incus/step2-sched-switch-classify.py:329-351`. The test does not enforce an exact top-level key set and the SUSPECT tests explicitly expect top-level `suspect_reason`, so the claimed schema fix is not complete. See `test/incus/step2-sched-switch-classify_test.py:229-265,322-371`.

- LOW-6 G8 grep / perf stderr: CONFIRMED. G8.2 now builds the whitespace-tolerant `${tp//:/\\s*:\\s*}` regex and uses `grep -qE`; G8.3 no longer suppresses failing `perf record` stderr. See `test/incus/step2-sched-switch-capture.sh:113-143`.

- LOW-7 monotonicity test: OPEN. The suite adds two wake-before-switch / out-of-order cases, but I did not find the claimed boundary equal-ts coverage. Both added tests use an earlier wake timestamp and assert the outer out-of-order path, not an equal-ts boundary case. See `test/incus/step2-sched-switch-reduce_test.py:308-437`.

- Test counts: CONFIRMED by local run. `python3 test/incus/step2-sched-switch-reduce_test.py` -> `Ran 13 tests ... OK`; `python3 test/incus/step2-sched-switch-classify_test.py` -> `Ran 11 tests ... OK`. Syntax/import validation also passed: `python3 -m py_compile` on the 4 modified `.py` files and `bash -n` on `test/incus/step2-sched-switch-capture.sh`.

- New regressions from option (a): none confirmed. The boundary-list binning remains same-domain as noted above, and the reducer still keeps both the out-of-order perf-ts guard and the wake-path negative-delta guard at `test/incus/step2-sched-switch-reduce.py:395-431`.

ROUND 2: MERGE YES

## Round 3 verification

Commit `a2784c6e`. Tests run from worktree `/home/ps/git/bpfrx/.claude/worktrees/agent-a9c94e15`.

- **LOW-5**: OPEN. `suspect_reason` is now nested under `diagnostic` (`step2-sched-switch-classify.py:335-349`) and two SUSPECT tests assert `meta["diagnostic"]["suspect_reason"]` (`classify_test.py:323-335`, `:371-374`). However, the root object still contains an extra top-level `diagnostic` key, so top-level is `{verdict, rho, pvalue, duty_cycle_pct, warn_blocks, diagnostic}` — not the plan-exact 5 keys. Schema test uses inclusion checks, not exact equality (`classify_test.py:240-266`).

- **LOW-7**: OPEN. New test `test_reducer_equal_ts_wake_delta_zero_accumulates` exists and sets `ts_wake == ts_switch` (`reduce_test.py:343-363`), asserts no WARN (`:374-379`). Does NOT explicitly assert `delta_ns = 0` or `bucket[0] += delta_ns`; instead asserts `off_cpu_time_3to6 == 0` and `sum(lines[0]["buckets"]) == 0` (`:380-386`). Plan §3.4 requires bucket[0] accumulates cleanly — zero-sum assertion is consistent but doesn't pin the routing.

- **Test counts**: reducer `Ran 14 tests in 0.006s OK`; classifier `Ran 11 tests in 0.542s OK`.
- **py_compile**: PASS (all 4 Python files).

ROUND 3: BLOCKED — LOW-5 top-level schema has extra `diagnostic` key; LOW-7 missing explicit bucket[0] routing assertion.

## Round 4 verification

Commit `ea10cf68`.

- **LOW-5 R4**: CONFIRMED — `step2-sched-switch-classify.py:324-356` writes top-level `meta` with exactly `{verdict, rho, pvalue, duty_cycle_pct, warn_blocks}`; diagnostic/suspect data goes to sibling `correlation-report.diag.json`. Strict set equality asserted at `classify_test.py:240-244`; sibling-diag coverage at `classify_test.py:246-268`.
- **LOW-7 R4**: CONFIRMED — `reduce_test.py:385-389` explicitly asserts `bucket_index_for_ns(0) == 0`, `buckets[0] == 0`, and full-array zeros.
- **Test counts**: reducer `Ran 14 tests in 0.006s OK`; classifier `Ran 11 tests in 0.582s OK`.
- **py_compile**: PASS (all 4 Python files, exit 0).

ROUND 4: MERGE YES
