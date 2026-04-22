# Issue #821 — Architect plan: P1 sister harness for off-CPU duration probe

> **Status.** Architect Round 2 (post-Codex R1: 3 HIGH + 2 MEDIUM). Deliverable
> of this plan is tooling (three scripts, two unit test files, one requirements
> file, one targeted extension to `step1-histogram-classify.py`) under
> `test/incus/`, landed into master via the standard two-reviewer workflow
> (`docs/development-workflow.md`). **No capture runs land under this plan** —
> running the probe is a separate follow-up issue tracked per §12 below.
>
> **Parent.** #819 design doc §10 Issue A. Plan references throughout point
> at `docs/pr/819-step2-discriminator-design/plan.md` (the parent plan) and
> `docs/pr/819-step2-discriminator-design/design.md` (the parent design doc).
>
> **Cluster.** Userspace cluster only — `loss:xpf-userspace-fw0` /
> `-fw1`. bpfrx forbidden (#819 plan §10).

## 1. Problem statement

Per #819 design doc §5.1, #821 wires the P1 sister harness (perf-record on
sched_switch + sched_stat_runtime + sched_wakeup), the reducer (perf-script
→ 12-block off-CPU duration histogram), and the classifier (Spearman ρ + T3
verdict). **The #821 deliverable is tooling, not a capture run.** Running
the probe on p5201-fwd / p5202-fwd is a follow-up issue (§12).

Round 2 resolves three HIGH rendezvous/data-flow correctness issues raised
by Codex R1 and documents two MEDIUM test/preflight surface fixes.

## 2. Hypotheses

None. Implementation, not measurement. M1–M5 + T1–T5 are owned by #819.

## 3. Design — per-file spec

### 3.1 `test/incus/step2-sched-switch-capture.sh`

**Responsibility.** Sister harness. G8 preflight inline as step 0, compose
`step1-capture.sh` with a concurrent `perf record`, invoke the step1
histogram classifier in `--only-cell` scope so `hist-blocks.jsonl` exists
before classification, dispatch reducer + classifier, emit summary log line.

**Args.**
```
step2-sched-switch-capture.sh <port> <direction> <cos-state> [--smoke-only]
```
- `<port>` ∈ {5201, 5202} — load-bearing cells only per #819 §6.
- `<direction>` = `fwd`.
- `<cos-state>` = `with-cos`.
- `--smoke-only` — run G8 preflight and exit 0 iff all four checks pass.

**Path variables (FIXED in Round 2; see HIGH-1).**
```bash
STEP1_OUTDIR="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}"
STEP2_OUTDIR="$REPO_ROOT/docs/pr/819-step2-discriminator-design/evidence/p${PORT}-${DIR}-${COS}/sched-switch"
```
Where `$COS = "with-cos"` and `$DIR = "fwd"`. `STEP1_OUTDIR` is what
`step1-capture.sh:90` computes; `STEP2_OUTDIR` is the sister-harness sink.

**Flow.**

1. **Step 0 — G8 preflight.** 4-command sequence inside
   `loss:xpf-userspace-fw0` (§5). Each tracepoint checked individually with
   `perf list <name> | grep -q <name>` to close the MED-5 false-pass.
   On `--smoke-only`, exit 0 here if all four checks pass.
2. **Step 1 — mkdir.** `mkdir -p "$STEP2_OUTDIR"`.
3. **Step 2 — launch `step1-capture.sh` in background.**
   `"$SCRIPT_DIR/step1-capture.sh" "$PORT" "$DIR" "$COS" &`. STEP1_PID captured for wait + rc check.
4. **Step 3 — rendezvous (FIXED in R2, HIGH-1).** Poll `"$STEP1_OUTDIR/worker-tids.txt"` with 60 s timeout (step1 writes it at line 254 between daemon checks and during-run spawn; usually appears within 2-5 s). Read `WORKER_TIDS=$(cat "$STEP1_OUTDIR/worker-tids.txt")` as the single source of truth.
5. **Step 4 — perf window centering.** `sleep 0.5` after worker-tids.txt appears so step1's samplers have fired the first snapshot. Then `PERF_START_NS=$(date +%s%N)` and spawn perf.
6. **Step 5 — `perf record`.**
   ```bash
   incus exec "$FW" -- perf record \
       -e sched:sched_switch \
       -e sched:sched_stat_runtime \
       -e sched:sched_wakeup \
       -t "$WORKER_TIDS" \
       --call-graph=fp \
       -o /tmp/sched-switch.perf.data \
       -- sleep 60 &
   PERF_PID=$!
   ```
   `PERF_START_NS` is diagnostic only — block boundaries are anchored to step1's `flow_steer_samples.jsonl` (see HIGH-2).
7. **Step 6 — wait for both.** On either non-zero, log stderr, mark SUSPECT, bail. Copy step1's final artifacts from `$STEP1_OUTDIR` to `$STEP2_OUTDIR` (`worker-tids.txt`, `flow_steer_cold.json`, `flow_steer_samples.jsonl`, `step1-capture.log`).
8. **Step 7 — pull perf artifacts.**
   ```bash
   incus file pull "$FW/tmp/sched-switch.perf.data" "$STEP2_OUTDIR/perf.data"
   incus exec "$FW" -- perf script -i /tmp/sched-switch.perf.data > "$STEP2_OUTDIR/perf-script.txt"
   ```
9. **Step 8 — step1 histogram classifier in single-cell scope (NEW in R2, HIGH-3).**
   ```bash
   python3 "$SCRIPT_DIR/step1-histogram-classify.py" \
       --evidence-root "$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence" \
       --only-cell "$COS/p${PORT}-${DIR}"
   ```
   Writes `hist-blocks.jsonl` next to step1's JSONL inputs at `"$STEP1_OUTDIR/hist-blocks.jsonl"`. See §3.6 for the `--only-cell` flag spec.
10. **Step 9 — reducer.**
    ```bash
    python3 "$SCRIPT_DIR/step2-sched-switch-reduce.py" \
        --perf-script "$STEP2_OUTDIR/perf-script.txt" \
        --step1-cold "$STEP1_OUTDIR/flow_steer_cold.json" \
        --step1-samples "$STEP1_OUTDIR/flow_steer_samples.jsonl" \
        --worker-tids "$WORKER_TIDS" \
        --perf-start-ns "$PERF_START_NS" \
        > "$STEP2_OUTDIR/off-cpu-hist-by-block.jsonl"
    ```
11. **Step 10 — classifier.**
    ```bash
    python3 "$SCRIPT_DIR/step2-sched-switch-classify.py" \
        --hist-blocks "$STEP1_OUTDIR/hist-blocks.jsonl" \
        --off-cpu "$STEP2_OUTDIR/off-cpu-hist-by-block.jsonl" \
        --cell "p${PORT}-${DIR}-${COS}" \
        --out "$STEP2_OUTDIR/correlation-report.md"
    ```
    Also writes `correlation-report.meta.json`.
12. **Step 11 — summary log line.** `[HH:MM:SS] step2-sched-switch COMPLETE cell=p${PORT}-${DIR}-${COS} outdir=$STEP2_OUTDIR verdict=<IN|OUT|INCONCLUSIVE>`.

### 3.2 `test/incus/step2-sched-switch-reduce.py`

**Responsibility.** perf-script text → 12-line JSONL histogram, with block boundaries aligned to step1's sample timeline (FIXED in R2, HIGH-2).

**Interface.**
```
step2-sched-switch-reduce.py \
    --perf-script <path> \
    --step1-cold <path-to-flow_steer_cold.json>         # NEW required in R3
    --step1-samples <path-to-flow_steer_samples.jsonl>  # cross-validation
    --worker-tids <csv-of-tids> \
    --perf-start-ns <u64>                               # diagnostic only
    [--block-size-s 5] \
    [--n-blocks 12]
```
Stdout: 12 JSON lines per §4.1 schema.

**Block-boundary derivation (R3 correction of Codex HIGH-2).**

step1's histogram blocks are **deltas** between consecutive snapshots: block 0 = `warm[0] - cold`, block 1 = `warm[1] - warm[0]`, etc. (see `step1-histogram-classify.py` `compute_blocks()` and `sum_per_binding_hist()`). The correct block-0 anchor is therefore **cold's** timestamp, not warm[0]'s.

However, `flow_steer_cold.json` as currently written by `step1-capture.sh:232` has NO `_sample_ts` field — it's the raw status dump. To fix this cleanly, **this plan adds ONE LINE to `step1-capture.sh` to stamp cold**: change the existing `echo "$PRE_STATUS" > "$OUTDIR/flow_steer_cold.json"` at line 232 to:

```bash
ts=$(date +%s)
echo "$PRE_STATUS" | jq -c --arg ts "$ts" '. + {_sample_ts: $ts}' > "$OUTDIR/flow_steer_cold.json"
```

This adds `step1-capture.sh` to the modified-files list (§7) alongside `step1-histogram-classify.py`. Scope remains tooling-only (no daemon code, no wire format). Existing consumers of `flow_steer_cold.json` (step1-histogram-classify.py) ignore unknown top-level fields, so adding `_sample_ts` is backward-compatible.

Reducer derivation (R4 Codex HIGH-2 closing fix — bin by actual snapshot timestamps, not fixed 5s windows).

1. Open `--step1-cold <path>` (cold snapshot) AND `--step1-samples <path>` (12 warm samples).
2. Build the **snapshot-boundary array** of 13 unix-ns timestamps:
   ```
   boundaries = [cold._sample_ts_ns] + [warm[i]._sample_ts_ns for i in 0..=11]
   ```
   This mirrors `step1-histogram-classify.py`'s 13-snapshot block derivation exactly: block `b` = `warm[b] - (cold if b==0 else warm[b-1])`.
3. Block assignment per perf event at time `t_event_ns`:
   ```
   for b in 0..=11:
       if boundaries[b] <= t_event_ns < boundaries[b+1]:
           assign to block b
           break
       else if t_event_ns < boundaries[0] or t_event_ns >= boundaries[12]:
           drop (outside the 60-s during-run window)
   ```
   Each block's duration is exactly the snapshot interval `warm[b] - prev`, not a fixed 5s. This aligns the reducer's block boundaries with step1's blocks EXACTLY, regardless of cadence jitter.
4. `STEP1_START_NS = boundaries[0] = cold._sample_ts_ns` (kept as a named constant for §11 hard-stop comparison and stderr diagnostics).
5. **Cross-validation.** For each pair, compute `boundaries[i+1] - boundaries[i]`. Expected ~5s. Assert ALL intervals within `[3, 7]`s; on violation, WARN on stderr but continue. Intervals outside `[1, 30]`s → HALT (sampler is broken).
6. **Diagnostic.** Print `drift_ns = PERF_START_NS - STEP1_START_NS` to stderr. Warn if `|drift_ns| > 1_500_000_000` (1.5 s); hard stop if `|drift_ns| ≥ 5_000_000_000` (nominal snapshot interval — the 5 s figure is the target sampler cadence, not the reducer's block width, which is computed from actual `boundaries[]` intervals per step 3 above).

**`jq` dependency on the test VM.** The `step1-capture.sh:232` cold-stamp rewrite uses `jq`. All existing step1-capture.sh invocations already depend on `jq` elsewhere (grep confirms). No new VM-image change needed, but §10 Non-negotiables calls out `jq ≥ 1.6` as a requirement (matches what the test VM already ships).

**Decision: perf-script format is the ONE supported input.** bpftrace fallback not in #821 scope.

**Streaming parse.** Line-by-line via file iterator; does NOT load full file into memory. Assumes time-ordered events (inherited from #819 plan §254).

**Event handling.**
- `sched_switch` with `prev_pid ∈ WORKER_TIDS` → record `off_start[prev_pid] = t_event`, `off_state[prev_pid] = prev_state`.
- `sched_wakeup` with `pid ∈ WORKER_TIDS` and `off_start[pid]` set → `delta_ns = t_wake - t_off`; `b = block_for_timestamp(t_off)` per the boundaries[] array derivation in the "Block-boundary derivation" section above (NOT fixed-5s arithmetic); if `0 ≤ b ≤ 11`, accumulate `buckets[b][bucket_index_for_ns(delta_ns)] += delta_ns` (total ns, NOT count); assign voluntary/involuntary per `prev_state`; clear `off_start[pid]`.
- `sched_stat_runtime` → accumulate per-(b, tid) `runtime_ns` for the post-pass `stat_runtime_check`.

**Monotonicity check.** `delta_ns < 0` → stderr WARN + skip sample.

**prev_state classification.** `prev_state.startswith("R")` → involuntary (captures `R+`, `R`); else voluntary (S/D/I/T/t/X/Z/P).

**Bucket boundaries — Python port** from `userspace-dp/src/afxdp/umem.rs:176-202`:

```python
def bucket_index_for_ns(ns: int) -> int:
    """Port of umem.rs bucket_index_for_ns.
    Layout: [0, 1024)→b0; [2^(N+9), 2^(N+10))→bN for N∈[1,15); ≥2^24→b15.
    """
    v = ns | 1
    clz = 64 - v.bit_length()
    b = max(0, 54 - clz)
    return min(b, 15)
```

Spot checks: 0→0, 1→0, 1023→0, 1024→1, 2048→2, 4096→3, 2^24→15, 2^64-1→15.

### 3.3 `test/incus/step2-sched-switch-classify.py`

**Responsibility.** `hist-blocks.jsonl` + `off-cpu-hist-by-block.jsonl` → `correlation-report.md` + `correlation-report.meta.json`.

**Interface.**
```
step2-sched-switch-classify.py \
    --hist-blocks <path> \
    --off-cpu <path> \
    --cell <slug> \
    --out <report-md-path>
```

**Computation.**

1. Read 12 × `T_D1,b = shape[3]+shape[4]+shape[5]+shape[6]`.
2. Read 12 × `off_cpu_time_3to6,b`.
3. Both lists must be length 12.
4. `rho, pvalue = scipy.stats.spearmanr(T_D1, off_cpu_time_3to6)`.
5. `duty_cycle_pct = 100 * sum(off_cpu_time_3to6) / 60e9`.
6. T3 rules (plan §4.1 verbatim):
   - `rho >= 0.8 and duty_cycle_pct >= 1.0` → **IN**
   - `rho <= 0.3 or duty_cycle_pct < 1.0` → **OUT**
   - else → **INCONCLUSIVE**
7. Sum voluntary / involuntary totals across blocks.
8. Count `stat_runtime_check == "WARN"` blocks.

**Report.** Markdown with cell header, per-block table, ρ + p-value, duty cycle %, TSV scatter data, verdict line with cited reason, vol/invol split, WARN block list.

### 3.4 `test/incus/step2-sched-switch-reduce_test.py`

**Responsibility.** Unit tests for reducer, `bucket_index_for_ns` port, and STEP1_START_NS derivation.

**Test surface split (addresses MED-4).** Two orthogonal gates:
- This file (V1–V3, V7): reducer/classifier math, fixture-driven, CI.
- `--smoke-only` on cluster (V4): preflight only, proves G8 surface, PR-merge time.

**Tests.**
1. `test_bucket_index_for_ns_boundary_pins` — 0, 1, 1023, 1024, 2048, 4096, 2^24, 2^64-1.
2. `test_step1_start_ns_from_samples` — inline JSONL with `_sample_ts: "1713571200"` → 1713571200_000_000_000. `_error` first-line skip handled.
3. `test_reducer_synthetic_three_switches_two_durations` — two (switch, wake) pairs at t=1.000008 s (prev_state=S, 8 µs) and t=2.500032 s (prev_state=R, 32 µs) relative to STEP1_START. Both in b=0. Assert `buckets[3]=8000`, `buckets[5]=32000`, others 0, `off_cpu_time_3to6=40000`, `voluntary_3to6=8000`, `involuntary_3to6=32000`.
4. `test_reducer_out_of_order_skip` — negative delta → WARN + skip.
5. `test_reducer_emits_12_blocks` — empty events still emit 12 lines with zero histograms.
6. `test_reducer_invariant_sum_buckets_3to6` — `sum(buckets[3:7]) == off_cpu_time_3to6` on every block.
7. `test_reducer_drift_warning` — `PERF_START_NS = STEP1_START_NS + 2e9` → WARN emitted, no fail.

### 3.4b `test/incus/step2-sched-switch-classify_test.py`

**Responsibility.** T3 classifier unit tests.

Tests for each of IN / OUT / INCONCLUSIVE on synthetic 12-block inputs; meta.json schema validation; WARN-block accounting.

### 3.5 `test/incus/requirements-step2.txt`

**Content.** `-r requirements-step1.txt`. No new pins.

### 3.6 `test/incus/step1-histogram-classify.py` — `--only-cell` flag (NEW in R2)

**Change scope.** ~10 lines of Python. Added under #821 to close HIGH-3.

**Interface addition.**
```
--only-cell <rel-dir>     # e.g. "with-cos/p5201-fwd"
```
Must match one key of `POOL_BY_CELL`; otherwise `ValueError` with non-zero exit.

**Semantics.**
1. When set, restrict the cell iteration (line ~326 `for rel_dir, pool in POOL_BY_CELL.items()`) to the single matching entry.
2. Skip the baseline-pool gather/H-STOP-5 block entirely. Log: `"--only-cell: skipping baseline gather and permutation classification (hist-blocks.jsonl only)"`.
3. Still write `hist-blocks.jsonl`. Skip `perm-test-results.json` (depends on baselines).
4. Skip `summary-table.csv` when `--only-cell` is set.

**Non-regression (V8).** Default invocation byte-identical to pre-change. Test: diff output on frozen canned evidence tree before/after.

**Why this over extract-a-helper.** Existing classifier owns `compute_blocks()` / `sum_per_binding_hist()`; restricting iteration is minimal change.

## 4. Data contract

### 4.1 Per-block JSON schema (reducer output — canonical)

```json
{
  "b": <int 0..11>,
  "buckets": [<u64 ns> × 16],
  "off_cpu_time_3to6": <u64 ns>,
  "voluntary_3to6": <u64 ns>,
  "involuntary_3to6": <u64 ns>,
  "stat_runtime_check": "PASS" | "WARN"
}
```

**Semantics.**
- `b` — block index 0..11 covering `[boundaries[b], boundaries[b+1])` where `boundaries` are the 13 unix-ns snapshot timestamps derived in §3.2 "Block-boundary derivation" (cold + 12 warm `_sample_ts` values). Block durations are the actual snapshot intervals (typically ~5s, but NOT fixed; this matches step1-histogram-classify.py's delta-on-snapshots shape exactly).
- `buckets[i]` — total ns of off-CPU time in bucket `i` across all worker TIDs. NOT a count.
- `off_cpu_time_3to6 = sum(buckets[3:7])`.
- `voluntary_3to6` / `involuntary_3to6` — restricted to `prev_state` NOT starting with R / STARTING with R.
- `stat_runtime_check` — "PASS" if sched_stat_runtime-based on-CPU accounting within ±1% of expected (±1% of 5 s = 50 ms advisory band); "WARN" otherwise. Not a verdict gate.

### 4.2 Evidence layout (emitted by follow-up capture run, NOT by #821)

```
docs/pr/819-step2-discriminator-design/evidence/p<port>-fwd-with-cos/sched-switch/
    perf.data
    perf-script.txt
    flow_steer_cold.json               # copied from STEP1_OUTDIR
    flow_steer_samples.jsonl
    worker-tids.txt
    step1-capture.log
    off-cpu-hist-by-block.jsonl
    correlation-report.md
    correlation-report.meta.json

docs/pr/line-rate-investigation/step1-evidence/with-cos/p<port>-fwd/
    hist-blocks.jsonl                  # step1-classify --only-cell output
```

## 5. G8 preflight — inline in capture script

4 commands, all `incus exec loss:xpf-userspace-fw0`-scoped. Tracepoint surface checked with per-name `grep -q` (closes MED-5 false-pass):

```bash
# 1. Sysctl read (guest). Acceptable ≤ 1.
incus exec loss:xpf-userspace-fw0 -- sysctl kernel.perf_event_paranoid

# 2. Tracepoint surface (guest) — each name verified individually.
for tp in sched:sched_switch sched:sched_stat_runtime sched:sched_wakeup; do
  incus exec loss:xpf-userspace-fw0 -- \
    bash -c "perf list '$tp' | grep -qE '${tp//:/\\s*:\\s*}'" \
    || { echo "G8 command 2 FAIL: $tp not found" >&2; exit 1; }
done

# 3. Privilege smoke (guest).
incus exec loss:xpf-userspace-fw0 -- bash -c \
  'TID=$(ps -eLo tid,comm | awk "\$2==\"xpf-userspace-w\"{print \$1;exit}"); \
   perf record -e sched:sched_switch -t "$TID" -o /tmp/smoke.data -- sleep 1 && \
   test -s /tmp/smoke.data'

# 4. perf script parseability (guest).
incus exec loss:xpf-userspace-fw0 -- \
  bash -c 'perf script -i /tmp/smoke.data | head -5 | grep -q sched_switch'
```

On fail:
- Command 1 > 1 → error pointing at runtime guest-side fix (`sysctl -w kernel.perf_event_paranoid=1`, reversible).
- Command 2 missing → "tracepoints absent; bpftrace fallback NOT in #821 scope" — HARD STOP.
- Command 3 → print perf stderr + `ps -eLo` output.
- Command 4 → print perf script stderr.

`--smoke-only` exits 0 iff all four pass.

## 6. Bucket boundaries — canonical source

Per `userspace-dp/src/afxdp/umem.rs:112-128` + `:176-202`.

| bucket | [ns_lo, ns_hi) | µ-unit lo |
|--------|----------------|-----------|
| 0 | [0, 1024) | 0 |
| 1 | [1024, 2048) | ~1 µs |
| 2 | [2048, 4096) | ~2 µs |
| 3 | [4096, 8192) | ~4 µs |
| 4 | [8192, 16384) | ~8 µs |
| 5 | [16384, 32768) | ~16 µs |
| 6 | [32768, 65536) | ~32 µs |
| 7 | [65536, 131072) | ~64 µs |
| 8 | [131072, 262144) | ~128 µs |
| 9 | [262144, 524288) | ~256 µs |
| 10 | [524288, 1048576) | ~512 µs |
| 11 | [1048576, 2097152) | ~1 ms |
| 12 | [2097152, 4194304) | ~2 ms |
| 13 | [4194304, 8388608) | ~4 ms |
| 14 | [8388608, 16777216) | ~8 ms |
| 15 | [16777216, ∞) | ≥16 ms |

Buckets 3-6 = [4096, 65536) ns = ~4-64 µs = the D1 signature window.

## 7. Execution matrix

| File | Responsibility |
|------|----------------|
| `test/incus/step2-sched-switch-capture.sh` | G8 preflight inline + compose step1 with perf record + invoke `step1-histogram-classify.py --only-cell` + dispatch reducer + classifier |
| `test/incus/step2-sched-switch-reduce.py` | perf-script + step1 samples → 12-line JSONL of off-CPU histograms, anchored to STEP1_START_NS |
| `test/incus/step2-sched-switch-classify.py` | 2 JSONL files → correlation-report.md + .meta.json with T3 verdict |
| `test/incus/step2-sched-switch-reduce_test.py` | Unit tests for reducer + `bucket_index_for_ns` + STEP1 anchor derivation |
| `test/incus/step2-sched-switch-classify_test.py` | Unit tests for T3 classifier (IN/OUT/INCONCLUSIVE) + meta.json + WARN accounting |
| `test/incus/requirements-step2.txt` | `-r requirements-step1.txt` only |
| `test/incus/step1-histogram-classify.py` | **MODIFIED.** Add `--only-cell <rel-dir>` flag. ~10 LoC. |
| `test/incus/step1-capture.sh` | **MODIFIED.** Line 232 stamps cold snapshot with `_sample_ts` via `jq -c --arg ts`. 1 LoC net (R3 HIGH-2 fix). Existing consumers ignore unknown top-level fields; backward-compatible. |

## 8. Validation gates (per-deliverable)

Two orthogonal surfaces (clarifies MED-4):

- **V1** — Bucket boundary pins match umem.rs.
- **V2** — Reducer synthetic test: correct bucket placement, vol/invol split, monotonicity skip, STEP1_START_NS anchor.
- **V3** — Artifact invariant `sum(buckets[3:7]) == off_cpu_time_3to6` on every block.
- **V4** — G8 preflight passes on `loss:xpf-userspace-fw0` (`--smoke-only` exit 0, each tracepoint verified individually).
- **V5** — Trial capture (optional): one run on p5201-fwd-with-cos. Not required.
- **V6** — `make test` green.
- **V7** — Classifier unit tests: IN/OUT/INCONCLUSIVE verdicts + meta.json + WARN aggregation.
- **V8** — `step1-histogram-classify.py` non-regression: default-mode output byte-identical on frozen canned evidence tree.

## 9. Rollback

Purely additive except `--only-cell` flag on `step1-histogram-classify.py`, strictly additive at argparse level (default unset = no change; V8). `git revert`. No cluster state, wire format, or daemon code touched.

## 10. Non-negotiables

- Userspace cluster only — bpfrx forbidden.
- No #816 H2 D1 verdict re-litigation (RT-3).
- No daemon code changes.
- Python 3 + scipy 1.13.1 + numpy 1.26.4.
- #819 §4.1 schema canonical — field names verbatim.
- Bucket layout matches `umem.rs:bucket_index_for_ns` verbatim.
- **STEP1_START_NS is the block anchor.** `PERF_START_NS` is diagnostic only.
- `step1-histogram-classify.py` default behavior byte-preserved.
- **`jq ≥ 1.6`** on the test VM (already satisfied by all existing step1 scripts; 14 call sites in `step1-capture.sh`).

## 11. Hard stops

- G8 preflight fails with no fallback (tracepoint surface absent) — halt, file bpftrace-path follow-up.
- Reducer output drifts from §4.1 schema.
- Bucket boundaries drift from umem.rs.
- `|PERF_START_NS - STEP1_START_NS| ≥ 5 s` (nominal snapshot interval; actual block widths derive from `boundaries[]`, not a fixed constant) — capture invalid; reducer still emits JSONL for forensics but classifier emits SUSPECT.
- `step1-histogram-classify.py` default-mode output differs from pre-change baseline (V8 fail).

## 12. Deferrals

- Running captures — follow-up issue.
- Issue B / P3 daemon counters — separate issue.
- Issue C / P2 NAPI harness — conditional per #819 §7.3.
- Issues D/E — deferred per #819 §12.
- `perf_event_paranoid` image-tightening — runtime sysctl change sufficient.
- bpftrace-input reducer variant — spawns follow-up if G8 cmd 2 fails.
- Matplotlib rendering — classifier emits TSV; rendering downstream.
- 1-s re-bin path — reducer supports via `--block-size-s` / `--n-blocks`; triggering is a capture-time decision, not in #821.

## 13. Evidence layout

```
docs/pr/821-p1-sched-switch-capture/
    plan.md
    codex-plan-review.md
    codex-review.md                 # code review
    <second-angle>-review.md
    fixtures/                        # OPTIONAL
    evidence/                        # OPTIONAL trial capture (V5)
```

*End of Architect Round 2. Awaiting Codex hostile plan re-review.*
