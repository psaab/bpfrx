# Issue #827 — Plan: P3 captures + classifier (apply T1 on p5201/p5202-fwd-with-cos)

> **Status.** Architect R3 (post-Codex R2: 2 MED remaining after R2
> =  R1's 2 HIGH + 4 MED + 3 LOW already addressed). R3 closes both
> R2 blockers: source-of-truth for deltas moves entirely to step1
> (§3.2 + §4.3 + §5); K0 no longer vacuous (§4.2). Deliverable is
> one Python classifier + a step1 parser extension + tests + two
> capture runs + a findings doc. No daemon changes. Follows #819
> §3.1 / §4.3 / §5.3 / §7.2 spec; mirrors #821 structure.

## 1. Goal

Emit per-cell M1 IN/OUT/INCONCLUSIVE verdicts by applying the
pre-registered #819 threshold T1 to per-block `Δ(retry_count)` and
`mean(kick_latency_ns)` against the top-quartile `T_D1,b`-elevated
blocks. Same 12-block schedule, same cluster, same CoS baseline as
#823.

## 2. Non-goals

- No daemon changes. PR #826 landed the wire.
- No new cells. Only `p5201-fwd-with-cos` + `p5202-fwd-with-cos`
  (#819 §6 scope reduction).
- No sister harness. #819 §4.3 "Harness integration" rejects one.
- No P2 / P4 / P5 probes. Downstream of this verdict per §7.2.
- No wire-format bump / no new bucket counts.
- No per-worker-class / per-CPU / per-VF aggregation. Pre-
  registered aggregation is "sum across all `per_binding` entries"
  (§4.2).

## 3. Files

### 3.1 New files

- `test/incus/step3-tx-kick-classify.py` — standalone classifier.
  Imports `numpy` + `scipy.stats.spearmanr` from
  `requirements-step1.txt` (no new deps).
- `test/incus/step3-tx-kick-classify_test.py` — unit tests (14
  tests).
- `docs/pr/827-p3-captures/plan.md` — this file.
- `docs/pr/827-p3-captures/codex-plan-review.md` — Codex rounds
  trail.
- `docs/pr/827-p3-captures/codex-code-review.md` — code-review trail.
- `docs/pr/827-p3-captures/pyshell-code-review.md` — Python
  second-angle review.
- `docs/pr/827-p3-captures/findings.md` — capture-run verdict doc.
- `docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/tx-kick/*`
  — cell 1 capture artifacts + classifier output.
- `docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/tx-kick/*`
  — cell 2 capture artifacts + classifier output.

### 3.2 Existing files touched

- `test/incus/step1-histogram-classify.py` — **extended** per Codex
  R1 HIGH-2 and R2 MED-2. **Sole source of truth for per-block
  kick deltas** (R2 MED-2 fix — step3 never recomputes). Adds
  per-block `tx_kick_count_delta`, `tx_kick_sum_ns_delta`,
  `tx_kick_retry_delta`, and `tx_kick_hist_delta` (16-int array)
  to each block in the emitted `hist-blocks.jsonl`. Also hosts all
  kick-side invariants K0-K3 (§4.2) so they fire pre-delta against
  the raw snapshot stream. Closes #819 Issue B acceptance #4
  deferred by #826. **Pre-#826 evidence incompatibility:** if any
  snapshot lacks `tx_kick_latency_count` on any per_binding entry,
  the extension raises `ValueError` at load time (K0; §4.2). No
  `-1` sentinels, no silent-zero pathway — a hostile reviewer's
  correct observation from R2 that sentinel semantics create
  drift risk.
- **`test/incus/step1-histogram-classify_test.py`** — preflight:
  check if exists. If present, extend with the K0-K3 kick tests
  enumerated in §5. If absent, create it with the full set plus a
  minimal existing-pathway smoke (sum_per_binding_hist over a
  trivial snapshot).

### 3.3 Explicitly not touched

- `step2-sched-switch-*` family (#821). P3 does not compose with
  perf.
- Daemon source (Rust / Go). PR #826 is frozen for the purpose of
  #827.
- `apply-cos-config.sh` + its canonical `full-cos.set` — the CoS
  config is fixed at the #823 value.

## 4. Classifier specification

### 4.1 Inputs

**Primary step3 input** (post R2 MED-2 — `hist-blocks.jsonl` is now
the *sole* per-block source):

- `hist-blocks.jsonl` — 12 JSONL lines, each carries:
  - `shape` (16 floats, from step1's submit-latency normalisation)
  - `tx_kick_count_delta` (int)
  - `tx_kick_sum_ns_delta` (int)
  - `tx_kick_retry_delta` (int)
  - `tx_kick_hist_delta` (16-int array)

Step1 already reads `flow_steer_cold.json` + `flow_steer_samples.jsonl`
to produce `hist-blocks.jsonl`. Step3 does NOT re-open the raw
snapshot files — it trusts step1's computed deltas. Invariant
enforcement (K0-K3 per §4.2) is entirely step1's responsibility;
step3 asserts only `hist-blocks.jsonl` shape + length contracts
on its own input (§5 tests).

### 4.2 Aggregation + invariants (in step1; per Codex R1 MED-2 + R2 MED-1/MED-2)

Per Codex R1 Axis 4 (CLEAR): sum across **all** bindings — same
cell-level aggregation as `step1-histogram-classify.py:sum_per_binding_hist()`.

**All of §4.2 runs inside `step1-histogram-classify.py`**, not
step3. The four new aggregate fields per snapshot:

```
kick_F[s] = Σ_b b.tx_kick_latency_F     # F ∈ {count, sum_ns, retry_count}
kick_hist[s, i] = Σ_b b.tx_kick_latency_hist[i]    # i ∈ 0..=15
```

#### Invariants enforced pre-delta

- **K0 (R1 R3 + R2 MED-1 — wire regression guard, non-vacuous).**
  For every snapshot `s ∈ 0..=12`:
  - (i) `len(per_binding[s]) ≥ 1` — reject empty snapshots.
    `ValueError("snap[<s>] has empty per_binding — either the
    daemon exported no bindings or the snapshot was truncated")`.
  - (ii) every `per_binding[s][b]` entry MUST contain all four
    keys (`tx_kick_latency_hist`, `tx_kick_latency_count`,
    `tx_kick_latency_sum_ns`, `tx_kick_retry_count`).
    `ValueError("snap[<s>] binding[<b>] missing key <key> — evidence
    is pre-#826 / wire regression")`.
  - Part (i) closes R2 MED-1 (vacuity on empty `per_binding`);
    part (ii) closes R1 R3 (silent-zero from `serde(default)`).
- **K1 (per-snapshot histogram coherence).**
  `Σ kick_hist[s, i] == kick_count[s]` for every `s ∈ 0..=12`.
  Raise `ValueError` otherwise. Mirror of step1 I13.
- **K2 (per-snapshot wire-regression guard).** If
  `kick_count[s] == 0` while `tx_packets_total[s] > 10_000`, raise
  `ValueError`. Mirror of step1's lines 130-135.
- **K3 (cross-snapshot monotonicity, R1 MED-2).** For every
  `s ∈ 1..=12` and every cumulative field (the 3 scalars + each of
  the 16 bucket entries):
  - `kick_count[s] ≥ kick_count[s-1]`
  - `kick_sum_ns[s] ≥ kick_sum_ns[s-1]`
  - `kick_retry[s] ≥ kick_retry[s-1]`
  - `kick_hist[s, i] ≥ kick_hist[s-1, i]` for every `i`
  If any decreases, raise `ValueError("non-monotonic <field>
  between snap[<s-1>] and snap[<s>]")`. Catches daemon restarts,
  counter resets, and cross-snapshot corruption.

All four fire **before** any block delta is computed (R1 MED-2 +
step1 §123-126 rationale).

Step1 then writes the four `tx_kick_*_delta` fields per block into
`hist-blocks.jsonl`. On an `ElevatedBlocks`-irrelevant error path
(e.g. K0-K3 fail), step1 exits with non-zero rc and does NOT emit
partial output; step3 sees no `hist-blocks.jsonl` and the capture
protocol §6.2 halts.

### 4.3 Block deltas (written by step1; read by step3)

Step1 writes per-block deltas for `b ∈ 0..=11`:

- `tx_kick_retry_delta[b]    = kick_retry[b+1]    - kick_retry[b]`
- `tx_kick_count_delta[b]    = kick_count[b+1]    - kick_count[b]`
- `tx_kick_sum_ns_delta[b]   = kick_sum_ns[b+1]   - kick_sum_ns[b]`
- `tx_kick_hist_delta[b, i]  = kick_hist[b+1, i]  - kick_hist[b, i]`

(Names match step1's field-naming convention; step3 uses the same
names when reading `hist-blocks.jsonl`.)

Step3 then applies T1 (§4.4) **in integer space** (Codex R1 LOW-3
fix):
- T1 OUT clause per block: `tx_kick_sum_ns_delta[b] < 2048 *
  tx_kick_count_delta[b]` (integer cross-multiplication — no
  f64 conversion).
- T1 IN clause per block: `tx_kick_sum_ns_delta[b] ≥ 4096 *
  tx_kick_count_delta[b]`.
Float `kick_latency_mean_ns` is still computed for the human-
readable report (via `tx_kick_sum_ns_delta / tx_kick_count_delta`),
but the **verdict itself is derived from integer math**.

When `tx_kick_count_delta[b] == 0`, the block is flagged
`no_kick=True`; IN requires `tx_kick_count_delta[b] > 0`. The
*latency* clause of OUT is vacuously satisfied (no kicks means no
mean to exceed 2048 ns); the *retry* clause of OUT
(`tx_kick_retry_delta[b] < 100`) still applies. In practice
`retry_delta > 0` implies `count_delta > 0` (a sendto-EAGAIN is
itself a sendto return, which the kick instrumentation observes
unless the VDSO sentinel skipped it), so a no-kick block with
retry >= 100 is a degenerate case that does not occur in clean
captures. Code-review R1 HIGH-1 fix: the formal definition in
§4.4 is authoritative; this prose paragraph is descriptive only.

### 4.4 Thresholds T1 (pre-registered per #819 §3.2, §5.3; bucket
edges corrected per R1 MED-1)

**`T_D1-elevated` definition (Codex R1 HIGH-1 fix).** Per #819 §3.1,
elevated = top quartile = top 3 of 12 ranked values. Tie handling:
if multiple blocks share the 3rd-place `T_D1` value, keep the full
tied set (size ≥ 3). Formally:

```
threshold = sorted(T_D1, reverse=True)[2]            # 3rd largest
ElevatedBlocks = { b | T_D1[b] ≥ threshold }         # size ≥ 3
```

**Bucket edges (Codex R1 MED-1 fix).** Per
`userspace-dp/src/afxdp/umem.rs:198-202`, `b = 54 − clz(ns|1)`:
- Bucket 3 = `[4096, 8192)` ns = `[4 µs, 8 µs)`. **Lower edge =
  4096 ns.**
- Bucket ≤ 1 = `[0, 2048)` ns = `[0, 2 µs)`. **Upper edge = 2047 ns
  (< 2048).**

**T1 IN** (explicit quantifiers per R1 LOW-2):

```
∃ b ∈ ElevatedBlocks such that
    tx_kick_retry_delta[b] ≥ 1000  ∧
    tx_kick_count_delta[b] > 0     ∧
    tx_kick_sum_ns_delta[b] ≥ 4096 * tx_kick_count_delta[b]
```

**T1 OUT** (all blocks, not just elevated):

```
∀ b ∈ 0..=11:
    tx_kick_retry_delta[b] < 100  ∧
    (tx_kick_count_delta[b] == 0  ∨
     tx_kick_sum_ns_delta[b] < 2048 * tx_kick_count_delta[b])
```

**T1 INCONCLUSIVE** ⟺ ¬IN ∧ ¬OUT.

### 4.5 Spearman ρ (diagnostic, not gating — per R1 Axis kept)

Per #819 §5.3 step 3, report two ρ values (not gating — T1
thresholds are the sole gate):

- `rho_retry = spearmanr(T_D1, retry_count_delta).correlation`
- `rho_kick  = spearmanr(T_D1, kick_latency_mean_ns_float).correlation`

Where `kick_latency_mean_ns_float[b]` is `kick_sum_ns_delta[b] /
kick_count_delta[b]` for float-domain correlation ONLY, with
`no_kick` blocks substituted as 0. Reported in `.meta.json`. A
block flagged `no_kick` contributes 0 to both series.

### 4.6 Outputs (per cell)

Written to `docs/pr/819-step2-discriminator-design/evidence/<cell>/tx-kick/`:

- `tx-kick-by-block.jsonl` — 12 lines:
  ```
  {"b": int,
   "retry_count_delta": int,
   "kick_count_delta": int,
   "kick_sum_ns_delta": int,
   "kick_latency_mean_ns": float,        # informational
   "kick_hist_delta": [int; 16],
   "T_D1": float,
   "T_D1_elevated": bool,
   "no_kick": bool,
   "T1_in_sufficient_block": bool,       # true if this block alone satisfies IN
   "T1_out_block": bool}                 # true if this block satisfies OUT clause
  ```
- `correlation-report.md` — human-readable, matching #823 P1
  format (Verdict, Summary, Per-block table, Scatter TSV).
- `correlation-report.meta.json`:
  ```
  {"cell": str,
   "verdict": "IN" | "OUT" | "INCONCLUSIVE",
   "rho_retry": float,
   "pvalue_retry": float,
   "rho_kick":  float,
   "pvalue_kick":  float,
   "elevated_threshold_T_D1": float,
   "elevated_blocks":               [int, ...],
   "max_retry_count_delta_in_elevated":     int,
   "max_kick_latency_mean_ns_in_elevated":  float,
   "T1_in_witness_block":      int | null,   # the ∃-witness, if IN
   "T1_out_holds":             bool,
   "block_count_no_kick":      int}
  ```
- `correlation-report.diag.json` — raw 12-block table + aggregates
  (parity with P1 sibling, see `step2-sched-switch-classify.py`).

`verdict.txt` is **dropped** per Codex R1 LOW-1 — the P1 sibling
does not emit one and the verdict is already grep-able from
`correlation-report.md` ("**OUT**"/"**IN**"/"**INCONCLUSIVE**"
H2 tag) and `.meta.json.verdict`.

### 4.7 CLI

Post R3 MED-1: step3 has no need for `--evidence-dir` since it
never opens raw snapshots. The flag is removed from the spec.

```
python3 test/incus/step3-tx-kick-classify.py \
    --hist-blocks <cell-dir>/hist-blocks.jsonl \
    --cell        <slug> \
    --out         <cell-dir>/tx-kick/correlation-report.md
```

`--hist-blocks` is step3's sole input per §4.1. Sibling files
(`.meta.json`, `.diag.json`, `tx-kick-by-block.jsonl`) are written
next to `--out`. Output directory is created if absent. If the
output-directory creation fails (read-only FS, etc.), raise
immediately — do not attempt partial writes.

## 5. Unit tests (split by file per R2 MED-2 source-of-truth)

### 5.1 In `test/incus/step3-tx-kick-classify_test.py` (T1 gating)

Step3 reads `hist-blocks.jsonl` only; its tests build synthetic
`hist-blocks.jsonl` fixtures and exercise the T1 gating + reports.

1. `test_block_delta_arithmetic_read_from_hist_blocks` — synthetic
   hist-blocks with known per-block `tx_kick_*_delta`; step3
   output's `kick_latency_mean_ns` field matches
   `sum_ns_delta / count_delta`.
2. `test_large_u64_integer_gating` — cumulative counts near
   `2^53` (f64 mantissa boundary); T1 integer-space gating yields
   the correct verdict where f64 division would quietly lose
   precision.
3. `test_no_kick_block_handled` — block with
   `tx_kick_count_delta==0`; `no_kick=True`, excluded from IN
   witness set, OUT clause vacuously satisfied.
4. `test_t1_in_verdict_topquartile` — IN witness in an elevated
   block; other blocks in OUT band; expect IN. Includes the
   3rd-place-tie case (blocks 2, 7, 9 tied → all three in
   `ElevatedBlocks`).
5. `test_t1_in_witness_outside_elevated_yields_not_in` — IN-shape
   block at rank 5 (outside top 3); all other blocks within OUT
   band; expected verdict INCONCLUSIVE (the rank-5 block fails
   OUT's `retry_delta < 100` clause AND fails IN's elevated-
   membership requirement, so neither verdict holds — the IN-
   shape block correctly does NOT trigger IN despite its shape;
   correctness condition is `verdict != IN`, satisfied by OUT or
   INCONCLUSIVE; the actual verdict is INCONCLUSIVE per plan
   §4.4 quantifiers; corrected from R2 plan's "verdict OUT" per
   code-review R1 MED-1).
6. `test_t1_out_verdict` — all blocks in OUT band; expect OUT.
7. `test_t1_inconclusive_verdict` — one block with
   `tx_kick_retry_delta=500, mean=3000 ns`; expect INCONCLUSIVE.
8. `test_rho_reported_not_gating` — synthetic where ρ is very
   high but thresholds land in OUT band; verdict OUT, ρ reported.
9. `test_hist_blocks_wrong_length_rejected` — 11-line input;
   raises `ValueError`.
10. `test_shape_wrong_length_rejected` — a block with `shape`
    length 15; raises.
11. `test_tx_kick_delta_fields_missing_rejected` — a block with
    `shape` but no `tx_kick_retry_delta`; raises with a clear "run
    step1 on post-#826 evidence first" message (source-of-truth
    guard: step3 fails closed if the pipeline stage above produced
    partial output).

### 5.2 In `test/incus/step1-histogram-classify_test.py` (K0-K3 invariants)

Preflight: if the file exists today, extend it with the 8 tests
below; otherwise create it. The tests exercise step1's kick-field
parsing + invariants.

12. `test_kick_aggregation_sums_across_bindings` — 2-binding
    synthetic snapshot; per-snapshot kick aggregates sum correctly.
13. `test_k0_i_empty_per_binding_rejected` (R2 MED-1 pin) — snap
    with `per_binding=[]`; raises with the empty-snapshot message.
14. `test_k0_ii_missing_key_rejected` (R1 R3 pin) — snap with one
    binding missing `tx_kick_retry_count`; raises with the pre-
    #826 message.
15. `test_k1_invariant_caught` — snap where `Σ kick_hist !=
    kick_count`; raises.
16. `test_k2_invariant_caught` — `kick_count==0,
    tx_packets=50_000`; raises.
17. `test_k3_retry_backwards_caught` — retry count decreases
    across two adjacent snapshots; raises "non-monotonic".
18. `test_k3_sum_ns_backwards_caught` — sum_ns decreases; raises.
19. `test_k3_hist_bucket_backwards_caught` — a single kick bucket
    decreases (daemon restart signature); raises.
20. `test_twelve_snapshot_input_rejected` — 12 instead of 13
    total snapshots; raises per the existing 13-snapshot contract.
21. `test_existing_submit_pathway_unchanged` — existing submit-
    latency invariants (I13 etc.) still pass on a synthetic
    snapshot WITH the new kick fields (regression guard).
22. `test_kick_delta_fields_emitted_correctly` (R3 MED-2 pin) —
    positive-path contract pin: feed a valid 13-snapshot stream
    with known per-snapshot `tx_kick_*` values; assert the
    emitted `hist-blocks.jsonl` has 12 blocks and every block's
    `tx_kick_count_delta`, `tx_kick_sum_ns_delta`,
    `tx_kick_retry_delta`, and `tx_kick_hist_delta[16]` exactly
    matches the expected adjacent-snapshot differences. This is
    the positive partner to the K-invariant negatives (tests
    #15-#19) — demonstrates step1 does NOT silently drop the
    fields on a clean input.

Target total across both files: **22 tests** (9 step1 + 11 step3,
vs plan R2's 18 — the R2→R3 split moved invariant tests into
step1 where the invariants live, added R2 MED-1 pin, added
cross-file source-of-truth guard, and added R3 MED-2 positive-path
pin). All pass with
`python3 -m pytest test/incus/step{1,3}-*classify_test.py`.

## 6. Capture protocol (per Codex R1 MED-3 — exact command pinning)

### 6.1 Pre-flight

```bash
# From repo root on the host (not inside the VM):
cd /home/ps/git/bpfrx
git fetch && git log -1 --format='%H %s' origin/master   # must be ≥ d8bf0603 (#826 merge)

# Confirm daemon is on post-#826 build:
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- \
    xpfd --version 2>/dev/null || systemctl status xpfd" | grep -E "active|version"
```

If the daemon isn't on the post-#826 build, run the #826 deploy
path first (documented in #826 validation):

```bash
make build-userspace-dp
sg incus-admin -c "BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    ./test/incus/cluster-setup.sh deploy all"
```

### 6.2 Per-cell capture sequence

For `CELL ∈ {p5201-fwd-with-cos, p5202-fwd-with-cos}` (PORT=5201
then 5202, DIR=fwd, COS=with-cos):

```bash
# 1) Run step1 capture. Writes to
#    docs/pr/line-rate-investigation/step1-evidence/with-cos/p<PORT>-fwd/
sg incus-admin -c "test/incus/step1-capture.sh <PORT> fwd with-cos"

# 2) Run step1 histogram classifier with --only-cell.
#    This emits hist-blocks.jsonl into the same dir. With this PR
#    the per-block output includes tx_kick_*_delta fields.
python3 test/incus/step1-histogram-classify.py \
    --evidence-root docs/pr/line-rate-investigation/step1-evidence \
    --only-cell with-cos/p<PORT>-fwd

# 3) Stage the artifacts into the #819 evidence tree.
STEP1_DIR="docs/pr/line-rate-investigation/step1-evidence/with-cos/p<PORT>-fwd"
TX_DIR="docs/pr/819-step2-discriminator-design/evidence/p<PORT>-fwd-with-cos/tx-kick"
mkdir -p "$TX_DIR"
for f in flow_steer_cold.json flow_steer_samples.jsonl hist-blocks.jsonl \
         iperf3.json verdict.txt worker-tids.txt control-status-pre.json \
         cluster-status-pre.txt cos-interface-pre.txt; do
  [[ -f "$STEP1_DIR/$f" ]] && cp "$STEP1_DIR/$f" "$TX_DIR/$f"
done

# 4) Run the new P3 classifier.
python3 test/incus/step3-tx-kick-classify.py \
    --hist-blocks   "$TX_DIR/hist-blocks.jsonl" \
    --cell          "p<PORT>-fwd-with-cos" \
    --out           "$TX_DIR/correlation-report.md"
```

**`STEP1_SKIP_PERF_STAT` is NOT set.** P3 does not compose a
sister perf probe, so step1's own `perf stat --per-thread` runs
unconstrained (per step1-capture.sh line 303-306).

### 6.3 Artifacts committed to the repo

Under `docs/pr/819-step2-discriminator-design/evidence/<cell>/tx-kick/`:

- `flow_steer_cold.json`, `flow_steer_samples.jsonl` — step1
  originals copied in for self-containment.
- `hist-blocks.jsonl` — step1-histogram-classify output with the
  new `tx_kick_*_delta` fields.
- `iperf3.json` — step1's iperf3 client stats (retrans count gate).
- `verdict.txt` — step1's SUSPECT/PASS per-cell flag (distinct
  from the dropped P3 `verdict.txt` — step1 still emits this for
  its own invariants).
- `correlation-report.md`, `correlation-report.meta.json`,
  `correlation-report.diag.json`, `tx-kick-by-block.jsonl` — P3
  classifier output.
- `worker-tids.txt`, `control-status-pre.json`,
  `cluster-status-pre.txt`, `cos-interface-pre.txt` — operational
  context.

Total size ceiling: <2 MB per cell. No `perf.data`.

### 6.4 Post-capture data sanity checks

```bash
# iperf3 must complete with 0 retransmits and ≥15 Gbps throughput.
jq '.end.sum_sent.retransmits' "$TX_DIR/iperf3.json"      # == 0
jq '.end.sum_sent.bits_per_second/1e9' "$TX_DIR/iperf3.json"  # ≥ 15

# step1 I6 invariant (12 valid samples) must have passed.
grep -q 'SUSPECT\|HALT' "$TX_DIR/verdict.txt" && echo FAIL

# Classifier's meta JSON must name exactly 3 (or more, on tie)
# elevated blocks.
jq '.elevated_blocks | length >= 3' \
    "$TX_DIR/correlation-report.meta.json"
```

If any check fails, re-run the capture once; on second failure
annotate in `findings.md` as a capture-run artefact.

## 7. Findings synthesis (§7.2 decision tree)

`docs/pr/827-p3-captures/findings.md` after both captures:

- Per-cell verdict table.
- Aggregate branch per #819 §7.2:
  - **M1 IN on at least one cell** → file Phase 4 (#793) scope
    issue: "in-AF_XDP TX-kick path mitigation" naming the IN
    cell(s).
  - **M1 OUT on both cells** → file Issue C (#819 §8.2) for P2
    NAPI cadence captures; #819 stays open.
  - **Split (one IN, one OUT)** → per §6.3 split handling: Phase 4
    sub-scope for the IN cell + Issue C for the OUT cell.
  - **Both INCONCLUSIVE** → escalate to Issue C and note in
    findings that additional non-P3 discriminators are required.
- Overhead retrospective: wall-clock delta
  `step1-capture.sh` pre-vs-post-#826 on one cell (≤2 s expected).

## 8. Workflow

1. Architect R2 (this file; was R1 + Codex review).
2. Codex R2 plan review → iterate to PLAN-READY YES.
3. Implement classifier + step1 parser extension + tests (single
   commit or split).
4. Two-angle code review (Codex + pyshell).
5. Run captures on both cells.
6. Write `findings.md`.
7. Open PR, merge, close #827.
8. File downstream Issue C (P2) OR Phase 4 scope issue per §7.

## 9. Risks & pre-registered outs

- **R1 — post-#826 daemon regression.** Validated in #826
  (17.79 Gbps, 0 retrans). If a P3 capture lands
  `iperf3.retransmits > 0` or `< 15 Gbps`, mark the cell as
  "capture-run suspect" and re-run once.
- **R2 — step1-capture.sh overhead drift from new fields.** The
  fields are already serialised in #826; step1's existing sampler
  loop is unchanged. Zero additional overhead. Nothing to
  mitigate.
- **R3 — missing kick keys in some snapshot (wire gap).** Step1's
  K0 (§4.2 part ii) rejects with a clear error. Test #14 pins.
- **R4 — non-monotonic counters (daemon restart during a run).**
  Step1's K3 invariant (§4.2) rejects. Tests #17-#19 pin.
- **R4a — empty `per_binding` in a snapshot** (R2 MED-1). Step1's
  K0 part (i) rejects. Test #13 pins.
- **R5 — "T_D1-elevated" top-quartile ties.** Tie-inclusion rule
  (§4.4) pre-registered; test #11 pins.
- **R6 — both cells land INCONCLUSIVE.** Synthesis path §7
  escalates to Issue C and flags the epistemic limit.
- **R7 — step1-histogram-classify.py extension breaks existing
  tests.** The new fields are additive; submit-latency pathway
  unchanged. If the existing test file has a strict
  length/signature assertion on block JSON, extend the fixture
  minimally. Detected at implement-time, not deferred.

## 10. Open questions

None; R1 questions Q1-Q3 were resolved in R1 and are carried as
settled decisions in this R2 plan:

- Q1 (pre-#826 evidence): hard error — codified as K0 invariant §4.2.
- Q2 (pool kick mean): pool (sum_ns_total / count_total) — codified §4.3.
- Q3 (smoke chain): out of scope — noted at plan head, not
  re-litigated.
