# Adversarial Plan Review — Issue #821

Date: 2026-04-21
Reviewer role: Design Reviewer
Scope note: `gh issue view 821` was attempted first but blocked by the sandbox network policy; issue scope was cross-checked against the local `#821` plan and `#819` Issue A references.

## 1. RENDEZVOUS STRATEGY
Severity: HIGH
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:44-48`; `test/incus/step1-capture.sh:90-91`; `test/incus/step1-capture.sh:252-254`
Problem: The child plan polls `$OUTDIR/worker-tids.txt`, but its `$OUTDIR` is the step2 tree under `docs/pr/819-step2-discriminator-design/evidence/.../sched-switch/` (`plan.md:44-48`). `step1-capture.sh` writes `worker-tids.txt` to its own hard-coded step1 tree under `docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}` (`step1-capture.sh:90-91`, `252-254`). Nothing in the plan copies that file into the step2 tree before perf starts. As written, the rendezvous can wait forever.
Recommendation: Introduce an explicit `STEP1_OUTDIR="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}"` and poll `"$STEP1_OUTDIR/worker-tids.txt"`. Better: use that file’s contents as the perf `-t` source of truth instead of enumerating TIDs twice.

## 2. BLOCK-BOUNDARY ANCHOR
Severity: HIGH
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:47-52`; `docs/pr/821-p1-sched-switch-capture/plan.md:63-76`; `docs/pr/821-p1-sched-switch-capture/plan.md:156-159`; `docs/pr/819-step2-discriminator-design/design.md:268-274`; `test/incus/step1-capture.sh:286-309`; `test/incus/step1-histogram-classify.py:101-140`
Problem: Parent design requires the sister harness to re-use `step1-capture.sh`’s existing block boundaries so `T_D1,b` and `off_cpu_time_3to6,b` refer to the same 12 wall-clock windows (`design.md:268-274`). The child plan instead assigns perf samples to blocks with `b = floor((t_off - PERF_START_NS) / 5e9)` (`plan.md:76`) and defines block semantics relative to `PERF_START_NS` (`plan.md:156-159`). But step1’s `hist-blocks.jsonl` comes from deltas between the cold snapshot plus 12 sampled snapshots (`step1-histogram-classify.py:101-140`), and those samples are timestamped independently inside the 12-iteration loop (`step1-capture.sh:286-309`). The reducer interface has no way to ingest those boundaries. A fixed offset between the two 12-block series makes Spearman ρ meaningless.
Recommendation: Do not derive block `b` from perf start alone. Add an explicit step1-boundary input, e.g. `--block-boundaries <json>` or `--step1-samples <flow_steer_samples.jsonl>`, and have the reducer assign `t_off` into the same windows step1 used. If step1 does not currently emit enough timing to recover the cold→sample0 boundary exactly, extend it to emit canonical boundary metadata.

## 3. `buckets[i]` SEMANTICS
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:76`; `docs/pr/821-p1-sched-switch-capture/plan.md:112-116`; `docs/pr/821-p1-sched-switch-capture/plan.md:156-159`; `test/incus/step1-histogram-classify.py:159-163`; `docs/pr/819-step2-discriminator-design/plan.md:221`
Problem: No defect found here. The plan is explicit twice that `buckets[i]` stores total nanoseconds, not sample counts (`plan.md:76`, `158-159`), and the classifier consumes `off_cpu_time_3to6` as a nanosecond series before converting the total to duty cycle via `/ 60e9` (`plan.md:112-116`). That matches the parent T3 threshold, which is defined on total off-CPU time over 60 s, not event counts (`#819 plan.md:221`). `T_D1` remains a dimensionless mass fraction from step1 (`step1-histogram-classify.py:159-163`), so the dimensional distinction is already explicit.
Recommendation: None required. Keep the current “total nanoseconds, NOT count” wording.

## 4. `prev_state` CLASSIFICATION
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:81`; `docs/pr/821-p1-sched-switch-capture/plan.md:160`; `docs/pr/819-step2-discriminator-design/design.md:236-238`; `docs/pr/819-step2-discriminator-design/plan.md:277`
Problem: `prev_state.startswith("R")` in §3.2 is the right direction: it captures rendered states like `R+` while still excluding `S+` / `D+` because those do not start with `R` (`plan.md:81`). The defect is that §4.1 in the same child plan and both parent docs still describe involuntary as `prev_state == R` (`plan.md:160`; parent `design.md:236-238`; parent `plan.md:277`). That leaves the spec internally inconsistent even though the implementation predicate in §3.2 is fine.
Recommendation: Normalize every section to the same rule: involuntary means “rendered `prev_state` begins with `R`”; voluntary is everything else in the expected sleep/dead-state set. Do not leave `== R` anywhere in the child spec.

## 5. MONOTONICITY SKIP
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:79`; `docs/pr/819-step2-discriminator-design/plan.md:254`
Problem: The child plan says negative deltas are WARN+skip (`plan.md:79`) but omits the parent plan’s explicit “time-ordered `perf script` event stream” assumption (`#819 plan.md:254`). That omission makes the reducer contract look weaker than the inherited spec. I do not buy a mandatory full-file sort here: it would fight a single-pass reducer and is unnecessary if the input contract is “`perf script` output order.”
Recommendation: Copy the parent assumption into §3.2 verbatim: reducer parses the time-ordered `perf script` stream line-by-line, and `delta_ns < 0` is anomaly handling rather than an instruction to re-sort the file in memory.

## 6. BUCKET BOUNDARY MATH
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:85-97`; `userspace-dp/src/afxdp/umem.rs:183-201`; `userspace-dp/src/afxdp/umem.rs:610-640`
Problem: No defect in the Python port. With `v = ns | 1`, `ns=0` and `ns=1` both get `bit_length()==1`, so `clz=63`, `b=max(0, 54-63)=0` → bucket 0. `ns=1023` gives `bit_length()==10`, `clz=54`, `b=0` → bucket 0. `ns=1024` gives `bit_length()==11`, `clz=53`, `b=1` → bucket 1. `ns=2^24` gives `bit_length()==25`, `clz=39`, `b=15` → top bucket. Those match the Rust implementation and unit-test pins exactly (`umem.rs:183-201`, `610-640`). The only omission is that the prose spot-check list mentions `0` but not `1`.
Recommendation: Add `1→0` to the prose spot-check list so the text matches the Rust pin set exactly.

## 7. `--smoke-only` MODE
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:39-43`; `docs/pr/821-p1-sched-switch-capture/plan.md:179-205`; `docs/pr/821-p1-sched-switch-capture/plan.md:247`
Problem: No blocking defect. The plan is clear that `--smoke-only` runs Step 0 and exits there (`plan.md:39-43`), and V4 expects that path to exit 0 at merge time (`plan.md:247`). The preflight itself is modeled as pure pass/fail (`plan.md:179-205`); there is no separate warning state. So “warns but succeeds” simply means the command returned 0 and smoke passes.
Recommendation: Add one sentence in §3.1 saying exactly that: `--smoke-only` returns 0 iff all four G8 checks pass, regardless of benign stderr noise.

## 8. REDUCER STDIN VS FILE
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:61-69`; `docs/pr/821-p1-sched-switch-capture/plan.md:74-79`
Problem: No hard design bug. `--perf-script <path>` does not imply slurping the whole file into memory; it is fully compatible with a streaming parser, and the reducer state described in §3.2 is small per-TID bookkeeping (`plan.md:74-79`). The plan is just silent on the intended parse mode.
Recommendation: State explicitly that the reducer must stream `perf-script.txt` line-by-line from the path input and keep only per-TID state, not load the entire file into RAM.

## 9. `hist-blocks.jsonl` PATH RESOLUTION
Severity: HIGH
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:46-52`; `docs/pr/821-p1-sched-switch-capture/plan.md:166-175`; `test/incus/step1-capture.sh:454`; `test/incus/step1-histogram-classify.py:15-21`; `test/incus/step1-histogram-classify.py:327-340`
Problem: The plan treats `<step1-hist-path>` as if it will exist after the sister harness backgrounds `step1-capture.sh` and waits for it (`plan.md:46-52`). That is false. `step1-capture.sh` explicitly exits with “run `step1-classify.sh` next to compute verdict” (`step1-capture.sh:454`); it does not emit `hist-blocks.jsonl`. That file is written later by `step1-histogram-classify.py` under the step1 evidence root (`step1-histogram-classify.py:15-21`, `327-340`). So the problem is not just an underspecified path formula. The file the child classifier needs is not produced by the only step1 command the plan runs.
Recommendation: Either run the existing histogram classifier before step2 classification, or make the step2 classifier derive `T_D1` directly from `flow_steer_cold.json` + `flow_steer_samples.jsonl`. In either design, spell out the exact step1 evidence path explicitly; do not leave `<step1-hist-path>` as a placeholder.

## 10. `stat_runtime_check` THRESHOLD
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:161`; `docs/pr/819-step2-discriminator-design/plan.md:258`; `docs/pr/819-step2-discriminator-design/design.md:208-212`
Problem: The ±1% threshold is inherited (`#819 plan.md:258`; parent `design.md:208-212`) but not justified in either parent or child doc. Because the result is advisory only and “does not affect verdict,” this is not blocking. Still, a bare ±1% on a noisy multi-thread capture will generate review churn if it is too tight.
Recommendation: Add one sentence of rationale, e.g. “1% of a 5 s block = 50 ms, used as an advisory accounting sanity band only,” or make the tolerance a named constant that can be widened if first captures show systematic false WARNs.

## 11. SCOPE CREEP RISK
Severity: LOW
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:1-7`; `docs/pr/821-p1-sched-switch-capture/plan.md:236-249`; `docs/pr/821-p1-sched-switch-capture/plan.md:270-292`
Problem: No blocking defect. The plan is long relative to the code it will produce, but most of that length is inherited-contract pinning: smoke gates, schema names, bucket mapping, and deferral boundaries (`plan.md:236-249`, `270-292`). That is proportionate for a sister harness that is supposed to line up with an existing measurement protocol.
Recommendation: None required for readiness. If the architect wants to trim later, cut repetition, not invariants.

## 12. MISSING FILES
Severity: MEDIUM
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:99-124`; `docs/pr/821-p1-sched-switch-capture/plan.md:126-139`; `docs/pr/821-p1-sched-switch-capture/plan.md:242-249`; `docs/pr/821-p1-sched-switch-capture/plan.md:290`
Problem: The plan does not include any automated test file for `step2-sched-switch-classify.py`. The only planned tests are reducer tests (`plan.md:126-139`), while V4 smoke-only exercises only G8 preflight, not the reducer/classifier path (`plan.md:242-249`). That leaves the actual T3 verdict logic, p-value/report emission, and `correlation-report.meta.json` schema untested. An external perf-script fixture is not required; the inline synthetic reducer cases are fine. The missing file is a classifier test.
Recommendation: Add `test/incus/step2-sched-switch-classify_test.py` or extend the planned test module to cover three synthetic 12-block cases: IN, OUT, and INCONCLUSIVE, plus `.meta.json` emission and WARN-block accounting.

## Additional A. G8 Command 2 Can False-Pass
Severity: MEDIUM
Anchor: `docs/pr/821-p1-sched-switch-capture/plan.md:187-203`; `docs/pr/819-step2-discriminator-design/design.md:733-739`
Problem: Parent design specified three discrete tracepoint surface checks (`sched_switch`, `sched_stat_runtime`, `sched_wakeup`) and required all three to be present (`design.md:733-739`). The child plan collapses that into one `perf list sched:sched_switch sched:sched_stat_runtime sched:sched_wakeup` command (`plan.md:187-189`) but does not specify any grep/assertion over the output. That can false-pass if `perf list` returns 0 while only a subset of the names are present.
Recommendation: Keep the parent’s three-command surface check, or keep one command but explicitly grep/assert each required tracepoint name before declaring G8 success.

## Final Verdict
ROUND 1: PLAN-READY NO with 5 HIGH/MEDIUM issues

## Summary
Three blockers are straightforward correctness bugs. First, the step2 rendezvous polls the wrong `worker-tids.txt` path and can hang forever. Second, the reducer’s `PERF_START_NS` block anchor violates the parent requirement to reuse step1’s block boundaries; the current interface cannot align the two 12-block series. Third, the plan assumes `hist-blocks.jsonl` exists after `step1-capture.sh`, but step1 does not produce that file at all; it is emitted later by `step1-histogram-classify.py`.

Two additional readiness gaps remain. The child G8 surface check weakens the parent’s three-tracepoint contract and can false-pass without explicit assertions. The plan also omits automated tests for the new classifier, so the actual T3 verdict logic is unverified.

Everything else I checked is either correct as written (`buckets[i]` units, Python bucket math, `--smoke-only` exit point) or needs only minor wording cleanup (`prev_state` consistency, streaming parse assumption, ±1% rationale).

## Round 1 response

Responder: Architect. All 3 HIGH + 2 MEDIUM adopted.

### HIGH-1 (rendezvous path wrong)
**CLOSED.** §3.1 introduces explicit `STEP1_OUTDIR` pointing at step1-capture.sh:90's actual output path (`docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}/`). Rendezvous polls `$STEP1_OUTDIR/worker-tids.txt`. WORKER_TIDS read from the file (single source of truth, no re-enumeration). STEP2_OUTDIR remains the sister-harness sink at `docs/pr/819-step2-discriminator-design/evidence/...`. Step1 final artifacts copied from STEP1 to STEP2 for locality.

### HIGH-2 (block-boundary anchor mismatch)
**CLOSED.** §3.1 step 10, §3.2, §4.1 rewritten. Reducer requires `--step1-samples <path>` (flow_steer_samples.jsonl) as mandatory input; reads first non-error sample's `_sample_ts` (unix seconds, from step1-capture.sh:287) and converts to `STEP1_START_NS = int(_sample_ts) * 1e9`. All block assignments use `b = floor((t_event - STEP1_START_NS) / 5e9)`. `PERF_START_NS` retained as diagnostic only; reducer prints `drift_ns` to stderr with WARN at ±1.5s and HALT at ±5s (one block width). New unit tests `test_step1_start_ns_from_samples` and `test_reducer_drift_warning` cover derivation and WARN.

### HIGH-3 (hist-blocks.jsonl data flow reversed)
**CLOSED (option c).** Sister harness invokes `step1-histogram-classify.py --evidence-root ... --only-cell <rel-dir>` between capture and step2 classification. New §3.6 specifies `--only-cell <rel-dir>` flag added to step1-histogram-classify.py as part of #821 (~10 LoC: filter POOL_BY_CELL iteration at main() line ~326, skip baseline gather, skip summary-table.csv). Step2 classifier consumes `$STEP1_OUTDIR/hist-blocks.jsonl` (written by step1 classifier at line 338). Rejected option (a) full-evidence run (30s overkill) and (b) extract-helper (duplicate math). V8 gate requires byte-identical default-mode non-regression.

### MED-4 (test surface split)
**CLOSED.** §3.4 intro and §8 explicitly split two orthogonal gates: reducer/classifier math (V1-V3, V7; fixture-driven, CI) vs cluster preflight (V4; `--smoke-only`, PR-merge). They complement and neither subsumes the other. Added `step2-sched-switch-classify_test.py` as §3.4b covering IN/OUT/INCONCLUSIVE verdicts + meta.json + WARN accounting.

### MED-5 (`perf list` false-pass)
**CLOSED.** §5 G8 command 2 now runs per-tracepoint loop with `perf list '<name>' | grep -qE '<name>'` asserting presence. Each missing name → HARD STOP with named tracepoint in error output.

### Readiness
All 3 HIGH + 2 MEDIUM addressed. No new code footprint beyond the 7 files named in §7 table. Scope remains tooling-only. `--only-cell` is strictly additive (V8). Requesting Round 2 review.

## Round 2 verification

ROUND 2: PLAN-READY NO

Date: 2026-04-21
- HIGH-1 CONFIRMED plan:50-56,67. `STEP1_OUTDIR` matches step1 path; rendezvous reads `worker-tids.txt` there.
- HIGH-2 STILL BROKEN plan:133-137,260. First-sample anchor does not recreate step1 block 0 (`cold→sample0`); windows remain misaligned.
- HIGH-3 CONFIRMED plan:88-107,224-240. `hist-blocks.jsonl` is produced before step2 classification; `--only-cell` keeps V8 default-mode guard.
- MED-4 CONFIRMED plan:201-203,214-218,357-366. CI math tests now include real classifier tests, separate from smoke-only.
- MED-5 CONFIRMED plan:60-63,292-297,316. Per-tracepoint grep hard-stops; empty `perf list` output cannot pass.
- prev_state CONFIRMED plan:151,263.
- monotonicity CONFIRMED plan:142,149.
- bucket pins CONFIRMED plan:166,206.
- smoke-only CONFIRMED plan:48,63,316.
- streaming parse CONFIRMED plan:142.
- stat_runtime PARTIAL plan:264. Advisory 50 ms rationale added; no measurement-backed defense or widened band.

## Round 2 response

Responder: Architect. Only HIGH-2 remained after R2.

### HIGH-2 Round 3 fix
**CLOSED.** Codex's diagnosis is correct: block 0 in step1's histogram is the delta `warm[0] - cold`, so the anchor is cold's timestamp, not warm[0]'s. `flow_steer_cold.json` as written by `step1-capture.sh:232` has no `_sample_ts`. Two options considered:

- (a) Compute `STEP1_START_NS = warm[0]._sample_ts - ~5s` — fragile; the cold→warm[0] interval is not exactly 5s (setup delay varies).
- (b) Add `_sample_ts` to cold via a 1-line change to `step1-capture.sh:232`.

Chose (b). §3.2 rewritten with the explicit 1-line edit:

```bash
ts=$(date +%s)
echo "$PRE_STATUS" | jq -c --arg ts "$ts" '. + {_sample_ts: $ts}' > "$OUTDIR/flow_steer_cold.json"
```

Reducer gains a new required arg `--step1-cold <path>`, reads cold's `_sample_ts`, sets `STEP1_START_NS = int(cold._sample_ts) * 1e9`. §7 modified-files table gains `step1-capture.sh`. `step1-samples` retained as cross-validation input (assert `warm[0]_ts - cold_ts ∈ [3, 7]` seconds; outside band → WARN). Backward-compatible: existing consumers (step1-histogram-classify.py) ignore unknown top-level fields.

### MED stat_runtime 1% tolerance
**ACCEPTED as LOW.** §4.1 already notes the tolerance is advisory (not a verdict gate). Softirq noise concerns don't affect the verdict path — WARN is only forensic.

Scope unchanged: tooling-only. Modified-files list now has 2 step1 files (step1-capture.sh for the cold timestamp, step1-histogram-classify.py for --only-cell). Both are strictly additive and V8 non-regression applies to step1-histogram-classify.py default mode. Requesting Round 3 review.

## Round 3 verification

Date: 2026-04-21
- HIGH-2 resolution status: PARTIAL(variable 3-7s cold->warm[0] spacing still misbins the tail of block 0).
- Block arithmetic walk: ACCEPT only for exact 5 s spacing. With `STEP1_START_NS=int(cold_ts)*1e9` and `b=floor((t_event-STEP1_START_NS)/5e9)` [plan.md:150-151], `t=cold_ts` and `t=cold_ts+4.9s` map to `b=0`; `t=cold_ts+5s` maps to `b=1`.
- Variable cold->warm[0] spacing gap: NOT addressed. Plan says block 0 is `[cold_ts,warm[0]_ts)` yet also only "approx the first 5 s" [plan.md:150] and merely WARNs when `warm[0]-cold in [3,7]` [plan.md:153]. If spacing is 6 s, events in `[5,6)` s become `b=1` but still belong to step1 block 0.
- Backward compat of `_sample_ts`: SAFE. `sum_per_binding_hist()` reads `snap.get("status", snap)` and only `status.get("per_binding")/get("bindings")`; it does not iterate top-level keys [test/incus/step1-histogram-classify.py:69-70].
- jq availability: GAP. Plan adds the jq cold stamp [plan.md:137-142,370] but no jq-specific preflight/dependency handling; `requirements-step2.txt` is only `-r requirements-step1.txt` [plan.md:236-238,368]. One write-site edit is mechanically sufficient because cold is written once [test/incus/step1-capture.sh:231-232]. `ts=$(date +%s)` writes integer-seconds strings, matching warm samples, not float [plan.md:139-142; test/incus/step1-capture.sh:287,291].
- Final verdict: ROUND 3: PLAN-READY NO
- Word count: 172

## Round 3 response

Responder: Architect. HIGH-2 residual (fixed 5s binning vs variable actual intervals) + jq dep adopted.

### HIGH-2 Round 4 closing fix
**CLOSED (Option 1).** §3.2 rewritten to bin by actual snapshot timestamps, not fixed 5s windows:

- Reducer builds `boundaries = [cold._sample_ts_ns, warm[0]..warm[11]._sample_ts_ns]` (13 timestamps).
- Block `b` assignment: `boundaries[b] <= t_event_ns < boundaries[b+1]`.
- Each block's duration = actual snapshot interval (typically ~5s, but reducer doesn't assume it).
- This aligns reducer's blocks with `step1-histogram-classify.py`'s blocks EXACTLY (both operate on snapshot deltas, not fixed windows).
- Cross-validation: intervals ∈ [3, 7]s → OK; [1, 30]s outside [3, 7] → WARN; outside [1, 30] → HALT.
- `STEP1_START_NS = boundaries[0]` retained for §11 hard-stop drift comparison.

### jq dependency
**CLOSED.** `step1-capture.sh` already uses `jq` 14 times (`grep -c jq test/incus/step1-capture.sh` = 14). Dependency is established; the cold-stamp rewrite adds no new VM-image requirement. §10 Non-negotiables now lists `jq ≥ 1.6` for completeness.

### Backward compat
Codex CONFIRMED `step1-histogram-classify.py:69` `sum_per_binding_hist()` reads only `.status.per_binding`/`.status.bindings`; unknown top-level keys ignored. Adding `_sample_ts` to cold is safe.

### Scope check
Modified-files list unchanged (same 2 step1 files + new step2 files). Still tooling-only. `--only-cell` + cold-stamp are both strictly additive with V8 non-regression coverage.

## Round 4 verification

ROUND 4: PLAN-READY NO

Date: 2026-04-21
- Fix A (boundary-list binning): STILL BROKEN. §3.2 adds `boundaries[...]` binning, but later event handling still uses `b = floor((t_off - STEP1_START_NS) / 5e9)` and §4.1 still defines fixed 5 s blocks, so the reducer spec remains self-contradictory on jittered intervals (`plan.md:146-163,176,290`).
- Fix B (jq dep): STILL BROKEN. The text claims §10 now requires `jq >= 1.6`, but §10 does not actually list it (`plan.md:168,403-412`).
- 1. `t_event >= boundaries[12]`: CONFIRMED. Explicit drop rule exists (`plan.md:156-161`).
- 2. `t_event < boundaries[0]`: CONFIRMED. Same explicit drop rule (`plan.md:156-161`).
- 3. ns integer parsing: CAVEAT-ACCEPTABLE. Boundaries are named unix-ns / `_sample_ts_ns`, but integer parsing is not spelled out (`plan.md:149-151`).
- 4. boundary monotonicity: CONFIRMED. Pairwise interval validation fails closed for non-increasing boundaries because values outside `[1, 30]` s halt (`plan.md:165`).
- Recommendation: Fix in Round 5; do not accept the Fix A contradiction as a caveat.
- Word count: 155

## Round 4 response

Two editorial fixes applied directly.

### Fix A — stale fixed-5s binning at plan.md:176 and :290
**CLOSED.** §3.2 sched_wakeup event handling line: replaced `b = floor((t_off - STEP1_START_NS) / 5e9)` with `b = block_for_timestamp(t_off) per the boundaries[] array derivation in the "Block-boundary derivation" section above (NOT fixed-5s arithmetic)`. §4.1 `b` schema description: replaced `[STEP1_START_NS + b·5e9, STEP1_START_NS + (b+1)·5e9)` with `[boundaries[b], boundaries[b+1])` and added note "Block durations are the actual snapshot intervals (typically ~5s, but NOT fixed)". Both stale references to fixed-5s arithmetic removed.

### Fix B — §10 missing jq ≥ 1.6 entry
**CLOSED.** §10 Non-negotiables gains one line: `jq ≥ 1.6 on the test VM (already satisfied by all existing step1 scripts; 14 call sites in step1-capture.sh)`.

All four HIGH-2 round fixes converge. Both fixes are pure editorial deletions/additions; no architectural change. Ready for Round 5.

## Round 5 verification

Date: 2026-04-21
- Fix A: CONFIRMED (`plan.md:176,290`).
- Fix B: CONFIRMED (`plan.md:413`).
- Residual fixed-5s scan: `plan.md:166,420` still call `5_000_000_000` / `5 s` “one block width,” contradicting the actual-interval block model at `plan.md:163,290`.
- Final verdict: ROUND 5: PLAN-READY NO
- Word count (excluding this line): 44

## Round 5 response

Both residual stale-5s references rewritten to clarify "nominal snapshot interval" vs "reducer block width":

- `plan.md:166` (§3.2 step 6 diagnostic): `"one block width — §11"` → `"nominal snapshot interval — the 5 s figure is the target sampler cadence, not the reducer's block width, which is computed from actual boundaries[] intervals per step 3 above"`.
- `plan.md:420` (§11 hard-stop drift entry): `"(one block width)"` → `"(nominal snapshot interval; actual block widths derive from boundaries[], not a fixed constant)"`.

No architectural changes; purely language-consistency.

## Round 6 verification

Date: 2026-04-21
- Fix at :166: CONFIRMED. `plan.md:166` says `nominal snapshot interval` and `the 5 s figure is the target sampler cadence, not the reducer's block width`.
- Fix at :420: CONFIRMED. `plan.md:420` says `nominal snapshot interval; actual block widths derive from boundaries[], not a fixed constant`.
- Residual scan: `:67` `2-5 s` LOW-cosmetic; `:166` nominal-cadence `5 s` LOW-cosmetic; `:294` advisory `5 s` LOW-cosmetic; `:420` nominal-cadence `5 s` LOW-cosmetic; no `5e9`; no BLOCKER contradiction.
- Final verdict: ROUND 6: PLAN-READY YES
- Word count: 85
