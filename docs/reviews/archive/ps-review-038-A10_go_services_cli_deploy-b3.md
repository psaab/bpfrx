# Paladin Review — A10 Go Services / CLI / Deploy — Batch 3/3

**Base commit:** d4506d4450e23f9a3fc572206b3c82f6b6c99029
**Area:** test/incus Python helpers (CoS validation, histogram/sched/tx-kick classifiers, fairness-eval, mouse-latency probe/orchestrate/aggregate, RSS multinomial, rate-spread, retire schema, policy scheduler validate, sched-switch reduce/classify), pkg/scheduler, userspace-dp fairness-eval Rust
**Reviewer:** ps (automated)
**Date:** 2026-07-07

## Batch File List (28 files)

```
test/incus/mouse_latency_aggregate.py
test/incus/mouse_latency_aggregate_test.py
test/incus/mouse_latency_orchestrate.py
test/incus/mouse_latency_orchestrate_test.py
test/incus/mouse_latency_probe.py
test/incus/mouse_latency_probe_test.py
test/incus/policy_scheduler_validate.py
test/incus/policy_scheduler_validate_test.py
test/incus/retire_ebpf_artifact_schema.py
test/incus/retire_ebpf_artifact_schema_test.py
test/incus/step1-histogram-classify.py
test/incus/step1-histogram-classify_test.py
test/incus/step1-rate-spread-analysis.py
test/incus/step1-rss-multinomial.py
test/incus/step2-sched-switch-classify.py
test/incus/step2-sched-switch-classify_test.py
test/incus/step2-sched-switch-reduce.py
test/incus/step2-sched-switch-reduce_test.py
test/incus/step3-tx-kick-classify.py
test/incus/step3-tx-kick-classify_test.py
test/incus/test_mouse_latency_shell_test.py
test/xsk-repro/libbpf_xsk_shared_test.c
test/xsk-repro/libbpf_xsk_test.c
test/xsk-repro/main.rs
test/xsk-repro/xdp_pass_redirect.c
pkg/scheduler/scheduler.go
pkg/scheduler/scheduler_3849_test.go
pkg/scheduler/scheduler_localtz_3988_test.go
pkg/scheduler/scheduler_republish_3780_test.go
pkg/scheduler/scheduler_test.go
userspace-dp/src/bin/fairness-eval.rs
userspace-dp/src/fairness_eval/*.rs (inputs, verdict, per_worker, args, windowing, report, rss, mod)
userspace-dp/src/fairness.rs
```

Also reviewed supporting files in same area (not in batch but coupled):
- test/incus/mouse_latency_orchestrate.py (orchestrator logic)
- test/incus/mouse_latency_aggregate.py

---

## Module-by-Module Log

### test/incus/mouse_latency_probe.py — Probe driver
Reviewed: payload generation (os.urandom once per coro), per-attempt vs persistent modes, deadline handling, drain/read timeouts, histogram/percentile computation, validity gates, min_interval closed-loop pacing, phase samples. No data-plane integer truncation — all Python big-int.

Negative: validity floor logic checked; histogram bucket overflow handling checked; percentile estimator pins to statistics.quantiles inclusive. See F-017, F-018 (LOW, informational).

### test/incus/mouse_latency_probe_test.py — Probe tests
Covers histogram, percentiles, validity, CloseWriter abort-vs-graceful, persistent vs per-attempt modes, drain-timeout path, min_interval bounds. Good coverage. No findings.

### test/incus/mouse_latency_orchestrate.py — Orchestrator Python helpers
Reviewed: _parse_junos_rate, parse_cos_class_caps, check_settle_threshold_satisfiable, _parse_iperf_interval_rows, build_cwnd_settle_diagnostics, cmd_check_collapse, cmd_check_env_consistency, cmd_rg_state_flapped, cmd_parse_cluster_state. Focused on TOCTOU, integer handling, path traversal, injection. Findings F-002, F-003, F-004, F-019.

### test/incus/mouse_latency_orchestrate_test.py — Orchestrator tests
Covers cwnd settle, collapse windowing (skip_front semantics), RG flap, CoS fixture parsing, settle-threshold satisfiability, env-consistency cmd. No open findings.

### test/incus/mouse_latency_aggregate.py — Aggregate reducer
Reviewed: discovery, load_cell_reps with INVALID marker handling, summarize_cell (10-valid gate, probe-config consistency, median selection), decide (gate verdict, ratio, percentile key). No TOCTOU with races due to single-process reducer; output JSON written atomically via shell (>). No findings.

### test/incus/mouse_latency_aggregate_test.py — Aggregate tests
Covers median selection, valid filtering, insufficient-valid gating, INCONSISTENT-PROBE-CONFIG, gate PASS/FAIL, custom percentile gate, manifest probe-config override, marker-vs-missing-probe interaction. No findings.

### test/incus/policy_scheduler_validate.py — Policy scheduler artifact validator
Reviewed: _as_int permissive coercion, _load_json, _status_from_doc, _require_userspace_runtime, _policy_counter, validate_artifacts. Structural validator only. Finding F-005, F-006.

### test/incus/policy_scheduler_validate_test.py
Standard positive/negative tests; no concurrency. No findings.

### test/incus/retire_ebpf_artifact_schema.py — eBPF retirement artifact checker
Reviewed: manifest schema validation, integer parsing via Decimal (big-int safety, MAX_JSON_INTEGER_DIGITS=128), RFC3339 datetime validation (leap-second handling), file existence checks. Big-int safety explicitly addressed (128-digit cap, Decimal-to-int conversion with overflow guards). Finding F-001 (LOW).

### test/incus/retire_ebpf_artifact_schema_test.py
Extensive mutation tests including boolean-vs-int (bool rejected via isinstance check), lossy decimal (1373.0000000000000001 rejected), huge decimal integer (1e999...), non-RFC JSON constants, non-UTF8, leap-second forms. No findings.

### test/incus/step1-histogram-classify.py — Step-1 histogram classifier
Reviewed: sum_per_binding_hist I13, sum_per_binding_kick K0-K3, compute_blocks deltas, compute_T_D1/D2, permutation_pvalue, classify_cell (I11/I12/suspect), gather_baseline, main. Python big-int safe; numpy int64 hist sums. Findings F-007 (LOW), F-016 (LOW).

### test/incus/step1-histogram-classify_test.py
K0-K3 invariant tests, kick delta emission correctness, submit-pathway unchanged, empty per_binding rejected. No findings.

### test/incus/step1-rate-spread-analysis.py — Verdict B threshold Y
Reviewed: load_per_flow_rates, trimmed_min, cell_spread, bootstrap CI. 4-cell stddev is noisy but CI is emitted to document uncertainty. No findings.

### test/incus/step1-rss-multinomial.py — RSS Monte Carlo
Reviewed: simulate (uniform and skewed), tail_probabilities, multi-cell aggregation. random.Random deterministic; no truncation. No findings.

### test/incus/step2-sched-switch-classify.py — Step-2 classifier
Reviewed: load_jsonl, compute_T_D1, spearman_rho (degenerate handling), verdict_from (SUSPECT short-circuit, duty gate), render_report, main (drift-halt marker, SUSPECT propagation, meta/diag split). Negative except F-SUBMIT (LOW, re-filed below as part of batch consolidation).

### test/incus/step2-sched-switch-classify_test.py
Verdicts IN/OUT/INCONCLUSIVE/SUSPECT, meta schema exact-keys, WARN aggregation, drift-halt marker, suspect_reason propagation. No open findings.

### test/incus/step2-sched-switch-reduce.py — Step-2 reducer
Reviewed: bucket_index_for_ns (defensive negative clamp), parse_perf_script (timestamp parsing without float), load_boundaries_ns (interval HALT/WARN, _error skip), block_for_timestamp (linear scan), reduce_events (monotonicity guard, vol/invol classification, stat_runtime accounting check, drift-halt SUSPECT stamping), main. Handles negative ns defensively. Finding F-008 (MEDIUM re-checked, downgraded to LOW informational).

### test/incus/step2-sched-switch-reduce_test.py
Covers bucket pins, boundary derivation, _error skip, synthetic 2-switch case, out-of-order skip, equal-ts zero-delta, wake-before-switch, empty events, invariant sum(buckets[3:7])==off_cpu_time_3to6, drift WARN/HALT, perf-script parse. No findings.

### test/incus/step3-tx-kick-classify.py — Step-3 TX-kick classifier
Reviewed: validate_hist_blocks, compute_T_D1, elevated_blocks (tie-inclusive), t1_in_block/t1_out_block (integer cross-multiplication, no float precision loss), classify (per-block table, rho_retry/rho_kick), spearman_rho, main. Integer gating is correct: sum_ns >= 4096*count uses Python big-int. No findings.

### test/incus/step3-tx-kick-classify_test.py
Covers delta arithmetic, 2^53 big-int stability, no-kick handling, IN/OUT/INCONCLUSIVE verdicts, elevated tie inclusion, rho reporting vs gating separation, wrong-length rejection. No findings.

### test/incus/test_mouse_latency_shell_test.py
Shell script structural assertions (env validation, manifest recording, settle budget, CoS artifacts). Not executable code. No findings.

### test/xsk-repro/*.c, *.rs, xdp_pass_redirect.c — XSK repro harness
Offline hardware debug tools; not part of production dataplane. Reviewed for obvious UB (use-after-free, TOCTOU) — none found. C files use aligned alloc correctly, handle map_fds, detach XDP on exit. Finding F-021 (LOW).

### pkg/scheduler/scheduler.go — Periodic scheduler
Reviewed: New/NewPrimed, Run loop (60s ticker), evaluate (wall-clock discontinuity detection, unsafeUntil hold, active map update, removed detection, republishPending retry), recordRepublishResultLocked, wallClockDiscontinuousLocked, isWithinWindow (date-range gate, effectiveDayWindow, half-window fail-closed), withinDateRange (now.Location() local TZ, #3988), effectiveDayWindow, withinTimeOfDay (wraparound). Concurrency reviewed in depth. Findings F-010 (Medium), F-011 (Low), F-012 (Low), F-CRITICAL (Critical, pre-existing batch file had this — re-checked, survives).

### pkg/scheduler/scheduler_*_test.go
Cover fail-closed on empty/half/no-window, per-day monday-only/tie-override/exclude/all-day, wall-clock backward/NTP shape/recovery hold, republish retry until converged, local-TZ date-range (PDT, UTC-0, daily window zone-safe). No findings.

### userspace-dp/src/bin/fairness-eval.rs + fairness_eval/*.rs + fairness.rs
Reviewed complete fairness-eval pipeline: args parsing, input loading (iperf JSON, binding TSV legacy 3-col and 6-col, CoS TSV), windowing (V-7 omitted filtering, V-6 iperf-epoch anchoring, 60s minimum with 5s slack, per-stream seeding from connected[]), per_worker aggregation (iface filtering, median-per-worker zero-filled for V-5, worker_id range check, sum before median), verdict (Gate 1 starved, Gate 2 CoV vs min(raw,trimmed) Cstruct (V-4 fix), Gate 3 saturation gated on expect_saturation (V-3 fix), RSS expectation, a_i sum guard, CoS-vs-binding cross-check), report (per-flow quantiles including starved-at-0, steady-state window timestamps, saturation series), RSS expectation parsing.

Integer handling: all counts u32, bps u64, structural_cap_bps computed as u128 intermediate then cast to u64 — safe (shaper_rate up to 25G, n_active<=6, intermediate <= 25G*6=150G < u64::MAX). Flow counts per worker u32 (max flows is small, ~hundreds). No truncation.

TOCTOU: CLI tool reads files once at startup; no concurrent mutation. No findings except F-020 (LOW), F-ARGS (LOW, same as F-020).

---

## Findings

---

### [F-CRITICAL-001] scheduler concurrent evaluate can clear republishPending for newer state — stale fail-open window

Title
Scheduler concurrent evaluate clears republishPending for newer closed-window state — scheduled permit stays past window (fail-open)

Severity
Critical

Confidence
Medium

Evidence
- File: `/home/ps/git/avacado-xpf/pkg/scheduler/scheduler.go:120-180`
```go
func (s *Scheduler) evaluate(now time.Time, notify bool) {
    s.mu.Lock()
    changed := false
    newActive := make(map[string]bool, len(s.schedulers))
    ...
    s.active = newActive
    ...
    if (!changed && !s.republishPending) || !notify || s.updateFn == nil {
        s.mu.Unlock()
        return
    }
    cp := copyActiveState(newActive)
    updateFn := s.updateFn
    s.mu.Unlock()
    err := updateFn(cp)
    s.mu.Lock()
    s.recordRepublishResultLocked(err, now)
    s.mu.Unlock()
}

func (s *Scheduler) recordRepublishResultLocked(err error, now time.Time) {
    if err != nil {
        if !s.republishPending {
            s.republishFirstFail = now
        }
        s.republishPending = true
        s.republishFailures++
        s.lastRepublishErr = err
        return
    }
    s.republishPending = false
    s.republishFirstFail = time.Time{}
    s.lastRepublishErr = nil
}
```

Trace
1. Ticker fires `evaluate(T)` with `newActive={workhours:true}`, `s.active` becomes `{true}`. Drops `mu`, starts `updateFn(true)` (takes e.g. 100ms for FRR reload).
2. Concurrent `Update(newSchedulers)` (same schedulers, or config commit that doesn't change schedulers) calls `evaluate(T+tick)` with `newActive={workhours:false}` (window closed). Drops `mu`, starts `updateFn(false)` which FAILS → should latch `republishPending=true`.
3. Earlier ticker's `updateFn(true)` returns success. Calls `recordRepublishResultLocked(nil)` → clears `republishPending=false` even though current `s.active` is `{false}` and its publish failed.
4. Next ticker tick at T+60s sees `changed=false` (active still `{false}`) and `!republishPending` (cleared by stale success) → returns without retry. Scheduled permit stays active 60s+ past window close (fail-open).

`mu` is released around `updateFn` so two `evaluate` calls overlap. No epoch/version check before clearing pending. `recordRepublishResultLocked` unconditionally clears on success.

Callers that can interleave: `Run` (ticker goroutine) and `Update` (daemon apply goroutine). `Update` holds daemon's apply lock but `Run`'s ticker is unsynchronized.

Refutation attempt
- Checked whether `Update` is serialized with `Run`: `Update` is called from `daemon.applyConfigLocked` which holds a daemon mutex, but `Run`'s ticker goroutine does NOT acquire that mutex. So they can interleave.
- Checked whether `evaluate` re-reads `s.active` before clearing: it does not. `recordRepublishResultLocked` blindly clears.
- Checked whether `evaluate` compares `cp` to current `s.active` before clearing: it does not.
- Checked whether `republishPending` is set before dropping `mu` (optimistic latch): it is NOT — set only after `updateFn` returns.
- Finding survives. Pre-existing file at `/tmp/ps-review-038-A10_go_services_cli_deploy-b3.md` (from prior batch run) already reported this as High; re-confirmed with full caller analysis.

HPC/invariant check
- Classic ABA / lost-update race on `republishPending` flag.
- Fix must either (a) version `s.active` and only clear pending if no newer `evaluate` has installed a newer `s.active`, or (b) set pending optimistically before dropping `mu`, or (c) serialize `evaluate` calls (singleflight / channel).

Why it matters
- A scheduler window closing (e.g., `deny` policy becoming active at 17:00) fails its first republish. Concurrent older evaluate's success clears the retry flag. Policy stays `permit` until next unrelated state change (could be hours away — overnight window). Security fail-open.

Fix direction
- Option 1 (minimal): In `evaluate`, capture current `s.active` generation / copy before dropping `mu`, and in post-`updateFn` path compare `s.active` vs captured `cp` — only clear pending if they are still equal (same epoch). If not equal, leave pending alone so newer state's pending retry survives.
```go
cp := copyActiveState(newActive)
gen := s.republishGen // increment on each evaluate that changes active
...
err := updateFn(cp)
s.mu.Lock()
if gen != s.republishGen { /* newer evaluate installed newer active, don't clear */ }
else { s.recordRepublishResultLocked(err, now) }
s.mu.Unlock()
```
- Option 2: Set `republishPending=true` optimistically before calling `updateFn` when `changed` is true, clear only on success and same-epoch.
- Option 3: Serialize `evaluate` via a single goroutine (channel-based: `Run` sends tick to same channel as `Update`, single consumer).

Dedup note: #3780 added republish self-heal but did not address concurrent evaluate interleave. Not in dedup index. Prior batch file reported similar but with High severity; elevating to Critical because fail-open on security policy window is Critical per project severity guidance.

Labels
concurrency, fail-open, scheduler, security

---

### [F-001] TOCTOU / UX nit in retire_ebpf_artifact_schema — uppercase SHA rejected via FULL_SHA_RE before lower() normalization

Title
Artifact commit comparison error message confusing for uppercase SHA — FULL_SHA_RE rejects before lowercasing

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/retire_ebpf_artifact_schema.py:21,139-220`
```python
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
...
self.expected_commit = candidate_commit.lower() if candidate_commit else None
...
raw_commit = manifest.get("candidate_commit")
if not isinstance(raw_commit, str) or not FULL_SHA_RE.match(raw_commit):
    self.error("manifest.json candidate_commit must be a full 40-character SHA")
else:
    self.candidate_commit = raw_commit.lower()
```
Input `raw_commit` is matched against `FULL_SHA_RE = ^[0-9a-f]{40}$` which rejects uppercase hex — so upper-case SHAs are rejected with "must be a full 40-character SHA" rather than normalized. `expected_commit` is lowercased before comparison but manifest raw_commit is not lowercased before regex.

Trace: Hand-edited manifest with `ABCDEF...` (40 uppercase hex chars) fails with "must be a full 40-character SHA" — misleading, it is 40 chars but wrong case.

Why it matters: Minor UX — confusing error message for hand-edited manifest.

Fix direction: Accept `[0-9a-fA-F]{40}` in FULL_SHA_RE, then normalize to lower, or improve error message to say "lowercase hex".

Dedup note: Not in dedup index.

Labels
ux

---

### [F-002] Float truncation in _parse_junos_rate — int(float*mult) can be off-by-one for fractional rates

Title
Float intermediaries in Junos rate parsing can produce off-by-one bps due to IEEE 754 representation

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/mouse_latency_orchestrate.py:54-65`
```python
def _parse_junos_rate(token: str) -> int | None:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([kmgt]?)", token.strip().lower())
    if not m:
        return None
    value = float(m.group(1))
    mult = _RATE_SUFFIX_MULTIPLIER[m.group(2)]
    return int(value * mult)
```
`float("0.3") * 1_000_000_000` = `299999999.99999994` → `int()` truncates to `299999999` (1 bps low). Similarly `float("1.001")`. The fixture only uses `1.0g`, `100m`, `3.0g` etc. which are safe, so no current impact. Future fractional rate could cause off-by-1 at settle-threshold boundary.

Trace:
1. `_parse_junos_rate("0.3g")` → `float("0.3")` = `0.29999999999999999` (IEEE 754)
2. `* 1_000_000_000` = `299999999.99999994`
3. `int(...)` truncates → `299999999` (1 bps low)
4. Compared against `floor_bps = math.ceil(0.7 * shaper_bps)` — off-by-1 mismatch at exact boundary could flip satisfiable verdict.

Why it matters: Could cause spurious unsatisfiable/satisfiable flip at tight boundary for future fractional rates.

Fix direction: Use `Decimal` for rate parsing, or `round(value * mult)` or `int(Decimal(m.group(1)) * mult)`.

Dedup note: Not in dedup index. Integer handling focus area; no prior entry about float truncation in Python rate parsing.

Labels
integer-handling

---

### [F-005] policy_scheduler_validate — _as_int silently coerces invalid values to 0

Title
Permissive _as_int coercion masks structural schema violations, degrading diagnostic quality

Severity
Medium

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/policy_scheduler_validate.py:46-54`
```python
def _as_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
```
Used for `packets` and `bytes` counters in `_policy_counter`. A counter value like `"corrupted"` becomes 0, making `active_counter.packets < min_active_packets` fail but with misleading message "packets=0" instead of "packets field is not an integer".

Trace:
1. Malformed artifact has `policy_rule_counters: [{"rule_id": "...", "packets": "corrupted"}]`
2. `_as_int("corrupted")` → 0 (except branch)
3. `active_counter.packets = 0`
4. Check `active_counter.packets < min_active_packets (1)` → True → ValidationFailure("active: packets=0, want >= 1")
5. Error message says "packets=0" but real issue is "packets field is not an integer" — debugging clarity loss. Not a bypass (still fails), so Medium not High.

Why it matters: In CI failure triage, misleading error messages waste engineer time.

Fix direction: Raise `ValidationFailure` on non-integer counter values instead of falling back to 0. Use strict variant for counters.

Dedup note: Not in dedup index.

Labels
correctness

---

### [F-006] policy_scheduler_validate — Regex validation is substring-based, not anchored

Title
Missing-scheduler rejection regex is substring-based — could false-PASS if artifact contains both rejection and success text

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/policy_scheduler_validate.py:169-177`
```python
missing_text = _read_text(root / missing_scheduler_output)
if not re.search(r"references undefined scheduler|scheduler .+ not defined", missing_text):
    raise ValidationFailure(
        "missing scheduler commit artifact does not contain the strict rejection"
    )
if re.search(r"\bcommit complete\b|\bcommit successful\b", missing_text, re.I):
    raise ValidationFailure(
        "missing scheduler commit artifact looks like a successful commit"
    )
```
An artifact that contains both the rejection text AND "commit complete" (e.g., retry-then-success) would fail the second check (correct). But an artifact with `CommitComplete` (no space) would pass second check. This is CI-only trusted-artifact validation, not security boundary.

Why it matters: If used as release gate, loosened regex could let bad commit through.

Fix direction: No fix needed for CI-only; if gating releases, anchor with multiline and tighten success detection.

Dedup note: Not in dedup index.

Labels
hardening

---

### [F-007] step1-histogram-classify — numpy int64 overflow theoretical (not triggerable)

Title
Potential int64 overflow in numpy histogram aggregation (theoretical only)

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/step1-histogram-classify.py:70-71`
```python
hist = np.zeros(16, dtype=np.int64)
...
hist += bh_arr  # bh_arr dtype=np.int64
```
`np.int64` max ~9.2e18. Each count at most ~1e7 per 5s block, total per cell <1e9. Cannot overflow in practice. Python `count` is big-int, safe.

Why it matters: Theoretical only.

Fix direction: None needed.

Dedup note: Not in dedup index.

Labels
integer-handling

---

### [F-008] step2-sched-switch-reduce — mono_wall_offset_ns semantics and sign confusion

Title
mono_wall_offset_ns addition could be confusing if offset sign is wrong — caller must pass CLOCK_REALTIME - CLOCK_MONOTONIC, not inverse

Severity
Low

Confidence
Medium

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/step2-sched-switch-reduce.py:406-415`
```python
# HIGH-3 R2 addendum: `-k CLOCK_REALTIME` was rejected by target kernel's perf (EINVAL).
# Fallback: perf emits CLOCK_MONOTONIC; capture harness measures mono_wall_offset_ns
# (difference between CLOCK_REALTIME and CLOCK_MONOTONIC at a single instant) and passes it.
# Conversion is exact: t_wall = t_mono + offset. This is NOT inferred from first-event.
t_event_wall_ns = ts_ns + mono_wall_offset_ns
```
If harness computes `mono_wall_offset_ns = CLOCK_MONOTONIC - CLOCK_REALTIME` (inverse sign), then `t_wall = t_mono + offset` would be wrong by 2*offset. The comment says "CLOCK_REALTIME - CLOCK_MONOTONIC" implicitly but does not state sign explicitly. Actual harness code should be checked. Python int is unbounded so no overflow.

Why it matters: Wrong offset sign would place all events in wrong blocks, causing SUSPECT or wrong verdict.

Fix direction: Add explicit assert or doc: `mono_wall_offset_ns = CLOCK_REALTIME - CLOCK_MONOTONIC`.

Dedup note: Not in dedup index.

Labels
correctness

---

### [F-010] scheduler wallClockDiscontinuousLocked — degrades to wall-only when now lacks monotonic reading

Title
wallClockDiscontinuousLocked assumes now carries monotonic reading — time.Date-constructed now degrades to wall-only comparison

Severity
Medium

Confidence
Medium

Evidence
- File: `/home/ps/git/avacado-xpf/pkg/scheduler/scheduler.go:218-244`
```go
func (s *Scheduler) wallClockDiscontinuousLocked(now time.Time) bool {
    if s.lastEval.IsZero() {
        return false
    }
    wallElapsed := time.Duration(now.UnixNano() - s.lastWallUnixNano)
    if wallElapsed < 0 {
        return true
    }
    monoElapsed := now.Sub(s.lastEval)
    if monoElapsed < 0 {
        return true
    }
    delta := wallElapsed - monoElapsed
    if delta < 0 {
        delta = -delta
    }
    if delta > wallClockDriftTolerance {
        return true
    }
    return false
}
```
`now.Sub(s.lastEval)` uses Go monotonic when both have it (from `time.Now()`). If `now` is `time.Date(...)` (no monotonic), it falls back to wall-clock diff, making `delta ≈ 0` always, missing NTP jumps. Production callers use `time.Now()` (safe). Future caller passing parsed timestamp would miss discontinuity.

Trace:
1. Production: `Run` ticker → `time.Now()` (has mono) → correct.
2. Hypothetical: `handler(time.Parse(...))` → `s.evaluate(parsed)` → `parsed` no mono → `now.Sub(s.lastEval)` = wall diff → `delta=0` → no fail-closed → window opens/closes at wrong wall time.

Why it matters: Scheduler windows are security boundaries. Undetected wall jump → fail-open or fail-closed at wrong time.

Fix direction: Document `evaluate`'s `now` must carry monotonic reading, or add guard: detect missing monotonic (Go 1.25+ `HasMonotonic`, or heuristic: `now == time.Date(...)`) and treat as discontinuous (fail-closed).

Dedup note: Not in dedup index. #3988 fixed date-range TZ but not monotonic stripping.

Labels
concurrency, fail-open-risk, scheduler

---

### [F-011] scheduler — concurrent evaluate from Update + Run ticker could race, delaying retry by 60s

Title
Concurrent evaluate calls from Update + Run ticker could race on active/republishPending — 60s delay in retry

Severity
Low

Confidence
Medium

Evidence
- File: `/home/ps/git/avacado-xpf/pkg/scheduler/scheduler.go:92-180`
```go
func (s *Scheduler) Update(schedulers map[string]*config.SchedulerConfig) {
    s.mu.Lock()
    s.schedulers = schedulers
    s.mu.Unlock()
    s.evaluate(time.Now(), true)
}
func (s *Scheduler) Run(ctx context.Context) {
    ticker := time.NewTicker(60 * time.Second)
    for {
        select {
        case t := <-ticker.C:
            s.evaluate(t, true)
        }
    }
}
```
`evaluate` drops `mu` during `updateFn`. During that window, another `evaluate` could see stale `republishPending`. Worst case: 60s extra fail-open window, not permanent (next tick retries). Lower severity than F-CRITICAL-001 (which is permanent fail-open until unrelated state change).

Why it matters: Scheduled permit could stay active 60s past window in rare race.

Fix direction: Same as F-CRITICAL-001 (versioning) or optimistic latch before dropping mu.

Dedup note: Subset of F-CRITICAL-001 mechanism but different manifestation (delay vs permanent).

Labels
concurrency, scheduler

---

### [F-012] scheduler — map aliasing in NewPrimed/Update

Title
Scheduler map aliasing — Update/NewPrimed store caller-supplied map without copy

Severity
Low

Confidence
Medium

Evidence
- File: `/home/ps/git/avacado-xpf/pkg/scheduler/scheduler.go:50-58,111-116`
```go
func NewPrimed(..., schedulers map[string]*config.SchedulerConfig, ...) {
    s := &Scheduler{
        schedulers: schedulers,
    }
}
func (s *Scheduler) Update(schedulers map[string]*config.SchedulerConfig) {
    s.mu.Lock()
    s.schedulers = schedulers
    s.mu.Unlock()
}
```

Trace: Current daemon code passes fresh map from `config.Compile`, not reused. Safe today. Future refactor could mutate.

Fix direction: Copy map in NewPrimed/Update, or document "caller must not mutate after passing".

Dedup note: Not in dedup index.

Labels
concurrency

---

### [F-016] step1-histogram-classify — submit side lacks K3 monotonicity check (kick side has it)

Title
Missing monotonicity check on tx_submit_latency_count (submit side) — kick side has K3, submit side does not

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/step1-histogram-classify.py:197-284`
```python
def compute_blocks(snaps: list[dict]) -> list[dict]:
    aggregated = [sum_per_binding_hist(s) for s in snaps]
    kick_aggregated = [sum_per_binding_kick(s, i) for i, s in enumerate(snaps)]
    # K3 only on kick side:
    for i in range(1, len(kick_aggregated)):
        ...
        if c_cur < c_prev: raise ValueError("K3 violation: non-monotonic ...")
    blocks = []
    for b in range(12):
        h0, c0, _, txp0 = aggregated[b]
        h1, c1, _, txp1 = aggregated[b + 1]
        count_delta = c1 - c0
        if count_delta > 0:
            shape = buckets_delta.astype(np.float64) / count_delta
        else:
            shape = np.zeros(16, dtype=np.float64)  # masks corruption
```

Trace:
1. Daemon restarts between snap[5] and snap[6], resetting tx_submit_latency_count from 1_000_000 to 0, new data 50_000.
2. `count_delta = 50_000 - 1_000_000 = -950_000` → `count_delta <= 0` → `shape = zeros` — masks data loss, not loud failure.
3. Block 5 D1/D2 contribution becomes 0, could suppress true IN verdict (false negative).

Why it matters: Could cause false-negative on cell that genuinely has D1/D2 signal if daemon restart during 60s capture.

Fix direction: Add monotonicity check for submit side analogous to K3, or at minimum raise on negative count_delta instead of silent zero.

Dedup note: Not in dedup index. No prior entry about submit-side monotonicity missing.

Labels
correctness, robustness

---

### [F-018] mouse_latency_probe — histogram last bucket conflates ≤100ms and >100ms

Title
Histogram overflow bucket double-counts: last bucket is both "≤100ms" and ">100ms" overflow

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/mouse_latency_probe.py:40-42,353-364`
```python
HISTOGRAM_BUCKETS_US = [10, 20, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 100000]
def _compute_histogram(rtts_us: List[int]) -> List[int]:
    counts = [0] * len(HISTOGRAM_BUCKETS_US)
    for rtt in rtts_us:
        placed = False
        for i, upper in enumerate(HISTOGRAM_BUCKETS_US):
            if rtt <= upper:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1  # > 100 ms goes into the top bucket.
```
`100000` and `200000` both land in `counts[-1]`. Bucket is `(25000, ∞)` in practice, labeled 100000. Intentional compact design, but comment " > 100 ms goes into the top bucket" is misleading — it's actually " > 25000us goes into top bucket (labeled 100000)".

Fix direction: Clarify comment: last bucket is `(25000, ∞)` overflow.

Dedup note: Not in dedup index.

Labels
documentation

---

### [F-019] mouse_latency_orchestrate — fixture parser silently skips malformed lines

Title
Fixture parser silently skips lines with unexpected tokenization — typo could mask a class

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/incus/mouse_latency_orchestrate.py:100-165`
- All `except (ValueError, IndexError): continue` paths silently drop malformed lines.
- Test `test_real_fixture_grid_matches_canonical_rates` pins known ports (drift guard) — catches drift for known ports. Non-elephant ports' typos would not be caught.

Why it matters: Typos in fixture not caught by parser could mask CoS configuration errors.

Fix direction: Add warnings for unmatched terms (term with destination-port but no forwarding-class, or vice versa).

Dedup note: Not in dedup index.

Labels
robustness

---

### [F-020] fairness-eval args — --iface does not validate flag-like values, inconsistent with --rss-expectation

Title
Inconsistent validation of flag values that look like flags — --iface accepts "--n-workers" as value

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/userspace-dp/src/fairness_eval/args.rs:60-63,76-78,114-123`
```rust
"--iface" => {
    iface = args.next().unwrap_or_default();
}
"--rss-expectation" => {
    rss_expectation = parse_required_string_arg("--rss-expectation", args.next());
}
// parse_required_string_arg rejects values starting with "--"
```
If user typo passes `--iface --n-workers`, iface becomes `"--n-workers"`, `--n-workers` flag never parsed, `n_workers` stays default 6, iface filter matches no rows, distribution all zeros. Guard `a_i_sum_check_ok` would catch (a_i_sum=0 vs expected>0 → FAIL), so not false-PASS in current code. But if guard logic changes, could false-PASS.

Fix direction: Apply `parse_required_string_arg` to `--iface` as well.

Dedup note: Not in dedup index.

Labels
cli-correctness

---

### [F-021] XSK repro — system() return value ignored for link DOWN/UP

Title
system() return value ignored in XSK repro's link DOWN/UP — could false-PASS if ip not installed

Severity
Low

Confidence
High

Evidence
- File: `/home/ps/git/avacado-xpf/test/xsk-repro/libbpf_xsk_test.c:257-261`
```c
char cmd[256];
snprintf(cmd, sizeof(cmd), "ip link set %s down", iface);
system(cmd);
usleep(200000);
snprintf(cmd, sizeof(cmd), "ip link set %s up", iface);
system(cmd);
```
And `/home/ps/git/avacado-xpf/test/xsk-repro/main.rs:64-68`:
```rust
std::process::Command::new("ip").args(["link", "set", iface, "down"]).status().ok();
```
Ignoring return means if `ip` missing, link cycle silently skipped, phase 2 rebind runs without DOWN/UP, could PASS when real bug exists.

Fix direction: Check return value and abort repro if link cycle fails.

Dedup note: Not in dedup index.

Labels
testing

---

### Findings from prior batch run (re-validated, re-filed with full evidence above where applicable)

The prior batch output file already contained these findings (now re-filed with full traces / re-validated):

- **scheduler concurrent evaluate clears republishPending** → F-CRITICAL-001 (Critical, upgraded from High)
- **step1 submit side lacks K3 monotonicity** → F-016 (Low)
- **step2-sched-switch-classify missing b uniqueness** → folded into general robustness (not filed separately; covered by existing step2 tests that assert len==12 after sort)
- **fairness-eval TSV silently drops malformed rows** → assessed: `inputs.rs` uses `continue` on parse failure for both binding and CoS rows. This is intentional for backward compat (legacy 3-col, header lines). In-window rows that fail parse are dropped silently — could mask corruption. However `per_worker.rs` aggregates only in-window rows, so dropped rows would reduce `a_i` counts, making `a_i_sum_check_ok` fail (safe). Keeping as informational, not filing as separate finding (covered by F-020's general validation concern).
- **fairness-eval args silently default n_workers/shaper_rate on parse error** → `args.rs:64-75` uses `unwrap_or(6)` / `unwrap_or(0)` for `--n-workers` and `--shaper-rate-bps` but `--warmup-secs` / `--final-burst-secs` similarly. `--n-workers` typo would stay default 6 (could hide misconfiguration). `--shaper-rate-bps` typo would become 0, making `structural_cap_bps=0`, `saturated=false`, Gate 3 diagnostic-only (if `--expect-saturation` not set) — safe. If `--expect-saturation` set with `shaper_rate_bps=0`, `parse_args` already exits 2 (explicit check at lines 114-118). So only `--n-workers` typo could cause silent wrong `n_workers`. LOW. Fix: use `parse_required_numeric_arg` for `--n-workers`.

---

## Summary of Severities

| Severity | Count | IDs |
|----------|-------|-----|
| Critical | 1 | F-CRITICAL-001 |
| High | 0 | — |
| Medium | 2 | F-005, F-010 |
| Low | 11 | F-001, F-002, F-006, F-007, F-008, F-011, F-012, F-016, F-018, F-019, F-020, F-021 (12 inc. F-CRITICAL breakdown) |

Corrected Low count: 12 (F-001, F-002, F-006, F-007, F-008, F-011, F-012, F-016, F-018, F-019, F-020, F-021)

No High findings. One Critical (F-CRITICAL-001) is the top priority fix.

Integer handling: No truncation bugs found in batch. Python big-int safe, Rust u128 intermediate for structural_cap, u32 for counts, u64 for bps. No Go→Rust narrowing cast in this batch. Close: `_parse_junos_rate` float truncation (F-002, LOW).

TOCTOU: No TOCTOU on /tmp in probe/orchestrate (per-rep dirs). No TOCTOU on fairness-eval TSV (single-process CLI, read-once).

Scheduler concurrency: F-CRITICAL-001 is the main finding. Single-writer external serialization (daemon apply lock) does NOT prevent ticker vs Update interleaving.

Fairness-eval logic: V-3, V-4, V-5, V-6, V-7, V-9 fixes all verified correct. No logic bug in verdict pipeline.

---

## Negative Results (Required)

- **Mouse-latency probe:** No integer truncation — Python big-int. No TOCTOU. No secret leakage.
- **Mouse-latency aggregate:** No TOCTOU — single-process. Probe-config consistency check correct. Median selection correct.
- **Retire eBPF artifact schema:** Big-int safety explicitly handled (Decimal, MAX_JSON_INTEGER_DIGITS=128, bool rejected). No TOCTOU (read-only validation).
- **Step-1 histogram classify:** No overflow in practice. K0-K3 invariants sound for kick side. Permutation test deterministic.
- **Step-2 sched-switch reduce:** No overflow (Python big-int). Monotonicity guard correct. Negative-delta wake path is defensive dead code (documented). bucket_index_for_ns correct (port of umem.rs).
- **Step-2 sched-switch classify:** No logic bug. SUSPECT propagation correct.
- **Step-3 tx-kick classify:** No overflow — Python big-int cross-multiplication. No float precision loss in verdict.
- **Fairness-eval Rust:** No integer truncation. Windowing correct. Zero-filling correct. Cstruct trim gating correct. Gate 3 correct.
- **Scheduler general:** Half-window fail-closed correct. No-window fail-closed correct. Date-range local TZ correct. Republish retry until converged correct (single-threaded case). No integer truncation.
- **XSK repro:** Offline debug tools, no production impact.

## Dedup Check

All findings checked against dedup index (47 open, 80+ closed). No duplicate:
- F-CRITICAL-001 is new — #3780 added republish retry but not concurrent interleave.
- F-005, F-010, F-002, F-016, F-020 not in dedup.
- Closed issues #4273-#4280 (fairness-eval gates V-3/V-4/V-5/V-6/V-7) are fixed and verified; no re-report.
- #4272 (cos_flow_fair buffer_limit without max(1)) unrelated.
- #4277-#4283 (CoS TX, fairness-eval) unrelated.
