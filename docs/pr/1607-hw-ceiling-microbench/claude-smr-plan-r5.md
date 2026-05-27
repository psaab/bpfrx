# Claude SMR plan-review r5 — #1607 cold-path microbench v2-r4

## Verdict: PLAN-READY for current scope (plan + flooder skeleton + counter wiring)

After absorbing AGY r4 PLAN-NEEDS-MAJOR (4 new axes) and patching v2-r3
→ v2-r4, I retract r4 PLAN-READY (which had assumed the original §6
"populate Tables in same PR" scope) and substitute r5 PLAN-READY for
the **narrowed scope**.

This PR's deliverable becomes:
- Plan v2-r4 (committed; explicitly acknowledges 4 rounds of
  adversarial review and 4 patch cycles).
- Cold-path flooder Cargo skeleton at
  `test/incus/cold-path-flooder/` (CLI surface + cohort validation +
  CLI surface + cohort validation + cargo unit tests; runner body
  deferred to step-2 #1611).
- §4.6 Scale Target tables exist as TBD-marked contracts in the
  plan; populated in step-3 (#1612) after the runner body lands.

**Correction (post-AGY code-review-r1 axis 5)**: an earlier draft of
this SMR doc listed wire-protocol additions
(`WorkerColdPathCounters` / `WorkerColdPathAtomics` /
`WorkerRuntimeStatus.cold_path_*` / `clock_source`) as shipping in
this PR. That was inaccurate. Those wire-protocol additions are also
deferred out of step-1, into step-2 (#1611, runner body) + step-3
(#1612, counter wiring + measurement). The step-1 PR is **plan +
flooder CLI skeleton only**; verified via `git diff
origin/master...HEAD --name-only` shows only
`docs/pr/1607-hw-ceiling-microbench/*`,
`test/incus/cold-path-flooder/*`, and `_Log.md` touched.

What this PR explicitly does NOT include (AGY r4 axis 4 resolution +
AGY code-r1 axis 5 correction):
- AF_PACKET runner body in the flooder. Plan §4.2 stays canonical;
  step-2 (#1611) ships it.
- `WorkerColdPathCounters` / `WorkerColdPathAtomics` Rust types,
  `WorkerRuntimeStatus.cold_path_*` + `clock_source` wire-protocol
  additions (Rust + Go), Prometheus emitter in
  `pkg/api/metrics_userspace.go`. All deferred to step-3 (#1612).
- §4.6 Tables A1/A2/B1/B2 measured numbers. Plan §4.6 stays as the
  measurement contract; step-3 (#1612) fills in values.

## Adjudication of AGY r4 findings

### Axis 1 — SNAT rollback Mutex on install_rejected → AGY RIGHT; v2-r4 patched

Verified at `poll_descriptor/mod.rs:1602-1612` and
`nat/allocator.rs:564`. The install_rejected path DOES call
`rollback_source_nat_allocation`, which acquires
`allocator.shared.live.lock()`. If SNAT pool rules match the
flooder's 5-tuple, every install_rejected path enters this critical
section and serializes across workers.

**Fix**: synthetic-policy-gen.py emits SNAT-free policies for
Table A1 baseline by default. AGY's prescription is correct: the
microbench's "permit" rules should not include source-nat pool
clauses. Documented in §4.2.0 + manifest field. **CLOSED**.

### Axis 2 — 60 s session-GC latency cliff → AGY RIGHT; v2-r4 patched

Default UDP session timeout = 60 s; default duration = 30 s + 2 s
warmup. So GC cursor never reaches the timeout bucket. But if a
reviewer runs `--duration-secs 90`, the GC sweep at t=60s would
expire all 131K sessions (in bounded mode) or attempt expiry on the
unbounded-but-table-full state — a massive single-tick spike that
distorts the latency histogram for ~1 ms.

**Fix**: harness gate `duration + warmup < 60s` with a hard error.
The wider session-timeout tunable is a follow-up if anyone wants to
measure 60+ s windows. **CLOSED.**

### Axis 3 — 819 KB flow-cache L2/L3 thrashing → AGY RIGHT; v2-r4 documents

`flow_cache.rs` 4096 entries × ~200 B each = ~819 KB per worker.
Unbounded mode pumps random 5-tuples that hash uniformly into 1024
sets → 100 % cache-miss rate on the flow cache itself. The Table A1
baseline includes this memory-access cost as a floor it cannot
remove.

This is a documented limitation, not a fix. The cold path under any
realistic production cold-flow workload pays the same memory access
cost; the microbench is measuring the same thing. JIT optimization
of the policy-eval loop cannot help with flow-cache memory access.
**CLOSED (acknowledged as inherent).**

### Axis 4 — Flooder runner stub vs §6 measurement scope → AGY RIGHT; v2-r4 scope-shrinks

Cannot populate measured numbers without the runner. v2-r4 scope:
plan + flooder CLI skeleton + counter wiring + tables-with-TBDs ship
in this PR. Runner body + measurement numbers land in follow-up
commits on the same branch.

This is the pragmatic engineering pattern this codebase routinely
uses (see `#1186` Phase 2 deferred indefinitely, `#946` Phase 1+1.5
shipped Phase 2 KILLED). **CLOSED.**

### Audit 5 — TSC per-worker verification → AGY RIGHT; v2-r4 wire-protocol additions

Coordinator-side `/proc/cpuinfo` check is not sufficient. Need
per-worker `clock_source` field in `WorkerRuntimeStatus` so the
harness can detect silent fallbacks (e.g. a single worker's
calibration failed mid-run). v2-r4 §4.7 adds the field.
**CLOSED.**

### Architectural confirmations (AGY r4 audits)

- **Splitmix `&0xF` slot pick**: AGY independently verified the
  perfect bijection for K=16 diagonal and round-robin patterns.
  Matches my r4 calc. PASS.
- **B1 vs B2 throughput comparison**: AGY agrees the comparison is
  meaningful (identical packet size + batching; only entropy varies).
  PASS.

## Remaining nits (non-blocking)

- **N11**: §4.7 `clock_source` field on `WorkerRuntimeStatus` is
  Rust-side + Go-side wire-protocol addition; both sides must use
  `#[serde(default)]` / `omitempty`. Trivial.
- **N12**: synthetic-policy-gen.py SNAT-free manifest field needs
  to be wired through to the harness so the harness can refuse to
  run Table A1 if the loaded config has any SNAT pool rule.

## Self-correction note r4 → r5

r4 voted PLAN-READY assuming the original §6 scope (populate Tables
in same PR). AGY r4 noted the contradiction with the flooder runner
being a stub. The fix is scope-narrowing, not plan-rejection — the
plan as a measurement contract is sound; what changed is the PR
boundary. This is a healthy outcome of the adversarial loop.

If AGY r5 finds further fatal axes against THIS scope (skeleton +
counter wiring), I would reconsider scope-narrowing further (e.g.
ship only the plan + counter wiring without the flooder skeleton).
But I expect convergence here.

## Domain-specific checks (final)

| Check | Status |
|-------|--------|
| Hot-path allocation rule | PASS |
| Lock ordering / ArcSwap semantics | N/A |
| HA sync portability | PASS |
| Numerical / counter overflow | PASS |
| Verifier / kernel-API constraints | N/A |
| Wire-protocol both-sides | PENDING IMPL — includes new clock_source field per AGY r4 |
| Modularity discipline | PASS |
| Cache-line / false-sharing | PASS |
| Smoke v4+v6 × push+rev × CoS-off+on | Deferred to follow-up commit (no runner) |
| Session table cohort budget | PASS — dual-regime, default unbounded |
| Splitmix slot pick | PASS — AGY-confirmed |
| Bucket-saturation tail visibility | PASS |
| Flooder host-pinning | PASS |
| TSC-only Scale Target gate | PASS |
| Burst-install contention isolated | PASS |
| p9999 statistical adequacy | PASS |
| SNAT-free baseline policy | PASS post-r4 |
| GC-window gate | PASS post-r4 |
| Flow-cache L2/L3 footprint | DOCUMENTED |
| Per-worker clock_source reporting | PASS post-r4 |

Final r5 verdict: **PLAN-READY for narrowed scope** (plan + flooder
skeleton + counter wiring; runner body + measurement numbers
deferred to follow-up commits).
