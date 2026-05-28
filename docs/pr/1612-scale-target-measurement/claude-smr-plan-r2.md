# Claude SMR Plan Review — #1612 step-3 v2

**Role**: Domain SMR (network perf measurement, TSC vs clock_gettime,
AF_XDP cold-path instrumentation, Prometheus histogram design).

**Plan**: `docs/pr/1612-scale-target-measurement/plan.md` v2, 2026-05-28.

**Round 1 outcome**: Codex PLAN-NEEDS-MAJOR with 5 findings (HIGH x2,
MED x3). AGY r1 hit a 15-min print timeout (job marked succeeded but
result file empty — infra issue per `feedback_codex_infra_must_retry`
analogue). Claude SMR r1 was PLAN-READY-WITH-NIT; v2 lifts Codex's
findings 1-5 into the plan body.

**Verdict (r2)**: PLAN-READY

## Codex r1 fix audit

| Codex r1 finding | v2 location | Resolved? |
|------------------|-------------|-----------|
| HIGH 1: bounded-mode 1-in-256 violates parent contract | §1.3 — `XPF_COLD_PATH_SAMPLE_MASK` env override sets mask=0 (1-in-1) for bounded regime; mask=0xff (1-in-256) for unbounded default | YES |
| HIGH 2: seqlock pair coverage broken if reusing runtime gen | §1.2 — `WorkerColdPathAtomics` carries dedicated `cold_window_gen` field; publish flips its own gen each ~1s tick, independent of runtime 60s-rotation gen | YES |
| MED 3: bucket layout self-contradiction | §1.1 + §3.3 — formula pinned: `b = (54 - clz(ns\|1)).max(0).min(23)`; bucket 0 = `[0, 1024)` ns; bucket 23 saturates at 2^32 ≈ 4.295 s | YES |
| MED 4: splitmix64 collisions on real zone set | §1.1 + §3.4 — `keys_xor` toggle stability check + harness publication gate excludes aliased slots from Tables; raw TSV retains all slots with `alias_detected` flag | YES |
| MED 5: STAGED ship gap on Tables + #1609 unblock | §1.9 + §6 — explicit `MEASUREMENT DEFERRED` disclaimer block prepended to Scale Target section; PR description carries `#1609 v2 acceptance REMAINS UNMET` line | YES |

All 5 findings folded into the plan body. v2 → v1 fatal-axis
resolution map at top of plan documents the inheritance trail.

## Independent r2 review pass

### Pass

- **Sample-rate regime conditioning** (§1.3) is hot-path-safe: mask
  read once at worker startup from environment, stored in
  `worker_ctx.cold_path_sample_mask`. The per-packet check is one
  AND + one compare; no per-tick atomic reloads.
- **Cold-path seqlock** (§1.2) follows the same `fetch_add(AcqRel)`
  / `fetch_add(Release)` template proven in `WorkerRuntimeAtomics`
  at `worker_runtime.rs:236-256`. 2352 Relaxed stores between
  brackets is bounded, ~5 µs on a modern x86. The publisher is
  the only writer; readers spin on odd gen.
- **Collision detector** (§3.4) keeps hot path branch-free. The
  publication gate runs in the harness, not the dataplane.
  Re-analyzable from raw TSV if reviewers later disagree.
- **STAGED disclaimer** (§1.9) is explicit and machine-readable:
  the literal `MEASUREMENT DEFERRED` header appears in the
  rendered markdown, so any downstream tool grepping for
  populated tables can detect the deferred state.
- **Bucket formula** (§1.1) is line-for-line consistent with the
  existing 16-bucket formula at `umem/mod.rs:244`; the only
  delta is the `.min(23)` clamp. Code review for the new module
  should verify a one-line audit-grep against the existing fn.

### Out-of-band r2 findings

None new. v2 is consistent with itself and with the parent §4.3-§4.7
contract.

### Minor / NIT (carried from r1, not yet folded into body but
non-blocking)

1. NIT — Prometheus cardinality precedent (`drain_latency_ns_bucket`
   is 1152 series — cold-path proposal is ~2× that). Worth noting
   explicitly in §1.6 prose but doesn't change the design.
2. NIT — `clock_source` Prometheus encoding (info-gauge vs
   gauge-with-value-1). Plan picks the latter; either is fine,
   but the doc could justify the choice. Pure prose NIT.

Neither NIT blocks PLAN-READY.

## Verdict r2: PLAN-READY

v2 addresses all 5 Codex findings with documented per-finding fixes
and consistent prose. Cross-check against parent §4.3-§4.7 contract
shows no inheritance violations. Two remaining NITs are non-blocking
prose-only items.

Recommendation: dispatch Codex r2 + AGY r2 for confirmation. If
both PLAN-READY, proceed to implement. If Codex returns a fresh
finding, fold and re-review; if AGY returns infra-blocked again,
proceed with 2-of-3 (Codex + Claude SMR + Copilot at code-r1)
per `feedback_codex_infra_must_retry` analogue.
