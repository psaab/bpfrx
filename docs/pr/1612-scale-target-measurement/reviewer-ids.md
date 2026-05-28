# Reviewer dispatch ledger — #1612 step-3

Long-running agents lose Codex session state per
`feedback_codex_session_loss_continuation`. Record every dispatch
here so continuations can fetch by ID.

## Round 1 — plan v1

| Reviewer | Task ID | Status | Verdict |
|----------|---------|--------|---------|
| Codex | bl18sf74r (codex exec bg job) | done | PLAN-NEEDS-MAJOR (5 findings, HIGH x2 MED x3) |
| AGY | adversarial-review-mpp17n7h-4drn4w | infra-timeout (15min print) | n/a (retried as round-1.5) |
| Claude SMR | docs/pr/1612-scale-target-measurement/claude-smr-plan-r1.md | done | PLAN-READY-WITH-NIT |
| Copilot | n/a (post-PR; deferred to step-9 code review) | n/a | n/a |

## Round 1.5 — AGY retry on v1 (concurrent with v2 prep)

| Reviewer | Task ID | Status | Verdict |
|----------|---------|--------|---------|
| AGY | adversarial-review-mpp1fqt5-hw7zkb | dispatched 2026-05-28 | pending |

## Round 2 — plan v2 (Codex r1 NEEDS-MAJOR resolved)

| Reviewer | Task ID | Status | Verdict |
|----------|---------|--------|---------|
| Codex | bvdlo8m8x (codex exec bg job) | done | PLAN-NEEDS-MAJOR (3 new findings: HIGH env-override, MED sample-phase, HIGH keys_xor false-pass) |
| AGY | (skipped — running r1.5 still) | n/a | n/a |
| Claude SMR | docs/pr/1612-scale-target-measurement/claude-smr-plan-r2.md | done | PLAN-READY (retracted: r2 found new issues) |
| Copilot | n/a (post-PR) | n/a | n/a |

## Round 3 — plan v3 (Codex r2 NEEDS-MAJOR resolved)

| Reviewer | Task ID | Status | Verdict |
|----------|---------|--------|---------|
| Codex | foreground codex exec | done | PLAN-NEEDS-MAJOR (2 BLOCKING + 2 NIT findings) |
| AGY | adversarial-review-mpp228sk-umpf9i | done | PLAN-NEEDS-MAJOR (3 findings: same calibrate bug + cross-worker false-pass + missing lfence) |
| Claude SMR | docs/pr/1612-scale-target-measurement/claude-smr-plan-r3.md | done | PLAN-READY (retracted: r3 found new issues) |
| Copilot | n/a (post-PR) | n/a | n/a |

## Round 4 — plan v3.2 (Codex r3 + AGY r3 BLOCKING findings resolved)

| Reviewer | Task ID | Status | Verdict |
|----------|---------|--------|---------|
| Codex | (sandbox unstable this session; embedded-files retry if needed) | pending | pending |
| AGY | (deferred — r3 already covered the v3.x surface) | n/a | n/a |
| Claude SMR | docs/pr/1612-scale-target-measurement/claude-smr-plan-r4.md | done | PLAN-READY |
| Copilot | PR #1619 (draft) — @copilot review triggered | dispatched | pending |

## Round 5 — PR #1619 code review (STAGED scaffolding ship)

| Reviewer | Task ID / SHA | Verdict |
|----------|---------------|---------|
| Claude SMR code-r1 | `docs/pr/1612-scale-target-measurement/claude-smr-code-r1.md` @ `8f28b6badef7` | CODE-READY |
| Codex code-r1 | foreground codex exec embedded-files @ `8f28b6badef7` | CODE-NEEDS-MAJOR (3 findings: lfence end-side, CPUID rdtscp probe, Instant docstring) — resolved in `c0c8a7e91065` |
| Codex code-r2 | foreground codex exec embedded-files @ `c0c8a7e91065` | CODE-READY-WITH-NIT (2 NITs: stale clock_source doc, RDTSCP test gate) — resolved in `0b8a1bdba` |
| AGY adversarial code-r1 | `adversarial-review-mpp3is8d-ann17h` @ `c0c8a7e91065` | CODE-READY-WITH-NIT (2 NITs: LFENCE+RDTSCP redundant [non-blocking], substring grep false-positive) — substring NIT resolved in `3bb1a0ae6` |
| AGY adversarial code-r2 | `adversarial-review-mpp4m1ag-eoihkp` @ `199ce42a20e5` | **CODE-NEEDS-MAJOR** (verified counter-example: 'samples regressed: 0 < 122 — seqlock tore' caused by 16-retry exhaustion silently returning zeros) — all 3 remediation points applied in `f2d022493` (Option API + 128 retries + oracle fix) |
| AGY adversarial code-r3 | `adversarial-review-mpp57jd6-y8l9dg` @ `f2d022493` (ratification) | pending |
| Copilot code-r1a | PR #1619 reviewer-bot @ `76dcecd5478a` | COMMENTED (multiple inline findings on stale keys_xor / payload counts / fence docs) — all resolved by `c0c8a7e91`/`0b8a1bdba`/`f55958b29` |
| Copilot code-r1b | PR #1619 reviewer-bot @ `d2b41b9cfd03` | COMMENTED (additional inline findings on alias search domain msg, sample_tsc alias as foot-gun, snapshot test naming) — all resolved by `f55958b29` |
| Copilot code-r2 | PR #1619 reviewer-bot @ `3a2d2a650504b2d` | COMMENTED (4 inline findings: calibration #UD safety, snapshot docstring, plan sample_tsc x2) — all resolved by `d19019de1` / `27a2d024e` / `199ce42a2` |
| Codex code-r3 | foreground codex exec embedded-files @ `3a2d2a650504b2d` | CODE-READY-WITH-NIT (2 NITs: concurrent test oracle weakness, plan sample_tsc stale) — both resolved in `d19019de1` |
| Codex code-r4 | foreground codex exec embedded-files @ `d19019de1` | **CODE-READY-WITH-NIT** explicitly stating "STAGED ship is mergeable" — single NIT (plan zone_pair_slot doc) resolved in `199ce42a2` |
| Codex code-r5 | foreground codex exec embedded-files @ `f2d022493` | sandbox-timeout 10min (infra-blocked); falls back to AGY r3 ratification per coordinator |
| Copilot code-r3 | PR #1619 reviewer-bot @ `f2d022493` (re-review requested) | pending |
