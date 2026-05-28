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

| Reviewer | Task ID | Status | Verdict |
|----------|---------|--------|---------|
| Copilot | PR #1619 reviewer-bot | dispatched 2026-05-28 | pending |
| Codex | (will dispatch on PR diff) | pending | pending |
| AGY | (will dispatch on PR diff) | pending | pending |
| Claude SMR | (in conversation) | done | CODE-READY for STAGED scaffolding scope |
