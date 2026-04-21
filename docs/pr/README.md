# `docs/pr/` — PR-scoped review and measurement records

Each subdirectory holds plans, reviews, measurement evidence, and
post-mortems for one PR or closely-related PR series. Contents are
durable artifacts of the adversarial review cycle — NOT working
specs (those live at the repo root `docs/` level).

## Subdirectories

| Dir                          | Scope                                                        | Status                |
|------------------------------|--------------------------------------------------------------|-----------------------|
| `785-phase3/`                | MQFQ virtual-finish-time scheduler (PR #796)                 | merged `f37597ec`     |
| `797-d3/`                    | mlx5 RSS indirection + knob (PR #797)                        | merged `50acc495`     |
| `803-tunables/`              | Step-0 zero-code tunables (governor/budget/coalescence; PR #803) | merged `019c3db6` |
| `804-instrumentation/`       | Per-binding ring-pressure counters (PR #804)                 | merged `3d2d63a4`     |
| `800-workers-queues/`        | Workers vs RSS queue-count experiment                        | closed, no PR         |
| `line-rate-investigation/`   | Parent investigation (#798) plan + phase-B step 0 + gaps doc | #798 open             |

## Conventions

- Plans live as `plan.md`.
- Reviewer docs: `codex-review.md`, `rust-review.md`, `go-review.md`,
  `systems-plan-review.md` — one per reviewer angle. Append
  `## Round N verification` sections in place; don't fork new files.
- Measurement evidence: `validation.md` (narrative) + `evidence/`
  directory for captured JSON.
- Post-investigation gap analysis: `remaining-gaps.md` (see
  `line-rate-investigation/`).

## When to add a subdirectory

- The work opens a PR that warrants multi-round adversarial review.
- The work is an investigation that may or may not become a PR.
- The work generates measurement artifacts that the author needs to
  cite back from the PR body or from a follow-up issue.

## When NOT to

- Single-commit cleanups or doc typo fixes.
- Feature design docs that live alongside the feature — those stay
  at `docs/` root (e.g. `docs/cos-traffic-shaping.md`).
