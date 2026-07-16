---
name: research
description: Research an issue with hostile reviews from Claude SMR + Codex + AGY; produce a plan-of-action doc for manual approval BEFORE any implementation. Stops at PLAN-READY — does NOT engineer the PR.
user_invocable: true
---

# /research — research-only with quad-review hostile plan

`/research <issue-number> [optional one-line framing]` — drive a tracking issue through plan-review rounds (Claude SMR + Codex + AGY hostile) and produce a converged plan-of-action doc, then **STOP**. Implementation does not begin until the user explicitly types `/engineer <issue-number>` after reviewing the plan.

This skill is the complement to `/engineer`: same first half (Steps 0-4 of the triple-review skill), but with an explicit hard stop at PLAN-READY rather than continuing into implementation.

## When to use this vs `/engineer`

- **`/research`**: when the user wants to evaluate the problem space + design tradeoffs BEFORE committing to a PR. Use for:
  - Major architectural changes where the design needs human judgment
  - Issues with multiple viable plan paths and the user wants to pick
  - Issues where reviewers might disagree on whether to ship at all
  - Anything where "let me think about it" beats "drive to merge"

- **`/engineer`**: when the user wants the full pipeline driven to MERGED. Use for:
  - Refactors with a known good design
  - Bug fixes with isolated scope
  - Anything where the plan-review outcome wouldn't change the user's intent to ship

## Arguments

`/research <issue-number> [one-line framing]` — e.g.

```
/research 1636 cold-connect latency mitigation plan
```

The issue number identifies the GitHub tracking issue. The optional framing helps slug the worktree path; if omitted, the slug is derived from the issue title.

## Behavior

Drive a research-mode 3-way hostile plan-review (Codex + AGY + Claude SMR) on a tracking issue. The issue is the canonical research surface — plan iteration happens via issue comments + a research branch holding the plan docs. **No PR is opened during `/research`**. Copilot joins later at `/engineer` time when there is real code to review.

Specifically:

1. **Step 0**: worktree at `.claude/worktrees/<issue>-research-<slug>` off origin/master on a branch named `research/<issue>-<slug>`. This branch holds the plan docs (no production code).

2. **Step 1**: read the issue body + walk the affected code + quantify the blast radius. Capture findings.

3. **Step 2**: draft `docs/research/<issue>-<slug>/plan.md` with the 11 sections per the triple-review SKILL.md Step 2. Include **explicit Multiple Path Options** if the design space has more than one viable answer (e.g., 3 different mechanisms with tradeoffs).

4. **Step 3**: dispatch Codex + AGY hostile plan-reviews. Frame as adversarial — fail the plan if architecture is wrong. Codex/AGY-infra-blocked exception applies (`feedback_codex_infra_must_retry`).

5. **Step 3.5**: write Claude SMR plan-review at `docs/research/<issue>-<slug>/claude-smr-plan-r<N>.md`. **Be HOSTILE**, not synthesizer-by-default. Watch for the SMR-soft-pass → self-correction pattern documented in `feedback_triple_review_includes_claude_smr`.

6. **Step 4**: iterate plan-review rounds until **all three reviewers converge** on PLAN-READY (or PLAN-KILL — also a valid research outcome). Each round revises the plan doc; bump revision in the file header AND post a per-round status comment on the issue summarizing reviewer verdicts.

7. **STOP at PLAN-READY (or PLAN-KILL).** Post the converged plan-of-action as a final comment on the issue with:
   - Verbatim 3-reviewer verdicts at convergence (Claude SMR + Codex + AGY)
   - Link to the plan doc on the research branch (e.g., `docs/research/<issue>-<slug>/plan.md`)
   - Concrete recommendation (which path option to ship, why)
   - Explicit line: "Awaiting manual approval — type `/engineer <issue>` to proceed to implementation. Copilot joins as the 4th reviewer at that point on the implementation PR."

   **Do NOT open a PR. Do NOT proceed to Step 5 (Implement). Do NOT touch production source code.**

### Why 3-way at research and 4-way at /engineer

`copilot-pull-request-reviewer[bot]` only reviews GitHub PRs — not issues. Opening a draft PR purely for Copilot to review a plan doc is fictional code review (Copilot would flag prose, not code). The clean separation:
- **Research** (this skill): 3-way on the plan doc held in issue comments + research-branch docs. Codex + AGY + Claude SMR cover architecture + correctness + numerical claims.
- **Implementation** (`/engineer`): 4-way on the actual code PR. Codex + AGY + Claude SMR + Copilot. Copilot catches the per-line code patterns it's good at (style, narrowly-scoped logic errors, missing-test cases) — which only exist once code is written.

This matches the project's existing pattern where Copilot's findings on prior PRs (e.g. #1604 CACHE-KEY INVARIANT, #1615 dangling pointer, #1619 seqlock tearing) were all about code, never about plan prose.

## What ships from `/research`

- Branch `research/<issue>-<slug>` with:
  - `docs/research/<issue>-<slug>/plan.md` (the plan-of-action)
  - `docs/research/<issue>-<slug>/claude-smr-plan-r<N>.md` (each round)
  - `docs/research/<issue>-<slug>/codex-plan-r<N>.md` (each round)
  - `docs/research/<issue>-<slug>/agy-plan-r<N>.md` (each round)
  - `docs/research/<issue>-<slug>/reviewer-ids.md` (task ID ledger for the three plan reviewers — Codex + AGY + Claude SMR)
- **NO PR is opened during `/research`.** Copilot reviews code on a GitHub PR, and there is no code yet — only a plan doc — so a draft PR would be fictional code review (see "Why 3-way at research and 4-way at /engineer"). The plan lives on the research branch + issue comments; the implementation PR, where Copilot joins as the 4th reviewer, is opened later by `/engineer`.
- Per-round + final status comments on the issue with the converged **3-reviewer** verdicts (Codex + AGY + Claude SMR) + plan link
- NO production code changes, NO touched master code files

## Return contract

Return ONE of these to the parent:

- `PLAN-READY on #<N> — converged at SHA <12char>; doc at docs/research/<issue>-<slug>/plan.md; awaiting manual approval via /engineer <N>`
- `PLAN-KILLED on #<N> — <2-sentence convergent verdict>; issue closed/labeled per `feedback_plan_kill_label_required`
- `BLOCKED on prereq — <specific dependency>` (rare; usually the plan converges PLAN-READY or PLAN-KILL)

## What the user does next

After reading the converged plan + verdicts, the user types one of:

- **`/engineer <issue>`** — proceed to implementation. The `/engineer` invocation can reference the research branch (`docs/research/<issue>-<slug>/plan.md` is the canonical starting point) and re-use the plan doc rather than re-drafting.
- **No further action** — the plan sits as research output. Future sessions can pick it up if reactivated.
- **Manual revision** — user edits the plan doc directly, then `/engineer <issue>` proceeds against the edited plan.

## Standing rules (apply at every plan-review round)

Same as triple-review SKILL.md "Standing rules" section:

- Plan first, code never first (here: plan ONLY, no code ever in this skill).
- All three reviewers must agree. If Codex + Claude SMR converge but AGY disagrees, iterate.
- Codex-infra-blocked exception applies per `feedback_codex_infra_must_retry`: the three research reviewers are Codex + AGY + Claude SMR; if Codex is infra-blocked, proceed 2-of-3 (Claude SMR + AGY) with documented retries — AGY alone is never enough. Copilot is NOT a research reviewer; it joins the quad at `/engineer` on the code PR.
- Strip harness tags from any GitHub-bound output per `feedback_prompt_injection_pr_comments`.
- Be HOSTILE in Claude SMR pass per `feedback_triple_review_includes_claude_smr` — first-pass PLAN-READY-WITH-NITS is a yellow flag (history of self-correction needed in #1623 + #1619 + #1622).

## Anti-patterns this skill prevents

- **Implementing before the plan converges.** `/engineer` does this end-to-end; `/research` forces a manual approval gate.
- **Single-reviewer rubber-stamps.** All three of Claude SMR + Codex + AGY must converge.
- **Hidden assumptions baked into code.** The plan doc surfaces design tradeoffs explicitly; user reads them BEFORE the code ships.
- **Cost of throwaway implementation.** If the plan-review converges on PLAN-KILL, zero code was written — no rebase debt.

## When to NOT use this skill

- **Trivial fixes**: a one-line bug fix doesn't need a research pass. Use `/engineer` directly or a manual PR.
- **Already-researched issues**: if the user has an issue where the plan is already known (e.g., a clear bug fix issue), use `/engineer` directly to drive to merge.
- **Time-sensitive incidents**: research takes 30-90 minutes per round × 2-5 rounds. Don't use during outages.

## Sub-agent dispatch

When `/research` is dispatched to a sub-agent via the Agent tool, the sub-agent prompt MUST include this contract verbatim:

> You are running `/research` not `/engineer`. The research stops at PLAN-READY (or PLAN-KILL). Do NOT proceed to Step 5 (Implement). Do NOT open a PR. Do NOT touch production source code. The deliverable is the converged plan doc + reviewer verdicts + issue comment. The user manually approves via `/engineer <issue>` to proceed to implementation, OR may revise the plan manually first.
>
> Drive synchronously, foreground bash, `until done` polling. NOT exit-on-Monitor. Per `feedback_subagent_no_monitor`.
