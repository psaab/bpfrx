# #1750 reviewer ID ledger

Research: reliable per-flow 5-tuple feed for the #1748 rebalance controller.
Branch: `research/1750-reliable-flow-feed` (docs only; no production code).

## Reviewers (3-way at /research: Codex + AGY + Claude-SMR)

| Round | Reviewer | Task/Job ID | Verdict | Notes |
|------:|----------|-------------|---------|-------|
| r1 | Codex | session 019e8aff-29b9-7e03-bc41-8c8e535966c7 (gpt-5.5) | PLAN-NEEDS-MAJOR | atomic-publish false; slot/worker_id keying bug (cause D) |
| r1 | AGY | adversarial-review-mpxd0g51-y35972 | PLAN-NEEDS-MAJOR (impl) | atomic-publish false; §6.3 dead code; low-PPS age-out/idle lag; PLAN-KILL rightly dismissed |
| r1 | Claude-SMR | claude-smr-plan-r1.md | PLAN-NEEDS-MAJOR (self-corrected) | converges with Codex+AGY on all 3 MAJORs |
| r2 | Codex | (pending) | | re-attack v2 |
| r2 | AGY | (pending) | | re-attack v2 |
| r2 | Claude-SMR | claude-smr-plan-r2.md | | re-attack v2 |

## r1 convergence
All three: PLAN-NEEDS-MAJOR. Three MAJORs folded into v2: (1) "atomic publish"
is FALSE — count(AtomicU32) and rows(ArcSwap) are two stores → real reader skew
→ Path 1 bundles count into the row snapshot; (2) slot-vs-worker_id keying bug
(`workers.live` keyed by slot, loop labels it worker_id, rows carry worker_id,
select_move filters on worker_id) → independent zero-install → Path 1 part 2
fixes keying; (3) §6.3 dedup-insert carry-forward is dead code (lookup-then-
insert never dedups) → replaced with cold-path eviction side-table, deferred.
All three agree PLAN-KILL is wrong and Path 1 is the cheap correct fix.

Copilot joins as the 4th reviewer only at `/engineer` time on the real code PR.
