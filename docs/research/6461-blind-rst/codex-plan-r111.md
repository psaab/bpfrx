# Codex hostile plan-review — round 111 (v10.27.0)

Reviewer: Codex (fresh thread, job task-ms9flcd0-6d0dof, 2026-07-31). Verdict: PLAN NO (1B/1M). r110-3 RESOLVED (the e2e regression is present and matches the code paths). r110-1 was UNRESOLVED at the reviewed commit v10.27.0 and was folded by v10.27.1's AGY-r110 folds (the struct declaration + every consumer gate now read effective_transition with its explicit Option<TransitionResult> type) before this review landed; r110-2's residual (three categorical overdue-contradicting claims) is folded in v10.27.2.

## Verbatim review

PLAN NO 1. **BLOCKER — `effective_transition` is still not mechanically defined or universall...

[2026-07-31T21:10:29.418Z] Assistant message
PLAN NO

1. **BLOCKER — `effective_transition` is still not mechanically defined or universally consumed.** The normative `MaterializeReport` declaration remains `{ site, validation, transition, displaced }`, omitting `effective_transition`, while later text initializes and carries the nonexistent field ([plan.md:1735](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1735), `plan.md:1769-1775`). Promotion and commit clauses still explicitly read raw `report.transition` at `plan.md:1749-1756` and `plan.md:1827-1833`, contradicting the “every consumer reads `report.effective_transition`” requirement at `plan.md:1798-1808`.

   Code trace: materialization is followed immediately by promotion before result construction ([session_glue/mod.rs:1194](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1194)); promotion currently checks only origin/disposition before overwrite, publication, and replication ([promote.rs:86](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86)). Consequently, the invalid `(Some(Site2c), Accepted, Installed)` report still lacks the specified fail-closed gate. Add the field and type to the report declaration, initialize it, and replace every raw normative transition read.

2. **MEDIUM — Categorical overdue statements still survive outside the SSOT.** Section 5.6 still says every closing site-2c materialization installs an alive probation copy (`plan.md:1302-1318`); §9 repeats `site 2c refuse → install ALIVE` (`plan.md:2418-2425`) and says the next unbuffered packet necessarily updates/promotes/clears (`plan.md:2596-2602`). These contradict the reachable `(Refused, OverdueSkipped)` branch, which performs no upsert, clear, or promotion (`plan.md:1354-1382`, `plan.md:1818-1834`). Due entries remain lookup-visible until strict, periodic wheel GC processes them ([expire.rs:130](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:130)).

The r110-3 regression is correctly present at `plan.md:2520-2528` and matches cache eligibility, lookup ordering, and exact-key invalidation (`flow_cache.rs:352-358`, `poll_descriptor/mod.rs:298-327`, `flow_cache.rs:1105-1120`). S2 production, capacity-three accounting, and current/sibling invalidation remain sound.

Round-110 dispositions: r110-1 UNRESOLVED; r110-2 UNRESOLVED; r110-3 RESOLVED.