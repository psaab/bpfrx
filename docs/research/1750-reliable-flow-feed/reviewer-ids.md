# #1750 reviewer ID ledger

Research: reliable per-flow 5-tuple feed for the #1748 rebalance controller.
Branch: `research/1750-reliable-flow-feed` (docs only; no production code).

## Reviewers (3-way at /research: Codex + AGY + Claude-SMR)

| Round | Reviewer | Task/Job ID | Verdict | Notes |
|------:|----------|-------------|---------|-------|
| r1 | Codex | session 019e8aff-29b9-7e03-bc41-8c8e535966c7 (gpt-5.5) | PLAN-NEEDS-MAJOR | atomic-publish false; slot/worker_id keying bug (cause D) |
| r1 | AGY | adversarial-review-mpxd0g51-y35972 | PLAN-NEEDS-MAJOR (impl) | atomic-publish false; §6.3 dead code; low-PPS age-out/idle lag; PLAN-KILL rightly dismissed |
| r1 | Claude-SMR | claude-smr-plan-r1.md | PLAN-NEEDS-MAJOR (self-corrected) | converges with Codex+AGY on all 3 MAJORs |
| r2 | Codex | session 019e8b09-490a-7451-bd41-c8d37fcafa1e (gpt-5.5) | PLAN-NEEDS-MAJOR | 3 r1 majors closed; StaleFlowSnapshot unbounded defer; name the flow_worker_map() API change; D already fixed on branch |
| r2 | AGY | adversarial-review-mpxdevby-5iqxdy | PLAN-NEEDS-MINOR | 3 r1 majors verified CLOSED; only StaleFlowSnapshot livelock (use snapshot-age, not count-vs-rows) |
| r2 | Claude-SMR | claude-smr-plan-r2.md | PLAN-NEEDS-MINOR | converges: bounded snapshot-age defer; D already fixed; name API change |
| r3 | Codex | session 019e8b0e-ce20-7aa0-a578-b37f12f3d4be (gpt-5.5) | PLAN-NEEDS-MINOR→closed | r2 MAJOR closed; sole MINOR = flow_worker_map() 2nd consumer (helpers.rs:124) — folded v4 |
| r3 | AGY | adversarial-review-mpxdmsds-5k0kxu | PLAN-NEEDS-MINOR→closed | snapshot-age defer livelock-free + covers transient; sole MINOR = same helpers.rs consumer — folded v4 |
| r3 | Claude-SMR | claude-smr-plan-r3.md | PLAN-READY | spine triple-verified; r3 MINOR folded |

## r3 convergence → PLAN-READY v4
Codex r3 + AGY r3 both validate the bounded snapshot-AGE defer (livelock-free,
covers transient publish lag) and raise the SAME single MINOR: `flow_worker_map()`
has a second consumer `server/helpers.rs:124` (status/wire path), so the API
change must preserve/update it. Folded into v4 §5 + §6.1 (add a controller-facing
accessor OR update both call sites; don't break the status/wire export). With
that, no open finding remains: Claude-SMR PLAN-READY, Codex + AGY MINOR resolved.
Converged at v4.

## r2 convergence
All three confirm the r1 MAJORs are closed. Single shared defect: the
`StaleFlowSnapshot` defer was unsafe (dead after bundling for count-vs-rows;
livelocks on non-steerable traffic if it checks the filtered list). v3 fixes it
as a BOUNDED snapshot-AGE check (publish timestamp), falling through to a real
skip after N stale ticks. Also: cause D is ALREADY fixed on the branch
(`rebalance.rs:207-256` joins live↔identities, keys by worker_id) — keep + test;
name the `flow_worker_map()` consumer-API change (rows-only → bundled count);
worker_id is on `identities (BindingIdentity)`, not live state. Codex MAJOR vs
AGY/SMR MINOR is a severity-label difference on the SAME single defect; v3
resolves it for all three.

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
