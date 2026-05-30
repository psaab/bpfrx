# #1319 PR 1 reviewer task IDs

PR 1 scope: re-home typed-leaf schema onto config.setSchema; generic
SchemaValidate walker; wire typed-value `?` completion (symptom-1 fix);
retire cmdtree config-mode overlay. Plan converged 3-way PLAN-READY at
research/1319-typed-leaf @ c0f6e5a79 (research rounds below).

## Code review (PR 1 implementation)
### Round 1 (HEAD b28d619e4 / f586b9677)
- Codex r1: task-mprx9qxn-mzfpf4 — MERGE-NEEDS-MAJOR (1 major: descendInstanceLevels drops leftover Keys; minor#2 golden replace-path; minor#3 stale cmdtree comment)
- AGY r1: adversarial-review-mprxa5tm-qi5hdm — incomplete (captured only investigation trace; mid-amend transient build error)
- AGY r2 (HEAD f586b9677): adversarial-review-mprxfd4w-at6of4 — MERGE-READY (verified 6 focus areas; did NOT catch the leftover-Keys major — caught by Copilot+Codex)
- Copilot r1: COMMENTED, 1 inline (same major — descendInstanceLevels leftover drop)
- Claude SMR r1: in-conversation — removed unused parentSchema param; concurred on the major after Copilot/Codex flagged it

### Round 2 (HEAD 4d6f93ce6 — major + 2 minors fixed)
- Codex r2: task-mprxlkar-e1auk6 — (pending)
- Copilot r2: (`@copilot review` re-requested) — (pending)
- AGY: MERGE-READY stands (r2 covered the unchanged areas; fix is additive)
- Claude SMR r2: MERGE-READY — fix is minimal + regression-tested, full suite green, 5/5 flake clean

---

# Research plan reviewer task IDs (pre-implementation, converged)

## Round 1 (plan v1 @ afdd4b7e9)
- Codex: codex-plan-r1.md — PLAN-NEEDS-MAJOR (5 findings; verified §2.2 symptom-1-open)
- AGY: adversarial-review-mprtnlr4-2yhgdt — PLAN-READY
- Claude SMR: claude-smr-plan-r1.md — PLAN-NEEDS-MAJOR (D1-D5)

## Round 2 (plan v2 / v2.1)
- Codex r2 (on v2): codex-plan-r2.md — PLAN-NEEDS-MAJOR (1 finding: multi value-tail row)
- Codex r3 (on v2.1): codex-plan-r3.md — PLAN-READY
- AGY r2 (on v2): adversarial-review-mprtw0nt-rql2rj — PLAN-READY
- Claude SMR r2 (on v2.1): claude-smr-plan-r2.md — PLAN-READY

## Convergence: PLAN-READY at c0f6e5a79 (v2.1) — all three reviewers.
