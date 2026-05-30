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

### Round 2 (HEAD 4d6f93ce6 — major #1 + 2 minors fixed)
- Codex r2: task-mprxlkar-e1auk6 — MERGE-NEEDS-MAJOR (2 NEW majors: fully-packed container leaf dropped; modifier child swallowed trailing garbage. Confirmed r1 major #1 + minors #2/#3 fixed)
- Copilot r2: COMMENTED, no inline (original major resolved)
- Claude SMR r2: concurred; verified probes

### Round 3 (HEAD 48fabf1d3 — both r2 majors fixed)
- Codex r3: task-mprxv25r-baz5f6 — MERGE-NEEDS-MINOR (1 minor: packed-leftover leaf validated with singleton sibling set → split-modifier siblings falsely rejected. Confirmed both r2 majors + r1 minors fixed)
- Claude SMR r3: concurred; reproduced the regression via probe

### Round 4 (HEAD c85f61e8b — r3 minor fixed via leftover grouping)
- Codex r4: task-mpry764r-46otxf — (pending)
- Copilot: re-requested on latest HEAD — (pending)
- Claude SMR r4: MERGE-READY — proved no double-validation (validator called exactly once per leaf), no false-reject on realistic multi-subtree configs, all reject cases still reject; full suite green, 5/5 flake clean

### AGY
- AGY r2 (HEAD f586b9677): adversarial-review-mprxfd4w-at6of4 — MERGE-READY (verified 6 focus areas; missed the packed-leftover majors that Copilot+Codex caught). Fix commits since are additive validation tightening; no new architecture.

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
