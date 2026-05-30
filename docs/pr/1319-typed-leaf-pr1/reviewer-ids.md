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
- Codex r4: task-mpry764r-46otxf — MERGE-NEEDS-MAJOR (multi-level packed chain `class-of-service schedulers be transmit-rate asd` as one flat node dropped; group pass must recurse). Confirmed r3 minor + r1 minor#2/#3 fixed.
- Claude SMR r4: proved no double-validation; concurred on the chain bug.

### Round 5 (HEAD 8da91bcfc — r4 chain bug fixed via group-pass recursion)
- Codex r5: task-mprxv25r-baz5f6/019e7775 — MERGE-NEEDS-MAJOR (extra unknown token in container identity `class-of-service extra { schedulers be transmit-rate asd; }` dropped nested typed leaves). Confirmed r4 chain fixed + Copilot separator commits correct.
- Copilot swe-agent: pushed d5d3243de/d0d16afdb (multi value-tail separator hardening — reject dangling/all-`to` tails). Reviewed + kept; rebased my work on top.

### Round 6 (HEAD ad2da1893 — r5 extra-token fixed)
- Codex r6: task-... /019e778d — MERGE-NEEDS-MAJOR (instance-path extra token `schedulers { be extra { transmit-rate asd; } }` dropped nested leaf). Confirmed r5 fixed + separator hardening correct.

### Round 7 (HEAD ffe8b7976 — r6 instance-extra fixed)
- Codex r7: task-mprz4suw-r7tl50 — MERGE-NEEDS-MAJOR (presence-token `schedulers { be surplus-sharing { priority foo; } }` mis-attributed child to the presence token's schema → `priority foo` accepted but compiler-applied). This finding exposed the design premise flaw behind the whole leftover machinery.

### Round 8 (HEAD 1035e4aae — COMPILER-FAITHFUL rewrite)
- Codex r8: task-mprzo9hr-m6e3gt/019e77a3 — **MERGE-READY**. Verified the compiler-faithful premise with a probe transcript (compileClassOfService reads leaves only from inst.node.Children; packed Keys ignored); confirmed every compiler-reachable garbage rejects (incl. r7 presence-token), packed shorthand genuinely compiler-discarded, walker has no dead code + terminates, full + focused suites green.
- Copilot r5 (commit 1035e4aae @ 06:51:10): COMMENTED, 0 open inline — **clean on final HEAD**.
- Claude SMR r8: **MERGE-READY** — drove the compiler-faithful rewrite; verified compileClassOfService+namedInstances read only instance children; probed every AST shape (flat-set/canonical/packed/extra-token/presence-token) against both SchemaValidate and CompileConfig; symptom-1 frontend tests pass; SetPath golden + two-SSOT docs intact.
- AGY final (HEAD 1035e4aae): adversarial-review-mprzyscf-xrggdm — **MERGE-READY** (verified import-cycle move, frontend completions, SetPath golden, cmdtree overlay retirement, compiler-faithful walker).

## Gate: 4-of-4 MERGE-READY on final HEAD 1035e4aae — Codex r8 + Copilot (0 inline) + Claude SMR + AGY. CLI/config only (no cluster smoke). Symptom-1 fixed: `set class-of-service schedulers x transmit-rate ?` => `<rate> 100k 10m 1g 10g`.

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
