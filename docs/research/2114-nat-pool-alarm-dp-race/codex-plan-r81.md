# Codex hostile plan-review — round 81 (plan v82 @ c4005f7c2)

Task: task-msb4689t-2vtj81 (session 019fc00f-417c-76e0-af83-ab38972e208e).
Verdict: PLAN-NEEDS-MAJOR (2 MAJOR — the registry AST canary had no precise self-enforced allowlist (and Store(true) lives in the caller, not the writer function); the reverse-schedule seam was not deterministically implementable (no injectable operation between adjacent statements) — 4 MINOR: summary carve-out erasures; oracle subcase qualifications; closure wording; citation + overbreadth). Verified passes: folds 2/3/5 present; nil-config/ctx ordering; per the fold-1 note 'repairable specification gaps, not grounds for PLAN-KILL'. Raw companion output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 2 major, 4 minor

Yes. Findings 1–2 are entirely within PR-1 and block `PLAN-READY` for #2114. They are repairable specification gaps, not grounds for `PLAN-KILL`. G+H+H2 were treated as out of scope.

### Fold verification

- Fold 1: normative escape → side-effect → neutral → error precedence is corrected and matches the real fabric errors. Minor summary/citation defects remain in finding 6.
- Fold 2: passes. `CompileConfig` checks nil config before `loaded`; the loaded-check set rejects in both unarmed states and proceeds armed.
- Fold 3: core ordering and the second post-Store/pre-unlock barrier pass. Minor per-entry/oracle wording remains in finding 4.
- Fold 4: motivation is correct, but neither new guard is specified at implementation grade; findings 1–2.
- Fold 5: requested principal sites pass. The obsolete objects are correctly described as live FD-backed objects of an old generation; one retained fixture plus a Close transition suffices; cleanup wording and the `:181` citation are corrected. A stale §6 copy remains in finding 3.

### Findings

1. **MAJOR — the registry AST canary has no precise, self-enforced allowlist.**

   V82 says direct access is allowed only inside “the registry helper and the whole-batch publication writer,” but names neither function nor signature and defines no scanner scope, permitted access shapes/counts, stale-allowlist check, or synthetic negative tests ([plan.md:4692](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4692)).

   This is material because the current candidate writer is the long `loadUserspaceShimObjectsOnce` function, with direct assignments at [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185), `:187`, and `:190`, while `loaded=true` currently occurs in its caller at [loader.go:161](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:161). Exempting the whole function would not prove every allowed access remains inside the critical section.

   The canary is also absent from the concrete inventories: PR-1 still says “canary pair” ([plan.md:4007](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4007)); §5.1 lists only the retirement and daemon-cell canaries ([plan.md:4120](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4120)); §9 item 5 likewise tests only those ([plan.md:4719](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4719)).

   Pin an exact, preferably tiny helper/writer allowlist; define whether matching is Manager-typed or package-wide name reservation; enforce allowed access modes/counts and stale entries; and add shared-scanner mutation tests.

2. **MAJOR — the reverse-schedule seam is not deterministically implementable as written.**

   V82 provides only the sentence at [plan.md:4688](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4688). The real critical intervals contain no injectable operation:

   - `ClearGlobalCounters`: side-effect unlock at [maps_counters.go:179](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:179), raw lookup at `:181`.
   - `ClearZoneCounters`: helper return at `:232`, lookup at `:233`.
   - `ClearNATRuleCounters`: helper return at [maps_nat.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:399), lookup at `:400`.

   An external `_test.go` schedule cannot guarantee writer acquisition between adjacent statements. This requires either:

   - a named production-referenced helper-entry hook before `m.mu.Lock`, plus a writer barrier after lock acquisition and before registry writes; or
   - dropping this runtime schedule in favor of a direct helper lock-ownership test backed by the fully specified AST canary from finding 1.

   The synthetic loader seam at [plan.md:4591](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4591) must also replace only privileged acquisition, not the real publisher; otherwise fake publication can make the test green without exercising production writes.

3. **MINOR — generic class/API summaries still erase the loaded-check and Teardown carve-outs.**

   Class 1 includes `AttachXDP`/`AttachTC` and generically promises the typed fresh-state error ([plan.md:3620](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3620)), although the later detailed exception correctly preserves their earlier `"eBPF programs not loaded"` checks ([plan.md:3673](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3673); [loader.go:490](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:490), `:1082`).

   Section 6 again says every retained class proceeds and mutations reach “live pinned maps” ([plan.md:4384](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4384)). Loaded-check entries reject, and Teardown-retained FDs remain live but are no longer pinned after [loader.go:1221](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1221).

4. **MINOR — §9’s “per-entry-point exact” oracle still needs explicit subcases.**

   “The rejection fires whenever `loaded==false`” needs valid-config, live-context, and successful-cleanup qualifications: nil config wins at [compiler.go:179](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:179), canceled context wins at [apply.go:238](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:238), and cleanup failures return first. Production `userspace.Manager.Compile` also removes XDP pins before its outer selector ([manager_compile.go:163](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:163)).

   Likewise, the “every class blocks” summaries should say loaded-check entries use two invocations: pre-Store rejection, then a new post-Store invocation that blocks. The second barrier at [plan.md:4637](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4637) makes this implementable; the summaries at `:4602`, `:4613`, and `:4673` do not state it.

5. **MINOR — closure wording remains contradictory.**

   PR-1 claims registry-selection race safety is closed in every state ([plan.md:4009](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4009)) and later calls registry access race-free (`:4782`), but the intervening summary says the population mutex merely narrows the lookup/population window without closure ([plan.md:4016](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4016)).

6. **MINOR — Fold 1 retains a mislabeled citation and overbroad status summary.**

   The class list cites `UpdateFabricFwd :30` ([plan.md:3621](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3621)); source line 30 belongs to `UpdateFabricFwd1`, while `UpdateFabricFwd` starts at [maps_fabric.go:18](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go:18). The status claim that error-outcome methods are class 1 “regardless” also ignores higher-precedence class-3/class-4 cases.

Nothing in the follow-up unit affects this verdict. No files were changed.

Codex session ID: 019fc00f-417c-76e0-af83-ab38972e208e
Resume in Codex: codex resume 019fc00f-417c-76e0-af83-ab38972e208e
