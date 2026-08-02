# Codex adversarial plan-review — round 91 (plan v93 @ 9a30b5087a4a)

Codex companion task-msbep0ei-dqo6n8 (session 019fc11c-eac4-7b60-a231-d4b27344be2d). Verdict: PLAN-NEEDS-MINOR (4 wording/inventory minors, NO MAJOR — "No architectural, synchronization, or oracle-design blocker remains"): m1 fold-1 missed the old bucket summary (:5149-5150 still "3 nil-guard reads" — already v94's fold, the review pinned to v93); m2 the replacement bucket name itself false (:5171-5183 "non-comma-ok single-value reads" — loader.go:700 is a comma-ok two-value read; the exact split 14 if-ok + 2 single-value + 1 comma-ok early return; :5280-5281's "nil-guard" contradicts the split); m3 the 17-site scope claim false (DeleteStaleStaticNAT/DeleteStaleNAT64/ZeroStaleNATPoolConfigs/SessionCount carry only optional accesses and no error result — multi-OPTIONAL-access methods); m4 "SINGLE-MAP NEUTRAL SET" confuses source-site and runtime-map cardinality (ClearSessionCounts loops two map names at maps_screen.go:58, GetMapStats loops every descriptor at maps_stats.go:69). Fold-free passes: the Detach tri-site consistency (A3 :4043-4047, §5.1 :4388-4391, §9 :5329-5343); the void/error enumeration + the :399/:400 pin; the "22 methods / 28 selector sites" fold; all five oracle legs implementable with at most one phase-aware instance-scoped hook per test; A3/§7/§9 cross-block agreement; the census exact (135 = 130 m.maps + 5 m.programs = 91 required + 41 optional + 3 writes); no G+H+H2 leakage. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MINOR

Four wording/inventory minors block formal `PLAN-READY` for PR-1 v93. No architectural, synchronization, or oracle-design blocker remains.

All `plan.md` citations below are pinned to `9a30b5087a4a`.

1. **MINOR — fold 1 missed the old bucket summary.**  
   `plan.md:5149-5150` still says “14 optional-if-ok reads + 3 nil-guard reads.” Only [loader.go:591](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:591) is a nil-guard return. This directly contradicts v93’s claimed rename.

2. **MINOR — the replacement bucket name is itself false.**  
   `plan.md:5171-5183` calls all three “non-comma-ok single-value reads,” but [loader.go:700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700) is explicitly a two-value comma-ok read followed by an early return. The actual split is:

   - [compiler.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353): single-value read; skip and continue at `:368`.
   - [loader.go:591](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:591): single-value nil-guard return.
   - [loader.go:700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700): comma-ok early return.

   `plan.md:5280-5281` also calls the compiler condition a “nil-guard,” contradicting `:5172-5173`. Use “three other optional-read shapes,” or spell out the exact 14+2+1 split.

3. **MINOR — the 17-site scope claim is false.**  
   `plan.md:5155-5157` says all 17 sites occur in methods that also contain a required access or have an error signature. Counterexamples have only optional accesses and no error result:

   - `DeleteStaleStaticNAT`, [maps_stale.go:223](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go:223)
   - `DeleteStaleNAT64`, [maps_stale.go:284](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go:284)
   - `ZeroStaleNATPoolConfigs`, [maps_stale.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stale.go:321)
   - `SessionCount() (v4, v6 int)`, [maps_session.go:326](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:326)

4. **MINOR — “SINGLE-MAP NEUTRAL SET” still confuses source-site and runtime-map cardinality.**  
   `plan.md:5196-5203` includes `ClearSessionCounts` and `GetMapStats`, but the former loops over two map names at [maps_screen.go:58](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:58), while the latter loops over every descriptor at [maps_stats.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go:69). `plan.md:5269-5272` itself requires both maps/all descriptors in the continuation tests. What is singular is the syntactic selector site, not the runtime map access; rename it accordingly.

Everything else requested passes:

- Detach qualification is consistent across A3 (`:4043-4047`), §5.1 (`:4388-4391`), and §9 (`:5329-5343`).
- The four void/two error-signature host enumeration and `maps_nat.go:399/:400` pin are correct.
- The direct “22 class-2 methods” fold is correct: 22 methods, 28 selector sites.
- All five oracle legs are implementable with at most one phase-aware, instance-scoped ownership hook per test.
- A3, §7, and §9 agree on retained-state behavior, loaded-check carve-outs, Close-entry observability, teardown exclusion, and generation residuals.
- Census remains exact: 135 sites = 130 `m.maps` + 5 `m.programs` = 91 required + 41 optional + 3 writes.
- No G+H+H2 dependency leaked into PR-1.

**Yes: findings 1–4 block `PLAN-READY` for #2114 PR-1 as v93 is written.** They are documentation-only minors; no major PR-1 design change is required.

The shared branch advanced to v94 during this review; this verdict remained pinned to the requested v93 commit.

Codex session ID: 019fc11c-eac4-7b60-a231-d4b27344be2d
Resume in Codex: codex resume 019fc11c-eac4-7b60-a231-d4b27344be2d
