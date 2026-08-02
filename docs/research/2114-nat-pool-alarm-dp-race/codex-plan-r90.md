# Codex adversarial plan-review — round 90 (plan v92 @ 7eb2e20df0d4)

Codex companion task-msbdsn1w-gi4d9e (session 019fc105-de20-71c2-8168-6dff64780c52). Verdict: PLAN-NEEDS-MINOR (4 minors, no MAJOR — the second consecutive all-minor round): m1 fold-2 retains the exact "simply returns" overgeneralization (plan.md:5101; and :5127 labels all three accesses "nil-guard reads" — compiler.go:353 skips-and-continues, loader.go:700 is comma-ok early return); m2 fold-4 corrected only in detailed §9, not A3 (:4010) or §5.1 (:4349) — the unconditional "cleanup always runs" summaries persist; m3 fold-1 leaves a false signature sentence (:5174 "inside error-signature methods" — four hosts are VOID: maps_nat.go:434, maps_session.go:611, loader.go:909/:927; only UpdatePolicyScheduleState and ClearZoneCounters return errors; and the v92 status reverses the source pin: offset reset maps_nat.go:399, lookup :400); m4 one stale class-2 count label (:3895 "22 best-fit class-2 lookups" → methods or 28). Fold results: fold-1's primary classification passes (ClearNATRuleCounters listed class-3, the triple complete, maps_nat.go:400 absent from the mixed list); fold-3 passes (§6/§8 both name the IsLoaded surface); fold-5 passes (legs 1-2 quiescent, 3-4 Start-hold, 5 Close-window); the census passes exactly (135 = 130 m.maps + 5 m.programs; 91 required + 41 optional + 3 writes; no stale "79 required"). Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MINOR

Four PR-1 consistency issues still block `PLAN-READY`; none requires architectural redesign.

1. **MINOR — fold 2 retains the exact “simply returns” overgeneralization.**  
   The corrected rule is immediately contradicted by [plan.md:5101](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5101>), which still says “the nil-guard simply returns.” [plan.md:5127](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5127>) also labels all three accesses “nil-guard reads.” In reality, [compiler.go:353](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353>) skips redirect-map population and continues at `:368`; [loader.go:700](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700>) is comma-ok with an early return. The normative rule and bucket names must preserve skip, return, and continue site-by-site.

2. **MINOR — fold 4 is corrected only in detailed §9, not A3 or §5.1.**  
   A3 still says claim cleanup “always runs” and specifies only `xdpLinks` plus `xdpFlagClaims` seeding at [plan.md:4010](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4010>); [plan.md:4349](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4349>) repeats the unconditional claim. Only [plan.md:5267](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5267>) adds the usable `iface_zone_map` and absent-map exception. Source returns at [loader.go:700](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700>) before claim discovery at `:711` and deletion at `:777`. Propagate §9’s qualification and seed into both summaries.

3. **MINOR — fold 1 leaves a false signature/classification sentence.**  
   [plan.md:5174](</home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5174>) says all six listed neutral accesses are “inside error-signature methods.” Four hosts are void: [maps_nat.go:434](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:434>), [maps_session.go:611](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:611>), and [loader.go:909](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:909>)/`:927`. Only `UpdatePolicyScheduleState` and `ClearZoneCounters` return errors. This conflicts with the otherwise-correct class assignment at [plan.md:5147](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5147>). The v92 status also reverses the source pin: offset reset is [maps_nat.go:399](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:399>); the registry lookup is `:400`.

4. **MINOR — one stale class-2 count label remains.**  
   [plan.md:3895](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3895>) says “22 … class-2 lookups.” The inventory has 22 class-2 methods but 28 selector sites: 17 single-site accesses at [plan.md:5149](</home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5149>) plus 11 class-2 sites in the mixed inventory. Change “lookups” to “methods” or use 28.

Fold results:

- Fold 1’s primary classification passes: A3 lists `ClearNATRuleCounters` as class 3, the class-3 triple is complete, and `maps_nat.go:400` is absent from the mixed neutral-return list.
- Fold 2: incomplete, finding 1.
- Fold 3: passes; §§6 and 8 both name loaded-check admission and the external `IsLoaded`/REST/gRPC surface.
- Fold 4: detailed oracle passes, summaries remain inconsistent.
- Fold 5: passes. Legs 1–2 are quiescent, 3–4 use the Start publisher hold, and 5 uses the distinct post-`Store(false)` Close hook. Remaining “four-leg” occurrences are explicit history or unrelated follow-up text.
- Census passes exactly: 135 sites = 130 `m.maps` + 5 `m.programs`; three publisher writes at `loader_userspace_shim.go:185/:187/:190`; therefore 91 required + 41 optional + 3 writes. No stale “79 required” arithmetic remains.

**Yes: PR-1 findings 1–4 block `PLAN-READY` as written.** The underlying PR-1 architecture and five-leg oracle are sound; only minor plan corrections remain.

Codex session ID: 019fc105-de20-71c2-8168-6dff64780c52
Resume in Codex: codex resume 019fc105-de20-71c2-8168-6dff64780c52
