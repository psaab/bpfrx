# Codex hostile plan-review — round 75 (plan v76 @ 27c602aab)

Task: task-msawe6xn-a4zxc3 (session 019fbf47-e420-7eb2-bf3d-8d22a8c7e2a9).
Verdict: PLAN-NEEDS-MAJOR (2 MAJOR — A3 conflates fresh-unarmed and retained-unarmed states (Close retains maps/programs for hitless restart; the gate would suppress master's retained-state behavior); the direct swap test reaches :632 but does not pin its LOCK (mutant schedule passes) — 3 MINOR: stale 5.1 delegation label; missing Detach leg + error-order qualification; fixture migration mechanism + ~30-test inventory). Passed rulings incl.: xdpFlagClaims locking NOT required (Start never touches it); no Start-window private-helper bypass (CompileConfig gates at compiler.go:178). Raw companion output follows verbatim.

---

# Verdict: PLAN-NEEDS-MAJOR (2M/3m)

Yes. Findings 1 and 2 independently block PLAN-READY for #2114 PR-1. v76 has not converged.

## Findings

1. **MAJOR — A3 conflates fresh-unarmed and retained-unarmed states.**

   The class contract assumes `loaded=false` means maps are absent, then claims class-2 outcomes are byte-for-byte preserved and class 1 is the only intentional behavior change ([plan.md:3595](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3595), [plan.md:3757](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3757), [plan.md:4233](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4233)).

   That premise is false in the retained re-arm state v76 itself uses for Detach:

   - Bootstrap calls `Teardown` but keeps the same manager for re-arm ([bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:470)).
   - Root `Close` sets `loaded=false` but clears neither `m.maps` nor `m.programs`; `Cleanup` only removes pinned filesystem state ([loader.go:1203](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1203), [loader.go:1223](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1223)).
   - Master therefore still reads or mutates retained objects: `SessionCount` iterates retained maps ([maps_session.go:326](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:326)); `GetMapStats` reports them ([maps_stats.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go:69)); `ClearSessionCounts` and `ClearStaticNATEntries` delete retained entries ([maps_screen.go:58](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:58), [maps_nat.go:259](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:259)).
   - Class-4 `Map`/`Program` return retained handles rather than nil ([loader.go:1151](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1151)).
   - Gating can also suppress Go-side effects outside root: userspace `UpdateHAWatchdog` returns on the root error before updating `haGroups` ([manager_ha.go:807](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_ha.go:807)).

   Suppressing stale handles may be the correct policy, but it is not preservation. A3 needs a two-state audit—fresh-unarmed versus retained-unarmed—for every class, including caller retry/side-effect analysis and retained-state matrix coverage. The Detach-only exception does not close this systemic gap.

2. **MAJOR — the direct swap test reaches `:632` but still does not pin its lock.**

   The distinct seeded program correctly defeats both early exits and reaches [loader.go:632](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:632). It does not establish that the final write is protected.

   A valid silent-green mutant schedule after removing only the `:632` lock is:

   1. Getter locks, reads, and unlocks.
   2. Swap subsequently takes the planned `m.mu` sections at `:609` and `:613`.
   3. Swap performs the unlocked `:632` write.

   The getter’s unlock synchronizes-before the swap’s earlier locks, so its read happens-before the mutant write. The `:154` Start seam does not place an actor between the last pre-write unlock and `:632`; seeding proves branch execution, not lock ownership ([plan.md:4439](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4439)).

   Add a seam inside the intended final critical section and assert a getter blocks until release, or use an in-section `TryLock`/structural lock assertion. The current race schedule can still pass after the exact regression it claims to catch.

3. **MINOR — §5.1 still directs the rejected Detach implementation.**

   The authoritative contract correctly says no loaded gate and class-3-like delegation ([plan.md:3695](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3695)), but Concrete Design still says “class-2 delegation target” ([plan.md:3960](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3960)). That is v75’s stale-claim bug.

4. **MINOR — the Detach test and error-order contract remain incomplete.**

   Section 4 promises the fake link/seeded-claims regression ([plan.md:3709](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3709)), but §9 item 4a contains no Detach leg and ends at the XSK fixture ([plan.md:4416](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4416)). Give it an `ArmedGate`/`PreArm`-matching name so the scoped race target actually runs it.

   Also qualify “cleanup always runs”: current `vlan_iface_map` lookup and `iface_zone_map` iteration errors return before claim mutation ([loader.go:730](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:730), [loader.go:747](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:747)), preserving claims and the link for retry. Do not accidentally delete claims before those discovery failures.

5. **MINOR — fixture migration is much broader than the one named test.**

   The armed fixture is constructible, but `xdp_shim_decouple_test.go` is package `userspace`; a helper placed only in `pkg/dataplane/*_test.go` is not importable. Specify either a production-compiled exported free test seam or the existing userspace-local reflection/unsafe mechanism ([manager_testhelpers_test.go:22](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_testhelpers_test.go:22)).

   Static inventory found at least 30 affected synthetic userspace tests, not only the named XSK test. Examples include class-4 `Map` calls from [maps_sync_cap_test.go:63](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync_cap_test.go:63) and class-1 setters on an injected unarmed manager in [clear_bounded_5304_test.go:35](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/clear_bounded_5304_test.go:35). Root fixtures such as [maps_session_clear_test.go:17](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_session_clear_test.go:17) and exact-error tests in [watchdog_test.go:9](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/watchdog_test.go:9) also require migration.

## Fold disposition

- **M1 Detach:** The §4 shape is correct for the three normal states, subject to the error-order clarification: fresh `New()` has no link and returns nil; armed behavior is preserved; retained re-arm still cleans claims. Scoped `m.maps` locking closes the Go-map repopulation race.
- **Attack 4(a): PASS.** Only acquire/copy the `*ebpf.Map` under `m.mu`; iteration, BPF lookup, and update stay outside. That matches [plan.md:3621](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3621).
- **Attack 4(c): PASS.** `xdpFlagClaims` is currently unlocked at [loader.go:719](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:719) and [loader.go:764](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:764). Start never touches it, so PR-1 does not require claim locking. Broad locking would need to cover `SetZone` too.
- **M2 swap:** Branch reachability passes; lock pinning fails.
- **m1 labels:** Trio single-homing and Detach’s §4 manifest label pass; §5.1 remains stale.
- **m2 fixture:** Intent passes; mechanism and inventory are incomplete.
- **m3/§10 premise:** PASS. Every status-loop start remains after `CompileUserspaceShim` returns; the post-arm VLAN race disposition is accurate.
- No additional Start-window private-helper bypass was found: `CompileConfig` returns on `!IsLoaded()` before attachment/fallback ([compiler.go:178](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:178)).

The G+H+H2 follow-up unit was not reviewed.

Codex session ID: 019fbf47-e420-7eb2-bf3d-8d22a8c7e2a9
Resume in Codex: codex resume 019fbf47-e420-7eb2-bf3d-8d22a8c7e2a9
