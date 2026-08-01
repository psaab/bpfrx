# Codex hostile plan-review — round 72 (plan v73 @ e33ab4a3a)

Task: task-msathcj1-mu2tjp (session 019fbefd-4133-7fd1-8964-99ad8ea1861c).
Verdict: PLAN-NEEDS-MAJOR (3 MAJOR — partition still neither total nor disjoint (3 unassigned no-op stubs; L/F overlap without direct-access limitation; no semantic oracle); category F contains a real Start-overlap race (the xdpEntryProg trio); detaches misclassified (break preserved neutral nil) — 3 MINOR: VlanSubInterfaces residual, class-3 test-oracle wording, ErrDataplaneNotArmed contract). Raw companion output follows verbatim.

---

## Verdict

**PLAN-NEEDS-MAJOR (3 major, 3 minor)** at `e33ab4a3a`.

Yes—PR-1 still contains blockers to PLAN-READY for #2114. G+H+H2 were not reviewed.

## Findings

1. **MAJOR — the 157-method partition is still neither total nor semantically disjoint.**

   The inventory count of 157 is correct, but applying v73’s written predicates leaves three methods unassigned: `StartFIBSync`, `NotifyLinkCycle`, and `SyncFabricState`. All are no-ops that touch neither Start-state nor `m.mu` state, and none appears in L/F’s explicit lists ([maps_fabric.go:71](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go:71), [plan.md:3535](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3535), [plan.md:3611](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3611)).

   L/F also overlap the earlier Start-state predicates unless “touches” is explicitly limited to direct access:

   - L-listed `LoadUserspaceShim` populates `m.maps`/`m.programs` ([loader.go:152](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:152), [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185)).
   - F-listed `ApplyConfig` delegates to `Compile`, which reaches map state ([apply.go:237](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:237), [compiler.go:316](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:316)).

   The proposed AST inventory can enforce one handwritten label per method. V73 specifies no semantic oracle capable of inferring escaping references, required side effects, indirect accesses, or missing-map outcomes. Therefore “misclassed method fails” and “disjointness asserted” remain prose ([plan.md:3543](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3543), [plan.md:4323](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4323)).

2. **MAJOR — category F contains a real Start-overlap race, invalidating the claimed RACE-3 L2 closure.**

   F explicitly includes the XDP entry-program trio, but they read/write plain `m.xdpEntryProg` without synchronization ([plan.md:3621](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3621), [loader.go:105](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:105), [loader.go:114](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:114)). `LoadUserspaceShim` writes it during Start before `loaded=true` ([loader.go:152](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:152)).

   There is a concrete RACE-3 schedule:

   - Boot publishes `d.dp`, then calls `Start` ([daemon_run_bringup.go:469](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:469), [daemon_run_bringup.go:493](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:493)).
   - A recovered rollback can concurrently invoke `d.dp.ApplyConfig` ([daemon_apply_dataplane.go:139](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_dataplane.go:139)).
   - Start’s load and userspace Compile both call the plain selector; Compile does so before its loaded check reaches the root compiler and before taking userspace `m.mu` ([manager.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go:370), [manager_compile.go:184](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:184)).

   That is an unordered write/write race even though both store the same string. The ordinary compile/status paths also race: status reads it at [maps_sync.go:481](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:481) and [maps_sync.go:947](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:947).

   The blocked-Start test covers classes 1–4, not F, and its barrier occurs around later map population ([plan.md:4313](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4313)). Synchronize/reclassify the trio or eliminate all post-construction writes, with dedicated overlap coverage.

3. **MAJOR — classifying both detaches as class 1 breaks preserved behavior.**

   V73 explicitly places `DetachXDP` and `DetachTC` in class 1, whose false path returns `ErrDataplaneNotArmed` ([plan.md:3615](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3615)). On a fresh unarmed manager, both currently return `nil` when the construction-created link maps are empty ([loader.go:639](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:639), [loader.go:1131](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1131)). `DetachTC` never touches `m.maps` or `m.programs` at all.

   This contradicts the claim that class-1 only changes map-not-found/fatal outcomes ([plan.md:4126](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4126)). The detaches need separate classifications/placement rules preserving their neutral no-link path.

4. **MINOR — the residual raw-state inventory remains incomplete.**

   The requested `XDPLinks` fold is accurate. But the same status helper also reads the exported `VlanSubInterfaces` Go map while `CompileUserspaceShim` writes it before acquiring userspace `m.mu` ([maps_sync.go:943](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:943), [maps_sync.go:950](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:950), [loader.go:201](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:201), [manager_compile.go:213](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:213)). That adjacent pre-existing Go-map race should join §10.

5. **MINOR — the class-3 test oracle contradicts M3’s preserved outcome.**

   The blocked-Start test says class-3 calls “succeed” ([plan.md:4322](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4322)). Mapless `ClearAllCounters` must perform its offset reset and then return `"interface_counters map not found"` ([maps_counters.go:246](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:246), [manager_counters_test.go:552](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_counters_test.go:552)). Lines 4327–4328 state the correct raw-helper expectation, so this is a test-wording correction.

6. **MINOR — the new exported error contract is undefined.**

   `ErrDataplaneNotArmed` is called “typed,” but the plan never specifies its declaration location, message, sentinel/type form, wrapping, or `errors.Is` contract ([plan.md:3550](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3550)).

## Fold verification and passed attacks

- **M1: folded.** The exact 22 class-2 methods have neutral missing-map outcomes, and v73 now requires the acquire-load before lookup. No `m.mu` is needed after observing true.
- **M3: folded in the production design.** The raw-helper rule preserves `ClearAllCounters`’ legacy later error; only the test wording needs correction.
- **m1/m2: literally folded.** `loader.go:534`, its reachability, raw `XDPLinks`, and the `loader.go:49` comment sweep are present.
- `Link`/`HA`/`Sessions`/`Telemetry` themselves only construct wrappers at [apply.go:217](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:217); they do not read `m.maps`.
- `IncrementGlobalCounter` touches only `userspaceCounterOffsets` under `m.mu` ([maps_counters.go:50](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:50)).
- The Attach arming-order invariant passes: `CompileConfig` rejects an unarmed manager before reaching attachment ([compiler.go:178](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:178)); the selector race above is the missed pre-arm operation.
- The class-2 overlap concept can distinguish gated-neutral from ungated-lucky-neutral: under `-race`, an ungated `m.maps` read conflicts with the population write regardless of the returned value. The test should explicitly drive all 22 entries, not merely representatives.

**Explicit answer: yes. Findings 1–3 are wholly inside PR-1 and block PLAN-READY for #2114.**

Codex session ID: 019fbefd-4133-7fd1-8964-99ad8ea1861c
Resume in Codex: codex resume 019fbefd-4133-7fd1-8964-99ad8ea1861c
