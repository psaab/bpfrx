# Codex adversarial plan-review — round 88 (plan v89 @ 14d74b3628dc)

Codex companion task-msbc0207-pjmnbd (session 019fc0d7-e584-75e1-acb3-3294774eedbe). Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the "complete 16-site" OPTIONAL inventory still false: its own citations enumerate 17, and the exhaustive audit is 132 reads = 91 required + 41 optional across 9 files, with 24 omitted sites class-assigned — class-3: maps_counters.go:181/:233, maps_nat.go:400; class-4: loader.go:1152/:1157; internal: loader.go:910/:928; seventeen class-2 — plus continuation coverage incomplete: ClearStaticNATEntries absent-v4→v6, setXDPAttachedFlag absent-vlan→physical :744-826, Compile absent-redirect_capable→continue — 2 MINORS: the promised §9 IsLoaded oracle did not exist in v89 and older summaries contradicted it; the partition preamble remained method-level singular-outcome). Also verified: the ClearNAT64Configs oracle is correct and discriminating; m2's operative gate placement fixed; the AttachXDP composition real but needs the pinned-link-reuse qualification (:536 skips the seed, still runs the defer). NOTE: this verdict ran against v89; its M1 headline + m2 headline were already folded in v90 (AGY b1/b2); the residuals (per-class assignment, continuation paths, preamble, AttachXDP qualification, limiting-summary cross-references) are folded in v91. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 1 major, 2 minors

Yes. Finding 1 is entirely within PR-1 and blocks `PLAN-READY` for #2114.

1. **MAJOR — the “complete 16-site” OPTIONAL inventory is still false, and continuation coverage remains incomplete.**

   The plan defines OPTIONAL broadly as an access “inside ANY class” that preserves its site-specific missing outcome ([plan.md:4959](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4959)), then claims a complete 13-if-ok + 3-nil-guard inventory ([plan.md:4968](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4968)).

   Its own citations enumerate **17**, not 16:

   - NAT: 4
   - stale: 7
   - session: 2
   - `loader.go:730`: 1
   - claimed nil guards: 3

   That is 14 + 3.

   The exhaustive audit remains 132 production registry reads: **91 required and 41 optional**. Optional reads occur in nine of the thirteen reader-bearing files:

   | File | Real optional | v89 names | Omitted |
   |---|---:|---:|---:|
   | `compiler.go` | 1 | 1 | 0 |
   | `loader.go` | 7 | 3 | 4 |
   | `maps_counters.go` | 2 | 0 | 2 |
   | `maps_nat.go` | 6 | 4 | 2 |
   | `maps_policy.go` | 1 | 0 | 1 |
   | `maps_screen.go` | 1 | 0 | 1 |
   | `maps_session.go` | 3 | 2 | 1 |
   | `maps_stale.go` | 19 | 7 | 12 |
   | `maps_stats.go` | 1 | 0 | 1 |
   | **Total** | **41** | **17** | **24** |

   Thus there are 24 omitted sites, not 25. They are not all class-2 neutral:

   - Class 3: [maps_counters.go:181](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:181), `:233`; [maps_nat.go:400](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:400).
   - Class 4: [loader.go:1152](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1152), `:1157`.
   - Internal/composed: [loader.go:910](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:910), `:928`.
   - Seventeen class-2 sites: `maps_nat.go:435`, `maps_policy.go:253`, `maps_screen.go:60`, `maps_session.go:612`, twelve additional `maps_stale.go` sites, and `maps_stats.go:72`.

   The terminology also fails against the cited code: [compiler.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353) does not “simply return” when nil; it skips redirect-map population and continues into attachment work at `:368+`. Conversely, [loader.go:700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700) is comma-ok plus an early return, not a nil lookup.

   The `ClearNAT64Configs` oracle itself is correct and discriminating: required `nat64_configs` at [maps_nat.go:319](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:319) → optional prefix at `:328` → required `SetNAT64Count(0)` at `:340`, implemented at `:309-314`. A nonzero key-0 seed is observable and an early return leaves it nonzero.

   For the methods named at [plan.md:5013](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5013), the same pattern works only if each fixture explicitly makes an earlier access absent and a later access present. But the list still omits known continuation paths:

   - `ClearStaticNATEntries`: absent v4 must continue to v6, [maps_nat.go:261](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:261) → `:274`.
   - `setXDPAttachedFlag`: absent `vlan_iface_map` must continue into physical-interface processing, [loader.go:730](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:730) → `:744-826`.
   - `Compile`: absent `redirect_capable` must continue past [compiler.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353).

   This is material because the plan concedes its AST canary cannot distinguish required from optional consumption ([plan.md:4997](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4997)).

2. **MINOR — the IsLoaded surface is correctly identified, but the promised §9 oracle does not exist and older summaries contradict it.**

   The chain is accurate:

   - [loader.go:456](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:456)
   - [legacy_dataplane.go:86](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/legacy_dataplane.go:86)
   - REST [health.go:104](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/api/health.go:104)
   - gRPC [server_show_status.go:19](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/grpcapi/server_show_status.go:19)

   But A3 claims “§9 teardown legs assert this directly” ([plan.md:3990](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3990)). Section 9 contains no Close-window `IsLoaded`, `DataplaneLoaded`, or status assertion. Its only Close-transition assertion proves registry preservation ([plan.md:4860](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4860)).

   Additionally, [§4.7](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4152), [§6](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4559), [§7](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4622), and [§8](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4655) still describe the Close-entry effect as limited to loaded-check admission, contradicting A3’s “NOT limited” correction.

3. **MINOR — m2’s operative gate placement is fixed, but the classification preamble remains method-level and ambiguous.**

   The important rules now correctly say class 1 contains at least one required access and gates at each required access ([plan.md:3717](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3717), [§5.1](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4234)). No normative first-access gate remains.

   However, the partition preamble still classifies by a method’s singular “missing-map outcome” ([plan.md:3683](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3683)). Mixed methods have both optional-neutral and required-error outcomes. It should use the same “contains at least one required access” definition as the operative bullet.

The AttachXDP composition is real but should be qualified: the full `:495 → :591 → deferred :700/:730` sequence occurs on successful fresh attachment. Pinned-link reuse returns at `loader.go:536`, skips the seed, and still executes the defer.

No G+H+H2 dependency leaked into PR-1. The blocker is entirely in the PR-1 A3 inventory/oracle contract.

Codex session ID: 019fc0d7-e584-75e1-acb3-3294774eedbe
Resume in Codex: codex resume 019fc0d7-e584-75e1-acb3-3294774eedbe
