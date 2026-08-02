# Codex adversarial plan-review — round 86 (plan v87 @ 66256246946b)

Codex companion task-msbacdl4-xntfjx (session 019fc0ad-68c3-7cf3-9828-99f8db9a6552). Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the class-1 absent cell is wrong for methods containing both required and optional registry accesses: SetNAT64Config errors on absent nat64_configs (maps_nat.go:290) but silently skips absent nat64_prefix_map (:298); ClearNAT64Configs the same (:318); Compile silently skips absent redirect_capable (compiler.go:353); AttachXDP/AddTxPort reach optional interface_counters work (loader.go:590) — one method label plus one `present` dimension cannot encode master — 2 MINORS: a fifth singular-helper site in the canary-allowlist sentence; the preservation/lifecycle summaries overclaim — NewEventSource's fresh typed error is a second intentional change and the Close-entry loaded=false move is an admitted timing change). Verified passes: the fold-verification table (4 classes × 3 cells against UpdateFabricFwd/ClearSessionCounts/ClearGlobalCounters/NewEventSource), the two-state predicate consistency, the four r85 pluralizations, the §9 armed-only scoping, the swap fixture retention fix, class-3 disjointness from the carve-out, no G+H+H2 leakage. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 1 major, 2 minors

Yes. Finding 1 is within PR-1 and blocks `PLAN-READY` for #2114.

1. **MAJOR — the class-1 absent cell is wrong for methods containing both required and optional registry accesses.**

   Classification is method-level: each exported method receives one class, and class 1 is defined by an error missing-map outcome ([plan.md:3613](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3613), [plan.md:3626](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3626)). The matrix consequently says every class-1 armed/retained absence produces master’s missing-map error ([plan.md:4860](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4860)).

   Real class-1 methods have mixed outcomes:

   - `SetNAT64Config` errors when required `nat64_configs` is absent ([maps_nat.go:290](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:290)), but silently skips an absent secondary `nat64_prefix_map` and returns nil ([maps_nat.go:298](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:298)).
   - `ClearNAT64Configs` has the same required/optional split ([maps_nat.go:318](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:318)).
   - `Manager.Compile`, expressly included in the classified loaded-check surface, silently skips an absent `redirect_capable` map ([compiler.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:353)).
   - `AttachXDP`/`AddTxPort` also reach optional `interface_counters` work that silently returns when absent ([loader.go:590](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:590)).

   Therefore one method label plus one `present` dimension cannot encode master. Applying the row to secondary lookups changes success into error; retaining the original comma-ok behavior violates the normative table.

   The §9 oracle does not close this: its generic retained-absent fixture can stop at the first required lookup and never exercise required-present plus optional-absent ([plan.md:4678](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4678), [plan.md:4779](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4779)). The design needs per-access required/optional semantics—or an explicit mixed-site inventory—with partial-registry tests.

2. **MINOR — a fifth singular-helper contract remains.**

   The “EXACTLY-NAMED allowlist” still names “the registry helper and `publishShimRegistryLocked`” ([plan.md:4836](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4836)). That contradicts the two signatures immediately below and the later correct “two helpers + publisher” wording ([plan.md:4842](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4842), [plan.md:4873](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4873)).

3. **MINOR — preservation/lifecycle summaries still overclaim.**

   The plan calls class-1 fresh gating the “only intentional behavior change” ([plan.md:3927](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3927), [plan.md:4457](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4457)), but class-4 `NewEventSource` also intentionally changes fresh behavior from `"events map not loaded"` to `ErrDataplaneNotArmed` ([plan.md:3788](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3788), [loader.go:1161](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1161)).

   Likewise, “Post-arm behavior bit-identical” and “PR-1 itself adds no lifecycle change” ([plan.md:4473](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4473), [plan.md:4563](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4563)) conflict with A3’s admitted move of `loaded=false` from `Close` exit to entry, which intentionally rejects the loaded-check set earlier than master ([plan.md:3905](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3905), [loader.go:1206](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1206)).

### Fold verification

| Class | Representative | Fresh | Armed/retained absent | Present |
|---|---|---|---|---|
| 1 | `UpdateFabricFwd` ([source](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go:18)) | Intended typed replacement | Legacy missing-map error | Calls `Update` |
| 2 | `ClearSessionCounts` ([source](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:58)) | Nil | Missing entry skipped | Iterates/deletes |
| 3 | `ClearGlobalCounters` ([source](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:176)) | Clears Go offsets, nil | Same pinned behavior | Also zeroes BPF map |
| 4 | `NewEventSource` ([source](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1161)) | Intended typed error | Legacy missing-map error | Constructs reader; present-nil keeps existing nil check |

The remaining requested folds pass:

- The two-state predicate, retained-proceed qualification, present-but-nil handling, and fresh-program-only rule are mutually consistent.
- No residual partial “else master’s missing-map outcome” phrasing remains.
- The four requested pluralizations landed; Finding 2 is the missed fifth site.
- §9 now correctly scopes the nonempty registry to an armed Manager’s Close/Teardown; no residual unconditional claim found.
- The swap fixture’s additional `m.maps` seed correctly makes it retained and reaches the intended write.
- Class 3 is disjoint from the `AttachXDP`/`AttachTC`/`CompileConfig` loaded-check carve-out.
- No G+H+H2 dependency leaked into the PR-1 verdict surface.

Reviewed at exact HEAD `66256246946b87f5222f27160f5bcba30a51d979`; no files changed.

Codex session ID: 019fc0ad-68c3-7cf3-9828-99f8db9a6552
Resume in Codex: codex resume 019fc0ad-68c3-7cf3-9828-99f8db9a6552
