# Codex hostile plan-review — round 70 (plan v71 @ 3f4d46d39)

Task: task-msarlue1-3rayvw (session 019fbecd-31b7-7de2-a68c-2317cd42f125).
Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the four-class partition still incomplete: error-signature no-ops and fallible hybrids with required pre-error side effects fit no class — 4 MINOR: gate-placement validation precedence, class-4 corrections, exact-schedule residual text, comment-sweep additions). Raw companion output follows verbatim.

---

Verdict: **PLAN-NEEDS-MAJOR (1M/4m)** at `3f4d46d39`.

Yes—PR-1 still contains a blocker to PLAN-READY.

## Findings

1. **MAJOR — A3’s four-class partition is still incomplete and cannot preserve existing behavior as written.**

   The plan defines class 1 by error signature/map requirement, class 2 by non-error signature, and class 3 as three named hybrids ([plan.md:3513](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3513)). Real methods fit none of those classes:

   - `ClearZoneCounters() error` clears meaningful Go-side offsets and then succeeds if the BPF map is absent ([maps_counters.go:227-235](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:227)). Its userspace contract explicitly requires the pre-Start/mapless clear ([zonecounters.go:7-18](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/zonecounters.go:7)). Class 1 breaks that behavior; leaving it out of class 3 leaves its `m.maps` lookup racing Start.
   - `ClearAllCounters()` is a fallible hybrid: it must reset global offsets before its later missing-interface error ([maps_counters.go:245-262](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:245)). The existing mapless test tolerates only that later error and requires the offsets to be zero ([manager_counters_test.go:509-565](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_counters_test.go:509)). A class-1 gate at entry skips the required side effect.
   - Error-returning intentional no-ops also fall outside class 2: `ClearSessionCounts` ([maps_screen.go:57-75](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:57)), `ClearStaticNATEntries` ([maps_nat.go:258-286](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:258)), and `UpdatePolicyScheduleState`, whose nil-on-missing-map behavior prevents scheduler self-heal spin ([maps_policy.go:244-255](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_policy.go:244)).

   This falsifies the claims that all pre-arm successes are covered and preserved ([plan.md:3559](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3559), [plan.md:3999](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3999)). The partition needs explicit classes for error-signature neutral/no-op methods and fallible hybrids with required pre-error side effects.

2. **MINOR — class-1 “gate FIRST” breaks pinned validation precedence.**

   `AddTxPort` validates the ifindex before accessing `m.maps` ([loader.go:982-991](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:982)). Its tests deliberately use an unarmed manager and require the capacity/remediation error before any map access ([constants_test.go:187-220](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/constants_test.go:187)). Define the rule as “gate before the first Start-state access,” while preserving inventoried pure validation.

3. **MINOR — class 4 includes construction-state APIs and underspecifies a two-result method.**

   `GetPersistentNAT` is allocated by `New()`, not Start ([loader.go:89-100](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:89)), and has its own synchronization ([persistent_nat.go:51-65](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/persistent_nat.go:51)). Gating it to nil breaks an existing pre-Start test ([server_show_nat_test.go:15-20](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/grpcapi/server_show_nat_test.go:15)). It belongs with ungated construction-time values.

   Likewise, `XDPLinks`/`TCLinks` are created by `New()` and continue changing after `loaded=true`, so class 4’s “fully constructed” rationale is false. `NewEventSource()` returns `(EventSource, error)`, but the plan specifies only “nil”; master currently returns nil plus an error ([loader.go:1161-1169](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1161)).

4. **MINOR — the M2 invariant is substantively repaired, but the shutdown text is not exact.**

   - The old bullet still says `Store(false)` occurs at `:1217`/Teardown ([plan.md:3509-3512](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3509)), contradicting the correct Close-entry contract later.
   - The residual says a timed-out apply can continue directly into concurrent Close ([plan.md:4235-4243](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4235)). Shutdown subsequently performs an unbounded `applySem` acquisition ([daemon_scheduler.go:170-183](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_scheduler.go:170)), which waits out that same holder. The surviving residual must be described as late/already-new admission after the semaphore is released.
   - `loader.go:1124` is a TC write, but the userspace shim path invokes only `AttachXDP` ([loader.go:211-253](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:211)). The live path also includes fresh XDP insertion at `:575` and detach deletion at `:661`.

   The residual is still pre-existing and not worsened. Close-entry `Store(false)` narrows new admission; the population mutex affects `m.maps`, not link maps. Consequently, the broad statement that every untouched hazard remains “exactly as exposed” is false ([plan.md:3668-3669](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3668)).

5. **MINOR — the source-comment sweep remains incomplete.**

   The three-site list at [plan.md:3902-3905](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3902) misses, for example:

   - direct-`d.dp` assertion wording at [daemon_ha_sync.go:1117-1124](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go:1117);
   - plain-race wording at [bootstrap.go:324-330](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:324);
   - direct sampler wording at [daemon_natpoolalarm.go:98-110](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_natpoolalarm.go:98).

## Folds and fresh attacks that pass

- The class-3 mutex mechanism is sound if implemented exactly as scoped lookup locking. Existing offset helpers release root `m.mu` before lookup, and Start’s proposed critical section contains only assignments. Locking an entire hybrid method would recurse; the plan does not require that.
- Named class-2 outcomes match master: `IsLoaded=false`, `SessionCount=(0,0)`, and `GetMapStats=nil/empty`.
- The synthetic per-manager loader seam, entered/resume barriers, real overlap, and AST-backed matrix are implementable and deterministic. The matrix will, however, expose Finding 1.
- The userspace HA path does not bypass the root gate: adapter HA → userspace controller → `UpdateRGActive` → `m.bpfShim.UpdateRGActive` ([manager_ha.go:657-666](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_ha.go:657)).
- The corrected pending-owner rejection reasons hold. A complete backend gate protects direct and future backend callers; pending-owner protects only cell readers and adds lifecycle state. It has no inherent correctness advantage once A3 is repaired.
- The forwarding-status nil-receiver, `NoDataplane`, empty-cell→userspace, and backend-transition legs are sufficient.
- The fwdstatus file-touch inventory itself is complete.

**Explicit answer:** yes, Finding 1 is wholly inside PR-1 and blocks PLAN-READY for #2114.

Codex session ID: 019fbecd-31b7-7de2-a68c-2317cd42f125
Resume in Codex: codex resume 019fbecd-31b7-7de2-a68c-2317cd42f125
