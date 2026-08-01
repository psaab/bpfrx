# Codex hostile plan-review — round 71 (plan v72 @ f04a5eca8)

Task: task-msasm6es-7vlbqg (session 019fbee7-105a-7a20-a546-ba8618c1cdb9).
Verdict: PLAN-NEEDS-MAJOR (3 MAJOR — class-2 specified outcomes but not synchronization; the partition fails the complete 157-method inventory (lifecycle/facade/Go-state categories + precedence missing); class-3 nested-call composition breaks the pinned legacy error text — 2 MINOR: residual writer inventory + XDPLinks hazard, m.mu comment sweep). Raw companion output follows verbatim.

---

Verdict: **PLAN-NEEDS-MAJOR (3 major, 2 minor)** at `f04a5eca8`.

Yes—PR-1 still contains blockers to PLAN-READY for #2114. G+H+H2 were not reviewed.

## Findings

1. **MAJOR — class 2 specifies outcomes but not synchronization, leaving the Start race open.**

   Unlike classes 1/4, class 2 never requires `loaded.Load()` before Start-state access; unlike class 3, it does not require `m.mu` ([plan.md:3539](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3539)). Twenty-two best-fit class-2 methods read `m.maps`, including:

   - `ClearSessionCounts` ([maps_screen.go:59](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:59))
   - `ClearStaticNATEntries` ([maps_nat.go:261](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:261))
   - `UpdatePolicyScheduleState` ([maps_policy.go:253](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_policy.go:253))
   - `SessionCount` ([maps_session.go:326](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:326))
   - `GetMapStats` ([maps_stats.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go:69))
   - both seeders and all fifteen `maps_stale.go` methods.

   Leaving these implementations unchanged preserves their ordinary empty-manager outcome while still racing Start’s writes at [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185).

   The test plan repeats the hole: `BlockedStart` overlaps classes 1/4 and class 3, but omits class 2 ([plan.md:4251](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4251)). A nonconcurrent pre-arm matrix cannot distinguish a correct neutral gate from today’s ungated lookup.

   Required fold: every Start-state-touching class-2 method must acquire-load `loaded` before its first access, return its exact neutral value on false, and participate in the blocked-Start overlap test. `ClearStaticNATEntries` should not hold `m.mu` across iteration; with the class-2 gate, it performs no lookup until population is complete.

2. **MAJOR — the claimed total, exclusive partition fails the complete 157-method inventory.**

   Inventory counts were: `apply.go` 8, `compiler.go` 1, `loader.go` 26, counters 11, fabric 8, filter 10, flow 2, mirror 2, NAT 30, policy 17, screen 8, session 18, stale 15, stats 1: **157 total**.

   Even under the most charitable classification, 14 fit no written class:

   `Start`, `Link`, `HA`, `Sessions`, `Telemetry`, `LastApplyResult`, `XDPEntryProgram`, `SelectUserspaceXDPShimEntryProgram`, `UsingUserspaceXDPShimEntryProgram`, `Load`, `LoadUserspaceShim`, `LastCompileResult`, `Close`, and `Teardown`.

   Lifecycle methods cannot be classed by a pre-arm rejection contract: `LoadUserspaceShim`/`Start` must execute while unarmed, while `Teardown` must run cleanup ([loader.go:1223](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1223)).

   Eleven more “offset helpers” are not class-3 hybrids as defined: `IncrementGlobalCounter`, the three offset readers, three setters, and four clear helpers across [maps_counters.go:50](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:50), [maps_nat.go:365](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:365), and [maps_screen.go:88](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:88). Several are readers with no side effects and can return non-neutral populated values on an unarmed manager, as tests require ([zone_flood_counters_hide_test.go:61](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/zone_flood_counters_hide_test.go:61)).

   Exclusivity also fails literally:

   - `IsLoaded` is class 2 ([plan.md:3542](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3542)) and in the ungated set ([plan.md:3585](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3585)).
   - `Map`/`Program` satisfy the broad neutral-nil predicate and class 4.
   - `NewEventSource` satisfies fallible/map-required class 1 and class 4.
   - The named `Mode()` is not a root `dataplane.Manager` method at all; it belongs to `userspace.Manager` ([manager.go:437](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go:437)).

   An AST name manifest can enforce that a label exists, but cannot prove that these semantic predicates are disjoint or correctly selected. The design needs explicit lifecycle/facade and ungated-Go-state categories plus precedence between outcome and escaping-reference properties.

3. **MAJOR — `ClearAllCounters`’ class-3 contract does not compose with its nested class-1 call.**

   `ClearAllCounters` first resets global offsets, then calls `ClearInterfaceCounters` ([maps_counters.go:246](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:246)). Under v72, that nested class-1 method must gate before its map lookup and return `ErrDataplaneNotArmed`, replacing master’s `"interface_counters map not found"`.

   The existing mapless test tolerates only the legacy later error while requiring the global reset ([manager_counters_test.go:552](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_counters_test.go:552)). This contradicts the plan’s class-3 preservation promise ([plan.md:3557](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3557)) and its claim that only class-1 behavior changes ([plan.md:4063](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4063)).

   The plan must choose explicitly: preserve the legacy later error through an internal raw helper/outer false-path, or declare and test the new typed error. Per-method classification alone cannot catch nested-call composition.

4. **MINOR — the link-map residual/caller audit is still incomplete.**

   The corrected schedule is valid: `stopPolicySchedulerLoop`’s unbounded acquisition waits out the incumbent holder ([daemon_scheduler.go:170](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_scheduler.go:170)); a late confirm rollback can acquire afterward using `context.Background()` ([daemon_apply_commit.go:629](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:629)).

   But the writer inventory omits pinned-link reuse insertion at [loader.go:534](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:534). It remains reachable because userspace Compile ignores pin-removal errors before calling `CompileUserspaceShim` ([manager_compile.go:168](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:168)). The residual should name `:534`, fresh insertion `:575`, and deletion `:661`.

   Separately, “daemon callers are applySem-serialized” is not a complete safety rationale for raw `XDPLinks`: the 1 Hz status path ranges it at [maps_sync.go:943](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:943), while Compile can mutate it before taking userspace `m.mu`. This is pre-existing and not worsened by PR-1, so ungating remains correct for the Start race, but the hazard should be stated honestly.

5. **MINOR — the comment sweep misses the changed `m.mu` contract.**

   [loader.go:49](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:49) says `m.mu` protects only offset state. V72 makes it also protect `m.maps`/`m.programs` population and scoped lookups; §5.5 should explicitly update that comment.

## Attacks that passed

- `AddTxPort`’s pure validation-before-gate rule is correct and preserves its pinned error precedence.
- The three named error-signature no-ops do not hide a daemon-required pre-arm failure. `ClearSessionCounts`/`ClearStaticNATEntries` have no production invocation; `UpdatePolicyScheduleState` is deliberately nil on the retired root path to avoid retry spin.
- Scoped class-3 locking is sound: lock only the Go-map lookup, copy the `*ebpf.Map`, then release before BPF iteration/update. No lock should span batch operations.
- Start’s proposed critical section contains only the assignment loops at [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185); collection construction and pinning stay outside. It should not materially stall the 1 Hz poll or any packet hot path.
- `Map`/`Program` nil gating, `NewEventSource`’s `(nil, ErrDataplaneNotArmed)`, and ungated `GetPersistentNAT` are behaviorally correct once the partition predicates are made disjoint.

**Explicit answer: yes. Findings 1–3 are wholly inside PR-1 and block PLAN-READY for #2114.**

Codex session ID: 019fbee7-105a-7a20-a546-ba8618c1cdb9
Resume in Codex: codex resume 019fbee7-105a-7a20-a546-ba8618c1cdb9
