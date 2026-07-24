# Adversarial Architecture Review (ROUND 4) — xpf Issue #2114 (v4 Plan)

---

## 1. Executive Summary

This is the Round 4 adversarial architecture review of the **REVISED v4 plan** (`docs/research/2114-nat-pool-alarm-dp-race/plan.md` at commit `e9ac48db1`).

All findings from prior review rounds (AGY r3, Codex r3, Claude SMR r3) have been systematically addressed and correctly folded into the v4 plan. In particular, the real-sampler test barrier design has been fixed to ensure zero happens-before edges between the conflicting reader and writer accesses, the reference count and per-row classifications have been verified against the codebase, the pre-publication RACE-1 scope has been strictly validated, and the typed-nil reflection guard now covers all nillable kinds in Go.

---

## 2. Detailed Verification Findings

### Job (A): Typed-Nil Kind-Gate Fold Verification
* **Status**: **FOLDED**
* **Evidence**:
  * In Section 4 (Option A1, lines 181–189 of [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L181-L189)): `setDataplane` uses `switch v.Kind()` matching `reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer` before invoking `v.IsNil()`. Non-nillable value types fall through safely without panicking.
  * In Section 7 (Rule 7, lines 478–481 of [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L478-L481)): Explicit invariant requiring typed-nil checks to cover all nillable kinds without panicking on value-type implementations.
  * In Section 9 (Test Plan, lines 510–513 of [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L510-L513)): `TestDataplaneCell_TypedNilAndValueShapes` explicitly includes a typed-nil named-slice fake (modelling `wire_uint8list.go:32` precedent) in addition to typed-nil pointers and value-receiver fakes.

---

### Job (B): Verification of Codex r3 Folds (v4 Delta)

#### B1. Real-Sampler Barrier Design (Codex r3 M1)
* **Status**: **FOLDED / VERIFIED**
* **Happens-Before Analysis**:
  * In [sampler.go:93](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go#L93), `s.sample()` invokes `s.proc.ReadSelfStat()` **before** evaluating `s.dp` (which with the narrowed adapter invokes `a.daemon.dataplane()`).
  * In `TestBootstrapExit_RealSamplerOverlap` (Section 9, lines 527–553 of [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L527-L553)):
    1. The reader side gates inside fake `ProcReader.ReadSelfStat` (signalling `readerEntered` and blocking on `<-release`), which executes prior to the `d.dp` load.
    2. `fwdSampler.Start(ctx)` runs on its own goroutine (handling `Start`'s initial synchronous call to `sample()`).
    3. The writer side gates inside fake `dp.Start()` (signalling `writerEntered` and blocking on `<-release`), which executes prior to `armBootstrapExitDataplane`'s `d.setDataplane(nil)` write.
    4. The test goroutine receives both signals and calls `close(release)`.
  * **Result**: Unblocking from `close(release)` happens-before both the reader's `d.dp` load and the writer's `d.dp` store. **No happens-before edge exists between the reader's load and the writer's store.** 
  * On the pre-fix plain field, this will deterministically trigger Go's `-race` detector. On the atomic cell, it is race-clean.
  * Teardown correctly handles `Sampler` having no join handle by calling `cancel(ctx)` and quiesce-polling the fake `ReadSelfStat` counter.

#### B2. Reference Count & Classification Audit (Codex r3 M2)
* **Status**: **FOLDED / VERIFIED**
* **Evidence**:
  * Grep search across `pkg/daemon/*.go` (excluding `_test.go`) confirms exactly **134 executable references** (5 writers + 129 readers).
  * Section 5.4 audit table ([plan.md:360-412](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L360-L412)) accurately reflects all per-row classifications:
    * Dead adapter methods (`daemon_forwarding_status.go:21,24,36,39,97,100`) are explicitly marked as deleted by the structural narrowing.
    * `daemon_run_servers.go:255,256` classified as `BOOT-SYNC` (API construction probes before HTTP serving).
    * `daemon_natpoolalarm.go:101` classified as `APPLY/BOOT-SYNC`.
    * `daemon_run_shutdown.go:161,167,173` classified as `CONCURRENT / unreachable via exclusion (uniformity)` vs `:214-229` as `CONCURRENT / RACE-2`.
    * `daemon_system.go:41` and `daemon.go:1012` classified as `APPLY/BOOT-SYNC`.

#### B3. RACE-1 Scope Analysis & Verification (Codex r3 M3)
* **Status**: **FOLDED / VERIFIED**
* **Codebase Verification**:
  * In [daemon_run_bringup.go:120-243](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L120-L243): `initManagers` constructs managers. The **only** goroutine launched inside `initManagers` is `go d.watchClusterEvents(d.daemonCtx)` at line 203. (`ipmon.Start()` at line 159 only starts netlink monitoring without touching `d.dp`).
  * `setupDataplaneAndInitialConfig()` is called right after `initManagers` and executes the publication assignment `d.setDataplane(dp)` at line 469.
  * All other background goroutines (conntrack GC, event reader, userspace event stream, NAT pool alarm sampler, cluster comms) are spawned in Phase 5 of `Run()` ([daemon_run.go:209-400](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L209-L400)), which runs **after** `setupDataplaneAndInitialConfig()` returns.
  * Because `go` goroutine creation establishes a happens-before relationship, all Phase 5 background readers have a strict happens-before edge with the boot publication assignment.
  * Therefore, `watchClusterEvents` (`daemon_ha.go:297,299,337,348,362,367`) is indeed the **sole pre-publication reader chain** subject to RACE-1.

#### B4. Option D Restatement & Comment Sweep (Codex r3 m3)
* **Status**: **FOLDED / VERIFIED**
* **Evidence**:
  * Option D ([plan.md:276-291](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L276-L291)) fairly acknowledges its advantages (clean representation of never-constructed vs cleared state; identity retention for post-clear introspection) while detailing its real trade-offs.
  * The comment sweep list ([plan.md:413-433](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L413-L433)) was expanded to cover [daemon.go:901](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon.go#L901), [bootstrap.go:276](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go#L276), [bootstrap.go:303](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go#L303), and [cluster_topology_preflight.go:117](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/cluster_topology_preflight.go#L117) (updating its stale citation of `daemon_run.go:1868` to `daemon_run_bringup.go:164`).

---

### Job (C): Fresh Attack on the v4 Delta

No new architectural gaps or edge cases were discovered in the v4 delta.

1. **Adapter Interface Simplification**: The structural narrowing of the daemon forwarding-status adapter (`forwardingStatusDaemonDataPlane`) to implement `fwdstatus.CachedStatusProvider` eliminates the unnecessary `IsLoaded()`, `GetMapStats()`, and `Status()` methods from the daemon adapter. This guarantees at compile-time that the daemon's forwarding-status adapter cannot be accidentally passed into `fwdstatus.Build()`.
2. **Canary & Self-Test Discipline**: Retaining and expanding the AST canary (`pkg/daemon/daemon_dp_canary_test.go`) ensures no raw `dpCell` access bypasses the `dataplane()` / `setDataplane()` accessors in future code edits. Both-direction canary self-testing guarantees that regressions in the canary itself will be caught immediately.
3. **Safety & Completeness**: The compiler enforcement via field retyping (`dp` -> `dpCell`) guarantees 100% conversion coverage across the 134 production and ~110 test sites.

---

## 3. Final Verdict

The plan is complete, rigorous, and fully ready for implementation.

VERDICT: PLAN-READY
