# AGY adversarial plan-review — round 73 (plan v74 @ ffa0b2970)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-NEEDS-MAJOR (4 items: the trio deadlock; the swapXDPEntryProg :632 unprotected write; the omitted SwapToUserspaceXDPShimEntryProgram partition entry; the VlanSubInterfaces status-path fatal-crash residual-boundary objection). Detaches-in-G confirmed PASS. Raw output follows verbatim.

---

# Adversarial PLAN Review: #2114 (Round 73 — CONVERGENCE)

**Plan Doc**: [`docs/research/2114-nat-pool-alarm-dp-race/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md)  
**Revision**: DRAFT v74 @ `ffa0b2970`  
**Verdict Surface**: **PR-1 ONLY** (`d.dp` core + A1 + A3 gate + site conversion + canaries + sampler; G+H+H2 in `followup-seed.md` is out of scope).

---

## Verdict: `PLAN-NEEDS-MAJOR`

The PR-1 design in v74 **cannot ship as specified**. Fresh hostile analysis of the five verification items reveals **one guaranteed runtime deadlock**, **one unprotected concurrent write site**, **one unclassified exported method in the partition inventory**, and **an unprincipled residual boundary that leaves a fatal Go map panic on the status path**.

---

## Verification Findings

### 1. The v74 Partition Closure & Inventory Audit: `MAJOR`

- **Omitted Exported Method**: [`loader.go:604`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L604) exports `func (m *Manager) SwapToUserspaceXDPShimEntryProgram() error`. 
  - `plan.md` line 3536 claims a total inventory partition for `loader.go` (26 methods). While there are indeed 26 exported methods in `loader.go`, `SwapToUserspaceXDPShimEntryProgram` is **completely missing** from every classification category in §4 A1 and §4.8.
- **Direct-Access vs Delegation Collision**: `SwapToUserspaceXDPShimEntryProgram` delegates to internal [`swapXDPEntryProg`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L608), which directly reads Start-populated BPF map `m.programs["xdp_userspace_prog"]` ([`loader.go:609`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L609)), ranges `m.xdpLinks`, reads `m.VlanSubInterfaces`, and writes `m.xdpEntryProg`.
  - On an unarmed manager, `m.programs` is empty, so `SwapToUserspaceXDPShimEntryProgram` returns `fmt.Errorf("XDP program %q not found", ...)` instead of `ErrDataplaneNotArmed` (Class 1) or neutral nil (Class 2). Because the plan omitted this method, its behavior under pre-arm and Start-overlap is completely unspecified.

---

### 2. `xdpEntryProg` Trio Synchronization: `MAJOR` (Deadlock & Data Race)

- **Guaranteed Runtime Deadlock**: In `plan.md` line 3683, the plan states:
  > *"all three accessors lock [under `m.mu`]"* (`XDPEntryProgram`, `SelectUserspaceXDPShimEntryProgram`, `UsingUserspaceXDPShimEntryProgram`).
  
  However, in [`loader.go:120-122`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L120-L122):
  ```go
  func (m *Manager) UsingUserspaceXDPShimEntryProgram() bool {
      return m.XDPEntryProgram() == userspaceShimEntryProg
  }
  ```
  If `UsingUserspaceXDPShimEntryProgram` acquires `m.mu.Lock()` and then invokes `m.XDPEntryProgram()` (which also calls `m.mu.Lock()`), Go's non-reentrant `sync.Mutex` will **deadlock immediately**. The plan failed to specify an un-exported `xdpEntryProgramLocked()` helper or clarify that `UsingUserspaceXDPShimEntryProgram` must delegate without acquiring `m.mu`.

- **Unprotected Concurrent Write Site**: The plan claims that locking the trio accessors fully synchronizes `m.xdpEntryProg`. But internal helper `swapXDPEntryProg` at [`loader.go:632`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L632) executes a direct plain write:
  ```go
  m.xdpEntryProg = name
  ```
  `swapXDPEntryProg` is invoked during periodic userspace map synchronization ([`maps_sync.go:490,498,505,517,540`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L490)). Because [`loader.go:632`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L632) does **not** acquire `m.mu`, concurrent calls to `SwapToUserspaceXDPShimEntryProgram` and the status-path readers (`XDPEntryProgram` / `UsingUserspaceXDPShimEntryProgram`) will still **race on `m.xdpEntryProg`**.

---

### 3. Detaches in Category G: `CONFIRMED PASS`

- [`DetachXDP`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L639) and [`DetachTC`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1131) look up construction-allocated link maps (`m.xdpLinks` / `m.tcLinks`). On an unarmed manager, these maps are empty, so the methods early-return `nil`.
- Categorizing detaches under Category G correctly preserves this neutral zero-op `nil` return path. Placing them in Class 1 would inject an erroneous `ErrDataplaneNotArmed` error into cleanup and teardown routines.

---

### 4. Residuals (§10) vs. L2 Closure Inconsistency: `MAJOR`

- In [`maps_sync.go:942-958`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L942-L958):
  ```go
  func (m *Manager) entryProgramsLocked() map[int]string {
      links := m.bpfShim.XDPLinks()
      if len(links) == 0 { return nil }
      progName := m.bpfShim.XDPEntryProgram()       // Line 947: read under A3
      result := make(map[int]string, len(links))
      for ifindex := range links {
          if m.bpfShim.VlanSubInterfaces[ifindex] {  // Line 950: ungated Go map read!
              continue
          }
          result[ifindex] = progName
      }
      return result
  }
  ```
- **The Inconsistency**: v74 folded `XDPEntryProgram()` into A3 to protect Line 947 from racing against `Compile`. But three lines later (Line 950), `entryProgramsLocked` reads Go map `m.bpfShim.VlanSubInterfaces[ifindex]`. Concurrently, `CompileUserspaceShim` ([`loader.go:203`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L203)) mutates `m.VlanSubInterfaces[ifidx] = true` before taking the userspace `m.mu`.
- In Go, a concurrent read and write to a `map[int]bool` causes an unrecoverable **fatal process crash** (`fatal error: concurrent map read and map write`).
- Folding `xdpEntryProg` into A3 while relegating `VlanSubInterfaces` to §10 Residuals is unprincipled. Both are status-path reads of plain `dataplane.Manager` fields called within the exact same method (`entryProgramsLocked`). Leaving `VlanSubInterfaces` as a residual leaves an active fatal map crash on the 1 Hz status path while claiming "L2 closure" for RACE-3.

---

## Required Plan Fixes to Reach PLAN-READY

1. **Fix `xdpEntryProg` Lock Shape & Fourth Write Site**:
   - Define an internal `xdpEntryProgramLocked()` helper.
   - Have `XDPEntryProgram()` lock `m.mu` and return `xdpEntryProgramLocked()`.
   - Have `UsingUserspaceXDPShimEntryProgram()` lock `m.mu` and compare `xdpEntryProgramLocked() == userspaceShimEntryProg` (eliminating mutex re-entrancy).
   - Wrap the write at [`loader.go:632`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L632) in `swapXDPEntryProg` under `m.mu`.
2. **Assign `SwapToUserspaceXDPShimEntryProgram`**:
   - Explicitly add [`SwapToUserspaceXDPShimEntryProgram`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L604) to the partition inventory in §4 A1 / §4.8 (Class 1 or Category G based on pre-arm error semantics).
3. **Synchronize `VlanSubInterfaces`**:
   - Protect `m.VlanSubInterfaces` reads and writes under `m.mu` (or a helper method) alongside `xdpEntryProg` to eliminate the status-path `fatal error: concurrent map read and map write`.

---

## Summary Statement

**PR-1 blocks `PLAN-READY` for #2114.** The plan cannot be declared ready until the `UsingUserspaceXDPShimEntryProgram` deadlock, the missing `swapXDPEntryProg` lock, the omitted `SwapToUserspaceXDPShimEntryProgram` partition entry, and the `VlanSubInterfaces` status-path panic are resolved in v75.
