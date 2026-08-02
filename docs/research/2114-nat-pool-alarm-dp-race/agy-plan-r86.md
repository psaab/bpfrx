# AGY adversarial plan-review — round 86 (plan v87 @ 66256246946b)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY. Raw output follows verbatim.

---

# Adversarial PLAN Review Verdict for #2114 (Round 86 — CONVERGENCE)

**Target Document**: [`docs/research/2114-nat-pool-alarm-dp-race/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md) (DRAFT v87 @ `66256246946b`)  
**Scope**: **PR-1 ONLY** (Synchronized `d.dp` core: work items A1 + A3 + sampler narrowing + site conversion + canary suite). Follow-up unit (G+H+H2 in `followup-seed.md`) is out of scope per §4.7.

---

### **FINAL VERDICT**: `PLAN-READY`

**Nothing in PR-1 blocks PLAN-READY for #2114.**

---

### Hostile Verification Results

#### 1. THE TOTAL MATRIX Walk
Wrote and verified every reachable $(\text{class} \times \text{state} \times \text{presence})$ cell in the v87 outcome table ([`plan.md:4858-4863`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4858-L4863)) against real master code paths:

| Class & Representative Method | State $\times$ Presence Cell | Master Code Path & v87 Behavior | Behavior Changed vs Master? |
| :--- | :--- | :--- | :--- |
| **Class 1**<br>[`swapXDPEntryProg`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L608-L635) | **Fresh** | `lookupProgramLocked` returns `(nil, false, fresh)`. Gate fires `ErrDataplaneNotArmed`. | **Yes (Intended A3 change)**: Replaces fatal race / missing-map error with `ErrDataplaneNotArmed`. |
| | **Armed/Retained + Absent** | `lookupProgramLocked` returns `(nil, false, armed/retained)`. `ok == false` branch executes: returns `fmt.Errorf("XDP program %q not found", name)`. | **No**: Preserves master's missing-map error. |
| | **Armed/Retained + Present** | `lookupProgramLocked` returns `(prog, true, armed/retained)`. Program swap executes: writes `:632` `m.xdpEntryProg = name`. | **No**: Proceeds with program handle. |
| **Class 2**<br>[`SessionCount`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go#L326-L340) | **Fresh** | `lookupMapLocked` returns `(nil, false, fresh)`. Comma-ok fails (`ok == false`), loop skipped. | **No**: Returns `(0, 0)` (neutral). |
| | **Armed/Retained + Absent** | `lookupMapLocked` returns `(nil, false, armed/retained)`. `ok == false`, loop skipped. | **No**: Returns `(0, 0)` (neutral). |
| | **Armed/Retained + Present** | `lookupMapLocked` returns `(sm, true, armed/retained)`. Iterates sessions, returns `(v4, v6)`. | **No**: Proceeds with present map. |
| **Class 2**<br>[`ClearSessionCounts`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go#L57-L76) | **Fresh** | `lookupMapLocked` returns `(nil, false, fresh)`. `ok == false` triggers `continue`. | **No**: Returns `nil` error (no-op). |
| | **Armed/Retained + Absent** | `lookupMapLocked` returns `(nil, false, armed/retained)`. `ok == false` triggers `continue`. | **No**: Returns `nil` error (no-op). |
| | **Armed/Retained + Present** | `lookupMapLocked` returns `(zm, true, armed/retained)`. Deletes entries, returns `nil`. | **No**: Mutates present maps. |
| **Class 2**<br>[`GetMapStats`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go#L68-L101) | **Fresh** / **Absent** | `lookupMapLocked` returns `present == false`. `if !ok \|\| bm == nil` continues. | **No**: Returns `[]MapStats` (empty/nil). |
| | **Armed/Retained + Present** | `lookupMapLocked` returns `(bm, true, armed/retained)`. Reports map stats + counts. | **No**: Reports present map stats. |
| **Class 3**<br>[`ClearAllCounters`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L246-L263) | **Any State** (Fresh / Retained / Armed) $\times$ (Absent / Present) | Go-side offsets cleared under `m.mu` (`ClearGlobalCounters`, `ClearZoneCounters`). Composes internal raw helpers (`clearInterfaceCountersRaw`). | **No**: Preserves pinned legacy side effects and error text ("interface_counters map not found"). |
| **Class 4**<br>[`Map`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1151-L1153) / [`Program`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1156-L1158) | **Fresh** / **Absent** | `lookupMapLocked`/`lookupProgramLocked` returns `present == false`. | **No**: Returns `nil`. |
| | **Armed/Retained + Present** | `lookupMapLocked`/`lookupProgramLocked` returns `(h, true, armed/retained)`. | **No**: Returns handle. |
| **Class 4**<br>[`NewEventSource`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L1161-L1171) | **Fresh** | `lookupMapLocked("events")` returns `st == fresh`. Gate fires `ErrDataplaneNotArmed`. | **Yes (Intended A3 change)**: Returns `(nil, ErrDataplaneNotArmed)`. |
| | **Armed/Retained + Absent** | `lookupMapLocked` returns `st == armed/retained`, `present == false`. | **No**: Returns `(nil, fmt.Errorf("events map not loaded"))`. |
| | **Armed/Retained + Present** | `lookupMapLocked` returns `(evMap, true, armed/retained)`. | **No**: Creates `ringbuf.NewReader(evMap)`. |

*Conclusion*: Every cell is total, explicit, and preserves master's observable behavior except for the intended Fresh $\times$ Class 1 / Class 4 error substitution.

---

#### 2. Pluralization Audit
Checked all references to the registry lookup helpers across `plan.md`. The four primary normative sites explicitly specify the helper **PAIR** (`lookupMapLocked` and `lookupProgramLocked`):
1. **The uniform rule** ([`plan.md:3684-3685`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3684-L3685)): `lookupMapLocked`/`lookupProgramLocked`, pluralized at v87 per r85 Codex m2.
2. **The §4.7 bullet** ([`plan.md:4151`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4151)): `lookupMapLocked`/`lookupProgramLocked`.
3. **The `m.mu` comment inventory** ([`plan.md:4347`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4347)): `helper PAIR, lookupMapLocked/lookupProgramLocked`.
4. **The lock ownership test** ([`plan.md:4811-4812`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4811-L4812)): BOTH typed helpers (`lookupMapLocked` AND `lookupProgramLocked`).

*Note on Line 4836*: Line 4836 reads `"outside the EXACTLY-NAMED allowlist — the registry helper and publishShimRegistryLocked"`, which uses singular phrasing before expanding in lines 4842–4845 to `"TWO helpers with typed results — lookupMapLocked ... and lookupProgramLocked"`. This is a minor narrative phrasing remnant, but the normative specification at lines 4843–4845 & 4872 is unambiguous and names both helpers.

---

#### 3. Swap Fixture State Under Two-State Predicate
Verified the swap fixture logic ([`plan.md:4739-4747`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4739-L4747)):
- **Predicate**: `fresh := loaded == false && len(m.maps) == 0`.
- **Fixture Seeding**: Seeds `m.programs["test_prog"]` **plus any one entry in `m.maps`** (e.g. sentinel map), with `xdpEntryProg = "other"`.
- **Trace**:
  1. `m.maps` is non-empty $\implies$ manager classifies as **`retained`** (not `fresh`).
  2. `swapXDPEntryProg("test_prog")` calls `lookupProgramLocked("test_prog")`.
  3. Class 1 gate sees `st == retained` $\implies$ does **not** return `ErrDataplaneNotArmed`.
  4. `lookupProgramLocked` returns `(prog, true, retained)` $\implies$ missing program error bypassed.
  5. `m.XDPEntryProgram() ("other") == "test_prog"` is `false` $\implies$ already-selected exit bypassed.
  6. `m.xdpLinks` is empty $\implies$ update loop executes 0 iterations without error.
  7. Execution reaches line 632 (`m.xdpEntryProg = name`) under `m.mu` $\implies$ proof of lock ownership at `:632` is reached.

---

#### 4. Class-1 Armed+Absent Error Preservation
Audited map lookups across `pkg/dataplane`:
- Every fallible map lookup in Class 1 (`maps_fabric.go:19,39`, `maps_filter.go:17,45,76`, `maps_nat.go:20,61`, `loader.go:700,989`) uses the comma-ok pattern (`zm, ok := ...`).
- On `armed/retained + absent`, `lookupMapLocked` returns `(nil, false, armed/retained)`.
- `present == false` causes the method to enter `if !ok` and return its specific master missing-map error (e.g., `"fabric_fwd map not found"`).
- Methods returning `nil`/`0`/neutral on `!ok` are categorized in Class 2, preventing any silent proceed or nil-dereference panics in Class 1.

---

### Final Summary
The v87 plan document completes all requirements for PR-1. All class outcomes are total, the two-state predicate is mathematically consistent across all test fixtures and methods, and no PR-1 claims block implementation readiness.
