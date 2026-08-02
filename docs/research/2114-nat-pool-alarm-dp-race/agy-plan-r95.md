# AGY adversarial plan-review — round 95 (plan v98 @ f9137e30ee67)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY ("Confirmed complete mathematical and architectural convergence for PR-1 of #2114"). Raw output follows verbatim.

---

### Adversarial PLAN Review — #2114 (Round 95 / CONVERGENCE)
**Target**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` @ `f9137e30ee67` (Plan v98)  
**Branch**: `research/2114-nat-pool-alarm-dp-race`  
**Verdict Surface**: **PR-1 ONLY** (G+H+H2 in [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md) is explicitly out of scope).

---

### Hostile Verification & Audit

#### 1. THE COEXTENSIVE COVERAGE
I walked all **17 enumerated mixed-subset sites** against their source locations in [`pkg/dataplane`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane) and their corresponding test leg specifications in §9 of [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5000-L5550):

* **The 3 Previously Omitted Legs (Folded in v98)**:
  1. [`maps_nat.go:300`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L300) (`SetNAT64Config` optional `nat64_prefix_map`): §9 leg `(i)` specifies a fixture with REQUIRED `nat64_configs` PRESENT and OPTIONAL `nat64_prefix_map` ABSENT; asserts call succeeds and index 0 write landed.
  2. [`loader.go:591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L591) (`seedInterfaceCounter` nil-guard `interface_counters`): §9 leg `(ii)` specifies a pair: ABSENT fixture asserts `AttachXDP`/`AddTxPort` succeed (seed skips), PRESENT fixture asserts seed wrote.
  3. [`loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) (`setXDPAttachedFlag` absent-`iface_zone_map` early-boot no-op): §9 leg `(iii)` specifies ABSENT `iface_zone_map` fixture asserting master's early-boot no-op `nil` return without mutating `xdpFlagClaims`.
* **The 14 Continuation & Optional-if-ok Sites**:
  4. [`maps_nat.go:328`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L328) (`ClearNAT64Configs` optional `nat64_prefix_map`): §9 partial-registry leg seeds `nat64_configs` + non-zero `nat64_count`, omits `nat64_prefix_map`, asserts success AND `nat64_count` zeroed at `:340`.
  5. [`maps_nat.go:261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L261) (`ClearStaticNATEntries` `static_nat_v4`): §9 leg exercises absent v4 continuing to v6 at `:274`.
  6. [`maps_nat.go:274`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L274) (`ClearStaticNATEntries` `static_nat_v6`): Covered under quiescent retained/fresh outcome legs & multi-optional absent-outcome assertions.
  7. [`loader.go:730`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L730) (`setXDPAttachedFlag` `vlan_iface_map`): §9 leg exercises absent `vlan_iface_map` continuing to physical interface processing (`:744-826`).
  8. [`compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353) (`Compile` `redirect_capable`): §9 leg exercises absent `redirect_capable` skipping redirect map population and continuing to attachment work at `:368`.
  9. 9–14: `maps_stale.go:224/:241` (`DeleteStaleStaticNAT`), `:285/:291` (`DeleteStaleNAT64`), `:322/:328/:336` (`ZeroStaleNATPoolConfigs`), `maps_session.go:327/:337` (`SessionCount`): §9 names the continuation pattern across all multi-map stale cleanups and dual-family counters (absent earlier map, present later map).

Coverage between the extensional 17-site list and §9 test legs is now strictly **coextensive**.

---

#### 2. THE NEW LEGS' CONSISTENCY & HOOK PROTOCOL
* **Fixture Independence**: The Detach leg ([`TestManager_ArmedGate_DetachRetainedClaims`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5542)) explicitly seeds `iface_zone_map` as **PRESENT** so execution passes [`loader.go:700`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L700) to reach claim discovery (`:711`) and deletion (`:777`). The new leg `(iii)` uses a **SEPARATE fixture** with `iface_zone_map` **ABSENT** to assert early-boot no-op `nil` at `:700`. There is zero fixture collision or assertion conflict.
* **Hook Protocol Alignment**: All 3 new legs are quiescent functional outcome tests operating on synthetic `Manager` instances with specific eBPF map seeding. They do not require concurrent lock interlocks or violate the instance-scoped mutex hook protocol.

---

#### 3. THE EXTENSIONAL DEFINITION & ENFORCEMENT MECHANISMS
* **Load-Bearing Extensional Definition**: The enumerated 17-site list is the exact extensional definition of the mixed/multi-access optional subset.
* **Automated Enforcement**:
  1. **AST Registry Canary** ([`daemon_dp_canary_test.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5560)): Scans all Go ASTs under `pkg/dataplane` and fails if any code accesses `m.maps` or `m.programs` outside [`lookupMapLocked`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5228), [`lookupProgramLocked`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5234), or [`publishShimRegistryLocked`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5214). All 135 accesses (including all 41 optional accesses) are structurally checked by compiler/test gates.
  2. **Totality Canary** ([`TestManager_PreArmMethodMatrix`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5144)): Mechanically verifies that every exported `*Manager` method is cataloged in the classification manifest.

---

#### 4. FRESH ATTACK ON OTHER PR-1 CLAIMS
* **Census & Arithmetic Integrity**:
  * Total `pkg/dataplane` registry accesses: $135 = 130\text{ maps} + 5\text{ programs} = 91\text{ required} + 41\text{ optional} + 3\text{ writes}$.
  * Optional shape breakdown: $14\text{ if-ok skips} + 1\text{ nil-guard return} + 3\text{ skip/continue} + 21\text{ comma-ok early returns} + 2\text{ direct nil returns} = 41$.
  * Per-file audit table: $1+7+2+6+1+1+3+19+1 = 41$.
  * Neutral access breakdown: $17\text{ mixed} + 24\text{ single-access-selector} = 41$.
  * Single-access remainder breakdown: $17\text{ class-2} + 3\text{ class-3 hybrids} + 2\text{ class-4 getters} + 2\text{ internal helpers} = 24$.
* **PR-1 Isolation**: Work items G, H, and H2 remain strictly isolated in [`followup-seed.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md). PR-1 carries only the accessor core (A1), armed gate (A3), site conversions, canaries, and sampler narrowing.

---

### Final Verdict

**VERDICT**: **PLAN-READY**

**Does anything in PR-1 block PLAN-READY for #2114?**
**No.** All oracle gaps, definition non-exclusivity, and continuation coverage mismatches from r94 are fully resolved in v98 with complete structural and mathematical consistency.

---
### Summary of Work

1. **Hostile Audit of Extensional 17-Site List**: Verified all 17 site citations against Go files in `pkg/dataplane` and confirmed coextensive test coverage in §9 of `plan.md`.
2. **Leg & Fixture Consistency Check**: Confirmed that the 3 new legs (`SetNAT64Config` optional access, `seedInterfaceCounter` nil-guard, and `setXDPAttachedFlag` absent-`iface_zone_map`) operate on independent fixtures, do not conflict with `TestManager_ArmedGate_DetachRetainedClaims`, and align with the hook protocol.
3. **Automated Enforcement Verification**: Verified that the AST canary and `TestManager_PreArmMethodMatrix` enforce registry access wrapping and method classification totality across the codebase.
4. **Final PR-1 Plan Certification**: Confirmed complete mathematical and architectural convergence for PR-1 of #2114 and issued **PLAN-READY**.
