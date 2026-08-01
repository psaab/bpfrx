# AGY adversarial plan-review — round 75 (plan v76 @ 27c602aab)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (DetachXDP class-3-like shape verified across fresh-unarmed/armed/retained-re-arm states; the scoped-lookup rule's library-handle iteration semantics verified; the direct :632 pin verified deterministic). Raw output follows verbatim.

---

# Hostile Adversarial Plan Review: #2114 (Round 75 — CONVERGENCE)

**Plan Document**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` (v76 @ `27c602aab`)  
**Scope**: PR-1 ONLY (`d.dp` accessor core, A3 armed-state gate, 157-method `*Manager` partition, sampler narrowing, AST canary, `-race` regressions). *Follow-up unit G+H+H2 in `followup-seed.md` is out of scope.*

---

### 1. Verification of the `DetachXDP` Class-3-Like Shape

* **No `loaded` Gate**: `DetachXDP` (`pkg/dataplane/loader.go:639-666`) and `setXDPAttachedFlag` (`:699-825`) carry NO `loaded` gate. 
* **State Behavior Preservation**:
  * **Fresh-unarmed state** (`m.xdpLinks` empty): `DetachXDP` checks `m.xdpLinks[ifindex]` at `:640`, finds `!exists`, and returns `nil` early at `:642`. Exact match for master's behavior.
  * **Armed state** (`m.loaded == true`): `DetachXDP` finds the link, delegates to `setXDPAttachedFlag(ifindex, false)`, unpins/closes, and deletes the link from `m.xdpLinks`. Exact match for master's behavior.
  * **Retained re-arm state** (`m.loaded == false` following `Close()` or re-arm attempt, but `m.maps`, `xdpLinks`, and `xdpFlagClaims` remain populated): Without a `loaded` gate, `setXDPAttachedFlag` executes fully, discovers retained claims (`:719-723`), updates `xdpFlagClaims`, and clears flags in `iface_zone_map` (`:816`). This corrects the v75 defect where a `loaded` gate skipped cleanup and left stale claims to spuriously re-flag entries on subsequent `SetZone` calls (`:851-865`).
* **Scoped-Lookup Rule**:
  * Scoped `m.mu` sections are taken **only** when reading `m.maps["iface_zone_map"]` (`:700`) and `m.maps["vlan_iface_map"]` (`:730`) to copy the handles.
  * `zm.Iterate()` (`:754`), `zm.Lookup()` (`:789`), and `zm.Update()` (`:816`) run on the extracted `*ebpf.Map` handle **outside `m.mu`**. They intentionally escape `m.mu` per the Class-3 design rule to prevent holding the mutex across blocking eBPF kernel calls and to avoid mutex reentrancy.

---

### 2. Verification of the XDP Seam Direct `:632` Pinning

* **Seam Mechanics in `swapXDPEntryProg` (`pkg/dataplane/loader.go:608-635`)**:
  * `:609`: `prog, ok := m.programs[name]` (returns early at `:610` if not found).
  * `:613`: `if m.XDPEntryProgram() == name` (returns early at `:614` if already set).
  * `:632`: `m.xdpEntryProg = name` (write).
* **Deterministic Pinning**:
  * In v75, calling the public `SwapToUserspaceXDPShimEntryProgram` on an unarmed manager tripped the Class-1 gate (`ErrDataplaneNotArmed`), while calling `swapXDPEntryProg` directly without seeded state exited at `:610` or `:614`, leaving line `:632` unexercised (a silent-green test flaw).
  * v76 specifies seeding `m.programs["test_prog"]` with a test handle and setting `m.xdpEntryProg = "other"`.
  * Calling `swapXDPEntryProg("test_prog")` directly bypasses both early returns (`:610` and `:614`), iterates an empty `m.xdpLinks` map, and directly executes `m.xdpEntryProg = "test_prog"` at line `:632` under `m.mu` while racing against `XDPEntryProgram()` across the `:154` barrier.
  * This deterministically exercises Go `-race` detection against line `:632`.

---

### 3. Verification of Label Hygiene, Fixture Migration & §10 Premise

* **Label Hygiene**:
  * The `xdpEntryProg` trio (`XDPEntryProgram`, `SelectUserspaceXDPShimEntryProgram`, `UsingUserspaceXDPShimEntryProgram`) is single-homed in Category G (`loader.go:105, 114, 119`), resolving the previous Category F/G double-listing.
  * `DetachXDP` is assigned a single manifest label in Category G for its construction link map check, explicitly referencing its Class-3-like delegation target.
* **Fixture Migration**:
  * `TestXSKLivenessFailureRestoresUserspaceShimEntry` (`pkg/dataplane/xdp_shim_decouple_test.go:32, 321`) previously constructed an unarmed `New()` manager and expected program selector restoration. Because `SwapToUserspaceXDPShimEntryProgram` is now Class-1 gated, this test is correctly migrated to an explicitly armed synthetic fixture via a `pkg/dataplane` test helper.
* **§10 Premise Correction**:
  * The status loop can start prior to Compile-failure propagation (`manager_ha.go:115`, `manager_compile.go:276, 378`). However, all loop-start paths execute strictly after `CompileUserspaceShim` has returned and `Start` delegates to `Load` (`manager.go:370`).
  * Thus, the post-arm Compile-vs-status race has zero Start-window overlap and is outside A3's pre-arm L2 scope. Retaining this as a documented post-PR-1 follow-up candidate is sound.

---

### 4. Fresh Hostile Attack on PR-1 Claims

* **`d.dp` Accessor Core**: `atomic.Pointer[dataplane.RuntimeDataPlane]` provides full acquire-release memory safety. All 129 read sites in `pkg/daemon` are converted to `d.getDataplane()`, all 5 write sites to `d.setDataplane(...)`, enforced by the `daemon_dp_canary_test.go` AST validator.
* **Method Totality**: All 157 exported `*Manager` methods are uniquely partitioned into Class 1 (34), Class 2 (21), Class 3 (4), Class 4 (3), Category L (9), Category F (6), and Category G (80), with unambiguous precedence rules preventing overlap.
* **Sampler Scope & Verification**: `pkg/fwdstatus/sampler.go` is cleanly isolated via `CachedStatusProvider`.

No unaddressed races, memory ordering hazards, or signature misalignments remain in PR-1.

---

## Verdict

### **PLAN-READY**

Nothing in PR-1 blocks **PLAN-READY** for #2114. The v76 plan is complete, structurally sound, and ready for implementation.
