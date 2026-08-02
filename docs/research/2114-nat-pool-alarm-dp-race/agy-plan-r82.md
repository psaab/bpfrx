# AGY adversarial plan-review — round 82 (plan v83 @ c3c4cad42)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (canary spec implementable with no site escaping the allowlist; the batch-hold placement mechanically sound — cleanups verified filesystem-only with no Manager receiver, best placed before the hold; the helper lock-ownership test deterministic and deadlock-free; all summary/oracle/citation folds verified). Raw output follows verbatim.

---

# Adversarial Plan Review: #2114 (round 82 - CONVERGENCE, plan v83 @ `c3c4cad42`)

**Target**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md`  
**Branch**: `research/2114-nat-pool-alarm-dp-race`  
**Verdict Surface**: **PR-1 ONLY** (Core `d.dp` accessor + armed-state gate A3 + site conversion + AST canaries + sampler narrowing).  

---

## Final Verdict

### **PLAN-READY**

**Does anything in PR-1 block PLAN-READY for #2114?**  
**NO.** All prior findings (including Codex r81 M1/M2/m1–m4) are fully folded, mechanically specified, and implementable as written.

---

## Detailed Item-by-Item Verification

### 1. THE CANARY SPEC: Allowlist, Scanner, Permitted Shapes, Stale Check, Synthetic Tests
* **Allowlist Specification**: Named exactly in `pkg/dataplane/retirement_boundary_canary_test.go`:
  1. The single `m.mu`-scoped registry helper function.
  2. The whole-batch writer `loadUserspaceShimObjects` (`loader_userspace_shim.go:183-190`).
* **Scanner & Permitted Shapes**: The AST scanner parses `pkg/dataplane/*.go` for `SelectorExpr`/`IndexExpr`/`AssignStmt` references to `m.maps` and `m.programs`. Outside the allowlist, direct accesses trigger a canary failure. Inside the allowlist, only the specified indexing/assignment shapes are permitted.
* **Stale-Allowlist Self-Check**: If any function on the allowlist is refactored so it no longer touches `m.maps`/`m.programs`, the canary self-check fails, preventing silent allowlist decay.
* **Synthetic Negative Tests**: Includes both-direction unit tests asserting that a forbidden access (e.g., in a test fixture snippet) fails the canary scanner.
* **Re-Grep Verification**: Full AST scan of `pkg/dataplane/*.go` confirms that after converting classes 1, 2, 3, 4, L, F, and G to the registry helper, direct `m.maps` and `m.programs` accesses exist *only* at `loadUserspaceShimObjects` and inside the registry helper. `dpCell` access in `pkg/daemon` is pinned by `daemon_dp_canary_test.go`.
* **Conclusion**: Implementable as written, fully watertight.

### 2. THE BATCH-HOLD PLACEMENT: `LoadUserspaceShim` & Legacy Cleanups
* **Hold Scope**: `LoadUserspaceShim` (`loader.go:152-167`) takes `m.mu.Lock()` spanning `loadUserspaceShimObjects()` AND `m.loaded.Store(true)` at `:164`. Population and publication occur as a single atomic unit.
* **Legacy Cleanups (`cleanupUserspaceShimLegacyTCLinks` :155 and `cleanupUserspaceShimLegacyOnlyMapPins` :158)**:
  * **Location**: Both helpers operate strictly on bpffs paths (`/sys/fs/bpf/xpf/...`) and take no `m *Manager` receiver. They touch zero `Manager` fields or registry state.
  * **Placement**: Running them outside the `m.mu` hold avoids extending the mutex hold across disk/bpffs I/O operations (`os.Remove`, `os.ReadDir`).
  * **Correctness**: Safe whether executed before acquiring the hold or inside the hold; placing them before `m.mu.Lock()` is optimal.
* **Conclusion**: Mechanically precise and sound.

### 3. HELPER LOCK-OWNERSHIP TEST & SEAM-SCOPING RULE
* **Replacement of Reverse-Schedule Seam**: Correctly replaces the non-implementable statement-interval pause with a deterministic lock-ownership proof:
  1. **Registry Helper Lock-Ownership Test**: The registry helper's critical section under `m.mu` contains a test hook (`chan struct{}` barrier). A racing writer attempting `LoadUserspaceShim` blocks on `m.mu.Lock()`, deterministically proving lock ownership without sleeps or race windows.
  2. **AST Canary Net**: Enforces that *all* registry accesses route through the registry helper.
* **Seam-Scoping Rule**: The synthetic test loader mocks only privileged kernel syscalls (bpf map/program pinning), leaving production registry assignments (`m.maps[...] = ...`) to run under the test barrier.
* **Deadlock Analysis**: The reader and writer compete for the single `m.mu` mutex with no nested mutexes. Zero risk of self-deadlock.
* **Conclusion**: Fully deterministic, deadlock-free, and implementable.

### 4. CARVE-OUT POINTERS, ORACLE SUBCASE QUALIFICATIONS & CITATIONS
* **Class-1 Carve-out Pointers**: Clarified in §6 and §4 (class 1) that attach methods (`AttachXDP`/`AttachTC`) and `CompileConfig` retain their pre-registry `!dp.IsLoaded()` rejections (carve-out) and do not fire the typed `ErrDataplaneNotArmed` error.
* **Oracle Subcase Qualifications**:
  * Nil config: `compiler.go:179` returns `"nil config"` before `IsLoaded()`.
  * Canceled context: `apply.go:238` returns `ctx.Err()` before `Compile`.
  * Pin removal: `manager_compile.go:163` executes pre-selector cleanup before `CompileUserspaceShim`.
  * Two-invocation shape: Pre-Store invocation rejects; a subsequent post-Store invocation blocks at registry selection.
* **Citations & Wording**: Verified `UpdateFabricFwd` at `maps_fabric.go:18` (corrected from `:30`), `compiler.go:179`, `apply.go:238`, and `manager_compile.go:163`.
* **Conclusion**: Verified accurate against codebase.

### 5. FRESH ATTACK ON OTHER PR-1 CLAIMS
* **Decoupling**: PR-1 is cleanly isolated from `followup-seed.md` (work items G, H, H2). No dependencies on follow-up code exist in PR-1.
* **Completeness**: All 157 `*Manager` methods are partitioned into disjoint classes (1, 2, 3, 4, L, F, G).

---

## Summary

Plan v83 (`c3c4cad42`) satisfies all convergence requirements for PR-1. There are **no blocking items**. The plan is **PLAN-READY**.
