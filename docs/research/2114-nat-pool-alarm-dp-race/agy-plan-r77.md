# AGY adversarial plan-review — round 77 (plan v78 @ a437f0246)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (re-grepped all 100+ registry access sites — none outside the helper; lock hierarchy userspace-m.mu -> shim-m.mu one-directional, no cycle; all-or-nothing population proof confirmed — the r76 M2 premise refuted; narrowed L2 claim audited exact). Raw output follows verbatim.

---

# Adversarial PLAN Review: #2114 — Round 77 (CONVERGENCE)

**Plan Document**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` (v78 @ `a437f0246`)  
**Verdict**: **PLAN-READY**

---

### Hostile Verification & Answers

#### 1. THE UNIFORM REGISTRY RULE
* **Access Site Re-Grep**: Evaluated all 100+ access sites across `pkg/dataplane/` (`loader.go`, `loader_userspace_shim.go`, `compiler.go`, and all `maps_*.go` files). Every single `m.maps` and `m.programs` access site (including `compiler.go:353` for `redirect_capable`, `loader.go:495/591/609/700/730/...`, and `loader_userspace_shim.go:185-190`) is subject to the single `m.mu`-scoped registry rule. No access site remains outside the helper rule.
* **Lock Order & Deadlock Analysis**: The whole-batch population critical section in `loader_userspace_shim.go:183-190` holds root `dataplane.Manager.mu` (`m.mu`). It performs pure Go map assignments (`m.programs[...] = ...`, `m.maps[...] = ...`) and does NOT make calls into `userspace.Manager` or acquire `userspace.Manager.mu`. The established lock hierarchy is strictly `userspace.Manager.mu` $\rightarrow$ `dataplane.Manager.mu` (as documented at `plan.md:3794,4664`). There is no reverse acquisition path or deadlock risk.
* **Classification + Selection as One Scoped Operation**: Fully implementable for all classes. Under `m.mu.Lock()`, reading `(!m.loaded.Load() && len(m.maps) == 0)` evaluates armed state, while handle extraction from `m.maps[name]` occurs atomically within the same critical section. This guarantees that gate classification and handle copying are indivisible.

#### 2. ALL-OR-NOTHING POPULATION PROOF (M2 Answer)
* In `loader_userspace_shim.go:160-183`, every fallible operation (collection compilation at `:162`, program lookup at `:167`, and BPF map pinning at `:179`) returns early on error **before** reaching the insert loops at `:185-190`.
* The insert loops at `:185-190` are non-fallible Go map assignments, executed inside a single `m.mu` critical section.
* **Conclusion**: No partial registry state can ever be left behind on arm failure, nor can concurrent readers observe partial population. This completely refutes the premise of partial-state false-fresh conflation.

#### 3. THE NARROWED L2 CLAIM
* **Scope**: L2 is explicitly narrowed to:
  1. Fresh-unarmed admission safety (returning `ErrDataplaneNotArmed` where master returned map-not-found).
  2. Registry-selection race safety across all states via the uniform `m.mu` rule + whole-batch publication.
* **Exclusions**: The plan explicitly disclaims current-generation delivery, re-arm linearizability, or teardown/lifetime safety on the bootstrap-recurrence path (`bootstrap.go:470`). The unpinned kernel map handle hazard is documented in §10 (`plan.md:3870-3882`) and assigned to follow-up work item **H** in `followup-seed.md`.
* **Audit**: No remaining plan text overclaims beyond this narrowed scope.

#### 4. §9 TEST MATRIX & FIXTURES
* **Retained Overlap Test**: `TestManager_ArmedGate_RetainedReStartOverlap` (`plan.md:4552-4560`) is specified with a blocked re-`Start` whole-batch critical section holding a test hook while methods from every class are driven across the seam.
* **Detach Test Actor**: The Detach test gains its concurrent population actor driving the same blocked re-`Start` seam.
* **Fixture Redo**: `injectShimMap` (`manager_testhelpers_test.go:22`) populates `m.maps` without setting `loaded=true`, correctly classifying injected test fixtures as **retained-unarmed**. Under the two-state predicate, retained-unarmed fixtures proceed normally (e.g., `xdp_shim_decouple_test.go:32`), preserving test behavior without spurious breakage.

#### 5. FRESH ATTACK ON OTHER PR-1 CLAIMS
* Evaluated PR-1 claims (A1 `d.dp` `atomic.Pointer`, A3 two-state gate, sampler narrowing, locked `xdpEntryProg` trio helper, site conversions, and canary strategy).
* All invariants, concurrency boundaries, and fail-closed error paths in PR-1 are sound, rigorous, and free of race hazards or deadlocks.

---

### Final Determination

Does anything in PR-1 block **PLAN-READY** for #2114? **No.**

PR-1 design in `plan.md` v78 is complete, mathematically coherent, and ready for `/engineer 2114`.
