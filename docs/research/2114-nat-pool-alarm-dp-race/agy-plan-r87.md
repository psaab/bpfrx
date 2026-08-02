# AGY adversarial plan-review — round 87 (plan v88 @ 4183be25c5ef)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (PR-1 ONLY). Raw output follows verbatim.

---

### Adversarial PLAN Review Verdict: **PLAN-READY**

**Target**: #2114 — round 87 (CONVERGENCE), plan v88 @ `4183be25c5ef`  
**Branch**: `research/2114-nat-pool-alarm-dp-race`  
**Verdict Surface**: **PR-1 ONLY** (Work Item G + H + H2 in `followup-seed.md` remain explicitly out of scope).

---

### Hostile Verification Analysis

#### 1. Inventory Completeness: **VERIFIED COMPLETE**
An exhaustive audit of all production `m.maps[...]` and `m.programs[...]` read operations in `pkg/dataplane/*.go` (excluding `_test.go` files) was conducted to classify every site as **required** (errors on absent) vs **optional** (skips or nil-guards on absent).

- **Total production reads**: 134 references (5 writers + 129 readers across the audit matrix).
- **Required accesses**: All single-map setters/clears in `maps_mirror.go:30`, `maps_nat.go:20,29,38,61,71,84,93,102,125,135,148,157,167,178,191,195,211,220,239,249,291,309,319,345,400,415,435`, `loader.go:495,609,831,880,890,910,928,957,989,1086`, `maps_filter.go`, `maps_flow.go`, `maps_policy.go`, `maps_fabric.go`, `maps_counters.go`, and `maps_screen.go`.
- **Optional/Nil-guard accesses (13 total sites)**:
  - 4 optional `if ok` reads in `maps_nat.go`:
    - `maps_nat.go:261` (`static_nat_v4` in `ClearStaticNATEntries`)
    - `maps_nat.go:274` (`static_nat_v6` in `ClearStaticNATEntries`)
    - `maps_nat.go:300` (`nat64_prefix_map` in `SetNAT64Config`)
    - `maps_nat.go:328` (`nat64_prefix_map` in `ClearNAT64Configs`)
  - 7 optional `if ok` reads in `maps_stale.go`:
    - `maps_stale.go:224` (`static_nat_v4` in `DeleteStaleStaticNAT`)
    - `maps_stale.go:241` (`static_nat_v6` in `DeleteStaleStaticNAT`)
    - `maps_stale.go:285` (`nat64_configs` in `DeleteStaleNAT64`)
    - `maps_stale.go:291` (`nat64_prefix_map` in `DeleteStaleNAT64`)
    - `maps_stale.go:322` (`nat_pool_configs` in `ZeroStaleNATPoolConfigs`)
    - `maps_stale.go:328` (`nat_pool_ips_v4` in `ZeroStaleNATPoolConfigs`)
    - `maps_stale.go:336` (`nat_pool_ips_v6` in `ZeroStaleNATPoolConfigs`)
  - 2 nil-guard reads:
    - `compiler.go:353` (`redirect_capable` in `Compile`)
    - `loader.go:591` (`interface_counters` in `seedInterfaceCounter`)

**Finding**: No optional or mixed site is missing. The 11 `if ok` sites + 2 nil-guard sites in v88 match the production codebase with 100% precision.

---

#### 2. First-Access Ordering & All-Optional Methods: **VERIFIED CORRECT**

1. **Ordering in Mixed Methods**:
   - In methods that mix required and optional accesses (`SetNAT64Config` at `maps_nat.go:290` and `ClearNAT64Configs` at `:318`), the **REQUIRED** access (`nat64_configs` at `:291` and `:319`) occurs **FIRST**. On a fresh registry (`st == fresh`), the method returns `ErrDataplaneNotArmed` at line 291 / line 319 before reaching the optional access at line 300 / line 328.
2. **All-Optional Methods (`DeleteStaleNAT64`, `DeleteStaleStaticNAT`, `ZeroStaleNATPoolConfigs`, `ClearStaticNATEntries`)**:
   - None of these methods have required accesses. Under master on a fresh/empty registry, all `if ok` blocks evaluate to `false`, and the method silently returns success (`nil` or void).
   - Under v88's per-access matrix rule:
     > *"The matrix row governs a class-1 method's REQUIRED accesses; an OPTIONAL access inside ANY class keeps master's exact per-site outcome (the `if ok` body simply does not run; the nil-guard simply returns)..."*
   - On `st == fresh`, `lookupMapLocked` returns `present = false`. The optional `if present` guards evaluate to `false`, skipping all bodies. The methods succeed, preserving master's exact neutral behavior (Class 2).

**Finding**: The per-access classification rules in v88 govern both mixed-access methods and all-optional methods without ambiguity or semantic breakage.

---

#### 3. Partial-Registry Oracle: **VERIFIED HARMLESS & EFFECTIVE**

- **Interaction with Two-State Predicate**: The two-state predicate checks `loaded` and `len(m.maps) == 0`. In the partial-registry fixture (`nat64_configs` present, `nat64_prefix_map` absent), `len(m.maps) > 0`, so the manager evaluates to `retained` (or `armed` if `loaded` is true).
- **Interaction with Whole-Batch Publication**: The whole-batch publication invariant governs production updates via `PublishShimRegistry`. The partial-registry oracle in §9 is a synthetic test fixture verifying that `lookupMapLocked` under `retained`/`armed` returns `(h, present=true)` for `nat64_configs` and `(nil, present=false)` for `nat64_prefix_map`, causing `SetNAT64Config` to succeed cleanly.

**Finding**: The partial-registry test fixture exercises the required-present + optional-absent path without violating or degrading the two-state predicate or whole-batch publication invariant.

---

#### 4. Fresh Attack on Remaining PR-1 Claims: **PASS**

- **`d.dp` publication cell & two-state predicate**: Atomic publication cell + `loaded` + `len(m.maps) == 0` is leak-free and race-free.
- **Canary Allowlist & Self-Tests**: Accessor helpers `lookupMapLocked` and `lookupProgramLocked` are strictly allowlisted, with synthetic negative tests covering lock-ordering and alias-escaping anti-patterns.
- **Audit Table**: 134 production references (5 writers, 129 readers) are fully accounted for.

---

### Final Determination

Nothing in PR-1 blocks **PLAN-READY** for #2114.

**Verdict**: **PLAN-READY**
