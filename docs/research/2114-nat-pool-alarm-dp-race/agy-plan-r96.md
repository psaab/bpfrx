# AGY adversarial plan-review — round 96 (plan v99 @ a862aa14d77c)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY. Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 — Round 96 (v99 @ `a862aa14d77c`)

**Target**: PR-1 ONLY (`d.dp` synchronized accessor core + `pkg/dataplane` A3 armed-state gate + site conversion + canaries + sampler narrowing).  
**Out of Scope**: Follow-up unit G+H+H2 (`followup-seed.md`).

---

### 1. THE MANIFEST MECHANISM

* **Canary Alignment**: The stale-checked helper-callsite manifest introduced in v99 (`plan.md:9-14, 5345-5352`) follows the **exact compile-time-invariant discipline** established by the registry access canary (`plan.md:5245-5254, 5558-5560`).
  * The registry canary uses Go AST / string scanning over `pkg/dataplane` to verify that every direct `m.maps`/`m.programs` reference matches the exact allowlist (`lookupMapLocked`, `lookupProgramLocked`, `publishShimRegistryLocked`), failing the build on any unexpected addition, deletion, or modification.
  * The helper-callsite manifest applies the identical pattern: AST/grep scanning enumerates every call to `lookupMapLocked` and `lookupProgramLocked` in `pkg/dataplane`, and the self-check asserts **exact set equality** against the manifest map. No new or unspecified mechanism is introduced.
* **Mechanical Enumeration**: Callsite enumeration is 100% mechanical. Because direct `m.maps`/`m.programs` accesses outside the two helper functions are forbidden by the registry canary, searching for invocation AST nodes of `lookupMapLocked` and `lookupProgramLocked` comprehensively enumerates every registry access site across `pkg/dataplane`.

---

### 2. THE MANIFEST SCOPE & DRIFT PREVENTION

* **Scope Coverage**: Every callsite maps to its required/optional outcome label, and each of the 17 mixed-method sites maps directly to its named §9 test leg (`plan.md:5347-5352`).
* **Sufficiency vs. Absent-Branch Control-Flow Shape**:
  * The manifest is a static inventory whose purpose is to **prevent silent changes or unreviewed additions/deletions/relocations** of helper callsites.
  * Capturing the syntactic shape of the absent-branch (e.g. `if !ok { return nil }` vs. `if !ok { break }`) inside the static manifest data structure is unnecessary and would duplicate AST parsing.
  * **Runtime semantic drift is caught by the §9 discriminating test legs**: Each of the 17 mixed sites has a dedicated runtime test leg (`plan.md:5479-5536`) asserting its exact absent-branch execution behavior (e.g., `SetNAT64Config` verifying required write landing when optional map is absent; `ClearNAT64Configs` partial-registry leg asserting completion of trailing required writes; `ClearStaticNATEntries` verifying continuation from v4 to v6; `Compile` verifying continuation past absent `redirect_capable`).
  * Together, the static manifest (enforcing callsite set equality) and the §9 test legs (enforcing absent-branch execution semantics) leave zero gaps for semantic drift.

---

### 3. AUDIT OF NORMATIVE TEXT & INVENTORY CLAIMS

* In earlier rounds, the 17-site inventory was described extensionally but lacked a mechanical test verifying set equality.
* In v99, all normative text in §4, §5, §7, and §9 (`plan.md:9-14, 5340-5352, 6160-6164`) unequivocally specifies that the extensional 17-site inventory is **load-bearing and mechanically checked** by the stale-checked callsite manifest test (`TestManager_CallsiteManifest` / canary self-check).
* No residual text remains in PR-1 suggesting or implying that the 17-site inventory is review-only or unchecked.

---

### 4. FRESH ATTACK ON OTHER PR-1 CLAIMS

* **Census & Cardinality Audit**:
  * `pkg/daemon` `d.dp` references: **134 total** (129 read sites + 5 writer sites, `plan.md:3587-3588, 4569-4570`).
  * `pkg/dataplane` registry access census: **135 total** (130 `m.maps` + 5 `m.programs` = 91 required + 41 optional + 3 writes, `plan.md:5263-5306`).
  * 41 optional reads breakdown: 14 `if ok` skips + 1 nil-guard return + 3 skip/continue outcomes + 21 comma-ok early returns + 2 direct `nil` returns = 41 (`plan.md:5302-5306`).
  * Mixed-method optional subset: 14 `if ok` + 2 single-value + 1 comma-ok early return = **17 mixed sites** (`plan.md:5311-5321`).
* **Accessor Core (`dpCell`)**: Retains `atomic.Pointer[RuntimeDataPlane]`, mapping typed `nil` values to `nil` interface stores via table-driven tests (`plan.md:4975-5020`).
* **Canary Allowlist**: Exactly 3 symbols (`lookupMapLocked`, `lookupProgramLocked`, `publishShimRegistryLocked`, `plan.md:5246-5251`).
* **PR-1 Isolation**: G+H+H2 remain strictly isolated in `followup-seed.md`. No leakage into PR-1.

---

### VERDICT

**VERDICT: PLAN-READY**

**Does anything in PR-1 block PLAN-READY for #2114?**  
**No.** All PR-1 design invariants, census enumerations, AST canary rules, stale-checked callsite manifests, and §9 test specifications in v99 @ `a862aa14d77c` are airtight, consistent, and mechanically verifiable.
