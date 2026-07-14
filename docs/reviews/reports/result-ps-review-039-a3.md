# Triage result — ps-review-039-a3.md

- **Subsystem:** Go config compilers + schema + validation monoliths (`pkg/config/compiler*.go`, `types_system.go`, `schema_*.go`)
- **Review base:** f70146951583823a5ace87b0b11a2e58f46e8db9
- **Base == master?** No, but base IS a direct ancestor of master (23 commits behind). All cited files are byte-for-byte the same *size* on master — none of the audited monoliths were split in those 23 commits, so the audit's shape claims still hold verbatim.
- **Master SHA at triage:** 95b33d49634d56086269a62a92e213dae7926f88
- **Repo:** real bpfrx (github.com:psaab/xpf) — no avacado-xpf fork paths cited.
- **Audit type:** MODULARITY / REFACTOR audit (file-size decomposition), NOT a correctness-bug audit. Every A-finding is explicitly class "(A) MECHANICAL / SAFE — byte-identical, no logic change." Finding 5 is a "(D) DO-NOT-SPLIT" negative finding.

## Outcome counts
- GENUINE-RESIDUAL (novel, reachable correctness bug): **0**
- ACCURATE-REFACTOR-OBSERVATION / NOT-MATERIAL (correct file-shape claim, no behavior bug): **4** (findings 1-4)
- DELIBERATE / negative-finding (correctly recommends no change): **1** (finding 5)
- CONFABULATED: 0
- ALREADY-FIXED: 0
- DUP: 0

**Bottom line:** every symbol, file size, and split-baseline claim in this audit is factually correct on current master. But this is a modularity audit — there is no input→wrong-output defect anywhere in it. Findings 1-4 are valid *refactor work items* (legitimate `refactor`/`modularity` issues), not residual bugs. `genuineResiduals[]` is empty by design: nothing here changes runtime behavior.

---

## Per-finding disposition + WHY

### Finding 1 — `compiler_validate_warn.go` 3330 LOC warning monolith → split
**Disposition: ACCURATE-REFACTOR-OBSERVATION / NOT-MATERIAL (no bug).**

- Verified: `git show origin/master:pkg/config/compiler_validate_warn.go | wc -l` = **3330** (exact match). `func ValidateConfig(` exists at line 51. The file is a warning-generation monolith as described.
- No behavior claim: the finding's own class is "(A) MECHANICAL / SAFE — cold path, pure file-move," hot-path statement confirms `ValidateConfig` runs only from `runTailGates` (P7, commit path). There is NO scenario in which any input produces a wrong output — the proposed change is a pure file move that must stay byte-identical.
- Why NOT a genuine residual: a residual requires a reachable defect (input → wrong output / crash). This is a cognitive-load / merge-conflict observation. Correct as a `refactor` issue; not a correctness bug. Severity "Medium" in the audit is a *refactor-priority* rating, not an exploitability rating.
- Not already-fixed: no `compiler_validate_warn_*.go` production sub-splits exist on master (only `compiler_validate_warn_nil_3494_test.go`, a test). The split has not landed.

### Finding 2 — `compiler_system.go` 1881 LOC system god-compiler → split
**Disposition: ACCURATE-REFACTOR-OBSERVATION / NOT-MATERIAL (no bug).**

- Verified: file is **1881** LOC exact. `func compileSystem(` at line 16, `compileUserspaceDataplane` at 710, `compileSNMP` at 1099, `compileChassis` at 1551 — all present as claimed. (The audit's "compileSystem 536 / compileChassis 300" line-span estimates are consistent with these offsets.)
- Cold path (commit-time), pure file-move, no logic change asserted by the finding itself.
- Why NOT genuine: organizational split, zero runtime effect. Legitimate `refactor`/`modularity` work item, not a defect. No sub-split files (`compiler_system_login.go` etc.) exist on master → not already-fixed.

### Finding 3 — `compiler_services.go` 1821 LOC services god-compiler → split
**Disposition: ACCURATE-REFACTOR-OBSERVATION / NOT-MATERIAL (no bug).**

- Verified: file is **1821** LOC exact. The RPM/DHCP/flow/sampling function inventory listed in the finding is consistent with the file. Cold path.
- Why NOT genuine: same reasoning — mechanical decomposition, no behavior change. Valid refactor item. No `compiler_services_*.go` sub-splits on master → not already-fixed.

### Finding 4 — `compiler_nat.go` 2529 LOC — helpers + strict gates + compile fused → split
**Disposition: ACCURATE-REFACTOR-OBSERVATION / NOT-MATERIAL (no bug).**

- Verified in detail (this finding makes the most specific placement claims — all confirmed):
  - File is **2529** LOC exact.
  - The 4 NAT strict gates DO live in `compiler_nat.go`, NOT in the existing `compiler_validate_strict_nat.go`: `validatePoolUtilizationAlarm` (L49), `validateNATHostMaskStrict` (L287), `validateNPTv6Strict` (L536), `validateNAT64PrefixStrict` (L770). Confirmed via `git grep` on origin/master.
  - `compiler_validate_strict_nat.go` exists (702 LOC) and does NOT contain those 4 gates — the finding's "already exists but does not contain these gates, move them here" claim is factually correct.
  - The 6 helper predicates are all in `compiler_nat.go`: `natAddrFamily` (L88), `natCIDRIPPart` (L105), `isHostMaskAddress` (L128), `natStaticPrefixInfo` (L158), `isNAT64PoolHostAddress` (L213), `nptv6PrefixHasHostBits` (L242). The cross-package-reuse note (helpers must stay in `package config` so `compiler_system.go:validateBackupRouterDst` still sees them) is a correct same-package caveat.
- Why NOT genuine: this is the most precise finding but it is still a *code-organization* observation — "these strict gates are physically in the wrong file relative to their sibling gates." The gates WORK correctly (they are called from `runUniformGates` P6b regardless of which file they live in); moving them changes nothing at runtime. No defect. Valid `refactor` item.
- Not already-fixed: `compiler_nat_helpers.go` does not exist on master; the 4 gates have not been moved into `compiler_validate_strict_nat.go`.

### Finding 5 — `compiler_uniformgates.go` 1659 + `compiler_validate_strict_filter.go` 1660 → DO NOT split (negative)
**Disposition: DELIBERATE / correct negative finding — no action.**

- Verified: `compiler_uniformgates.go` is **1659** LOC and contains exactly ONE function, `runUniformGates` (L27) — `grep -c '^func '` = 1. The finding's rationale (ordered single call-site preserving strict-first-error / tolerant-warning-order invariants #6/#7, guarded by golden tests) is architecturally sound. `compiler_validate_strict_filter.go` is **1660** LOC, the per-domain filter split from #4405.
- The reservation on `types_system.go` (1544 LOC, 64 types, firewall types mixed in — high blast-radius, defer, file tracking issue) is a reasonable judgment call, not a defect.
- Why correct: this finding explicitly recommends NO change and correctly warns future work off re-splitting the orchestrator. Nothing to fix or file.

## Dedup / baseline verification
The audit's dedup checklist is accurate against master:
- #4405 split result present: `compiler_validate_strict.go` (478 LOC remainder), `compiler_validate_strict_nat.go` (702), `compiler_validate_strict_filter.go` (1660) all exist.
- #4406 split result present: `compiler_prewalk.go` (432), `compiler_dispatch.go` (106), `compiler_derivations.go` (177), `compiler_earlystrict.go` (144), `compiler_uniformgates.go` (1659), `compiler_tailgates.go` (191) all exist; `compileExpanded` is at compiler.go L1986 (thin orchestrator).
- No new monolith is mis-reported as needing a split that was already done.

## Notes on severity framing
The "Medium" severities in findings 1-4 are refactor-*priority* ratings (merge-conflict surface, reviewer cognitive load), NOT correctness/security severities. Mapped to this triage's residual-bug lens they are all INFO-level (no reachable defect). Consistent with the ps-038/039 expectation that a heavily-hardened codebase yields ~0 correctness residuals in core scopes — this A3 batch confirms that: the config compiler layer has no behavioral bug in it, only large well-tested cold-path files that would benefit from mechanical decomposition.
