# Triage Result — ps-review-036-cohort1.md (Policy Verdict Engine RE-AUDIT)

- **Cohort**: Cohort 1 — Policy verdict engine (`userspace-dp/src/policy.rs` + Go compile/lower layer)
- **Review base**: 33b891d11 (merge PR #4563, navigatePath fix) — **STALE by 3 commits** vs 0b4109522 at task time; current `origin/master` = **bfe83c531** (further ahead)
- **Stale-base verdict**: NO false-open risk. `git log 33b891d11..origin/master` touching the two cited finding files (`policies_addrbook.go`, `policies_lower.go`, `builder.go`, `policy.rs`) = **EMPTY**. Both findings verified byte-identical against current `origin/master`.
- **Prior coverage**: ps-025 covered this engine → 0 genuine residuals (hardened by the #2124 fail-closed family). This re-audit CORROBORATES that: reviewer found NO new High/Med fail-open across ~14 modules and 60+ negative-path verifications.
- **Outcome counts**: GENUINE-RESIDUAL (novel) **0** · NOT-MATERIAL **2** (L-01, L-02) · DUP 0 · ALREADY-FIXED 0 · DELIBERATE 0 · CONFABULATED 0 · NEGATIVE (verified fail-closed inventory) ~60 (reviewer's supporting evidence, not standalone findings).
- **#4569 overlap check**: The review discusses the non-first-fragment port-bearing-DENY-falls-to-default scenario (lines 114, 126-127) but explicitly treats it as a KNOWN documented/deferred limitation, NOT as a filed finding. This is exactly the #4569 (frag DENY bypass) case, correctly NOT re-reported as a new finding. No DUP #4569 finding to flag.

---

## Per-finding dispositions

### L-01 — `normalizeAnyInCIDRs` dead no-op → NOT-MATERIAL (known, previously-triaged)

**Symbol EXISTS.** `git show origin/master:pkg/dataplane/userspace/policies_addrbook.go` — function at line 399, called at line 202. Code matches the review's evidence exactly:
```go
func normalizeAnyInCIDRs(v4, v6 []string) ([]string, []string) {
    hasAny4 := false; hasAny6 := false
    cleanV4 := v4[:0]
    for _, s := range v4 { if s == "0.0.0.0/0" { hasAny4 = true }; cleanV4 = append(cleanV4, s) }
    cleanV6 := v6[:0]
    for _, s := range v6 { if s == "::/0" { hasAny6 = true }; cleanV6 = append(cleanV6, s) }
    _ = hasAny4; _ = hasAny6
    return cleanV4, cleanV6   // input returned unchanged
}
```

**Why NOT-MATERIAL (not a genuine residual):**
- The function is genuinely dead — it computes `hasAny4/hasAny6`, discards them, and returns the input via `v4[:0]` slice-reuse. It filters nothing. Confirmed.
- **No security impact / no fail-open.** Its only role is address-book content-equality dedup (whether two content-identical books share one runtime u32 ID). Failing to collapse `0.0.0.0/0` vs `any`-expanded means two books get distinct canonical bytes → two runtime rows instead of one. **Both rows still contain `0.0.0.0/0` and match-all identically** — a `deny` still denies, a `permit` still permits. No extra permit, no missed deny. The worst downstream effect is snapshot bloat, and if bloat ever tripped `MaxRulesPerPolicy` (256) the result is a fail-**closed** config reject, never a fail-open.
- The `v4[:0]` aliasing is harmless: `v4`/`v6` are locals in `buildAddressBookTableWithFeeds`, freshly produced by `expandBookNameToCIDRs`, not shared with any caller that reads the backing array afterward. And the very next lines re-sort+`dedupSortedStrings`, so ordering/dup state is normalized regardless.

**Why not higher / why not filed:** This is the reviewer's own L-01 and its dedup note is accurate — F-124/F-145 in `/tmp/all_findings.txt`, noted in ps-review-019 §5.2.4, -022, -024, -025, **never filed as a GH issue** because every prior triage correctly classified it Low/dead-code/harmless. This re-audit re-states it with full code evidence at the same Low/harmless bar. Consistent prior triage → keep as NOT-MATERIAL (dead-code cleanup nicety, no security residual). Not novel.

### L-02 — `policyActionString` default-arm ↔ Rust `parse_action` coupling → NOT-MATERIAL (robustness nit; fail-closed today AND in the hypothetical)

**Symbols EXIST.** `policies_lower.go:221` (`policyActionString`), `builder.go:93` (`DefaultPolicy: policyActionString(...)`), `policy.rs:2530-2533` (`parse_action(default_policy).ok_or_else(...UnknownPolicyAction)`), `policy.rs:3980` (`fn parse_action`). All match the review's evidence.

**Premise verified against the enum.** `pkg/config/types_security.go:459-465`:
```go
type PolicyAction int
const ( PolicyPermit PolicyAction = iota; PolicyDeny; PolicyReject )   // exactly 3 values
```
`policyActionString` maps `PolicyPermit→"permit"`, `PolicyReject→"reject"`, `default→"deny"` (which catches `PolicyDeny`). All three real values map to the three valid Rust tokens. The Rust `UnknownPolicyAction` reject arm is therefore **unreachable from any clean Go build** — Go only ever emits one of the three known tokens.

**Why NOT-MATERIAL (not a genuine residual):**
- **No current fail-open.** The review concedes this ("This is NOT a current fail-open"). Today the mapping is exhaustive and correct; the `default:` arm handles `PolicyDeny` correctly.
- **The hypothetical is fail-CLOSED, not fail-open.** The finding posits a *future* 4th `PolicyAction(99)` silently collapsing to `"deny"`. Even in that invented case: mapping a would-be reject/drop action to `"deny"` still **blocks the traffic** (silent drop vs RST) — a cosmetic loss of RST behavior, not a permit. There is no scenario where the default arm turns a block into a pass. So it is not even a *latent* fail-open.
- This is a defensive-coding / exhaustiveness observation (add explicit `case PolicyDeny` + a cross-language contract test), not a security bug. Severity is style/robustness-Low at most.

**Novelty:** The reviewer's dedup note claims this specific Go-`default`-arm↔Rust-hard-reject coupling is not in F-001..F-274, GH issues, or ps-018..035. I did not exhaustively re-scan those corpora, but the observation is plausibly novel *as a stated defensive-coding nit*. It does **not** clear the bar for a NOVEL GENUINE-RESIDUAL because there is no real bypass — a policy fail-open must trace to real code admitting traffic that should be blocked, and this path admits nothing (it is fail-closed today and fail-closed in the hypothetical). Classified NOT-MATERIAL.

---

## Weight-verification notes

- Both findings trace to real, current code (verified via `git show origin/master`), so neither is CONFABULATED.
- Neither is a misread of a #2124-hardened path being reported as open — the reviewer explicitly and correctly classifies both as Low/non-fail-open, and my independent read confirms fail-closed (L-01: identical enforcement + fail-closed overflow; L-02: block preserved in every arm).
- The review's core verdict — policy verdict engine has **no new High/Med fail-open on HEAD**, fully hardened by the #2124 family — is corroborated. Spot-checked negatives (#3110 unzoned→default, #3405 empty-zone default-deny, #2008 excluded empty-both fail-closed, #4024 flowless MissingNeighbor policy enforcement, #4569 frag-DENY documented-limitation) all hold and match filed/tracked state.
- No overlap re-report of #4569, #2387, or #4146 as findings. The frag scenario is discussed as the known deferred limitation (now = #4569), consistent with dedup expectations.

## Bottom line
No novel genuine residuals. Two Low findings, both NOT-MATERIAL: L-01 is a known, harmless, repeatedly-noted dead-code no-op (never filed by prior triage — correct); L-02 is a fail-closed defensive-coding nit with no current or hypothetical fail-open. Nothing to file. Re-audit confirms ps-025's "0 genuine residuals" for the policy verdict engine.
