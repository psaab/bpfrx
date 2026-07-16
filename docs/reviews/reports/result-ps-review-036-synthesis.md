# Triage result — /tmp/ps-review-036.md (all-cohort SYNTHESIS roll-up)

- **Cohort**: ps-036 top-level SYNTHESIS ("all-cohort" roll-up of the ps-036 batch)
- **Review base**: `33b891d11` (stated in doc), ≈ current `origin/master`
- **Current master SHA at triage**: `d4506d4450e23f9a3fc572206b3c82f6b6c99029`
  (origin/master; the ps-036 base 33b891d11 is an ancestor — checkout advanced past it)
- **Real bpfrx or avacado?**: REAL bpfrx. Every cited symbol resolves in
  `git show origin/master:<path>`. No avacado tells (no `/home/ps/git/xpf`
  path, no redacted template base, symbols exist).
- **File length**: 137 lines. **TRUNCATED** at "(continues in full report)"
  — §5 and §6 (the detailed per-finding section) are NOT present in this file.
  Only §1 base commit, §2 output path, §3 dedup summary, §4 module/coverage
  inventory are present.

## Outcome counts

| Disposition | Count |
|---|---|
| NOVEL GENUINE-RESIDUAL (not covered by any ps-036 cohort filing or prior issue) | **0** |
| DUP of already-filed issue (ps-036 novel or prior open) | 30+ (all §3/§4 issue-referenced rows) |
| ALREADY-FIXED (CLOSED on this HEAD, dedup-verified) | 25+ (§3 CLOSED table) |
| NOT-MATERIAL | 5 (L-01 normalizeAny, M-01 rollback n=0, H-01 quote bypass, flex-cache moot, next-table overstated) |
| NEGATIVE / NOT-MATERIAL (fail-closed by design) | 1 (L-02 policyActionString default-arm) |
| DELIBERATE | 2 (isIdentChar `@` #4530 revert, bare-ACK/PSH mid-stream pickup) |

**Bottom line: 100% dup / non-novel, as expected.** The synthesis is a
dedup + coverage roll-up. It surfaces NO cross-cutting finding that no single
cohort filed. Its §6 detailed-findings section is not even included in this
file. There is nothing new to file.

---

## Per-finding disposition WITH reasoning

Because §6 is absent, the only "findings" in this file are the candidate LOW
items named in the §4 module-inventory table plus the dedup-table rows. Each:

### Candidate NEW items in §4 (the only non-issue-referenced rows)

**Cohort 1, L-01 — `normalizeAny` dead no-op → NOT-MATERIAL.**
Real symbol is `normalizeAnyInCIDRs` (`pkg/dataplane/userspace/policies_addrbook.go:399`).
Verified body: it sets `hasAny4`/`hasAny6` when it sees `0.0.0.0/0` / `::/0`,
then explicitly discards them (`_ = hasAny4; _ = hasAny6`) and returns the
input CIDRs unchanged (`cleanV4 = v4[:0]` then re-appends every element).
So the "normalize any" collapse it hints at is dead — but the OUTPUT is the
input verbatim, i.e. correct/no behavior change. This is dead-variable cruft,
not a security or correctness defect. The synthesis itself dispositions it
NOT-MATERIAL. Cohort-1 already triaged this session. Not novel, not filed.

**Cohort 1, L-02 — `policyActionString` default-arm → NEGATIVE / NOT-MATERIAL
(fail-closed).**
Verified `pkg/dataplane/userspace/policies_lower.go:221`:
```
switch action {
case config.PolicyPermit: return "permit"
case config.PolicyReject: return "reject"
default:                   return "deny"
}
```
The concern (a `default:` arm masking non-exhaustive enum handling) resolves
to SAFE behavior: any unrecognized `PolicyAction` maps to `"deny"` — the most
restrictive verdict (fail-CLOSED). This is the correct defensive posture, the
opposite of a fail-open bug. Adding a hypothetical future action would degrade
to deny, not permit. Marked "NEW Low but LOW value" by the synthesis; factually
it is a NEGATIVE (correct-by-design). Not novel, not worth filing.

**Cohort 2 — `isIdentChar` `@` handling → DELIBERATE.**
`@` sigil is intentionally not a valid Junos identifier char
(`pkg/config/lexer.go:289`, `ast_format.go:551` comment refs #4530 revert).
Deliberate, documented. Not a bug.

**Cohort 2 — `validateMultiValueLeaf` `to`-separator (F-043) → DUP.**
Already covered by #4556 (the "validateMultiValueLeaf 'to'-gate" LOW batch,
CLOSED on this HEAD) / F-043 in all_findings.txt. Synthesis marks it dup.

**Cohort 8 — flex cache moot, next-table overstated → NOT-MATERIAL.**
Prior-triage dispositions carried forward; both non-material per earlier cohort
triage. No new trace. Not novel.

**Cohort 12/13 — M-01 rollback n=0 → NOT-MATERIAL.**
Path actually returns HTTP 400 (fail-closed) on n=0 rollback; #4556 already
shipped the message + gRPC parity. Verified CLOSED. Not a fail-open.

**Cohort 12/13 — H-01 monitor-filter quote bypass → NOT-MATERIAL.**
Defense-in-depth LOW only; the primary `--` argument terminator holds, so it is
not exploitable. #4556 shipped the quote-strip residual. Verified CLOSED.

### Dedup-table rows (all DUP or ALREADY-FIXED — spot-verified via `gh`)

Every substantive item in §3/§4 maps to a tracked issue. Confirmed states:

- **#4569** OPEN — "non-first fragment bypasses port-bearing DENY when later
  permit-any exists (ps-036-c7 F-001)". DUP (ps-036 novel filing).
- **#4566** OPEN — "CachedThreeColorPolicers::push drops 3rd+ policer
  (ps-036-cohort8 F-003)". DUP.
- **#4567** OPEN — UDP-flood non-first fragment CMS bucket split. DUP.
- **#4555** OPEN — MAX_EXT_HDRS 6 vs 8 fail-closed parity. DUP.
- **#4565** OPEN — nat64 HA reverse-translation. DUP (#4512 family).
- **#4559** OPEN — deterministic NAT (CGNAT) advisory-only, unenforced. DUP
  (ps-034 M-01). Synthesis re-checked for a "new enforcement angle" — none;
  §6 not present, so no new trace shipped.
- **#4549** OPEN — 4 LOW hardening batch. DUP.
- **#4548** OPEN — VRRP MaxAdverInt no min clamp. DUP.
- **#2387** OPEN — bare 5-tuple session identity (S-001/V-01, P0). DUP.
- **#4498** OPEN — FRR sanitize-belt residual (Origin bare %s). DUP.
- **#3776** OPEN — flow-cache session-expiry stale-descriptor + SNAT reuse. DUP.
- **#4478 / #4455 / #4313 / #4146 / #3226 / #2852 / #2562 / #4533 / #4515 /
  #4512** OPEN — all pre-filed, no new trace. DUP.
- **ALREADY-FIXED (CLOSED, dedup-verified on this HEAD):** #4562 (navigatePath
  unionChildren), #4556 (cli/api LOW batch), #4544 (`mergeHostInbound` +
  `dedupHostInboundTokens` — symbol verified at
  compiler_security_zones.go:50-58), #4543 (screen malformed-TLV fail-closed),
  #4541, #4540, #4539 (has_syn gate), #4535, #4534, #4526, #4525, #4524, #4521,
  #4518, #4517, #4514, #4487/#4453/#4400, #4399/#4438, #4393, #4392,
  #4388/#4384/#4381/#4380, #3864, #4547, #4546.

## Cross-cutting check (the only way this synthesis could be NOT dup)

Weight-verified the specific hypothesis the task flags: does the roll-up expose
a finding that emerges only from combining cohorts (that no single cohort
filed)? Answer: **NO.** Every §4 cohort row terminates in either a filed issue,
a NOT-MATERIAL/DELIBERATE/NEGATIVE disposition already reached by that cohort's
own triage, or an ALREADY-FIXED CLOSED issue. The §6 detailed section that
could have carried a synthesized cross-cut is not present in the 137-line file.
No emergent/composite residual is surfaced.

## Confabulation / symbol-existence audit

All cited symbols exist on origin/master:
- `normalizeAnyInCIDRs` → policies_addrbook.go:399 ✓ (doc said "normalizeAny";
  minor name shorthand, not confabulated — real function found)
- `policyActionString` → policies_lower.go:221, builder.go:93 ✓
- `isIdentChar` → lexer.go:289 ✓
- `mergeHostInbound` / `dedupHostInboundTokens` → compiler_security_zones.go:50 ✓
No confabulated symbols.

## NOVEL GENUINE-RESIDUALs

**NONE.** Nothing to file. This synthesis is fully covered by prior ps-036
cohort filings and this session's backlog.
