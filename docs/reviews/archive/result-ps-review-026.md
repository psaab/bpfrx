# Triage result — ps-review-026 (Cohort 2: Config + schema compilation)

- **Cohort**: 2 — Config path (lexer / parser / ast / ast_groups / ast_edit / inactive / schema / schema_walk / compiler / compiler_nat / types), bracket-list (#2419 class), apply-groups, inactive:, lenient-vs-strict, bracket stripping.
- **Review base**: b1bd96fb6 (merge #4531).
- **Triaged against**: current `origin/master` = **af5b739308** (fetched). Base ≈ current master, FRESH (only a handful of commits ahead; none touch the disputed symbols).
- **Real bpfrx code or avacado?**: **REAL bpfrx.** Every cited symbol exists on `origin/master` (`isIdentChar` lexer.go:289, `validateMultiValueLeaf` schema_walk.go:665, `appendPoolAddresses`, `mergeNodes`/`isLeafListSchema`, `removeMultiLeafMembers`, etc.). NOT the ps-021 avacado-confabulation class. No CONFABULATED findings.
- **Outcome counts**: 0 GENUINE-RESIDUAL (driveable) · 1 NOT-MATERIAL/DELIBERATE (NEW-01) · 1 DUP+NOT-MATERIAL (NEW-02 = F-043) · 6 NEGATIVE (NEG-01..06, reviewer-verified-clean, code-consistent) · 3 informational notes (all dedup'd / documented).

This is a heavily-audited cohort. The review itself found **no High** and self-downgrades both of its two "NEW" findings. My independent verification confirms neither is a driveable residual.

---

## Findings

### NEW-01 — `@` removed from `isIdentChar` "breaks unquoted `scp://user@host/path` archive-sites" — **NOT-MATERIAL / DELIBERATE (Low parity-gap, not a revert regression)**

- **Reviewer rating**: Low severity / Medium confidence; escalated to "Medium priority" in the issue-split with label `drop-in-blocker`.
- **Symbol reality**: CONFIRMED real. `isIdentChar` (pkg/config/lexer.go:289) on current master does NOT include `@`. Matches the review's evidence block verbatim.
- **Disposition: NOT-MATERIAL / DELIBERATE.** The review's central causal claim — that the **#4530 revert (bd870991e) introduced scope creep that broke archive-sites** — is **factually wrong**. Git history:
  - `2c24ac842` (CoS #1398) and every commit before it: `isIdentChar` has **no `@`**.
  - `8a2d4f365` ADDED `@` (R-04).
  - `bd870991e` (#4530) REVERTED, removing `@`.
  So `@` lived in `isIdentChar` only for the brief `8a2d4f365 → bd870991e` window inside this same review cohort. On **stable master, unquoted `scp://user@host/path` has NEVER parsed**. The revert **restored** long-standing behavior; it did not "break" archive-sites. The review's trace step ("the revert DOES break archive-sites with scp://user@host") is the faulty step — it treats a pre-existing, deliberate exclusion as a new revert-induced regression.
- **The exclusion is load-bearing / deliberate**, not an oversight: `nodesToJSON` (pkg/config/ast_format.go:551) emits the deactivation marker key `"<keypath> @inactive"` and documents *"The `@` sigil is not a valid Junos identifier character (lexer.isIdentChar), so the marker key can never collide with a real configuration key."* Adding `@` back to `isIdentChar` would violate that #2008-H1 collision-safety invariant. So the reviewer's suggested "fix direction" (re-add `@` globally, reject at the monitor-traffic validator) would **regress** a separate hardened path.
- **Workaround exists and is the standard Junos form**: URLs with `@` in userinfo are configured **quoted** — `set system archival configuration archive-sites "scp://user@host/path"`. Quoted values lex as `TokenString` and bypass `isIdentChar` entirely. Evidence the codebase already assumes the quoted form everywhere `@` appears in a value: `login_password_test.go:68/102` (`ssh-ed25519 "... op@host"` quoted), `parser_system_test.go:321` (`"ssh-rsa AAAA... user@host"` quoted). The DDNS url-template path (`compiler_validate_warn.go:2235`) also carries `%p@host` userinfo and is handled string-based, not as a bare identifier.
- **No parse-path test regresses**: the #651 archive-sites test (`parser_ast_test.go:5024`, `TestValidateConfig_ArchiveSitesPasswordWarns`) builds the `Config` struct directly with `ArchiveSites: ["scp://alice@host1/configs"]` — it never feeds an **unquoted** URL through the lexer/parser, so it neither proves nor breaks on the `@` behavior.
- **Why not higher / why not a residual to drive**: it is (a) not a regression (long-standing), (b) a deliberate design choice with a documented dependent invariant, (c) fully worked around by quoting (the correct Junos form). At most this is a LOW parity-gap tracker ("accept unquoted `@` in URL-bearing leaves") — but implementing it via `isIdentChar` is actively wrong (breaks `@inactive`), so it would need a scoped validator-aware approach and is not obviously desirable. Recommend **file-only as a Low parity-gap** if the parent wants a tracker, NOT drive as a bug.

### NEW-02 — `validateMultiValueLeaf` treats literal `to` as range separator on every typed multi-value leaf — **DUP F-043 + NOT-MATERIAL (safe in practice)**

- **Reviewer rating**: Low / Medium, and the review **explicitly dedups this as F-043** ("this is the same finding, already tracked… Not new… safe in practice. Dedup'd.") and downgrades to informational in its own summary.
- **Symbol reality**: CONFIRMED real. `validateMultiValueLeaf` (pkg/config/schema_walk.go:665). The `to`-separator loop matches the evidence.
- **Disposition: NOT-MATERIAL, DUP F-043.** Verified the logic is safe against all three malformed `to` shapes:
  - leading `to` → `!validatedAny` → `"missing value"` error (line ~673).
  - double `to` → `lastWasSeparator` → error.
  - trailing `to` → post-loop `if lastWasSeparator` → error (line ~686).
  The only theoretical mis-parse is a typed multi-value leaf whose **value domain includes the literal string `"to"`**. Every typed multi-value leaf's `valueType` is IP / CIDR / port / prefix-list-name / zone-name / etc. — none can equal `"to"`. The `checkValue` validator would reject `"to"` as a value regardless. So no fail-open, no value-drop. Untyped multi leaves (policy match-address, NAT pool `address`) never reach this function (they have `valueType==ValueAny` → walker returns nil; NAT pool addresses go to `appendPoolAddresses` which range-expands `to` correctly, #4521).
- **Why not higher**: defensive-only; would require a future leaf whose free-form value legitimately is `"to"` to bite, and Junos itself reserves `to` as its range keyword. Correctly a hardening/documentation note, already tracked. No action.

### NEG-01..NEG-06 — reviewer-verified clean paths — **NEGATIVE (code-consistent)**

Spot-checked against current master; consistent with the code:
- **NEG-01** bracket-list (#2419): `appendPoolAddresses` reads full `Keys[1:]`+Children (verified compiler_nat.go), `removeMultiLeafMembers`, `firewallMatchValues` SSOT all present. No truncation fail-open.
- **NEG-02** apply-groups leaf-list UNION (#4070): `mergeNodes`/`isLeafListSchema`/`leafListUnionEligible`/`mergeLeafListInto` present; scalar OVERRIDE, range/`groupReplace`/args>=2 exclusions correct.
- **NEG-03** `inactive:` prune (leading vs inline, quoted preservation #4348, deactivate round-trip #3975): consistent.
- **NEG-04** lenient-vs-strict (#1960): lenient path is Load/SyncApply/peer-display only, never candidate-commit; no security bypass.
- **NEG-05** bracket stripping lossless in lexer.
- **NEG-06** `closedWorld` single production flip = DNAT `then` only (#4313 PR-B), leaf-complete; source-NAT deliberately open-world (#4191 class).

No hidden residual surfaced in the negatives.

### Informational notes in the review's split (not formal findings) — all NOT-MATERIAL / dedup'd

- **`IsIdentRune` vs `isIdentChar` Unicode asymmetry** — tab-completion may suggest a non-ASCII token the lexer would reject. No security impact, cosmetic completion-only. NOT-MATERIAL.
- **`isLeafListSchema` OVERRIDE fallback for unmodeled leaf-lists under apply-groups** — a not-yet-modeled leaf-list would OVERRIDE instead of UNION. Documented as the intentional opt-in gate (matches pre-#4070 behavior); parity/doc note as new leaves are added, not a bug today. NOT-MATERIAL / documented.
- **F-044 — 80-flag `compileOpts` literal duplicated in `CompileConfigLenient` / `CompileConfigForNodeLenient`** — refactor debt, already tracked as F-044 in /tmp/all_findings.txt. DUP, not re-reported.

---

## Bottom line

**Zero genuine driveable residuals.** The cohort is clean at af5b739308. NEW-01 rests on a factually incorrect "revert caused it" trace (the `@`-exclusion predates and outlives #4530, is deliberate, and is worked around by the standard quoted-URL form). NEW-02 is a reviewer-acknowledged dup of F-043 and provably safe. If the parent wants a paper-trail, NEW-01 could be filed as a **Low parity-gap tracker** ("accept `@` in unquoted URL-bearing leaves — but NOT via isIdentChar, which is load-bearing for `@inactive`"), but it is not a bug to drive.
