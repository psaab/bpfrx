# Triage result — ps-review-036-cohort2.md (Cohort 2: Config + schema compilation)

## Header

- **Cohort:** 2 — Config + schema compilation (pkg/config lexer/parser/ast/schema/compiler)
- **Review base:** 33b891d11 (Merge #4563) — **3 commits behind** current master
  0b4109522 (0b4109522). The 3 delta commits (#4552 VRRP clamp, #4558
  cluster dup-node-id, #4564 NAT64 HA cross-node) touch **nothing in
  `pkg/config/`** (`git diff --stat 33b891d11..0b4109522 -- pkg/config/`
  is empty) — so **no stale-base false-opens** are possible in this cohort.
- **Master SHA at triage:** 0b4109522e7f4a93cb3b8ec7b7655483bb5a6b3f
- **RE-AUDIT** of the config/schema cohort. Prior triage ps-026 found 0 genuine
  here. This review self-concludes **HIGH: none, MEDIUM: none** and files no
  new issue. My independent verification concurs.

### Outcome counts

| Disposition | Count | Findings |
|-------------|-------|----------|
| GENUINE-RESIDUAL (novel) | **0** | — |
| DUP (ps-026 / F-nnn) | 2 | L-01, L-02 |
| ALREADY-FIXED | 1 (overlaps L-02, N-01) | L-02 (#4556/#4561), N-01 (#4562/#4563) |
| NOT-MATERIAL | 1 | L-03 |
| DELIBERATE | 1 (overlaps L-01) | L-01 (#4530) |
| NEGATIVE | 1 | N-01 |
| CONFABULATED | 0 | — |

Findings in the review: **HIGH none, MEDIUM none, L-01, L-02, L-03, N-01.**
Total genuine novel residuals: **0.**

---

## Per-finding dispositions

### HIGH — None
Review claims no new High. Verified: all prior HIGHs (#3842 dup match/then,
#3846 DeletePath, #3982 RenamePath, #4521 NAT pool, #4541 writeJSON, #4524
monitor injection) are already closed. No independent High surfaced. Concur.

### MEDIUM — None
Review claims no new Medium; deterministic-NAT enforcement gap #4559 stays
OPEN as a tracked advisory (parse fix #3864 landed; dataplane allocator is
the deferred follow-up; warning emitted in `compiler_validate_warn.go`).
Not re-filed. Concur — this is a tracked, intentional parity gap, not a
novel residual.

---

### L-01 — `isIdentChar` excludes `@` → unquoted `scp://user@host` fails to parse
**Disposition: DUP of ps-026 NEW-01 → DELIBERATE. Not a bug.**

- Symbol verified on master: `git show origin/master:pkg/config/lexer.go`
  → `isIdentChar` (lexer.go:289) does **not** include `ch == '@'`. Exists,
  matches the review's evidence exactly.
- **Why DELIBERATE / not a bug:** `_Log.md` (2026-07-07 entry) + commit
  `bd870991e` (#4530, "config lexer: revert R-04 `@` isIdentChar (broke #4099
  fail-closed test)") document that `@` was speculatively added by R-04 (a
  #4521/#4523 ride-along) and **reverted**. Adding `@` reclassifies a token
  like `SENTINEL@` from a *ParseError* into a clean identifier, which broke
  `TestLoadRescueConfigRedactedFailClosedOnParseError` (#4099) — the redaction
  fail-closed path depends on `@` producing a parse error. Additionally
  `ast_format.go:551` documents the `@` exclusion as **load-bearing** for the
  `"<keypath> @inactive"` marker (the `@` sigil can never collide with a real
  config key). Re-adding `@` regresses both #4099 and the #2008-H1 @inactive
  marker.
- **Which review-step is wrong:** none — the review itself correctly
  dispositions this as NOT-MATERIAL/DELIBERATE (WONTFIX) and does not file it.
  It merely re-surfaces a settled item.
- **Dedup:** ps-026 NEW-01 (refuted, DELIBERATE — #4530 revert restored
  long-standing behavior + guards the @inactive marker; workaround = quote the
  URL). Also the review's own ps-035 NEW-01. Exact dup. **Not filing.**

### L-02 — `validateMultiValueLeaf` treated literal `"to"` as a range separator on every typed multi leaf
**Disposition: DUP of ps-026 NEW-02 / F-043 → ALREADY-FIXED (#4556/#4561). Not a bug.**

- Symbols verified on master:
  - `schema.go:80` — `rangeSeparator bool` field exists (opt-in for
    `multi && children==nil` typed leaf).
  - `schema_walk.go:681` — `if leafSchema.rangeSeparator && tok == "to"` gate
    exists, with `lastWasSeparator` tracking and the trailing-separator reject
    at line 694. The `"to"` skip is now **gated behind `rangeSeparator`**, not
    unconditional.
- **Why ALREADY-FIXED:** commit `906b4deed` (#4556, L-01 "gate
  validateMultiValueLeaf 'to'-separator behind rangeSeparator"), merged in
  #4561. Production typed multi leaves (name-server, virtual-address,
  dns-server-address, session-log flags) do **not** set `rangeSeparator`, so
  a stray `"to"` is now validated as an ordinary value and rejected (invalid
  IP/enum) instead of silently skipped. Port-range / NAT-pool-address leaves
  are compiler-validated and never reach this walker, so no regression.
- **Dedup:** F-043 in `/tmp/all_findings.txt`; ps-026 NEW-02 (DUP F-043, now
  FIXED by #4556/#4561 rangeSeparator gate); review's own ps-035 NEW-02.
  Exact dup of an already-merged fix. **Not filing.**

### L-03 — `IsIdentRune` (Unicode) vs `isIdentChar` (ASCII) mismatch → "completion suggests a Unicode identifier that fails to parse"
**Disposition: NOT-MATERIAL (dead code; premise factually false). Novel claim, but no live code path — no user impact.**

This is the review's only NOVEL finding (it is NOT in ps-026, not in
`/tmp/all_findings.txt`, not a GH issue). It fails weight-verification.

- **Symbols verified on master:** both exist. `isIdentChar` (lexer.go:289)
  is ASCII-only (`a-z`/`A-Z`/`0-9` + punctuation). `IsIdentRune` (lexer.go:300)
  uses `unicode.IsLetter(r) || unicode.IsDigit(r)` — genuinely Unicode-wider.
  The divergence the review describes is real *at the source level*.
- **Why NOT-MATERIAL — the harm scenario has no code path.** The review's
  refutation section asserts: *"Checked `complete.go` uses `IsIdentRune` for
  tab completion boundary detection."* This is **factually false**:
  - `git grep -n IsIdentRune origin/master` returns **only** the definition
    (lexer.go:299-300) plus three `_Log.md` history notes. **Zero callers**
    in any `.go` file, production or test.
  - There is **no `complete.go`** in the tree (the completion file is
    `pkg/config/schema_complete.go`, which never references `IsIdentRune`).
  - CLI completion word-boundary handling is done by the external
    `chzyer/readline` library (`pkg/cli/cli.go`), not by `IsIdentRune`.
  - `IsIdentRune` is therefore **dead code** with a stale/misleading doc
    comment ("for use in tab completion"). Because nothing invokes it, the
    claimed "completion suggests `café`, then commit fails at the lexer"
    scenario **cannot occur** — the completer never consults `IsIdentRune`.
- **Which review-step is wrong:** the L-03 "Refutation attempted" step
  ("`complete.go` uses `IsIdentRune`…") is the false premise. It assumes a
  caller that does not exist. The severity ("completion suggests value that
  fails to commit") is built entirely on that non-existent caller, so the
  finding does not trace to a real mis-compile, silent-drop, or false-reject.
- **Residual (cosmetic only):** the sole real defect is a dead helper with an
  inaccurate comment — at most a tidy-up (delete `IsIdentRune`, or restrict it
  to ASCII to match `isIdentChar`, or fix the comment). No security, no
  parse/commit divergence, no user-facing behavior. Not worth an issue; the
  review itself declines to file it. **Not filing** — recorded here as
  NOT-MATERIAL with the disproving evidence (zero callers).

### N-01 — `navigatePath` intermediate descent now unions all same-prefix siblings (was first-only)
**Disposition: NEGATIVE + ALREADY-FIXED (#4562/#4563). Display-only, not a bug.**

- Symbols verified on master: `ast.go` `navigatePath` uses `unionChildren(...)`
  (the #4562 fix); `unionChildren` present. Callers confirmed **display-only**:
  `git grep navigatePath` → only `ast_format.go` (FormatPath/Set/JSON/XML/
  Inheritance/Compare). The compiler uses `findNode`/`findNodeWithParent`/
  `navigateToNode` — no forwarding/enforcement path touches `navigatePath`.
- **Why NEGATIVE:** the pre-fix first-only descent only affected scoped
  `show configuration ... | display set` output for duplicate sibling
  contexts; the underlying policy was always still *enforced* (compiler reads
  the full tree). No fail-open, no fail-closed. Fixed in `40a5ba8ec` (#4562),
  merged #4563, with RED-on-revert tests (`show_config_dup_context_4562_test.go`).
- **Dedup:** review's own ps-035 N-1; #4562/#4563 CLOSED. Already-fixed
  negative. **Not filing.**

---

## Weight-verification summary

Every finding was checked for: (a) symbol existence on `origin/master`
(all four cited symbols exist — **zero confabulations**); (b) dedup against
ps-026 + the filed/merged set (#4556/#4561, #4562/#4563, #4534/#4535, #2419,
#4406, #4521); (c) a real mis-compile / silent-drop / false-reject trace.

- L-01, L-02, N-01 are settled dups of merged fixes or documented deliberate
  behavior — re-surfaced, correctly self-dispositioned by the review.
- L-03 is the only novel claim and it **fails** the "trace to real code"
  gate: its harm depends on `IsIdentRune` being a live completion caller, but
  `IsIdentRune` has **zero callers** — it is dead code. Non-material.

**No NOVEL GENUINE-RESIDUAL in Cohort 2 on 33b891d11 / 0b4109522.**
