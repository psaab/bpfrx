# #2072 — route-filter `upto /N` match-type silently ignored

Status: v2 — both round-1 reviewers' PLAN-NEEDS-MAJOR findings folded
(FRR idiom fixed to bare `le N`); ready to implement. See "v2 —
adversarial plan-review resolution" at the bottom.

## Issue framing

`from route-filter <prefix> upto /N` is a documented, accepted Junos
match-type (config schema accepts it; `config.RouteFilter` already
carries `MatchType string` and `UptoLen int`). But two gaps make it a
no-op that silently over-matches:

1. **Compiler never reads the length token.** Both compile paths in
   `pkg/config/compiler_routing.go` build the `RouteFilter` from only
   `Keys[1]` (prefix) and `Keys[2]` (match-type) and never read the
   trailing `/N` length token, so `UptoLen` is always 0.

2. **Renderer has no `upto` case.** The `switch rf.MatchType` in
   `pkg/frr/policy_render.go` handles `exact`, `longer`, `orlonger`
   only. `upto` falls through to the default `matchStr` set above the
   switch (`le 32` for v4 / `le 128` for v6).

Net effect: `route-filter 10.0.0.0/8 upto /24` renders as
`ip prefix-list ... permit 10.0.0.0/8 le 32` — it matches every
more-specific down to /32 instead of stopping at /24, i.e. it behaves
identically to `orlonger`. The operator's intent (exclude prefixes
longer than /24) is silently discarded.

## Honest scope / value framing

This is a **correctness fix** in the control plane (FRR config
generation), not a perf change. The win is that `upto /N` now enforces
the configured upper bound instead of over-matching. Blast radius is
small and contained to two functions plus the new struct-field read.
There is no dataplane (Rust/AF_XDP) impact and no hot path — this is
config compile + FRR text render only.

If reviewers conclude the fix is wrong (e.g. wrong FRR idiom, wrong
AST-token location), PLAN-KILL / PLAN-NEEDS-MAJOR is an acceptable
verdict.

## What's already in place

- `config.RouteFilter{ Prefix, MatchType, UptoLen }` already declares
  `UptoLen int` (`pkg/config/types_routing.go:62-66`) — no type change
  needed for `upto`.
- `pkg/frr/policy_render.go` was just reworked by #2071 (merged) to make
  the route-filter / prefix-list match family-aware (emit `ipv6
  prefix-list` + `match ipv6 address` for v6, exactly one matcher per
  route-map index). This plan extends the **match-type** branch of that
  same family-aware path; it does not touch the family selection logic.
- Existing render tests: `TestRouteFilterExactFRR`,
  `TestRouteFilterFRR` (v4+v6 exact) in `pkg/frr/frr_test.go`.
- Existing compile test: `TestPolicyOptionsSetSyntax` in
  `pkg/config/parser_security_test.go` (flat-set exact).

## AST shapes verified (load-bearing — drove the design)

`route-filter 10.0.0.0/8 upto /24` reaches the compiler in TWO distinct
shapes, confirmed empirically:

- **Brace parse** (`NewParser`): one leaf node,
  `fc.Keys = ["route-filter","10.0.0.0/8","upto","/24"]`, no children.
  Length token is `fc.Keys[3]`.
- **Flat set** (`ParseSetCommand` + `SetPath`):
  `fc.Keys = ["route-filter","10.0.0.0/8","upto"]` with a single child
  `Keys=["/24"]`. Length token is `fc.Children[0].Keys[0]`.

Both shapes are dispatched through `parsePolicyTermChildren` (the term
node has children in both cases, because `from` is always a child
node). The `parsePolicyTermInlineKeys` path is, for route-filter,
effectively dead code under the current schema (a `term` with a `from`
clause always produces a `from` child, never inline `from` keys), but
we patch it as belt-and-suspenders so it cannot silently drop the
length if dispatch ever changes; it reads the length at `keys[i+3]`.

Flat-set single-line caveat (does NOT affect the length read): if the
ENTIRE term is written on one `set` line
(`... route-filter 10.0.0.0/8 upto /24 then accept`), SetPath folds the
trailing clause tokens into the route-filter child leaf
(`Children[0].Keys=["/24","then","accept"]`) and `then accept` is lost
— a pre-existing flat-set limitation, not introduced here. The length
is still `Children[0].Keys[0]="/24"`, so the `upto` fix reads it
correctly. Real configs use one `set` line per clause (multi-line),
where the child is exactly `["/24"]`.

The `/N` token is one lexer token, a `/`-prefixed length (e.g. `/24`) —
empirically confirmed whole in both AST shapes (the lexer treats `/` as
an identifier char). Parse it by stripping the leading `/` and
`strconv.Atoi` on the remainder.

## Concrete design

### Compiler (`pkg/config/compiler_routing.go`)

A small shared helper to parse a `/N` length token:

```go
// parseRouteFilterLen parses a Junos route-filter length token of the
// form "/24" (leading slash) or "24". Returns (n, true) on success.
func parseRouteFilterLen(tok string) (int, bool) {
    tok = strings.TrimPrefix(tok, "/")
    n, err := strconv.Atoi(tok)
    if err != nil || n < 0 || n > 128 {
        return 0, false
    }
    return n, true
}
```

`parsePolicyTermChildren` route-filter case — after building `rf`,
populate `UptoLen` when `MatchType == "upto"` from whichever shape
carries the length:

```go
case "route-filter":
    if len(fc.Keys) >= 3 {
        rf := &RouteFilter{Prefix: fc.Keys[1], MatchType: fc.Keys[2]}
        if rf.MatchType == "upto" {
            // brace shape: length is Keys[3]; flat-set shape: length
            // is the single child's first key.
            if len(fc.Keys) >= 4 {
                if n, ok := parseRouteFilterLen(fc.Keys[3]); ok {
                    rf.UptoLen = n
                }
            } else if len(fc.Children) > 0 && len(fc.Children[0].Keys) > 0 {
                if n, ok := parseRouteFilterLen(fc.Children[0].Keys[0]); ok {
                    rf.UptoLen = n
                }
            }
        }
        term.RouteFilters = append(term.RouteFilters, rf)
    }
```

`parsePolicyTermInlineKeys` route-filter case — read the length at
`keys[i+3]` when present and the match-type is `upto`, consuming it:

```go
case "route-filter":
    if i+2 < len(keys) {
        rf := &RouteFilter{Prefix: keys[i+1], MatchType: keys[i+2]}
        consumed := 2
        if rf.MatchType == "upto" && i+3 < len(keys) {
            if n, ok := parseRouteFilterLen(keys[i+3]); ok {
                rf.UptoLen = n
                consumed = 3
            }
        }
        term.RouteFilters = append(term.RouteFilters, rf)
        i += consumed
    }
```

### Renderer (`pkg/frr/policy_render.go`)

Add an `upto` case to the existing `switch rf.MatchType`. Junos `upto
/N` = the prefix itself plus all more-specifics with length ≤ N. The
correct, FRR-safe idiom is **bare `le N`** (NO `ge`), mirroring the
existing `orlonger` case (which is bare `le max`) but capped at N:

```go
case "upto":
    // upto /N = this prefix or any more specific, but no longer than
    // /N. FRR renders this as a bare "le N" — the implicit lower bound
    // of a le clause is the prefix's own mask length, so "le N" matches
    // the prefix itself plus every more-specific down to /N. This
    // mirrors the orlonger case (bare "le max"), just capped at N.
    //
    // FRR requires len < le-value (and len < ge-value); a le/ge equal
    // to or below the prefix length is REJECTED by FRR's prefix-list
    // validator ("make sure: len < ge-value <= le-value") and an
    // invalid line can fail the whole frr-reload. So:
    //   - UptoLen > plen      -> "le N"   (the normal case)
    //   - UptoLen == plen     -> ""       (exact: only the prefix itself)
    //   - UptoLen < plen / 0  -> leave the default (orlonger-equivalent),
    //                            degrade-safe; never emit an invalid line.
    parts := strings.SplitN(rf.Prefix, "/", 2)
    if len(parts) == 2 {
        if plen, err := strconv.Atoi(parts[1]); err == nil {
            maxLen := 32
            if strings.Contains(rf.Prefix, ":") {
                maxLen = 128
            }
            switch {
            case rf.UptoLen == plen:
                matchStr = "" // upto /plen on a /plen == exact match
            case rf.UptoLen > plen && rf.UptoLen <= maxLen:
                matchStr = fmt.Sprintf("le %d", rf.UptoLen)
            }
        }
    }
```

`le N` (no `ge`) on `10.0.0.0/8 upto /24` renders
`permit 10.0.0.0/8 le 24`, semantically `8 <= len <= 24` — exactly
Junos `upto /24`. The existing `longer` case proves the codebase
already follows the `len < value` rule (it uses `ge plen+1`, strictly
greater). An earlier draft of this plan emitted `ge plen le N`; that is
wrong — FRR rejects `ge == plen` ("len < ge-value" is required; pfSense
FRR docs, FRR `filter.html`, VyOS T3133, FRR issue #9355). Bare `le N`
is the canonical FRR form for Junos `upto` (FRR docs worked example:
`permit 10.0.0.0/8 le 24` matches the /8 plus all more-specifics up to
/24).

## Public API preservation

- `config.RouteFilter` gains no new field (UptoLen already exists). No
  signature changes to `parsePolicyTermChildren`,
  `parsePolicyTermInlineKeys`, `generatePolicyOptions`,
  `CompileConfig`.
- `parseRouteFilterLen` is a new unexported helper — purely additive.

## Hidden invariants the change must preserve

- **Other match-types unchanged.** `exact` (no ge/le), `longer`
  (`ge plen+1 le max`), `orlonger` (default le max) render byte-
  identical to today. The new `case "upto"` only intercepts `upto`.
- **Family-aware path (#2071) untouched.** The v4/v6 prefix-list
  keyword + single-matcher selection logic is not modified.
- **Degrade-safe.** If `UptoLen` is 0/invalid (e.g. a config that
  somehow stored `upto` with no length), the renderer falls back to the
  prior default `matchStr` — and never emits a `le`/`ge` value ≤ the
  prefix length, which FRR rejects ("len < ge-value <= le-value") and
  which could fail the whole frr-reload. This is why the render guard is
  `UptoLen > plen` (strict) and `UptoLen == plen` renders as bare exact.
- **Inline-key index advance.** `parsePolicyTermInlineKeys` must
  advance `i` by exactly the number of tokens consumed (2 normally, 3
  when an `upto` length is consumed) so the next clause keyword is not
  misread as a value.
- **Compile-store round-trip.** `UptoLen` is set at compile; it is not
  persisted separately — it is re-derived from the AST on every
  compile, so no migration concern.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression (other match-types) | LOW | new case is additive; default `matchStr` fallback preserved |
| Lifetime / borrow (Go) | N/A | Go, no borrow checker; no goroutines/shared state |
| Performance regression | NONE | config-compile + text render only, not hot path |
| Architectural mismatch | LOW | extends an existing switch + an existing field; no new abstraction |
| FRR-idiom wrong | RESOLVED | v1 draft `ge plen le N` was wrong (FRR rejects `ge == plen`); fixed to bare `le N` + `==plen→exact`, confirmed against FRR docs/VyOS T3133/FRR #9355 by both plan reviewers; covered by render tests asserting `le N`, no `ge`, no `le 32`/`le 128` |

## Test plan

All Go (no smoke — zero dataplane code touched, control-plane only):

- `pkg/config` compile tests (NEW), non-tautological (fail pre-fix):
  - Flat-set via `ParseSetCommand` + `SetPath`:
    `route-filter 10.0.0.0/8 upto /24` → `UptoLen == 24`,
    `MatchType == "upto"`.
  - Brace parse via `NewParser`: same config → `UptoLen == 24`.
  - v6: `route-filter 2001:db8::/32 upto /48` → `UptoLen == 48`.
  - Regression: `exact`/`longer`/`orlonger` still compile with
    `UptoLen == 0`.
- `pkg/frr` render tests (NEW), non-tautological (fail pre-fix):
  - `upto /24` on `10.0.0.0/8` → contains
    `ip prefix-list ... permit 10.0.0.0/8 le 24`, and contains NO `ge `
    and NO `le 32`.
  - v6 `upto /48` on `2001:db8::/32` →
    `ipv6 prefix-list ... permit 2001:db8::/32 le 48`, no `ge `, no
    `le 128`.
  - Edge `upto /8` on `10.0.0.0/8` (UptoLen == plen) → bare
    `permit 10.0.0.0/8` (exact, no `le`/`ge`).
  - Degrade: `upto` with `UptoLen == 0` falls back to default le 32 (no
    invalid line).
  - Regression: `exact`/`longer`/`orlonger` byte-identical to current.
- `go build ./...`, `go vet ./pkg/config/... ./pkg/frr/...`.
- Full `go test ./...`.
- Affected named tests 5x flake check.

## Out of scope (explicitly)

- **`prefix-length-range /min-/max`** and **`through <prefix>`** match
  types. These are ALSO currently unhandled (no compiler field for
  min/max range; renderer has no case → defaults to le 32). Fixing them
  requires new `RouteFilter` fields (RangeMin/RangeMax or ThroughLen) +
  parse + render + tests — a larger change than #2072's `upto`. They are
  a separate, pre-existing gap and should be a follow-up issue, not
  folded here. This plan touches ONLY `upto`.
- Config-schema completion for the `upto /N` value slot (the schema
  already accepts the tokens; this is a render/compile correctness fix).
- **Commit-time rejection of invalid `upto`** (missing length, or
  `UptoLen <= prefix-len`). Junos rejects these at commit; this plan
  degrades them safely at render (default / exact, never an invalid FRR
  line) but does not add a typed-leaf commit validator. That is a
  separate hardening — FILE A FOLLOW-UP issue for a `setSchema` /
  `SchemaValidate` typed-leaf check. Both plan reviewers agreed the
  degrade-then-follow-up split is acceptable for this correctness PR.

## Open questions for adversarial review

1. **FRR idiom.** Is `<prefix> ge <prefix-len> le N` the correct FRR
   prefix-list rendering of Junos `upto /N`? Specifically: does FRR
   treat `ge <prefix-len>` as redundant-but-valid (equivalent to
   omitting `ge` and writing only `le N`)? If `ge plen` is rejected or
   changes semantics when `plen == le`, the render is wrong — PLAN-KILL.
2. **AST token location.** Are the three token shapes (brace `Keys[3]`,
   flat-set child `Children[0].Keys[0]`, inline `keys[i+3]`) the
   complete set? Is there a fourth shape (e.g. mixed) that would still
   drop the length? The plan claims empirical verification of the first
   two; challenge the inline path.
3. **Degrade behavior.** Is silently falling back to `le 32/128` when
   `UptoLen` is invalid the right call, or should the compiler reject
   the config at commit time (return an error) so the operator learns
   the length was unparseable? Junos rejects a route-filter `upto` with
   no length at commit. Should we?
4. **`upto /N` where N < prefix-len.** Junos rejects `10.0.0.0/8 upto
   /4` (upto shorter than the prefix). The plan's render guard
   (`UptoLen >= plen`) silently drops to default instead of erroring.
   Is commit-time rejection warranted?
5. **`upto` at exactly the prefix length** (`10.0.0.0/8 upto /8`).
   Renders `ge 8 le 8` = exact-match-only. Is that the correct Junos
   semantic for `upto /8` on a /8? (It should match only 10.0.0.0/8
   itself — yes.)
6. **Inline-path `i` advance.** Confirm the variable `consumed`
   increment is correct and cannot skip or double-read a following
   clause keyword (e.g. `... upto /24 then accept`).

## v2 — adversarial plan-review resolution

Round 1: Codex = PLAN-NEEDS-MAJOR, hostile Claude reviewer (Gemini
companion was down) = PLAN-NEEDS-MAJOR. Both converged on the same root
cause. Resolutions folded into v2 above:

- **Q1 FRR idiom (BLOCKER, both reviewers): FIXED.** The v1 `ge plen
  le N` form is wrong — FRR requires `len < ge-value` and rejects
  `ge == plen`, which would be the common case and could fail the
  managed frr-reload. v2 renders bare `le N` (mirrors `orlonger`), with
  the guard `UptoLen > plen`. Confirmed correct against FRR `filter.html`,
  pfSense FRR docs, VyOS T3133, FRR issue #9355.
- **Q5 / `==plen` edge (BLOCKER, Claude): FIXED.** `upto /8` on a /8
  renders bare `permit <prefix>` (exact), not `le 8` (which FRR also
  rejects, `le == len`).
- **Q2 `/` tokenization (Codex MAJOR): REFUTED empirically.** `/24` is a
  single lexer token in both AST shapes (verified by throwaway probe);
  no off-by-one. Brace `Keys[3]="/24"`, flat-set child `Keys[0]="/24"`.
- **Q2 flat-set shape description (Claude): CLARIFIED.** Single-line
  set folds trailing clause tokens into the child leaf; multi-line (real
  configs) gives child exactly `["/24"]`. Length read is correct either
  way. Inline path is dead code for route-filter — patched as
  belt-and-suspenders, framing softened.
- **Q3/Q6 inline index advance: CONFIRMED correct** by both (dead code
  regardless).
- **Q4 degrade vs commit-reject: degrade-safe + follow-up.** Both
  reviewers accepted silent degrade (now never an invalid FRR line) for
  this correctness PR, with a follow-up issue for commit-time typed-leaf
  validation. Recorded in Out of scope.

Status: PLAN v2 — both reviewers' MAJOR findings folded; ready to
implement.
