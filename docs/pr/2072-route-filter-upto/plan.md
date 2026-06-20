# #2072 — route-filter `upto /N` match-type silently ignored

Status: DRAFT v1 — pending adversarial plan review

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
node has children in both cases). A third, fully-flat shape
(`parsePolicyTermInlineKeys`, where the whole `from route-filter ...`
run is packed into one node's `Keys`) reads the length at `keys[i+3]`.

The `/N` token is a `/`-prefixed length (e.g. `/24`); parse it by
stripping the leading `/` and `strconv.Atoi` on the remainder.

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
/N` = the prefix itself plus all more-specifics with length ≤ N. FRR
idiom: `<prefix> ge <prefix-len> le N`. Mirror the existing `longer`
case's family-aware max derivation; clamp/validate against `UptoLen`:

```go
case "upto":
    // upto /N = this prefix or any more specific, but no longer than
    // /N. FRR: "ge <prefix-len> le N". If UptoLen is unset/invalid,
    // fall back to the prior orlonger-equivalent default (le 32/128)
    // so a malformed config degrades to the pre-fix behavior rather
    // than producing an invalid prefix-list line.
    parts := strings.SplitN(rf.Prefix, "/", 2)
    if len(parts) == 2 {
        if plen, err := strconv.Atoi(parts[1]); err == nil {
            maxLen := 32
            if strings.Contains(rf.Prefix, ":") {
                maxLen = 128
            }
            if rf.UptoLen >= plen && rf.UptoLen <= maxLen {
                matchStr = fmt.Sprintf("ge %d le %d", plen, rf.UptoLen)
            }
        }
    }
```

`ge <prefix-len>` is the FRR default lower bound for a `le` clause, so
`ge 8 le 24` on `10.0.0.0/8` is semantically `8 <= len <= 24` — exactly
Junos `upto /24`. Emitting `ge <prefix-len>` explicitly mirrors the
`longer` case style and is unambiguous.

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
  prior default `matchStr` — no invalid `ge X le Y` with Y<X is ever
  emitted (which FRR would reject and could fail the whole reload).
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
| FRR-idiom wrong | MED | the one real risk — `ge plen le N` semantics must equal Junos `upto`; covered by render tests asserting exact output |

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
    `ip prefix-list ... permit 10.0.0.0/8 ge 8 le 24` and NOT `le 32`.
  - v6 `upto /48` on `2001:db8::/32` →
    `ipv6 prefix-list ... permit 2001:db8::/32 ge 32 le 48`, not `le 128`.
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
