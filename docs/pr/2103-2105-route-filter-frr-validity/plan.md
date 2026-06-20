# #2103 + #2105 — route-filter FRR-validity: `longer` max-len + prefix CIDR validation

Status: DRAFT v1 — pending adversarial plan review

These two issues are siblings of #2072 (PR #2102, just merged), both
found in that PR's hostile code review, and both live in the same render
path (`pkg/frr/policy_render.go` `generatePolicyOptions`). Fixing them
together avoids a self-conflict in that file.

## Issue framing

### #2103 — `longer` /32 (/128) emits an FRR-invalid `ge plen+1 le max`

The `case "longer"` arm of the route-filter MatchType switch always
renders `ge <plen+1> le <maxLen>`. For a max-length prefix:

- `route-filter 10.0.0.0/32 longer` → `... permit 10.0.0.0/32 ge 33 le 32`
- `route-filter 2001:db8::1/128 longer` → `... permit 2001:db8::1/128 ge 129 le 128`

FRR's prefix-list validator requires `len < ge-value <= le-value <=
maxlen`. `ge 33 le 32` (ge > le AND ge > maxlen) is REJECTED, and a
rejected line can fail the whole managed `frr-reload`. Semantically,
"strictly more specific than a /32" is the empty set, so the correct
render is to emit NO prefix-list entry for that route-filter, not an
invalid line. This is the same class of FRR-validity hole #2072 closed
for `upto` (where the `plen >= maxLen -> exact ("")` guard already
handles the max-length edge).

### #2105 — route-filter prefix slot has no CIDR validator

`from route-filter <prefix> <match-type>` is a single schema node
(`pkg/config/schema_routing.go:87`, `args: 2`, no `keyValidator`). A
syntactically invalid prefix (no `/`, non-numeric mask, out-of-range
mask) is therefore NOT rejected at commit and reaches the FRR renderer,
where `strings.SplitN(prefix, "/", 2)` / `strconv.Atoi` fails to set
`matchStr`, leaving the pre-switch default `le 32` / `le 128`. The
emitted `ip prefix-list ... permit <garbage> le 32` line is FRR-invalid
and can fail the managed `frr-reload`. This affects ALL match-types
identically — it is the remaining hole for *malformed* prefixes that
#2072 did not close (which only handled well-formed prefixes).

## Honest scope/value framing

Both are correctness/robustness fixes, not perf. The win is FRR-reload
safety: today a single bad route-filter line can fail the entire
managed `frr.conf` reload, taking down ALL routing config (BGP/OSPF/
static), not just the offending policy. #2103 closes the well-formed-
but-max-length path; #2105 closes the malformed-prefix path. The churn
is small (one render-arm change + one validator + a render-side belt +
tests). If reviewers conclude the gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict — but note these were both
explicitly filed as review-bar follow-ups of a just-merged PR, so the
project has already decided they are in scope.

## What's already shipped / partially batched (must compose with)

- **#2072 / PR #2102 (merged, `7ecac1033`)** added the `case "upto"`
  arm with the FRR-validity guard pattern this plan MIRRORS for
  `longer`. Key precedent in `policy_render.go`:
  - `plen >= maxLen -> matchStr = ""` (exact): a max-length host prefix
    has no more-specifics, so emit just the bare prefix — and this dodges
    the invalid `le maxLen` (le == plen) line.
  - All invalid-value paths degrade to a *valid* line or to `""`, never
    to an FRR-invalid line.
  - `parseRouteFilterLen` (compiler_routing.go) parses the `/N` length
    token, rejecting `/0`, signed forms, and out-of-range.
- **#1319 typed-leaf / keyValidator gate** (`schema_walk.go`):
  - `SchemaValidate` runs at commit / commit-check (STRICT).
  - `compileTreeLenient` downgrades the same gate to a WARNING on
    `Store.Load` and `Store.SyncApply` (the #1960 lenient-downgrade-on-
    load doctrine; proven by `pkg/configstore/typed_leaf_lenient_test.go`).
  - A `keyValidator` on a container node is invoked for EACH identity arg
    token in `node.Keys[1:argEnd]` where `argEnd = 1 + args`
    (`schema_walk.go:295-305`, and the nested-AST peel path
    `walkInstanceChildren` at :347-352).
  - **Critical consequence for #2105:** the route-filter node has
    `args: 2`, so a `keyValidator` is called for BOTH the prefix AND the
    match-type token. A naive CIDR-only validator would reject the
    `exact`/`longer`/`orlonger`/`upto` keyword. The validator MUST accept
    the match-type keywords (and the `upto` length token) as well as a
    valid CIDR — see design below.

This means #2105 needs NO new strict-vs-lenient wiring: registering a
`keyValidator` automatically inherits commit-strict / load-lenient
behavior for free. That is exactly the doctrine the issue asks for.

## Concrete design

### #2103 — `longer` arm (render)

Replace the `case "longer"` body in `generatePolicyOptions` so the
max-length edge skips the entry instead of emitting `ge plen+1 le max`.

Current:
```go
case "longer":
    parts := strings.SplitN(rf.Prefix, "/", 2)
    if len(parts) == 2 {
        if plen, err := strconv.Atoi(parts[1]); err == nil {
            maxLen := 32
            if strings.Contains(rf.Prefix, ":") {
                maxLen = 128
            }
            matchStr = fmt.Sprintf("ge %d le %d", plen+1, maxLen)
        }
    }
```

New (mirrors the `upto` max-length guard):
```go
case "longer":
    // longer = strictly more specific (the prefix itself excluded).
    // For a max-length prefix (/32 v4, /128 v6) there are NO
    // more-specifics, so "longer" is the EMPTY set — emit no
    // prefix-list entry rather than an FRR-invalid "ge plen+1 le max"
    // line (ge > le and ge > maxlen, which FRR rejects and which can
    // fail the whole frr-reload). Mirrors the upto plen>=maxLen guard
    // (#2072) and closes #2103.
    parts := strings.SplitN(rf.Prefix, "/", 2)
    if len(parts) == 2 {
        if plen, err := strconv.Atoi(parts[1]); err == nil {
            maxLen := 32
            if strings.Contains(rf.Prefix, ":") {
                maxLen = 128
            }
            if plen+1 > maxLen {
                // match-nothing: skip this route-filter entry.
                skipEntry = true
            } else {
                matchStr = fmt.Sprintf("ge %d le %d", plen+1, maxLen)
            }
        }
    }
```

"Skip the entry" needs a mechanism. Two options (open question Q1):

- **Option A (continue):** set a `skipEntry := false` flag at the top of
  the per-`rf` loop body; on the max-length `longer` case set it true and
  `continue` past the prefix-list emit block. Clean, but the
  `match ip/ipv6 address prefix-list <plName>` line is emitted ONCE after
  the loop using `term.RouteFilters[0].Prefix` for family selection —
  skipping individual entries does NOT remove that match line. If ALL
  route-filters in the term are skipped, the term emits a
  `match ... prefix-list <plName>` referencing an EMPTY prefix-list,
  which in FRR is a valid (match-nothing) construct, NOT a reload
  failure. So `continue` is safe.
- **Option B (sentinel matchStr):** introduce a sentinel that suppresses
  the whole line. More invasive.

Plan picks **Option A** (`continue` on a per-entry skip flag) — it is
the minimal change and FRR-safe even when every entry is skipped (empty
prefix-list = match-nothing, which is the correct semantics for "longer
than /32").

### #2105 — route-filter prefix CIDR validator (compile-time)

Add a `keyValidator` to the route-filter schema node. Verified AST
ground truth (dumped via `ParseSetCommand` + `SetPath`):

- `route-filter 10.0.0.0/24 exact` → node
  `Keys=[route-filter, 10.0.0.0/24, exact]`. Walker validates
  `Keys[1:argEnd]` = `Keys[1:3]` = `["10.0.0.0/24", "exact"]` — BOTH the
  prefix AND the match-type token are passed to keyValidator.
- `route-filter 10.0.0.0/24 upto /28` → node
  `Keys=[route-filter, 10.0.0.0/24, upto]` with a CHILD `Keys=[/28]`. The
  length token `/28` is a CHILD, NOT in the node's `Keys`, so it is NOT
  passed to the node's keyValidator (and `upto /N` already commits fine
  today, so the unknown `/28` child is tolerated by the walker).

So the validator must accept a valid CIDR (prefix slot) OR a match-type
keyword (match-type slot). It does NOT need to accept the `upto` length
token (it never reaches the keyValidator). The validator is
position-agnostic — the walker does not tell it which slot it is in:

```go
// schema_routing.go
"route-filter": {desc: "Route filter", args: 2, placeholder: "<prefix>",
    keyValidator: ValidateRouteFilterArg, children: nil},
```

```go
// schema_validators.go (new)
// routeFilterMatchTypes are the match-type keywords the route-filter
// arg-2 slot accepts. The schema node packs BOTH the prefix and the
// match-type into Keys, and the walker validates each identity token
// with the SAME keyValidator, so this validator must accept a valid
// CIDR (the prefix slot) OR a match-type keyword (the match-type slot).
var routeFilterMatchTypes = map[string]bool{
    "exact": true, "longer": true, "orlonger": true, "upto": true,
    // "prefix-length-range" and "through" are accepted as keywords so a
    // future render of them is not blocked at commit; they are still
    // unrendered (deferred, see #2103 note) but the grammar admits them.
    "prefix-length-range": true, "through": true,
}

// ValidateRouteFilterArg validates one identity-arg token of a
// `from route-filter <prefix> <match-type>` node. The node is args:2 so
// the walker invokes this for the prefix token AND the match-type token
// (Keys[1:3]); the `upto` length token is a CHILD and never reaches
// here. A token is accepted if it is:
//   - a match-type keyword (exact/longer/orlonger/upto/...), OR
//   - a syntactically valid CIDR prefix (v4 or v6, net.ParseCIDR).
// A malformed prefix (no "/", non-numeric mask, out-of-range mask) that
// is none of the above is REJECTED at commit, closing #2105. Strictness
// is automatic: SchemaValidate is strict at commit and lenient (warn,
// not fail) on Store.Load / SyncApply (#1960 doctrine), so a prefix
// persisted by an older binary never blackouts boot.
func ValidateRouteFilterArg(raw string, _ *Config) error {
    tok := strings.TrimSpace(raw)
    if tok == "" {
        return fmt.Errorf("missing route-filter prefix (e.g. 10.0.0.0/24)")
    }
    if routeFilterMatchTypes[tok] {
        return nil
    }
    if _, _, err := net.ParseCIDR(tok); err == nil {
        return nil
    }
    return fmt.Errorf("not a valid route-filter prefix (expected CIDR e.g. 10.0.0.0/24 or 2001:db8::/32): %q", raw)
}
```

Known limitation (open question Q2): a token that is a bare match-type
keyword in the *prefix* slot (e.g. `route-filter longer exact`) would
pass — the validator is position-agnostic. This is the documented
trade-off in the issue ("the validator must accept the match-type
keywords ... OR the schema must be restructured"). It is strictly better
than today (any garbage passes) and catches the real-world malformed-
CIDR case the issue targets. Restructuring the schema to validate only
the prefix slot is the alternative (Q2 invites it).

### #2105 — render-side belt-and-suspenders (defense in depth)

Even with the commit validator, the lenient-on-load path can let a
stored garbage prefix through to the renderer (a pre-gate config). Add a
render-side skip so the renderer NEVER emits a garbage FRR line: in the
per-`rf` loop, if the prefix has no `/` or its mask does not
`strconv.Atoi`, set `skipEntry = true` (reuse the #2103 skip mechanism)
so no `permit <garbage> ...` line is produced. This is the same skip
flag #2103 introduces — one mechanism, two callers.

## Public API preservation

No exported signatures change. `generatePolicyOptions` keeps its
signature. New: package-level `ValidateRouteFilterArg` (exported to match
the existing `ValidateIPv4CIDR`/`ValidateIPv6CIDR` convention; could be
unexported — Q3). `routeFilterMatchTypes` is a new unexported var.

## Hidden invariants the change must preserve

- **Render side-effect ordering:** the `seq` numbering of prefix-list
  entries. With Option A `continue`, a skipped entry's `seq` slot
  `(i+1)*5` is simply not emitted — gaps in seq are FRR-legal and do not
  reorder remaining entries. Verify a test that mixes a skipped /32
  `longer` with a normal entry keeps the normal entry's seq stable.
- **The `match ip/ipv6 address prefix-list <plName>` line** is emitted
  from `term.RouteFilters[0].Prefix` family detection — unchanged. If
  entry 0 is the skipped one, the family is still read from its prefix
  string (still parseable for family — a /32 longer skip still has a
  valid v4 prefix string). For a *malformed* prefix at index 0 (#2105),
  family detection falls back to `strings.Contains(":")` which is
  garbage-tolerant (defaults to v4) — acceptable, the prefix-list is
  empty/match-nothing anyway.
- **Commit-strict / load-lenient gate:** inherited automatically via
  keyValidator — no new wiring. Must add a `configstore` lenient test
  proving a stored garbage route-filter prefix does NOT fail
  `Store.Load` (mirrors `typed_leaf_lenient_test.go`).
- **Dual-AST compile:** the compiler already reads route-filter from both
  brace (`Keys[1]`/`Keys[2]`) and flat-set (SetPath) shapes
  (compiler_routing.go). The validator runs on the schema walk, which
  also handles both shapes — but tests MUST use `ParseSetCommand` +
  `SetPath` (NOT `NewParser`) per the project rule.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | `longer` for non-max prefixes unchanged; only the /32-/128 edge changes (from invalid line → no line). Other match-types untouched. |
| Lifetime / borrow | N/A | Go, no borrow checker. |
| Performance | NONE | Control-plane render + commit-check only; no dataplane/hot path. |
| Architectural mismatch | LOW | Mirrors the just-merged #2072 pattern exactly; keyValidator is the established #1319 mechanism. Risk is the position-agnostic validator (Q2) — a deliberate, documented trade-off, not a wrong architecture. |

## Test plan

CONTROL-PLANE ONLY — no dataplane smoke (per task scope). Coverage:

- `pkg/frr` render tests (extend `frr_test.go`):
  - `/32 longer` → NO `ge 33 le 32` line emitted (and no `permit
    .../32 ge` at all); term still well-formed.
  - `/128 longer` → NO `ge 129 le 128` line.
  - `/24 longer` (control) → still emits `ge 25 le 32` (no regression).
  - `/64 longer` v6 (control) → still emits `ge 65 le 128`.
  - Mixed term: a skipped /32 longer alongside a normal /24 longer keeps
    the /24's seq + the `match ... prefix-list` line.
  - Render-side belt: a malformed prefix (e.g. `10.0.0.0` no mask) →
    NO `permit 10.0.0.0 le 32` garbage line emitted.
  - **Non-tautological:** each new render assertion must FAIL against
    pre-fix `policy_render.go` (the current `ge 33 le 32` / garbage line).
- `pkg/config` compile/validate tests (dual-AST, `ParseSetCommand` +
  `SetPath`):
  - Malformed prefix (`route-filter 10.0.0.0 exact`, no mask) REJECTED
    at `SchemaValidate` (commit-check) with a useful error.
  - Out-of-range mask (`10.0.0.0/99 exact`) REJECTED.
  - Non-numeric mask (`10.0.0.0/ab exact`) REJECTED.
  - Valid v4 + v6 prefixes with every match-type ACCEPTED (control —
    proves the match-type keyword is not falsely rejected).
  - `upto /24` length token ACCEPTED (proves the arg-3 length is not
    falsely rejected).
- `pkg/configstore` lenient test:
  - A stored garbage route-filter prefix does NOT fail `Store.Load`
    (mirrors `typed_leaf_lenient_test.go`), but a fresh strict commit of
    the same DOES fail.
- `GOCACHE=/dev/shm/cache go test ./pkg/frr/... ./pkg/config/...
  ./pkg/configstore/...` green; full `go test ./...` green.

## Out of scope (explicitly)

- `prefix-length-range` and `through` RENDER (still default `le 32`) —
  the other #2072 follow-up; they need new struct fields. This plan only
  ADMITS their keywords in the validator so a future render is not
  blocked at commit, and audits them per #2103's note, but does NOT
  render them. (If admitting the keyword is judged out of scope, drop
  them from `routeFilterMatchTypes` — Q4.)
- Any dataplane / userspace-dp change.
- Schema restructuring to make the route-filter node validate only the
  prefix slot (Q2 alternative — heavier, deferred unless reviewers
  demand it).

## Open questions for adversarial review

1. **Q1 — skip mechanism.** Option A (`continue` on a per-entry skip
   flag) vs Option B (sentinel matchStr). Is `continue` correct given the
   single post-loop `match ... prefix-list` line? Confirm an all-skipped
   term yields an empty (match-nothing) prefix-list that FRR accepts, NOT
   a reload failure. Is there a case where the `match` line should ALSO
   be suppressed when every entry is skipped?
2. **Q2 — position-agnostic validator.** Accepting match-type keywords in
   the prefix slot means `route-filter longer exact` passes. Is this an
   acceptable known limitation (the issue flags it), or must the schema
   be restructured so only the prefix is CIDR-validated? Does any other
   args:2 node in the schema already solve this?
3. **Q3 — exported vs unexported validator.** `ValidateRouteFilterArg`
   exported (matches `ValidateIPv4CIDR`) or unexported (only used in this
   package)? The existing CIDR validators are exported but consumed
   cross-package — is route-filter's?
4. **Q4 — admit `prefix-length-range`/`through` keywords now?** Admitting
   them in the validator (so a future render is not commit-blocked) vs
   rejecting them until they render. Which is less surprising to an
   operator who configures `through` today?
5. **Q5 — `upto` length token (RESOLVED by AST dump).** Verified: the
   `upto /N` length token lands as a CHILD of the route-filter node, NOT
   in `Keys[1:3]`, so it never reaches the keyValidator. The validator
   therefore does NOT accept a bare length token, which AVOIDS the
   widening risk (`route-filter 24 exact` is correctly REJECTED — `24` is
   neither a CIDR nor a match-type keyword). Reviewers: confirm there is
   no alternate AST shape (e.g. single-line brace parse) that packs the
   length into `Keys[3]` where it WOULD be validated and falsely
   rejected. (The compiler reads `Keys[3]` in the brace shape per
   compiler_routing.go — if a brace parse yields
   `Keys=[route-filter, P, upto, /28]`, then `Keys[1:3]` still excludes
   index 3, so still safe; confirm `argEnd=3` never reaches index 3.)
6. **Q6 — family detection on malformed index-0 prefix.** When the FIRST
   route-filter has a malformed prefix (#2105 render belt), the
   `match ip/ipv6 address prefix-list` family is chosen by
   `strings.Contains(prefix, ":")` on garbage. Is defaulting to v4
   acceptable, or should the family be derived from a parseable entry?
