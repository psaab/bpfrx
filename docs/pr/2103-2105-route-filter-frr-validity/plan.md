# #2103 + #2105 — route-filter FRR-validity: `longer` max-len + prefix CIDR validation

Status: v2 — both round-1 hostile reviewers' PLAN-NEEDS-MINOR findings
folded (FRR empty-vs-NULL prefix-list semantics corrected, all-skipped
term now suppresses the `match` line, family derived from a parseable
entry, orlonger/32 recorded as FRR-valid). Ready to implement. See "v2 —
adversarial plan-review resolution" at the bottom.

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
    // line. FRR rejects ge 33 (YANG range 0..32) AND ge>le; a rejected
    // line can fail the whole frr-reload (tools/frr-reload.py applies
    // the add-batch via a single vtysh -f and exits non-zero on any
    // CMD_WARNING_CONFIG_FAILED). Mirrors the upto plen>=maxLen guard
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

Boundary check (verified, both reviewers): `plen+1 > maxLen` skips ONLY
`plen == maxLen`. `/31 → 32 > 32` false → emits `ge 32 le 32` (one
more-specific, FRR-valid, `mask(31) <= ge(32) <= le(32)`). `/32 →
33 > 32` true → skip. `/127 v6 → ge 128 le 128` (valid); `/128 v6 → skip`.
Does NOT over-skip /31.

### Skip mechanism + the post-loop `match` line — CORRECTED in v2

Round-1 reviewers (both, F1, load-bearing) caught that the v1 rationale
"all entries skipped → empty prefix-list = match-nothing" is BACKWARDS
on FRR semantics. Verified against FRR `lib/plist.c prefix_list_apply_ext`:

- A **count==0 *materialized* prefix-list** (the name exists, has zero
  entries) returns **`PREFIX_PERMIT` (match-EVERYTHING)**.
- A **non-existent (NULL) prefix-list** (the name was never created by an
  `ip prefix-list <name>` line) → `prefix_list_lookup` returns NULL, and
  the route-map match handlers
  (`route_match_address_prefix_list`/zebra) short-circuit to
  `RMAP_NOMATCH` (DENY).

The skip mechanism emits ZERO `ip prefix-list <plName>` lines for a
skipped entry, so a fully-skipped term references a name that is never
materialized → NULL → DENY → correct match-nothing. But relying on
NULL-vs-empty is fragile: any future change that materializes a
zero-entry list flips the term to PERMIT-ALL. v2 therefore takes the
robust path the v1 Q1 itself offered:

**Mechanism (v2):**
1. Per-`rf` loop: a `skipEntry bool` flag, reset each iteration. Set true
   on the #2103 max-length `longer` case AND on the #2105 malformed
   prefix. `continue` past the prefix-list emit block when set.
2. Count entries actually emitted: `emitted++` only when a `permit` line
   is written. Track the family of the FIRST emitted entry
   (`firstEmittedV6 bool`) for the `match` line.
3. After the loop, emit the `match ip/ipv6 address prefix-list <plName>`
   line **only if `emitted > 0`** — using `firstEmittedV6` (a
   parseable, non-skipped entry's family), NOT `term.RouteFilters[0]`.
   When `emitted == 0` the whole term has no usable route-filter, so
   suppress BOTH the prefix-list entries (already skipped) AND the
   `match` line. The term then has no route-filter match condition
   (other `from`/`then` clauses still render); this is deterministic and
   does not depend on FRR's NULL-vs-empty behavior.

This closes round-1 F1 (no count==0 list ever materialized; no
`match` line ever references a non-existent list) and F6 (family of the
`match` line is derived from a parseable emitted entry, fixing the
mixed-term malformed-v4-index-0 + valid-v6-index-1 case that v1 would
have mis-rendered as `match ip` for a v6-only list → wrong-namespace
DENY of a legitimate term).

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
    // "prefix-length-range" and "through" are ADMITTED as keywords (v2,
    // resolving Q4). They are unrendered (default le 32/128 — a separate
    // deferred follow-up, see Out of Scope), but they COMMIT FINE TODAY
    // (no validator exists), so rejecting them would be a grammar
    // regression breaking configs already on the wire. Their current
    // default render le 32/le 128 is FRR-VALID even at /32 (le==plen is
    // accepted by FRR; only strictly-less is rejected — see v2 F2), so
    // admitting them introduces no reload failure.
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
    // Family-agnostic CIDR (v4 or v6). parseCIDRStrict requires a
    // /prefix-length and upgrades the common mistakes (bare IP →
    // "missing /prefix-length", garbage → targeted message), matching
    // the ValidateIPv4CIDR/ValidateIPv6CIDR convention. Ignore the
    // returned IP — route-filter accepts both families.
    if _, err := parseCIDRStrict(tok, "10.0.0.0/24"); err == nil {
        return nil
    }
    return fmt.Errorf("not a valid route-filter prefix (expected CIDR e.g. 10.0.0.0/24 or 2001:db8::/32): %q", raw)
}
```

Note: `parseCIDRStrict` returns `(net.IP, error)`; we discard the IP.
`net.ParseCIDR` (which it wraps) accepts `/0`, `/32`, v6, and host-bits-
set forms, and rejects `10.0.0.0` (no mask), `/99`, `/ab`, and the
keywords — verified against the live parser. (If `parseCIDRStrict`'s
required-prefix message is judged too interface-flavored for
route-filter, fall back to bare `net.ParseCIDR` — functionally
equivalent for acceptance; this is a cosmetic choice.)

Known limitation (open question Q2): a token that is a bare match-type
keyword in the *prefix* slot (e.g. `route-filter longer exact`) would
pass — the validator is position-agnostic. This is the documented
trade-off in the issue ("the validator must accept the match-type
keywords ... OR the schema must be restructured"). It is strictly better
than today (any garbage passes) and catches the real-world malformed-
CIDR case the issue targets. Restructuring the schema to validate only
the prefix slot is the alternative (Q2 invites it).

### #2105 — render-side belt-and-suspenders (defense in depth)

Even with the commit validator, the lenient-on-load path (Store.Load /
SyncApply, #1960) can let a stored garbage prefix through to the
renderer (a pre-gate config, or an HA sync from an un-upgraded peer). Add
a render-side skip so the renderer NEVER emits a garbage FRR line: in the
per-`rf` loop, if the prefix has no `/` or its mask does not
`strconv.Atoi` (i.e. `SplitN(prefix,"/",2)` len != 2 OR the mask is not
a number in range), set `skipEntry = true` (the SAME flag #2103 uses) so
no `permit <garbage> ...` line is produced and `emitted` is not bumped.
One mechanism, two callers. A valid CIDR always has `/` + numeric mask,
so this never false-skips a valid v4 or v6 prefix (locked by a test).

## Public API preservation

No exported signatures change. `generatePolicyOptions` keeps its
signature. New: package-level `ValidateRouteFilterArg`, EXPORTED to match
the existing `ValidateIPv4CIDR`/`ValidateIPv6CIDR` convention (v2,
resolving Q3 — the existing validators are exported even when consumed
in-package). It reuses the existing `parseCIDRStrict` helper internally
for operator-friendly messages (bare-IP → "missing /prefix-length"),
matching the project convention (v2 F7), but is family-agnostic
(route-filter accepts both v4 and v6). `routeFilterMatchTypes` is a new
unexported var.

## Hidden invariants the change must preserve

- **Render side-effect ordering:** the `seq` numbering of prefix-list
  entries. A skipped entry's `seq` slot `(i+1)*5` is simply not emitted —
  the loop still iterates with `i`, so remaining entries keep their
  original `(i+1)*5` seq. Gaps in seq are FRR-legal and do not reorder
  remaining entries. Verify a test that mixes a skipped /32 `longer`
  (i=0) with a normal /24 `longer` (i=1) keeps the /24 entry's
  `seq 10` stable. (Decision: keep `i`-based seq, do NOT renumber from
  the emitted count — renumbering would change seq of EXISTING entries
  across a config edit, a gratuitous diff; gaps are harmless.)
- **The `match ip/ipv6 address prefix-list <plName>` line** (v2,
  CORRECTED — see "Skip mechanism" above): emitted only when
  `emitted > 0`, with family from the FIRST emitted (parseable,
  non-skipped) entry's prefix, NOT `term.RouteFilters[0].Prefix`. This
  fixes the round-1 F6 mixed-term case (malformed v4 at index 0 + valid
  v6 at index 1 would have emitted `match ip` for a v6-only list). When
  every entry is skipped the `match` line is suppressed entirely — no
  reference to a non-existent prefix-list, deterministic match-nothing
  via "term has no route-filter condition" (the term still renders its
  other `from`/`then` clauses).
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

- `pkg/frr` render tests (extend `frr_test.go`; direct
  `config.RouteFilter` struct construction — the render tests do not need
  an AST, matching `TestRouteFilterExactFRR`):
  - `/32 longer` → NO `ge 33 le 32` line emitted (and no `permit
    .../32 ge` at all).
  - `/128 longer` → NO `ge 129 le 128` line.
  - `/31 longer` (boundary control) → still emits `ge 32 le 32` (proves
    no over-skip of the one legal more-specific).
  - `/24 longer` (control) → still emits `ge 25 le 32` (no regression).
  - `/64 longer` v6 (control) → still emits `ge 65 le 128`.
  - `orlonger /32` (control, v2 F2) → still emits bare `le 32`
    (le==plen is FRR-valid; proves the fix did not touch orlonger and
    documents the valid equality case).
  - **All-skipped term (v2 F1):** a term whose ONLY route-filter is a
    `/32 longer` → NO `ip prefix-list <plName>` line AND NO
    `match ... prefix-list <plName>` line emitted (locks the
    no-count==0-list / no-dangling-match invariant; without this a
    regression that materializes an empty list → PERMIT-ALL would slip
    past the "no ge 33" assertions).
  - **Mixed term (v2 F1/F6):** a skipped `/32 longer` (index 0) +
    a normal `/24 longer` (index 1) → the /24 entry IS emitted with
    `seq 10` (stable), the `match ... prefix-list` line IS present.
  - **Mixed family (v2 F6):** malformed v4-ish prefix at index 0
    (skipped by the belt) + valid `2001:db8::/64 longer` at index 1 →
    the `match` line is `match ipv6 address prefix-list` (NOT `match ip`),
    proving family derives from the emitted v6 entry, not index 0.
  - Render-side belt (v2 #2105): a malformed prefix (e.g. `10.0.0.0`
    no mask) → NO `permit 10.0.0.0 le 32` garbage line emitted.
  - A valid v6 `/64 orlonger` is NOT belt-skipped (proves the belt does
    not false-skip valid prefixes).
  - **Non-tautological:** each new render assertion must FAIL against
    pre-fix `policy_render.go` (the current `ge 33 le 32` / garbage line /
    unconditional match line).
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
  ADMITS their keywords in the validator (v2 Q4 resolution) so the
  existing commit behavior is preserved, but does NOT render them. Their
  default `le 32`/`le 128` render is FRR-valid even at /32 (le==plen
  accepted — v2 F2), so admitting them adds no reload risk. Audited per
  #2103's note; render deferred.
- The `orlonger`/`upto`/`exact` arms — UNCHANGED. `orlonger /32 → le 32`
  is FRR-valid (le==plen accepted; v2 F2 refuted the suspected sibling
  bug), so no fix needed there.
- Fixing the misleading `<=`-vs-`<` wording in the existing #2072 `upto`
  comment (v2 F2): OPTIONAL one-line comment cleanup; will fold it if
  trivially adjacent, else leave a note — the `upto` code itself is
  correct (it never emits `le==plen`, mapping `UptoLen==plen`→exact).
- Any dataplane / userspace-dp change.
- Schema restructuring to make the route-filter node validate only the
  prefix slot (Q2 — heavier; the position-agnostic validator is the
  accepted v2 design, documented as a known limitation).

## Open questions for adversarial review (ALL RESOLVED in v2)

1. **Q1 — skip mechanism. RESOLVED.** Both reviewers (F1) corrected the
   v1 "empty list = match-nothing" rationale (FRR count==0 list =
   PERMIT-ALL; only a NULL/non-existent list = DENY). v2 suppresses the
   `match` line entirely when `emitted == 0` and never materializes a
   count==0 list — deterministic, not dependent on FRR NULL-vs-empty.
2. **Q2 — position-agnostic validator. RESOLVED (accepted limitation).**
   No other args:2 node solves per-position validation (`as-path` is the
   only other args:2 node, no keyValidator). The position-agnostic design
   is strictly better than today and catches the real malformed-CIDR
   target; documented as a known gap. Schema restructuring deferred.
3. **Q3 — exported validator. RESOLVED: exported** (matches the existing
   exported-validator convention).
4. **Q4 — admit `prefix-length-range`/`through`. RESOLVED: admit.**
   They commit fine today (no validator), so rejecting would be a grammar
   regression; their default `le 32`/`le 128` render is FRR-valid even at
   /32 (v2 F2).
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
6. **Q6 — family detection on malformed index-0 prefix. RESOLVED
   (F6): derive from a parseable emitted entry.** v1 read
   `term.RouteFilters[0].Prefix`; a mixed term (malformed v4 index-0 +
   valid v6 index-1) would emit `match ip` for a v6-only list →
   wrong-namespace DENY of a legitimate term. v2 tracks the family of the
   FIRST emitted entry and uses that for the `match` line.

## v2 — adversarial plan-review resolution

Two independent hostile Claude plan reviewers (read-only scratch
worktrees) both returned **PLAN-NEEDS-MINOR**, with convergent,
source-verified findings. Resolution:

- **F1 (both reviewers, load-bearing) — FRR empty-vs-NULL prefix-list
  semantics.** v1 claimed "all entries skipped → empty prefix-list =
  match-nothing." This is BACKWARDS: FRR `lib/plist.c` returns
  `PREFIX_PERMIT` (match-ALL) for a materialized count==0 list; only a
  non-existent (NULL) list yields DENY. **Resolved:** v2 suppresses the
  `match` line when `emitted == 0` and never emits a count==0 list, so
  correctness no longer depends on FRR's fragile NULL-vs-empty behavior.
  Added an all-skipped-term test asserting NO `ip prefix-list` AND NO
  `match` line.
- **F6/Q6 (reviewer B) — family detection.** Resolved: derive the
  `match` line family from the first emitted (parseable) entry, with a
  mixed-family test.
- **F2 (reviewer B) — orlonger/32 sibling bug REFUTED.** `le == plen` is
  FRR-valid (only strictly-less is rejected by
  `lib/filter_nb.c prefix_list_length_validate`), so `orlonger /32 →
  le 32` is fine; no fix needed. The existing #2072 `upto` comment
  overstates the rule (`<=` should be `<`) but is harmless (the `upto`
  code never emits `le==plen`). Recorded; optional one-line comment
  cleanup folded if trivially adjacent. Added an `orlonger /32` control
  test.
- **F3/F4/F5 (both) — citations + stakes.** Confirmed `ge 33` fails the
  YANG range `0..32` (primary) AND `ge>le`; `frr-reload.py` fails the
  WHOLE reload on a bad add line (single `vtysh -f`, no per-line skip for
  adds). Folded into the code comments and the framing.
- **F7 (reviewer B) — validator convention.** Resolved: reuse
  `parseCIDRStrict` for operator-friendly messages, family-agnostic.
- **Q3 (both) — exported.** Resolved: export `ValidateRouteFilterArg`.
- **Q4 (split: A reject-until-rendered, B admit) — resolved: ADMIT.**
  Rejecting `prefix-length-range`/`through` would regress the grammar
  (they commit fine today); their default render is FRR-valid.
- **Q5 (both) — CONFIRMED safe.** The `upto /N` length token is never in
  `Keys[1:3]` in any AST shape (`argEnd = 1 + args = 3`; the slice
  excludes index 3 even in the brace shape that packs `/28` at index 3).
  `route-filter 24 exact` is correctly rejected; `upto /28` is not
  falsely rejected.

Round-1 reviewer agentIds: A `a406b6cade7888116`, B `a89e7a393bd20ddde`.
