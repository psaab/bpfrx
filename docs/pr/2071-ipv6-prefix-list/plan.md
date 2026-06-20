# #2071 — IPv6 prefix-list rendered with the IPv4 `match ip address` matcher

**Status:** PLAN-READY v3 — round-3 both reviewers agree the single
family-chosen matcher is correct (A: NEEDS-MINOR ×3 honesty/coverage
items, all folded; B: PLAN-READY). Mirrors the route-filter precedent
exactly; two-sequence machinery (v2) abandoned after it collided with
co-resident route-filters.

## Issue framing

`pkg/frr/policy_render.go` `generatePolicyOptions()` renders a policy
term's `from prefix-list <name>` unconditionally as
`match ip address prefix-list <name>` (the IPv4 matcher), with no
address-family detection:

```go
if term.PrefixList != "" {
    fmt.Fprintf(&b, " match ip address prefix-list %s\n", term.PrefixList)
}
```

If the referenced prefix-list holds IPv6 prefixes (e.g. `2001:db8::/32`)
and the policy is applied in an IPv6 context (OSPFv3 export, BGP `inet6`
route-map), FRR's `match ip address` clause never matches IPv6 routes.
The operator's export/import filter is a **silent no-op for IPv6** — it
can leak routes that should be filtered, or fail to permit routes that
should pass.

The adjacent route-filter path (lines 619-633) already branches on
`strings.Contains(prefix, ":")` to choose `match ipv6 address` vs
`match ip address`. The explicit-prefix-list path was never given the
same family check.

## Honest scope/value framing

This is a **single-site control-plane correctness bug** in FRR config
rendering. There is no perf dimension — it is a missing address-family
branch that makes a configured IPv6 routing-policy filter inert. The win
is correctness: an IPv6 `from prefix-list` filter starts actually
matching IPv6 routes instead of being silently dropped on the floor.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (There is no perf gain; the
justification is pure correctness, and the change is ~10 lines.)

## What's already shipped / partially batched

- The prefix-list *definition* render (lines 535-540) already splits a
  Junos prefix-list into FRR `ip prefix-list NAME` (v4 entries) and
  `ipv6 prefix-list NAME` (v6 entries) by per-entry `strings.Contains(":"`
  detection. FRR keeps `ip` and `ipv6` prefix-lists in independent
  namespaces even under the same NAME.
- The route-filter inline-prefix-list path (lines 619-633) already
  branches the *matcher* on family (it inspects `RouteFilters[0].Prefix`).
- The compiler (`pkg/config/compiler_routing.go`) already populates both
  `PolicyOptionsConfig.PrefixLists[name].Prefixes` (line 362) and
  `term.PrefixList` (lines 518 / 620) from flat-set and hierarchical
  syntax.

So everything needed to determine the family already exists in the typed
config; the render just doesn't consult it.

## Concrete design

`generatePolicyOptions` already has `po *config.PolicyOptionsConfig` in
scope, so `po.PrefixLists[term.PrefixList]` is available. Replace the
unconditional emit with a family-aware emit.

Determine the family by inspecting the referenced prefix-list's entries.
A prefix-list may hold v4 entries, v6 entries, or both (mixed).

### FRR route-map AND semantics (round-1 finding — why "both in one sequence" is wrong)

Round-1 reviewer A refuted v1's "emit both matchers in one sequence"
design. Verified against FRR master source:

- `lib/routemap.c` `route_map_apply_match` combines match clauses within
  a single route-map index with **AND** semantics — the truth table is
  `MATCH + NOMATCH → NOMATCH`, and the iteration loop calls EVERY match
  rule's `func_apply` with no address-family pre-filter (an IPv4 route is
  still tested against a `match ipv6 address` rule).
- `bgpd/bgp_routemap.c` `route_match_address_prefix_list` returns
  `RMAP_NOMATCH` (never `RMAP_NOOP`) both when the named list is absent in
  that AFI namespace AND when the prefix fails a present list.

So two `match ip|ipv6 address prefix-list` clauses must never coexist in
one route-map index — one of them will always NOMATCH a given route and
AND the index to a silent deny.

### Round-2 finding — why the two-sequence machinery is also wrong here

v2 tried to express a mixed list as TWO consecutive route-map sequences
(a v4 sequence and a v6 sequence) each carrying the full term body.
Round-2 reviewers A and B both found this collides with a co-resident
route-filter: a term may carry BOTH `from route-filter` and
`from prefix-list` (independent Junos `from` clauses; the compiler
populates `term.RouteFilters` and `term.PrefixList` independently —
`compiler_routing.go`). The route-filter emits its OWN
`match ip|ipv6 address prefix-list NAME-TERM` clause whose family is fixed
from `RouteFilters[0].Prefix`. Duplicating the full term body into both
split sequences puts a v4 route-filter `match` clause into the v6
sequence → a v6 route AND-NOMATCHes → the round-1 silent-deny bug,
relocated. The two-sequence design also re-emits the route-filter's inline
prefix-list *definition* lines twice. Rejected.

### v3 design — mirror the route-filter precedent exactly

The issue and the parent directive both say to "branch the PrefixList
render path on address family **exactly like the adjacent route-filter
path**." The route-filter path (lines 629-633) emits exactly ONE matcher,
chosen by family, and makes a deliberate homogeneous-family assumption
(it inspects only `RouteFilters[0].Prefix`). v3 mirrors that precisely:

- Look up `po.PrefixLists[term.PrefixList]`. If ANY entry is IPv6
  (`strings.Contains(p, ":")`), emit `match ipv6 address prefix-list X`;
  otherwise emit `match ip address prefix-list X`. Exactly ONE matcher,
  in the term's single sequence, in the same position as today.

```go
if term.PrefixList != "" {
    matchKW := "ip"
    if pl := po.PrefixLists[term.PrefixList]; pl != nil {
        for _, p := range pl.Prefixes {
            if strings.Contains(p, ":") {
                matchKW = "ipv6"
                break
            }
        }
    }
    fmt.Fprintf(&b, " match %s address prefix-list %s\n", matchKW, term.PrefixList)
}
```

This is ~8 lines, no helper extraction, no term-body duplication, no
sequence renumbering, and therefore **no interaction with co-resident
route-filters, set-actions, or other match clauses** — the change is
strictly local to the single match line that #2071 reports.

- **v6 list** (the #2071 report): now correctly emits `match ipv6 address`.
- **v4-only list:** byte-identical to master (`match ip address`).
- **unknown / empty list** (name absent from `po.PrefixLists`, or no
  entries): `pl` is nil or has no entries → loop sets nothing → default
  `match ip address` — byte-identical to master. (FRR NOMATCHes an
  undefined list regardless of the keyword, so the default is cosmetic for
  the miss case; v4 preserves byte-identity for existing configs.)
- **mixed list** (a genuinely rare config — `from prefix-list` of a list
  holding both families): picks `ipv6` (any v6 entry wins). This is a
  **behavior change** vs master, and it is a TRADE, not a strict
  improvement: master renders `match ip address` for a mixed list, so
  today the v4 entries match (in a v4 context) and the v6 entries are the
  reported no-op; v3 renders `match ipv6 address`, so the v6 entries now
  match (in a v6 context) but the v4 entries STOP matching. A single FRR
  route-map index cannot serve both families (the round-1 AND finding), so
  one direction must be chosen; v3 chooses the family the #2071 report is
  about (v6). The same dual-stack route-map is attached under BOTH
  `address-family ipv4 unicast` and `address-family ipv6 unicast` for BGP
  (`policy_render.go` ~342/361), so a mixed list referenced by a dual-stack
  export will, after v3, filter v6 routes and no longer filter v4 routes
  via that term. This is the SAME homogeneous-family limitation the
  adjacent route-filter path already has (it keys on `RouteFilters[0]`),
  and a fully correct mixed-list render is out of scope (see Out of scope).

### Why "any v6 entry → ipv6" rather than "first entry's family"

The route-filter precedent keys on `RouteFilters[0].Prefix` (first entry).
v3 keys on "any v6 entry" so that a list whose first entry happens to be
v4 but which the operator intends as a v6 filter (e.g. listed v4 then v6)
still gets the v6 matcher — directly serving the reported bug. For a
homogeneous list (the overwhelming common case) the two rules are
identical. The difference only shows for a mixed list, where neither rule
is fully correct (FRR limitation) and "any v6 wins" is the choice that
makes the reported v6 case work.

### Why look up the list instead of carrying family on the term

`PolicyTerm.PrefixList` is just the name string; the family lives on the
referenced `PrefixList.Prefixes`. The issue text itself calls out that
the fix "would need to look up `po.PrefixLists[term.PrefixList]` to
inspect the family." `po` is already the function parameter, so no
signature change is needed.

### Ordering

The single match clause is emitted in exactly the same position as the
current single line (between the route-filter block and the
`match source-protocol` lines). No clause moves; no seq renumbering. For
v4-only and unknown/empty lists the output is byte-identical to master.

## Public API preservation

No signature changes. `generatePolicyOptions(po
*config.PolicyOptionsConfig) string` is unchanged. No exported symbols
touched. No config schema, AST, or compiler change.

## Hidden invariants the change must preserve

- **Byte-identity for v4-only and unknown/empty configs:** a term that
  references a v4-only (or unknown/empty) prefix-list renders byte-identically
  to master — the same single `match ip address` line in the same
  position, same seq numbering. The new v4-only render test asserts the
  exact line directly (the two existing tests `internal`/`trusted-nets`
  assert only the `redistribute route-map` line, NOT the match line, so
  they do not by themselves guarantee byte-identity — round-2 reviewer A's
  MAJOR-2; the new test closes that gap). NOTE the byte-identity claim is
  scoped to v4-only / unknown / empty lists ONLY: a **v6-only list**
  changes output unconditionally (master `match ip address` → v3
  `match ipv6 address`) — that IS the fix — including the (benign) case of
  a v6-only list referenced from a v4-only-attached route-map, where the
  v6 matcher was already matching nothing useful under the v4 keyword
  (round-3 MINOR-2).
- **Single match line only:** exactly one `match ... address prefix-list`
  line per `from prefix-list`, in the term's single sequence. No term-body
  duplication, no second route-map sequence, no seq renumbering — so NO
  interaction with co-resident route-filters, set-actions, or other match
  clauses (round-2 MAJOR-1 / F1 eliminated by construction).
- **No AND of v4 and v6 prefix-list matchers in one index** — the round-1
  defect; v3 emits only one matcher, so it cannot occur.
- **Determinism:** `pl.Prefixes` is scanned only to pick one keyword;
  the `break` on the first v6 entry makes it order-independent for the
  v4/v6 decision (any v6 entry → ipv6). FRR config generation is sorted by
  policy-statement name upstream.
- **No nil deref:** `po` is non-nil at this site (the function
  dereferences `po.PrefixLists`, `po.Communities`, etc. unconditionally
  above). The map index returns nil for a missing key (and indexing even a
  nil map is panic-safe in Go), guarded by the `pl != nil` check.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | v4-only and unknown/empty lists render byte-identically; v6 lists change broken→correct. ONE regression vector: a **mixed** list (v4+v6 entries) referenced by `from prefix-list` flips master's v4 matcher to ipv6, so v4 routes that matched via that term stop matching (the v6 routes start). Rare config; same homogeneous-family limitation the route-filter precedent already has; documented in Out of scope |
| Lifetime / borrow-checker | N/A | Go, no borrow checker; no allocation beyond one stack string |
| Performance regression | NONE | Control-plane render at commit time; one map lookup + early-exit slice scan per term |
| Architectural mismatch (#961 / #946-P2) | NONE | Mirrors the adjacent route-filter family branch exactly; no new abstraction, no helper extraction |

## Test plan

This is a control-plane (FRR render) change — **no dataplane smoke**, no
cluster deploy, no iperf3. Coverage is a Go unit test in `pkg/frr`.

1. `go build ./...` clean.
2. New render unit tests (white-box `package frr`, matching the existing
   `pkg/frr` test convention):
   - **v4 prefix-list** referenced by `from prefix-list` → output
     contains the exact line `match ip address prefix-list <name>` and does
     NOT contain `match ipv6 address prefix-list <name>`. This directly
     asserts the v4 byte-identity that the existing tests do not (round-2
     MAJOR-2).
   - **v6 prefix-list** referenced by `from prefix-list` → output
     contains `match ipv6 address prefix-list <name>` and does NOT
     contain `match ip address prefix-list <name>`.
   - **mixed prefix-list** → output picks `match ipv6 address` (any v6
     entry wins) and emits exactly ONE such match line (assert it does NOT
     contain `match ip address prefix-list <name>` and that there is a
     single route-map sequence for the term — no second sequence). This
     locks in the v3 single-matcher behavior and guards against any
     regression to the rejected v1 dual-emit or v2 two-sequence designs.
   - **prefix-list co-resident with a v4 route-filter, mixed list** → a
     term with both a v4 `from route-filter` and a mixed `from prefix-list`
     renders the route-filter's `match ip address ...-<term>` clause AND
     the prefix-list's `match ipv6 address prefix-list <name>` clause in
     the term's single sequence, with the route-filter inline definition
     emitted exactly once. The test asserts exactly ONE
     `route-map <name> permit <seq>` header for the term (count == 1, e.g.
     `strings.Count`) — guarding against any regression to the rejected v2
     two-sequence design — and that the route-filter `ip prefix-list
     <name>-<term> seq ...` definition line appears exactly once
     (round-2 F1 / round-3 MINOR-3, confirming no term-body duplication).
   - **unknown prefix-list name** (not in `po.PrefixLists`) → falls back
     to `match ip address`, one sequence (no panic, no regression).
   Non-tautology: the v6 and mixed cases FAIL against pre-fix code (which
   emits `match ip address`).
3. An **end-to-end flat-set test** honoring the CLAUDE.md rule
   (`ParseSetCommand` + `tree.SetPath` loop, NOT `NewParser`). The test
   lives in `package frr` (it calls the unexported `generatePolicyOptions`)
   and therefore inlines its own `ParseSetCommand`+`SetPath`+`CompileConfig`
   loop using the exported `config` APIs — it CANNOT reuse the
   `package config` `buildTree` helper (round-2 F2). Feed
   `set policy-options prefix-list v6nets 2001:db8::/32`,
   `set policy-options policy-statement p term t1 from prefix-list v6nets`,
   `set policy-options policy-statement p term t1 then accept`, compile with
   `config.CompileConfig`, render via `m.generatePolicyOptions(&cfg.PolicyOptions)`
   (note: `PolicyOptions` is a value field, so pass its address — round-2
   B Minor-1), assert `match ipv6 address`. Proves the family propagates
   compiler→render.
4. `go test ./pkg/frr/... ./pkg/config/...` green.
5. Named new test 5x for flake stability.
6. Full `go test ./...` green (30 Go packages).

**Docs:** `pkg/frr/README.md` describes `generatePolicyOptions`'
responsibilities at a high level but does not document per-clause
match-family rendering, so it stays accurate and needs no change — noted
here per the CLAUDE.md docs-contract rule (round-2 both reviewers
confirmed no doc under `docs/` documents render-family behavior either).

## Out of scope (explicitly)

- **Fully-correct mixed-family prefix-list rendering.** A prefix-list
  holding BOTH v4 and v6 entries, referenced by an AF-agnostic
  `from prefix-list`, cannot be expressed as a single FRR route-map index
  (two `match ... address` clauses would AND to a silent deny), and the
  two-sequence workaround collides with co-resident route-filters (round-2
  MAJOR-1). v3 picks the v6 matcher for a mixed list (making the reported
  v6 case work) and accepts the same homogeneous-family limitation the
  adjacent route-filter path already has. A complete mixed-family fix
  (e.g. commit-time validation/warning, or a route-map redesign) is a
  separate, larger effort — file a follow-up if a real mixed-list config
  appears.
- The route-filter path's own homogeneous-family assumption (it inspects
  only `RouteFilters[0].Prefix`). Pre-existing; not what #2071 reports.
  Not touched.
- Any change to how prefix-lists are *defined* in FRR (lines 535-540) —
  already family-correct.
- BGP address-family-aware route-map *attachment* (which `address-family`
  block a route-map is referenced under). Out of scope; the bug is the
  match clause, not the attachment.

## Review resolution log

**Round 1:**
- Reviewer A — PLAN-NEEDS-MAJOR: v1's "emit both matchers in one sequence"
  is FRR-broken. ACCEPTED, verified against FRR master source.
- Reviewer B — PLAN-READY w/ 2 minors (`&cfg.PolicyOptions` pointer; docs
  note). Both folded.

**Round 2 (on the v2 two-sequence design):**
- Reviewer A — PLAN-NEEDS-MAJOR: (MAJOR-1) the two-sequence split puts a
  v4 route-filter `match` clause into the v6 sequence for a term carrying
  BOTH a route-filter and a mixed prefix-list → relocated silent-deny;
  (MAJOR-2) the byte-identity claim leaned on existing tests that do not
  assert the `term.PrefixList` match line.
- Reviewer B — PLAN-NEEDS-MINOR: (F1) the route-filter inline *definition*
  lines get emitted twice under the split; (F2) the e2e test must live in
  `package frr` and inline its own ParseSetCommand loop (can't reuse
  `config.buildTree`); (F5) promote the reject-term OR-correctness to
  resolved text.

**v3 resolution — ACCEPTED ALL, by simplification:** rather than keep the
two-sequence machinery and patch its route-filter interactions, v3 drops
it entirely and mirrors the route-filter precedent exactly — ONE match
clause, family chosen by the referenced list (any v6 entry → ipv6). This
eliminates MAJOR-1, F1, and the F2 helper-extraction complexity by
construction (no body duplication, no second sequence). MAJOR-2 is closed
by the new v4-only test that asserts the exact `match ip address` line.
F2's e2e-test-package guidance is folded into the test plan. The mixed
case is explicitly scoped to the route-filter-equivalent homogeneous-family
limitation (Out of scope).

**Round 3 (on the v3 single-matcher design) — BOTH AGREE:**
- Reviewer A — PLAN-NEEDS-MINOR (×3, all honesty/coverage, no design
  change): MINOR-1 drop the "strictly improves" overclaim and name the
  mixed-list v4→ipv6 flip as the explicit regression vector; MINOR-2 scope
  the byte-identity claim to exclude the v6-list-in-v4-context emit change;
  MINOR-3 tighten the co-resident test to assert exactly one route-map
  sequence for the term. ALL FOLDED above.
- Reviewer B — PLAN-READY: verified the exact snippet compiles and is
  correct for all six edge cases, byte-identity proven against the master
  line, non-tautology proven, the e2e compile path verified live, and the
  no-doc-change claim accurate.

Both reviewers confirm v3 closes round-1 and round-2 by construction (one
matcher only → no AND-in-index; no body duplication → no route-filter
interaction). PROCEED TO IMPLEMENT.

## Open questions for adversarial review (round 3 — on the v3 single-matcher design)

1. **Single-matcher correctness:** for a homogeneous list, is one
   family-chosen `match ... address prefix-list` the complete and correct
   fix (it is what the route-filter precedent does)? Any case where one
   matcher is insufficient for a homogeneous list?
2. **"Any v6 entry → ipv6" vs route-filter's "first entry":** is keying on
   any-v6 (rather than first-entry family, as the route-filter path does)
   a defensible deviation, or should v3 match the precedent's first-entry
   rule byte-for-byte? (They differ only for mixed lists.)
3. **Mixed-list scoping:** is accepting the route-filter-equivalent
   homogeneous-family limitation (mixed → ipv6, document as out-of-scope)
   the right call, or must #2071 also solve mixed lists? (Claim: a single
   FRR route-map index cannot express a mixed match without a silent-deny;
   solving it is a separate larger effort.)
4. **Lookup-miss default to v4:** still the right no-regression choice
   given FRR NOMATCHes an undefined list regardless of keyword?
5. **Byte-identity:** does the v4-only test assert the exact unchanged line
   (closing round-2 MAJOR-2), and is the v3 render provably identical to
   master for all v4-only / unknown / empty configs?
6. **Test adequacy / non-tautology:** do the v6 and mixed tests FAIL
   against pre-fix code? Does the co-resident-route-filter test confirm no
   term-body duplication and a single match clause? Is the end-to-end
   flat-set test correctly placed in `package frr`?
