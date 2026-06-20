# #2071 — IPv6 prefix-list rendered with the IPv4 `match ip address` matcher

**Status:** DRAFT v2 — mixed-list design corrected after round-1 review
(reviewer A PLAN-NEEDS-MAJOR: dual-emit-in-one-sequence is FRR-broken)

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

### FRR route-map AND semantics (round-1 correction)

Round-1 reviewer A correctly refuted v1's "emit both matchers in one
sequence" design. Verified against FRR master source:

- `lib/routemap.c` `route_map_apply_match` combines match clauses within
  a single route-map index with **AND** semantics — the truth table is
  `MATCH + NOMATCH → NOMATCH`, and the iteration loop calls EVERY match
  rule's `func_apply` with no address-family pre-filter (an IPv4 route is
  still tested against a `match ipv6 address` rule).
- `bgpd/bgp_routemap.c` `route_match_address_prefix_list` returns
  `RMAP_NOMATCH` (never `RMAP_NOOP`) both when the named list is absent in
  that AFI namespace AND when the prefix fails a present list.

The definition render (lines 535-540) splits a mixed Junos list into BOTH
a populated `ip prefix-list X` and a populated `ipv6 prefix-list X`.
Therefore, if v1 emitted `match ip address X` and `match ipv6 address X`
in the SAME route-map sequence, a v4 route would MATCH the v4 clause but
NOMATCH the (populated) v6 clause → index NOMATCH → the route is
**silently denied**, and symmetrically for v6 routes. That is strictly
worse than today (today, mixed-list v4 routes at least work). The
dual-emit-in-one-sequence design is therefore rejected.

### Corrected design

The two address families must never be AND-ed in one index. Render rule:

- **Single-family list** (all v4, or all v6 — the common case and the
  exact #2071 report): emit the one family-correct matcher in the term's
  single sequence. This is the uncontested, correct fix.
- **Mixed list:** emit the term as **two consecutive route-map
  sequences** — an IPv4 sequence carrying `match ip address` and an IPv6
  sequence carrying `match ipv6 address` — each carrying the term's other
  match clauses and `then` set-actions. FRR evaluates sequences in order
  and falls through on NOMATCH, so a v4 route NOMATCHes the v6 sequence
  and is caught by the v4 sequence (and vice versa). This is the FRR-idiomatic
  way to express "match if the route is in the v4 list OR the v6 list"
  for an AF-agnostic Junos term.
- **Unknown / empty list** (name absent from `po.PrefixLists`, or no
  entries): default to the IPv4 matcher in the single sequence — the
  pre-fix rendering, so no regression. (Note: FRR itself NOMATCHes an
  undefined list regardless of the v4/v6 keyword, so the default is
  cosmetic for the miss case; v4 is chosen only to preserve byte-identical
  output for existing v4-only configs that reference a list.)

Implementation: factor the term body (the route-filter block, the
prefix-list match line, `match source-protocol`, `match community`,
`match as-path`, the `then` set-actions, and the trailing `exit`) into a
helper `func renderPolicyTermBody(b, term, prefixListMatch string)` so
the only thing that varies between the v4 and v6 sequences is the
prefix-list match line. The route-map loop then becomes:

```go
v4, v6 := prefixListFamilies(po, term.PrefixList) // (hasV4, hasV6)
switch {
case term.PrefixList == "":
    emit one sequence, prefixListMatch = ""
case v4 && v6:
    // mixed: two sequences
    emit sequence @ seq   with "match ip address prefix-list X"
    seq += 10
    emit sequence @ seq   with "match ipv6 address prefix-list X"
case v6 && !v4:
    emit one sequence with "match ipv6 address prefix-list X"
default: // v4-only, or unknown/empty (default v4)
    emit one sequence with "match ip address prefix-list X"
}
seq += 10
```

`prefixListFamilies` classifies each entry with the SAME
`strings.Contains(p, ":")` test the definition render uses, guaranteeing
the match clause and the prefix-list namespace can never disagree.

The mixed case is rare but real (Junos `from prefix-list` is
AF-agnostic and a list may hold both families); handling it correctly
rather than producing a silent-deny is worth the small helper extraction.

### Why look up the list instead of carrying family on the term

`PolicyTerm.PrefixList` is just the name string; the family lives on the
referenced `PrefixList.Prefixes`. The issue text itself calls out that
the fix "would need to look up `po.PrefixLists[term.PrefixList]` to
inspect the family." `po` is already the function parameter, so no
signature change is needed.

### Ordering

For a single-family or unknown list the match clause is emitted in the
same position as the current single line (between the route-filter block
and the `match source-protocol` lines) — output is byte-identical to
v1-of-master for v4-only configs. For a mixed list, the v4 sequence is
emitted at the term's seq, the v6 sequence at seq+10 (deterministic),
shifting later terms' seq numbers by one step — a cosmetic numbering
change with no semantic effect (FRR seq numbers only order evaluation).

## Public API preservation

No signature changes. `generatePolicyOptions(po
*config.PolicyOptionsConfig) string` is unchanged. No exported symbols
touched. No config schema, AST, or compiler change.

## Hidden invariants the change must preserve

- **Output ordering / byte-identity for v4-only configs:** a term that
  references a v4-only (or unknown/empty) prefix-list renders byte-identically
  to master — same single `match ip address` line in the same position,
  same seq numbering. Verified against the two existing tests
  (`internal`, `trusted-nets`, both v4-only) which must still pass
  unchanged.
- **Term body equivalence across split:** the extracted
  `renderPolicyTermBody` must emit exactly the same clauses (route-filter
  block, source-protocol/community/as-path matches, all `then`
  set-actions, trailing `exit`) it does today — only the prefix-list match
  line is parameterized. A mixed-list split therefore duplicates the full
  term semantics into both sequences (AND-ed per sequence, OR-ed across
  the two sequences) — correct for an AF-agnostic term.
- **No AND of v4 and v6 prefix-list matchers in one index** — the round-1
  defect. The two matchers only ever appear in separate sequences.
- **Determinism:** `pl.Prefixes` is iterated only to compute two booleans;
  iteration order does not affect output. FRR config generation is sorted
  by policy-statement name upstream.
- **No nil deref:** `po` is non-nil at this site (the function
  dereferences `po.PrefixLists`, `po.Communities`, etc. unconditionally
  above). The map index returns nil for a missing key (and indexing even a
  nil map is panic-safe in Go), guarded by the `pl != nil` check.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | v4-only and unknown/empty lists render byte-identically; only v6 (now correct) and mixed (now two-sequence, was broken) change |
| Lifetime / borrow-checker | N/A | Go, no borrow checker; the helper extraction is pure code motion |
| Performance regression | NONE | Control-plane render at commit time; one map lookup + slice scan per term |
| Architectural mismatch (#961 / #946-P2) | NONE | Single-family path mirrors the route-filter family branch; mixed path is the FRR-idiomatic two-sequence OR |

## Test plan

This is a control-plane (FRR render) change — **no dataplane smoke**, no
cluster deploy, no iperf3. Coverage is a Go unit test in `pkg/frr`.

1. `go build ./...` clean.
2. New render unit tests (white-box `package frr`, matching the existing
   `pkg/frr` test convention):
   - **v4 prefix-list** referenced by `from prefix-list` → output
     contains `match ip address prefix-list <name>` and does NOT contain
     `match ipv6 address prefix-list <name>`; ONE route-map sequence.
   - **v6 prefix-list** referenced by `from prefix-list` → output
     contains `match ipv6 address prefix-list <name>` and does NOT
     contain `match ip address prefix-list <name>`; ONE sequence.
   - **mixed prefix-list** → output contains `match ip address` in one
     route-map sequence and `match ipv6 address` in a SEPARATE sequence
     (assert TWO `route-map <name> ...` headers and that the two matchers
     are NOT in the same sequence body). This asserts the SAFE shape, not
     "both lines present somewhere" — guarding against the round-1 defect.
   - **unknown prefix-list name** (not in `po.PrefixLists`) → falls back
     to `match ip address`, one sequence (no panic, no regression).
   Each assertion is non-tautological: the v6 case FAILS against pre-fix
   code (which emits `match ip address`); the mixed case FAILS against
   both pre-fix code AND the rejected v1 dual-emit-in-one-sequence design.
3. An **end-to-end flat-set test** honoring the CLAUDE.md rule
   (`ParseSetCommand` + `tree.SetPath` loop, NOT `NewParser`): feed
   `set policy-options prefix-list v6nets 2001:db8::/32`,
   `set policy-options policy-statement p term t1 from prefix-list v6nets`,
   `... then accept`, compile with `CompileConfig`, render via
   `generatePolicyOptions(&cfg.PolicyOptions)` (note: `PolicyOptions` is a
   value field, so pass its address), assert `match ipv6 address`. This
   proves the family propagates compiler→render.
4. `go test ./pkg/frr/... ./pkg/config/...` green.
5. Named new test 5x for flake stability.
6. Full `go test ./...` green (30 Go packages).

**Docs:** `pkg/frr/README.md` describes `generatePolicyOptions`'
responsibilities at a high level but does not document per-clause
match-family rendering, so it stays accurate and needs no change — noted
here per the CLAUDE.md docs-contract rule.

## Out of scope (explicitly)

- The route-filter path's homogeneous-family assumption (it inspects only
  `RouteFilters[0].Prefix`). That is a pre-existing, separate behavior and
  not what #2071 reports. Not touched.
- Any change to how prefix-lists are *defined* in FRR (lines 535-540) —
  already family-correct.
- BGP address-family-aware route-map *attachment* (which `address-family`
  block a route-map is referenced under). Out of scope; the bug is the
  match clause, not the attachment.

## Round-1 review resolution

- **Reviewer A — PLAN-NEEDS-MAJOR (mixed-list dual-emit-in-one-sequence is
  FRR-broken).** ACCEPTED. Verified against FRR master source
  (`lib/routemap.c` AND truth-table + no AF pre-filter in the match loop;
  `bgpd/bgp_routemap.c route_match_address_prefix_list` returns NOMATCH on
  off-family). v2 replaces dual-emit with the single-family matcher for
  homogeneous lists and a **two-sequence OR** for mixed lists, and the
  mixed test now asserts the two matchers are in SEPARATE sequences.
- **Reviewer B — PLAN-READY w/ 2 minors.** Minor-1 (`&cfg.PolicyOptions`
  pointer in the end-to-end test) FOLDED into the test plan. Minor-2 (docs
  note) FOLDED — `pkg/frr/README.md` needs no change, stated explicitly.
  B's heuristic-consistency verification (the fix's `strings.Contains(":")`
  is byte-identical to the definition render at line 536, so the match
  clause and namespace can never disagree) is retained as a load-bearing
  correctness argument.

## Open questions for adversarial review (round 2)

1. **Two-sequence mixed-list emit:** is splitting a mixed-list term into a
   v4 sequence and a v6 sequence (each carrying the full term body, OR-ed
   by fall-through) semantically correct for both `permit` and `reject`
   terms? For a `reject` term, does the off-family sequence falling
   through (rather than denying) ever change the policy outcome vs. a
   single AF-agnostic Junos term? Challenge the OR-of-two-sequences model.
2. **Term-body duplication side-effects:** does emitting the `then`
   set-actions (next-hop, local-pref, metric, community, origin) twice —
   once per sequence — cause any double-apply hazard, or is it inert
   because only one sequence ever matches a given route?
3. **Lookup-miss default to v4:** still the right no-regression choice
   given FRR NOMATCHes an undefined list regardless of keyword?
4. **Seq renumbering:** the mixed case shifts later terms' seq numbers by
   +10. Any concern for config-diff churn or FRR reload behavior? (Claim:
   seq numbers only order evaluation; cosmetic.)
5. **Should mixed lists instead be rejected/warned at commit time** rather
   than rendered as two sequences? (Claim: two-sequence render preserves
   the operator's intent without a new failure mode; commit-time refusal
   would break configs that work today for v4.)
6. **Test adequacy:** does the mixed test assert the SAFE two-sequence
   shape (not merely "both lines present")? Does it prove non-tautology
   against BOTH pre-fix code and the rejected v1 design? Is the end-to-end
   flat-set test redundant or load-bearing?
