# #2071 — IPv6 prefix-list rendered with the IPv4 `match ip address` matcher

**Status:** DRAFT v1 — pending adversarial plan review

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
A prefix-list may hold v4 entries, v6 entries, or both (mixed). FRR's
`match ip address` consults only the v4-namespace list; `match ipv6
address` consults only the v6-namespace list. A given route is either v4
or v6, so the correct, safe behavior is to emit the v4 matcher when the
list has any v4 entry, and the v6 matcher when it has any v6 entry —
emitting **both** for a mixed list. Each clause is consulted only in the
matching address-family context, so a mixed list does the right thing in
both an inet and an inet6 route-map without ever ANDing two
mutually-exclusive matchers (FRR ANDs different-type match clauses, but
v4-vs-v6 are never simultaneously true for one route, so emitting both is
strictly correct per-AF and strictly better than today's v4-only).

```go
if term.PrefixList != "" {
    hasV4, hasV6 := false, false
    if pl := po.PrefixLists[term.PrefixList]; pl != nil {
        for _, p := range pl.Prefixes {
            if strings.Contains(p, ":") {
                hasV6 = true
            } else {
                hasV4 = true
            }
        }
    }
    // Unknown / empty prefix-list (not defined, or no entries): default
    // to the IPv4 matcher to preserve today's behavior — this is the
    // pre-fix rendering for the lookup-miss case, so no regression.
    if !hasV4 && !hasV6 {
        hasV4 = true
    }
    if hasV4 {
        fmt.Fprintf(&b, " match ip address prefix-list %s\n", term.PrefixList)
    }
    if hasV6 {
        fmt.Fprintf(&b, " match ipv6 address prefix-list %s\n", term.PrefixList)
    }
}
```

### Why look up the list instead of carrying family on the term

`PolicyTerm.PrefixList` is just the name string; the family lives on the
referenced `PrefixList.Prefixes`. The issue text itself calls out that
the fix "would need to look up `po.PrefixLists[term.PrefixList]` to
inspect the family." `po` is already the function parameter, so no
signature change is needed.

### Ordering

The match clause(s) are emitted in the same position as the current
single line (between the route-filter block and the `match
source-protocol` lines). For a mixed list, `match ip address` is emitted
before `match ipv6 address` (deterministic order). No other clause moves.

## Public API preservation

No signature changes. `generatePolicyOptions(po
*config.PolicyOptionsConfig) string` is unchanged. No exported symbols
touched. No config schema, AST, or compiler change.

## Hidden invariants the change must preserve

- **Output ordering:** the prefix-list match clause stays between the
  route-filter block and the `match source-protocol` block. Verified by
  reading the surrounding emits.
- **Lookup-miss behavior:** if `term.PrefixList` names a list not present
  in `po.PrefixLists` (or an empty list), the output is byte-identical to
  today (`match ip address prefix-list NAME`). No new failure mode.
- **Determinism:** `pl.Prefixes` is iterated only to compute two booleans;
  iteration order does not affect output. The two emits are in fixed
  order. FRR config generation is already sorted by name upstream.
- **No nil deref:** `po` is non-nil at this site (the function
  dereferences `po.PrefixLists`, `po.Communities`, etc. unconditionally
  above). The map index returns nil for a missing key, guarded by the
  `pl != nil` check.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | v4-only lists render identically; lookup-miss renders identically; only v6/mixed lists change, and they were broken |
| Lifetime / borrow-checker | N/A | Go, no borrow checker; no new allocations beyond two stack bools |
| Performance regression | NONE | Control-plane render, runs at commit time; one extra map lookup + slice scan per term |
| Architectural mismatch (#961 / #946-P2) | NONE | Mirrors the already-accepted route-filter family branch directly above; no new abstraction |

## Test plan

This is a control-plane (FRR render) change — **no dataplane smoke**, no
cluster deploy, no iperf3. Coverage is a Go unit test in `pkg/frr`.

1. `go build ./...` clean.
2. New render unit tests (white-box `package frr`, matching the existing
   `pkg/frr` test convention):
   - **v4 prefix-list** referenced by `from prefix-list` → output
     contains `match ip address prefix-list <name>` and does NOT contain
     `match ipv6 address prefix-list <name>`.
   - **v6 prefix-list** referenced by `from prefix-list` → output
     contains `match ipv6 address prefix-list <name>` and does NOT
     contain `match ip address prefix-list <name>`.
   - **mixed prefix-list** → output contains BOTH matchers.
   - **unknown prefix-list name** (not in `po.PrefixLists`) → falls back
     to `match ip address` (no panic, no regression).
   Each assertion is non-tautological: the v6 case FAILS against the
   pre-fix code (which emits `match ip address`), and the v4 case FAILS
   if the fix accidentally flips the default.
3. An **end-to-end flat-set test** honoring the CLAUDE.md rule
   (`ParseSetCommand` + `tree.SetPath` loop, NOT `NewParser`): feed
   `set policy-options prefix-list v6nets 2001:db8::/32`,
   `set policy-options policy-statement p term t1 from prefix-list v6nets`,
   `... then accept`, compile with `CompileConfig`, render via
   `generatePolicyOptions(cfg.PolicyOptions)`, assert `match ipv6
   address`. This proves the family propagates compiler→render.
4. `go test ./pkg/frr/... ./pkg/config/...` green.
5. Named new test 5x for flake stability.
6. Full `go test ./...` green (30 Go packages).

## Out of scope (explicitly)

- The route-filter path's homogeneous-family assumption (it inspects only
  `RouteFilters[0].Prefix`). That is a pre-existing, separate behavior and
  not what #2071 reports. Not touched.
- Any change to how prefix-lists are *defined* in FRR (lines 535-540) —
  already family-correct.
- BGP address-family-aware route-map *attachment* (which `address-family`
  block a route-map is referenced under). Out of scope; the bug is the
  match clause, not the attachment.

## Open questions for adversarial review

1. **Mixed-list correctness:** is emitting BOTH `match ip address` and
   `match ipv6 address` for a mixed prefix-list correct, or could FRR AND
   them and break matching in a single-AF route-map? (Claim: a route is
   exactly one family, so the off-family matcher is simply never
   consulted; per-AF behavior is correct. Challenge this.)
2. **Lookup-miss default:** is defaulting to `match ip address` on an
   undefined/empty prefix-list the right no-regression choice, or should
   it emit nothing / a warning? (Pre-fix behavior was v4; preserving it
   avoids surprise, but is silent-v4 the right call?)
3. **Is the family knowable at render time at all?** Could a referenced
   prefix-list legitimately be absent from `po.PrefixLists` in production
   (forward reference, cross-instance)? If so, is silent v4 a latent bug?
4. **Ordering:** does emitting `match ip` before `match ipv6` for mixed
   lists matter to FRR, or to config-diff stability? (Claim: independent
   clauses, order-irrelevant to FRR; fixed order for diff stability.)
5. **Should the fix instead refuse / warn at commit time** when a v6
   prefix-list is referenced from an inet-only policy context, rather than
   fixing the renderer? (Claim: the renderer is the right layer — the
   policy term itself is AF-agnostic in Junos; the render must honor the
   referenced list's family. Challenge.)
6. **Test adequacy:** does the unit test prove non-tautology (fails
   pre-fix) AND cover the mixed + lookup-miss cases? Is the end-to-end
   flat-set test redundant or load-bearing?
