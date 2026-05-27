# Claude SMR plan review — round 5 (plan v5 → v6)

## Plan v5 round-5 verdict: PLAN-NEEDS-MAJOR (convergent with Codex r5)

Codex r5 caught two real issues in v5 that I missed in my r4 review.

### F-r5-1: v3-shaped "any" → MatchNone (FAIL-CLOSED regression)

Verified against the code. `userspace-dp/src/policy.rs:520`:

```rust
fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    ...
}
```

"any" pushes NO prefixes. So a v3-shaped rule with
`source_literals=["any"]` would produce empty prefix vecs →
`from_v3_literals(empty) = MatchNone` → `MatchNone.contains() =
false` → src side fails closed.

This is a structural semantic regression (Junos "match any" rule
silently matches nothing in the v3 path).

V6 fixes this by introducing an explicit "any" token handler in the
new `parse_v3_literal_set` helper. The helper carries
`any_v4: bool` / `any_v6: bool` flags before vec collapse; if set,
force `MatchAny`.

### F-r5-2: fallibility scope too narrow

V5 said "`parse_policy_state_with_counters` becomes fallible; errors
propagate to the snapshot handler BEFORE any side-effect." But
walking the actual call graph reveals multiple side-effecting
mutations BETWEEN the snapshot handler and the policy build:

- `snapshot.rs:apply` mutates `guard.status.last_snapshot_generation`
  + several other status fields at lines 37-41 BEFORE calling the
  reconcile/refresh path.
- `Coordinator::refresh_runtime_snapshot` mutates neighbor manager
  keys, validation, and counters BEFORE calling
  `build_forwarding_state_with_policy_counters_and_previous`.
- `reconcile/snapshot.rs:apply` applies validation and reconciles
  counters BEFORE the forwarding build.

V5's "+2 LOC at the one call site" was wrong — the actual fix needs
to propagate fallibility through `build_forwarding_state*`,
`Coordinator::refresh_runtime_snapshot`, the reconcile path, and
the snapshot handler. The snapshot handler must do a **preflight
build** before any of its status-field mutations.

V6 corrects the scope. The change list now includes:
- `forwarding_build/mod.rs`: build_forwarding_state* fallible.
- `coordinator/mod.rs:454-485`: refresh_runtime_snapshot
  propagates the Result.
- `reconcile/snapshot.rs`: preflight build before mutations.
- `server/handlers/snapshot.rs`: preflight build at the top,
  before any guard mutation.

## V6 incorporates AGY r5 F2 (tie-breaker)

AGY r5 voted PLAN-READY but offered a minor refinement: when two
distinct CONTENT hashes collide on low_32, sort by full 64-bit hash
value to break ties deterministically. V6 adds this — buckets are
sorted by full 64-bit FNV-1a hash before entering the probe loop.
This is overlay-safe: at ≤10K books (realistic enterprise) the
content-hash collision rate is effectively zero, so the sort is a
no-op in practice; at 100K+ books, it makes the order
deterministic.

## V6 verdict: PLAN-READY (pending Codex r6 confirmation)

The plan now:
1. Closes the original fail-open paths (book-only rule,
   family-incomplete book) via `MatchNone` + `from_v3_literals`.
2. Closes the v3-shaped "any" → MatchNone regression via the
   explicit any-token handler in `parse_v3_literal_set`.
3. Propagates fallibility through the full call graph
   (forwarding_build → coordinator → reconcile → handler), with
   the snapshot handler running a preflight build before any
   side-effect.
4. Has deterministic collision-resolution tie-breaking via
   full-64-bit-hash bucket ordering (AGY r5 F2).
5. Closes all prior-round findings (HA determinism, version
   baseline, content-vs-name dedup, u32 widening, family/count
   hash framing, hard-fail unknowns).

If Codex r6 doesn't find a new structural issue, this should be
PLAN-READY.

## What I'd kill on r6

- Discovery of any path where a `from_prefixes(empty)=MatchAny`
  result reaches a v3-shaped rule's match-side.
- An incomplete fallibility-propagation chain (e.g. a side-effect
  that runs before the preflight build).
- Any new collision-determinism gap.

None of those should be present in v6 by construction. But Codex
has surprised me three rounds in a row, so I won't pre-bless.
