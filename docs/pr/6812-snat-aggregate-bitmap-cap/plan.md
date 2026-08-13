# #6812 — Lenient SNAT aggregate eager bitmap allocation (opus-review-001 R73)

## Problem

The #5877 aggregate cardinality gate hard-rejects an over-budget source-NAT
config at STRICT commit and downgrades to a warning on the tolerant load /
peer-sync path (#1960 no-brick). But a tolerated over-budget config still
reaches the Rust apply boundary, which:

1. builds `PortAllocator::new(total_pool, port_low, port_high)` EAGERLY for
   every pool-mode rule with `total_pool > 0` — BEFORE the reuse maps are
   consulted and even when `pool_failure` is already set
   (`userspace-dp/src/nat/source.rs:723-737`), and
2. has NO aggregate budget at the final allocation boundary — only the
   per-member `MAX_POOL_PREFIX_HOSTS = 65536` cap.

Three full-range `/16` pools (the review trace) expand 196,608 addresses and
construct one `AddressOccupancy` word array per address: 12,683,575,296
bitmap bits (~1.48 GiB) before counters, live-state indexes, and address
vectors — on an upgrade boot or HA convergence the apply can stall or OOM the
dataplane while processing the legacy config the tolerant path exists to
recover.

## Approach

Two coordinated layers, one shared formula.

### Rust apply boundary (the fix that makes the eager bitmap impossible)

Restructure `parse_source_nat_rules_with_previous` into parse + resolve
phases:

- The parse loop is unchanged (match prefixes, pool member expansion,
  failure determination, deterministic CGNAT) EXCEPT the allocator block is
  deferred: it records a per-rule `PendingPoolAllocator { port_low,
  port_high, total_pool }` only for rules that pass today's
  `allocator_key()` gate (`pool_mode && total_pool > 0 && pool_failure.is_none()`).
- A new `resolve_pool_allocators` pass then assigns allocators:
  - **Reuse before build**: consult this-apply and previous-apply allocator
    maps FIRST; only a miss constructs `PortAllocator::new`. A same-config
    re-apply no longer builds (and immediately discards) a full bitmap per
    pool.
  - **Failed pools build nothing**: a rule with `pool_failure` keeps the
    empty default allocator. The match path short-circuits on `pool_failure`
    before touching the allocator, and `reserve_flow` on an empty allocator
    returns false gracefully, so this is behavior-safe.
  - **Aggregate budget gate**: distinct allocator keys are charged against
    budgets mirroring Go's #5877 constants (count 1024, addresses 1,048,576,
    port capacity 2^33) in deterministic first-seen order. REUSED keys
    consume budget but are always accepted (a no-op re-apply must not kill
    live state); NEW keys are admitted only if they fit the remaining
    budget, first-fit (a refused key does not consume budget, so a later
    smaller key can still install). Refused keys mark every referencing rule
    `pool_failure = OverBudget` (fail-closed with a dataplane diagnostic via
    the existing `exception_reason` plumbing) and build no bitmap.
- Charging reuse is load-bearing: without it, a two-step apply (two
  full-range /16 pools, then the same two plus a third) would creep past the
  2^33 slot budget one apply at a time — the exact 1.48 GiB scenario via
  incremental applies.
- Port-capacity charge reuses `allocator_capacity` (now `pub(super)`) — one
  formula, no drift.
- New `SourceNatFailureReason::OverBudget` with exception reason
  `source_nat_pool_over_budget`; the snapshot-reason mapper learns
  `"aggregate_over_budget" -> OverBudget` (wire-skew safe: an old helper
  maps the unknown string to `InvalidPool` via its catch-all, still
  fail-closed).
- Config-vs-state hygiene folded in during implementation: with failed
  pools no longer building an allocator, `pool_allocator` is the empty
  default for them — but `source_nat_pool_statuses` read the port range
  off the allocator, so failed pools would have reported the default
  1024-65535 instead of their configured range. The configured
  (snapshot-defaulted) range now rides on the rule (`pool_port_low` /
  `pool_port_high`); the status view and `allocator_key()` read it from
  there, the allocator of a healthy pool is built with exactly those
  values, and a failed pool's status keeps telling the truth.

### Go tolerant snapshot poison (per-pool diagnostic + shrink the blast radius)

- Extract the #5877 validator's referenced-pool walk into
  `sourceNATAggregateReferencedCharges` (same deterministic sorted-rule-set
  order, same saturating arithmetic). The strict validator keeps its exact
  error messages but runs on the shared walk — one source of truth for
  scoping and charge arithmetic.
- New exported `SourceNATAggregateOverBudgetPools(cfg)` runs the SAME
  first-fit admission the Rust boundary uses and returns the pool names that
  do not fit.
- `buildSourceNATSnapshotsWithFeeds` marks a rule's pool
  `PoolUnusable=true`, `PoolUnusableReason="aggregate_over_budget"` when its
  pool is in that set (only if not already unusable for a more specific
  reason). Strict-commit configs never reach the builder over budget, so
  this only ever fires for tolerated configs — the path that needs it. The
  operator gets a per-pool unusable signal (`show` + counters) instead of a
  silent dataplane refusal, and the refused pool's bitmap is never requested
  of the helper at all.

### Strict-vs-lenient split (assignment checkpoint)

Unchanged and already correct: strict commit / commit-check hard-rejects
(`validateSourceNATAggregateCardinalityStrict`, also in the #5876
peer-effective view), tolerant load / peer-sync warns and boots (#1960).
This PR closes what the tolerant path does AFTER the warning: the snapshot
poisons the over-budget pools and the Rust boundary refuses their bitmaps,
so "boots" no longer means "materializes 1.48 GiB of allocator state".

## Files touched

- `userspace-dp/src/nat/source.rs` — parse/resolve split, budget gate,
  `OverBudget` reason, snapshot-reason mapping, rule-carried port range.
- `userspace-dp/src/nat/allocator.rs` — `allocator_capacity` -> `pub(super)`;
  `#[cfg(test)]` white-box accessors (`debug_occupancy_words`,
  `debug_shared_identity`); header doc paragraph on the budget.
- `userspace-dp/src/nat/status.rs` — status reads the rule-carried range.
- `userspace-dp/src/nat/tests_aggregate_budget.rs` (new) + `mod.rs`
  registration.
- `pkg/config/compiler_validate_strict_nat.go` — walk extraction +
  `SourceNATAggregateOverBudgetPools`.
- `pkg/config/compiler_nat_source_pool_aggregate_6812_test.go` (new).
- `pkg/dataplane/userspace/nat_source.go` — tolerant poison.
- `pkg/dataplane/userspace/nat_source_aggregate_6812_test.go` (new).
- `docs/config-schema.md` — update the #5877 section (tolerant path now
  poisons; Rust boundary enforces the same budget; reuse-before-build).
- `_Log.md`.

## Test strategy (fail-on-revert)

Rust (`cargo test -p xpf-userspace-dp nat::tests_aggregate_budget`):
- tiny injected budget (parse wrapper takes a budget; production passes the
  const): 3 pools of 8 addrs x 10 ports, cap 200 slots -> third key refused
  with `OverBudget`, `debug_occupancy_words() == 0` for it, accepted keys
  carry real bitmaps; match on the refused rule returns `Unavailable` with
  `source_nat_pool_over_budget`.
- reuse charges budget + preserves last-good: apply1 pools A,B; apply2 A,B,C
  -> A,B are the SAME Arc (identity accessor), C refused (240 > 200).
  Charge-new-only would accept C -> RED.
- failed pool builds no bitmap (`pool_unusable` snapshot): occupancy words 0
  (pre-fix: 8) -> RED on revert of the skip.
- first-fit continuation: small, oversize, small -> middle refused, last
  accepted.
- real-const arithmetic pin of the review scenario: 2 x (65,536 x 64,512)
  admitted, third refused; the refused candidate sum is exactly
  12,683,575,296 slots. No allocation — pure admission-function test.
- `"aggregate_over_budget"` snapshot reason maps to `OverBudget`.

Go:
- `pkg/config`: `SourceNATAggregateOverBudgetPools` — count/address/
  port-capacity trips poison exactly the first non-fitting pool(s);
  at-budget -> empty; first-fit continuation; unreferenced pools ignored.
- `pkg/dataplane/userspace`: lenient-compile the review fixture (3 x /16
  full-range) -> snapshot for p2 is `PoolUnusable` with reason
  `aggregate_over_budget`, p0/p1 unaffected; under-budget config all usable.
- Existing #5877 strict tests unchanged and still green (strict reject +
  lenient warn preserved).

## Out of scope

- Not changing the allocator's per-pool memory model (bitmap per address).
- Not bounding the raw address-vector expansion (bounded by the Go grammar
  and the poison for tolerated configs; the bitmap is the 1.48 GiB driver).
- NAT64 has its own allocator keying; the review scoped R73 to source-NAT.

## Post-review correction — F1: the two admissions were not the same set

The design above says `SourceNATAggregateOverBudgetPools` "runs the SAME
first-fit admission the Rust boundary uses". The ORDER and the CHARGE matched;
the SCOPE did not, and the gap was a fail-closed over-rejection.

The Go walk charged every DEFINED referenced pool. The snapshot builder, in a
separate pass further down the same config, marks a pool UNUSABLE for reasons
settled by the pool definition alone — empty membership, a `%zone` member
(#5875), a port range the parser rejected (#5457). Rust never charges those:
the parse loop only records a `PendingPoolAllocator` when
`pool_failure.is_none()`, so `resolve_pool_allocators` neither charges such a
pool nor lets it occupy a slot. `MaxSourceNATPoolCount` unusable pools therefore
filled the whole pool-count budget Go-side while costing the dataplane nothing,
and the next HEALTHY pool was poisoned `aggregate_over_budget` — a pool the
dataplane would have installed. Reproduced on all three unusable shapes, plus a
fourth where the definition is fine but no member expands.

It lands on the TOLERANT path specifically (lenient load / peer-sync, #1960
no-brick), which is the path an operator uses to recover — the worst place to
over-reject.

Fix: the unusability verdict became a SHARED predicate instead of builder-local
knowledge. `config.SourceNATPoolMembers`, `config.SourceNATPoolPortRange`
(moved out of pkg/dataplane/userspace) and `config.SourceNATPoolUnusableReason`
are now read by BOTH the builder (to poison) and the budget walk (to SKIP);
`pkg/nat`'s third hand-copy of the port-range rule delegates to the same
function. The walk additionally skips a pool whose members all fail to expand,
mirroring Rust's `total_pool > 0` gate. No strict-path change:
`validateSourceNATPoolStrict` / `validateSourceNATPoolAddressScopeStrict` run
earlier in `runUniformGates`, so an unusable pool never reaches the aggregate
sum on a strict commit — and a pool that builds no allocator costs no allocator
memory, so the resource model is unchanged either way.

The equivalence claim is now TESTED on both sides rather than asserted in a
comment: `TestAggregateBudgetExcludesUnusablePools_6812` (pkg/config) and
`TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812`
(pkg/dataplane/userspace) drive the Go half and pin the exact snapshot markers
that `production_entry_admits_a_healthy_pool_after_failed_pools_6812`
(userspace-dp) feeds to the Rust production entry at the real budget.
