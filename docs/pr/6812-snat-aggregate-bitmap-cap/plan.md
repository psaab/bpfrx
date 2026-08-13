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
mirroring Rust's `total_pool > 0` gate. **[SUPERSEDED IN ROUND 2 — that skip
was a SUM standing in for an all-or-nothing runtime contract; see "Round 2"
below.]**

No strict-path change. **[CORRECTED IN ROUND 2]** The gate order in
`runUniformGatesNAT` is port-range (:109), pool-reference (:134), zone-scope
(:163), address-grammar (:189), aggregate (:228), so strict acceptance is
genuinely unchanged — but the two gates originally cited
(`validateSourceNATPoolStrict` / `validateSourceNATPoolAddressScopeStrict`)
cover only the port range and the `%zone` qualifier. It is
`validateSourceNATPoolAddressGrammarStrict` at :189, missing from the original
account, that keeps the empty, malformed, mixed-invalid and over-capacity
membership shapes away from the aggregate sum on a strict commit. A pool that
builds no allocator costs no allocator memory, so the resource model is
unchanged either way.

The equivalence claim is now TESTED on both sides rather than asserted in a
comment: `TestAggregateBudgetExcludesUnusablePools_6812` (pkg/config) and
`TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812`
(pkg/dataplane/userspace) drive the Go half and pin the exact snapshot markers
that `production_entry_admits_a_healthy_pool_after_failed_pools_6812`
(userspace-dp) feeds to the Rust production entry at the real budget.

## Round 2 — the fifth unusability class, and why it was the last one

Codex re-gate at `a00a03fc1`: **MERGE-NEEDS-MAJOR**. Round 1 closed four
classes of "pool that installs nothing but charges the budget" by adding
conditions to a host-count sum. A fifth class was still open, and its existence
was the finding — not the class itself.

### The class

The runtime's pool grammar is **ALL-OR-NOTHING**. `parse_source_nat_rules_inner`
ORs `expand_pool_address` over every member into one `invalid_pool_address`
flag and fails the WHOLE pool as `InvalidPool`
(`userspace-dp/src/nat/source.rs`, the `invalid_pool_address` assignment and
the `pool_failure` chain); the `PendingPoolAllocator` gate
(`pool_mode && total_pool > 0 && pool_failure.is_none()`) then builds nothing,
so the pool occupies no slot in `resolve_pool_allocators`.

Round 1's budget walk instead SUMMED per-member host counts and skipped only a
zero total. Two shapes escape that:

| membership | round-1 sum | runtime | round-1 outcome |
|---|---|---|---|
| `[198.51.100.1, not-an-ip]` | 1 + 0 = **1** | whole pool `InvalidPool` | **charged** |
| `[10.0.0.0/15]` | **131,072** | over the 65,536 cap → `InvalidPool` | **charged** |

Measured before the fix, through the real `CompileConfigLenient` +
`SourceNATAggregateOverBudgetPools`: 1,024 pools of the first shape ahead of one
healthy pool put `poison[good] = true`, reason `aggregate_over_budget` — the
original F1 defect, alive on the lenient / peer-sync path. One pool of the
second shape charged `addrs=131072 portCap=8,455,716,864`, 98.4% of the 2^33
port-capacity budget, for an allocator that never exists.

### The fix: consult the verdict, do not re-derive it

Not a fifth condition. `config.SourceNATPoolUnusableReason` — the predicate the
snapshot builder ALREADY stamps on the wire — gained an all-or-nothing
membership clause built from `sourceNATPoolAddressReason`, the existing
per-member mirror of `expand_pool_address` that the #5627 strict grammar gate
uses. The budget walk's pre-existing `SourceNATPoolUnusableReason(pool) != ""`
skip then covers both shapes with no new condition, and the two sides cannot
disagree because there is one predicate.

Wire reason: **`invalid_pool`**, which
`source_nat_failure_reason_from_snapshot` already decoded to
`SourceNatFailureReason::InvalidPool` — the exact variant the parse loop
assigned for these pools on its own. The dataplane disposition is therefore
unchanged; only the DECIDER moves, control-plane-ward, where the budget can see
it. `go_side_invalid_pool_verdict_matches_the_parse_loop_verdict_6812` compares
the two wire shapes field for field to bind that.

Precedence: the clause sits between `empty_pool` and `zone_scoped_pool_address`,
deliberately. `netip.ParsePrefix` rejects a zone qualifier, so `fe80::1%eth0/64`
fails the grammar too; only a LATER `zone_scoped_pool_address` write keeps that
member reporting the specific #5875 reason it reported before. All three
pre-existing reasons remain reachable under exactly their old conditions — and
the ordering is now BOUND by a `zone_scoped_prefix` cell rather than asserted in
a comment. Nothing covered it before: the #5875 tests pin the STRICT diagnostic,
which is protected by gate order (zone-scope :163 precedes address-grammar
:189), and the snapshot-side #5875 test uses a bare `fe80::1%eth0`, which
netip parses — so the clause order never mattered to it.

### What became unrepresentable

The `poolAddrs == 0` skip was **deleted, not kept as a belt**. It is
unreachable: the shared verdict is all-or-nothing over
`sourceNATPoolAddressReason`, so a pool with any unparseable member is already
excluded; a pool with no members reports `empty_pool`; and a member that parses
has a host count of at least 1. A charged pool therefore always sums to >= 1.
`TestBudgetChargeImpliesHonorableMembers_6812` binds both premises over the full
grammar surface, since a deleted branch cannot be tested directly.

### Fixture vacuity found while re-cutting

`snatAggregateCfg_6812` emitted `10.<i>.0.0/16`, valid only for i < 256. At
`MaxSourceNATPoolCount+1` pools, indices 256..1024 were unparseable — so 769 of
the 1,025 pools in the "healthy pools past the budget" over-reach control were
never healthy. The old zero-total rule silently skipped them; the shared verdict
names them. Fixed (`distinctSlash16_6812`) plus a by-name precondition in the
fixture builder.

The `no_member_expands` cell was re-cut: it now binds through the shared verdict
(`wantReason: "invalid_pool"`) rather than through the deleted zero-total rule,
and every cell asserts its round-1 host-count sum exactly, so a case cannot be
mistaken for a class it does not exercise.

## Round 3 — the round-2 premise, corrected

Codex re-gate at `3b7c71cca`: **MERGE-NEEDS-MAJOR**, three findings. The first
undercuts the sentence round 2 leans on above: *"the two sides cannot disagree
because there is one predicate."*

**That sentence is false as written, and the correction is the round.** Sharing
one predicate between the snapshot builder and the budget walk makes the two
**Go** call sites agree. Whether Go and the dataplane agree is a claim about two
**PARSERS**, and nothing in round 2 established it. Round 2 removed the last
*derived quantity*; it did not remove the last *unverified premise*.

### F1 — measured, and the cited instance was wrong

The finding cited `198.51.100.1/032` (Go rejects a leading-zero prefix length,
Rust's `IpNet` allegedly accepts it). Running the real `expand_pool_address`
against the real `sourceNATPoolAddressReason` over a 53-entry table shows **both
sides reject it**: `ipnet`'s prefix-length reader is `read_number(10, 2, 33)`
for IPv4 — a two-DIGIT cap, not a canonical-form rule — so a three-digit `/032`
fails to parse there too. Its IPv6 reader allows three digits, so `/064` *does*
parse as `/64`, but every leading-zero-expressible prefix length is over
`MAX_POOL_PREFIX_HOSTS` anyway, so the pool is refused regardless. **That
agreement is a coincidence of two unrelated bounds, not a property** — raising
the host cap would split them — so the mask grammar is now pinned explicitly
(`parse_canonical_prefix_len`) instead of left to arithmetic.

The general claim was right; the field was wrong. The measured differential
found **six** divergences, in both directions:

| member | Go (netip) | Rust (before) | class |
|---|---|---|---|
| `010.0.0.0/24` | reject | **accept, 256 hosts** | leading-zero IPv4 octet |
| `10.000.0.0/24` | reject | **accept, 256** | " |
| `192.168.001.1/32` | reject | **accept, 1** | " |
| `010.0.0.0/32` | reject | **accept, 1** | " |
| `00.0.0.0/24` | reject | **accept, 256** | " |
| `::ffff:010.0.0.0/120` | reject | **accept, 256** | " (embedded v4) |
| `fe80::1%eth0` | **accept** | reject | IPv6 zone on a bare member |

Root cause: `expand_pool_address`'s CIDR branch parsed via `ipnet::IpNet`, which
hand-rolls its own address parser (`read_number(10, 3, 0x100)` per octet —
up to three digits with any leading zeros), while its BARE branch used
`std::net::IpAddr`, which rejects a leading-zero octet exactly as Go's `netip`
does. The function was self-inconsistent: `010.0.0.1` refused, `010.0.0.1/32`
accepted as `10.0.0.1`.

**Fix: in the runtime, not the predicate.** The CIDR branch now parses its
address half with the same `std::net::IpAddr` the bare branch always used, and
its mask half with `parse_canonical_prefix_len`; `IpNet` is no longer on the
pool-member path at all. Rejected alternatives:

- *Widen Go to match `ipnet`.* This blesses an octal-confusion spelling at
  commit — `010` is 8 to some resolvers, which is why both `std` and `netip`
  refuse it — and mirrors a third-party crate's accident as firewall policy.
- *Document the divergence.* It is a live over-rejection: Go stamps
  `invalid_pool`, the builder poisons the pool, and a pool the dataplane would
  have installed translates nothing — on the tolerant load / peer-sync path
  (#1960 no-brick), which is the path an operator recovers through.

The chosen direction is narrowing and fail-closed, and it changes **no** pool's
disposition: `InvalidPool` is the verdict Go already assigned. Only the
disagreement is removed. The zone half is closed on the Go side instead, because
there the runtime is the stricter one; the #5875 precedence is unaffected
(`SourceNATPoolUnusableReason` writes `zone_scoped_pool_address` after the
grammar clause, and the scope gate is registered before the grammar gate) and
`TestZoneScopedBarePoolAddressKeepsItsSpecificReason_6812` binds that.

**The class-level fix is the fixture.** `userspace-dp/tests/fixtures/
snat_pool_grammar_v1.json` is ONE table read by both
`TestPoolAddressGrammarMatchesDataplane_6812` (Go) and
`nat_pool_grammar_parity_fixture` (Rust, through the real
`expand_pool_address`) — same convention as the #3612 AppID parity guard.
Neither side keeps a copy, verdict AND expanded host count are both asserted,
and `nat_pool_bare_and_host_cidr_grammars_agree` separately drives the
bare-vs-CIDR invariant inside Rust so the self-inconsistency cannot return by a
different route.

### F2 — the guard fires; the claim under it did not hold

The finding says the aggregate walk recomputes the port range from raw fields,
so a referenced pool with no `port` leaf charges a zero-width window and is
admitted. **Measured through the real `CompileConfigLenient`: it does not.**
`compileNATSource` defaults an unset `PortLow`/`PortHigh` to 1024/65535 before
storing the pool, so three `/16` pools with no `port` leaf charge
`portCap=4,227,858,432` each and the third is poisoned — which is exactly what
`TestAggregateOverBudgetPoolsPortCapacity_6812` has been asserting all along.

The SHAPE is real even though the instance is not: a consumer re-deriving what a
shared function already answers, with the equivalence resting on a defaulting
three files away and nothing binding the two. The walk now consults
`SourceNATPoolPortRange` — the resolver the builder ships to the dataplane.
Behaviour-preserving on the live path, and now a contract:
`TestAggregateChargeConsultsResolvedPortRange_6812` drives a `*NATPool` with the
raw 0/0 the resolver documents as its input (charging 0 before the fix,
12,683,575,296 after), and `TestCompiledPoolCarriesDefaultedPortRange_6812` pins
the other half so the claim "behaviour-preserving" is itself tested.

### F3 — first-fit order, and a false claim in this PR's own prose

Confirmed. Go ordered rule-sets by NAME; the builder emits rules STABLE-sorted
by #4161 scope tier; `resolve_pool_allocators` charges that emitted slice in
order. With two pools that each fit alone but not together, an alphabetically
earlier ZONE-scoped rule-set took the budget and the more-specific
INTERFACE-scoped rule-set's pool was poisoned `aggregate_over_budget`.

Two things are worth stating precisely. First, this is **not** a Go/Rust
disagreement in the shipped artefact: the poison travels on the wire and the
Rust parse loop honours it, so both sides always agree on which pools live. It
is a defect of POLICY — the surviving pool was chosen by an unrelated
alphabetical accident, contradicting the Junos most-specific-wins precedence the
builder enforces for matching one function later. Second, it made this PR's own
sentence *"the first-fit admission rule here mirrors it exactly — same order,
same charge"* false on the order axis.

Fix: the walk stable-sorts by the same tier, through ONE definition —
`config.SourceNATScopeTier`, moved out of `pkg/dataplane/userspace` so the
builder and the walk call it rather than each spelling it. The sibling
grammar/scope gates keep their name sort; they pick a deterministic
first-reported OFFENDER for an error message, where admission plays no part.
`TestAggregateFirstFitFollowsEmittedScopeOrder_6812` (with preconditions that
each pool fits alone and the pair does not, so the fixture cannot decay into one
that no longer discriminates on order) and
`TestSnapshotPoisonFollowsEmittedScopeOrder_6812` (at the emission boundary)
bind it.

### Fixture re-cut

No fixture cell changed meaning. The widened grammar rejects strictly more on
the Rust side and one more shape on the Go side, and no existing cell uses a
leading-zero octet or a zone-scoped bare member except the #5875 snapshot cell —
which continues to bind `zone_scoped_pool_address` for the reason it always
did, now verified by an explicit precedence test rather than by the clause order
alone.
