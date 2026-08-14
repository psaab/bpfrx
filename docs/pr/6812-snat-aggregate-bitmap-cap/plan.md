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

The chosen direction is narrowing and fail-closed. **The claim that stood here —
that it changes no pool's disposition — is false, and round 4 below corrects
it**: on the TOLERANT path a pool with an `010.0.0.0/24` member goes from
translating to poisoned across this branch. `InvalidPool` is the verdict the Go
predicate already assigned, which is why the round-3 leg reached that
conclusion; but the Go predicate itself only started assigning it one commit
earlier, in round 2. The zone half is closed on the Go side instead, because
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

## Round 4 — a disposition change I said did not happen, and a backstop that was order-dependent

Codex re-gate at `8f9b53b44`: **MERGE-NEEDS-MAJOR**, three findings. The first
falsifies a claim this document made in round 3.

### F1 — the tolerant path moved, and the movement is round 2's, not round 3's

Round 3 argued the narrowing "changes no pool's disposition: `InvalidPool` is
the verdict Go already assigned". True on the STRICT path — `netip.ParsePrefix`
has rejected `010.0.0.0/24` since #5627 — and **false on the tolerant one**:

| tree | tolerant snapshot | runtime |
|---|---|---|
| merge base `edefb7570` | `PoolUnusable=false` | `ipnet` reads it as `10.0.0.0/24`, allocator built, **flows translate** |
| this branch | `PoolUnusable=true`, `invalid_pool` | `Unavailable`, **packets dropped** |

A config on disk today, or arriving from an older primary over peer-sync, goes
from working SNAT to a persistent silent outage across the upgrade.

**The attribution matters and was missed by every leg, including mine.**
`config.SourceNATPoolUnusableReason` **does not exist at the merge base**
(`git show edefb7570:pkg/config/compiler_validate_strict_nat.go` has no such
function). The membership-grammar clause that stamps `invalid_pool` arrived in
ROUND 2 (`bc1329ae0`); round 3's Rust narrowing only stopped the runtime
disagreeing with a poison Go had already begun applying. Reverting round 3
alone would restore the divergence without restoring the pool. So the question
is not "narrow Rust or not" — it is **"should the shared verdict refuse a
non-canonical literal"**.

### The decision: keep the refusal, make the diagnostic name the fix

Three options were on the table: normalize on the tolerant path, keep the
poison and make it loud, or something else. **Kept, deliberately**, for reasons
in descending strength:

1. **#5875 already settled this exact question in this exact subsystem, and
   chose reject over rewrite.** Its rationale is in the code:
   "stripping the `%zone` silently would change the modeled address, so the fix
   rejects rather than rewrites". A leading zero is the WEAKER case of the two —
   `010` has two readings (decimal 10, octal 8) where `fe80::1%eth0` has exactly
   one. Normalizing here would overturn a settled doctrine for the worse case.
2. **Normalizing installs a NAT pool on a guess that nothing reveals.**
   `show configuration` would print `010.0.0.0/24` while the dataplane
   translated from `10.0.0.0/24`. A stopped pool is loud — packets drop, two log
   channels fire. A silently reinterpreted pool is quiet and wrong, which is the
   worse failure mode for a firewall.
3. **The merge base was already making this promise.** Its warning said the
   dataplane "marks the pool unusable (InvalidPool) and drops it at runtime,
   silently stopping translation" — aspirational there. This branch makes the
   code honest.

**Where the framing of option (b) needed re-scoping.** "Make it loud" implies
adding a signal. Both channels already exist and already fire: the compiler's
downgraded gate message lands in `cfg.Warnings`, which the daemon logs at apply
(`slog.Warn("config validation", ...)`, daemon_apply.go), and the snapshot
builder logs its own `slog.Warn` naming the pool and reason. Adding a third
would have been noise. What was actually missing is that the message says
**"is not a valid CIDR"** for a string that looks exactly like one — so the
operator cannot see that the fix is deleting one character. The deliverable is
therefore a SPECIFIC diagnostic, not new plumbing:

> address `"010.0.0.0/24"` spells an octet with a leading zero; write it as
> `"10.0.0.0/24"` — a leading zero is octal to some parsers, so the dataplane
> refuses the ambiguous spelling rather than guessing, and marks the whole pool
> unusable (this pool translates nothing until the address is corrected)

`canonicalPoolAddressHint` computes the canonical spelling and is used ONLY to
render that sentence — never to substitute. It reports a rewrite only when the
rewrite is what made an unparseable literal parse, so it can never suggest a
change to an address that already works, and never invents a suggestion for an
unrelated malformation.

Regression tests drive the real tolerant entries, which nothing had ever
covered: `CompileConfigLenient` (tolerant load) and `CompileConfigForNodeLenient`
(peer-sync, both node ids) — asserting the compile SUCCEEDS (#1960 no-brick
holds), that the warning names both spellings and says translation stopped, that
the pool is poisoned, and that the raw literal still ships unmodified.

### F2 — CONFIRMED by measurement: the backstop was order-dependent

Verified before touching anything, since the finding was relayed unreproduced.
Two live pools A and B at 160 of a 200-slot test budget, plus a new C worth 80:

| snapshot order | C | live occupancy |
|---|---|---|
| `A, B, C` (the existing test) | `OverBudget` | 16 words |
| `C, A, B` | **admitted, bitmap built** | **24 words = 240 slots vs a 200 cap** |

Same pools, same reuse map, opposite outcome from ORDER alone — and it repeats,
one extra pool per apply. `resolve_pool_allocators` charged a reused key where
it MET it, so a new key earlier in the slice was admitted against a `used` total
that did not yet include the reused keys behind it, and those are then accepted
unconditionally.

Go-side poisoning hides this for snapshots this control plane generates, which
is exactly why it mattered: this boundary exists as the INDEPENDENT backstop for
a tolerated, older-control-plane or handcrafted snapshot, where no Go poison is
coming.

Fixed by splitting the resolver into two phases: phase 1 charges every DISTINCT
key that will be reused, phase 2 admits. Reused keys are still always accepted
(never kill last-good state) and are charged exactly once; new-key admission now
sees the true live total whatever order the snapshot arrives in. The new test
asserts the refusal, a zero construction count, the preserved live identities,
and order-INVARIANCE directly; a second test drives three incremental applies
and asserts the live set stops at the cap instead of growing per generation.

### F3 — the guards did not bind, and one proposed mutation needed re-sizing

Two were end-state assertions blind to a transient allocation: identity of the
final allocator, and its occupancy-word count. Both survive a throwaway
`PortAllocator::new` immediately before the reuse lookup — the pre-#6812
build-then-discard behaviour. Fixed with a THREAD-LOCAL construction counter
(`reset_port_allocator_build_count` / `port_allocator_build_count`); process-
global counters in Rust tests produced a master-red flake once already (#6819),
and `resolve_pool_allocators` is synchronous on the caller's thread, so a
thread-local counts exactly the constructions the test under it caused.

The third is the same-tier tie-break. **The property is true** — both slices
derive from `cfg.Security.NAT.Source` and a stable sort preserves config order
within a tier — but nothing pinned it, and the round-3 fixtures put the two
competing rule-sets in DIFFERENT tiers, so they bind the tier ordering only.

**The proposed mutation needed a correctly sized fixture to be distinguishing
at all.** Measured directly: Go's `sort.Slice` runs an insertion sort below
n=12 and detects an already-ordered input above it, so with an all-equal key it
preserves order at every size tried (2, 8, 13, 16, 32, 64) — a small same-tier
fixture would leave `sort.Slice` and `sort.SliceStable` observationally
identical and no test could red. With MIXED tiers and same-tier ties it first
reorders at **n=13**. The new fixture therefore uses 20 rule-sets interleaved
across two tiers, and `sort.SliceStable -> sort.Slice` reds it with
`charge order[0] = if05, want if00`. A second test puts a budget boundary
between two same-tier rule-sets so the property decides which pool survives.

## Round 4 amendment — a mask with no witness, and an option that is not one

Two items arrived after round 4 was pushed. Both verified independently.

### B2 — the round-3 network-base mask was bound by nothing

Deleting BOTH masks from `expand_pool_address` left the whole crate green,
including the two parity tests that carry the claim. The reason is structural:
**the shared fixture asserted VERDICT and HOST COUNT, and a missing mask changes
WHICH addresses are produced, never HOW MANY.** The two rows added for exactly
this case carried the claim in a `note` string that no assertion read; every
CIDR pool-address literal elsewhere in the crate is network-aligned, a
`/32`/`/128`, or over-cap, so nothing pre-existing could see it either.

The shipped mask is correct — that was verified — so nothing is wrong in
production. It blocked because it is a coverage hole on a line THIS round
rewrote (it replaced `IpNet::network()`), and because a comment asserted the
opposite:

> "A verdict-only table would not catch a masking or off-by-one drift on either
> side (the round-3 Rust rewrite replaced IpNet::network() with its own mask)."

That sentence is measured false and is corrected in place.

Fixed by giving the fixture an address-SET dimension: optional `first` / `last`
/ `expanded` fields, asserted Rust-side (where the expansion happens), with the
Go side cross-checking that a row cannot contradict itself. Eleven rows carry
one, including all three where host bits are set — the only rows where a missing
mask changes the answer. The concrete case is encoded in full:
`203.0.113.10/28` expands to `.0`-`.15` masked, and `.10`-`.25` unmasked —
eight addresses in the NEXT `/28`, translating from IPs the operator never
configured, with the budget charging 16 either way so nothing else notices.
Two non-vacuity assertions keep the annotations from being silently dropped.

### B1 — option (c) is not available, and the reason is measurable

The proposal: stop poisoning this class on the tolerant / peer-sync builder
path, keep the narrowing at strict commit, and let a persisted config keep
working. It rests on the builder's poison being what stops the pool.

**It is not.** Since round 3 the RUNTIME refuses a leading-zero octet on its
own: `expand_pool_address` parses the CIDR address half with `std::net::IpAddr`.
A snapshot with `pool_unusable: false` — exactly what option (c) produces —
still reaches `InvalidPool`, with zero expanded addresses and no allocator.
`declining_to_poison_a_leading_zero_member_does_not_restore_it_6812` measures
it, against a canonical-spelling control that installs normally in the same
shape.

So (c) is not "stop poisoning"; it is "stop poisoning AND revert the round-3
narrowing". And that end state is the one the objection to option (a) already
rules out: `ipnet` silently resolves the octal-ambiguous literal to its decimal
reading and the pool translates from addresses that are not the ones `show
configuration` displays. (a) makes that guess by rewriting the address; (c)+
revert makes it by leaving `ipnet` to rewrite it for us. Same guess, less
visibility, and it would re-open the commit-vs-apply divergence that #5627 and
this round exist to close.

**Kept: refuse, and name the fix.** Unchanged from round 4.

### What the amendment corrects in this document and elsewhere

The pre-fix state at master was a **commit-vs-apply divergence** — strict commit
rejecting since #5627 while the runtime installed — **not** a tolerant-path
over-rejection. The over-rejection framing was true only relative to an earlier
commit of this PR, which had already added the poison. Three prose sites carried
the wrong framing; all three are corrected. The blast radius is also narrower
than round 4 implied: **exactly** the leading-zero-octet CIDR family. Every
other shape the membership clause catches was already fail-closed at the merge
base — a mixed pool with an unparseable member and an over-capacity `/15` were
both refused by the expander, and a bare `%zone` member was poisoned by the
#5875 builder check — so round 2's "only the decider moves" argument holds for
every class except this one.

### A process note worth keeping

The round-4 correction to the `expand_pool_address` doc comment **did not reach
the commit**. The mutation harness took its restore snapshot BEFORE that edit
and its final `cp` reverted it, so the round-4 report claimed a correction that
was not in the tree. Backups for a mutation matrix must be taken after the last
production edit, not before the first mutation.

### A vacuity MECHANISM is a query, not a one-off fix

Round 4 found that Go's `sort.Slice` preserves order for an **all-equal key**
(pdqsort detects an already-sorted input), so a stability mutation against a
single-keyed fixture is a no-op, and sized the new fixture at 20 rule-sets
across two tiers so the mutation would distinguish.

Its sibling `TestAggregateSameTierBudgetBoundaryFollowsConfigOrder_6812` had 17
rule-sets **all at tier 1** — the very shape that had just been diagnosed. Under
`sort.SliceStable -> sort.Slice` it **passed**, while its own doc comment and
`docs/config-schema.md` both credited it with binding the tie-break. The
mechanism had been applied to the test the finding named, and not carried one
function over.

Re-cut: four interface-scoped rule-sets are INTERLEAVED among sixteen
zone-scoped ones, so the input is neither single-keyed nor already tier-sorted;
the four tier-0 pools consume 4 addresses, so the address budget admits fifteen
`/16`s and refuses the sixteenth, and WHICH zone pool loses depends only on
config order among equals. Both same-tier tests now red under the mutation —
the boundary one with `poison set = map[q01:true], missing "q15"`. The fixture
also asserts its own preconditions (both tiers present, input NOT already
tier-sorted), so it cannot silently regress to the single-keyed shape.

**The rule this leaves behind: when you learn WHY a test failed to bind, that
reason is a greppable predicate — run it over the neighbouring cells before
closing the round.** "All-equal sort key", "asserts only a count", "fixture
input is already canonical" are all queries, not observations.

### The mask's stake, and a claim in a commit message that cannot be edited

The reviewer who found B2 established that the stake is **cross-language**, not
just "wrong addresses". `pkg/nat/deterministic.go` expands the same pool CIDR
from `net.ParseCIDR`'s `ipnet.IP` — already masked — and `lookupForwardInPool`
INDEXES that slice to answer the operator-facing deterministic-NAT query. A
drifted Rust base therefore makes the Go lookup and the actual dataplane
translation disagree by exactly the host-bits offset: the #5794 invariant-8
forensic failure, on a line this PR authored. Concretely, a pool declared
`address 10.0.0.1/24` would SNAT from `10.0.0.1` through `10.0.1.0` — one
address in the NEIGHBOURING prefix — with the whole suite green.

`TestDeterministicPoolExpansionMatchesSharedGrammarFixture_6812` binds it
against the SAME fixture, so the one-table property now spans three consumers:
the Rust expander, the Go grammar predicate, and the Go deterministic expander.
Mutating the Go base to skip the mask reds it with
`expandPoolV4("10.0.0.1/24") starts at 10.0.0.1, want 10.0.0.0`.

**A correction that cannot be applied where it was made.** The round-3 commit
message (`8f9b53b44`) claims the fixture asserts "verdict AND expanded host
count, so a masking drift is caught too". The second clause is false — a
masking drift is exactly what a count cannot catch. The commit is pushed and
shared, so the message is not editable without rewriting history; the
correction is recorded here and in `_Log.md` instead. A false claim in an
immutable artefact still has to be findable from the mutable ones.

### B3 — a production line whose only binding lived in another package

Deleting both `canonicalPoolAddressHint` branches left
`go test ./pkg/config/ -run '6812|LeadingZero'` GREEN: the production line is in
`pkg/config`, and all three tests binding it were in `pkg/dataplane/userspace`.
A full-tree run catches it; a package-scoped run — what a maintainer editing
that file actually runs — does not. `TestLeadingZeroHintIsBoundInThisPackage_6812`
closes it, and also pins the negative half (the hint must never fire for an
address that already works, nor invent a suggestion for an unrelated
malformation).

### The BUILDER half of F3 — the half with a dataplane consequence

F3's deliverable is an EQUALITY: a same-tier tie resolves in config order,
"which is what makes the walk's sequence equal the builder's emitted sequence".
Round 4 pinned the WALK
(`compiler_validate_strict_nat.go`, `sort.SliceStable(rulesets, ...)`). The
BUILDER's sort (`nat_source.go`, the #4161 tier sort) was pinned by nothing:
swapping it for `sort.Slice` left the entire Go suite green.

The unpinned half is the one that matters. The walk's order decides which pool
wins a budget slot; the builder's order is what the Rust matcher consumes, and
`match_source_nat_result_for_tuple` is FIRST-MATCH on that slice precisely
because it arrives pre-tiered — the production comment says so. Break the order
and a flow takes another rule-set's translation.

Three invariants are claimed by the comment above that sort, and they are now
asserted SEPARATELY so a failure names which one broke: rule-sets in config
order within a tier; each rule-set's rules CONTIGUOUS; rules in within-set
order.

**Contiguity is not implied by config order, and that is proved rather than
argued.** Two mutations:

| mutation | (1) order | (2) contiguity |
|---|---|---|
| `sort.SliceStable` -> `sort.Slice` | RED — `order[1] = if09, want if01` | RED — `if07 SPLIT: rules at 11..14 with [if05/r0@12 if03/r1@13] between` |
| stable sort by (tier, RULE NAME) | **green** | RED — `if00 SPLIT: rules at 0..10 with nine other rule-sets between` |

The second mutation keeps every rule-set's FIRST reference in config order
while lifting its second rule past nine others — first-references ascending,
blocks shredded. A config-order-only assertion passes it. That is why the
contiguity check exists as its own assertion rather than as a consequence of a
full-sequence comparison.

The new test is also the ONLY thing in the repo that reds on the builder
mutation — `go test ./...` under it produced exactly one failure.

Provenance: the builder sort line is pre-existing and not authored by this PR.
It is in scope because this PR's F3 claims an equality and shipped a binding
for one side of it.

## Round 6 — a guard that could not see the rule it exists to forbid

Four items, none blocking.

### F-A — the fixtures could not see a NAME tiebreak

All three same-tier fixtures declared their rule-sets in ASCENDING suffix order
(`if00..if09`, `zn00..zn09`, `q00..q15`). Within a tier that makes config order
and ascending lexicographic NAME order the SAME sequence; across tiers
`'i' < 'z'` makes name order match tier order too. So a stable sort keyed on
(tier, PoolName ASC) — the realistic edit someone makes while "making the sort
deterministic" — was GREEN on all three.

That is worse than an ordinary coverage gap: a name tiebreak is precisely the
rule F3 removed, and the walk's own comment says so ("Ordering by rule-set NAME
matched neither that order nor any Junos semantic"). The guard that exists to
stop that rule returning could not see it return.

Fixed by declaring high-to-low in all three fixtures, so config order is no
longer lexicographic, plus a precondition in the builder test that FATALS if
declaration order is ever again ascending by name.

**Round-7 correction.** That last clause was false as shipped in round 6. The
precondition asked whether the WHOLE declared rule-set-name sequence was
non-decreasing — a question this fixture shape can never answer yes to. It
interleaves two tiers (`if00 zn00 if01 zn01 …`) and `"zn00" > "if01"`, so the
global sequence is non-monotonic in BOTH directions; `nameAscending` was always
false and the `t.Fatal` was unreachable. Measured on a scratch copy at
`ba44bb85d`: re-cutting the three loops ascending left the check silent with
pristine production AND with the `(tier, PoolName ASC)` builder mutation
applied — the exact edit it existed to catch.

The blindness that matters is ascending WITHIN a tier, because that is what a
`(tier, name)` stable sort keys on. Round 7 replaces the check with a per-tier
predicate — `assertNoTierDeclaredNameAscending6812`, one copy per package —
that fails if ANY tier holding two or more rule-sets is declared in ascending
name order, and fails if NO tier holds two (a fixture with no within-tier tie
cannot bind the rule at all). It is now present in all three fixtures, not one:
the descending re-cut is a shape assumption all three share, and a future
re-cut is a per-file edit, so the tripwire belongs wherever the assumption
lives. `TestAggregateFirstFitSameTierFollowsConfigOrder_6812` also gains the
tier-sortedness precondition its two siblings already had.

Measured after (round 7):

| step | old predicate | new predicate |
|---|---|---|
| ascending re-cut, production pristine | green (silent) | RED — `tier 0 is declared in ascending NAME order [if00 … if09]` |
| ascending re-cut + `(tier, PoolName ASC)` | green (silent) | RED — same precondition line, before the assertion |
| head fixture + `(tier, PoolName ASC)` | RED on the assertion | RED on the assertion (precondition does not shadow it) |
| head fixture + walk `(tier, Name ASC)` | RED on the assertions | RED on the assertions (`charge order[0] = if00, want if09`; `poison set = map[q15:true], missing "q00"`) |
| one rule-set per tier, tiers declared high-first | n/a | RED — `no tier holds two or more rule-sets` |

The last row exists because the "no within-tier tie" belt would otherwise be
unfalsifiable: the callers' tier-sortedness precondition shadows it for every
multi-element shape, so it was driven directly to prove it is reachable.

Round-6 measurement, retained:

| mutation | before | after |
|---|---|---|
| walk (tier, Name ASC) | green | RED — `charge order[0] = if00, want if09`; `poison set = map[q15:true], missing "q00"` |
| builder (tier, Name ASC) | green | RED — `emitted rule-set order[0] = if00, want if09` |

The ORDER axis regressions still hold after the re-cut: `sort.Slice` reds both
walk tests and the builder test, and the (tier, RULE NAME) mutation still reds
contiguity ALONE (0 order lines, 20 SPLIT lines).

Explicitly NOT conflated: a PoolName-only sort that ignores tier reds four
pre-existing #4161 tests plus the snapshot poison test, so the tier axis was
already covered. These fixtures bind the TIE-BREAK axis, which was not.

### F-B — a summary comment describing pre-round-4 behaviour

`sourceNATAggregateReferencedCharges`'s summary still said charges come back
"(rule-sets sorted by name, ...)" — false since round 4, and contradicted 55
lines below inside the same comment block. Corrected to name the actual rule
(stable sort by #4161 tier, config order preserved within a tier).

### F-C — VERIFIED, and fixed rather than documented

Relayed unconfirmed, so measured first. Driving `expandPoolV4` over all 58
fixture rows: **2 genuine v4 divergences**, both in the reject half —
`198.51.100.1/032` accepted as 1 address, `10.0.0.0/016` accepted as 65,536.
Cause confirmed directly: `net.ParseCIDR` reads a leading-zero prefix length,
`netip.ParsePrefix` refuses it.

(My first probe reported 14 disagreements. Twelve were artifacts of its own
crude `accepted := err == nil && len > 0` test: `expandPoolV4` is the v4 mode-1
path and deliberately SKIPS a colon-bearing member rather than rejecting it, so
a v6 row yielding zero v4 addresses is correct-by-design. The reject-half walk
classifies with `config.NATAddrFamily`, the same predicate production uses.)

**Fixed, not narrowed.** The claim "all three consumers are pinned to one
table" was true of the accept half only; the honest options were to narrow the
sentence or to walk the reject half. Walking it exposes a real defect, so the
sentence was not the thing that was wrong. A tolerant load with `10.0.0.0/016`
gets a pool that translates nothing while `show`/gRPC/REST answer with a
confident 65,536-address mapping — the invariant-8 forensic failure, one
consumer over from the divergence class this whole PR exists to close.
Narrowing the claim would have been the "document the divergence" option
already rejected for F1.

The fix is a `netip.ParsePrefix` check in `expandPoolV4`. Narrowing only: such
a pool translates NOTHING either way — the snapshot builder stamps it
`invalid_pool` and it installs no allocator — so no working config changes
behaviour; the lookup reports an error instead of a fiction. `net.ParseCIDR` is
pre-existing and untouched by the diff, so this is not a regression this PR
introduced; it is a divergence the shared fixture made visible.

**Round-7 correction to this paragraph.** It also claimed such a pool is
"already refused at commit". That conjunct is over-broad and is withdrawn:
`validateSourceNATPoolAddressGrammarStrict` iterates pools reachable from a
pool-mode rule's `Then.PoolName`, not the pool table, so an UNREFERENCED pool
carrying `10.0.0.0/016` compiles STRICT-CLEAN. Measured both directions — the
referenced spelling is refused (`source-nat pool "refd" ... address
"10.1.0.0/016" is not a valid CIDR`), the unreferenced one compiles with
`err = <nil>` and `SourceNATPoolUnusableReason == "invalid_pool"`. The
conclusion is unchanged, because it rests on the pool being unusable, not on
the commit gate.

### F-D — assertion (3) was not independent of (2)

Within-set rule order reads `out[lo+r]`, which only identifies that rule-set's
rules when its block is contiguous. Now gated on (2). Under `sort.Slice` the
within-set line count drops 16 -> 10; the remaining 10 are CONTIGUOUS rule-sets
whose two rules are genuinely out of order, which is a true (3) violation, so
the gate removed the artifacts and kept the findings.

## Round 8 — the same blindness one nesting level in, and an assertion that admitted empty success

Three live findings from a Codex leg that ran at the pre-round-7 head; all three
re-verified at `52f7e735a` before anything was changed. A fourth (the anti-vacuity
guard checks global rather than per-tier name order) was already closed by round 7
and is recorded here as a non-defect: the guard at head IS per-tier
(`assertNoTierDeclaredNameAscending6812`), two reviewers reached that shape
independently.

### B1 — round 7 de-correlated the rule-SET names and left the RULES correlated

Round 7's fix was right and incomplete. `TestBuilderEmittedOrderIsStableWithinATier_6812`
declares rule-sets high-to-low so a `(tier, name ASC)` tiebreak is visible — and
then declares each rule-set's two rules `r0` then `r1`, which is config order AND
ascending name order at once. Assertion (3) ("rules keep their within-rule-set
config order") therefore could not see a within-set sort.

Measured at `52f7e735a`, not argued: inserting

```go
mutRules := append([]*config.NATRule(nil), rs.Rules...)
sort.SliceStable(mutRules, func(i, j int) bool { return mutRules[i].Name < mutRules[j].Name })
```

ahead of the emit loop in `buildSourceNATSnapshotsWithFeeds` left the whole test
**GREEN**. This is the identical property the PR exists to protect — config order
and lexicographic name order being the same sequence — one level in from where
round 7 corrected it.

Fixed three ways:

1. The rule loop declares `r1` before `r0` (and the per-rule match address rides
   on the same index, so a sort keyed on `MatchSourceAddresses` is de-correlated
   too). Under the mutation the test now reds on the assertion:
   `rule-set if05 rule[0] = r0, want r1 ... Declared: [r1 r0]; emitted block: [r0 r1]`.
2. Assertion (3) no longer re-derives `r%d`. It reads the DECLARED rule sequence
   out of the compiled config and requires the emitted block to reproduce it, so
   a future re-cut of the fixture loop cannot leave the expectation pointing the
   other way.
3. `assertNoRuleSetDeclaredRuleNameAscending6812` — the round-7 tripwire one level
   in. It fails if any rule-set with two or more rules is declared name-ascending,
   and fails if no rule-set discriminates at all. Proven reachable the way round 7
   proved its own: re-cutting the loop ascending reds against PRISTINE production
   with `rule-set for pool if00 declares its rules in ascending NAME order [r0 r1]`.

### The third level — enumerated, not assumed

Every generated name in the ordering fixtures, and whether a production sort
could key on it:

| generated | fixture direction | reachable as a sort key? | status |
|---|---|---|---|
| rule-set name (`if%02d`/`zn%02d`) | descending | yes — the outer `sort.SliceStable` comparator | de-correlated (round 7) |
| pool name (same strings) | descending | yes — `SourceNATRuleSnapshot.PoolName` | de-correlated (round 7); this is what the tripwire keys on |
| **rule name (`r%d`)** | **was ascending** | **yes — `SourceNATRuleSnapshot.Name`** | **B1, fixed here** |
| rule match address (`10.0.%d.0/24`) | rode on the rule index | yes — `MatchSourceAddresses` | de-correlated as a side effect of B1 |
| from-interface (`ge-0/0/%d.0`) | descending | yes — a scope field on the snapshot | already de-correlated |
| from-zone (`trust%d`) | descending | yes — a scope field on the snapshot | already de-correlated |
| pool address (`10.%d.0.1`, 100+i / 200+i) | descending (all three digits, so lexicographic == numeric) | yes — `PoolAddresses[0]` | already de-correlated |
| counter ID | n/a — `natCounterIDs` is nil in this fixture | no: constant 0, not discriminating | n/a |

There is no fourth level: below the rule there is no per-rule collection this
builder emits in a caller-visible order.

The first-fit fixtures (`p0/p1/p2`, `bad0..badN` + `good`) DO declare pools in
ascending name order, and that is deliberate rather than an oversight: none of
them asserts an order. `TestAggregateOverBudgetPoolsFirstFit_6812` refuses `p1`
because `p1` alone exceeds the address budget, which is order-independent; the
`bad*`/`good` fixtures need only that `good` is charged last, which a name sort
preserves (`"bad9" < "good"`). Recorded so a later reader does not "fix" them
into fixtures that prove less.

### B1b — the walk side had no rule-level assertion either

`sourceNATAggregateReferencedCharges` documents three ordering clauses; rounds 4
and 7 bound the rule-set one, and nothing asserted "rules in config order". Every
walk-side ordering fixture declares exactly ONE rule per rule-set, so there is no
within-set order to permute at all.

`TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812` asserts it directly:
one rule-set (single tier, so the tier sort is a no-op and only the rule walk can
reorder anything), four rules declared `r03 r02 r01 r00` referencing pools
`qb qd qa qc`, with the three candidate sequences kept pairwise distinct and that
distinctness asserted so the fixture cannot decay:

```
declaration order:  qb qd qa qc   <- the walk must reproduce this
rule-name ASC:      qc qa qd qb
pool-name ASC:      qa qb qc qd
```

Under the same sort inserted into the charge walk it reds with
`charge order = [qc qa qd qb], want [qb qd qa qc]`.

One honest qualifier, because what detected it was an accident. The same mutation
also reds `TestAggregateOverBudgetPoolsAddresses_6812` and
`TestAggregateOverBudgetPoolsCount_6812` (`poison set = map[p999:true], missing
"p1024"`). Those are count/address BUDGET fixtures; they move only because their
1,025 rules are named `r0..r1024` and `"r1000" < "r999"` lexicographically. Zero-pad
those names — a plausible readability edit — and both go blind while the clause
stays unbound.

### B2 — the reject assertion did not bind all-or-nothing

`TestDeterministicPoolExpansionMatchesSharedGrammarFixture_6812`'s reject half
fired only for `lerr == nil && len(got) > 0`. Empty success was admissible — and
empty success is exactly what a per-member SKIP produces, because every fixture row
is a SINGLE-member pool. Measured at `52f7e735a`: changing the `netip.ParsePrefix`
branch in `expandPoolV4` from `return nil, lerrf(...)` to `continue` left the test
GREEN.

Two changes:

- The per-row assertion now requires a NON-NIL error. Under the `continue`
  mutation it reds on twelve rows, e.g. `expandPoolV4("10.0.0.0/016") returned NO
  ERROR (0 addresses)`.
- A MIXED-member half, in BOTH orders. `[refused, 198.51.100.7/32]` and
  `[198.51.100.7/32, refused]` must each fail with zero addresses. This is the
  shape with the operator-visible consequence: the Rust parse loop ORs
  `expand_pool_address` over every member and fails the WHOLE pool
  `SourceNatFailureReason::InvalidPool`, so a per-member skip reports a working
  1-address mapping for a pool that translates nothing. Under the mutation:
  `expandPoolV4(pool [198.51.100.1/032 198.51.100.7/32]) returned NO ERROR and 1
  addresses [198.51.100.7]`. A control asserts the good member expands cleanly on
  its own, so the mixed rows cannot pass for the wrong reason.

Note the order asymmetry the round-7 assertion depended on: with the refused member
FIRST a skip yields empty success (invisible), with it SECOND it yields non-empty
partial success (visible). Only the second shape was ever in reach.

### B3 — "same order" is true only of a FIRST apply

`SourceNATAggregateOverBudgetPools`' doc comment said the Go first-fit rule
"mirrors it exactly — same order, same charge". The order half is false whenever
`previous_allocators` is non-empty. `resolve_pool_allocators` is TWO passes
(source.rs, "Reused keys are RESERVED before any new key is admitted", #6812 F2
round 4): phase 1 charges every distinct REUSED key, phase 2 then admits NEW keys
against that total. The Go walk is a single first-fit pass in emitted order
throughout. With an empty previous map the sequences coincide; on a re-apply they
do not.

The 60,000-config differential could not see this because it models the Rust gate
in Go — it reproduces the admission arithmetic, not the two-pass structure.

The Go/Rust AGREEMENT claim is unaffected and is left standing. The two are not
independent deciders: the poison this walk computes travels on the wire, and the
Rust parse loop builds no `PendingPoolAllocator` for a rule whose pool already
failed, so a poisoned pool reaches neither Rust phase and Rust re-derives
admission over the reduced set. The reserve-first order exists for the snapshots
no Go poison is coming for — a tolerated, older control plane's, or handcrafted
snapshot — which is precisely what makes that boundary an INDEPENDENT backstop
rather than a second opinion.

Corrected at both live sites (the `SourceNATAggregateOverBudgetPools` doc comment
and `TestSnapshotPoisonFollowsEmittedScopeOrder_6812`'s "walks the emitted rule
slice in order"). The round-3 narrative above quotes the sentence as it stood then
and is accurate as history; this section is its correction.

### Deferred, with the site list — capacity surfaces still count a refused member

Codex's remaining finding is real, verified at head, and DELIBERATELY NOT FIXED
HERE. `expandPoolV4` now refuses a pool with a non-canonical member, but four
other operator-facing surfaces still derive capacity from `len(pool.Addresses)`,
which counts members the grammar refuses. Because the pool predicate is
all-or-nothing, such a pool installs NO allocator and its true capacity is zero.

Measured at `52f7e735a` for a pool `{Addresses: ["10.0.0.0/016"], Deterministic:
{BlockSize: 512}}`, whose `SourceNATPoolUnusableReason` is `"invalid_pool"`:

| site | reports |
|---|---|
| `pkg/cli/cli_show_nat.go:206` and `:349` | 64,512 total ports |
| `pkg/api/metrics_nat.go:31` | 64,512 (`natPoolTotalPorts` gauge) |
| `pkg/api/metrics_nat.go:109` (`deterministicPoolBlockCapacity`) | 126 blocks |
| `pkg/grpcapi/server_nat.go:132` | 64,512 |
| `pkg/api/nat.go:271` | address count 1, and `:277` PRESERVES it when the runtime reports `AddressCount == 0` — so "the helper has zero addresses" never reaches the operator |

That is SIX call sites in four files, not four; the line numbers in the review ran
one commit back. Adjacent but differently derived: `deterministicSubscriberCapacity`
publishes `host_count = 256` on `natPoolDeterministicInfo` for the same pool, from
the subscriber CIDR rather than from the pool members.

Why it is not in this PR: it lives entirely in `pkg/cli`, `pkg/api` and
`pkg/grpcapi`, none of which this 21-file diff touches; it changes what four
operator surfaces REPORT (including a Prometheus gauge, which is a
monitoring-visible contract) and each owes its own test; and there is a design
question underneath that a separate change should settle rather than half-answer.
All six sites use the MEMBER count, so a healthy `203.0.113.0/24` pool already
reports 1 where the dataplane installs 256. A one-place derivation — capacity
from the same grammar the dataplane accepts — should settle zero-on-unusable AND
member-vs-expanded together. Fixing only the first half here would leave the same
shape half-closed.

Recommended shape for the follow-up: one exported helper in `pkg/config` beside
`SourceNATPoolUnusableReason` returning the reportable address cardinality (0 when
the pool is unusable, the expanded honorable count otherwise), with all six sites
consulting it. What that makes unrepresentable: a surface that reports capacity
for a pool the dataplane refused, because there is no longer a per-consumer
expression to get wrong — the same "consult the verdict, do not re-derive it"
rule round 2 applied to the budget walk, one layer out.

## Round 9 — the anti-coincidence property, asked mechanically

Codex returned MERGE-NEEDS-MINOR with zero runtime defects at `1995806ee`. Two
minors and a set of stale claims. Everything below was re-measured at that head
before being changed; the mutation harness now classifies a build/infra failure
as **VOID** rather than as a red, after `/dev/shm` filled mid-round.

### M1 — round 8 permuted the columns it was thinking about

Round 8's walk-side fixture permuted the rule and pool NAMES and then generated
the match address and the pool member address from the loop index `i`. Both
ascended with declaration order. Its comment claimed the fixture was "neither
ascending nor descending in either coordinate", which was also false of the rule
column: `r03 r02 r01 r00` is exactly descending.

Measured at `1995806ee`, sorting each rule-set's rules in the charge walk:

| axis | ASC | DESC |
|---|---|---|
| `Rule.Name` | RED | **GREEN — blind** |
| `Match.SourceAddress` | **GREEN — blind** | RED |
| `Then.PoolName` | RED | RED |

The `Match.SourceAddress ASC` cell is worse than the round-8 finding it mirrors:
the rule-name sort at least reds two neighbouring budget fixtures by accident,
whereas the match-address sort left the **entire `pkg/config` suite** green.

Every column is now an independent permutation — neither the identity nor its
reverse, and pairwise distinct so each axis fails for its own reason. All six
cells are RED.

### The generalisation: sweep VALUES, and sweep DIRECTIONS

Round 8 enumerated generated NAMES against "could a production sort key on it".
That enumeration was sound for what it covered and missed an axis that is not a
name. Two dimensions were being confused with one: *which key* a sort reads, and
*which direction* it sorts in. Both were swept by measurement this round, at
both mutation sites of the builder fixture (a within-rule-set rule sort, and a
tiebreak appended to the tier comparator):

| axis | site | ASC | DESC (before) |
|---|---|---|---|
| `Rule.Name` | within-set | RED | **GREEN** |
| `Match.SourceAddress` | within-set | RED | **GREEN** |
| `PoolName` | tiebreak | RED | **GREEN** |
| `Name` | tiebreak | RED | RED |
| `PoolAddresses[0]` | tiebreak | RED | **GREEN** |
| `FromInterface` | tiebreak | RED | **GREEN** |
| `FromZone` | tiebreak | RED | **GREEN** |

Five blind cells, and the cause is structural rather than incidental: rounds 7
and 8 each fixed an ascending coincidence by re-cutting the fixture DESCENDING,
which trades one monotone direction for the other. `Name`-at-tiebreak is the
lone exception because a rule-name tiebreak at the rule-SET level splits every
rule-set's block, which contiguity assertion (2) catches in either direction.

Fixed by emitting a PERMUTATION rather than a direction, at both levels
(`declOrder`, and `ruleOrder` with **three** rules per rule-set — two cannot be
de-correlated from both directions, since any two-element sequence is ascending
or descending by construction). All fourteen cells are now RED. The `wantRefs`
expectation is derived from the declared sequence stable-sorted by tier rather
than transcribed, so a future re-cut cannot leave it behind.

### Is the set closed?

> **SUPERSEDED BY ROUND 10.** Two of the three claims below are wrong and one is
> wider than what is measured. They are left in place because the record of what
> was claimed matters; each carries its correction, and the round-10 section at
> the end of this document has the full replacement.

**Axes: yes, and by construction rather than by exhaustion.** The belt does not
enumerate — `assertDeclarationOrderIsNotSortedBy6812` is called on every column
the fixture emits, and asks the question mechanically. A new column added later
that nobody remembers to permute fails the belt rather than silently widening
the blind set. That is the difference between this and the round-8 answer, which
was a list.

> **Wrong.** Both fixtures MANUALLY ENUMERATE the helper calls
> (`nat_source_aggregate_6812_test.go:812`,
> `compiler_nat_source_pool_aggregate_6812_test.go:893`). Round 9 moved the list
> up one level — from axis names to helper calls — and a column with no call was
> still silent. Round 9's own sentence, "round 8's answer was a list, and a list
> is exactly what failed", applied to round 9 too.

**Directions: yes, both, now checked explicitly.**

**One case is deliberately exempt, and it is not a hole.** A column that is
CONSTANT is a non-axis: a stable sort keyed on a value identical for every
element cannot permute anything, so there is nothing to be blind to. This is not
hypothetical — zone-tier rule-sets carry no `from interface` and interface-tier
ones carry no `from zone`, so each of those axes is empty for half the fixture.
Requiring them to be permuted would demand that a fixture discriminate a
mutation that cannot exist.

> **Right in principle, wrong in application.** The argument is sound only when
> the key is invariant for all relevant PRODUCTION inputs. These columns are not
> — they are constant in the fixture only, which is a blind spot rather than a
> non-axis. Fixture-only constancy is not regression coverage.

**What is still out of scope, stated rather than left implicit:** a
non-order-preserving mutation that is not a sort at all (a reversal, a rotation,
a shuffle). Assertion (1) compares the emitted sequence against the declared one
elementwise, so it catches any of those on the rule-set axis, and assertion (3)
does the same within a rule-set — but that is coverage by the assertions, not by
this precondition, which only ever claimed to keep sorts visible.

> **Wider than what is measured.** Reversal and nonzero rotation are caught,
> because the elementwise comparison sees distinct identities in changed
> positions. A PARTITION is caught only when it actually changes this fixture,
> and the `[1,0,2]` rule order is already stably partitioned by match address
> `< 10.0.2.0/24` — so that partition is invisible. The accurate claim is
> narrower: the elementwise comparisons catch transformations that realise a
> NONIDENTITY PERMUTATION ON THIS DATA. "Any of those" is not true of the
> partition family in general.

### M2 — "only on a first apply" replaced one categorical claim with another

Round 8 corrected "same order" to "identical on a first apply, NOT identical on
a re-apply". The second half is too strong. Empty `previous_allocators`
**guarantees** the sequences coincide; a re-apply **may** differ and need not —
an all-reused apply coincides trivially, and so does any apply whose reused keys
already precede its new ones in emitted order. Phase 1 also reserves only the
keys that are BOTH viable in this apply AND present in `previous_allocators`; a
previously-allocated but currently-poisoned key gets no pending and is not
reserved.

The comment now carries the admission proof rather than the assertion that the
two sides "are not independent deciders". Let `A` be the set this walk admits.
First-fit admits greedily only while the running total fits, so `charge(A)` is
within every budget. The poison travels on the wire and Rust builds no pending
for a failed pool, so Rust's pendings are exactly `A`. Phase 1 reserves `R ⊆ A`;
phase 2 accepts reused keys unconditionally and admits a new key `k` when
`used + charge(k)` fits — and `R`, the new keys already processed, and `k` are
DISJOINT subsets of `A`, so that sum is bounded by `charge(A)`, which fits. Rust
refuses nothing this walk admitted, in any emitted order. The live set is
exactly `A`.

Three further sites carried the uncorrected unconditional claim and now carry
the qualified one: `sourceNATAggregateReferencedCharges`' head comment,
`SourceNATScopeTier` (`nat_source_scope.go`), and the builder's poison comment
(`pkg/dataplane/userspace/nat_source.go`), which also said Rust "independently
refuses the same set" — it re-derives admission over what survives, and by the
proof above refuses none of it.

### M3 — the two-order rationale did not hold for its own mutation

The mixed-member comment justified driving both member orders by an asymmetry —
refused-first yields empty success, refused-second yields non-empty partial. That
is true of a SINGLE-member pool and false of these: under the `continue` mutation
the loop skips the bad member and appends the good one in either order, so both
return `[198.51.100.7]`. The mutation is caught either way and the stated reason
is not the reason.

Withdrawn and replaced with the two that hold:

1. All-or-nothing is a property of the member SET, not of a position. The Rust
   contract ORs `expand_pool_address` over every member, so a validation reading
   only `addrs[0]`, or short-circuiting once one member expands, is
   position-dependent in a way the contract forbids — and a fixture that only
   ever puts the refused member in one slot cannot see it.
2. The two positions differ in the internal state at the point of refusal. With
   the good member first, `out` is already non-empty when the failure fires,
   which is the only arrangement making the "reported an error AND returned
   addresses" assertion non-vacuous. Measured rather than asserted: substituting
   `return out, err` for `return nil, err` reds 12 rows, and every one is a
   `[good, refused]` pool — zero `[refused, good]` rows fire, because their
   `out` is still empty at the point of failure.

### Confirmed by Codex, recorded so no later round re-opens them

- The per-rule-set tripwire is reachable AND correctly layered: an ascending
  fixture reaches and fails it; with the descending fixture plus a
  `Rule.Name`-ascending production mutation the tripwire passes, contiguity
  stays valid, and assertion (3) fails against the declared sequence — the
  intended reason, not the precondition shadowing it. The round-8 layering
  argument is confirmed.
- The rejected-member assertions are sound: replacing the canonical-prefix error
  with `continue` fails the singleton and both mixed-member orders.
- The Go/Rust agreement reasoning holds on re-apply, by the `charge(A)` bound
  now written into the comment.
- No executable production line changed in round 8 — only the comment at
  `compiler_validate_strict_nat.go:3268`. That independently confirms the
  `.text`/`.rodata` measurement showing the cluster smoke carries from
  `52f7e735a` to `1995806ee`.

## Round 10 — the closure claim was still a list, one level up

Codex: MERGE-NEEDS-MINOR, no runtime-behaviour defect. Four items, all in test
plumbing and prose. Round 9's own diagnosis of round 8 — "the answer was a list,
and a list is exactly what failed" — turned out to describe round 9.

### M1 — "closed by construction" was false, and the constant exemption was applied where it does not hold

Round 9 claimed the axis set was closed by construction because
`assertDeclarationOrderIsNotSortedBy6812` ran on every column in both
directions. Both fixtures still MANUALLY ENUMERATED the calls
(`nat_source_aggregate_6812_test.go:812`,
`compiler_nat_source_pool_aggregate_6812_test.go:893`). Adding a column without
adding a call stayed silent; the list had moved from axis names to helper calls,
not gone away.

Three concrete columns it left open, all named by Codex and all confirmed here:

- **`CounterID`.** The builder fixture called `buildSourceNATSnapshots(cfg, nil)`
  so every emitted ID was zero, while production supplies populated FNV-derived
  IDs. A stable `(tier, CounterID)` tiebreak reorders production.
- **Pool cardinality.** Every pool carried exactly one member, so a sort by
  `len(PoolAddresses)` — or by any charge derived from it — was a no-op.
- **Port capacity.** Every pool sat at the default 1024-65535 range, so the
  range, its width, and members × width were all constant.

And the exemption. Round 9 skipped a CONSTANT column silently, arguing a stable
sort keyed on a value identical for every element cannot permute anything. That
argument is sound only when the key is invariant for all relevant PRODUCTION
inputs. These columns are constant in the FIXTURE and settable in production —
a blind spot, not a non-axis. Fixture-only constancy is not regression coverage.

**What replaced it.** `sweepAxes6812` (new, one twin per package:
`pkg/dataplane/userspace/nat_source_axis_sweep_6812_test.go`,
`pkg/config/nat_source_axis_sweep_6812_test.go`) REFLECTS over the value the
production comparator reads:

- one column per struct field, recursing into nested structs and pointers;
- one `.len` column per slice or map, plus the first element's columns when the
  slice is non-empty;
- a field whose kind has no ORDER-PRESERVING key encoding is a hard FAILURE, not
  a skip — otherwise a new field type would silently drop a column, which is the
  exact failure being closed.

So a field added to `SourceNATRuleSnapshot`, `NATRule`, `NATMatch`, `NATThen` or
`NATPool` later joins the sweep with no edit to any fixture. That is closure at
FIELD granularity, by construction.

A constant column is no longer skipped. It must be REGISTERED, and the
registration records which of the two kinds it is — `fixtureConstantAxes6812`
(an admitted blind spot) or `productionConstantAxes6812` (invariant for every
production input, so exempting it costs nothing). An unregistered constant fails
with the full list of offenders; a registered column that is constant in no
swept group fails as stale. The registries are therefore the honest enumeration,
and they are checked rather than asserted.

**Where closure stops, stated plainly rather than left for round 11.** Keys
DERIVED from fields by arithmetic are not enumerable by reflection: a comparator
may key on `PortHigh-PortLow+1`, on a computed budget charge, or on a prefix
length, and no walk can enumerate the functions someone might write. Field-level
closure does not imply derived-key coverage — every pool member address can
differ while every pool has exactly one member. Two mitigations, both explicit:
`.len` is swept mechanically, which covers the cardinality shape; and the
remaining derived keys are declared as FIELDS OF A WRAPPER STRUCT
(`snapshotAxisSlot6812`, `ruleAxisSlot6812`) that the sweep then treats like any
other column. That wrapper's field list is a list. It is the only one left, it
is in one place, and it is visible.

### M2 — the transformation-coverage claim was wider than what is measured

Round 9 wrote that assertion (1) "catches any of those" — reversal, rotation,
shuffle — because it compares elementwise. Reversal and nonzero rotation are
caught: the comparison sees distinct identities in changed positions. A
PARTITION is caught only when it actually changes this fixture, and the
`[1,0,2]` rule order is already stably partitioned by match address
`< 10.0.2.0/24` (10.0.1.0/24 and 10.0.0.0/24 keep their order ahead of
10.0.2.0/24), so that partition is invisible. Corrected in place: the
elementwise comparisons catch transformations that realise a NONIDENTITY
PERMUTATION ON THIS DATA — not the partition family in general.

### M3 — the re-apply proof sentence is false with a shared pool

`compiler_validate_strict_nat.go` said "Rust's pendings are exactly A". Pendings
are per-RULE, so a pool referenced by several rule-sets contributes several —
a multiset with repeats, not the set A. The runtime argument is unaffected, and
Codex verified why: multiple references to one key are charged once by
`reserved`, assigned once through `pool_allocators`, and refused consistently
through `refused_keys`, so the disjointness argument holds at DISTINCT-KEY
granularity. The sentence now says exactly that, and adds the reason distinct
pool NAMES give distinct keys — the key carries the pool name alongside the
expanded members and the port range, and the builder derives all three from the
pool, so every rule referencing one pool ships the same three.

### M4 — a fail-on-revert rationale that no longer names its own line

`userspace-dp/src/nat/tests_aggregate_budget.rs` justified
`repeated_references_to_a_reused_key_are_charged_once` by deleting the reuse-path
`pool_allocators.insert`. Phase-one reservation (the F2 fix) moved the charge:
`reserved` charges each distinct reused key once BEFORE phase 2, and phase 2's
reuse branch charges nothing, so that deletion no longer double-charges.

Measured rather than reasoned, cargo release, `--test-threads=1`:

| cell | mutation | result |
|---|---|---|
| control | none | GREEN |
| MUT-A | delete the reuse-path `pool_allocators.insert` (the rationale on record) | **GREEN** |
| MUT-B | drop phase 1's distinct-key dedup, charging every REFERENCE | **RED** |
| MUT-C | delete phase 1's charge entirely | GREEN |

MUT-A confirms the finding. MUT-B is the replacement rationale — it is the line
that binds "charged ONCE" now, and it reds with `pool "B" refused at apply:
aggregate allocator budget exceeded (count 2/2, ...)`. MUT-C is recorded as an
explicit NON-counterexample: it under-charges rather than over-charges, so B
still fits; the F2 order defect it reopens is bound by the reuse-ordering
fixtures, not by this one.

### The measurement: base vs head

Two questions, and they need different denominators. (A) Did round 9 actually
have the blind spots M1 names? (B) Can the replacement fail?

**A — production tiebreaks, applied identically to the PR base (`a1db9f734`,
round 9's fixtures) and to this head.** Package scope at both, `-count=1`, so a
GREEN at base means the WHOLE package missed it, not just the fixture.

| cell | mutation in the production comparator | base | head |
|---|---|---|---|
| A1 | `(tier, CounterID ASC)` | **GREEN** | RED |
| A2 | `(tier, len(PoolAddresses) ASC)` | **GREEN** | RED |
| A3 | `(tier, PortLow ASC)` | **GREEN** | RED |
| A4 | walk: stable-sort `rs.Rules` by pool cardinality | RED* | RED |

Every head RED is `TestBuilderEmittedOrderIsStableWithinATier_6812` (A1-A3) or
`TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812` (A4).

\* A4 needs the honest footnote. At package scope the base is RED — but through
`TestMultipleSNATRules`, an unrelated fixture whose data happens to move under a
cardinality sort. Narrowed to the #6812 order fixture, the base is **GREEN**
(cell A4b) while `TestMultipleSNATRules` alone is RED (A4c). So the property was
caught sideways by accident and not by the fixture that asserts it — the same
shape the round-8 comment describes for the two budget fixtures, and the reason
"the package is red" is not the same claim as "the fixture binds it".

**B — the sweep must be able to fail.** Head only; a belt that cannot fail
proves nothing. Every cell reds through the axis sweep itself, not through a
downstream assertion.

| cell | mutation | result |
|---|---|---|
| B1 | add a field to `SourceNATRuleSnapshot` (production struct) | RED — unregistered constant column |
| B2 | pool cardinality back to a constant 1 | RED |
| B3 | `buildSourceNATSnapshots(cfg, nil)` — the round-9 call | RED |
| B4 | delete one registry entry | RED |
| B5 | register a column that VARIES | RED — stale entry |
| B6 | port range back to the 1024-65535 default | RED |
| C1 | walk side: register a column the fixture now guards | RED — stale entry |
| C2 | walk side: add a field to `NATPool` | RED — unregistered constant column |

B1 and C2 are the closure claim itself: a field added to a production struct
that nobody remembers to think about fails the fixture rather than silently
widening the blind set. That is what round 9 claimed and did not have.

### What the fixtures now guard, counted rather than asserted

`go test -v` prints the split. Builder fixture, per-TIER grouping: 11 columns
guarded, 23 fixture-constant (unguarded, each registered with why), 0
production-constant. Per-RULE-SET grouping: 3 guarded, 25 fixture-constant, 6
production-constant — the six scope fields, which
`buildSourceNATSnapshotsWithFeeds` stamps from `rs` for every rule of a rule-set,
so within one block they cannot vary for any config. Walk-side fixture: 11
guarded, 26 fixture-constant, 3 production-constant (`Rule.nil`, `Pool.nil` —
the walk skips both before charging — and `Rule.Then.Type`, which
`compileNATSource` only ever writes as `NATSource`, itself the zero value).

Round 9 guarded 6 cells across the two fixtures by hand. This is 25, with 74
named holes rather than an unbounded unnamed set.

## Round 11 — "swept or stops the test" had a third outcome

Codex at `cade69ad9`: no production regression, and the round's headline
property false. A switch-for-switch probe of the collector found **SILENTLY
SKIPPED** sitting between the two outcomes round 10 claimed, and it landed on
precisely the case round 10 said it had closed.

| field form | round-10 outcome |
|---|---|
| **nil pointer, every fixture** | `.nil` swept, **every pointee field skipped** |
| `[]byte` | `.len` and `[0]`; everything past the first element skipped |
| map with a struct key | `.len` only — key, value, nil-vs-empty all skipped |
| nil interface | `.nil` only; the payload schema is hidden |
| `time.Time` | swept as `wall`/`ext`/`loc.nil` — not chronological |

The first row is the one that matters. `PersistentNATConfig` and
`DeterministicNATConfig` are nil in every fixture pool, so adding a field to
either changed **no emitted column** — while round 10's own text said a new
field "cannot be silently omitted". And the map counterexample is concrete:
three one-entry maps keyed `{N:2}`, `{N:0}`, `{N:1}` all emitted `M.len=1`
alone, so a comparator keying on the sole key reorders them with the sweep
green.

**A partial column is worse than no column, because it reads as coverage.**

### The fix is the disappearance of the third outcome, not another `case`

Every kind the collector meets now does exactly one of five things:

1. contribute an **order-preserving** column for its own value;
2. contribute a **TOTAL** column over its contents — `.all` for a sequence,
   `.entries` for a map (sorted, so it is a function of contents and not of
   iteration order). No change to those contents can be invisible to it;
3. enumerate the contained **TYPE's schema with ABSENT keys** when the value is
   missing — a nil pointer's pointee, an empty list's element, an empty map's
   key and value. The columns still exist, so a field added to the contained
   type still produces one and still has to be registered;
4. **declare itself UNENCODABLE** (`…-UNENCODED`), which the registry then
   forces someone to justify in writing. A nil interface takes this path: its
   dynamic type genuinely is not knowable from the static one;
5. **stop the test** — the `default` arm. Floats have no order-preserving
   fixed-width decimal here; chan/func/unsafe.Pointer have no order at all.

Keys are TAGGED: present values encode as `"\x01"+key`, absent ones as `"\x00"`.
Absent sorts below every present key, a uniform present-prefix preserves order
among present keys, and "absent" can never collide with a legitimately empty
string.

`nat_source_axis_collector_6812_test.go` asserts the four repaired forms
directly, against synthetic types, because the property belongs to the collector
rather than to any NAT fixture. Outcome 5 needs no case: a kind the switch does
not handle reaches a `default` that fails, which is a property of the language.

### Measured

Controls green. Every cell RED.

| cell | mutation | result |
|---|---|---|
| P1 | drop the nil-pointer schema walk | RED — `a NIL pointer emitted no "P.Alpha" column` |
| P2 | drop the total `.all` | RED — `{7,1,2}` and `{7,9,2}` collide |
| P3 | drop the total `.entries` | RED — 3 distinct maps → 1 key |
| P4 | drop the UNENCODED declaration | RED |
| P5 | walk `time.Time` as a plain struct | RED — ordering not chronological |
| P6 | drop the empty-list schema walk | RED — 13 columns vanish from the fixture |
| **W1** | **add a field to `PersistentNATConfig`, a PRODUCTION type every fixture leaves nil** | **RED** |
| X1-X3 | the round-10 `(tier, CounterID)`, `(tier, len(PoolAddresses))`, `(tier, PortLow)` tiebreaks | RED — round 11 unbound nothing |

W1 is the round-10 claim, now true: a field added to a type no fixture ever
populates fails the fixture instead of passing quietly.

### The registry: a claim that was not checked, and one that was wrong

**`productionConstant` truth is now mechanically checked.** Round 10 checked
fixture constancy and stale names and left the harder half as prose — marking a
per-rule `PoolName` production-constant would have stayed green, and Junos
allows a pool per rule. Every such entry now carries a **WITNESS**: an
independently built sequence constructed to make the column vary if the claim
were false. `TestProductionConstantAxesAreWitnessed_6812` runs them and requires
each claimed column to EXIST in the witness projection and be constant in every
group — an absent column fails as loudly as a varying one, because a claim about
a column the witness never emits is not a checked claim.

Measured: marking `Snapshot.PoolName` production-constant reds with
`VARIES in witness … group witness rule-set wb: ["\x01wp10" "\x01wp11" "\x01wp12"]`.

The witnesses found something on their own. Building one rule-set carrying all
six scope clauses is **not a representable input**: `compileNATSource` expands a
multi-kind `from`/`to` into the CROSS PRODUCT of from-kind × to-kind — six
clauses on one named rule-set compile to NINE rule-sets, each with exactly one
of each. The witness therefore uses one from-kind and one to-kind per rule-set
and groups on the rule-NAME prefix; grouping on a scope field would have been
circular, since scope constancy is the thing being witnessed.

**`Pool.nil` was misclassified and moves.** `CompileConfigLenient` permits a
dangling pool reference (`compiler_nat_pool_ref_5626_test.go:164`) and the
charge walk skips it (`compiler_validate_strict_nat.go:3192`), so it is
order-irrelevant AFTER filtering — a different statement from the registry's own
"invariant for every production input". What makes it constant in the fixture is
the fixture's own precondition. The entry moves to fixture-constant rather than
the definition moving to accommodate it.

### Three columns were pessimistically classified; verified and corrected

Each verified here, not relayed:

- **`Rule.Match.Protocol` / `Protocols.*`** — the only non-test writer is
  `compiler_nat_destination.go:167-169`, and destination rules never enter
  `Security.NAT.Source`.
- **`Pool.Address` / `Port` / `PortRaw`** — `compileNATSource` builds its pools
  fresh (`pool := &NATPool{Name: inst.name}`, `compiler_nat_source.go:471`) and
  is the sole writer of `SourcePools` (`:686`); the only non-test writers of
  those three fields are in `compiler_nat_destination.go`, on DNAT pool objects
  this map never aliases.
- **`Snapshot.AddressPersistent`** — one config-global bit
  (`types_security.go:620`) stamped onto every rule by `nat_source.go:223`.

All three are now production-constant WITH a witness whose config populates them
on the other side of the compiler.

### The split, with its derivation

The column universe GREW, because the collector now sees what it used to skip —
so these are not comparable to round 10's counts as a like-for-like regression.

| sweep | columns | guarded | fixture-constant | production-constant |
|---|---|---|---|---|
| builder, per tier | 58 | 13 | 44 | 1 |
| builder, per rule-set | 58 | 4 | 47 | 7 |
| walk, per rule-set | 72 | 13 | 49 | 10 |

Round 10 reported 25 / 74 / 9 over 108 cells; this is 30 / 140 / 18 over 188.
The blind count rose because the sweep now enumerates the pointee fields, list
schemas and container totals it previously skipped — every one of those was a
hole before, it was simply not counted. The reclassifications move 12 cells from
blind to non-axis in the other direction.
