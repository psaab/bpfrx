# Flow Cache Simplification

## Purpose

This document captures the current flow-cache simplification work in the
userspace dataplane, why it matters for HA failover, what has already been
simplified, and the next implementation phases.

The goal is not to remove the flow cache. The flow cache is still needed for
performance. The goal is to make it a disposable acceleration layer instead of
another piece of HA transition machinery.

## Why This Matters

The current HA/failover path is hard to reason about because several concerns
are mixed together in the hot packet path:

1. forwarding decision
2. rewrite data
3. cache validation state
4. RG ownership / HA freshness checks
5. transition-time invalidation rules

That makes failover fragile because the fast path is carrying both performance
state and transition state.

The simpler model is:

1. canonical forwarding/session state decides what should happen
2. flow cache stores a validated shortcut for that decision
3. cache entries self-invalidate cheaply when config/FIB/RG state changes
4. failover remains correct even if the cache is cold or empty

## Current Cache Model

The current cache is still:

- per-worker
- direct-mapped
- keyed by session 5-tuple plus ingress ifindex
- validated by:
  - config generation
  - FIB generation
  - owner RG epoch

Relevant code:

- [userspace-dp/src/afxdp/types.rs](../userspace-dp/src/afxdp/types.rs)
- [userspace-dp/src/afxdp.rs](../userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/session_glue.rs](../userspace-dp/src/afxdp/session_glue.rs)

This is the right general direction. The problem was that validation and cache
construction logic were spread through the hot packet loop.

## Simplifications Already Implemented

### 1. Separate rewrite data from validation state

Committed in:

- `744a7ef5` `refactor: simplify flow cache validation state`

Changes:

- `RewriteDescriptor` now carries only rewrite/tx data
- cache validation moved into:
  - `FlowCacheStamp`
  - `FlowCacheLookup`
- `FlowCacheEntry` now carries a single `stamp`

Why this helps:

- rewrite state is no longer polluted with HA/config epoch bookkeeping
- lookup and insert semantics are explicit
- cache validation is easier to audit independently of packet rewrite logic

### 2. Extract cache eligibility and entry construction helpers

Committed in:

- `4f20542b` `refactor: extract flow cache eligibility helpers`

Changes:

- added `FlowCacheEntry::packet_eligible(...)`
- added `FlowCacheEntry::should_cache(...)`
- added `FlowCacheEntry::from_forward_decision(...)`
- packet loop now stops hand-building flow-cache entry fields inline

Why this helps:

- the hot path is less branch-heavy and easier to read
- all cacheability policy is centralized
- future cache policy changes will touch one helper instead of duplicated
  packet-loop logic

#### Cacheability contract: lookup and insertion are symmetric (#2363)

`FlowCacheEntry::packet_eligible(meta)` is the single source of truth for
which segments may use the flow cache:

- UDP — always eligible.
- established-TCP **pure ACK** (`tcp_flags::is_ack_only`, i.e.
  `flags & (FIN|SYN|RST|ACK) == ACK`; PSH and URG are ignored, so a
  **PSH+ACK data segment stays cacheable**).
- TCP control segments (SYN, SYN-ACK, FIN, RST) — **never eligible**.

Both directions of the cache must reference this predicate:

- **Lookup** is gated in `poll_descriptor/mod.rs` — the fast path is
  only entered when `FlowCacheEntry::packet_eligible(meta)` holds.
- **Insertion** is gated by `FlowCacheEntry::should_cache`, which calls
  `packet_eligible` first (#2363). Before #2363 only lookup was gated:
  a control segment that produced a `ForwardCandidate` decision would
  seed a cache entry, and a later pure-ACK on the same 5-tuple would
  take the fast path and skip the session lookup that observes and
  advances TCP closing state on FIN/RST. The cached decision is the
  legitimately-computed forward decision (so this was never a policy
  fail-open) — the harm is the skipped flag-sensitive session-state
  observation, plus the hazard of seeding any future per-packet
  flag-sensitive feature off the first control packet.

Keeping the eligibility rule in `packet_eligible` and calling it from
both sites means admission and lookup can never drift apart: a segment
that cannot look up the cache also cannot populate it.

## What Is Simpler Now

After the two refactors above:

1. cache lookup takes one context object
2. cache insertion takes one constructor path
3. descriptor fields are only packet rewrite fields
4. config/FIB/RG epoch validation is isolated from rewrite logic

This removes a large amount of inline cache plumbing from the packet path
without changing behavior.

## What Is Still Too Complex

The flow cache is improved, but the hot path still contains too much inline
execution logic after a cache hit.

The biggest remaining complexity is in cached-hit execution:

- target binding selection
- fabric queue selection
- in-place rewrite attempt
- fallback to `PendingForwardRequest`
- same-binding vs cross-binding behavior

That code still lives inline in the packet loop in
[userspace-dp/src/afxdp.rs](../userspace-dp/src/afxdp.rs).

This is still harder than it should be for HA work because the control flow of
"cache hit -> how do we transmit this?" is mixed into the control flow of
"packet classification -> should we do slow path or fast path?"

## Desired End State

The desired end state is:

1. packet loop determines whether the cache may be used
2. cache lookup returns a validated cached entry or a miss
3. one helper executes the cached hit
4. one helper constructs cache entries from authoritative forwarding decisions
5. cache invalidation remains epoch/generation based
6. failover does not require special flow-cache scans or transition-specific
   cache repair

Conceptually:

```text
packet
  -> flow cache allowed?
  -> cache lookup(validated)?
     -> yes: execute_cached_flow(...)
     -> no: resolve authoritative decision
           -> maybe cache result
           -> execute authoritative path
```

## Remaining Implementation Phases

### Phase 1: Extract cached-hit execution

Move the remaining cached fast-path execution block into one helper, for
example:

- `execute_cached_flow(...)`

That helper should own:

- target binding selection
- fabric target selection
- in-place rewrite attempt
- fallback request construction
- final recycle / continue decision

Expected benefit:

- removes most of the remaining flow-cache complexity from the packet loop
- makes fast-path correctness review substantially easier

### Phase 2: Shrink cached metadata

`FlowCacheEntry` still stores more than it likely needs.

Today it carries:

- `decision`
- `descriptor`
- `metadata`
- `stamp`

The next step is to determine whether the cached execution path really needs the
full `SessionMetadata`, or whether it only needs a smaller subset such as:

- ingress zone
- owner RG
- fabric ingress flag

Expected benefit:

- smaller entries
- clearer separation between authoritative session state and cached execution
  hints

### Phase 3: Make cache decision classes explicit

Today caching is still effectively tuned around `ForwardCandidate`.

If additional dispositions ever become cacheable, the code should not regress
back into ad hoc packet-loop branches.

Expected direction:

- define explicit cache decision classes / supported dispositions
- keep unsupported classes out of the cache constructor

Expected benefit:

- avoids future HA regressions caused by silently widening cache coverage

### Phase 4: Tighten tests around the helper boundary

Add focused tests for:

1. cache hit, same-binding transmit
2. cache hit, cross-binding transmit
3. stale HA validation forcing miss/fallthrough
4. stale RG epoch forcing miss
5. non-cacheable NAT64 decisions staying uncached (NPTv6 is now
   cacheable — see "NPTv6 fast-path caching (#2652)" below)

Expected benefit:

- protects the flow cache as a performance layer without forcing HA behavior to
  be debugged from the packet loop

## Non-Goals

This work does **not** attempt to solve the whole HA failover problem by
itself.

It does **not**:

- replace session sync design
- remove ownership or HA runtime state
- make failover MAC-move-only on its own
- remove the need for a simpler canonical HA state model

Those broader problems are covered in:

- [ha-simple-failover-design.md](./ha-simple-failover-design.md)
- [userspace-forwarding-and-failover-gap-audit.md](./userspace-forwarding-and-failover-gap-audit.md)

This document is narrower: make the flow cache easier to reason about so it
stops amplifying HA complexity.

## Validation

The current simplification work has been validated with:

- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_invalidation_for_demoted_owner_rg -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_unrelated_rg_not_invalidated -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_descriptor_nat64_falls_back -- --nocapture`

## RG epoch index fallback (#2466)

The per-RG epoch table is a fixed `MAX_RG_EPOCHS = 16` array (`rg_epochs:
[AtomicU32; 16]`). The config schema accepts redundancy-group IDs with no
upper bound, so an operator can configure an RG whose ID is `>= 16`.

Before #2466 the flow-cache stamp/consumer guard only consulted a per-RG
epoch slot when `owner_rg_id > 0 && owner_rg_id < MAX_RG_EPOCHS`; any other
owner (an out-of-range high RG ID, or `owner_rg_id <= 0` for fabric /
unresolved-owner reverse) was stamped with a literal epoch `0` and never
re-checked against any epoch slot on lookup. A cached forwarding decision
for an RG `>= 16` therefore survived that RG's activation/demotion until the
`owner_rg_lease_until` or node-level session-expiry backstop caught it —
delayed invalidation, not immediate.

The fix routes every owner through a single helper,
`flow_cache::rg_epoch_index(owner_rg_id)`:

- in-range (`1 ..= MAX_RG_EPOCHS-1`): use the owner's own slot (unchanged —
  RG 0/1/2 used by the loss cluster behave bit-identically);
- out-of-range high RG IDs and `owner_rg_id <= 0`: fall back to the
  node-level `rg_epochs[0]` activation edge.

Both `FlowCacheStamp::capture` and the lookup invalidation now use that
helper, so the stamp and the re-check always agree. This mirrors the worker
session-expiry gate (`epoch_of` in `worker/loop_body/mod.rs`), which already
maps out-of-range/`<= 0` owners to `rg_epochs[0]`; the two gates are now
consistent. A high-RG flow is now stamped with the node-level epoch and
invalidates on a node-level **activation** edge (`rg_epochs[0]` is bumped
when any RG activates, ha.rs) plus the unconditional `owner_rg_lease_until`
backstop, instead of never (it was previously stamped epoch 0). A high-RG
**demotion-without-activation** does not bump `rg_epochs[0]` (the per-RG
bump loops are themselves guarded by `idx < MAX_RG_EPOCHS`), so that case
is caught by the lease backstop rather than the epoch edge — the same
structural behavior the worker session-expiry gate already has. No schema
change and no operator-facing rejection. Tests: `out_of_range_owner_rg_stamps_node_level_epoch`,
`out_of_range_owner_rg_invalidates_on_node_level_bump`,
`in_range_owner_rg_unchanged_by_node_level_bump` (flow_cache_tests.rs).

## NPTv6 fast-path caching (#2652)

Before #2652 `FlowCacheEntry::should_cache` excluded BOTH `decision.nat.nat64`
and `decision.nat.nptv6`, so every NPTv6- and NAT64-translated packet missed
the flow cache and re-ran the full session-lookup + policy-eval slow path on
every packet. #2652 splits these two cases on the actual dataplane mechanics:

- **NPTv6 (RFC 6296) is now cacheable.** At the dataplane an NPTv6 decision is
  nothing more than a same-family IPv6 address byte-rewrite of one side
  (`rewrite_dst` for inbound, `rewrite_src` for outbound). The RFC 6296
  checksum-neutral adjustment word is computed entirely upstream in
  `src/nptv6.rs` (`translate_inbound`/`translate_outbound` via `adjust_word`),
  so the `Ipv6Addr` handed to the worker in `NatDecision` already preserves
  the L4 ones-complement sum. The slow path (`apply_nat_ipv6`) writes that
  address and SKIPS the L4 checksum adjust (`skip_l4_csum = nat.nptv6`); the
  descriptor fast path carries `l4_csum_delta == 0` (`compute_l4_csum_delta`
  short-circuits on `nat.nptv6`) so the IPv6 arm
  (`apply_rewrite_descriptor_ipv6`) ALSO leaves the L4 checksum untouched.
  The two paths are therefore byte-identical. The orchestrator
  (`frame/rewrite/mod.rs`) no longer early-returns for `rd.nptv6`; it keeps a
  defense-in-depth fall-back only when a `nptv6` descriptor carries a non-v6
  `ether_type` (NPTv6 is IPv6-only). `should_cache` drops the
  `!decision.nat.nptv6` clause and `from_forward_decision` propagates
  `nptv6: decision.nat.nptv6` into the descriptor.

- **NAT64 stays excluded (correct).** NAT64 is a version-changing translation:
  the IPv6 40-byte header is rebuilt as an IPv4 20-byte header (or vice versa),
  the frame length changes, and fragment-header handling differs. It is
  produced by `build_nat64_*_frame`, which ALLOCATES a fresh frame of a
  different size — there is no in-place rewrite the byte-write
  `RewriteDescriptor` could carry. The orchestrator still early-returns
  `None` for `rd.nat64`, and `should_cache` keeps `!decision.nat.nat64`.

Validation:

- `nptv6_is_cacheable`, `nat64_not_cacheable` (flow_cache_tests.rs) — the
  admission split; fail-on-revert if the `!nptv6` exclusion is reinstated.
- `pin_nptv6_descriptor_matches_generic_byte_for_byte`
  (frame/prop_tests/rewrite.rs) — proves the descriptor fast path output is
  byte-identical to the generic slow path for an NPTv6 dst rewrite, with the
  L4 checksum unchanged (checksum-neutral). Fail-on-revert: reinstating the
  `rd.nptv6` decline makes `apply_rewrite_descriptor` return `None` and the
  `.expect(...)` panics.
- `pin_descriptor_nat64_decline_frame_untouched` — NAT64 (and a `nptv6`
  descriptor with a v4 `ether_type`) still decline before any byte is written.
- `descriptor_generic_differential` (unmasked) — existing same-family parity
  unaffected.

## Recommended Next Step

Implement Phase 1 next:

- extract cached-hit execution into one helper

That is the next change most likely to reduce packet-loop complexity without
changing flow-cache behavior.
