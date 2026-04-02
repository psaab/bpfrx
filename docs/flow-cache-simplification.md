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

- [userspace-dp/src/afxdp/types.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/types.rs)
- [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/session_glue.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/session_glue.rs)

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
[userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs).

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
5. non-cacheable NAT64/NPTv6 decisions staying uncached

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

- [ha-simple-failover-design.md](/home/ps/git/codex-bpfrx/docs/ha-simple-failover-design.md)
- [userspace-forwarding-and-failover-gap-audit.md](/home/ps/git/codex-bpfrx/docs/userspace-forwarding-and-failover-gap-audit.md)

This document is narrower: make the flow cache easier to reason about so it
stops amplifying HA complexity.

## Validation

The current simplification work has been validated with:

- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_invalidation_for_demoted_owner_rg -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_unrelated_rg_not_invalidated -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_descriptor_nat64_falls_back -- --nocapture`

## Recommended Next Step

Implement Phase 1 next:

- extract cached-hit execution into one helper

That is the next change most likely to reduce packet-loop complexity without
changing flow-cache behavior.
