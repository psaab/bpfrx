# #1787 — learn_dynamic_neighbor cheap-first rework (per-packet 64-shard bulk lock + heap allocs)

Status: DRAFT v1 — pending adversarial plan review

## Issue framing

`learn_dynamic_neighbor` runs per validated RX packet (stage 7/8, before the
flow-cache hit stage). Its only per-packet suppression is a single-element
`last_learned_neighbor` dedup keyed on (ifindex, vlan, src_ip, src_mac). With
≥2 interleaving source keys on one binding — ordinary multi-host traffic —
every packet takes: heap alloc #1 (`vec![ingress_ifindex]`,
neighbor_dispatch.rs:331), then `with_all_shards` which locks all 64 shard
mutexes in order and heap-allocs the guard Vec (sharded_neighbor.rs:168-184),
then unconditionally overwrites entries whose MAC almost never changes.
While one worker holds all 64 shards, every other worker's per-key neighbor
lookup blocks — a global serialization point per packet.

## Honest scope/value framing

This is invisible in single-source iperf3 smoke (the 1-entry dedup absorbs
it). The win is for multi-host traffic shapes: removes 2 heap allocs + a
64-mutex acquisition per packet in the interleaved case, replacing them with
1-2 uncontended shard reads in the steady state. No throughput delta is
expected on the standard smoke; the deliverable is a hot-path-allocation-rule
violation fix plus contention removal that is measurable only under an
N-source mix. If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.

## What's already shipped / composes with

- #949 sharded map + atomic-pair bulk insert semantics (the comment at
  neighbor_dispatch.rs:340-344 is the contract: a reader sees both
  (ingress_ifindex, ip) and (logical_ifindex, ip) updated or neither).
- `insert_if_changed` (sharded_neighbor.rs:138) exists, unused on this path.
- Per-binding bounded FastMap pattern precedent: `neg_neigh_cache`,
  `resolver_enqueue_throttle` (#1769/#1771).
- #1769 resolver epoch/generation machinery (`insert_confirmed_if_generation`)
  is adjacent but UNTOUCHED — this plan changes only the RX-learn path.

## Concrete design

Stage 1 — cheap-first read-check (the core fix), in
`learn_dynamic_neighbor`:

```rust
// Stack array, no alloc. At most 2 keys: ingress + resolved logical.
let mut keys: [(i32, IpAddr); 2] = [(ingress_ifindex, src_ip), (0, src_ip)];
let mut n = 1usize;
if let Some(logical) = resolve_ingress_logical_ifindex(...) {
    if logical > 0 && logical != ingress_ifindex {
        keys[1] = (logical, src_ip);
        n = 2;
    }
}
// Read-only pre-check: per-key shard get(), 1-2 single-shard locks.
let all_current = keys[..n].iter().all(|k|
    dynamic_neighbors.get(k).map(|e| e.mac) == Some(src_mac));
if all_current {
    return; // steady state: no bulk lock, no write, no alloc
}
// Actual change (or first sighting): keep #949 atomic-pair bulk path.
dynamic_neighbors.with_all_shards(|bulk| {
    for k in &keys[..n] {
        bulk.insert(*k, NeighborEntry { mac: src_mac });
    }
});
```

Stage 2 — remove `with_all_shards`'s guard-Vec heap alloc IF cheap
(`[MaybeUninit<MutexGuard>; 64]` is fiddly; alternative: keep the Vec — it
is now off the steady-state path entirely, so the alloc only happens on
genuine MAC change/first-learn). Default: NOT done; documented as out of
scope unless reviewers insist.

Stage 3 (optional, measurement-gated) — widen the per-binding dedup from
`Option<LearnedNeighborKey>` to a small bounded per-binding FastMap (cap
~64, keep-newest), so steady-state multi-host traffic short-circuits before
even the 1-2 shard reads. Deferred to a follow-up unless the N-source
measurement shows the get() pre-check is still hot.

### TOCTOU analysis (the hard part)

The pre-check (read locks) and the bulk write are not atomic. Interleaving:
worker A pre-checks key K (stale → miss), worker B writes K with the same
MAC, A then bulk-writes the same value — harmless idempotent overwrite.
A reader between A's pre-check and A's bulk write can still observe the
OLD pair state — identical to today (the write simply hadn't happened yet).
The #949 invariant ("both or neither") is preserved because all writes to
the pair still go through `with_all_shards`. A torn read of a HALF-updated
pair remains impossible. The only semantic change: a no-op overwrite is
skipped; readers that previously saw a refreshed-but-identical entry see an
identical entry. NeighborEntry has no generation/timestamp today (verify:
sharded_neighbor.rs struct field is `mac` only) so skipping the write is
observationally equivalent.

## Public API preservation

`learn_dynamic_neighbor` signature unchanged; `ShardedNeighborMap` API
unchanged (uses existing `get` + `with_all_shards`). No protocol.go/rs wire
changes.

## Hidden invariants

- #949 atomic-pair visibility (above).
- `with_all_shards` non-reentrancy: pre-check `get()` calls happen BEFORE
  the bulk closure, never inside it.
- Resolver interplay: the #1769 resolver writes REACHABLE/PERMANENT entries
  via per-key generation-guarded inserts; RX-learn overwrites are
  last-writer-wins today and remain so for genuine changes. Skipping a no-op
  RX write cannot regress resolver state (same MAC).
- Hot-path allocation rule: stack array replaces vec!.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | steady-state write elision only; change path identical |
| Lifetime/borrow | LOW | no new structures (Stage 1) |
| Performance regression | LOW | adds 1-2 shard get() to the CHANGE path (rare); removes 64-lock from steady path |
| Architectural mismatch | LOW | uses existing map API; matches insert_if_changed precedent |

## Test plan

- cargo unit tests: steady-state elision (insert once, re-learn same MAC →
  map generation/contents unchanged, e.g. by counting with a probe map or
  asserting no change via get-before/after), change path (MAC flip updates
  BOTH keys), vlan logical-ifindex pair coverage, multicast/zero-MAC guards
  untouched.
- cargo test --release full suite; 5x flake on the touched module's tests.
- Go suite untouched (no Go changes).
- Smoke: standard Pass A v4/v6 push+rev + P12R (regression guard) on the
  loss userspace cluster. Measurement (best-effort, not a gate): 2-source
  concurrent iperf3 (cluster-lan-host + a second source container if
  available, else two -B source addrs) before/after, reporting worker CPU
  via /metrics or perf if accessible.
- Failover gate: NOT cluster-semantics code, but it is dataplane hot path —
  run `make test-failover` once before merge per the dataplane-change
  convention.

## Out of scope

- Stage 2 guard-array de-alloc of `with_all_shards` (now off steady path).
- Stage 3 widened per-binding dedup (follow-up, measurement-gated).
- Resolver (#1771 Phase 4 epoch) work.
- Any change to NeighborEntry layout.

## Open questions for adversarial review

1. Is the TOCTOU analysis sound — is there any reader that depends on the
   no-op overwrite happening (e.g. as a liveness/refresh signal)? Grep for
   consumers of insert side effects.
2. Does any path rely on RX-learn REPLACING a resolver-revoked entry with
   the same MAC (i.e., the no-op write actually re-creating a REMOVED key)?
   If key was removed, get() misses → bulk path runs → still correct. Verify
   remove paths.
3. Should the pre-check use `get()` twice (two shard locks) or a new
   `get_pair()` that locks ≤2 shards once? Is double-get acceptable?
4. Is Stage 1 alone enough to close the issue, with Stages 2-3 explicitly
   deferred?
5. Per-packet `resolve_ingress_logical_ifindex` cost — unchanged from today,
   but confirm it doesn't allocate or lock.
