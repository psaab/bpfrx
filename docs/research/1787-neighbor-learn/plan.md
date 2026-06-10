# #1787 — learn_dynamic_neighbor cheap-first rework (per-packet 64-shard bulk lock + heap allocs)

Status: CONVERGED PLAN-READY (Codex + AGY + Claude SMR)
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
- #1769 resolver epoch/generation machinery (`insert_confirmed_if_unchanged` (sharded_neighbor.rs:120))
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

Two distinct interleavings (round-1 Codex finding folded):

1. Miss-then-write (analyzed in v1): worker A pre-checks key K (stale →
   miss), worker B writes K with the same MAC, A then bulk-writes the same
   value — harmless idempotent overwrite. Readers between A's pre-check
   and bulk write see the OLD pair state, identical to today.

2. **Current-then-removed (the v1 gap): linearization semantics.** If the
   pre-check sees the current MAC and a concurrent remover then deletes
   the key, the elided write does NOT re-create it (today's unconditional
   write would have). New semantics, stated explicitly: **a no-op RX learn
   linearizes at the successful pre-check read — a remove that lands after
   the read wins.** This is correct for every production remove path:
   netlink FAILED/delete (neighbor.rs:351), resolver authoritative-FAILED
   revoke (neighbor_resolver.rs:708), and manager replace/bulk-remove
   (coordinator/mod.rs:177, :671) all intend the entry GONE. Recovery
   (r2 fold — the "next packet" claim was too strong): the next packet
   from that source THAT REACHES learn_dynamic_neighbor pre-check-misses
   and re-learns via the bulk path. A packet suppressed by the
   per-binding `last_learned_neighbor` dedup (set at
   neighbor_dispatch.rs:320 after this call, including after an elided
   no-op) does not reach it — but this dedup-delayed re-learn window is
   PRE-EXISTING, not introduced: today a write also sets the dedup, so a
   remove landing after the write is equally suppressed from re-learn by
   identical packets until the dedup key changes/evicts. The elision
   merely makes the interleaved-source case behave like the
   single-source case always has. Recovery for dedup-suppressed sources
   comes from the same paths as today: any second source key on the
   binding evicting the 1-entry dedup, the ARP/NDP learn stage
   (poll_stages.rs:80, :103), and the #1769 resolver probe on
   forwarding miss. Document both halves at the call site.

The #949 "both or neither" invariant is **scoped to this function's pair
write only** (v1 overstated it): the ARP/NDP learn stage inserts the
single ingress key via per-key insert (poll_stages.rs:80, :103), so pair
atomicity was never a global map property. All pair writes from
`learn_dynamic_neighbor` still go through `with_all_shards`; a torn read
of THIS pair remains impossible. NeighborEntry is `{ mac }` only
(types/forwarding.rs:143 — v1 cited the wrong file), no
generation/timestamp, so eliding an identical write is observationally
equivalent for all consumers (AGY audited all get() sites: forwarding
lookup, pending-retry sweep, fabric peer resolution, status count — none
depend on write side effects).

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

- cargo unit tests (round-1 fold: contents-comparison cannot prove
  elision and RX learn does not bump `neighbors.generation`): factor the
  decision into a pure helper, e.g.
  `fn pair_write_needed(current: [Option<[u8;6]>; 2], n: usize, mac: [u8;6]) -> bool`,
  unit-tested directly (all-current → false; any-miss/any-stale → true).
  Integration tests assert end-state map contents for: change path (MAC
  flip updates BOTH keys), first-learn, vlan logical-ifindex pair,
  removed-key re-learn on next packet, multicast/zero-MAC guards.
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
2. RESOLVED round 1 (Codex): remove-after-pre-check is the real race —
   answered by the linearization semantics above (removes win; next packet
   re-learns). Remove-before-pre-check misses → bulk path → correct.
3. Should the pre-check use `get()` twice (two shard locks) or a new
   `get_pair()` that locks ≤2 shards once? Is double-get acceptable?
4. Is Stage 1 alone enough to close the issue, with Stages 2-3 explicitly
   deferred?
5. Per-packet `resolve_ingress_logical_ifindex` cost — unchanged from today,
   but confirm it doesn't allocate or lock.
