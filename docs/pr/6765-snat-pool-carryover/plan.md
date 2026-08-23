# #6765 — changed SNAT/NAT64 pools reissue live translated tuples on retained addresses

**Status: IMPLEMENTED** (the plan below is kept as the record of what was decided and why; see the PR for the landed shape).

Originally: PLAN, no implementation. This touches the NAT allocator (hot-path
data structures) and both config-apply rebuild paths, so it is a boundary change
and gets a plan first.

## Verification of the issue's own re-derivation

The issue body carries a re-derivation "VERIFIED at `39f1f8b93`". It was
**re-verified by SYMBOL at `b3acae439`** (current master) rather than inherited —
the cohort's original cites point at a deleted `/tmp/opus-review-001.md` and
rotted line numbers. All five claims hold:

| # | Claim | Symbol checked at `b3acae439` |
|---|---|---|
| 1 | Carry-over keyed on the whole address list | `SourceNatPoolAllocatorKey { pool_name, pool_addresses_v4: Vec<Ipv4Addr>, pool_addresses_v6, port_low, port_high }` — `nat/source.rs` |
| 2 | Occupancy rebuilt from zero | `AddressOccupancy::new` — all-zero `words`, `cursor` at 0; the set bit is the sole ownership token |
| 3 | Snapshot refresh purges nothing NAT-related | `coordinator/snapshot_refresh.rs` — only `tunnel_remap_purge_ids` |
| 4 | NAT64 identical shape | `nat64.rs` `reuse_allocator` requires `p.pool_v4.as_slice() == pool_v4` |
| 5 | No re-seed on the apply path | `source_nat_runtime_compatible` is `#[allow(dead_code)]`; every `reserve_synced_source_nat_allocation*` caller is HA session-import |

Two structural facts the fix turns on, also verified:

- `PortAllocatorShared.occupancy` is a `Vec<AddressOccupancy>` indexed **by pool
  address position**. A changed address list changes the indices, which is why
  the existing all-or-nothing key cannot simply be loosened — reuse across a
  changed list would misindex.
- `parse_source_nat_rules_inner` receives `previous: Option<&[SourceNatRule]>`,
  so the **previous allocator is in scope at the rebuild site**. It does *not*
  receive the session table. So the carry must come from the old allocator's own
  live state, not from a session walk.

## The defect, stated as an invariant

> A translated tuple that a live session holds must not be issued to a second
> flow. Rebuilding an allocator over a **retained** address discards the bitmap
> that enforced that, and `claim()` then hands out `port_low` first.

The exposed case is precisely a **partial-overlap** pool change — add or remove
one address from a pool of ten — and it is the one case no test covers. The
existing `nat64_4518_pool_change_resets_allocator` swaps to a **disjoint**
address, where reissuing `port_low` is not a collision, so it pins the reset as
correct and never reaches the retained-address case.

## Proposed fix

At each of the two rebuild sites, when the new pool **overlaps** the old one but
the key does not match exactly:

1. build the fresh allocator as today (indices are correct for the new list);
2. then **re-seed the retained addresses' live port ownership from the previous
   allocator** before the new rules are published.

Re-seeding is what the HA session-import path already does for exactly this
purpose — seed an allocator with a tuple that someone else owns — so the
mechanism exists and is exercised; only the caller is new.

### Where the re-seed lives

Inside `nat/allocator.rs`, as a method taking the previous `PortAllocator` and
the retained address set. `live_by_flow` is private to that module and should
stay private: an enumeration accessor exported for one caller is a wider blast
radius than the operation itself.

### Bounds, stated so they are not discovered later

- Only addresses present in **both** pools are re-seeded.
- Only ports inside the **new** `port_low..port_high` range. A narrowed range
  cannot re-seed everything; what is dropped is **counted and logged once**, not
  silently discarded — a silent drop here is the same class of defect as the one
  being fixed.
- Runs at **config apply only**. No per-packet cost, no change to `claim()`.

### What must NOT change, and is pinned by existing tests

- **Unchanged pool** — exact key match still shares the whole
  `Arc<PortAllocatorShared>`, so bitmap, cursor, `live_by_flow` and persistent
  leases all carry (`tests_pool.rs`
  `pool_snat_persistent_compatible_refresh_preserves_lease_state`).
- **Fully-disjoint swap** — still a full reset
  (`nat64_4518_pool_change_resets_allocator`).
- **Cold start** — still a full reset; `previous` is `None` and the existing
  comment's reasoning ("replaying unproven translated tuple ownership") is
  unaffected.

## Scope decision that needs a call

**Persistent leases and `address_persistent` state are NOT re-seeded by this
plan.** Today they survive only an exact key match, so a partial-overlap change
already loses them for retained addresses. That is a real gap, but it is a
*different* defect: losing a lease re-maps a source to a new address (a policy
surprise), whereas the reported defect issues a tuple a live session still holds
(a correctness/reverse-path collision).

Folding both into one change would make the diff much larger and mix a
correctness fix with a behaviour question. Recommendation: fix the collision,
file the lease half separately, and say so in the PR rather than leaving a reader
to notice the asymmetry.

## Test strategy

The binder is the case that does not exist today:

- reload with a pool that **retains** an address and changes another;
- a live allocation exists on the retained address at `port_low`;
- assert the rebuilt allocator does **not** issue that tuple to a new flow.

Plus the three safe cases above must stay green — this fix *narrows* what the
allocator will issue, so the over-reach direction is real and each cell needs its
pair.

Mutation cells: neutralise the re-seed (binder reds, safe cases green); re-seed
**all** addresses rather than retained-only (a disjoint-swap cell must red);
re-seed outside the new port range (a narrowed-range cell must red).

## Validation

- `cargo test --release --bins --tests -- --test-threads=1` with
  `CARGO_TARGET_DIR` outside the worktree (parallel deadlocks silently).
- `go test -count=1 ./...` for the Go side.
- This **moves the `userspace-dp` binary**, so it owes the cargo leg on the merge
  result plus the cluster smoke — the Go fold gate cannot see a Rust regression.
