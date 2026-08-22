# #2852 SNAT PortAllocator contention microbench — results & verdict

This is the REQUIRED merge-gate measurement the #2852 converged v3 plan
(`gh issue view 2852`, the Claude-SMR + Codex + AGY design round) demands
before any Phase-1 lock-free refactor lands. It answers the PLAN-KILL
question the reviewers agreed must not be weakened:

> Is the single global `Mutex<PortAllocatorLiveState>` a *measurable*
> bottleneck at the loss cluster's 6-worker scale, or does another limit
> dominate first (in which case the correct outcome is PLAN-KILL, not a
> speculative rewrite of correctness-critical NAT state)?

## What is measured

`userspace-dp/benches/snat_allocator.rs` (`harness = false`, its own
multithreaded `main` — criterion times only single-threaded closures and
cannot express M-thread contention or cross-thread p99/p999, which is the
whole point of a lock-contention gate). The production allocator is
`pub(crate)` in a bin crate, so the bench re-implements the two hot-path
shapes side by side — the same precedent as `benches/session_table.rs`
and `benches/tx_kick_latency.rs`:

- **CUR** — the current shape: ONE global `Mutex` guarding the whole
  `allocate` critical section (reuse-get + forward-probe cursor
  `next_port_offset_by_addr` + `owner_by_translated` collision arbiter +
  the #3011 FIFO `recycled_ports_by_addr` drain + `live_by_flow` insert).
  #3011 (FIFO recycle) and #4388 (`reserve_flow`, HA-synced port
  reservation) piled still more state under this one lock.
- **NEW** — the plan's Phase-1 shape: a per-pool-address atomic occupancy
  bitmap (`Vec<AtomicU64>` + atomic cursor, `fetch_or` CAS-claim where the
  bit IS the ownership token) — completely lock-free — and a TINY mutex
  held only for the single `live_by_flow` map insert (and remove on
  release). The global tracked-flow cap is one `AtomicUsize`
  (fetch_add-reserve / fetch_sub-rollback, plan F4).

Both shapes select the pool address identically and lock-free (sticky
`hash(src_ip) % num_addrs`, i.e. address-persistent selection —
`sticky_pool_index` is already lock-free on master and untouched by the
plan), so the ONLY measured difference is the port-claim + map-lock
mechanism. Both model pure NEW-flow churn (globally unique 5-tuples; in
production established flows hit the session table, not the allocator),
holding a steady occupancy by releasing the oldest outstanding flow on
each successful allocate. Persistent NAT (the colder two-lock path, and
Phase 1 has no map sharding) is not modeled.

Four AGY-5 stress profiles, threads M = {1, 2, 4, 6, 8}. Reported:
aggregate successful `allocate()`/sec across all M threads, and the
allocate-latency p50 / p99 / p999 in nanoseconds. Run on a 16-core host
(so M=8 is genuine parallelism, not oversubscription). Numbers are one
representative run; the run-to-run absolute a/s wobbles ~10% but the CUR
vs NEW *ratio* is stable.

## Measured numbers

`speedup` = NEW a/s ÷ CUR a/s. All four profiles ran at 0.0% allocation
failure for both shapes except high-occ (0.2%, identical CUR/NEW — genuine
92%-full address saturation, not a shape artifact).

### (a) uniform-low-10pct — 16 addrs × 4096 ports, 10% full, uniform sources
```
 M     CUR a/s     NEW a/s  speedup |  CUR p99  CUR p999 |  NEW p99  NEW p999
 1   2,868,506   3,950,589   1.38x  |     300      411   |     177      234
 2     955,130   1,386,382   1.45x  |    8948    14312   |    1675     2712
 4     803,664   1,152,502   1.43x  |   16203    27075   |   10344    17777
 6     657,194   1,029,144   1.57x  |   23468    37762   |   16425    26265
 8     623,612   1,001,846   1.61x  |   31385    49820   |   21982    34753
```

### (b) high-occ-92pct — same wide pool, 92% full, uniform sources
```
 M     CUR a/s     NEW a/s  speedup |  CUR p99  CUR p999 |  NEW p99  NEW p999
 1   2,153,597   3,467,297   1.61x  |     339      558   |     376      530
 2     931,594   1,329,393   1.43x  |    8388    14328   |    1635     5921
 4     738,564   1,089,348   1.47x  |   16876    27977   |   10538    17437
 6     623,879     988,945   1.59x  |   24220    38907   |   16658    26167
 8     596,575     959,130   1.61x  |   32613    52046   |   22299    35032
```

### (c) skew-80-20 — 16 addrs, 50% full, 80% of flows from 10% of sources
```
 M     CUR a/s     NEW a/s  speedup |  CUR p99  CUR p999 |  NEW p99  NEW p999
 1   2,468,139   3,703,412   1.50x  |     310      484   |     202      277
 2     932,573   1,421,488   1.52x  |    8645    14659   |    1590     5590
 4     760,738   1,122,890   1.48x  |   16490    27780   |   10310    17103
 6     642,948   1,014,904   1.58x  |   23929    38118   |   16263    26083
 8     599,597     970,374   1.62x  |   32491    51213   |   22236    36607
```

### (d) narrow-64port — 1 addr × 64 ports (one AtomicU64 word), 75% full
```
 M     CUR a/s     NEW a/s  speedup |  CUR p99  CUR p999 |  NEW p99  NEW p999
 1   4,150,769   4,321,267   1.04x  |     192      251   |     168      281
 2   1,592,324   1,312,937   0.82x  |    8166    11613   |    1778     6118
 4     969,312   1,100,647   1.14x  |   15638    26462   |   11423    19054
 6     685,918   1,040,272   1.52x  |   24337    44327   |   17335    27909
 8     630,316     978,180   1.55x  |   32157    51139   |   23477    36635
```

## Verdict

**1. The global mutex IS a measurable bottleneck — no PLAN-KILL.**
The CURRENT shape exhibits textbook mutex-contention collapse: aggregate
throughput *drops* as cores are added (uniform-low: 2.87M a/s at M=1 →
0.62M a/s at M=8 — negative scaling), and the allocate p99 tail explodes
~100× (300 ns → 31 µs) over the same range. The whole allocator caps
around 0.6 M allocs/sec regardless of core count, entirely on the lock.
This is a per-NEW-FLOW cost, so a pure throughput / elephant-flow workload
is unaffected — but a high connection-setup rate (the issue's stated
workload) serializes hard on this one lock. The reviewers' PLAN-KILL
condition ("if the mutex isn't the dominant bottleneck") is NOT met; the
mutex plainly is.

**2. Phase-1 (lock-free bitmap claim + tiny map lock) is warranted.**
NEW is consistently **1.4–1.6× faster at the loss cluster's M=6 scale (and
M=8) across all four profiles**, with 1.3–2× lower p99, and never
regresses at M≥4. It stays ahead under 92% occupancy (the competent
bitmap word-scans `trailing_zeros(!word)` for a free bit in O(1) per
non-full word, so a near-full pool does NOT devolve to a linear probe) and
under 80/20 source skew (which concentrates load onto ~10% of the bitmaps
— per-address CAS contention, still a net win). Removing the port-claim
from the critical section is the dominant, lowest-churn win the plan
identified, and the measurement confirms it. The only place NEW is roughly
par / slightly behind is the narrow 64-port pool at M=1–2 (0.82–1.04×),
where the single-`AtomicU64` CAS + tiny-map-lock has no advantage over the
current cache-hot FIFO at low concurrency — but even there NEW pulls ahead
(1.14–1.55×) once contention rises to M≥4.

**3. Phase-1 alone does NOT achieve near-linear scaling — Phase-2 (shard
the maps) is INDICATED, not merely optional.** NEW *also* falls off with
core count (uniform-low: 3.95M at M=1 → 1.00M at M=8) because the residual
tiny mutex — `live_by_flow` insert on allocate + remove on release — is
now the serialization point. NEW converges to ~1.0 M allocs/sec at M=6–8
versus CUR's ~0.62 M: a solid 1.6× uplift, but well short of the plan's
"near-linear scaling to 6 threads" target. These numbers therefore satisfy
the exact condition the plan set for Phase 2 ("hash-shard the maps *only
if* Phase-1 lab numbers still show the residual mutex as the bottleneck")
— they do. Phase 1 should land first (biggest win, no shard-key
correctness surface, no F5 two-lock path); Phase 2 is the follow-on to
reach linear scaling.

### Implementation caveat surfaced by the bench (for the /engineer follow-on)

The plan's F4 global cap uses fetch_add-reserve *before* the port is
claimed and before the paired release runs, so up to M reservations are in
flight at once. On a *tiny* pool at very high occupancy this transiently
overshoots the cap by up to M and spuriously rejects: the narrow-64 pool
run at 89% occupancy failed 71–79% of allocations at M=6/8 purely from
this overshoot (48 outstanding + 8 in-flight > the 64 cap), which is why
the shipped narrow profile uses 75% occupancy to measure the *claim*
mechanism rather than cap thrash. This is a corner (a 64-port pool at ~90%
is already effectively exhausted), but the Phase-1 implementation should
either order release-before-reserve or fall back to the serialized path
for very small pools, and its unit tests should cover the near-full narrow
pool under concurrency.

## Reproduce

```bash
cd userspace-dp
CARGO_TARGET_DIR=/tmp/cargo-2852 cargo bench --bench snat_allocator
```

No cluster required — this is a pure in-process contention microbench. The
complementary cluster new-flow-ceiling measurement on
`loss:xpf-userspace-fw0/fw1` (a connection-rate generator, distinct from
the bulk-throughput `perf-test` skill) remains the lab-deferred gate for
the actual Phase-1/Phase-2 code PR, per the plan.

## Phase-1 shipped (fix/2852-phase1-lockfree)

Phase 1 landed in `userspace-dp/src/nat/allocator.rs`. What changed vs the
pre-#2852 single-mutex allocator:

- **Port ownership is a lock-free per-address bitmap.** `AddressOccupancy`
  (`Vec<AtomicU64>` + an atomic fresh-port cursor) replaces the
  mutex-guarded `owner_by_translated` + `next_port_offset_by_addr` maps.
  A `fetch_or` CAS on the bit is the sole port-ownership arbiter (a set
  bit cannot be re-claimed — the ABA-safe ownership token). The
  non-persistent new-flow hot path claims its port with NO global mutex
  and takes the retained `Mutex<PortAllocatorLiveState>` only for a tiny
  reuse-check + exact-cap-check + `live_by_flow` insert.
- **F1 (conditional bit-clear on release):** `release_flow` /
  `rollback_flow` only clear the bit after confirming the flow's record
  still owns that translated tuple (the `live_by_flow` lookup under the
  mutex is the guard); the clear is idempotent (`fetch_and` returns
  whether the bit was set).
- **F2 (FIFO recycle preserved):** freed ports still recycle oldest-first
  via `AddressOccupancy::recycle`, a `VecDeque` behind a per-ADDRESS
  mutex (not the global one) — the exact `push_back`/`pop_front` ordering
  the #3011 tests pin. A fully lock-free MPMC recycle ring is a Phase-2
  option; `crossbeam` is not a dependency and a hand-rolled lock-free ring
  is not worth the correctness risk on this hot path. Lock ordering is
  always global → recycle (recycle is innermost), so there is no deadlock
  and F5 is sidestepped (Phase 1 has no two-map-shard path).
- **F7 (addr_index in the record):** `LiveAllocation` carries the
  pool-address index so release is O(1) — the `addr_index_by_translated`
  reverse map is gone.

### F4 resolution — the overshoot caveat does not apply to Phase 1

The caveat above worried that a `fetch_add`-reserve global cap overshoots
by up to M in-flight and falsely exhausts a tiny pool near capacity. The
shipped Phase 1 does **not** use a pre-claim atomic reserve at all: the cap
is `live_by_flow.len()` re-checked under the tiny insert mutex, where the
map length is authoritative. That check is EXACT — it never overshoots, so
a tiny pool near capacity is never falsely exhausted. This is strictly
better than release-before-reserve / small-pool-fallback, and it is
available precisely because Phase 1 keeps the maps under one mutex (the
overshoot only exists in the Phase-2 sharded world where the cap would be
checked outside any lock). Covered by
`pool_snat_fills_to_exact_capacity_then_exhausts` and the concurrent
`pool_snat_lockfree_concurrent_fill_is_exact_and_collision_free`.

### Merge-gate status

- **Microbench gate:** met (this doc — no PLAN-KILL; the mutex is a
  measurable bottleneck and Phase 1 is 1.4–1.6× at M=6/8).
- **Regression:** full `cargo test` green (3743/0); the NAT suite includes
  the new concurrent no-double-alloc / no-leak / exact-cap RED-on-revert
  tests plus the preserved #3011 / #3047 / #4388 / #4559 tests.
- **Cluster new-flow-ceiling on `loss:xpf-userspace-fw0/1`:** still the
  lab-deferred gate (needs a connection-rate generator, distinct from the
  bulk-throughput `perf-test` skill) — flagged, not run in this change.
- **`make test-failover`:** recommended before merge (HA reserve_flow path
  is exercised by the change); flagged as a nice-to-have cluster smoke.

### Phase 2 (still deferred)

Hash-shard `live_by_flow` and the persistent-lease maps (the residual tiny
mutex is now the serialization point — the microbench shows NEW also falls
off with core count). Deferred until the loss-cluster new-flow-ceiling
measurement shows the residual map mutex is the next bottleneck. Design
(two-tier shard keys, F5 lock-ordering resolution) is in the converged v3
plan on the `research/2852-portalloc` branch.

## #6610 — the bench's flow-key overflow, and why these numbers stand

`benches/snat_allocator.rs` computed its synthetic `dst_ip` uniqueness tag as
`0xc000_0000 + ((owner as u32) << 24) + (n & 0x00ff_ffff)`, with `owner = 255`
for the pre-population pass. `0xc0` already occupies the top byte, so that
addition overflows `u32` for any owner >= 64 and **panicked on the very first
prepop flow** under debug assertions — which is why `cargo test --all-targets`
blew up while `make test-rust` (release, `--bins --tests`) never noticed.

**The published numbers above are NOT affected, and nothing needs
re-measuring.** The failure mode had to be established rather than assumed,
because a silent release wrap producing a wrong accumulator would have
invalidated every figure here. It does not:

- `dst_ip` is a uniqueness tag consumed only by the `FxHashMap<FlowKey, _>`
  hash. Address selection uses `src_ip`. No throughput, percentile or
  fail-fraction figure reads its numeric value.
- Every realized `n` is `< 2^24`, so the low-24 term can never carry into the
  top byte. The wrap was therefore a pure mod-256 fold of that byte: prepop
  landed on `0xbf`, worker threads on `0xc0..0xc7`. All nine realized tags stay
  **distinct**, so the globally-unique-5-tuple invariant — the only thing this
  arithmetic has to guarantee — survived intact.
- Confirmed empirically: a post-fix release run reproduces this document's
  fail-fraction fingerprint exactly (0.0/0.0 on uniform-low, skew-80-20 and
  narrow-64port; 0.2/0.2 on high-occ, identical CUR/NEW). Had the wrap aliased
  prepop flows onto churn flows, the duplicate keys would have leaked bitmap
  bits and live-count slots and the fail fractions would have diverged.

Two fixes that look right and are **not**, recorded so they are not tried
again: `saturating_add` collapses `0xc0 + 0xff` to `u32::MAX` for *every*
prepop `n`, destroying the low-24 discriminator and manufacturing the exact
duplicate keys the invariant forbids; and a wider accumulator changes the tag
values, so a run is no longer byte-comparable with the numbers above.

The tag is now built as two disjoint bit fields OR'd together, with the
producer byte named (`WORKER_TAG_BASE`, `PREPOP_TAG`) rather than computed, and
the injectivity invariant expressed as `const _: () = assert!(...)` so it is
checked at compile time. `make test-rust` gained a `cargo check --benches` leg:
benches are still never *run* there, but compiling them is what evaluates those
const asserts, so a reintroduction of this class now fails the gate.
