# Plan v3 — #1635 Cold-path histogram bucket layout + per-zone-pair slot map redesign

**Issue**: #1635. Foundation redesign that #1622 PLAN-KILL identified as required for
trustworthy Scale Target measurement.

**Branch**: `refactor/1635-cold-path-hist-redesign`.

**Status**: PLAN-READY pending Codex r1 (retry in flight; AGY r1 + Claude SMR r1+r2
have ratified the v3 shape).

**v3 changelog** — absorbs:
- Claude SMR r1 F1 (bucket stride too wide), F2 (silent slot-63 alias), F3
  (older-Go silent miscompile), F4 (stale slot-map remapping).
- AGY r1 [1.1] (Prometheus cardinality math error: 80 buckets × series-per-bucket
  fan-out, NOT one series per family), [1.2] (sparse wire serialization), [1.6]
  (rename to `builder_collision`), [1.7] (hot-path FastMap lookup hazard under 1-in-1
  sampling), [1.9] (raise capacity behind sparse serialization).
- Claude SMR r2 F5 (per-slot byte-count math error), F7 (example/prose
  inconsistency on hole reuse).

**v3 deltas vs v2**:
- Bucket layout: 80 → **48** buckets (pivot at 512 ns, not 1024 ns).
- Slot capacity: 128 → **256** (only viable because of sparse wire serialization).
- Wire layout: dense fixed-shape arrays → **sparse active-slot-only** Vec encoding.
- Hot-path lookup: per-sample `FastMap` lookup → **per-binding precomputed
  `cold_path_slot: Option<u8>`** populated at config-apply.
- Slot reuse: append-only-monotonic → **immediate slot reuse with control-plane
  zero-out of the slot's atomic counters**.
- `alias_seen` → renamed `builder_collision`.

---

## §1 Context — the three #1622 structural findings to fix

### F1: Bucket-0 resolution floor
Current `cold_path_hist.rs:62 bucket_index_for_ns_24` is purely power-of-two starting
at `[0, 1024) ns` for bucket 0. The 10-rule cold-path target range is ~50-150 ns.
Every 10-rule sample falls into bucket 0; Prometheus `histogram_quantile()` reports
p50 = bucket-0 midpoint = 512 ns. True p50 of a 50-150 ns distribution = ~100 ns.
**Reported error = 5×.** Operator-facing Scale Target table is untrustworthy at low
rule counts.

### F2: 16-slot splitmix64 collision bias
`zone_pair_slot` hashes packed `(from_zone_id, to_zone_id)` through splitmix64 into a
4-bit index. Birthday paradox on 8 active zone-pairs into 16 slots gives 88.2%
collision probability. On collision, `alias_seen` excludes BOTH slots from
publication. When the colliding pair is `(high-rule-count, low-rule-count)`, the
published aggregate is biased toward the survivor.

### F3: Bimodal aggregate corruption
The published "aggregate p50 across non-aliased slots" is a union of disjoint
per-zone-pair latency distributions. Aggregate percentiles over a union are
packet-mix-ratio artifacts, not flow-duration percentiles.

**All three are structural — no harness fix rescues them. The primitive (and its wire
contract) has to change.**

---

## §2 What this PR delivers

### §2.1 Fix F1 — log-linear bucket layout (16-ns stride, 48 buckets, pivot at 512 ns)

Replace the 24-bucket pow-of-2 layout with a **log-linear** layout:

```
Linear band:   ns ∈ [0, 512) ns split into 32 buckets of 16-ns stride each.
               Bucket b (0 ≤ b ≤ 31) covers [b*16, (b+1)*16) ns.

Exponential band: ns ∈ [512, 2^24) ns split into 15 pow-of-2 buckets.
               Bucket 32+i (0 ≤ i ≤ 14) covers [2^(9+i), 2^(10+i)) ns.
               (i=0: [512, 1024); i=1: [1024, 2048); ...; i=14: [2^23, 2^24).)

Saturate band: ns ≥ 2^24 (≈16.8 ms) lands in bucket 47.
```

**Total: 48 buckets** (up from 24; down from v2's 80).

**Pivot rationale (AGY r1 [1.1])**: pivoting at 512 ns instead of 1024 ns halves the
linear-band bucket count (32 instead of 64) with **no resolution loss** in the
critical 50-150 ns range. A 600 ns sample lands in the `[512, 1024)` bucket with
worst-case relative error `(1024-512) / 768 = 67% (= 1.67× error)` — satisfies the
"≤2× error" gate. The 1M-rule target (~5000-50000 ns) lands in the same
exponential band as v2 with the same per-bucket relative error.

**Branchless formula**:

```rust
#[inline]
pub(in crate::afxdp) fn bucket_index_for_ns_48(ns: u64) -> usize {
    if ns < 512 {
        (ns / 16) as usize    // [0, 32) linear band
    } else {
        let clz = ns.leading_zeros() as i32;
        // ns ∈ [512, 2^24): log2(ns) ∈ [9, 24)
        let log2 = 63 - clz;
        let b = 32 + (log2 - 9) as usize;
        b.min(POLICY_COLD_PATH_HIST_BUCKETS - 1)
    }
}
```

**Acceptance criterion**: per-bucket relative error ≤ 2× for any true p50 ≥ 24 ns
(the 1.5×-stride floor matches the ~25-40 ns wrapper baseline measured in #1620
calibration). Below 24 ns the wrapper-underflow gate already discards.

### §2.2 Fix F2 — direct zone-pair slot map (256 slots, sparse wire serialization)

Replace the splitmix64 hash with a **direct, snapshot-built** map from
`(from_zone_id, to_zone_id)` to slot index.

**Slot capacity = 256** (AGY r1 [1.9]: 128 v2 was too low; 256 gives ~21× headroom
over the largest known deployment. Memory cost is now bounded by **sparse
serialization** below — only active slots ride the wire.)

**Per-worker local memory** = 256 slots × (1 + 1 + 1 + 0.125 + 48 buckets × 8) byte
≈ **99 KB** local + **99 KB** atomics per worker. For 12 workers that's ~2.4 MB
total per host — fine.

**Wire payload (sparse)**: only slots with `samples > 0` are serialized. At 12 active
zone-pairs the payload is ~12 × (48 × 8 + 24) = **~5 KB per worker per scrape**
(vs v2's 82 KB dense). A 12-worker cluster scrapes ~60 KB/sec — trivial.

### §2.2.1 Sparse wire encoding (AGY r1 [1.2])

The wire format encodes only **active** slots. Both Rust and Go sides exchange:

```
cold_path_active_slot_ids:    Vec<u8>        // slot indices with samples > 0
cold_path_active_zone_from:   Vec<u16>       // parallel array, from_zone_id
cold_path_active_zone_to:     Vec<u16>       // parallel array, to_zone_id
cold_path_active_samples:     Vec<u64>       // parallel array, samples count
cold_path_active_sum_ns:      Vec<u64>       // parallel array
cold_path_active_buckets:     Vec<Vec<u64>>  // parallel array; each inner Vec is 48 buckets
cold_path_active_builder_collision: Vec<bool>// parallel array (renamed from alias_seen)
cold_path_overflow_active:    bool           // true if any (from, to) couldn't be assigned
cold_path_layout_version:     u32            // = 3
```

All Vec fields use `skip_serializing_if = "Vec::is_empty"`. A worker that has never
sampled emits zero new wire bytes — identical to pre-#1635 (forward-compat with v1
Go readers that don't know these field names).

Empty-slot fields (e.g., a slot with samples == 0 because its zone-pair has had no
traffic this window) are **omitted** from the wire payload. The Go side reconstructs
which slots are "absent" from the union of active_slot_ids vs the snapshot's
known zone-pair list.

**Cardinality**: Prometheus emits N series per metric family per scrape where N =
number of active (from_zone, to_zone) labels actually present in the payload. At 12
active pairs × 12 workers × 4 per-slot families × (48 bucket labels + 3 scalar
families) ≈ **~30K series steady state**. Acceptable for Prometheus at typical
operator scale. (vs v2's 100K theoretical worst case identified by AGY r1 [1.1].)

### §2.3 Fix F4 + AGY r1 [1.7] — slot map lookup precomputed per-binding

A `Binding` (one per AF_XDP queue) is created per `(interface, queue_id)` and pinned
to one or more `(from_zone_id, to_zone_id)` pairs depending on traffic direction.
**For ingress traffic on a binding, the (from_zone, to_zone) pair is determined by
policy lookup per packet, not statically by the binding.**

This means the AGY [1.7] "precompute per-binding" suggestion is wrong as literally
stated — a binding's zone-pair is NOT static; the from_zone derives from the binding
but the to_zone derives from the routed destination. So per-packet we still need
SOME lookup.

**Resolution** (AGY [1.7] in spirit, refined): the lookup happens inline in the
poll_descriptor hot path AFTER the policy lookup decides from_zone + to_zone. The
hot-path cost question is then "what's the fastest way to map (from_zone:u16,
to_zone:u16) → slot:u8?"

**Implementation**: a flat `[u8; 65536 * 8]` lookup table is wildly too large.
Instead, since `from_zone_id` and `to_zone_id` are bounded by zone count (typically
< 32 in production) we use a **bounded 2D table**:

```rust
pub(in crate::afxdp) struct ColdPathSlotMap {
    /// 32x32 = 1024-entry table indexed by (from & 0x1F, to & 0x1F).
    /// 1024 bytes per snapshot. A miss (entry == u8::MAX) means the pair has no
    /// slot assigned; sample is dropped at the hot path.
    pub flat_table: Box<[u8; 1024]>,
    /// slot_idx -> Option<(from, to)>. Inverse for Prometheus label emission.
    pub inverse: [Option<(u16, u16)>; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// True if some zone-pair couldn't be assigned a slot (capacity exhausted).
    pub overflow_active: bool,
}

#[inline]
pub(in crate::afxdp) fn lookup_slot(
    map: &ColdPathSlotMap,
    from: u16,
    to: u16,
) -> Option<u8> {
    if from >= 32 || to >= 32 {
        return None;
    }
    let entry = map.flat_table[((from as usize) << 5) | (to as usize)];
    if entry == u8::MAX { None } else { Some(entry) }
}
```

**Cost**: one `>= 32` predicate, one bit-shift, one array index, one `!= u8::MAX`
predicate. Compiles to ~3-5 ns even on a cold cache miss (the 1 KB table fits in
L1d). At 1-in-256 sampling this is amortized; at 1-in-1 sampling under stress
this is ~3-5% of the 100 ns packet budget — acceptable, far less than the FastMap
hashmap hazard AGY r1 [1.7] flagged.

**Zone-id ceiling at 32**: Junos vSRX deployments use small named zone counts
(typically 4-20). Linux + AF_XDP test rigs cap at ~10. Junos's MAX_ZONES const is
historically 32 in xpf (see `pkg/config/zone.go`). Pairs where either zone_id ≥ 32
land in slot None and are silently dropped at the hot path. The Prometheus gauge
`xpf_userspace_worker_cold_path_zone_id_out_of_range_total` counts these drops so
operators see if their deployment has outgrown the static 32-zone limit.

### §2.4 Fix F4 + Claude SMR r2 F7 — immediate slot reuse with zero-out (AGY r1 [1.3])

The v2 plan had an internal contradiction (prose said "hole reuse", example showed
"append-only-no-reuse"). v3 resolves with AGY's recommendation:

**Slot reassignment policy**: when a zone-pair `(from, to)` is removed from the
active set in a snapshot apply, its slot is marked free. When a new
`(from', to')` is added, it takes the lowest free slot index. **Before the new
assignment becomes live, the control plane atomically zeros the slot's
accumulator fields** (`buckets`, `sum_ns`, `samples`, `builder_collision`,
`first_key`) in BOTH the `WorkerColdPathAtomics` and the per-binding
`WorkerColdPathCounters` local accumulator.

Concretely the zero-out runs in `forwarding_build/mod.rs`:

```rust
fn rebuild_slot_map(prev: &ColdPathSlotMap, new_pairs: &[(u16, u16)])
    -> (ColdPathSlotMap, Vec<u8> /* slots to zero on next worker tick */)
{ ... }
```

The returned `slots_to_zero` Vec is consumed by the worker on its next poll-loop
iteration via the existing `WorkerColdPathAtomics` reset path (added in v3).

Per-binding `WorkerColdPathCounters` (worker-local mutable accumulator) is zeroed
on the same worker tick.

**Subtle race**: between the snapshot publish (Arc-swap) and the worker's
zero-out tick, the hot path might record a sample at the new slot using a stale
local accumulator value. v3 mitigates by ordering:
1. Snapshot apply publishes the new `ColdPathSlotMap` via ArcSwap.
2. Worker's first observation of the new map kicks the zero-out path.
3. Zero-out completes BEFORE `record_sample` is called for the new (from, to).

Ordering enforced by checking `Arc::ptr_eq(&old_map, &new_map)` at the top of the
hot-path slot lookup; if pointer differs, run zero-out for the affected slots
synchronously before the sample record.

### §2.5 Fix F3 — per-zone-pair Prometheus labels

Per-slot metrics carry `from_zone` and `to_zone` labels (string zone-name resolved
from snapshot on Go side). Since wire is sparse (§2.2.1), the label set is
naturally bounded by active-pair cardinality.

```
xpf_userspace_worker_cold_path_ns_bucket_v3{worker_id, from_zone, to_zone, le}
xpf_userspace_worker_cold_path_samples_total_v3{worker_id, from_zone, to_zone}
xpf_userspace_worker_cold_path_sum_ns_total_v3{worker_id, from_zone, to_zone}
xpf_userspace_worker_cold_path_builder_collision_v3{worker_id, from_zone, to_zone}
xpf_userspace_worker_cold_path_overflow_active{worker_id}
xpf_userspace_worker_cold_path_zone_id_out_of_range_total{worker_id}
xpf_userspace_worker_cold_path_layout_version{worker_id, version}
```

The `_v3` suffix replaces v2's `_v2` and the existing v1 names. Operators querying
the cold-path tables must use `_v3` post-rollout. v1 names are still emitted by
pre-#1635 daemons; the version-switch on the Go side honors that.

### §2.6 `alias_seen` → `builder_collision` (AGY r1 [1.6])

The field is renamed end-to-end:
- Rust `WorkerColdPathCounters.builder_collision: [bool; 256]`
- Rust `WorkerColdPathAtomics.builder_collision: [AtomicBool; 256]`
- Wire `cold_path_active_builder_collision: Vec<bool>`
- Prometheus `xpf_userspace_worker_cold_path_builder_collision_v3{...}`

A non-zero `builder_collision` means the snapshot builder produced two
distinct `(from, to)` keys mapping to the same slot — should never happen with the
direct map. Treated as a hard error in operator dashboards.

---

## §3 Wire-protocol contract change

### §3.1 Versioning

`cold_path_layout_version: u32 = 3`. Go side switches:
- v=0/1 → emit pre-#1635 v1 boundaries (24 buckets × 16 slots).
- v=2 → no-op; v2 never shipped (this PR jumps direct from v1 to v3).
- v=3 → emit v3 boundaries + zone labels + sparse encoding.
- unknown → refuse + warn.

### §3.2 Forward/backward compat

| Rust | Go  | Outcome                                                                   |
|------|-----|---------------------------------------------------------------------------|
| v1   | v1  | Identical to pre-#1635 master.                                            |
| v1   | v3  | v3 Go sees `cold_path_layout_version == 0`, emits v1-correct boundaries.  |
| v3   | v1  | v1 Go ignores `cold_path_layout_version` and the new sparse field names; **no cold-path metrics emitted** (v1 Go reads the old field names which are now zero-length → skip). This is the safe fallback per `feedback_wire_protocol_both_sides`. |
| v3   | v3  | Full v3 emission with zone labels.                                        |

The (v3 Rust, v1 Go) row is now safe-by-construction because the v1 wire field names
(`cold_path_hist`, `cold_path_samples`, etc.) are **emitted as empty arrays** by v3
Rust. The new fields (`cold_path_active_*`) are unknown to v1 Go and silently
ignored. Result: v1 Go sees no cold-path data, emits nothing. **No structurally-wrong
data** — the v2 plan's worst-case scenario is eliminated.

---

## §4 Implementation seams (in dependency order)

### §4.1 `userspace-dp/src/afxdp/cold_path_hist.rs`

- Const `POLICY_COLD_PATH_HIST_BUCKETS = 48` (was 24).
- Const `POLICY_COLD_PATH_ZONE_PAIR_SLOTS = 256` (was 16).
- `bucket_index_for_ns_48` replaces `bucket_index_for_ns_24`.
- `splitmix64` + `zone_pair_slot` deleted (no longer used).
- `lookup_slot(map: &ColdPathSlotMap, from: u16, to: u16) -> Option<u8>`.
- `ColdPathSlotMap` struct as defined in §2.3.
- `record_sample(slot: u8, delta_ns: u64)` — slot precomputed by caller.
- `record_sample_with_collision_check(slot: u8, expected_key: u64, delta_ns: u64)` —
  asserts the caller's `(from, to)` matches the slot's `first_key`; sets
  `builder_collision = true` on mismatch.
- Renamed field `alias_seen` → `builder_collision` throughout.
- `WorkerColdPathAtomics::zero_slot(idx: u8)` — atomic zero-out per §2.4.
- `WorkerColdPathCounters::zero_slot(idx: usize)` — local zero-out.
- All offset_of! tests updated for new sizes.

### §4.2 `userspace-dp/src/afxdp/types/forwarding.rs`

```rust
pub(in crate::afxdp) cold_path_slot_map: Arc<ColdPathSlotMap>,
```

`Arc<ColdPathSlotMap>` is small (1024 + ~2 KB inverse). Arc-swap via the existing
`ForwardingState` ArcSwap pattern.

### §4.3 `userspace-dp/src/afxdp/forwarding_build/mod.rs`

At build time:
1. Walk policy zone-pair keys; collect into `BTreeSet<(u16, u16)>` for stable order.
2. Diff against `previous: Option<&ForwardingState>`. For retained pairs: copy
   slot assignment. For removed pairs: mark slot free. For new pairs: take lowest
   free slot index.
3. Cap at 256. Set `overflow_active = true` if more.
4. Return `(new_slot_map: Arc<ColdPathSlotMap>, slots_to_zero: SmallVec<u8>)`.
5. Caller stashes `slots_to_zero` on the next `ForwardingState` so workers
   can consume it.

### §4.4 `userspace-dp/src/afxdp/poll_descriptor/mod.rs`

Hot path:
```rust
let Some(slot) = crate::afxdp::cold_path_hist::lookup_slot(
    &worker_ctx.forwarding.cold_path_slot_map, from_zone_id, to_zone_id
) else {
    // Unmapped (overflow or zone_id ≥ 32); skip the sample.
};
binding.cold_path.record_sample(slot, delta_ns);
```

### §4.5 `userspace-dp/src/afxdp/coordinator/status.rs`

Build the sparse encoding from the per-worker merged accumulator:

```rust
let mut active_slot_ids = Vec::new();
let mut active_zone_from = Vec::new();
let mut active_zone_to = Vec::new();
let mut active_samples = Vec::new();
let mut active_sum_ns = Vec::new();
let mut active_buckets = Vec::new();
let mut active_builder_collision = Vec::new();
for slot in 0..POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
    if cold.samples[slot] == 0 { continue; }
    let Some((from, to)) = slot_map.inverse[slot] else { continue; };
    active_slot_ids.push(slot as u8);
    active_zone_from.push(from);
    active_zone_to.push(to);
    active_samples.push(cold.samples[slot]);
    active_sum_ns.push(cold.sum_ns[slot]);
    active_buckets.push(cold.buckets[slot].to_vec());
    active_builder_collision.push(cold.builder_collision[slot]);
}
```

### §4.6 `userspace-dp/src/protocol/binding.rs`

Replace v1 dense Vec fields (`cold_path_hist`, `cold_path_sum_ns`, etc.) with v3
sparse Vec fields (`cold_path_active_*`). Keep v1 fields emitting as empty for
forward-compat with v1 Go.

### §4.7 `pkg/dataplane/userspace/protocol.go`

Mirror the sparse fields. Add `ColdPathLayoutVersion uint32` and the seven
`ColdPathActive*` fields.

### §4.8 `pkg/api/metrics_descriptors.go` + `metrics_userspace.go`

`emitWorkerColdPath` branches on `w.ColdPathLayoutVersion`:
- 0 or 1 → old `emitColdPathV1` path (existing, unchanged).
- 3 → new `emitColdPathV3` path: iterate the sparse arrays, emit per-active-slot
  series with `from_zone` / `to_zone` labels resolved from the
  `ColdPathActiveZoneFrom` / `ColdPathActiveZoneTo` indices through the snapshot's
  zone-name table.
- other → emit `cold_path_layout_version_unknown_total` increment + warn.

`bucketLeV3(idx int) string` returns:
- `idx < 32` → `strconv.FormatUint(uint64((idx+1)*16-1), 10)` (linear, 15, 31, ..., 511).
- `32 ≤ idx ≤ 46` → `strconv.FormatUint((uint64(1)<<uint(10+idx-32))-1, 10)` (exp, 1023, 2047, ...).
- `idx ≥ 47` → `"+Inf"`.

---

## §5 Test plan

### §5.1 Cargo test suite

- All `cold_path_hist::tests::*` updated for new bucket count + slot count.
- `bucket_index_for_ns_48_linear_band`: `ns ∈ {0, 15, 16, 31, 511}` → expected idx.
- `bucket_index_for_ns_48_pivots_at_512`: `bucket_index_for_ns_48(511) == 31` AND
  `bucket_index_for_ns_48(512) == 32`.
- `bucket_index_for_ns_48_exponential_band`: `ns=1024 → 33`, `ns=2048 → 34`, ...,
  `ns=2^23 → 46`.
- `bucket_index_for_ns_48_saturates`: `ns ≥ 2^24 → 47`.
- `bucket_layout_resolves_low_end_within_2x`: for sample ns ∈ {50, 75, 100, 125,
  150, 1000, 5000, 50000}, assert `abs(reported - truth) / truth ≤ 1.0`.
- `direct_slot_map_assigns_sequential`: build for 5 pairs, slots `{0,1,2,3,4}`.
- `direct_slot_map_no_collisions_under_256_pairs`: build for 256 pairs; verify
  unique slot 1:1.
- `direct_slot_map_overflow_at_257_pairs`: 257th returns `None` + overflow_active.
- `direct_slot_map_immediate_reuse_after_removal_zeros_atomics`: build A with
  pairs `{(1,2),(3,4)}`; record samples; build B with `{(1,2),(5,6)}` (drop 3,4
  add 5,6); verify (3,4)'s old slot is reassigned to (5,6) AND the atomic
  counters/buckets for that slot are zeroed.
- `lookup_slot_returns_none_for_zone_id_ge_32`: pair with `from=33` → None.
- `lookup_slot_returns_none_for_unmapped_pair`: pair not in map → None.
- `record_sample_via_slot_dispatches_correctly`: end-to-end record/snapshot.
- `builder_collision_set_on_key_mismatch`: directly poke slot's first_key, record
  with mismatched key, assert builder_collision flips.

Run 5/5 flake check.

### §5.2 Go test suite

- `pkg/api/metrics_cold_path_test.go` updated for v3 metrics + sparse path.
- `metrics_userspace_layout_version_1_emits_v1`: synthetic v1 status (no v3
  fields) → v1-suffixed metrics.
- `metrics_userspace_layout_version_3_emits_v3_with_zone_labels`: synthetic v3
  status (sparse active arrays) → v3 metrics + zone labels.
- `metrics_userspace_layout_version_unknown_emits_warning`: synthetic v=99 →
  no v1/v3 metrics; warning gauge increments.
- `metrics_userspace_v3_sparse_emits_only_active_slots`: 12 active slots out of
  256 → 12 series per family, not 256.

### §5.3 Smoke matrix (loss userspace cluster)

Pass A (CoS-off): v4 + v6 × push + reverse × multi-stream `-P 12`.
Pass B (CoS-on): same matrix at full per-class load.

Drop tolerance: zero-drop per SKILL.md.

### §5.4 HA failover

`make test-failover`.

### §5.5 Verification harness (cold-path accuracy)

New `userspace-dp/tests/cold_path_accuracy.rs` integration test gated on
`--features cold-path-bench`:

- Drives the real `bucket_index_for_ns_48` path AND `record_sample` AND
  `WorkerColdPathAtomics::snapshot` (AGY-via-SMR-N2 finding: not a unit-test mock).
- Mocks the TSC counter via a feature-gated injection point so synthetic latencies
  are deterministic.
- For each true latency in {50, 75, 100, 125, 150, 1000, 5000, 50000} ns, record
  1000 samples and assert reported cumulative-midpoint p50 ≤ 2× off truth.

---

## §6 Out of scope

- `userspace-dp/src/afxdp/cos/queue_service/` (#1630 in flight).
- `userspace-dp/src/afxdp/cos/` broader.
- `userspace-dp/src/policy/`.
- `test/incus/`.
- `pkg/cluster/`.

---

## §7 Open questions for plan-review

1. **Bucket layout pivot at 512 ns vs 1024 ns** — AGY r1 [1.1] proposed 512 to halve
   bucket count to 48. v3 takes the proposal. Reviewers: agree, or does the
   600-1000 ns sub-range need higher resolution?

2. **Slot capacity 256 vs 128 vs 512** — v3 picks 256 (AGY [1.9]). Memory cost is
   bounded by sparse serialization, so 512 is also viable. Reviewers: is 256 the
   right cap, or should it be 512 / configurable?

3. **Sparse wire encoding** — v3's `cold_path_active_*` parallel arrays. Reviewers:
   should we use a single `Vec<ColdPathSlotData>` of structs instead? Saves wire
   bytes via better serde layout but harder to read on the Go side.

4. **Per-slot reuse atomic zero-out** — v3 zeros the slot atomic on reassignment
   in the WORKER, not the control plane. The control plane only stashes
   `slots_to_zero` for the worker to consume on its next tick. Reviewers: is the
   ordering safe under HA failover (where multiple snapshots can apply rapidly)?

5. **32×32 flat lookup table** — v3 uses `[u8; 1024]` indexed by
   `(from & 0x1F, to & 0x1F)`. Reviewers: should we instead use the full 16-bit
   range with a `FastMap<u32, u8>` and accept the hashmap cost (~5-10 ns)?
   1024-byte L1d-resident table is hot, but zone-ids > 32 are silently dropped.

---

## §X Consumer success criteria (the #1622 gate — pinned)

This redesign is **only** worth doing if #1622 can reopen against it:

- [ ] **10-rule cell publishes a meaningful p50** — true 100 ns p50 reads as ≤ 16 ns
  off (≤16% error), not 412% (v1's 512 ns floor).
- [ ] **8+ active zone-pairs publishes meaningful per-zone-pair rows** — direct map
  ⇒ zero builder_collision events ⇒ all 8 rows publish.
- [ ] **Aggregate row replaced with per-zone-pair rows** — labels carry
  disambiguation; aggregating is operator's PromQL choice.
- [ ] **Tables A1/A2/B1/B2 ship populated with non-aliased numbers**.

Pinned commitment: this PR's wire surface is **per-zone-pair only**. If #1622 wants
aggregate emission, #1622's plan proposes it; not this PR's surface.

---

## §Z Validation summary

- cargo build + test clean.
- go build + test clean.
- 5/5 flake check on histogram tests.
- Smoke Pass A + Pass B clean.
- `make test-failover` clean.
- Verification harness shows ≤2× per-bucket error at 10-rule (~100 ns) target AND
  1M-rule (~5000-50000 ns) target.

After this lands → #1622 reopens with the redesigned foundation in place.
