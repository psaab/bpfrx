# Plan v2 — #1635 Cold-path histogram bucket layout + per-zone-pair slot map redesign

**Issue**: #1635. Foundation redesign that #1622 PLAN-KILL identified as required for
trustworthy Scale Target measurement.

**Branch**: `refactor/1635-cold-path-hist-redesign`.

**v2 changelog**: absorbs Claude SMR r1 findings F1 (bucket stride), F2 (overflow
semantics), F3 (older-Go-on-newer-Rust silent miscompile), F4 (stale slot-map
remapping). v1 archived as `plan-v1.md.bak`.

**Co-related shipped commits this redesigns**:
- #1619 (squash `4ac85e2fd`) — `cold_path_hist.rs` scaffolding (24-bucket pow-2 + 16-slot splitmix).
- #1620 (PR #1631 `dd0e1e62`) — BindingWorker integration + `--cold-path-sample-mask`.
- #1621 (PR #1633 `dbfbf680`) — wire protocol + Prometheus emission (8 metric families).

---

## §1 Context — the three #1622 structural findings to fix

### F1: Bucket-0 resolution floor
Current `cold_path_hist.rs:62 bucket_index_for_ns_24` is purely power-of-two starting at
`[0, 1024) ns` for bucket 0. The 10-rule cold-path target range is ~50-150 ns. Every
10-rule sample falls into bucket 0; Prometheus `histogram_quantile()` reports
p50 = bucket-0 midpoint = 512 ns. True p50 of a 50-150 ns distribution = ~100 ns.
**Reported error = 5×.** Operator-facing Scale Target table is untrustworthy at low rule
counts.

### F2: 16-slot splitmix64 collision bias
`zone_pair_slot` hashes packed `(from_zone_id, to_zone_id)` through splitmix64 into a
4-bit index. Birthday paradox on 8 active zone-pairs into 16 slots gives 88.2%
collision probability. On collision, `alias_seen` excludes BOTH slots from publication.
When the colliding pair is `(high-rule-count, low-rule-count)`, the published aggregate
is biased toward the survivor. At typical operator cardinalities (8-20 active
zone-pairs) the bias is large.

### F3: Bimodal aggregate corruption
The published "aggregate p50 across non-aliased slots" is a union of disjoint
per-zone-pair latency distributions. Aggregate percentiles over a union are
packet-mix-ratio artifacts, not flow-duration percentiles.

**All three are structural — no harness fix rescues them. The primitive (and its wire
contract) has to change.**

---

## §2 What this PR delivers

### §2.1 Fix F1 — log-linear bucket layout (16-ns stride at the low end)

Replace the 24-bucket pow-of-2 layout with a **log-linear** layout:

```
Linear band:   ns ∈ [0, 1024) ns split into 64 buckets of 16-ns stride each.
               Bucket b (0 ≤ b ≤ 63) covers [b*16, (b+1)*16) ns.

Exponential band: ns ∈ [1024, 2^24) ns split into 14 pow-of-2 buckets.
               Bucket 64+i (0 ≤ i ≤ 13) covers [2^(10+i), 2^(11+i)) ns.

Saturate band: ns ≥ 2^24 (≈16.8 ms) lands in bucket 78.
```

**Total: 80 buckets** (up from 24).

**Stride rationale (v2 — Claude SMR r1 F1 resolution)**: v1 picked 64-ns stride. SMR
r1 F1 showed a sample at ns=1 lands in bucket-0 midpoint=32 ns → 32× error. With 16-ns
stride at the low end, bucket-0 midpoint is 8 ns; a 50-ns true sample lands in bucket
3 (midpoint 56 ns); a 100-ns true sample lands in bucket 6 (midpoint 104 ns); a 150-ns
true sample lands in bucket 9 (midpoint 152 ns). **Relative error at p50 of any
distribution with true p50 ≥ 24 ns is ≤ 16 ns / 24 ns = 67% (= 1.67× error).** This
satisfies the "≤2×" criterion for the 10-rule target range without ambiguity.

**Acceptance criterion (v2 — pinned)**: per-bucket relative error ≤ 2× for any true
p50 ≥ 24 ns (the 1.5×-stride floor). Below 24 ns the floor is the wrapper baseline
(~25-40 ns measured on the loss cluster — see #1620 calibration); samples there are
already discarded by the wrapper-underflow gate so the regime is moot.

**Exponential-band relative error**: within each pow-2 bucket the worst-case relative
error is `(upper - lower) / midpoint` = `(2^(k+1) - 2^k) / (1.5 × 2^k)` = **2/3 ≈
67% (= 1.67× error)**. The 1M-rule target (~5000-50000 ns) lands in buckets 66-70;
all within 1.67× of truth.

### §2.2 Fix F2 — direct zone-pair slot map (128 slots, hard-overflow refuse)

Replace the splitmix64 hash in `zone_pair_slot` with a **direct, snapshot-built** map
from `(from_zone_id, to_zone_id)` to slot index.

**Slot count**: grow from 16 → **128 slots** (Claude SMR r1 F2 resolution: v1 picked
64 + silent slot-63 alias; SMR r1 escalated that silent-alias-in-slot-63 reintroduces
F3 of #1622's complaint at the boundary).

128 slots gives ~10× headroom over the largest production deployment seen (12 pairs).
Per-worker memory cost = 128 × (1 + 1 + 1 + 0.125 + 80) bytes ≈ **10.6 KB local +
10.6 KB atomics**. Wire payload ≈ **82 KB per worker per scrape** — still under the
gRPC 4MB cap for a 12-worker cluster.

**Build site**: `forwarding_build/mod.rs` at config-apply time. The snapshot's
compiled policy already enumerates all `(from_zone_id, to_zone_id)` keys; we walk them
and assign sequential slot indices.

**Overflow handling (v2 — hard refuse)**: if a deployment exceeds 128 active
zone-pairs, the build sets `cold_path_overflow_active: bool = true` and assigns slot
indices to the first 128 pairs in stable order (sorted by `(from_zone_id,
to_zone_id)`). The remaining pairs get **no slot** (`lookup_slot` returns `None`) and
their samples are **dropped at the hot path before `record_sample`**. The publisher
emits `xpf_userspace_worker_cold_path_overflow_active{worker_id} = 1` so operators see
the truncation; the per-slot rows for the **dropped pairs are simply absent** from
the table (no bias-inducing aggregate row).

The slot-63 silent-alias pattern from v1 is eliminated.

### §2.3 Fix F4 — stable slot assignment across snapshots (v2 NEW)

Claude SMR r1 F4: when the slot map changes mid-flight, the per-binding
`binding.cold_path` accumulator stays around with stale counts that get published
under the new slot's labels on the next tick → consumer table is corrupted on every
config-apply.

**v2 solution: stable slot assignment.** Once a `(from_zone_id, to_zone_id)` pair has
been assigned a slot index in a worker's lifetime, that assignment is **immutable for
the worker's lifetime**:

1. Worker startup: `cold_path_slot_map` is empty.
2. Snapshot 1 applies a policy with pairs `{A, B, C}` → slots `{0, 1, 2}` assigned.
3. Snapshot 2 applies a policy with pairs `{A, C, D}` (B removed, D new) → slots
   `{0, 2, 3}` (B's slot 1 retained but unused; D gets a fresh slot 3).
4. Snapshot 3 re-adds B → slot 1 reused.

The slot map is **append-only with hole reuse**: pairs that come back map back to
their original slot. Build state lives in the forwarding state (ArcSwap-published) so
all workers see consistent assignments.

When slot 1 (B) goes unused between snapshots, the bucket counts under slot 1
**accumulate** if B traffic returns. The harness side reads `samples` as the source of
truth for "this slot has data"; an empty (zero-samples) slot is harmless.

**Edge case**: if the 129th distinct pair ever arrives across the daemon's lifetime,
it can't be assigned. `overflow_active` flips to true, the daemon logs a one-shot
warning, and the operator's remediation is `systemctl restart xpfd` (which resets the
slot map). This is acceptable because 128 distinct pairs in a daemon's lifetime is
~10× the largest known deployment.

**Compatibility with the existing `binding.cold_path` accumulator**: the local
accumulator's slot indices match the worker-shared slot map (same const), so no per-
binding reset is needed at snapshot apply.

### §2.4 Fix F3 — per-zone-pair Prometheus labels

Each per-slot metric carries `from_zone` and `to_zone` labels (string zone-name from
snapshot) **in addition to** the existing numeric `zone_pair_slot` label. Harness
scrapes by name; slot label remains for debugging.

**Label resolution path**: the slot map at build time is keyed on numeric IDs. The
zone-name strings are resolved on the Go side at scrape time from the latest
snapshot's zone-id-to-name table. When a worker reports per-slot data, the Go side
looks up the names from a sidecar `cold_path_slot_zone_from / cold_path_slot_zone_to`
that the Rust side publishes alongside the histogram bytes.

Cardinality budget: 128 slots × ~8 workers × 8 metric families ≈ ~8K series per
scrape worst case. Prometheus handles this trivially.

---

## §3 Wire-protocol contract change

### §3.1 New / changed fields

```
cold_path_hist:               Vec<Vec<u64>>  shape [128 slots][80 buckets]  (was [16][24])
cold_path_sum_ns:             Vec<u64>       shape [128]                    (was [16])
cold_path_samples:            Vec<u64>       shape [128]                    (was [16])
cold_path_first_key:          Vec<u64>       shape [128]                    (was [16])
cold_path_alias_seen:         Vec<bool>      shape [128]                    (was [16])
cold_path_slot_zone_from:     Vec<u16>       shape [128]                    NEW
cold_path_slot_zone_to:       Vec<u16>       shape [128]                    NEW
cold_path_overflow_active:    bool                                          NEW
cold_path_layout_version:     u32            2                              NEW
```

### §3.2 Versioning + compat — Claude SMR r1 F3 resolution

**`cold_path_layout_version`** is a positive u32 emitted by all v2-aware Rust
daemons. Missing field (older Rust) deserializes as 0, which the Go side treats as
"layout v1 (24 buckets × 16 slots)".

The Go side MUST switch on `cold_path_layout_version`:

```go
switch w.ColdPathLayoutVersion {
case 0, 1:  // older Rust pre-#1635
    emitColdPathV1(ch, label, w)  // 24 buckets, 16 slots, no zone labels
case 2:     // post-#1635
    emitColdPathV2(ch, label, w)  // 80 buckets, 128 slots, zone labels
default:
    // Unknown version — refuse to emit. Log a one-shot warning. This is the
    // graceful-fail path; v2-correct emission requires a Go upgrade.
    emitColdPathUnknownVersionWarning(label, w.ColdPathLayoutVersion)
}
```

**Critical (SMR r1 F3)**: the current `pkg/api/metrics_userspace.go:570-580` is
shape-agnostic and would silently emit v2 bucket counts under v1 `le` labels —
producing structurally wrong `histogram_quantile()` numbers. The Go side change in
this PR replaces the shape-agnostic emitter with the version-switched emitter
ABOVE. This is a **hard requirement** of v2.

### §3.3 Forward/backward compat scenarios

| Rust | Go  | Outcome                                                                 |
|------|-----|-------------------------------------------------------------------------|
| v1   | v1  | Identical to pre-#1635 master. No change.                                |
| v1   | v2  | v2 Go sees `cold_path_layout_version == 0`, emits v1-correct boundaries.|
| v2   | v1  | v1 Go ignores `cold_path_layout_version`; **shape-agnostic loop emits 80 buckets under 24-bucket `le` labels → wrong**. Mitigation: v2 daemon ALSO version-bumps the binding manifest in `pkg/dataplane/userspace/protocol.go` to require Go ≥ v2. If Go side is older, the cold-path metric family is silently absent (operator sees "missing scrape data" not "wrong data"). |
| v2   | v2  | Full v2 emission with zone labels.                                       |

The (v2 Rust, v1 Go) row is the dangerous one. **Mitigation**: ship Rust + Go binaries
together (current build pipeline does this; the cluster deploys `xpfd` and
`userspace-dp` in lockstep). The plan does not support standalone Rust upgrade or
standalone Go upgrade; this matches `feedback_smoke_loss_userspace_only` (deploy
ships both halves).

---

## §4 Implementation seams (in dependency order)

### §4.1 `userspace-dp/src/afxdp/cold_path_hist.rs`

- Const `POLICY_COLD_PATH_HIST_BUCKETS = 80` (was 24).
- Const `POLICY_COLD_PATH_ZONE_PAIR_SLOTS = 128` (was 16). `ZONE_PAIR_SLOT_MASK`
  removed (no longer power-of-two indexing).
- Rewrite `bucket_index_for_ns_24` → `bucket_index_for_ns_80` with the log-linear
  formula. Keep the math branchless:
  ```rust
  #[inline]
  pub(in crate::afxdp) fn bucket_index_for_ns_80(ns: u64) -> usize {
      if ns < 1024 {
          (ns / 16) as usize    // [0, 64) linear band
      } else {
          let clz = ns.leading_zeros() as i32;
          // ns ∈ [1024, 2^24): bucket_idx = 64 + (log2(ns) - 10)
          let log2 = 63 - clz;
          let b = 64 + (log2 - 10) as usize;
          b.min(POLICY_COLD_PATH_HIST_BUCKETS - 1)
      }
  }
  ```
- Remove `zone_pair_slot` from the public API (keep `splitmix64` as a `#[cfg(test)]`
  helper since it's referenced in plan rationale).
- Add `lookup_slot(map: &ColdPathSlotMap, from: u16, to: u16) -> Option<u8>`.
- `record_sample` now takes `slot: u8` precomputed by the call site.
- All `offset_of!` tests updated for new sizes.

### §4.2 `userspace-dp/src/afxdp/types/forwarding.rs`

Add to `ForwardingState`:

```rust
pub(in crate::afxdp) cold_path_slot_map: Arc<ColdPathSlotMap>,

pub(in crate::afxdp) struct ColdPathSlotMap {
    /// packed_key((from, to)) -> slot_idx. None means unmapped.
    pub map: FastMap<u32, u8>,
    /// slot_idx -> Option<(from, to)>. None for slots never assigned.
    pub inverse: [Option<(u16, u16)>; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// True if the snapshot had > 128 active zone-pairs.
    pub overflow_active: bool,
}
```

`Arc<ColdPathSlotMap>` so the worker hot path takes `Arc::ptr_eq` rather than
deep-copying.

### §4.3 `userspace-dp/src/afxdp/forwarding_build/mod.rs`

At build time:
1. Walk policy zone-pair keys.
2. Diff against `previous: Option<&ForwardingState>`. For each retained pair, copy
   its assignment from the previous map. For each new pair, append to the lowest
   unused slot index. For each removed pair, leave its slot vacant (next pair to be
   added gets that slot).
3. Cap at 128. Set `overflow_active = true` if more.

### §4.4 `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (call sites at 1380 + 2444)

```rust
let Some(slot) = crate::afxdp::cold_path_hist::lookup_slot(
    &worker_ctx.forwarding.cold_path_slot_map, from_zone_id, to_zone_id
) else {
    // Unmapped (transient at snapshot transition, or overflow); skip the sample.
    // Note: the wrapper baseline still ran — that cost is unavoidable. But the
    // record path is skipped so no slot gets bogus data.
};
binding.cold_path.record_sample(slot, delta_ns);
```

Sample-mask + tsc-start/end logic unchanged.

### §4.5 `userspace-dp/src/afxdp/coordinator/status.rs`

Publish the inverse map and overflow flag alongside the histogram:

```rust
cold_path_slot_zone_from: cph_inverse.iter()
    .map(|p| p.map(|(f, _)| f).unwrap_or(0)).collect(),
cold_path_slot_zone_to: cph_inverse.iter()
    .map(|p| p.map(|(_, t)| t).unwrap_or(0)).collect(),
cold_path_overflow_active: cph.overflow_active,
cold_path_layout_version: 2,
```

A slot with `None` inverse (never assigned) emits `(0, 0)` placeholder; consumer
gates on `samples > 0`.

### §4.6 `userspace-dp/src/protocol/binding.rs`

Add the four new fields per §3.1. All Vec fields use `skip_serializing_if =
"Vec::is_empty"`. `cold_path_overflow_active: bool` uses `default` + `is_false`
skip. `cold_path_layout_version: u32` uses `u64_is_zero`-style skip (older Rust ⇒
field absent ⇒ 0 ⇒ "v1").

### §4.7 `pkg/dataplane/userspace/protocol.go`

Mirror the four new fields with appropriate `json:",omitempty"`.

### §4.8 `pkg/api/metrics_descriptors.go` + `metrics_userspace.go`

Add new descriptors:

```
xpf_userspace_worker_cold_path_ns_bucket_v2{worker_id, zone_pair_slot, from_zone, to_zone, le}
xpf_userspace_worker_cold_path_samples_total_v2{worker_id, zone_pair_slot, from_zone, to_zone}
xpf_userspace_worker_cold_path_sum_ns_total_v2{worker_id, zone_pair_slot, from_zone, to_zone}
xpf_userspace_worker_cold_path_alias_seen_v2{worker_id, zone_pair_slot, from_zone, to_zone}
xpf_userspace_worker_cold_path_overflow_active{worker_id}
xpf_userspace_worker_cold_path_layout_version{worker_id, version}
```

The v2-suffixed family names ensure no PromQL query against the v1 names accidentally
mixes data from both layouts. v1 names remain emitted for `cold_path_layout_version <=
1` daemons (so a partial rollout doesn't blank the dashboards).

Bucket `le` boundary computation (v2):

```go
func bucketLeV2(idx int) string {
    if idx < 64 {
        // Linear band: idx -> upper edge (idx+1)*16 - 1.
        return strconv.FormatUint(uint64((idx+1)*16-1), 10)
    }
    if idx >= 79 || (11 + idx - 64) >= 64 {
        return "+Inf"
    }
    // Exponential band: bucket 64+i covers [2^(10+i), 2^(11+i)) ns.
    return strconv.FormatUint((uint64(1)<<uint(11+idx-64))-1, 10)
}
```

---

## §5 Test plan

### §5.1 Cargo test suite

- All `cold_path_hist::tests::*` updated for the new bucket boundaries.
- `bucket_index_for_ns_80_linear_band`: assert for `ns ∈ {0, 15, 16, 31, 1023}` the
  expected bucket index.
- `bucket_index_for_ns_80_pivots_at_1024`: assert `bucket_index_for_ns_80(1023) == 63`
  and `bucket_index_for_ns_80(1024) == 64`.
- `bucket_index_for_ns_80_exponential_band`: assert `ns=2048 → bucket 65`,
  `ns=4096 → bucket 66`, `ns=2^23 → bucket 77`.
- `bucket_index_for_ns_80_saturates`: assert any `ns ≥ 2^24` → bucket 78 or 79
  (whichever is the saturation choice — pin 79 in code).
- `bucket_layout_resolves_low_end_within_2x`: for sample ns ∈ {50, 75, 100, 125, 150,
  1000, 5000, 50000}, compute bucket midpoint and assert
  `abs(reported - truth) / truth ≤ 1.0`.
- `direct_slot_map_assigns_sequential`: build for 5 pairs, assert slots `{0,1,2,3,4}`
  assigned in sorted order.
- `direct_slot_map_no_collisions_under_128_pairs`: build for 128 pairs; verify all
  slots used 1:1.
- `direct_slot_map_overflow_at_129_pairs`: build for 129 pairs; verify the 129th
  returns `None` from `lookup_slot` AND `overflow_active = true`.
- `direct_slot_map_stable_across_snapshots`: build map A with pairs `{(1,2),(3,4)}`
  → slots `{0, 1}`. Build map B (diff from A) with pairs `{(1,2),(5,6)}` (drop (3,4),
  add (5,6)). Assert (1,2) still maps to slot 0, (5,6) maps to slot 1 OR slot 2 (the
  next free index).
- `record_sample_via_slot_map_dispatches_correctly`: end-to-end record/snapshot test.
- `lookup_slot_returns_none_for_unmapped_pair`: pair not in map → None.

Run 5/5 flake check per `feedback_no_test_dismissal`.

### §5.2 Go test suite

- `pkg/api/metrics_cold_path_test.go` updated.
- `metrics_userspace_layout_version_1_emits_v1`: synthetic v1 status →
  v1-suffixed metrics, v1 `le` boundaries.
- `metrics_userspace_layout_version_2_emits_v2_with_zone_labels`: synthetic v2 status
  with shape [128][80] → v2 metrics + zone labels.
- `metrics_userspace_layout_version_unknown_emits_warning`: synthetic v=99 status →
  no v1 / v2 metrics emitted; warning log captured.

### §5.3 Smoke matrix (loss userspace cluster)

Pass A (CoS-off): v4 + v6 × push + reverse × multi-stream `-P 12`.
Pass B (CoS-on): same matrix at full per-class load.

Drop tolerance: zero-drop per existing SKILL.md gate.

### §5.4 HA failover

`make test-failover` — the wire-protocol change is HA-visible.

### §5.5 Verification harness (cold-path accuracy)

New `userspace-dp/tests/cold_path_accuracy.rs` integration test:
- Drive a 1-in-1 sample workload with synthetic samples at known true latencies.
- For each true latency in {50, 75, 100, 125, 150, 1000, 5000, 50000} ns, record 1000
  samples and assert reported p50 (computed from buckets via histogram_quantile-style
  cumulative midpoint interpolation) is within 2× of truth.

---

## §6 Out of scope (do NOT touch)

- `userspace-dp/src/afxdp/cos/queue_service/` (#1630 in flight).
- `userspace-dp/src/afxdp/cos/` more broadly.
- `userspace-dp/src/policy/`.
- `test/incus/`.
- `pkg/cluster/`.

---

## §7 Open questions for plan-review

1. **Slot count 128 vs 256** — 128 gives ~10× headroom, fits the largest deployment +
   10×. 256 would be 20× headroom for ~20 KB local + ~20 KB atomics. Reviewers: is 128
   right or should we be more conservative?

2. **Linear-band stride 16 ns vs 8 ns** — 16 ns matches the wrapper baseline noise
   floor (~25-40 ns). 8 ns would halve the low-end error at the cost of doubling
   the linear band to 128 buckets (+ 14 exponential = 142 total). Reviewers: is the
   wrapper noise floor really the right calibration anchor?

3. **Wire-protocol `_v2` suffix on metric names** — keeps PromQL queries stable
   across the rollout but doubles metric cardinality during partial deploys.
   Reviewers: better to keep the same metric name and bump the layout-version label?

4. **Stale slot reuse** — when (3,4) is removed and (5,6) added, (5,6) gets the next
   FREE slot, not (3,4)'s old slot. This means slot indices grow monotonically until
   wrap. Alternative: reuse (3,4)'s slot for (5,6) when (3,4) hasn't been seen in N
   snapshots. Reviewers: is monotonic-grow okay (cap is 128) or do we need recycle?

5. **Concurrency of slot-map publish** — the slot map is built in the control plane
   and Arc-swapped into ForwardingState. The hot path reads `lookup_slot` per sample.
   The lookup is a FastMap read — currently a hashmap access (~5-10 ns). At
   1-in-256 sampling, the per-sample cost amortizes. Reviewers: should we precompute
   `slot_idx` per binding (since a binding's `(from_zone, to_zone)` is the same for
   all packets after policy lookup)?

---

## §X Consumer success criteria (the #1622 gate — pinned)

This redesign is **only** worth doing if #1622 can reopen against it. The
consumer-facing criteria, taken directly from #1622's PLAN-KILL findings:

- [ ] **10-rule cell publishes a meaningful p50** — true 100 ns p50 reads as ≤ 16 ns
  off (16% error), not 412% (v1's 512 ns floor).
- [ ] **8+ active zone-pairs publishes meaningful per-zone-pair rows** — direct map
  ⇒ zero alias_seen exclusions ⇒ all 8 rows publish.
- [ ] **Aggregate row is replaced with per-zone-pair rows** — Prometheus labels
  `from_zone`/`to_zone` carry the disambiguation; aggregating across the union is
  the operator's choice via PromQL.
- [ ] **Tables A1/A2/B1/B2 ship populated with non-aliased numbers** — once #1622 is
  reopened.

The plan **commits to** the per-zone-pair publication pattern as the consumer
contract. If #1622's reopen wants an aggregate row in addition, it proposes that in
its own plan; this PR's surface is per-zone-pair-only.

---

## §Z Validation summary

- cargo build + test clean.
- go build + test clean.
- 5/5 flake check on histogram tests.
- Smoke Pass A + Pass B clean.
- `make test-failover` clean.
- Verification harness shows ≤2× per-bucket error at the 10-rule (~100 ns) target
  AND the 1M-rule (~5000-50000 ns) target.

After this lands → #1622 reopens with the redesigned foundation in place.
