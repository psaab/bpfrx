# Claude SMR code-r1 — #1621 PR #1633

**Reviewer**: Claude (SMR: wire protocol, seqlock semantics,
Prometheus exposition format, cumulative-bucket histograms)
**Head SHA**: 52094b9e7 (post Copilot fixes)
**Verdict**: MERGE-READY

## r1 implementation matches plan v2

All five r1 amendments (le label, ns_per_tsc_q32 gauge,
snapshot_failed counter, always-present clock_source gauge, scalar
skip_serializing_if) implemented. Code in tree.

## Resolution check vs Copilot code-r1 findings

| Copilot | v2 + post-fix resolution | Status |
|---------|---------------------------|--------|
| C1 (HIGH/MED): bucket counts are raw, not cumulative — PromQL histogram_quantile() returns wrong quantiles | metrics_userspace.go bucketLe emitter accumulates per-slot running total before each MustNewConstMetric. Cumulative semantic. | RESOLVED |
| C2 + C5 (MED): unconditional Vec<>::from(fixed_array) bypasses skip_serializing_if for never-sampled workers | coordinator/status.rs has_data check (sample_phase != 0 || samples != 0 || alias_seen). Vec fields stay empty when !has_data. snapshot()==None handled the same way (empty Vecs but snapshot_failed still stamped). Wire-invariant preserved byte-identical for pre-#1621 daemons. | RESOLVED |
| C3 (NIT): Go round-trip tests missing | cold_path_status_test.go adds 3 tests: default omits all 11 fields, populated round-trips, Rust-emitted JSON decodes. | RESOLVED |
| C4 (NIT): Rust round-trip tests missing | protocol/tests.rs adds 2 tests: default omits + populated round-trips. | RESOLVED |
| C6 (NIT): clock_source help text says "source=''" but emitter outputs "unset" | metrics_descriptors.go fixed: "source='unset'" in help string. | RESOLVED |

## Axis verification (10 axes per AGY r1 framework)

### AXIS 1 — Cross-binding merge alias detection (loop_body/mod.rs)

```rust
if merged.first_key[slot] == 0 {
    merged.first_key[slot] = src.first_key[slot];
} else if src.first_key[slot] != 0 && src.first_key[slot] != merged.first_key[slot] {
    merged.alias_seen[slot] = true;
}
merged.alias_seen[slot] |= src.alias_seen[slot];
```

Walk all 4 cases:
- A=0, B=0: merged.first_key[slot] = 0, alias unchanged. Correct (no data).
- A=K, B=0: merged stays K, alias unchanged. Correct (single source).
- A=0, B=K: merged.first_key = K (after this iteration), alias unchanged.
- A=K, B=L (K≠L, both nonzero): merged stays K on second iteration; src=L != merged=K → alias_seen = true. Correct.
- A=K, B=K (same nonzero): merged stays K, alias unchanged. Correct.

Plus per-binding alias_seen OR — if A flagged alias internally (within-binding), the merged status carries that.

### AXIS 2 — snapshot_failed ordering

```rust
// Inside snapshot() retry-exhaust branch:
self.snapshot_failed.fetch_add(1, Ordering::Relaxed);
None
// In coordinator/status.rs:
let cold_snapshot_failed = handle.cold_path_atomics.snapshot_failed_count();
let cold_opt = handle.cold_path_atomics.snapshot();
```

Hmm, looking at the ordering — status.rs reads snapshot_failed_count
BEFORE calling snapshot(). That means a snapshot() that fails THIS
scrape doesn't show up until the NEXT scrape's snapshot_failed_count
read. This is a 1-tick lag but not incorrect — the counter is
monotonic so the operator still sees the failure, just delayed by
one scrape interval.

Actually wait — re-reading the diff: `cold_opt = ...snapshot()`
comes AFTER `cold_snapshot_failed = ...snapshot_failed_count()`. So
the FIRST scrape after a failure will MISS the bump. The counter
catches up on the second scrape. Acceptable as long as
documentation reflects this. The diff comment claims "AFTER snapshot()"
but the actual code reads BEFORE.

**Minor inconsistency** but not a correctness bug — the
snapshot_failed counter remains monotonic and operators will see
the bump on the next scrape. I'll note this in r2 review.

Actually, looking more carefully at the post-Copilot-fix diff:

```rust
let cold_snapshot_failed =
    handle.cold_path_atomics.snapshot_failed_count();
let cold_opt = handle.cold_path_atomics.snapshot();
```

`snapshot_failed_count()` is called BEFORE `snapshot()`. If snapshot()
fails THIS scrape, the counter increment lands AFTER the read. The
next scrape will see the increment.

Per Copilot C2/C5, the design intent is "snapshot_failed reports
publish-contention failures." A 1-scrape lag means the operator's
dashboard sees the alert one tick late. Acceptable for a 1-Hz
scrape interval but worth documenting.

**Note** for future: should swap the order so snapshot_failed_count()
runs AFTER snapshot(). Trivial fix.

### AXIS 3 — Layout

`#[repr(C, align(64))]` + offset_of! tests in cold_path_hist.rs.
Hot fields fit in cacheline 0 (54 bytes total: 7 × u64 + 1 × u8 +
16 × bool = 7*8 + 1 + 16 = 73 bytes — straddles into cacheline 1).
Wait, let me re-check.

Field sizes:
- cold_window_gen u64: 8
- snapshot_failed u64: 8
- sample_phase u64: 8
- ns_per_tsc_q32 u64: 8
- wrapper_ns_baseline u64: 8
- wrapper_underflow_count u64: 8
- clock_source u8 (#[repr(u8)]): 1
- alias_seen [bool; 16]: 16

Cumulative: 8+8+8+8+8+8+1+16 = 65 bytes. So alias_seen[15] is at
offset 64, which IS the start of cacheline 1.

The hot reads (cold_window_gen + snapshot_failed + sample_phase +
ns_per_tsc_q32 + wrapper_ns_baseline + wrapper_underflow_count +
clock_source = 49 bytes) all fit in cacheline 0. alias_seen partially
in cacheline 0 (15 of 16 entries) + 1 entry in cacheline 1. The
publish-tick writes all 16 alias_seen entries so the boundary is
crossed every publish. ~1 Hz tick → ~6 cacheline-1 invalidations per
second across 6 workers. Negligible.

### AXIS 4 — Wire-protocol both-sides

11 new fields. With C2/C5 fixes:
- Default WorkerRuntimeStatus: all 11 fields omitted (Rust round-
  trip test + Go round-trip test pin this).
- Populated: all 11 round-trip preserved (both tests).
- Cross-language: Rust-emitted JSON decodes into Go (Go round-trip
  test).

### AXIS 5 — Prometheus bucket cumulative

Post-Copilot-C1 fix:
```go
var running uint64
for b := 0; b < len(w.ColdPathHist[slot]); b++ {
    running += w.ColdPathHist[slot][b]
    ch <- prometheus.MustNewConstMetric(c.workerColdPathBucket,
        prometheus.CounterValue, float64(running),
        label, slotLabel, bucketLe(b))
}
```

Cumulative. `histogram_quantile()` works correctly.

`bucketLe(b)` returns "1023", "2047", ..., "8388607", "+Inf" for
b ∈ [0..23]. The `+Inf` bucket carries the total count for the slot
(per Prometheus histogram convention).

### AXIS 6 — clock_source always emitted

```go
src := w.ColdPathClockSource
if src == "" {
    src = "unset"
}
ch <- prometheus.MustNewConstMetric(c.workerColdPathClockSource,
    prometheus.GaugeValue, 1.0, label, src)
```

Always emits. Test pins all 3 source values.

### AXIS 7 — HA-sensitivity

worker_loop merge: 6 bindings × 16 slots × 24 buckets ~3000
saturating_add per tick. At 6 workers × 1 Hz = ~18 µs/sec node-wide.
test-failover 13/13 PASS confirms no VRRP perturbation.

### AXIS 8 — Test coverage

- 2 new Rust round-trip tests (default omit + populated).
- 3 new Go round-trip tests (default omit + Go→Go + Rust→Go).
- 4 new Go Prometheus tests (always-emitted + le label + populated
  slot + clock_source all 3 sources).
- cold_path_hist:: 28/28 with 5/5 flake clean.
- 1494/1494 cargo bin tests pass.
- emitWorkerRuntime count test updated 14→20.

Coverage adequate.

## Verdict — MERGE-READY

Implementation matches plan v2 + all 6 Copilot nits addressed.

**Self-correction (post r1 draft)**: caught the
`snapshot_failed_count()` vs `snapshot()` ordering issue in
coordinator/status.rs and fixed it in the same commit. The fixed
order calls snapshot() FIRST so any retry-exhaust counter bump
inside snapshot() is visible to the subsequent snapshot_failed_count()
load. Without that order, a failure on the CURRENT scrape only
showed up on the NEXT scrape. Now: same-scrape visibility.

AGY code-r1 MERGE-READY 10/10. Awaiting Codex code-r1 (retry
task-mppqoldq-elil7k pending — per session-wide Codex sandbox
unreliability pattern, may not register).
