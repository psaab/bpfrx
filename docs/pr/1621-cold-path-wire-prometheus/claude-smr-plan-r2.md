# Claude SMR plan-r2 — #1621 cold-path wire + Prometheus

**Reviewer**: Claude SMR
**Plan**: v2 (resolution map at top of plan.md)
**Verdict**: PLAN-READY

## Resolution map vs r1 findings

| r1 finding | v2 resolution | Status |
|------------|---------------|--------|
| Codex F1 (omitempty + fixed array) | v1 already used Vec<Vec<u64>> not [[u64;24];16]; Codex misread the shape. v2 explicit. | RESOLVED |
| Codex F2 + Claude SMR F1 (cross-binding merge contract) | v1 pseudocode correctly handles nonzero-mismatch alias. v2 adds 4-case test matrix in §4.2. Code matches. | RESOLVED |
| Codex F3 + AGY F6 + Claude SMR F5 (bucket label le vs bucket_hi_ns) | v2 switches to PromQL-compatible `le` label. Implementation uses `le`; test pins the contract. | RESOLVED |
| Codex F4 + AGY F5 + Claude SMR F2 (missing ns_per_tsc_q32 metric) | v2 adds workerColdPathNSPerTSCQ32 Gauge family. | RESOLVED |
| Codex F5 + AGY F3 (snapshot None silence) | v2 adds snapshot_failed: AtomicU64 on WorkerColdPathAtomics (incremented inside snapshot() on retry exhaust); snapshot_failed_count() accessor; new xpf_userspace_worker_cold_path_snapshot_failed_total Counter family. Coordinator status path reads it. Cold field in WorkerRuntimeStatus + Go *uint64. | RESOLVED |
| AGY F1 (scalar fields need skip_serializing_if u64_is_zero) | v2 applies skip_serializing_if to all u64 scalar fields + String::is_empty on cold_path_clock_source. Wire-invariant test fixture remains unchanged for default workers (no field growth on the wire). | RESOLVED |
| Claude SMR F4 (clock_source gauge always present) | v2 always emits clock_source gauge; "unset" label when ColdPathClockSource is empty. Test pins this. | RESOLVED |
| Claude SMR F3 (clock_source omitempty truth table walk) | v2 §4.3 + implementation: serde_serialize skip when String::is_empty; Go omitempty matches. Both directions handled. | RESOLVED |

## Implementation status

Code in tree matches plan v2:

- `cold_path_hist.rs`: WorkerColdPathAtomics gains `snapshot_failed:
  AtomicU64` field (cacheline 0, between cold_window_gen + sample_phase
  per the field reorder). snapshot() increments the counter on retry-
  exhaust before returning None. snapshot_failed_count() accessor.
  3 layout-test offsets updated. 28/28 tests pass with 5/5 flake.
- `WorkerHandle` gains `cold_path_atomics: Arc<WorkerColdPathAtomics>`
  field; bringup.rs allocates alongside runtime_atomics; worker_loop
  receives a new param.
- `worker_loop`: per-binding cold_path counters MERGED at the publish
  tick (saturating_add + OR-alias + first-non-zero); merged result
  goes through cold_path_atomics.publish_from_local(). install_calibration
  called at startup so first scrape sees q32 + clock_source.
- `coordinator/status.rs`: snapshots cold_path_atomics + reads
  snapshot_failed_count(); stamps both onto WorkerRuntimeStatus.
- `WorkerRuntimeStatus` (Rust binding.rs + Go protocol.go): 11 new
  fields total; all use skip_serializing_if so an uncalibrated /
  empty-data worker emits ZERO new bytes on the wire.
- `metrics_userspace.go::emitWorkerColdPath`: 8 metric families;
  ALWAYS emits the per-worker scalars (sample_phase, wrapper_*,
  ns_per_tsc_q32, clock_source, snapshot_failed) so dashboards see
  every worker regardless of cold-path activity; per-(worker, slot)
  metrics only emitted when Vec fields populated.
- `metrics.go` xpfCollector + `metrics_descriptors.go`: 10 new
  descriptors.
- `metrics_cold_path_test.go`: 4 new tests pinning the always-
  emitted metric contract + the `le` label contract + the populated-
  slot semantic.
- Wire-protocol fixture (`protocol_wire_v1.json`) UNCHANGED — the
  skip_serializing_if attributes mean a default WorkerRuntimeStatus
  serializes identically to pre-#1621.

## Test status

- cargo test --release --bin xpf-userspace-dp: 1492/1492 pass.
- cold_path_hist:: 28/28 with 5/5 flake clean.
- go test ./...: all packages pass.
- 4 new Go cold-path Prometheus tests pass.

## Cross-PR risk

#1623 (policy/) and #1625 (cos/) sub-agents on different file zones.
No conflict. #1622 gated on #1621.

## Verdict — PLAN-READY

All 5 r1 fix axes implemented (Codex F1-F5 + AGY F1-F5 + Claude SMR
F1-F5). Code matches plan; tests pin all the new contracts. Ready
for round-2 Codex/AGY adversarial confirmation.
