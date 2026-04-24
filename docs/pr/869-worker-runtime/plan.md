# PR: #869 userspace-dp worker runtime telemetry

## Goal
Expose per-worker busy/idle time + thread CPU time + loop counts so
operators can tell apart: compute saturation vs idle spin vs real
idle headroom vs VM scheduling loss vs per-worker imbalance.

## Design
Loop-top accounting: attribute `now - last_loop_ns` delta to the
PREVIOUS loop's classified state (Active / IdleSpin / IdleBlock).
Worker-local u64 math; no per-packet atomics.  Publish to
cacheline-isolated atomics on ~1s cadence, same time `clock_gettime
CLOCK_THREAD_CPUTIME_ID` is sampled.

## Files
- `userspace-dp/src/afxdp/worker_runtime.rs` (new): state enum, local
  counters struct, `WorkerRuntimeAtomics` publish struct, tid + cpu
  samplers, unit tests.
- `userspace-dp/src/afxdp/worker.rs`: loop-top delta accounting,
  classification at `did_work`/spin/block sites, 1s publish cadence.
- `userspace-dp/src/afxdp/coordinator.rs`: `Arc<WorkerRuntimeAtomics>`
  per worker, `worker_runtime_snapshots()` accessor.
- `userspace-dp/src/afxdp/types.rs`: `WorkerHandle.runtime_atomics`.
- `userspace-dp/src/afxdp.rs`: expose `worker_runtime` module.
- `userspace-dp/src/protocol.rs`: `WorkerRuntimeStatus` struct,
  `StatusSnapshot.worker_runtime`.
- `userspace-dp/src/main.rs`: populate status field on each snapshot.
- `pkg/dataplane/userspace/protocol.go`: Go mirror struct + field.
- `pkg/dataplane/userspace/statusfmt.go`: compact worker-runtime table
  in status output.
- `pkg/api/metrics.go`: 7 Prometheus counters, `collectWorkerRuntime`
  helper.

## Risk
- Hot path gets 1 `monotonic_nanos()` + small arithmetic per loop
  (worker was already taking that timestamp at loop top; we added a
  `saturating_sub` + `match` + 1-2 add/store).  No atomics, no
  allocs, no syscalls on hot path.
- `clock_gettime` once per second per worker — negligible.
- JSON wire format is additive with `serde(default)` for
  compatibility with older daemons.
