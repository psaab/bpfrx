# userspace-dp/src/afxdp/worker/

The per-worker hot path. One `BindingWorker` per RSS queue, owns
its AF_XDP socket + UMEM + RX/TX/fill/completion rings + per-worker
state. The `worker_loop` fn (defined in `loop_body/mod.rs`,
re-exported from `worker/mod.rs`) calls `poll_binding` once per
binding per tick.

`worker_loop` was extracted out of `worker/mod.rs` into `loop_body/`
in #1326 Phase 1 (PR #1569) when `worker/mod.rs` crossed the 2000-LOC
modularity gate. #1776 (Phase 2, narrowed v3.1 scope) carved the two
cold extractions out of the fn: `loop_body/setup.rs` (one-shot setup,
returns the loop's initial `WorkerLoopSetup` state) and
`loop_body/debug_report.rs` (the cfg(debug-log) verbose report /
stall dump + `DbgCounters`, feature-gated at the `mod` declaration so
release builds compile none of it). All per-tick logic — including
the hot `poll_binding` sweep, the ArcSwap config refresh, command
drain, and the always-on binding diagnostics + `BindingLiveState`
publish — stays inline in `loop_body/mod.rs` by design (no call
boundary added to the per-tick path; Codex r1-4).

`BindingWorker` was decomposed into sub-structs in #959 (Phases 1–11).
Each phase extracted one cluster of fields into a dedicated
sub-struct so the parent struct stays cache-line-friendly and so
each cluster has a clear ownership boundary.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `BindingWorker` struct + shared-binding helpers + `pub(crate) use loop_body::worker_loop` re-export. |
| `loop_body/mod.rs` | `worker_loop` body (extracted in #1326 Phase 1; decomposed in #1776). Per-tick orchestrator — all per-tick logic stays inline here. |
| `loop_body/setup.rs` | #1776 — one-shot cold setup (`worker_loop_setup`): thread pin via `pin_current_thread` (defined in `afxdp/neighbor.rs`), TSC calibration, binding construction, BPF-map-FD cache; returns `WorkerLoopSetup`. |
| `loop_body/debug_report.rs` | #1776 — cfg(debug-log)-only `DbgCounters` + per-second verbose report (`emit_periodic_report`) + stall dump (`check_and_dump_stall`). Compiled out of release builds. |
| `lifecycle.rs` | `poll_binding` — the per-poll RX/TX orchestrator. The "central function" extracted in Issue 73 step 2. |
| `cos.rs` | Per-worker CoS runtime helpers + shared-exact threshold (the empirical sustained per-worker exact throughput ceiling — see comment block in the file for the evidence basis). |
| `cos_state.rs` | `WorkerCos` (#959 Phase 3) — per-binding CoS-engine state. |
| `cos_tests.rs` | Co-located CoS unit tests. |
| `telemetry.rs` | `WorkerTelemetry` (#959 Phase 1) — `dbg_*` debug counters. |
| `scratch.rs` | `WorkerScratch` (#959 Phase 2) — pre-allocated per-poll reusable buffers. |
| `tx_counters.rs` | `WorkerTxCounters` (#959 Phase 4) — per-binding TX-disposition packet counters (direct, copy, in-place + 3 fallback paths). |
| `bpf_maps.rs` | `WorkerBpfMaps` (#959 Phase 5) — four BPF map FDs opened once at construction (heartbeat, session, conntrack v4/v6). |
| `timers.rs` | `WorkerTimers` (#959 Phase 6) — five fields gating per-binding wake / heartbeat pacing. |
| `tx_pipeline.rs` | `WorkerTxPipeline` (#959 Phase 7 + Phase 10's `outstanding_tx`) — eight fields holding the TX pipeline buffers. |
| `bind_meta.rs` | `WorkerBindMeta` (#959 Phase 8) — `bind_time_ns`, `bind_mode` (copy vs ZC), and identity. |
| `flow_cache_state.rs` | `WorkerFlowCacheState` (#959 Phase 9) — per-worker flow cache. (#2220 dropped the binding-global modulo-64 `flow_cache_session_touch` keepalive counter; the cache fast path now calls `SessionTable::touch_if_stale`, a per-session time-threshold keepalive — see `session/README.md` "Flow-cache keepalive".) |
| `xsk_rings.rs` | `WorkerXskRings` (#959 Phase 11) — the three XSK kernel-ring handles (`device`, `rx`, `tx`). |

## Where it sits

- Top of the dataplane stack. Spawned by `coordinator/supervisor.rs`.
- Reads/writes to all the AF_XDP sub-modules (`umem/`, `tx/`,
  `frame/`, `cos/`, `forwarding/`, `session_glue/`).
- After #959, fields are accessed via the sub-struct prefix
  (`binding.cos.cos_X`, `binding.scratch.scratch_X`, etc.). The
  per-phase top-of-file comments name which field cluster moved.

## Notable invariants

- CPU pinning honors the inherited systemd `CPUAffinity=` mask. Worker
  N pins to the N-th *allowed* CPU in that mask, so
  `CPUAffinity=2 3 4 5` puts workers 0..3 on CPUs 2..5. Don't revert
  to absolute-index pinning; the `CPUAffinity=` test catches it.
- Each phase of #959 was a pure structural extraction — capacities
  and access semantics were preserved. Treat the sub-struct field
  layout as load-bearing for the cache-line story.
- `worker_loop` polls every binding once per tick in
  `RX_BATCH_SIZE = 64`-sized batches up to
  `MAX_RX_BATCHES_PER_POLL = 4` per tick. `RX_BATCH_SIZE` and
  `TX_BATCH_SIZE` carry compile-time `const_assert`s in
  `afxdp/mod.rs`; `MAX_RX_BATCHES_PER_POLL = 4` is a plain `const`
  there with a `const _: () = assert!(MAX_RX_BATCHES_PER_POLL >= 1);`
  compile-time guard in `worker/lifecycle.rs`. The guard pins the
  lower bound only — there is no compile-time pin on the value 4
  itself; change it deliberately and re-run the guarantee-phase
  per-visit budget tests (`guarantee_phase_visit_cap_drains_banked_frames`
  and `guarantee_phase_allows_larger_high_rate_visit_quantum`). #1630 (P2)
  split the per-visit budget into a rate-scaled Phase-1 cost
  (`cos_guarantee_quantum_bytes`) and a FRAME-count send cap
  (`cos_guarantee_visit_cap_bytes` = `TX_BATCH_SIZE × frame`); the
  `TX_BATCH_SIZE` const-assert covers the latter.
- Binding creation must publish the selected shared-UMEM mode/group/role
  into `BindingLiveState` for both private and shared paths before the
  first coordinator refresh. The coordinator treats the live snapshot as
  authoritative after worker start, so a bind path that only logs the
  kernel role but does not update live status will make the CLI report
  `Shared UMEM bindings: 0/N` even when the sockets are actually shared.
- `BindingWorker::new_for_cos_drain_test` is test-only scaffolding for
  hermetic CoS service-path tests. It uses in-memory AF_XDP ring fixtures
  and must not become a production construction path; production workers
  still go through `BindingWorker::create`, which performs the real bind
  and seeds ring/UMEM ownership from the binding plan.
