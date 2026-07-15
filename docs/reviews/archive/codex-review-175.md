# Paladin Full-Tree Defensive Review - Codex 175

## 1. Review target

Base commit reviewed: `385f940b7c3208734775d48763e60d66ee8274e0`

Output path: `/tmp/codex-review-175.md`

The checkout was updated with `git pull --rebase` before the campaign. All 23 subagents read the immutable base from detached worktrees. No repository source file was modified.

## 2. Duplicate suppression and merge disposition

The coordinator compact-indexed 116 prior final reports required by the campaign (`codex`, `agy`, `fable`, `ps`, and `avo`) before dispatch. An auxiliary exact-title scan over 136 visible final reports from all local review roles found zero exact matches for this campaign's raw titles. Each subagent also compared root cause, file, and consequence against the compact index.

- Raw batch findings: 150
- Cross-batch duplicate pairs merged: 3 (six raw reports became three findings)
- Coordinator-refuted findings dropped: 1
- Coordinator-confirmed finding downgraded from High to Medium: 1
- Final non-duplicate findings: 146

Cross-batch merges:

1. Signed queue/binding/injection identifiers narrowed to `uint32` before helper control (A6-b1 + A8-b2).
2. Filtered session clear materializes unbounded key snapshots (A8-b2 + A10-b2).
3. Local/remote policy inventory silently discards malformed zone selectors (A10-b1 + A10-b2).

## 3. Expertise-area and batch checklist

| Area | Scope | Files | Batches | Final findings attributed |
|---|---|---:|---:|---:|
| A1 | Rust dataplane packet path & memory safety | 348 | 4 | 8 |
| A2 | Rust NAT/NAT64/translation | 19 | 1 | 2 |
| A3 | Go config compiler, schema & CLI grammar | 438 | 4 | 12 |
| A4 | Go configstore, persistence & crypto-at-rest | 49 | 1 | 6 |
| A5 | HA cluster, VRRP, RA, conntrack sync | 94 | 1 | 2 |
| A6 | Dataplane Go manager/control-plane to dataplane compilation | 273 | 2 | 3 |
| A7 | Daemon lifecycle & host integration | 233 | 3 | 13 |
| A8 | APIs (gRPC/REST) & surfaces | 250 | 2 | 6 |
| A9 | Observability & telemetry | 108 | 1 | 13 |
| A10 | Services, policy simulator, CLI/show, build/deploy tooling | 435 | 4 | 81 |

Coverage proof: `2247/2247` tracked `go|rs|c|h|hpp|cpp|cc|cxx|py` files were assigned exactly once; duplicate assignments: 0; missing files: 0; extra files: 0.

Batch manifest:

| Batch | Files | Intermediate report |
|---|---:|---|
| A1-b1 | 6 | `codex-A1-b1.md` |
| A1-b2 | 150 | `codex-A1-b2.md` |
| A1-b3 | 100 | `codex-A1-b3.md` |
| A1-b4 | 92 | `codex-A1-b4.md` |
| A2-b1 | 19 | `codex-A2-b1.md` |
| A3-b1 | 16 | `codex-A3-b1.md` |
| A3-b2 | 150 | `codex-A3-b2.md` |
| A3-b3 | 150 | `codex-A3-b3.md` |
| A3-b4 | 122 | `codex-A3-b4.md` |
| A4-b1 | 49 | `codex-A4-b1.md` |
| A5-b1 | 94 | `codex-A5-b1.md` |
| A6-b1 | 150 | `codex-A6-b1.md` |
| A6-b2 | 123 | `codex-A6-b2.md` |
| A7-b1 | 150 | `codex-A7-b1.md` |
| A7-b2 | 17 | `codex-A7-b2.md` |
| A7-b3 | 66 | `codex-A7-b3.md` |
| A8-b1 | 104 | `codex-A8-b1.md` |
| A8-b2 | 146 | `codex-A8-b2.md` |
| A9-b1 | 108 | `codex-A9-b1.md` |
| A10-b1 | 49 | `codex-A10-b1.md` |
| A10-b2 | 132 | `codex-A10-b2.md` |
| A10-b3 | 117 | `codex-A10-b3.md` |
| A10-b4 | 137 | `codex-A10-b4.md` |

### Fallback assignments

Files outside the explicit path map were assigned to the nearest A10 generalist batch:

- docs/pr/812-tx-latency-histogram/evidence/vdso_probe.c -> A10 nearest generalist fallback
- docs/pr/812-tx-latency-histogram/evidence/vdso_probe2.c -> A10 nearest generalist fallback
- pkg/devicemap/devicemap.go -> A10 nearest generalist fallback
- pkg/devicemap/devicemap_test.go -> A10 nearest generalist fallback
- pkg/diagcmd/diagcmd.go -> A10 nearest generalist fallback
- pkg/diagcmd/diagcmd_test.go -> A10 nearest generalist fallback
- pkg/fairness/expectation.go -> A10 nearest generalist fallback
- pkg/fairness/expectation_test.go -> A10 nearest generalist fallback
- pkg/fsatomic/canary_test.go -> A10 nearest generalist fallback
- pkg/fsatomic/fsatomic.go -> A10 nearest generalist fallback
- pkg/fsatomic/fsatomic_test.go -> A10 nearest generalist fallback
- pkg/fwdstatus/builder.go -> A10 nearest generalist fallback
- pkg/fwdstatus/fwdstatus.go -> A10 nearest generalist fallback
- pkg/fwdstatus/fwdstatus_test.go -> A10 nearest generalist fallback
- pkg/fwdstatus/osprocreader_test.go -> A10 nearest generalist fallback
- pkg/fwdstatus/procreader.go -> A10 nearest generalist fallback
- pkg/fwdstatus/sampler.go -> A10 nearest generalist fallback
- pkg/fwdstatus/sampler_test.go -> A10 nearest generalist fallback
- pkg/ipmon/display.go -> A10 nearest generalist fallback
- pkg/ipmon/ipmon.go -> A10 nearest generalist fallback
- pkg/ipmon/ipmon_test.go -> A10 nearest generalist fallback
- pkg/ipmon/nexthop_test.go -> A10 nearest generalist fallback
- pkg/linuxsock/canary_test.go -> A10 nearest generalist fallback
- pkg/linuxsock/linuxsock.go -> A10 nearest generalist fallback
- pkg/linuxsock/linuxsock_test.go -> A10 nearest generalist fallback
- pkg/lldp/lldp.go -> A10 nearest generalist fallback
- pkg/lldp/lldp_test.go -> A10 nearest generalist fallback
- pkg/lldp/socket_test.go -> A10 nearest generalist fallback
- pkg/monitoriface/monitor.go -> A10 nearest generalist fallback
- pkg/monitoriface/monitor_test.go -> A10 nearest generalist fallback
- pkg/natpoolalarm/natpoolalarm.go -> A10 nearest generalist fallback
- pkg/natpoolalarm/natpoolalarm_test.go -> A10 nearest generalist fallback
- pkg/natpoolalarm/render.go -> A10 nearest generalist fallback
- pkg/natpoolalarm/render_test.go -> A10 nearest generalist fallback
- pkg/nftables/host_inbound_counters.go -> A10 nearest generalist fallback
- pkg/nftables/host_inbound_counters_test.go -> A10 nearest generalist fallback
- pkg/nftables/lo0_counters.go -> A10 nearest generalist fallback
- pkg/nftables/rst_suppress.go -> A10 nearest generalist fallback
- pkg/nftables/rst_suppress_test.go -> A10 nearest generalist fallback
- pkg/scheduler/scheduler.go -> A10 nearest generalist fallback
- pkg/scheduler/scheduler_3849_test.go -> A10 nearest generalist fallback
- pkg/scheduler/scheduler_localtz_3988_test.go -> A10 nearest generalist fallback
- pkg/scheduler/scheduler_republish_3780_test.go -> A10 nearest generalist fallback
- pkg/scheduler/scheduler_test.go -> A10 nearest generalist fallback
- pkg/upgrade/cluster_cli.go -> A10 nearest generalist fallback
- pkg/upgrade/cluster_cli_test.go -> A10 nearest generalist fallback
- pkg/upgrade/cutover.go -> A10 nearest generalist fallback
- pkg/upgrade/cutover_refuse_test.go -> A10 nearest generalist fallback
- pkg/upgrade/flip.go -> A10 nearest generalist fallback
- pkg/upgrade/imageversions.go -> A10 nearest generalist fallback
- pkg/upgrade/imageversions_test.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_drain.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_drain_test.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_linux.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_linux_test.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_run.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_selfrecover.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_selfrecover_test.go -> A10 nearest generalist fallback
- pkg/upgrade/kernel_test.go -> A10 nearest generalist fallback
- pkg/upgrade/lock/lock.go -> A10 nearest generalist fallback
- pkg/upgrade/lock/lock_test.go -> A10 nearest generalist fallback
- pkg/upgrade/lock_integration_test.go -> A10 nearest generalist fallback
- pkg/upgrade/lock_seam_test.go -> A10 nearest generalist fallback
- pkg/upgrade/manifest/manifest.go -> A10 nearest generalist fallback
- pkg/upgrade/manifest/manifest_drift_test.go -> A10 nearest generalist fallback
- pkg/upgrade/rolling.go -> A10 nearest generalist fallback
- pkg/upgrade/rolling_test.go -> A10 nearest generalist fallback
- pkg/upgrade/runner.go -> A10 nearest generalist fallback
- pkg/upgrade/runner_test.go -> A10 nearest generalist fallback
- pkg/upgrade/runtime/seed.go -> A10 nearest generalist fallback
- pkg/upgrade/runtime/seed_test.go -> A10 nearest generalist fallback
- pkg/upgrade/stagedgen/fsutil.go -> A10 nearest generalist fallback
- pkg/upgrade/stagedgen/stagedgen.go -> A10 nearest generalist fallback
- pkg/upgrade/stagedgen/stagedgen_test.go -> A10 nearest generalist fallback
- pkg/upgrade/stagedgen_cut_test.go -> A10 nearest generalist fallback
- pkg/upgrade/state.go -> A10 nearest generalist fallback
- pkg/upgrade/system_linux.go -> A10 nearest generalist fallback
- pkg/upgrade/system_linux_test.go -> A10 nearest generalist fallback
- pkg/upgrade/verify_cleanup_test.go -> A10 nearest generalist fallback
- pkg/upgrade/version.go -> A10 nearest generalist fallback
- pkg/upgrade/version_test.go -> A10 nearest generalist fallback
- pkg/wgkey/wgkey.go -> A10 nearest generalist fallback
- pkg/wgkey/wgkey_test.go -> A10 nearest generalist fallback
- test/incus/cluster_status_parse.py -> A10 nearest generalist fallback
- test/incus/cluster_status_parse_test.py -> A10 nearest generalist fallback
- test/incus/cold-path-flooder/src/main.rs -> A10 nearest generalist fallback
- test/incus/cos_be_contention_validate.py -> A10 nearest generalist fallback
- test/incus/cos_be_contention_validate_test.py -> A10 nearest generalist fallback
- test/incus/cos_port_grid_test.py -> A10 nearest generalist fallback
- test/incus/fairness_cov.py -> A10 nearest generalist fallback
- test/incus/fairness_cov_test.py -> A10 nearest generalist fallback
- test/incus/fairness_equal_flow_capture.py -> A10 nearest generalist fallback
- test/incus/fairness_multi_sample.py -> A10 nearest generalist fallback
- test/incus/fairness_multi_sample_test.py -> A10 nearest generalist fallback
- test/incus/fairness_surplus_giveback_validate.py -> A10 nearest generalist fallback
- test/incus/fairness_surplus_giveback_validate_test.py -> A10 nearest generalist fallback
- test/incus/iperf3_sum_parse.py -> A10 nearest generalist fallback
- test/incus/iperf3_sum_parse_test.py -> A10 nearest generalist fallback
- test/incus/mouse_latency_aggregate.py -> A10 nearest generalist fallback
- test/incus/mouse_latency_aggregate_test.py -> A10 nearest generalist fallback
- test/incus/mouse_latency_orchestrate.py -> A10 nearest generalist fallback
- test/incus/mouse_latency_orchestrate_test.py -> A10 nearest generalist fallback
- test/incus/mouse_latency_probe.py -> A10 nearest generalist fallback
- test/incus/mouse_latency_probe_test.py -> A10 nearest generalist fallback
- test/incus/policy_scheduler_validate.py -> A10 nearest generalist fallback
- test/incus/policy_scheduler_validate_test.py -> A10 nearest generalist fallback
- test/incus/retire_ebpf_artifact_schema.py -> A10 nearest generalist fallback
- test/incus/retire_ebpf_artifact_schema_test.py -> A10 nearest generalist fallback
- test/incus/step1-histogram-classify.py -> A10 nearest generalist fallback
- test/incus/step1-histogram-classify_test.py -> A10 nearest generalist fallback
- test/incus/step1-rate-spread-analysis.py -> A10 nearest generalist fallback
- test/incus/step1-rss-multinomial.py -> A10 nearest generalist fallback
- test/incus/step2-sched-switch-classify.py -> A10 nearest generalist fallback
- test/incus/step2-sched-switch-classify_test.py -> A10 nearest generalist fallback
- test/incus/step2-sched-switch-reduce.py -> A10 nearest generalist fallback
- test/incus/step2-sched-switch-reduce_test.py -> A10 nearest generalist fallback
- test/incus/step3-tx-kick-classify.py -> A10 nearest generalist fallback
- test/incus/step3-tx-kick-classify_test.py -> A10 nearest generalist fallback
- test/incus/test_mouse_latency_shell_test.py -> A10 nearest generalist fallback
- test/xsk-repro/libbpf_xsk_shared_test.c -> A10 nearest generalist fallback
- test/xsk-repro/libbpf_xsk_test.c -> A10 nearest generalist fallback
- test/xsk-repro/main.rs -> A10 nearest generalist fallback
- test/xsk-repro/xdp_pass_redirect.c -> A10 nearest generalist fallback

## 4. Aggregated module-by-module inspection log

The following logs are the coverage records from each isolated batch. They include positive findings, checked invariants, prior-root suppression, and explicit negative results.

### A1-b1

### userspace-dp/benches/prefix_set_lookup.rs

Reviewed the local trie reimplementation, deterministic LCG, p50/p95/p99 computation, and enforced p95 threshold. The fixed `prefix_len = 32` call keeps `ip >> (31 - i)` in range, the LCG wrapping arithmetic is intentional deterministic input generation, and the allocation result is black-boxed after construction. Minimal contract read: `userspace-dp/src/prefix_set.rs` confirms the production V4 trie uses the same MSB-first `TrieNode { covers, children }` insertion shape. Negative result: no memory-safety, integer-overflow, or fail-open parser finding in the bench itself. Coverage gap recorded as F3.

### userspace-dp/benches/session_table.rs

Reviewed the current-vs-slab table models, key construction, secondary index install/remove symmetry, owner-RG export, and `u32` slab-handle cast. `N = 16384` makes `raw.try_into().unwrap()` safe inside this bench, and all handle lookups use `Slab::get` before dereferencing. The `wrapping_add(1)` port transforms are deliberate synthetic reverse/alias keys, not packet parsing. Negative result: no runtime memory-safety bug in the bench; the main risk is that its documented pass criteria are observational rather than enforced, covered by F2.

### userspace-dp/benches/snat_allocator.rs

Reviewed the global-mutex model, proposed bitmap model, atomic bitmap claim/free ordering, live-count reservation/rollback, workload profiles, deterministic flow generation, and result reporting. The atomic bitmap uses the bit itself as the ownership token, so relaxed loads plus AcqRel `fetch_or`/Release `fetch_and` are adequate for the bench's token-only state. Minimal contract read: `userspace-dp/src/nat/allocator.rs` shows production at this base already has the #2852 lock-free claim design with exact cap/reuse checks under the retained map mutex. Findings: F1 for stale production-model drift, F2 for non-enforced gate behavior.

### userspace-dp/benches/tx_kick_latency.rs

Reviewed the local `bucket_index_for_ns`, `KickLatencyOwner` alignment, relaxed atomic counter updates, and `clock_gettime(CLOCK_MONOTONIC)` wrapper. Minimal contract reads in `userspace-dp/src/afxdp/umem/mod.rs` and `userspace-dp/src/afxdp/tx/stats.rs` confirm the bucket math and relaxed update sequence match production. Negative result: no unsafe memory bug; stack `timespec` is valid for the libc call and the sentinel `0` behavior matches production. Finding: F2 because the documented p99 gate is not enforced by this Criterion bench.

### userspace-dp/build.rs

Reviewed the C bridge compilation and link directives. The source path is fixed (`csrc/xsk_bridge.c`), not derived from untrusted input; the script requests static libxdp/libbpf/libelf/z/zstd and emits `rerun-if-changed` for the bridge source. Negative result: no command injection or source mutation risk in this build script. Portability risk from hard-coded `/usr/include` is noted but not security-relevant for this batch.

### userspace-dp/csrc/xsk_bridge.c

Reviewed every FFI wrapper, with minimal contract reads of Rust callers in `userspace-dp/src/xsk_ffi.rs` and libxdp inline ring helpers in `/usr/include/xdp/xsk.h`. Reserve/submit/cancel invariants are balanced by the Rust `WriteTx`/`WriteFill` drop paths; consumer cancel mirrors libxdp; descriptor setters/getters use libxdp-masked ring access; stats zero-initialize before `getsockopt`. Negative result: no direct C memory-safety finding. The FFI remains unsafe by contract, but the reviewed callers bound writes to reserved slots and only cancel unread/unused reservations.

- `userspace-dp/csrc/xsk_bridge.c`: No finding on producer reserve/submit/cancel. Libxdp `xsk_ring_prod__reserve` advances `cached_prod`; Rust drops submit written descriptors and cancels only unused reservations, so `cached_prod` is restored to the committed producer position.
- `userspace-dp/csrc/xsk_bridge.c`: No finding on consumer peek/release/cancel. Libxdp exposes `xsk_ring_cons__cancel`, and Rust only cancels peeked-but-unread entries.
- `userspace-dp/csrc/xsk_bridge.c`: No finding on stats zeroing. `struct xdp_statistics stats` is zeroed before `getsockopt`, and errors return `-errno`.
- `userspace-dp/build.rs`: No untrusted command surface; all files/libraries are fixed literals.
- `userspace-dp/benches/session_table.rs`: No unsafe or out-of-bounds handle dereference in the bench. Handles are generated from `Slab::insert`, constrained by `N`, and read through `Slab::get`.
- `userspace-dp/benches/tx_kick_latency.rs`: No atomic ordering bug in the modeled counters. The production contract is single writer with relaxed snapshot readers, and the bench mirrors that.

### A1-b2

Legend: C/S = correctness, security, fail-open/fail-closed posture. MCI/R = memory safety, concurrency, integer, resource checks. Perf = performance/latency. Tests = reviewed nearby tests or noted coverage gap. vSRX = feature-completeness parity where applicable.

- userspace-dp/src/afxdp/bind.rs - Negative. C/S: AF_XDP bind/ring sizing and syscall error paths checked for fail-closed setup. MCI/R: mmap/fd cleanup and ring-entry arithmetic bounded. vSRX: not a parity surface. Perf: ring sizing preserves fixed UMEM frame model. Tests: sizing helpers covered.
- userspace-dp/src/afxdp/bpf_map/ha.rs - Negative. C/S: HA BPF map access stays keyed and error-returning. MCI/R: typed map buffers checked. vSRX: no parity gap. Perf: cold control path. Tests: no new gap found.
- userspace-dp/src/afxdp/bpf_map/metrics.rs - Finding 1. C/S: BPF map iteration caps checked. MCI/R: unaligned `ptr::read` in debug dump found. vSRX: no parity gap. Perf: debug-only syscall path. Tests: no unaligned-read regression coverage.
- userspace-dp/src/afxdp/bpf_map/mod.rs - Finding 1 contract. C/S: session key/value map contracts checked. MCI/R: `repr(C)` key alignment makes metrics read unsafe from `Vec<u8>`. vSRX: no parity gap. Perf: hot publish remains typed. Tests: no layout/alignment test for dump path.
- userspace-dp/src/afxdp/bpf_map/pin.rs - Negative. C/S: pin path validates map fds and names. MCI/R: fd lifetime and error unwinds checked. vSRX: no parity gap. Perf: cold setup path. Tests: no new gap found.
- userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs - Negative. C/S: conntrack publish/delete keys use typed buffers and explicit errors. MCI/R: byte-order and value sizing checked. vSRX: no parity gap. Perf: map syscalls are not per-packet steady state. Tests: map contract tests exist elsewhere.
- userspace-dp/src/afxdp/bpf_map_tests.rs - Negative. C/S: tests cover map sizing/encoding contracts. MCI/R: no unsafe production logic. vSRX: n/a. Perf: n/a. Tests: useful but missing Finding 1 case.
- userspace-dp/src/afxdp/checksum.rs - Negative. C/S: checksum fold/update helpers preserve network-order semantics. MCI/R: integer accumulation bounded in wider types. vSRX: no parity gap. Perf: no allocation. Tests: checksum tests present in frame modules.
- userspace-dp/src/afxdp/cold_path_hist.rs - Negative. C/S: histogram accounting does not affect packet verdicts. MCI/R: atomics checked for relaxed telemetry use. vSRX: no parity gap. Perf: bounded buckets. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/bpf_maps.rs - Negative. C/S: coordinator map ownership/setup errors fail closed. MCI/R: fd ownership and Arc sharing checked. vSRX: no parity gap. Perf: cold path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/cos_leases.rs - Negative. C/S: CoS lease grant/revoke state checked. MCI/R: counters and lock scope bounded. vSRX: no parity gap. Perf: control-path updates only. Tests: coordinator tests cover lease bounds.
- userspace-dp/src/afxdp/coordinator/cos_state.rs - Negative. C/S: CoS snapshot publication keeps default/no-class behavior explicit. MCI/R: Arc swap and generation handling checked. vSRX: no parity gap. Perf: avoids per-packet mutation. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/ha_state.rs - Negative. C/S: HA state transitions checked for explicit role/session publication. MCI/R: atomic/lock ownership sound in reviewed paths. vSRX: no parity gap. Perf: control-plane cadence. Tests: HA tests nearby.
- userspace-dp/src/afxdp/coordinator/inject.rs - Negative. C/S: injected frame length is capped to UMEM size. MCI/R: descriptor arithmetic checked. vSRX: no parity gap. Perf: injected path not packet fast path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/mod.rs - Negative. C/S: coordinator lifecycle/start-stop and shared handles checked. MCI/R: Arc ownership, worker handles, and dynamic-neighbor accessors sound. vSRX: no parity gap. Perf: shared state avoids hot locks where intended. Tests: coordinator tests cover lifecycle.
- userspace-dp/src/afxdp/coordinator/neighbor_manager.rs - Negative. C/S: neighbor manager owns dynamic map replacement/warm queue. MCI/R: queue depth bounded. vSRX: no parity gap. Perf: warm queue capped. Tests: no new gap beyond Finding 2.
- userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs - Negative. C/S: bringup orders bindings, workers, neighbor/tunnel supervision. MCI/R: resource handoff checked. vSRX: no parity gap. Perf: cold path. Tests: coordinator tests cover bringup classes.
- userspace-dp/src/afxdp/coordinator/reconcile/mod.rs - Negative. C/S: reconcile dispatcher preserves explicit reset/bringup/teardown paths. MCI/R: no unsafe logic. vSRX: no parity gap. Perf: cold path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/reconcile/reset.rs - Negative. C/S: reset tears down before re-arming workers. MCI/R: handle cleanup checked. vSRX: no parity gap. Perf: cold path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs - Negative. C/S: snapshot reconcile keeps state publication explicit. MCI/R: clone/Arc usage checked. vSRX: no parity gap. Perf: cold path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs - Negative. C/S: teardown path closes workers and sockets explicitly. MCI/R: resource ownership checked. vSRX: no parity gap. Perf: cold path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/refresh_bindings.rs - Negative. C/S: binding refresh preserves active binding set and failure handling. MCI/R: fd/worker handle updates checked. vSRX: no parity gap. Perf: control path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/session_manager.rs - Negative. C/S: session manager command path checked for bounded deltas. MCI/R: ring/drop accounting checked. vSRX: no parity gap. Perf: inline drain limits retained. Tests: session tests cover over-cap deltas.
- userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs - Negative. C/S: snapshot refresh fails closed on missing state. MCI/R: Arc/lock use checked. vSRX: no parity gap. Perf: control path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/status.rs - Negative. C/S: status rendering caps rows and does not mutate dataplane. MCI/R: dynamic-neighbor and flow rows bounded. vSRX: no parity gap. Perf: cold introspection path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/supervisor.rs - Negative. C/S: supervision restarts bounded workers and surfaces errors. MCI/R: thread handle/lifetime checks sound. vSRX: no parity gap. Perf: not hot path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/tests.rs - Negative. C/S: tests exercise reconcile, CoS, and state publication. MCI/R: no production unsafe. vSRX: n/a. Perf: n/a. Tests: useful coverage, not exhaustive for findings here.
- userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs - Negative. C/S: tunnel liveness supervision checked against dynamic-neighbor and HA state use. MCI/R: queue/resource bounds checked. vSRX: no new parity gap. Perf: periodic control path. Tests: no new gap.
- userspace-dp/src/afxdp/coordinator/wg_control.rs - Negative. C/S: WG socket receive/send and endpoint handling checked. MCI/R: `recvmsg` control buffer is explicitly aligned and cmsg lengths guarded. vSRX: no parity gap. Perf: socket poll loop bounded. Tests: cmsg/sockaddr tests cover alignment/scope cases.
- userspace-dp/src/afxdp/coordinator/worker_manager.rs - Negative. C/S: worker spawn/stop path checked. MCI/R: handles and channels bounded by config. vSRX: no parity gap. Perf: cold path. Tests: coordinator coverage nearby.
- userspace-dp/src/afxdp/cos/admission.rs - Negative. C/S: admission clamps class bandwidth and buffer expansion. MCI/R: integer math uses widened/saturating forms. vSRX: no parity gap. Perf: admission path avoids hot locks. Tests: admission tests cover max buckets and clamps.
- userspace-dp/src/afxdp/cos/admission_tests.rs - Negative. C/S: tests cover admission edge cases. MCI/R: no production unsafe. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/builders.rs - Negative. C/S: queue config builders validate rates/limits. MCI/R: conversions checked. vSRX: no parity gap. Perf: build path only. Tests: builder tests present.
- userspace-dp/src/afxdp/cos/builders_tests.rs - Negative. C/S: builder fail-closed cases covered. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/cos/cross_binding.rs - Negative. C/S: cross-binding queue selection checked. MCI/R: shared state and indices bounded. vSRX: no parity gap. Perf: avoids per-packet allocation. Tests: cross-binding tests present.
- userspace-dp/src/afxdp/cos/cross_binding_tests.rs - Negative. C/S: tests cover cross-binding invariants. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/ecn.rs - Negative. C/S: ECN mark/drop decision code checked. MCI/R: arithmetic bounded. vSRX: no parity gap. Perf: no allocation. Tests: ECN tests present.
- userspace-dp/src/afxdp/cos/ecn_tests.rs - Negative. C/S: tests cover ECN threshold behavior. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/fairness.rs - Negative. C/S: SFQ bucket fairness formulas checked. MCI/R: active bucket math avoids u8 truncation. vSRX: no parity gap. Perf: fixed bucket model. Tests: flow-hash/fairness coverage nearby.
- userspace-dp/src/afxdp/cos/flow_hash.rs - Negative. C/S: flow hash uses 4096 bucket mask. MCI/R: return width avoids old u8 wrap class. vSRX: no parity gap. Perf: monomorphic arithmetic. Tests: flow hash tests present.
- userspace-dp/src/afxdp/cos/flow_hash_tests.rs - Negative. C/S: collision and width regression tests checked. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/mod.rs - Negative. C/S: module exports do not alter dataplane behavior. MCI/R: n/a. vSRX: no parity gap. Perf: n/a. Tests: covered by submodules.
- userspace-dp/src/afxdp/cos/queue_ops/accounting.rs - Negative. C/S: byte/packet accounting checked for saturation. MCI/R: integer math bounded. vSRX: no parity gap. Perf: hot path arithmetic only. Tests: queue ops tests cover accounting.
- userspace-dp/src/afxdp/cos/queue_ops/active_buckets.rs - Negative. C/S: active bucket set updates checked. MCI/R: indices bounded. vSRX: no parity gap. Perf: avoids full scans in steady state. Tests: active bucket tests nearby.
- userspace-dp/src/afxdp/cos/queue_ops/drain.rs - Negative. C/S: drain target/eligibility checked. MCI/R: queue counters bounded. vSRX: no parity gap. Perf: no per-packet heap allocation. Tests: queue drain tests present.
- userspace-dp/src/afxdp/cos/queue_ops/fused_diff_tests.rs - Negative. C/S: fused diff test cases cover bucket state transitions. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/queue_ops/mod.rs - Negative. C/S: queue op exports preserve helper boundaries. MCI/R: n/a. vSRX: no parity gap. Perf: n/a. Tests: covered by submodules.
- userspace-dp/src/afxdp/cos/queue_ops/pop.rs - Negative. C/S: pop handles empty/deficit queues fail-closed. MCI/R: VecDeque indices checked. vSRX: no parity gap. Perf: hot path no allocation. Tests: pop tests present.
- userspace-dp/src/afxdp/cos/queue_ops/pop_tests.rs - Negative. C/S: pop edge cases covered. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/queue_ops/push.rs - Negative. C/S: push enforces capacity/backpressure. MCI/R: descriptor ownership checked. vSRX: no parity gap. Perf: bounded queue operations. Tests: queue ops tests present.
- userspace-dp/src/afxdp/cos/queue_ops/tests.rs - Negative. C/S: queue op integration tests checked. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/cos/queue_ops/v_min.rs - Negative. C/S: virtual-time minimum logic checked. MCI/R: integer comparisons and snapshots bounded. vSRX: no parity gap. Perf: avoids broad queue scans where intended. Tests: v_min tests present.
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests.rs - Negative. C/S: v_min regression tests checked. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/queue_service/drain.rs - Negative. C/S: service drain submits only eligible descriptors. MCI/R: descriptor ownership and completion accounting checked. vSRX: no parity gap. Perf: bounded per-service work. Tests: queue service tests present.
- userspace-dp/src/afxdp/cos/queue_service/mod.rs - Negative. C/S: queue service module split sound. MCI/R: n/a. vSRX: no parity gap. Perf: n/a. Tests: covered by submodules.
- userspace-dp/src/afxdp/cos/queue_service/service.rs - Negative. C/S: service loop preserves rate and completion ordering. MCI/R: resource counters checked. vSRX: no parity gap. Perf: target-bps clamp checked. Tests: service tests present.
- userspace-dp/src/afxdp/cos/queue_service/submit_local.rs - Negative. C/S: local submit checks frame capacity before TX. MCI/R: unsafe UMEM writes guarded by slice availability. vSRX: no parity gap. Perf: no extra allocation found. Tests: queue service tests cover submit behavior.
- userspace-dp/src/afxdp/cos/queue_service/submit_prepared.rs - Negative. C/S: prepared submit preserves descriptor metadata. MCI/R: frame capacity checked. vSRX: no parity gap. Perf: hot submit bounded. Tests: no new gap.
- userspace-dp/src/afxdp/cos/queue_service/tests.rs - Negative. C/S: drain/submit/service tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/cos/token_bucket.rs - Negative. C/S: token accounting clamps burst/rate. MCI/R: time/math overflow checked. vSRX: no parity gap. Perf: cheap arithmetic. Tests: token bucket tests present.
- userspace-dp/src/afxdp/cos/token_bucket_tests.rs - Negative. C/S: token edge cases covered. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/cos/tx_completion.rs - Negative. C/S: TX completion returns descriptors to the right pool. MCI/R: ring completion accounting checked. vSRX: no parity gap. Perf: bounded completion batch. Tests: completion tests present.
- userspace-dp/src/afxdp/cos/tx_completion_tests.rs - Negative. C/S: TX completion tests cover recycling. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/disposition.rs - Negative. C/S: disposition enum maps explicit verdicts. MCI/R: n/a. vSRX: no parity gap. Perf: n/a. Tests: covered by callers.
- userspace-dp/src/afxdp/ethernet.rs - Negative. C/S: Ethernet helpers check frame length and ethertype offsets. MCI/R: slice bounds checked. vSRX: no parity gap. Perf: no allocation. Tests: frame tests cover consumers.
- userspace-dp/src/afxdp/event_emit.rs - Negative. C/S: event emission does not affect packet verdicts. MCI/R: channel/resource behavior checked. vSRX: no parity gap. Perf: cold/telemetry path. Tests: no new gap.
- userspace-dp/src/afxdp/flow_cache.rs - Negative. C/S: flow cache invalidation and neighbor epoch stamping checked. MCI/R: atomics/Arc and integer widths checked. vSRX: no parity gap. Perf: cache-line/epoch fast path preserved. Tests: flow cache tests extensive.
- userspace-dp/src/afxdp/flow_cache_tests.rs - Negative. C/S: cache invalidation, neighbor MAC epoch, and session tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/forward_request.rs - Negative. C/S: forward request fields are explicit and typed. MCI/R: no unsafe logic. vSRX: no parity gap. Perf: POD-like path. Tests: covered by forwarding tests.
- userspace-dp/src/afxdp/forwarding/host_inbound.rs - Negative. C/S: host-inbound protocol/zone gates checked against deduped known issues. MCI/R: no unsafe logic. vSRX: no new parity gap. Perf: no allocation concern found. Tests: forwarding tests cover host-inbound cases.
- userspace-dp/src/afxdp/forwarding/mod.rs - Negative. C/S: route/neighbor/tunnel resolution checked for fail-closed misses and dynamic-neighbor fallback. MCI/R: recursion/depth and integer math checked. vSRX: no new parity gap. Perf: cache-aware resolution. Tests: forwarding tests extensive.
- userspace-dp/src/afxdp/forwarding/tests.rs - Negative. C/S: route/neighbor/host-inbound tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage, but not Finding 2's exact non-unicast RX learn gap.
- userspace-dp/src/afxdp/forwarding_build/cos.rs - Negative. C/S: CoS forwarding build validates class state. MCI/R: config projection widths checked. vSRX: no parity gap. Perf: build path. Tests: forwarding build tests present.
- userspace-dp/src/afxdp/forwarding_build/fib.rs - Negative. C/S: FIB build handles routes/next-hops explicitly. MCI/R: index and depth handling checked. vSRX: no new parity gap. Perf: build path. Tests: forwarding build tests present.
- userspace-dp/src/afxdp/forwarding_build/interfaces.rs - Negative. C/S: interface/VLAN/source-MAC projection checked. MCI/R: ifindex/vlan widths checked. vSRX: no new parity gap. Perf: build path. Tests: interface build tests present.
- userspace-dp/src/afxdp/forwarding_build/mod.rs - Negative. C/S: forwarding-state assembly keeps validation centralized. MCI/R: no unsafe logic. vSRX: no new parity gap. Perf: cold build. Tests: covered by submodules.
- userspace-dp/src/afxdp/forwarding_build/tests.rs - Negative. C/S: build tests cover routes, interfaces, tunnels, WG. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/forwarding_build/tunnels.rs - Negative. C/S: tunnel endpoint build validates families, TTL, MTU, keys. MCI/R: integer projection checked. vSRX: no new parity gap. Perf: build path. Tests: tunnel tests present.
- userspace-dp/src/afxdp/forwarding_build/validated.rs - Negative. C/S: validated config wrappers fail closed on malformed inputs. MCI/R: conversions checked. vSRX: no parity gap. Perf: cold path. Tests: forwarding build tests cover validation.
- userspace-dp/src/afxdp/forwarding_build/wg.rs - Negative. C/S: WG forwarding build checks endpoint/family fields. MCI/R: widths and options checked. vSRX: no parity gap. Perf: build path. Tests: WG build tests present.
- userspace-dp/src/afxdp/forwarding_build/zones.rs - Negative. C/S: zone build preserves interface bindings. MCI/R: zone id widths checked. vSRX: no new parity gap. Perf: build path. Tests: forwarding build tests present.
- userspace-dp/src/afxdp/frame/build/ipv4.rs - Negative. C/S: IPv4 builders write lengths/checksums consistently. MCI/R: slice bounds and integer lengths checked. vSRX: no parity gap. Perf: no allocation. Tests: frame build tests present.
- userspace-dp/src/afxdp/frame/build/ipv6.rs - Negative. C/S: IPv6 builders write payload lengths consistently. MCI/R: length widths checked. vSRX: no parity gap. Perf: no allocation. Tests: frame tests cover consumers.
- userspace-dp/src/afxdp/frame/build/mod.rs - Negative. C/S: build module exports only checked helpers. MCI/R: n/a. vSRX: no parity gap. Perf: n/a. Tests: covered by submodules.
- userspace-dp/src/afxdp/frame/byte_writes.rs - Negative. C/S: byte write helpers preserve network order. MCI/R: slice bounds checked. vSRX: no parity gap. Perf: inlinable helpers. Tests: byte write tests present.
- userspace-dp/src/afxdp/frame/byte_writes_tests.rs - Negative. C/S: byte write regressions covered. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/frame/checksum.rs - Negative. C/S: checksum fast/scalar paths checked. MCI/R: AVX2 path feature-gated; scalar handles odd lengths. vSRX: no parity gap. Perf: SIMD fast path and no allocation. Tests: checksum coverage nearby.
- userspace-dp/src/afxdp/frame/generated.rs - Negative. C/S: generated packet structs/offsets checked for layout use. MCI/R: no unchecked deref found in reviewed surface. vSRX: no parity gap. Perf: POD layout. Tests: generated tests present.
- userspace-dp/src/afxdp/frame/generated_tests.rs - Negative. C/S: generated layout tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/frame/headers.rs - Negative. C/S: header writers guard buffer lengths and eth offsets. MCI/R: unsafe writes have slice-length preconditions. vSRX: no parity gap. Perf: no allocation. Tests: header tests present.
- userspace-dp/src/afxdp/frame/headers_tests.rs - Negative. C/S: header write tests cover IPv4/IPv6/UDP/TCP offsets. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/frame/inspect.rs - Finding 2 evidence; otherwise negative. C/S: parse bounds, fragment gates, ICMP/NDP checks reviewed. MCI/R: unaligned metadata read uses `read_unaligned`. vSRX: no parity gap. Perf: metadata fast path avoids extra parse. Tests: no exact non-unicast RX source learn test.
- userspace-dp/src/afxdp/frame/inspect_tests.rs - Negative. C/S: parser/inspect edge cases covered. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/frame/mod.rs - Negative. C/S: descriptor/frame copy helpers check same-UMEM-frame constraints. MCI/R: unsafe slice writes are guarded. vSRX: no parity gap. Perf: no allocation in common helper path. Tests: frame tests cover many paths.
- userspace-dp/src/afxdp/frame/prop_tests/inspect.rs - Negative. C/S: property tests cover inspect/parsing invariants. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/frame/prop_tests/mod.rs - Negative. C/S: property test module only. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: organizer.
- userspace-dp/src/afxdp/frame/prop_tests/oracle.rs - Negative. C/S: oracle supports parser/rewrite comparisons. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful test infra.
- userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs - Negative. C/S: rewrite properties checked. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/frame/prop_tests/segment.rs - Negative. C/S: segmentation properties checked. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/frame/prop_tests/strategies.rs - Negative. C/S: strategy generation supports malformed/truncated cases. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/frame/rewrite/ipv4.rs - Negative. C/S: IPv4 rewrite checks lengths, fragments, port availability. MCI/R: checksum/port writes bounded. vSRX: no parity gap. Perf: no allocation. Tests: rewrite props/tests cover.
- userspace-dp/src/afxdp/frame/rewrite/ipv6.rs - Negative. C/S: IPv6 rewrite checks extension/L4 offsets. MCI/R: writes bounded. vSRX: no parity gap. Perf: no allocation. Tests: rewrite props/tests cover.
- userspace-dp/src/afxdp/frame/rewrite/mod.rs - Negative. C/S: rewrite dispatcher preserves family/protocol gates. MCI/R: no unsafe logic beyond submodules. vSRX: no parity gap. Perf: inlinable dispatch. Tests: covered by submodules.
- userspace-dp/src/afxdp/frame/tcp.rs - Negative. C/S: TCP helper parsing/writes checked. MCI/R: bounds and flags accesses guarded. vSRX: no parity gap. Perf: no allocation. Tests: TCP tests present.
- userspace-dp/src/afxdp/frame/tcp_segmentation.rs - Negative. C/S: TCP segmentation handles GRE/WG modes and recomputes checksums. MCI/R: UMEM 4096 cap refuted length wrap risk. vSRX: no parity gap. Perf: per-segment bounded work. Tests: TCP segmentation tests/properties present.
- userspace-dp/src/afxdp/frame/tcp_tests.rs - Negative. C/S: TCP parser/segmentation tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/frame/tests.rs - Negative. C/S: broad frame parse/rewrite/forward tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: strong coverage, no exact Finding 2 case.
- userspace-dp/src/afxdp/frame/wg.rs - Negative. C/S: WG frame encap/decap and endpoint paths checked. MCI/R: inner length cap and scratch contracts checked. vSRX: no parity gap. Perf: scratch-buffer pattern avoids avoidable allocation. Tests: WG tests extensive.
- userspace-dp/src/afxdp/gre.rs - Finding 3. C/S: GRE checksum/key/family/ECN/MTU gates checked. MCI/R: no unsafe UB found. vSRX: no parity gap. Perf: per-packet Vec allocations in GRE encap/decap found. Tests: no allocation regression test.
- userspace-dp/src/afxdp/ha.rs - Negative. C/S: HA publication/failover hooks checked. MCI/R: shared state ownership checked. vSRX: no parity gap. Perf: control path. Tests: HA tests present.
- userspace-dp/src/afxdp/ha_tests.rs - Negative. C/S: HA failover/state tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/icmp.rs - Negative. C/S: ICMP error/reject helper checks source/destination validity. MCI/R: packet build bounds checked. vSRX: no parity gap. Perf: no allocation issue found. Tests: frame/icmp tests cover.
- userspace-dp/src/afxdp/icmp_embed/builders.rs - Negative. C/S: embedded ICMP builders checked for length/checksum. MCI/R: slice bounds checked. vSRX: no parity gap. Perf: no allocation concern. Tests: embed tests present.
- userspace-dp/src/afxdp/icmp_embed/mod.rs - Negative. C/S: embedded ICMP dispatcher preserves NAT/session match gates. MCI/R: offsets bounded. vSRX: no parity gap. Perf: bounded parse. Tests: embed tests present.
- userspace-dp/src/afxdp/icmp_embed/nat_match_v4.rs - Negative. C/S: IPv4 embedded NAT match checks family/protocol/ports. MCI/R: offset and checksum fields bounded. vSRX: no parity gap. Perf: no allocation. Tests: session/embed tests cover.
- userspace-dp/src/afxdp/icmp_embed/nat_match_v6.rs - Negative. C/S: IPv6 embedded NAT match handles extension/fragment gates. MCI/R: bounds checked. vSRX: no parity gap. Perf: no allocation. Tests: embed tests cover.
- userspace-dp/src/afxdp/icmp_embed/parse.rs - Negative. C/S: embedded packet parser length checks reviewed. MCI/R: offset arithmetic checked. vSRX: no parity gap. Perf: bounded work. Tests: embed tests cover.
- userspace-dp/src/afxdp/icmp_embed/return_resolution.rs - Negative. C/S: return resolution uses forwarding/dynamic-neighbor lookup fail-closed on miss. MCI/R: no unsafe logic. vSRX: no parity gap. Perf: cache-aware lookup. Tests: embed/session tests cover.
- userspace-dp/src/afxdp/icmp_embed/session_match.rs - Negative. C/S: embedded session matching preserves reverse/forward tuple semantics. MCI/R: key encoding checked. vSRX: no parity gap. Perf: no allocation concern. Tests: embed/session tests present.
- userspace-dp/src/afxdp/icmp_ptb.rs - Negative. C/S: packet-too-big handling checks MTU/family. MCI/R: integer and length checks sound. vSRX: no parity gap. Perf: cold/error path. Tests: PTB tests present.
- userspace-dp/src/afxdp/icmp_ptb_tests.rs - Negative. C/S: PTB edge cases covered. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/icmp_ratelimit.rs - Negative. C/S: ICMP rate limit gates error amplification. MCI/R: token/time math bounded. vSRX: no parity gap. Perf: cheap limiter. Tests: no new gap.
- userspace-dp/src/afxdp/mirror/fast_path.rs - Negative. C/S: mirror fast path does not alter forwarding verdicts. MCI/R: descriptor/frame access checked. vSRX: no parity gap. Perf: hot path bounded. Tests: no new gap.
- userspace-dp/src/afxdp/mirror/mod.rs - Negative. C/S: mirror module wiring checked. MCI/R: n/a. vSRX: no parity gap. Perf: n/a. Tests: covered by submodules.
- userspace-dp/src/afxdp/mirror/resolver.rs - Negative. C/S: mirror resolver fail-closed on missing target. MCI/R: resource/queue checks sound. vSRX: no parity gap. Perf: resolver path bounded. Tests: no new gap.
- userspace-dp/src/afxdp/mod.rs - Negative. C/S: global constants and module wiring checked. MCI/R: UMEM frame size and queue caps refute several truncation/resource concerns. vSRX: no parity gap. Perf: constants enforce fixed frame model. Tests: broad module tests.
- userspace-dp/src/afxdp/mpsc_inbox.rs - Negative. C/S: queue full/empty states explicit. MCI/R: lock-free per-slot sequence ordering uses acquire/release and single-consumer unsafe contract is documented. vSRX: n/a. Perf: cache-padded bounded ring. Tests: mpsc inbox tests present.
- userspace-dp/src/afxdp/mpsc_inbox_tests.rs - Negative. C/S: MPSC empty/full/drop tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: useful coverage.
- userspace-dp/src/afxdp/neg_neigh.rs - Negative. C/S: negative-neighbor cache checks real forwarding/dynamic neighbors before suppressing. MCI/R: cap and TTL checked. vSRX: no parity gap. Perf: bounded cache. Tests: no new gap.
- userspace-dp/src/afxdp/neighbor.rs - Negative. C/S: netlink neighbor monitor/dump/probe paths checked against known NUD/dedup findings. MCI/R: socket buffers, seq, and dynamic map updates checked. vSRX: no parity gap. Perf: monitor path bounded. Tests: neighbor tests nearby.
- userspace-dp/src/afxdp/neighbor_dispatch.rs - Finding 2. C/S: RX source-MAC learn has own-IP and MAC gates but lacks non-unicast IP gate. MCI/R: pair insert semantics checked. vSRX: no parity gap. Perf: cheap pre-check and bulk insert retained. Tests: own-IP test exists, non-unicast source test missing.
- userspace-dp/src/afxdp/neighbor_latency.rs - Negative. C/S: latency telemetry does not affect verdicts. MCI/R: atomic/counter use checked. vSRX: no parity gap. Perf: bounded telemetry. Tests: no new gap.
- userspace-dp/src/afxdp/neighbor_resolver.rs - Negative. C/S: resolver pending/probe behavior checked for bounded unresolved hops. MCI/R: queue cap and resource cleanup checked. vSRX: no parity gap. Perf: bounded async work. Tests: resolver coverage nearby.
- userspace-dp/src/afxdp/parser.rs - Negative. C/S: ARP/NDP/IP parser length and malformed cases checked. MCI/R: slice bounds checked. vSRX: no parity gap. Perf: no allocation. Tests: parser tests present.
- userspace-dp/src/afxdp/parser_tests.rs - Negative. C/S: parser malformed/truncated tests reviewed. MCI/R: n/a. vSRX: n/a. Perf: n/a. Tests: good coverage.
- userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs - Negative. C/S: cookie replies build only for valid contexts. MCI/R: frame build bounds checked. vSRX: no parity gap. Perf: rare path. Tests: poll descriptor tests cover related paths.
- userspace-dp/src/afxdp/poll_descriptor/debug_log_throttle.rs - Negative. C/S: debug logging cannot alter verdict. MCI/R: atomics checked. vSRX: n/a. Perf: throttle bounded. Tests: no new gap.
- userspace-dp/src/afxdp/poll_descriptor/filter.rs - Negative. C/S: filter pipeline checked for explicit permit/drop/reject path. MCI/R: TX pipeline buffers bounded. vSRX: no new parity gap. Perf: no per-packet allocation found. Tests: filter tests present.
- userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs - Negative. C/S: flow-cache hit validates neighbor epoch and decision state. MCI/R: atomics and descriptor writes checked. vSRX: no parity gap. Perf: hot path remains inlinable. Tests: flow cache tests present.
- userspace-dp/src/afxdp/poll_descriptor/mod.rs - Finding 1 call site; otherwise negative. C/S: main packet pipeline checked for fail-closed parse/forward/session paths. MCI/R: descriptor/UMEM accesses guarded. vSRX: no new parity gap. Perf: hot path largely no allocation; GRE exception in Finding 3. Tests: broad poll descriptor tests.
- userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs - Negative. C/S: NAT exception handling preserves explicit miss/drop paths. MCI/R: tuple fields checked. vSRX: no parity gap. Perf: no allocation concern. Tests: poll descriptor tests cover.
- userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs - Negative. C/S: reject reply generation validates protocol/family and embedded context. MCI/R: packet build bounds checked. vSRX: no parity gap. Perf: rare path. Tests: reject tests nearby.
- userspace-dp/src/afxdp/poll_descriptor/rx_telemetry.rs - Negative. C/S: telemetry metadata extraction does not alter verdict. MCI/R: UMEM metadata offset checked. vSRX: n/a. Perf: bounded telemetry. Tests: no new gap.
- userspace-dp/src/afxdp/poll_stages.rs - Finding 2 call site; otherwise negative. C/S: ARP/NDP learning has non-unicast and own-IP gates; stage ordering checked. MCI/R: dynamic-neighbor mutations go through guarded helpers. vSRX: no parity gap. Perf: staged parse avoids duplicate work. Tests: ARP/NDP tests strong; RX non-unicast source gap remains.
- userspace-dp/src/afxdp/rst.rs - Negative. C/S: TCP RST generation checks packet/protocol state. MCI/R: checksum and length writes bounded. vSRX: no parity gap. Perf: rare/error path. Tests: frame/RST related coverage nearby.
- userspace-dp/src/afxdp/session_delta.rs - Negative. C/S: session delta representation explicit. MCI/R: ring/counter widths checked by session manager. vSRX: no parity gap. Perf: POD command path. Tests: session glue tests cover overflow/drop behavior.
- userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs - Negative. C/S: synced delete removes explicit keys and handles misses. MCI/R: map/session state ownership checked. vSRX: no parity gap. Perf: command path. Tests: session glue tests cover.
- userspace-dp/src/afxdp/session_glue/commands/demote_owner_rgs.rs - Negative. C/S: owner RG demotion checks dynamic forwarding resolution. MCI/R: no unsafe logic. vSRX: no parity gap. Perf: command path. Tests: session glue tests cover.
- userspace-dp/src/afxdp/session_glue/commands/export_owner_rg_sessions.rs - Negative. C/S: export filters owner RG sessions explicitly. MCI/R: bounded iteration/drop handling checked. vSRX: no parity gap. Perf: command path. Tests: session glue tests cover.
- userspace-dp/src/afxdp/session_glue/commands/mod.rs - Negative. C/S: command module wiring only. MCI/R: n/a. vSRX: no parity gap. Perf: n/a. Tests: covered by command tests.

### A1-b3

- userspace-dp/src/afxdp/session_glue/commands/refresh_owner_rgs.rs: Reviewed HA owner-RG refresh flow. Re-evaluation gates HA-managed sessions on current active/replacement state and republishes under the same resolution contracts. No new finding.
- userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs: Reviewed peer-synced upsert, re-resolution, local-active guard, SNAT/NAT64 reservation, and publish ordering. Existing NAT64 reservation themes are deduped; no new finding.
- userspace-dp/src/afxdp/session_glue/mod.rs: Reviewed shared command application, lock recovery, session publish/delete, local delivery, lo0/input filter, and owner-RG export paths. Poison recovery and chunking were present. No new finding.
- userspace-dp/src/afxdp/session_glue/promote.rs: Reviewed transient-to-session promotion/purge behavior and active-owner checks. No new finding.
- userspace-dp/src/afxdp/session_glue/tests.rs: Reviewed tests for sync/upsert/promotion behavior. No new finding.
- userspace-dp/src/afxdp/sharded_neighbor.rs: Reviewed sharded neighbor map, generation checks, all-shard replacement, cacheline padding, and poisoning behavior. No new finding.
- userspace-dp/src/afxdp/sharded_neighbor_tests.rs: Reviewed coverage for generation and sharding behavior. No new finding.
- userspace-dp/src/afxdp/shared_ops.rs: Reviewed shared NAT/session/publish helpers, reverse prewarm, sync export, and poison recovery. Known NAT displacement/reservation classes are deduped. No new finding.
- userspace-dp/src/afxdp/shared_umem.rs: Reviewed shared-UMEM policy, sysfs owner/secondary role detection, eligibility, fallback to private UMEM, and logging. No new finding.
- userspace-dp/src/afxdp/test_fixtures.rs: Reviewed test helpers used by AF_XDP unit coverage. No new finding.
- userspace-dp/src/afxdp/tests.rs: Reviewed broader AF_XDP tests touched by this batch. No new finding.
- userspace-dp/src/afxdp/tunnel.rs: Reviewed local-origin tunnel source, TUN nonblocking reads/writes, endpoint Arc validation, parked endpoint behavior, GRE/WG encapsulation entry, HA gates, and CoS fail-closed behavior. Offset/pkt_len narrowing is bounded by buffer/parser constraints. No new finding.
- userspace-dp/src/afxdp/tunnel_tests.rs: Reviewed tunnel unit coverage for endpoint and packet behaviors. No new finding.
- userspace-dp/src/afxdp/tx/cos_classify.rs: Reviewed local generated-packet CoS classification, mirror/reserve handling, fallback demotion, frame allocation, and checked UMEM slice usage. No hot-path per-packet heap allocation in normal path. No new finding.
- userspace-dp/src/afxdp/tx/cos_classify_tests.rs: Reviewed CoS classify tests. No new finding.
- userspace-dp/src/afxdp/tx/dispatch/cos.rs: Reviewed CoS enqueue/fallback dispatch behavior and queue ownership assumptions. No new finding.
- userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs: Reviewed dispatch tests, including failure/recycle expectations. No new finding.
- userspace-dp/src/afxdp/tx/dispatch/mod.rs: Reviewed direct/copy/in-place/fabric redirect dispatch, PMTUD suppression, recycle behavior, and failure paths. Native GRE owned-frame layout was checked via a minimal contract read. No new finding.
- userspace-dp/src/afxdp/tx/dispatch/shared_recycle.rs: Reviewed shared recycle slot lookup, scan fallback, unknown-slot counters, and fail-closed drops. No new finding.
- userspace-dp/src/afxdp/tx/dispatch/slow_path.rs: Reviewed slow-path transmit fallback and recycle ownership. No new finding.
- userspace-dp/src/afxdp/tx/drain/mod.rs: Reviewed pending queue draining, prepared overflow recycling, CoS leftover scanning, local rescue, and bounded behavior. No new finding.
- userspace-dp/src/afxdp/tx/drain/phase_backup.rs: Reviewed backup drain retry-state restoration and queue wake behavior. No new finding.
- userspace-dp/src/afxdp/tx/drain/phase_shaped.rs: Reviewed shaped drain phase, bounded reingest, and non-CoS regression guard. No new finding.
- userspace-dp/src/afxdp/tx/drain/phase_trivial.rs: Reviewed trivial drain phase. No new finding.
- userspace-dp/src/afxdp/tx/drain/tests.rs: Reviewed drain tests. No new finding.
- userspace-dp/src/afxdp/tx/mod.rs: Reviewed TX module wiring. No new finding.
- userspace-dp/src/afxdp/tx/rings.rs: Reviewed completion drain, fill submit unwind, TX wake, and recycle sequencing. No new finding.
- userspace-dp/src/afxdp/tx/stats.rs: Reviewed sidecar timestamp stamp/reap logic and shared-UMEM out-of-bounds handling. No new finding.
- userspace-dp/src/afxdp/tx/tcp_segmentation.rs: Reviewed cold-path TSO segmentation, parser bounds, NAT/hop-limit/checksum updates, and unwind of prepared frames on early returns. No new finding.
- userspace-dp/src/afxdp/tx/test_support.rs: Reviewed TX test helpers. No new finding.
- userspace-dp/src/afxdp/tx/transmit/finalise.rs: Reviewed accepted-tail retry, recycle marking, and completion finalization. No new finding.
- userspace-dp/src/afxdp/tx/transmit/mod.rs: Reviewed local transmit batch staging, capacity/reserve checks, rollback, commit, stamping, and ring-full behavior. No new finding.
- userspace-dp/src/afxdp/tx/transmit/rewrite.rs: Reviewed rewrite path for staged prepared frames. No new finding.
- userspace-dp/src/afxdp/tx/transmit/stage.rs: Reviewed staging and bounds before UMEM writes. No new finding.
- userspace-dp/src/afxdp/tx/transmit/verify.rs: Reviewed prepared transmit verification and fail-closed drops. No new finding.
- userspace-dp/src/afxdp/tx/transmit/write.rs: Reviewed descriptor write/commit ordering and accepted-prefix semantics. No new finding.
- userspace-dp/src/afxdp/tx/transmit_tests.rs: Reviewed transmit tests for rollback/recycle paths. No new finding.
- userspace-dp/src/afxdp/types/cos.rs: Reviewed CoS runtime types, queue state, flow-fair boxed initialization, counters, and compile-time size/padding invariants. No new finding.
- userspace-dp/src/afxdp/types/cos_sojourn_tests.rs: Reviewed sojourn-time tests. No new finding.
- userspace-dp/src/afxdp/types/forwarding.rs: Reviewed forwarding state layout, GRE/WG endpoint indexes, route/neighbor/local ownership maps, and hot-path field contracts. No new finding.
- userspace-dp/src/afxdp/types/mod.rs: Reviewed metadata layout, compile-time offsets, pending-neighbor size guard, and shared owner-RG index container. No new finding.
- userspace-dp/src/afxdp/types/runtime.rs: Reviewed runtime/shared stat types and atomic snapshot behavior. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/backlog.rs: Reviewed backlog atomics, token bucket residual handling, CAS ordering, and bounded publish/update behavior. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/epoch.rs: Reviewed epoch padding and seqlock documentation. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs: Reviewed shared lease acquisition/release, u128 arithmetic, v8 tag checking, class/worker outstanding accounting, and seqlock snapshots. Known shared-lease design debts in the dedup index were not re-reported. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs: Reviewed shared CoS lease module wiring. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs: Reviewed equal-flow epoch publish guards and arithmetic bounds. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs: Reviewed v8 rotation scratch reuse, single-winner rotation, tag publish ordering, and no-heap hot path. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs: Reviewed extensive shared lease tests for v8, release recredit, no-tear snapshots, and concurrent release. No new finding.
- userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs: Reviewed vtime sentinel, live-vtime clamp, peer frontier max, and documented cross-slot non-atomicity. No new finding.
- userspace-dp/src/afxdp/types/tx.rs: Reviewed TX request/enum types and ownership contracts. No new finding.
- userspace-dp/src/afxdp/umem/debug_state.rs: Reviewed debug state helpers. No new finding.
- userspace-dp/src/afxdp/umem/mmap.rs: Reviewed mmap length/alignment overflow checks, zero-length rejection, checked slice access, and unsafe pointer contracts. No new finding.
- userspace-dp/src/afxdp/umem/mmap_tests.rs: Reviewed mmap tests. No new finding.
- userspace-dp/src/afxdp/umem/mod.rs: Reviewed WorkerUmem ownership, free-frame accounting, private vs shared usage, checked slices, and reserve behavior. No new finding.
- userspace-dp/src/afxdp/umem/profile.rs: Reviewed UMEM profile types. No new finding.
- userspace-dp/src/afxdp/umem/snapshot.rs: Reviewed UMEM snapshot helpers. No new finding.
- userspace-dp/src/afxdp/umem/tests.rs: Reviewed UMEM tests. No new finding.
- userspace-dp/src/afxdp/wg/allowed_ips.rs: Reviewed AllowedIPs trie behavior; existing overlap/misconfiguration/wrong-peer-wins class is deduped and not re-reported. No new finding.
- userspace-dp/src/afxdp/wg/cookie.rs: Reviewed responder cookie DoS mitigation, secret rotation, per-source buckets, reply build/decrypt, and cookie consumption. Finding 1 covers cookie-reply canonicality. No additional finding.
- userspace-dp/src/afxdp/wg/counters.rs: Reviewed WireGuard counter mapping and relaxed atomic use. No new finding.
- userspace-dp/src/afxdp/wg/dscp.rs: Reviewed DSCP helper masking and ECN handling. No new finding.
- userspace-dp/src/afxdp/wg/engine.rs: Reviewed encap/decap, session lookup, counter allocation, replay checks, AEAD error handling, zeroing plaintext on post-AEAD drops, AllowedIPs enforcement, and keepalive handling. No new finding beyond Finding 1's parser input.
- userspace-dp/src/afxdp/wg/engine_tests.rs: Reviewed engine tests including replay, malformed, expired, and allowed-IP behavior. No new finding.
- userspace-dp/src/afxdp/wg/framing.rs: Reviewed transport framing encode/parse. Finding 1 covers reserved-byte canonicality. No additional finding.
- userspace-dp/src/afxdp/wg/handshake.rs: Reviewed strict type parsing, length checks, MAC1 verification, and Noise message parsing. No new finding.
- userspace-dp/src/afxdp/wg/handshake_session.rs: Reviewed pending index reservation, peer re-checks under lock, anti-replay timestamp handling, PSK mixing, install/clear ordering, and RNG fallback. No new finding.
- userspace-dp/src/afxdp/wg/mod.rs: Reviewed module constants, exports, endpoint canonicalization, and protocol sizes. No new finding.
- userspace-dp/src/afxdp/wg/mss.rs: Reviewed WG overhead/MSS and inner MTU clamping helpers. No new finding.
- userspace-dp/src/afxdp/wg/peer.rs: Reviewed peer configuration/session containers and endpoint handling; duplicate public key rejection is enforced in config validation by the minimal contract read. No new finding.
- userspace-dp/src/afxdp/wg/scratch.rs: Reviewed worker scratch preallocation and single-threaded borrowing expectations. No new finding.
- userspace-dp/src/afxdp/wg/session.rs: Reviewed transport session state, replay window, counters, confirmation/expiry, and zeroization-sensitive paths. No new finding.
- userspace-dp/src/afxdp/wg/tai64n.rs: Reviewed monotonic TAI64N timestamping, carry behavior, whitening, and high-water hooks. Existing high-water reset finding is deduped and not re-reported. No new finding.
- userspace-dp/src/afxdp/wg/tests.rs: Reviewed WireGuard integration/unit tests in the module. No new finding.
- userspace-dp/src/afxdp/wg/timers.rs: Reviewed timer deadlines, endpoint-known gate, usable-session criteria, and rekey/keepalive action selection. No new finding.
- userspace-dp/src/afxdp/worker/bind_meta.rs: Reviewed binding metadata structure. No new finding.
- userspace-dp/src/afxdp/worker/bpf_maps.rs: Reviewed BPF map fd cache behavior and disabled sentinel. No new finding.
- userspace-dp/src/afxdp/worker/cos/interface_row.rs: Reviewed CoS interface status row aggregation. No new finding.
- userspace-dp/src/afxdp/worker/cos/mod.rs: Reviewed worker CoS reset, shared-exact eligibility, owner selection, and runtime rebuild behavior. Existing shared-lease design gaps are deduped. No new finding.
- userspace-dp/src/afxdp/worker/cos/queue_row.rs: Reviewed CoS queue status row saturation and sentinel behavior. No new finding.
- userspace-dp/src/afxdp/worker/cos/status.rs: Reviewed CoS status snapshot helpers. No new finding.
- userspace-dp/src/afxdp/worker/cos/tests.rs: Reviewed worker CoS tests for exact-service and reset behavior. No new finding.
- userspace-dp/src/afxdp/worker/cos_state.rs: Reviewed worker CoS state container. No new finding.
- userspace-dp/src/afxdp/worker/flow_cache_state.rs: Reviewed flow-cache state container and reset surface. Cached CoS filter safety was checked via minimal contract read. No new finding.
- userspace-dp/src/afxdp/worker/lifecycle.rs: Reviewed poll lifecycle, RX/TX sequencing, fill/recycle ordering, raw mmap pointer safety comment, and backpressure handling. No new finding.
- userspace-dp/src/afxdp/worker/loop_body/debug_report.rs: Reviewed debug reporting hooks. No new finding.
- userspace-dp/src/afxdp/worker/loop_body/mod.rs: Reviewed main worker loop, config refresh order, binding sweep, command drain, HA expiry gates, CoS rebuild/release, session export chunks, and zone counter flush order. No new finding.
- userspace-dp/src/afxdp/worker/loop_body/setup.rs: Reviewed setup path, pinning, TSC calibration, binding creation, and initial forwarding/CoS state. No new finding.
- userspace-dp/src/afxdp/worker/mod.rs: Reviewed worker creation, binding drop-order contract, fill/TX reserve initialization, shared-UMEM group fallback, XSK registration cleanup, and worker struct layout. No new finding.
- userspace-dp/src/afxdp/worker/scratch.rs: Reviewed worker scratch buffers and reuse contracts. No new finding.
- userspace-dp/src/afxdp/worker/telemetry.rs: Reviewed telemetry update state. No new finding.
- userspace-dp/src/afxdp/worker/timers.rs: Reviewed worker timer state. No new finding.
- userspace-dp/src/afxdp/worker/tx_counters.rs: Reviewed TX counter aggregation. No new finding.
- userspace-dp/src/afxdp/worker/tx_pipeline.rs: Reviewed TX pipeline state grouping. No new finding.
- userspace-dp/src/afxdp/worker/xsk_rings.rs: Reviewed XSK ring state grouping. No new finding.
- userspace-dp/src/afxdp/worker_queue.rs: Reviewed worker command queue, poison recovery, and nonblocking lock behavior. No new finding.
- userspace-dp/src/afxdp/worker_queue_tests.rs: Reviewed poison-recovery and queue behavior tests. No new finding.
- userspace-dp/src/afxdp/worker_runtime.rs: Reviewed runtime seqlock writer/reader ordering, thread id sampling, CPU time sampling, and no-tear snapshot behavior. No new finding.
- userspace-dp/src/afxdp/worker_runtime_tests.rs: Reviewed runtime snapshot and concurrent no-tear tests. No new finding.
- userspace-dp/src/afxdp/zone_counters.rs: Reviewed zone counter slot maps, counter recording, and flush usage. Potential reload mismatch was refuted by worker loop refresh/sweep/flush ordering. No new finding.

### A1-b4

- `event_stream/*`: Reviewed codec framing, replay buffer, write budget, producer rollback, control-frame payload cap, slow-consumer handling, and tests. Negative result: fixed-size frame buffers and sequence/budget rollback paths are explicit; no unbounded per-event allocation or replay poisoning issue found.
- `filter/*`: Reviewed compiler, term model, match/eval engine, cache-sensitive flags, policer state, and TX selection. Negative result: missing filter/policer refs fail closed, impossible protocol-plus-port/flags/ICMP combinations reject at compile time, DSCP is range-checked, flex-match lengths are checked, and cached match metadata carries the cache-sensitive fields.
- `policy.rs`, `policy_snapshot_error.rs`, `policy_tests.rs`: Reviewed snapshot parse, address-book family checks, duplicate rule handling, app/ICMP validation, default policy, host policy, fragment handling, and counters. Negative result: malformed v3 address/book/app cases reject before install; default-policy and fragment deny fail-closed behavior are present. Prior host-inbound/default-policy gaps are covered in the dedup index.
- `screen/*`: Reviewed extractors, stateless checks, rate counters, SYN-rate sketch, syncookie cache, profile update, flowless screen path, and scan/sweep trackers. Negative result except the finding below: IPv4/IPv6/TCP/extension parsing is bounded, rate state is bounded and seeded, syncookie cache is fixed-size with TTL/key generation, and flowless source-independent screen/rate checks remain active.
- `session/*`: Reviewed key shape, entry metadata, lookup indexes, install, expiry wheel, TCP promotion/close paths, session-limit counters, and tests. Negative result: reverse/translated/forward-wire secondary indexes validate handles before use; removal cleans per-handle indexes; timer wheel is key-based; TCP opening/closing/RST timeout handling and companion cleanup are explicit.
- `io_uring_write.rs`, `slowpath.rs`, `state_writer.rs`: Reviewed packet-fd write semantics, TUN reinjection, io_uring fallback, MTU gates, rate limiting, and state persistence. Negative result: partial packet writes are treated as drops, partial io_uring transfer does not sync-retry, state writes use private temp files plus fsync/atomic rename, and stale temp cleanup uses pid plus process start time.
- `xsk_ffi.rs`: Reviewed unsafe ring reservations, UMEM frame bounds, RX/TX/fill/completion RAII paths, and partial reserve semantics. Negative result: checked frame offsets and reservation wrappers prevent overrun of rings/UMEM in the reviewed Rust surface; constructor assumptions are not attacker-controlled in this batch path.
- `userspace-xdp/src/lib.rs`: Reviewed native XDP parse/redirect path, metadata writes, fallback/degraded behavior, trace gating, native GRE inner classify, session/DNAT lookup, and parser helpers. Negative result: IPv4 IHL/TCP data-offset and IPv6 extension walks are bounded, parse failure drops transit in degraded path, trace map writes are gated by TRACE, and the ifindex/binding dense-index concern is already covered by current MAX_INTERFACES wiring and cap tests outside this Rust batch.
- `protocol/*`: Reviewed DTO defaults/null-tolerant vectors, security snapshot fields, application/filter/policy wire fields, resolution/status surfaces, and snapshot versioning. Negative result: schema compatibility defaults are explicit; no packet-path memory-safety issue found in these DTOs.
- `server/*`: Reviewed request dispatch, request size cap, snapshot apply/bump, worker binding plan, export off-lock split, socket lifecycle, and tests. Negative result: control requests are read with `MAX_CONTROL_REQUEST_BYTES`, snapshot apply has policy preflight and rollback on forwarding build failure, FIB rollback is rejected, and blocking session exports run after releasing the global state lock.
- `fairness.rs`, `fairness_eval/*`, `tests/fairness_eval_blackbox.rs`, `bin/fairness-eval.rs`: Reviewed offline fairness math, window extraction, RSS expectations, stale overcount guard, and black-box tests. Negative result: this is not a packet hot path; out-of-range worker IDs, truncated windows, stale-overcount normalization, and RSS expectation failures are covered by checks/tests.
- `hot_hash_seed.rs`, `ip_proto.rs`, `prefix.rs`, `prefix_set.rs`, `tcp_flags.rs`, small tests/guards: Reviewed entropy fallback, protocol token mapping, prefix-set trie/linear membership, and TCP flag helpers. Negative result: no unchecked packet memory access; protocol name parsing and prefix semantics are centralized and tested.

### A10-b1

**Retired BPF headers (`xpf_common.h`, `xpf_conntrack.h`, `xpf_helpers.h`, `xpf_maps.h`, `xpf_nat.h`, `xpf_trace.h`).** Correctness/security/fail-open: checked packet bounds, IPv4/IPv6 byte order, extension walking, reverse-key initialization, NAT checksum updates, map-miss behavior, policy/filter defaults, HA watchdog handling, and trace gating. Safety/performance: loops are statically bounded, packet accesses are verifier-guarded, maps/counters are fixed-capacity or LRU/per-CPU, and tracing compiles out. The orientation establishes that these headers are not the runtime forwarding dataplane, so dormant legacy defects (including the six-extension-header ceiling, permissive old filter map-miss behavior, and the old `u8` session flag field being unable to retain `SESS_FLAG_NPTV6`) were not promoted as production findings. vSRX/modularity/tests: these files retain broad legacy feature/layout coupling and have no standalone tests in the batch; reviving them would require a fresh design and verifier/runtime audit, not parity fixes here.

**Remote CLI mutation and lifecycle (`clear.go`, `main.go`, `request.go`, `shared.go`).** Correctness/security/fail-open: traced every destructive RPC, confirmation gate, config-mode transition, typed selector, pipe dispatcher, and cancellation path. Findings H01, M01-M04, L01, and the integer companion in M03 are in this group. `clear security flow session` is a verified negative: unknown/value-less filters error before an empty clear-all request. Safety/performance: command context access is mutex-protected and monitor/stream contexts are cancelled, but pipe output is fully buffered and local file loads are unbounded; the already-indexed `showSessionsTop` memory root cause was suppressed. vSRX/modularity/tests: the hand-written grammar is inconsistent with the canonical command tree; tests cover non-TTY destructive guards and malformed rollback tokens but omit commit grammar, successful-integer overflow, DHCP selector arity, failover selector arity, and terminal interruption.

**Remote monitor (`monitor.go`, `main_test.go`, `monitor_keyreader_4694_test.go`).** Correctness/security/fail-open: interactive mode switching uses generation tags so stale frames are discarded, and stream contexts are cancelled. Safety/performance: frame/key channels are bounded; raw TTY `VMIN=0/VTIME=1` plus `stopKeys` closes the prior leaked-reader window. The malformed packet-drop port/count parser remains, but its root cause matches indexed F-038-014 and was suppressed. vSRX/modularity/tests: monitor traffic/flow remain local-only by explicit design; key lifecycle tests are strong, while no test drives rapid stream churn or malformed packet-drop selectors end to end.

**Remote show surfaces (`show.go`, `show_dhcp.go`, `show_flow.go`, `show_interfaces.go`, `show_nat.go`, `show_protocols.go`, `show_security.go`, `show_services.go`, `show_system.go`).** Correctness/security/fail-open: traced structured RPC projections, policy/global/default tier rendering, host-inbound effective unions, NAT identity/counters, session filters, rollback views, DHCP lease/delegated-prefix display, DDNS status topics, and protocol/system dispatch. Findings M05 and L03 are here; M03 also recurs in show-only rollback indices and session limits. Safety/performance: ordinary lists stream directly to stdout, but maps make some row order nondeterministic and top-talker aggregation is the indexed unbounded-work duplicate. vSRX/modularity/tests: policy/zone parity tests are extensive, but no remote NAT summary test uses a named pool with hits, and no strict parser tests cover policy inventory selectors.

**Remote CLI regression tests (`nontty_test.go`, `policymatch_dup_3709_test.go`, `query_strictness_3696_test.go`, `request_wireguard_test.go`, `rollback_3447_test.go`, `show_events_zone_3547_test.go`, `show_flowsession_3439_test.go`, `show_matchpolicies_port_3354_test.go`, `show_matchpolicies_test.go`, `show_policies_metadata_3672_test.go`, `show_policies_scoped_global_3357_test.go`, `show_wireguard_test.go`, `show_zones_hostinbound_3654_test.go`, `show_zones_polerr_3669_test.go`, `show_zones_tiers_3683_test.go`, `testpolicy_port_test.go`, `testpolicy_protocol_test.go`, `testpolicy_srcport_test.go`, `usage_matchpolicies_3628_test.go`).** Correctness/security/fail-open: all were read and executed. They pin strict policy/session selectors, no-RPC rejection paths, zone policy metadata/tier visibility, host-inbound output, and malformed rollback strings. Safety/performance: race execution passed; test helpers only buffer small bounded outputs. vSRX/modularity/tests: tests call handlers directly, which misses the offline WireGuard entrypoint defect, and the rollback table uses a value too large for `int` rather than values that fit `int` but overflow `int32`.

**Verifier wrapper (`cmd/shimverify/main.go`).** Correctness/security/fail-open: exact argument count is required, verifier rejection has a distinct exit code, and no production map/attach state is touched through the called verifier contract. Safety/performance: single bounded object verification, no concurrency. vSRX/modularity/tests: no command-package tests; behavior is a build/deploy guard rather than a vSRX feature. No finding.

**Daemon entrypoint and upgrade verbs (`cmd/xpfd/main.go`, `publish_generation.go`, `seed_runtime.go`, `upgrade.go`, `upgrade_kernel.go`).** Correctness/security/fail-open: traced subcommand dispatch, config-check limits and device-map preflight, upgrade locks, rolling-vs-standalone routing, journal source protection, kernel arm/promote/status/drain/rejoin, and exit-code contracts. Findings H02, M06, and L02 are here. Safety/performance: these are cold paths with host-wide locks and bounded deadlines; no dataplane hot-path cost. vSRX/modularity/tests: `cmd/xpfd` has no tests, while called `pkg/upgrade/...` tests pass but do not exercise leftover CLI arguments or journal-read-error GC from this wrapper.

**VDSO probes (`vdso_probe.c`, `vdso_probe2.c`).** Correctness/security/fail-open: both check errors and return nonzero on failure. Safety/performance: fixed 10,000-iteration probe and one aux-vector lookup, with no allocation loop or packet-path linkage. vSRX/modularity/tests: evidence-only utilities; both pass `gcc -O2 -Wall -Wextra -Werror -fsyntax-only`. No finding.

- DDNS ownership invariant checked: `request system dynamic-dns update|check` maps to the intended force boolean, the server returns Unavailable when the engine is absent, and the called manager contract preserves the per-RG active-writer gate. No ownership bypass found.
- DHCP display invariant checked: remote lease rendering includes delegated prefixes and both preferred/valid lifetimes. The assigned omission is confined to malformed clear selector parsing in M02.
- Session clear invariant checked: every value-taking filter errors on a missing value, unknown filters error, ports are bounded to 1..65535, and an accidental empty clear-all request is prevented.
- Policy simulator invariant checked: both remote match-policies and test-policy paths use the strict shared parser for missing, duplicate, malformed IP/port/protocol/ICMP selectors. Existing route-drop and host-inbound verdict advisories are rendered from shared server strings.
- Host-inbound policy/zone rendering checked: structured system-services/protocols, interface overrides, lifeline exemptions, zone/global/default tiers, scheduler/inactive metadata, exclusion sense, logging mode, and counters are surfaced. Prior host-inbound findings in the dedup index were not re-reported.
- Monitor stdin-reader leak was directly rechecked and is fixed by poll-mode termios plus a stop-and-wait lifecycle; race tests pass. The prior indexed leaked-reader finding is suppressed as fixed.
- `monitor security packet-drop` still silently ignores malformed/overflowed ports/counts, but this matches indexed F-038-014 (remote monitor port validation) and was suppressed rather than duplicated.
- `show security flow session sort-by` still reaches whole-table top-talker aggregation; the supplied index already records unbounded `showSessionsTop` memory/CPU and it was suppressed.
- BPF header defects were not reported as production dataplane issues because the orientation makes the Rust AF_XDP dataplane the only runtime forwarding path. No recommendation revives retired eBPF behavior.
- Upgrade lock acquisition/release, kernel arm/promote error-code separation, drain/rejoin calls, cold-path sample-mask validation, shim verifier exit codes, and VDSO probe error handling were checked with no additional finding.

### A10-b2

- `app_resolve.go`, `proto.go`, `session_display.go`: checked protocol/application inversion, byte order, integer casts, display identity, and live call reachability. The `uint16` port cast in unused `matchApp` and incomplete inverse protocol naming match prior dedup roots and were not re-reported. Session endpoint/VLAN formatting is bounded and byte-order aware.
- `apply.go`, `cli_config.go`, `cli_helpers.go`, `runtime.go`: checked commit/apply ordering, standalone fallback, fail-open handling, rollback/confirm semantics, config redaction helpers, and runtime capability adapters. Daemon commits use the injected atomic callbacks. The interface-monitor `Up: true` status fallback is already indexed and suppressed. One new low grammar issue is F19.
- `cli.go`, `cli_dispatch.go`, `completion.go`, `link.go`: checked command resolution, RBAC-before-dispatch, pager/pipe ownership, global I/O mutation, signal/readline goroutine lifetime, completion bounds, and shell argument construction. Completion bounds regressions are covered; pager capture is F7.
- `cli_clear.go`, `session_filter.go`: checked every filter token, clear-all prevention, zone/interface/NAT/application matching, network-order ports, reverse/DNAT companion deletion, peer propagation, iterator errors, memory growth, and partial-failure reporting. Existing tests cover parse fail-closed and reverse keys; F3 and F6 remain.
- `cli_request.go`, `cli_request_ping.go`, `cli_request_security.go`, `cli_request_testcmd.go`: checked dispatch, argv option termination, VRF normalization, policy simulator strictness, ICMP/source-port parity, routing diagnostics, WireGuard key generation, and command cancellation. Ping/traceroute negative numeric handling shares the indexed remote-diagnostic root and was suppressed; policy simulators use the strict shared parser and scheduler/feed overlays.
- `cli_request_chassis.go`, `cli_request_system.go`, `permissions.go`: checked maintenance classification, abbreviation parity, confirmation, peer routing, userspace control verbs, ISSU, rescue/DDNS, zeroize durability, and predefined/custom class resolution. F1 and F2 are new; prior F21 is fixed only for its originally enumerated verbs.
- `cli_request_policies_check.go`: checked shadow/redundancy logic, exclusions, schedules, globals, and conservative failure behavior. It remains intentionally heuristic and does not certify dataplane equivalence; broader policy-check completeness is already represented in the dedup index.
- `cli_show.go`, `cli_show_shared.go`, `cli_show_chassis.go`, `cli_show_cluster.go`: checked dispatch guards, chassis/forwarding adapters, HA status, fabric counters, interface monitor presentation, VRRP joins, and error surfacing. Counter read failures warn. F18 is the remaining logical-interface join error.
- `cli_show_flow.go`: checked v4/v6 filtering, summary/brief/full rendering, NAT tuple display, application/policy identity, HA ownership, peer limits/errors, iterator failures, top-talkers work, and cluster parity. Unbounded top-talkers is indexed and suppressed; F4 and F5 remain.
- `cli_show_interfaces.go`, `cli_show_interfaces_detail.go`, `cli_show_interfaces_extensive.go`, `cli_show_interfaces_shared.go`, `cli_show_interfaces_stats.go`, `cli_show_interfaces_terse.go`: checked authored/logical/kernel name conversion, RETH/member resolution, VLAN IDs, addresses, zone/host-inbound joins, DHCP annotations, statistics, filtering, unzoned interfaces, and absent netdev behavior. RETH tests are strong; normal logical/kernel identity remains inconsistent in F9.
- `cli_show_nat.go`: checked source/destination/static/NPTv6/persistent views, counter IDs, iterator failures, pool arithmetic, ordering, and userspace parity. Per-zone-pair counts being repeated as per-rule/rule-set counts is already indexed and suppressed; iterator errors now warn.
- `cli_show_routing.go`, `chrony.go`, `peer.go`: checked route/instance/RIB/BGP/OSPF/RA views, FRR fixed-command boundaries, raw neighbor handling, time status, peer timeout/VRF binding, and address-family formatting. Raw BGP command injection is indexed. F16 and F17 remain.
- `cli_show_security.go`, `cli_show_security_dispatch.go`, `cli_show_security_filters.go`, `cli_show_security_ipsec.go`, `cli_show_security_log.go`, `cli_show_security_objects.go`, `cli_show_security_screen.go`, `cli_show_security_wireguard.go`, `cli_show_security_zones.go`: checked policy tier/order/IDs/schedules/exclusions/log/count, strict diagnostics, counter gates/errors, zones/host-inbound, screen inventory, alarms, runtime/config absence, IPsec/WireGuard status, feeds, firewall filters, and secret redaction. Indexed flat-policy omissions and hardcoded ALG parity were suppressed. F12 and F15 remain.
- `cli_show_services.go`, `show_services_cos.go`, `show_services_ddns.go`, `show_services_dhcp.go`, `show_services_lldp.go`, `show_services_mirror.go`, `show_services_snmp.go`: checked service dispatch, runtime/config joins, lease parsing/errors, DUID identity, DDNS ownership/error state, LLDP untrusted text, CoS/mirror counters, and SNMP secrets. LLDP strings are sanitized at parse time and SNMP communities are class-redacted. F13 and F14 remain.
- `cli_show_system.go`: checked proc/sysfs arithmetic, external command argv, redaction, journal/history, rollback/rescue, filesystem information, connection/process views, log file selection, and output bounds. F8 remains.
- `monitor.go`, `monitor_interface.go`, `monitor_traffic.go`: checked atomic parser updates, traversal/symlink/mode protections, rotation, subscription lifetime, writer failure, stale display, key-reader teardown, tcpdump option termination, count bounds, cancellation, and fail-open query behavior. Indexed root file-write privilege and multi-token truncation are suppressed; F10 and F11 are distinct residuals.

Test module log:

- Apply/config/clear tests read in full: `apply_syslog_zonemap_3704_test.go`, `cli_activate_test.go`, `cli_clear_errors_test.go`, `cli_clear_reversekey_test.go`, `cli_commit_confirm_pending_4000_test.go`, `cli_commit_test.go`, `cli_config_test.go`, `cli_rollback_3447_test.go`, `configstore_helper_test.go`. They pin zonemap propagation, activate/deactivate, reverse-key deletion, surfaced partial failures, atomic commit callbacks, pending-confirm behavior, retired backends, and strict rollback. No test covers invalid `commit confirmed` duration.
- Request/RBAC/cluster tests read in full: `cli_request_argv_test.go`, `cli_request_policies_check_test.go`, `cli_request_wireguard_test.go`, `cluster_failover_test.go`, `permissions_custom_class_4304_test.go`, `permissions_maintenance_4108_test.go`, `permissions_monitor_traffic_4067_test.go`. They pin argv separators, VRF normalization, policy lint basics, key generation, failover routing, destructive verbs already enumerated, and monitor-traffic control permission. The RBAC tests explicitly exercise `forwarding arm`, not `disarm`, queue/binding teardown, or ISSU failover.
- Flow/session tests read in full: `cli_show_flow_test.go`, `session_display_test.go`, `session_filter_test.go`, `sessions_iterator_error_test.go`. They pin formatting, byte order, source-NAT pools, filter parse errors, peer filter serialization, and iterator errors. Their interface fixture has exactly one interface per zone; no test covers multi-interface ingress, per-RG HA labels, filtered peer summary, peer sentinel totals, or high-cardinality clear memory.
- Interface/chassis tests read in full: `cli_show_chassis_adapter_test.go`, `cli_show_cluster_test.go`, `cli_show_interfaces_reth_4328_test.go`, `host_inbound_display_3654_test.go`. They pin userspace status projection, fabric counters, RETH synthesis, one slash-to-kernel summary case, and host-inbound posture. They do not cover slash-form `detail`/`extensive`, non-RETH VLAN address lookup, unzoned summary inventory, VLAN zone columns, or logical VRRP joins.
- NAT tests read in full: `cli_show_nat_shared_test.go`, `cli_show_nat_test.go`. They pin shared renderer equality, apply-result snapshotting, and deterministic fixture counters; no new NAT root survived deduplication.
- Policy/security tests read in full: `cli_matchpolicies_scheduler_3414_test.go`, `cli_show_policies_bulk_reader_test.go`, `cli_show_policies_hitcount_gate_test.go`, `cli_show_policies_scheduler_3062_test.go`, `cli_show_policies_thencount_3074_test.go`, `cli_show_security_flat_zone_local_3358_test.go`, `cli_show_security_log_argparse_3347_test.go`, `cli_show_security_log_historical_zone_3335_test.go`, `cli_show_security_log_negative_3342_test.go`, `cli_show_security_nil_3476_test.go`, `cli_show_security_policy_addr_excluded_3336_test.go`, `cli_show_security_policy_index_3063_test.go`, `cli_show_security_scoped_global_3286_test.go`, `cli_show_security_scoped_global_3357_test.go`, `cli_show_security_screen_inventory_3327_test.go`, `cli_show_security_test.go`, `cli_show_security_wireguard_test.go`, `cli_show_security_zone_local_3358_test.go`, `cli_show_security_zones_explicit_any_3680_test.go`, `cli_show_security_zones_metadata_3684_test.go`, `cli_show_security_zones_policy_tiers_3658_test.go`, `policymatch_dup_3709_test.go`, `policymatch_feed_overlay_test.go`, `policymatch_port_test.go`, `policymatch_protocol_test.go`, `query_strictness_3696_test.go`, `show_security_counter_error_test.go`, `testpolicy_icmp_4497_test.go`, `testpolicy_idscope_3674_test.go`, `testpolicy_srcport_test.go`, `usage_matchpolicies_3628_test.go`, `zone_flood_counters_hide_test.go`. These strongly cover strict simulator input, scheduler fail-closed matching, feed overlays, policy IDs/tiers/scopes/exclusions/counts, nil tolerant slots, historical names, screen inventory, counter errors, and usage. They do not test the loose inventory-only zone parser or cumulative-vs-active alarm semantics.
- Config/system/service tests read in full: `cli_show_config_redaction_4099_test.go`, `cli_show_services_test.go`, `cli_show_snmp_community_redaction_4111_test.go`, `cli_show_system_buffers_test.go`, `cli_zone_nil_3493_test.go`. They pin secret redaction, RPM fallback, userspace buffers, and nil-zone safety. There is no local zeroize filesystem test, arbitrary-log allowlist test, DHCP lease read-error test, or DHCPv6 DUID display test.
- Completion tests read in full: `completion_activate_test.go`, `completion_panic_test.go`, `completion_typed_leaf_test.go`. They pin schema parity, overtyped suffix bounds, and typed-leaf examples. Cursor bounds rely on readline's valid-position contract; no credible new crash was found.
- Monitor tests read in full: `monitor_interface_stdin_3985_test.go`, `monitor_match_test.go`, `monitor_nil_eventbuf_3381_test.go`, `monitor_security_test.go`, `monitor_test.go`, `monitor_traffic_count_bound_4589_test.go`, `monitor_traffic_filter_4005_test.go`, `monitor_traffic_injection_4524_test.go`, `monitor_traffic_keyword_4540_test.go`, `monitor_traffic_quotestrip_4556_test.go`. They pin key-reader drain, regex compilation, nil buffer handling, path/mode/symlink/rotation hardening, filter atomicity, count limits, full BPF expressions, and tcpdump option neutralization. They do not cover an empty `matching` clause, unknown top-level traffic token, or writer-error state cleanup.

### A10-b3

- `pkg/ddns` (all 44 listed production/test files): swept backend construction, source binding, HTTP/TLS behavior, response parsing, exact-record ownership, forward/PTR ordering, write-ahead state, Surface A/B scope gates, provider transitions, lock/I/O boundaries, integer bounds, cache reaping, and tests. New issues are H03, H04, M03-M06, L08, and L09. Negative invariants checked: RFC2136 message IDs and TSIG errors propagate; HTTP bodies are bounded; malformed source binds fail closed on current paths; generic URL port-only-host rejection is pinned; address-family parsing and DHCID scope keys do not cross families; Surface A observation is outside the manager lock at this SHA. Known provider-transition, checkip, whole-RRset, and sibling-family findings in `codex-review-157`, `codex-review-172`, and `opus-review-172` were dedup-suppressed rather than repeated. There is no packet hot path in this package.
- `pkg/devicemap` (both files): swept identity precedence, ambiguity refusal, duplicate claims, PCI/MAC normalization, deterministic output, live inventory error handling, and tests. PCI-hit/MAC-mismatch and duplicate-identity cases fail closed. M09 is the remaining inventory-completeness gap for non-PCI devices.
- `pkg/dhcp` (all 12 files): swept client registration/reconcile locking, v4/v6 acquisition/renew/rebind state, DUID persistence and clearing, netlink address/route application, classless routes, IA_NA selection, IA_PD storage, callbacks, timers, retries, and tests. Classless-route bounds, IA_NA address/lifetime pairing, NAK deconfiguration, and reconcile cancellation are pinned. New issues are H01, M01, M02, L03, and L04. The prior option-121 and IA_NA-last-entry findings are fixed at this SHA.
- `pkg/dhcprelay` (all 9 files): swept socket lifecycle, hop-count and relay-reply validation, giaddr selection, Option 82, L2 frame construction, short writes/errors, counters, and cancellation. Server-origin validation and maximum-hop enforcement are present; the known option-set parity limitations remain dedup context. Only L06 was new.
- `pkg/dhcpserver` (all 11 files): swept generated Kea JSON, systemd lifecycle, async coalescing, destructive DDNS lease parsing, reservation/expiry rendering, control-socket protocol, memfile fallback/seeding, HA lifetime conversion, atomic writes, and tests. New issues are H02, H05, H06, M05-M07. JSON generation and family-specific reservation/expired-lease knobs are covered; socket reads/writes have deadlines and framed response limits. The lease-sync path remains cold control-plane work, but its full-set operations must stay bounded.
- `pkg/diagcmd` (both files): swept argv tokenization, VRF prefix normalization, target option termination, and exact-argv tests. The target is always placed after `--`, command execution is argv-based rather than shell-based, and `vrf-` normalization prevents a leading-option device token. No new finding.
- `pkg/fairness` (both files): swept grammar normalization, numeric range/NaN/Inf handling, uint accumulation, zero-flow behavior, canonicalization, and tests. Parsing rejects non-finite/out-of-range thresholds and evaluation accumulates flows in `uint64`; the previously reported expectation-parser issues are fixed. No new finding.
- `pkg/fsatomic` (all 3 files): swept temp-file creation, mode/owner preservation, symlink resolution, rename/fsync ordering, cleanup, directory durability, concurrent writers, and injected failures. The writer itself preserves its documented atomic/durable invariants; M04 is a DDNS caller selecting plain `MkdirAll`. The repo-walking canary test was intentionally not executed because it would inspect source outside this batch; focused writer tests passed.
- `pkg/fwdstatus` (all 7 files): swept `/proc` parsing, cgroup limits, CPU ring ordering, counter resets, heartbeat state, userspace status consumption, formatting, integer conversion, and tests. Missing `/proc` and userspace status errors yield Unknown and counter decreases invalidate windows. M08 and L02 remain; no per-packet work is introduced.
- `pkg/ipmon` (all 4 files): swept probe result state transitions, hysteresis, actuation retries, lock/goroutine lifecycle, next-hop matching, rendering, and tests. Failed actuations retry without falsely promoting state, Stop/Start lifecycle is serialized, and prior findings in `codex-review-160` are fixed/pinned. No new finding.
- `pkg/linuxsock` (all 3 files): swept socket flag composition and tests. `SOCK_CLOEXEC` is applied atomically at creation and direct-socket canary intent is sound. The repo-walking canary was not executed due batch isolation; focused socket tests passed. No new finding.
- `pkg/lldp` (all 3 files): swept raw-socket lifecycle, packet type filtering, mandatory TLV parsing, TLV length caps, string sanitization, neighbor caps, concurrent Apply generations, expiry, frame construction, and tests. Truncation and oversized identities fail closed and sessions close descriptors on replacement. L05 is the remaining shutdown-TTL behavior gap.
- `pkg/monitoriface` (both files): swept interface enumeration/aliasing, physical-parent resolution, userspace/kernel counter composition, reset-safe deltas, rate timing, formatting, and tests. Counters use reset-safe subtraction, list output is stable, and absent userspace telemetry does not fabricate userspace totals. No new finding.
- `pkg/natpoolalarm` (all 4 files): swept coherent-view gating, raise/clear hysteresis, invalid thresholds, unavailable-data hold behavior, renderer determinism, goroutine lifecycle, and tests. Alarm transitions are stable and unavailable samples do not clear active alarms. L07 is a concurrent lifecycle race not covered by the sequential idempotence test.
- `pkg/natshow` (all 6 files): swept source/destination/static/persistent rendering, byte order, v4/v6 handling, nil/unloaded behavior, session counting, deterministic projections, and tests. IPv6 persistent rendering no longer assumes `As4`, and known per-rule session-count findings were deduped. L01 remains at the called persistent-table snapshot contract.
- `pkg/nftables` (all 5 files): swept counter-name encode/decode, malformed object filtering, table absence/error distinction, RST suppression family/offset expressions, atomic replace planning, empty-plan deletion, and tests. Install errors propagate and delete/add is one netlink flush; no new finding. `RemoveRSTSuppression` is currently uncalled, so its void best-effort API was logged as a dormant design gap rather than reported.

### A10-b4

1. **Policy simulator and zone detail (34 files):** Read the matcher and every assigned regression test. Exact, single-wildcard, both-wildcard, global, and default transit tiers are fail-closed for undefined zones; host-inbound and transit queries remain separated; malformed selector values and omitted protocols/ports are rejected or represented consistently. Finding A10-b4-14 is the one display/runtime divergence: wildcard zone-pair rules are filtered and ordered differently in zone detail. The previously cataloged explicit-`any` global-summary issue is fixed and was not re-filed.
2. **Scheduler (5 files):** Checked local-time conversion, epoch replacement, callback cancellation, nil/empty schedule handling, and scheduler-state republish behavior. Replacing a schedule invalidates stale timer callbacks and does not create an overlapping publisher. The known per-day overnight-tail limitation is already in coordinator history and was suppressed.
3. **Binary upgrade, generations, manifests, and locks:** Checked generation pinning, path/version validation, cutover rollback, refusal behavior, crash journals, lock serialization, manifest drift, runner cleanup, and image-version ordering. Generation publication is atomic and readers stay pinned; failed mutations do not silently advance current generation. No new issue outside the kernel-specific findings below.
4. **Kernel upgrade and HA recovery:** Traced preflight, install, arm, BootNext, promotion, revert, drain/rejoin, lease, and self-recovery state transitions. Findings A10-b4-02, -11, -12, and -27 cover ambiguous boot cleanup, watchdog fail-open behavior, semantic-empty leases, and a continuity-timer gap. Known lease-release and node-order defects from `fable-review-165` were not duplicated.
5. **WireGuard key utility (2 files):** Checked entropy, scalar clamping, X25519 derivation, length bounds, encoding, and malformed input. `crypto/rand`, standard-library X25519, RFC 7748 vectors, and bounded pre-decode validation preserve the key-generation invariant; no finding.
6. **Deployment driver (7 files):** Read all hypervisor, disk, config-drive, fetch, destroy, image-roll, and kernel-roll paths and all assigned tests. Findings A10-b4-03 and -13 cover reboot inference and path containment. Existing findings for golden disks, virtio order, physical backing, no-start, lease release, node IDs, alias swaps, and SSH host keys were suppressed as duplicates.
7. **Distribution signing/publication (2 files):** Checked signature verification, verified-byte manifest parsing, basename/default-deny rules, installer key agreement, apt suite checks, and dispatch. Signed manifest parsing itself uses copied verified bytes and rejects duplicate/unsafe names. Finding A10-b4-06 covers the remaining gate-to-upload race.
8. **Image bake/config-drive/validation (5 files):** Checked upstream acquisition, customize inputs, artifact finalization order, signing, ISO staging, signature verification, and Incus scenario lifecycle. Findings A10-b4-04, -05, -15, and -26 cover signing after an explicitly skipped gate, unauthenticated upstream checksums, secret-bearing ISO modes, and destructive fixed resource names.
9. **General HA metrics and MTR helpers (4 files):** Checked JSON and JSON-stream parse failures, incomplete-run metadata, interval accounting, collapse metrics, IPv4 final-hop fail-closed behavior, and the explicitly observability-only IPv6 exception. Callers that hard-gate throughput also check average/completion; no new fail-open finding.
10. **Cluster/CoS/fairness evidence parsers (14 files):** Checked cluster state vocabulary, finite/nonnegative numeric validation, queue deltas, exit-code artifacts, fairness CoV, surplus handback sequencing, and iperf summary completeness. Findings A10-b4-19 and -20 cover an exit/verdict mismatch and unobservable RG polling gaps. The already cataloged lack of a live surplus-giveback producer was suppressed.
11. **Mouse latency tools (7 files):** Checked probe attempt accounting, rate floors, percentile aggregation, valid-repetition thresholds, CoS fixture consistency, and shell contracts. Finding A10-b4-07 is a definitive gate-status bug; A10-b4-20 covers RG poll cadence.
12. **Policy scheduler and retirement evidence (4 files):** Required artifacts, userspace capability/armed state, monotonic counters, strict undefined-scheduler rejection, and retired-eBPF schema checks fail closed. The retirement checker is intentionally structural and labels itself as such; no finding.
13. **Step-1 analysis (4 files):** Checked histogram delta invariants, baseline quorum, per-cell iteration, rate-spread derivation, bootstrap behavior, and RSS Monte Carlo bounds. Findings A10-b4-28, -29, and -30 cover success on missing cells, partial rate evidence, and O(trials) retention.
14. **Step-2/Step-3 analysis (6 files):** Checked timestamp conversion, drift halt, block boundaries, histogram/kick input shapes, verdict thresholds, tie handling, and metadata output. Findings A10-b4-08, -16, and -17 invalidate scheduler timing semantics and two evidence-quality assumptions. Step-3's integer cross-multiplication avoids float threshold drift and its required block fields fail closed.
15. **Cold-path flooder (1 file):** Checked argument arithmetic, port/span bounds, frame sizes/checksums, seed separation, CPU pinning, shared deadlines, sendmmsg error accounting, and summary math. Finding A10-b4-18 covers bounded-cohort reuse; integer products use `u128` and frame-layout assertions are sound.
16. **AF_XDP reproducers (4 files):** Checked XDP map bounds, UMEM/ring ownership, process lifecycle, link cycling, existing-program handling, shared sockets, and cleanup. Findings A10-b4-01, -09, -10, -21 through -25 cover the privileged process, memory/ring, TOCTOU, false-result, and operational hazards. The BPF program itself bounds map lookup through normal map semantics and passes on absent entries.

### A2-b1

- userspace-dp/src/nat/allocator.rs: Reviewed port allocator lifecycle, occupancy/reuse, persistent leases, release/rollback, deterministic v4/v6 block allocation, reverse deterministic mapping, HA reservation helpers, and counters. Finding 1 below is in deterministic v6 subscriber selection. Other allocator paths had no new credible issue; F-038-023 persistent-NAT HA lease sync and F-038 deterministic /0 Go-side host-count issue were treated as deduped existing roots.
- userspace-dp/src/nat/destination.rs: Reviewed DNAT exact/prefix maps, source/L4 constraints, off exemptions, scoped local target generation, and prefix expansion. No new issue. Existing DNAT duplicate/shadowing and local-address routing-table findings are in the dedup index and were not re-filed.
- userspace-dp/src/nat/mod.rs: Reviewed NAT decision merge/reverse helpers and rule counters. No new issue; atomic counters and clear semantics are guarded by the store mutex for the exposed API.
- userspace-dp/src/nat/source.rs: Reviewed source NAT rule parsing, scope matching, malformed address fail-closed behavior, l4/application constraints, deterministic branch, non-first fragment refusal, and NAT64 allocator wrappers. No new issue beyond Finding 1 through the wrapped deterministic v6 allocator.
- userspace-dp/src/nat/static_nat.rs: Reviewed host, port-mapped, scoped, source-constrained, and block-to-block static NAT. Translation offset logic is correct; Finding 2 is limited to local-address registration for block rules.
- userspace-dp/src/nat/status.rs: Reviewed source NAT pool status aggregation. No new issue; it is status-only and does not enforce allocator behavior.
- userspace-dp/src/nat/tests_counter.rs: Reviewed counter store tests, stable IDs, shared counter wiring, and concurrent clear behavior. No new issue.
- userspace-dp/src/nat/tests_destination.rs: Reviewed DNAT tests covering exact/prefix lookup, LPM, source/L4 scope, off exemptions, destination IP registration, precedence, and duplicate behavior. No new issue; duplicate last-rule behavior is already deduped.
- userspace-dp/src/nat/tests_dnat_proto.rs: Reviewed DNAT protocol-specific test coverage. No new issue.
- userspace-dp/src/nat/tests_l4_match.rs: Reviewed source/DNAT L4 application constraints, source-port constraints, ICMP type/code, fail-closed sentinels, and destination-port range behavior. No new issue.
- userspace-dp/src/nat/tests_pool.rs: Reviewed pool allocation, persistent NAT, rollback, expiry indexes, GC, fail-closed pool validation, address-persistent hashing, non-first fragments, HA reservations, and deterministic v4/v6 tests. Test gap noted for Finding 1: deterministic NAPT64 covers in-prefix and out-of-range words but not wrong-prefix/same-word subscribers.
- userspace-dp/src/nat/tests_scope.rs: Reviewed zone/interface/routing-instance scope tests for source NAT, static NAT, and DNAT. No new issue.
- userspace-dp/src/nat/tests_source.rs: Reviewed source NAT interface/pool/off/malformed-address/source/destination scoping tests. No new issue.
- userspace-dp/src/nat/tests_static.rs: Reviewed static NAT host/port/block/source/scope/canonical-mask tests. Tests cover block translation but not block local-address registration; see Finding 2.
- userspace-dp/src/nat64.rs: Reviewed NAT64 prefix parsing, pool parsing, allocator reuse, deterministic NAPT64 branch, classification tri-state, release/reserve wrappers, fragment-association cache, extension-header walkers, core v6-to-v4/v4-to-v6 translators, embedded ICMP translation, checksum adjustment, and non-first fragment helpers. Finding 1 applies to deterministic NAPT64 source prefix membership. Known NAT64 fragment/embedded-ICMP issues in the dedup index were not re-filed.
- userspace-dp/src/nat64_tests.rs: Reviewed NAT64 prefix, pool, deterministic NAPT64, translation, VLAN, traffic class, padding trim, length, ICMP, fragment, embedded ICMP, and reload-related tests. Test gap noted for Finding 1.
- userspace-dp/src/nptv6.rs: Reviewed NPTv6 prefix parsing, overlap rejection, checksum-neutral adjustment, inbound/outbound translation, and external-prefix publication. No new issue; self-overlap and invalid-prefix roots already appear in dedup/fixed coverage.
- userspace-dp/src/nptv6_tests.rs: Reviewed NPTv6 parse, invalid snapshot, overlap, checksum-neutrality, edge host-word, and composition tests. No new issue.
- userspace-dp/src/protocol/nat.rs: Reviewed NAT wire structs and additive serde defaults, especially deterministic NAT64 fields. No new issue in the wire contract itself; the field comments support Finding 1's prefix-membership expectation.

### A3-b1

- pkg/appid/catalog.go: swept BuildCatalog id assignment, CatalogNames interaction, protocol resolution, port parsing, ICMP type guard, and parsePortRange. Found F1 and F2. Negative checks: app_id uint16 cap rejects overflow before narrowing; bad destination ports do not consume ids; bad source ports and reversed ranges are no longer emitted; explicit `protocol 0` no longer fans out to TCP/UDP.
- pkg/appid/runtime.go: swept CatalogNames, ResolveSessionName, tuple fallback, canonical port parsing, protocol display/parse helpers. Found F1 in tuple fallback. Negative checks: nil zone-pair/policy entries are skipped in CatalogNames; source-port constraints are honored; malformed port specs do not uint16-narrow; AppID enabled path returns UNKNOWN for unmapped ids.
- pkg/appid/textrender.go: no finding. Renderer is deterministic, handles nil config with a no-active sentinel, and does not mutate config or parse operator input.
- pkg/appid/catalog_icmp_3781_test.go: no new finding. Regression tests pin the current no-false-label interim for ICMP type/code-constrained apps.
- pkg/appid/catalog_proto0_4008_test.go: supports F2 refutation. It pins explicit `protocol 0` vs omitted protocol, but does not cover unrepresentable explicit protocols on the tolerant path.
- pkg/appid/catalog_tolerant_3725_test.go: no duplicate finding. Existing tests cover malformed source ports, reversed ranges, and dangling AppNames for malformed ports.
- pkg/appid/precedence_parity_test.go: no finding. Cross-language precedence fixture checks Go fallback vs Rust catalog on valid catalog rows.
- pkg/appid/protocol_lenient_3439_test.go: no finding. Lenient protocol filter parser round-trips current ProtocolName output.
- pkg/appid/protocol_number_2124_test.go: no finding. ProtocolNumber correctly distinguishes `(0,true)` for protocol 0 from `(0,false)` for unrepresentable tokens; F2 is in BuildCatalog discarding that bool, not in ProtocolNumber.
- pkg/appid/runtime_test.go: no duplicate finding. Tests cover NAT-only refs, strict-walk parity, malformed ports, source-port constraints, nil zpp/policy entries, and app-id overflow. Missing nil application map value and bad-protocol catalog emission tests are findings below.
- pkg/appid/textrender_test.go: no finding. Tests cover enabled, disabled, and nil config output.
- pkg/cmdtree/tree.go: swept static operational/config tree, dynamic completions, placeholder descent, typed-leaf completions, lookup, help rendering, and helper functions. Found F3 in dynamic completion loops over nil-tolerant pointer slices. Negative checks: placeholder-with-children and placeholder-without-children behavior is covered; unique prefix resolution rejects ambiguous prefixes; nil zone-pair/policy and nil zone-value cases have targeted guards.
- pkg/cmdtree/tree_test.go: no finding. It covers placeholder descent, dynamic routing table names, unique prefixes, CoS drilldowns, and dynamic CoS names. It does not cover nil routing-instance or nil redundancy-group entries.
- pkg/cmdtree/completion_nil_3476_test.go: no finding. It pins nil zone-pair and nil policy guards for `show security policies ... policy`.
- pkg/cmdtree/completion_nil_3493_test.go: no finding. It pins a nil security zone map value guard for `monitor security packet-drop from-zone`.
- pkg/cmdtree/tree_hb167_test.go: no finding. Static node-presence test only; no parser/runtime risk found.

### A3-b2

- AST core: `ast.go`, `ast_edit.go`, `ast_format.go`, `ast_groups.go`, `ast_redact.go`, `ast_redact_test.go`, `apply_groups_leaflist_test.go`, `apply_groups_leaflist_exclude_test.go`, `apply_groups_transitive_4474_test.go`. Negative result: dual flat/hierarchical shapes, schema-aware apply-groups union, leaf-list exclusions, transitive group expansion, inactive/orphan handling, and secret redaction paths are explicit and covered by regression tests; I did not find a batch-unique fail-open. `ast_format.go` still uses keyed maps in compare output, but this is display tooling rather than a config-enforcement path and was not raised as a finding.
- Compiler orchestration and gates: `compiler.go`, `compiler_earlystrict.go`, `compiler_prewalk.go`, `compiler_dispatch.go`, `compiler_derivations.go`, `compile_golden_4406_test.go`, `allow_dataplane_sleep_test.go`, `archival_leading_dash_4589_test.go`, `compiler_retired_dataplane_knobs_test.go`, `compiler_inert_knobs_4306_test.go`. Negative result: strict-vs-lenient knobs are wired in both generic and node-aware compiles, P1/P6/P7 ordering is documented, and the golden test protects behavior across the decomposed phases.
- Applications: `compiler_applications.go`, `compiler_applications_collision.go`, `application_set_nested_test.go`, `compiler_application_*_test.go`, `compiler_applications_collision_3339_test.go`. Negative result: application term parsing handles multi-protocol expansion, service-name port resolution, timeout parse failures, nested sets, duplicate/generated-name collisions, and undefined members with strict gates plus lenient warnings.
- Security policy validation: `compiler_policy_match.go`, `compiler_policy_then.go`, `compiler_policy_missing_match.go`, `compiler_policy_*_test.go`, `compiler_default_policy_3065_test.go`, `compiler_default_policy_log_3534_test.go`, `compiler_preid_default_policy_log_2509_test.go`, `compiler_dup_policy_name_3473_test.go`, `compiler_dup_match_then_3850_test.go`, `compiler_dup_security_3562_test.go`. Negative result: unsupported match/then leaves, required match dimensions, duplicate blocks, deny modifiers, terminal actions, log actions, duplicate names, and global zone context are all walked across duplicate roots and both AST shapes.
- Firewall and prefix lists: `compiler_firewall.go`, `compiler_filter_*_test.go`, `compiler_firewall_family_*_test.go`, `compiler_prefix_list_*_test.go`, `compiler_lo0_mirror_modifiers_3445_test.go`, `compiler_dynamic_address_feed_ref_3300_test.go`, `compiler_feed_address_token_3294_test.go`, `compiler_f3_hb167_test.go`. Negative result: family `any` routing to v4/v6 pools, family-specific literal rejects, DSCP/filter action gates, prefix-list bracket/hier merge, address-feed references, and lo0 mirror modifiers are covered. Family-any/source-prefix-list/NAT64-style candidates matched prior dedup entries and were suppressed.
- NAT: `compiler_nat.go`, `compiler_nat_dnat_to.go`, all `compiler_nat*_test.go`, `compiler_dnat_*_test.go`, `compiler_nptv6*_test.go`. Findings below. Negative coverage outside findings: duplicate NAT match/then blocks, DNAT `to` strict reject, NAT64 prefix/host-mask gates, address-name/feed resolution, pool alarms, static/source pool ports, application references, and multivalue matches are covered by tests or prior dedup entries.
- Interfaces, VRRP, and DDNS: `compiler_interfaces.go`, `compiler_interfaces_unsupported.go`, `compiler_interface_range.go`, `compiler_interfaces_unsupported_test.go`, `compiler_interface_range_4027_test.go`, `compiler_flat_reth_nodeid_4329_test.go`, `backup_router_family_2911_test.go`, `compiler_cluster_authkey_4107_test.go`, `compiler_dhcp_ddns_test.go`, `compiler_dhcp_relay_overrides_test.go`. Negative result: interface-range expansion is bounded and strips phantom interfaces, unsupported ARP-policer/MAC/QinQ stanzas are reject/warn gated, VRRP track/auth paths avoid secret leaks and duplicated tracking, and interface DDNS handles packed/two-shape keys.
- IPsec: `compiler_ipsec.go`, `compiler_ipsec_bindiface.go`, `compiler_ipsec_proposalset.go`, `compiler_ipsec_trafficselector.go`, `compiler_ipsec_*_test.go`. Negative result: proposal-set expansion, multivalue proposal refs, manual-key/vpn-monitor capture, gateway reference validation, secure-tunnel bind-interface alias collision, and traffic-selector injection gates all handle duplicate security/ipsec blocks and lenient downgrade contracts.
- Routing/protocols/policy-options: `compiler_routing.go`, `compiler_protocols.go`, `compiler_bgp_as_3870_test.go`, `bgp_*_test.go`, `compiler_as_path_prepend_2892_test.go`, `compiler_qualified_nexthop_3871_test.go`, `compiler_ribgroup_ref_2226_test.go`, `compiler_rip_multivalue_3904_test.go`, `compiler_route_filter_range_2525_test.go`, `compiler_routing_instance_interface_3904_test.go`, `compiler_routing_rules_test.go`, `compiler_frr_policy_inject_4097_test.go`, `compiler_rpm_http_scheme_2495_test.go`, `compiler_rpm_linklocal_zone_2494_test.go`. Negative result: static route next-hop/qualified-next-hop shape handling, rib-group table classification, stable RI table IDs, prefix-list/policy term list accumulation, BGP ASN/missing-peer gates, RIP multivalue parsing, route-filter range validation, and RA/RPM warning gates are covered; the RA NAT64 prefix gap is a known dedup item and not re-reported.
- Class of service: `compiler_class_of_service.go`, `compiler_cos_*_test.go`, `compiler_equal_flow_*_test.go`, `compiler_f3_hb167_test.go`, `compiler_filter_loss_priority_2507_test.go`. Negative result: queue/FC bijection, scheduler-map refs, loss-priority checks, rate percent/exact/remainder grammar, percent resolution, DSCP/PCP codepoint bounds, interface-level CoS folding, TCP profile shaping, and fairness expectation parsing are explicit and tested.
- Chassis/device-map: `compiler_chassis.go`, `compiler_chassis_device_map_test.go`, `compiler_flat_reth_nodeid_4329_test.go`. Negative result: device-map identity collection scans nested keys, MAC normalization is canonical, duplicate logical/PCI/MAC keys and node-slot alignment are strict-gated, and node-aware derivation stamps node ID before fabric/device-map checks.
- Address book and miscellaneous warnings: `addressbook_name_slash_*_test.go`, `compiler_addrbook_warn_3958_test.go`, `compiler_junos_host_direct_warn_4146_test.go`, `compiler_p3_http_providers_test.go`, `compiler_dhcp_*_test.go`, `compiler_frr_policy_inject_4097_test.go`, `compiler_rpm_*_test.go`. Negative result: these files are regression tests for previously fixed warning/validation behavior; no new code path beyond the modules above was introduced by them.

Dedup suppressions checked: prior reports already cover source-prefix-list flat/hier drops, NAT64 non-/96 and host-mask gaps, family-any prefix-list/literal issues, DSCP validation, apply-groups transitive/list-union issues, duplicate policy/app collisions, DNAT `to` scope drops, address-book extra tokens, default-policy-log list tails, and host-inbound bracket tails. The two findings below use different root causes.

### A3-b3

### Production Files

| File | Result |
|---|---|
| `pkg/config/compiler_security.go` | Reviewed security subtree dispatcher and error propagation. Negative: no dropped child from this file itself; issues below are in dispatched compilers. |
| `pkg/config/compiler_security_addressbook.go` | Reviewed global and zone-local address-book folding. Findings A3-b3-02 and A3-b3-03. |
| `pkg/config/compiler_security_alg.go` | Reviewed ALG flag compilation. Negative: accepted-but-inert ALG breadth is already covered by dedup/fable167; no new distinct issue. |
| `pkg/config/compiler_security_flow.go` | Reviewed flow traceoptions, aging, and TCP MSS AST validators. Negative: numeric/string gates are present for the reviewed flow leaves; existing tests cover range/size/file cases. |
| `pkg/config/compiler_security_log.go` | Reviewed security log stream and TLS-profile AST validation. Negative: port/TLS profile gates fail closed or warn per existing design; no new issue. |
| `pkg/config/compiler_security_policy.go` | Reviewed policy AST dual-shape helpers, match/then handling, and collapsed deny modifiers. Negative: prior duplicate match/then and app/address drops are deduped/fixed; no new policy-local issue. |
| `pkg/config/compiler_security_screen.go` | Reviewed screen numeric parsing and strict numeric/unknown gates. Negative: known SYN-flood/default findings are deduped; no new numeric edge found. |
| `pkg/config/compiler_security_zones.go` | Reviewed zone/interface/host-inbound merge. Negative: duplicate host-inbound blocks merge through `mergeHostInbound`; no new drop found. |
| `pkg/config/compiler_services.go` | Reviewed DHCP, RPM, dynamic-address, IP monitoring, sampling, flow monitoring, event-options, and bridge domains. Finding A3-b3-04. |
| `pkg/config/compiler_system.go` | Reviewed system/SNMP/DDNS/userspace/chassis/scheduler paths. Negative: SNMPv3 flat-set path compiles passwords through child nodes; no new finding beyond existing inert-knob dedup. |
| `pkg/config/compiler_tailgates.go` | Reviewed tail gate sequence/order. Negative: behavior-preserving first-error/warning-order invariant is explicit; no new issue. |
| `pkg/config/compiler_uniformgates.go` | Reviewed uniform validation gate ordering and downgrades. Negative: address-set validators only see compiled structs, which is relevant to A3-b3-02/A3-b3-03, but no separate gate-order issue. |
| `pkg/config/compiler_validate_strict.go` | Reviewed dataplane type, trailing token, flow aging, DHCP static, VRRP VIP gates. Negative: existing address extra-token and flow-aging fixes cover their intended shapes; no new issue. |
| `pkg/config/compiler_validate_strict_application.go` | Reviewed application set/spec/syntax validators. Negative: app-set recursion and port/protocol value gates look fail-closed for reviewed paths. |
| `pkg/config/compiler_validate_strict_chassis.go` | Reviewed chassis cluster strict validation. Negative: group-id/count gates exist; no new issue in batch scope. |
| `pkg/config/compiler_validate_strict_cos.go` | Reviewed scheduler references, scheduler-map, loss-priority, forwarding-class queue gates. Negative: relevant fail-open gates are present. |
| `pkg/config/compiler_validate_strict_filter.go` | Reviewed firewall prefix-list/filter references, protocol/port/address/dscp/action/cross-field gates. Negative: existing DSCP/source-prefix-list/dedup items suppressed; no new distinct issue. |
| `pkg/config/compiler_validate_strict_ipsec.go` | Reviewed IPsec/IKE proposal/reference/manual-key gates. Negative: prior crypto/typed-leaf findings are deduped; no new issue. |
| `pkg/config/compiler_validate_strict_nat.go` | Reviewed NAT application/address/protocol/port/pool gates. Negative: existing NAT64/pool/port-overloading findings are deduped; no new issue. |
| `pkg/config/compiler_validate_strict_observability.go` | Reviewed log profile, dynamic-address endpoint/ref, flow-server/sampling gates. Negative: endpoint/ref gates exist but do not cover A3-b3-04 interval parsing. |
| `pkg/config/compiler_validate_strict_policy.go` | Reviewed policy address/application/zone/terminal/log/address-set gates. Negative: validators correctly reject compiled unresolved sets, but cannot see address-set members lost before compile (A3-b3-02/A3-b3-03). |
| `pkg/config/compiler_validate_strict_routing.go` | Reviewed routing policy/community/BGP/FRR auth/router-id/rib/route-filter gates. Negative: no new issue in assigned files. |
| `pkg/config/compiler_validate_strict_screen.go` | Reviewed screen profile reference/numeric/unknown gates. Negative: screen numeric range checks cover compiled screen fields. |
| `pkg/config/compiler_validate_strict_vrrp.go` | Reviewed VRRP group-id strict validation. Negative: no new issue. |
| `pkg/config/compiler_validate_strict_zones.go` | Reviewed reserved-zone, zone count, interface membership/definition, host-inbound token validation. Negative: undefined interface finding is deduped; current file has strict gates. |
| `pkg/config/compiler_validate_vrf_overlap.go` | Reviewed VRF overlap warning logic. Negative: warning-only is documented product posture; no new issue. |
| `pkg/config/compiler_validate_warn.go` | Reviewed broad warning pass for address/policy/app/NAT/filter/DDNS/host-inbound/CoS. Negative: warnings cannot recover members dropped before compile; otherwise no new finding beyond dedup. |
| `pkg/config/compiler_validate_wireguard.go` | Reviewed WireGuard peer/tunnel validation. Negative: key/endpoint/family gates present for reviewed path; known WG items deduped. |
| `pkg/config/dup_host_local_address.go` | Reviewed duplicate host-local address host-inbound signature logic. Negative: strict duplicate gate accounts for zone/interface overrides. |
| `pkg/config/event_options_match.go` | Reviewed event attribute match parser/validators. Negative: field/event/pattern validations are explicit; event numeric issue is in dedup and not re-reported. |
| `pkg/config/event_options_within.go` | Reviewed event `within` trigger spec parser/AST validator. Negative: unknown fields and numeric clauses validated in strict AST path. |
| `pkg/config/filter_match_resolve.go` | Reviewed port/ICMP/service token resolution. Negative: canonical port parser avoids signed-port drift already covered by tests. |
| `pkg/config/firewall_filter_expand.go` | Reviewed filter term expansion counting. Negative: count is bounded by prefix-list members; prior truncation concern is deduped. |
| `pkg/config/freetext.go` | Reviewed annotation/comment/control-char validation and sanitization. Negative: annotation delimiter injection is already in dedup; this file now contains sanitizers. |
| `pkg/config/host_inbound_multicast.go` | Reviewed multicast token catalog/warnings. Negative: catalog is deterministic and not a compiler drop point. |
| `pkg/config/host_inbound_tokens.go` | Reviewed system-service/protocol token catalog and L4 expansion. Negative: host-inbound gaps are deduped; no new token drift found in this batch. |
| `pkg/config/host_inbound_view.go` | Reviewed operational host-inbound view rendering/effective merge. Negative: presentation only; no enforcement/compiler drop found. |
| `pkg/config/inactive.go` | Reviewed inactive stripping/cloning. Negative: inactive nodes are removed consistently before compile; inline inactive parser edge covered by tests. |
| `pkg/config/lexer.go` | Reviewed tokenization, bracket-list stripping, strings, comments, and ident set. Negative: unterminated block comment fix present; top-level `}` issue is parser-level A3-b3-01. |
| `pkg/config/lifeline.go` | Reviewed lifeline base-name and host-inbound interface helpers. Negative: no new issue. |
| `pkg/config/natpool.go` | Reviewed source NAT pool address-set resolution helpers. Negative: parser/compile address-set drops can affect inputs, but this file correctly expands the compiled book. |
| `pkg/config/parser.go` | Reviewed hierarchical parser and set-command parser. Finding A3-b3-01. |
| `pkg/config/predefined.go` | Reviewed predefined application/app-set and address-set expansion. Negative: cycle/depth/empty errors are returned; no new issue. |

### Test Files

| File | Result |
|---|---|
| `pkg/config/compiler_rpm_routing_instance_2496_test.go` | Reviewed RPM RI strict tests; no new finding. |
| `pkg/config/compiler_rpm_scoped_hostname_2493_test.go` | Reviewed RPM host/scoping tests; no new finding. |
| `pkg/config/compiler_rpm_source_2492_test.go` | Reviewed RPM source-address tests; no new finding. |
| `pkg/config/compiler_sampling_source_address_test.go` | Reviewed sampling source-address coverage; no new finding. |
| `pkg/config/compiler_schedulers_3849_test.go` | Reviewed scheduler compile tests; no new finding. |
| `pkg/config/compiler_security_bracket_list_3703_test.go` | Reviewed policy deny/log bracket-list tests; gap remains for address-set member bracket lists (A3-b3-02). |
| `pkg/config/compiler_signed_port_3606_test.go` | Reviewed signed port tests; no new finding. |
| `pkg/config/compiler_snmp_trapgroup_2990_test.go` | Reviewed SNMP trap-group tests; no new finding. |
| `pkg/config/compiler_ssh_hardening_4305_test.go` | Reviewed SSH hardening tests; no new finding. |
| `pkg/config/compiler_static_nexthop_list_3872_test.go` | Reviewed next-hop bracket-list tests; no new finding. |
| `pkg/config/compiler_static_route_inline_iface_3881_test.go` | Reviewed static route interface modifier tests; no new finding. |
| `pkg/config/compiler_surface_a_ddns_test.go` | Reviewed DDNS surface tests; no new finding. |
| `pkg/config/compiler_syslog_hostmods_4303_test.go` | Reviewed syslog host modifier tests; no new finding. |
| `pkg/config/compiler_tcp_mss_range_test.go` | Reviewed TCP MSS range tests; no new finding. |
| `pkg/config/compiler_tcp_session_seqcheck_test.go` | Reviewed TCP sequence-check tests; no new finding. |
| `pkg/config/compiler_test.go` | Reviewed broad compiler tests; no new finding. |
| `pkg/config/compiler_three_color_default_4535_test.go` | Reviewed three-color policer default tests; no new finding. |
| `pkg/config/compiler_undefined_ref_2217_test.go` | Reviewed undefined-reference tests; no new finding. |
| `pkg/config/compiler_validate_scheduler_no_window_3860_test.go` | Reviewed scheduler no-window tests; no new finding. |
| `pkg/config/compiler_validate_strict_chassis_4434_test.go` | Reviewed chassis strict tests; no new finding. |
| `pkg/config/compiler_validate_strict_vrrp_4573_test.go` | Reviewed VRRP strict tests; no new finding. |
| `pkg/config/compiler_validate_vrf_overlap_2387_test.go` | Reviewed VRF overlap warning tests; no new finding. |
| `pkg/config/compiler_validate_warn_nil_3494_test.go` | Reviewed nil warning tests; no new finding. |
| `pkg/config/completion_prefix_test.go` | Reviewed completion prefix tests; no new finding. |
| `pkg/config/ddns_porthost_4589_test.go` | Reviewed DDNS host/port tests; no new finding. |
| `pkg/config/ddns_provider_string_test.go` | Reviewed DDNS provider string tests; no new finding. |
| `pkg/config/deactivate_multi_leaf_3975_test.go` | Reviewed deactivate multi-leaf tests; no new finding. |
| `pkg/config/delete_multi_leaf_member_3846_test.go` | Reviewed delete multi-leaf member tests; no new finding. |
| `pkg/config/delete_static_nexthop_3872_test.go` | Reviewed static next-hop delete tests; no new finding. |
| `pkg/config/deterministic_nat_advisory_4559_test.go` | Reviewed deterministic NAT advisory tests; no new finding. |
| `pkg/config/deterministic_nat_flatset_3864_test.go` | Reviewed deterministic NAT flat-set tests; no new finding. |
| `pkg/config/dhcp_expired_leases_test.go` | Reviewed DHCP expired leases tests; no new finding. |
| `pkg/config/dhcp_static_binding_test.go` | Reviewed DHCP static binding tests; no new finding. |
| `pkg/config/dual_ast_differential_test.go` | Reviewed dual-AST differential tests; gap remains for address-set bracket-list and duplicate-block shapes (A3-b3-02/A3-b3-03). |
| `pkg/config/dup_host_local_address_3718_test.go` | Reviewed duplicate host-local address tests; no new finding. |
| `pkg/config/event_options_4423_test.go` | Reviewed event-options tests; no new finding. |
| `pkg/config/event_options_match_test.go` | Reviewed event attribute match tests; no new finding. |
| `pkg/config/event_options_within_3751_test.go` | Reviewed event within tests; no new finding. |
| `pkg/config/fable167_advisory_test.go` | Reviewed fable167 advisory tests; no new finding. |
| `pkg/config/fbf_fixture_test.go` | Reviewed FBF fixture tests; no new finding. |
| `pkg/config/filter_protocol_rust_mirror_3393_test.go` | Reviewed protocol mirror tests; no new finding. |
| `pkg/config/firewall_address_except_matchany_4338_test.go` | Reviewed address-except match-any tests; no new finding. |
| `pkg/config/firewall_address_except_mutex_3359_test.go` | Reviewed address-except mutex tests; no new finding. |
| `pkg/config/firewall_address_literal_3433_test.go` | Reviewed address literal tests; no new finding. |
| `pkg/config/firewall_crossfield_3723_test.go` | Reviewed firewall cross-field tests; no new finding. |
| `pkg/config/firewall_dscp_drift_3309_test.go` | Reviewed DSCP drift tests; no new finding. |
| `pkg/config/firewall_dscp_range_3309_test.go` | Reviewed DSCP range tests; no new finding. |
| `pkg/config/firewall_from_unenforced_3307_test.go` | Reviewed firewall from-unenforced tests; no new finding. |
| `pkg/config/firewall_multivalue_2545_test.go` | Reviewed firewall multi-value tests; no new finding. |
| `pkg/config/firewall_port_except_2622_test.go` | Reviewed port-except tests; no new finding. |
| `pkg/config/firewall_port_except_mutex_3297_test.go` | Reviewed port-except mutex tests; no new finding. |
| `pkg/config/firewall_ri_conflict_3308_test.go` | Reviewed routing-instance conflict tests; no new finding. |
| `pkg/config/firewall_ri_output_direction_3432_test.go` | Reviewed RI output direction tests; no new finding. |
| `pkg/config/firewall_symbolic_match_3205_test.go` | Reviewed symbolic match tests; no new finding. |
| `pkg/config/firewall_terminal_conflict_4375_test.go` | Reviewed terminal conflict tests; no new finding. |
| `pkg/config/flow_aging_3440_test.go` | Reviewed flow aging tests; no new finding. |
| `pkg/config/flow_traceoptions_file_3420_test.go` | Reviewed flow traceoptions file tests; no new finding. |
| `pkg/config/flow_traceoptions_filter_3422_test.go` | Reviewed flow traceoptions filter tests; no new finding. |
| `pkg/config/flow_traceoptions_size_3424_test.go` | Reviewed flow traceoptions size tests; no new finding. |
| `pkg/config/flowserver_template_ref_test.go` | Reviewed flowserver template ref tests; no new finding. |
| `pkg/config/freetext_test.go` | Reviewed free-text validation tests; no new finding. |
| `pkg/config/global_policy_zone_scope_3680_test.go` | Reviewed global policy zone scope tests; no new finding. |
| `pkg/config/host_inbound_dup_block_4544_test.go` | Reviewed host-inbound duplicate block tests; no new finding. |
| `pkg/config/host_inbound_effective_3720_test.go` | Reviewed effective host-inbound tests; no new finding. |
| `pkg/config/host_inbound_fulladmit_warn_3226_test.go` | Reviewed full-admit warning tests; no new finding. |
| `pkg/config/host_inbound_match_3627_test.go` | Reviewed host-inbound match tests; no new finding. |
| `pkg/config/host_inbound_multicast_warn_4455_test.go` | Reviewed host-inbound multicast warning tests; no new finding. |
| `pkg/config/host_inbound_per_iface_3362_test.go` | Reviewed per-interface host-inbound tests; no new finding. |
| `pkg/config/host_inbound_rust_parity_test.go` | Reviewed Rust parity host-inbound tests; no new finding. |
| `pkg/config/host_inbound_tokens_test.go` | Reviewed host-inbound token tests; no new finding. |
| `pkg/config/host_inbound_view_3654_test.go` | Reviewed host-inbound view tests; no new finding. |
| `pkg/config/host_inbound_view_lifeline_3682_test.go` | Reviewed host-inbound lifeline view tests; no new finding. |
| `pkg/config/ike_policy_chain_ref_test.go` | Reviewed IKE policy chain reference tests; no new finding. |
| `pkg/config/inactive_test.go` | Reviewed inactive tests; no new finding. |
| `pkg/config/inline_inactive_4335_test.go` | Reviewed inline inactive tests; no new finding. |
| `pkg/config/interface_parity_4308_test.go` | Reviewed interface parity tests; no new finding. |
| `pkg/config/ipsec_dhgroup_test.go` | Reviewed IPsec DH group tests; no new finding. |
| `pkg/config/ipsec_proposal_ref_test.go` | Reviewed IPsec proposal reference tests; no new finding. |
| `pkg/config/log_profile_schema_test.go` | Reviewed log profile schema tests; no new finding. |
| `pkg/config/log_profile_test.go` | Reviewed log profile tests; no new finding. |
| `pkg/config/log_stream_config_3349_test.go` | Reviewed log stream config tests; no new finding. |
| `pkg/config/log_stream_tls_profile_3350_test.go` | Reviewed log stream TLS profile tests; no new finding. |
| `pkg/config/login_custom_class_4304_test.go` | Reviewed login custom class tests; no new finding. |
| `pkg/config/login_password_test.go` | Reviewed login password tests; no new finding. |
| `pkg/config/named_port_caseinsensitive_3372_test.go` | Reviewed named port case-insensitive tests; no new finding. |
| `pkg/config/natpool_test.go` | Reviewed NAT pool tests; no new finding. |
| `pkg/config/parser_ast_test.go` | Reviewed parser AST tests. Gap: unterminated comment is covered, but top-level unmatched `}` with trailing config is not (A3-b3-01). |
| `pkg/config/parser_bracket_list_2419_test.go` | Reviewed bracket-list tests. Gap: firewall/policy lists covered, not address-set membership (A3-b3-02). |
| `pkg/config/parser_class_of_service_test.go` | Reviewed CoS parser tests; no new finding. |
| `pkg/config/parser_cluster_test.go` | Reviewed cluster parser tests; no new finding. |
| `pkg/config/parser_fbf_test.go` | Reviewed FBF parser tests; no new finding. |
| `pkg/config/parser_ipmonitoring_test.go` | Reviewed IP monitoring parser tests; no new finding. |
| `pkg/config/parser_recursion_dos_hb164_test.go` | Reviewed recursion/bracket DoS tests; no new finding. |
| `pkg/config/parser_routing_test.go` | Reviewed nested address-set tests. Gap: repeated same-name address-set blocks are not covered (A3-b3-03). |
| `pkg/config/parser_rpm_pin_test.go` | Reviewed RPM pin tests; no new finding. |
| `pkg/config/parser_security_test.go` | Reviewed security parser tests; no new finding beyond address-set gaps noted above. |
| `pkg/config/parser_services_test.go` | Reviewed dynamic-address tests. Gap: only valid numeric intervals are tested; invalid strings are not rejected (A3-b3-04). |
| `pkg/config/parser_system_test.go` | Reviewed system/SNMP parser tests; no new finding. |
| `pkg/config/policy_community_ref_test.go` | Reviewed policy community ref tests; no new finding. |
| `pkg/config/policy_from_multileaf_2689_test.go` | Reviewed policy from multi-leaf tests; no new finding. |
| `pkg/config/policy_log_action_3060_test.go` | Reviewed policy log action tests; no new finding. |
| `pkg/config/policy_match_excluded_test.go` | Reviewed policy match excluded tests; no new finding. |
| `pkg/config/policy_rematch_advisory_test.go` | Reviewed policy rematch advisory tests; no new finding. |
| `pkg/config/policy_terminal_action_3043_test.go` | Reviewed policy terminal action tests; no new finding. |
| `pkg/config/policy_zone_matrix_4422_test.go` | Reviewed policy zone matrix tests; no new finding. |
| `pkg/config/policy_zone_ref_test.go` | Reviewed policy zone reference tests; no new finding. |
| `pkg/config/predefined_app_sets_4102_test.go` | Reviewed predefined app-set tests; no new finding. |

### A3-b4

Production files in the batch reviewed with no additional reportable issue beyond the findings above:

- `pkg/config/reth_show.go`: display/helper path only; no parser/schema acceptance issue found.
- `pkg/config/routinginstanceid.go`: identifier parsing and routing-instance helpers reviewed for numeric/string edge cases; no new fail-open behavior found.
- `pkg/config/schema.go`: root schema mechanics and scalar leaf helper reviewed; stale comments noted but no production bug filed.
- `pkg/config/schema_chassis.go`: main issue reported in Finding 3; other typed leaves use bounded validators.
- `pkg/config/schema_complete.go`: completion traversal reviewed for schema exposure; no security-relevant silent drop found.
- `pkg/config/schema_cos.go`: main issue reported in Finding 2; other CoS typed leaves route to stricter CoS validators.
- `pkg/config/schema_interfaces.go`: VLAN, VRRP, DDNS, tunnel, and nested interface leaves use validators or known strict gates; no new issue found.
- `pkg/config/schema_routing.go`: route preference, BGP, OSPF, RA, LLDP, and sampling numeric leaves reviewed; prior numeric classes appear gated.
- `pkg/config/schema_schedulers.go`: scheduler CLI grammar reviewed; no new typed-leaf or trailing-token issue found.
- `pkg/config/schema_security.go`: main issue reported in Finding 1; prior host-inbound/session-log closed-world/list issues appear addressed in current schema.
- `pkg/config/schema_system.go`: logging, dataplane, NTP, API, flow template, event-options, and probe leaves reviewed; no non-deduped issue found.
- `pkg/config/schema_validators.go`: main issue reported in Finding 2; integer validators otherwise fail closed on parse/range.
- `pkg/config/schema_validators_cos.go`: CoS-specific numeric validators reject non-finite values; no additional issue found.
- `pkg/config/schema_validators_ddns.go`: hostname/source-address validation reviewed; no new issue found.
- `pkg/config/schema_validators_devicemap.go`: PCI/MAC validation reviewed; no new issue found.
- `pkg/config/schema_validators_ipsec.go`: IPsec group validator reviewed; no new issue found.
- `pkg/config/schema_validators_logging.go`: facility/severity/unit validation reviewed; no new issue found.
- `pkg/config/schema_validators_network.go`: IP, prefix, interface, and zone validators reviewed; no new issue found.
- `pkg/config/schema_validators_routing.go`: route/BGP/RA validators reviewed; no new issue found.
- `pkg/config/schema_validators_scheduler.go`: scheduler name validation reviewed; no new issue found.
- `pkg/config/schema_validators_system.go`: system validators reviewed; no new issue found.
- `pkg/config/schema_walk.go`: main named-instance tail issue reported in Finding 3; scalar and closed-world checks otherwise reviewed.
- `pkg/config/screen_inventory.go`: screen inventory/reference helper reviewed; no new issue found.
- `pkg/config/secret.go`: secret redaction/marshal behavior reviewed; no leakage issue found in this batch.
- `pkg/config/snmp_clients.go`: SNMP client parsing helpers reviewed; no new issue found.
- `pkg/config/tcp_flags.go`: TCP flag parser reviewed for invalid string handling; no new issue found.
- `pkg/config/tunnelemit.go`: tunnel emit helpers reviewed; no new issue found.
- `pkg/config/tunnelid.go`: tunnel ID parsing reviewed; no new reportable numeric edge found.
- `pkg/config/types.go`: shared interface/FPC/unit helpers reviewed; no new issue found.
- `pkg/config/types_chassis.go`: HA model types reviewed; Finding 3 covers the priority range invariant.
- `pkg/config/types_cos.go`: CoS model types reviewed; Finding 2 covers the float invariant.
- `pkg/config/types_interfaces.go`: interface model types reviewed; no new issue found.
- `pkg/config/types_routing.go`: routing model types reviewed; no new issue found.
- `pkg/config/types_security.go`: IPsec/DPD model types reviewed; Finding 1 covers the numeric invariant.
- `pkg/config/types_system.go`: system model constants and types reviewed; no new issue found.
- `pkg/config/value_type.go`: value metadata reviewed; issue is in `ValidatePercent`, not value-type display.
- `pkg/config/xfrmi.go`: XFRM interface parser reviewed; no new issue found.
- `pkg/config/zoneid.go`: zone ID parsing/reservation helpers reviewed; no new issue found.

Test files in the batch reviewed for coverage/dedup signals. Relevant gaps are recorded under the findings:

- DPD tests validate closed-world keyword rejection but not malformed/overflowing `interval` or `threshold`.
- `TestValidatePercent` lacks `NaN`/`Inf` cases.
- `TestSchemaValidate_ChassisCluster_PackedOneLinerBypassesGate` currently pins acceptance of an invalid compact hierarchical priority.
- Other batch tests cover prior fixes for inactive quoting, routing references, closed-world NAT/IPsec proposals, scalar trailing tokens, screen strictness, SNMP clients, tunnels, VRRP, zones, and related schema behavior; I did not find additional non-deduped issues in those files.

### A4-b1

- `activate_test.go`: Covered activate/deactivate candidate edit tests. Negative: they pin inactive state and idempotence; no persistence or crypto finding in this test-only module.
- `archive_rotate_enoent_4689_test.go`: Covered archive rotation ENOENT handling. Negative: ENOENT tolerance is correct for concurrent cleanup; durable deletion is not claimed for archive pruning.
- `check.go`: Covered day-0 `CheckText` size gate, parse, strict compile pipeline. Negative: size ceiling and strict validator composition are sound for config payloads; parse-error redaction was noted as a possible UX gap but not reported because the caller supplied the config text.
- `check_test.go`: Covered strict check tests for valid configs, parse errors, retired dataplane, schema gate, node expansion, and node-id mismatch. Negative: tests match `check.go` strict-path contract.
- `cluster_readonly_3893_test.go`: Covered read-only secondary mutation gates and SyncApply bypass. Negative: user-session writes are rechecked at mutation time; SyncApply bypass is intentional HA ingress.
- `commit_confirm_demote_4378_test.go`: Covered demotion-confirm tests. Negative for timer generation; finding F1 still applies because the test proves in-memory clearing only, not crash-durable removal of `confirm.json`.
- `commit_confirm_pending_edit_4000_test.go`: Covered pending edit behavior during confirmed windows. Negative: no storage issue found beyond the confirm-state persistence findings below.
- `commit_confirmed_3861_test.go`: Covered plain commit and HA sync confirming pending windows plus nested confirmed re-arm. Negative: generation and rollback-target preservation are pinned; durable confirm-state removal is not.
- `commit_confirmed_persist_4577_test.go`: Covered restart recovery, re-arm, explicit confirm, and bare commit after confirmed commit. Negative: it checks filesystem-visible removal, but not directory fsync or injected `DeleteConfirm` failure, which is F1.
- `config_size_ceiling_hb164_test.go`: Covered `MaxConfigSize` gates on LoadOverride, LoadMerge, LoadSet, SyncApply. Negative: config payload size is bounded; commit description/journal Detail is not covered and is F6.
- `crypto.go`: Covered master-password PRF extraction, AES-GCM envelope write/read, HKDF PRF mapping, master key creation. Findings F3 and F4.
- `crypto_prf_sync_4578_test.go`: Covered drift guard between accepted PRF names and runtime `prfHash`. Negative: PRF name sync is pinned.
- `dataplane_retire.go`: Covered load/sync tolerant rewrite of retired dataplane-type leaves in top-level and group stanzas. Negative: no persistence/crypto issue beyond normal lenient-load doctrine.
- `dataplane_retire_test.go`: Covered retired dataplane rewrite tests including split stanzas and apply-groups. Negative: tests align with helper invariants.
- `db.go`: Covered DB directory creation/perms, active/candidate/rollback read/write, confirm record persistence, outer envelope stripping, active writes. Findings F1, F3, F4.
- `db_test.go`: Covered plain/encrypted active DB round trips and plaintext rewrite after master-password removal. Negative: happy-path encryption is tested; malformed envelope and nonce panic cases are not.
- `durability_3441_test.go`: Covered rollback slot durable write, dir sync, degraded bit, rollback load through errors, stale cleanup. Negative: rollback text history durability is well tested; confirm-state deletion durability is not covered.
- `envelope.go`: Covered config compatibility header grammar, min-reader gate, committed marker parsing. Negative: outer envelope fails closed on too-new DB; F4 is the inner encrypted-envelope fallthrough, not this outer envelope.
- `envelope_test.go`: Covered outer envelope round trip, old-reader rejection, too-new DB unreadable tagging, corrupt DB tagging, legacy no-envelope load. Negative: tests support outer envelope only.
- `equal_flow_worker_cap_test.go`: Covered lenient load behavior for retired equal-flow cap. Negative: no A4 storage issue.
- `file_perms_4056_test.go`: Covered 0600/0700 owner-only posture for active DB, rollback slots, rescue, archive, and journal. Finding F5 is distinct: owner-only files can still be cleartext despite master-password encryption.
- `freetext_store_test.go`: Covered persisted/synced control-character sanitization and strict commit reject. Negative: no persistence/crypto issue.
- `history.go`: Covered ring buffer API. Negative: max size is fixed at 50 through `Store.New`; no standalone zero-size production caller found.
- `inactive_test.go`: Covered inactive apply-groups and display-set round trip. Negative: no A4 issue.
- `journal/journal.go`: Covered compact JSONL journal, fsynced append, rotation, bounded tail, corrupt-line skip. Finding F6.
- `journal/journal_test.go`: Covered journal round trip, bounded tail, fat legacy lines, torn tail, rotation gaps, over-cap corrupt line skip, concurrency. Negative: recovery is robust for corrupt data; no test bounds legitimate `Detail` size, which is F6.
- `journal_compat_test.go`: Covered v1 compatibility, compact v2 entries, config hash on config-bearing actions, rollback-file hash correlation. Negative: compact entry removes config payloads as intended.
- `load_compile_fail_test.go`: Covered unreadable vs compile-failed DB behavior and recovery tree/history retention. Negative: fail-closed boot classification is tested for parse/compile failures.
- `marker_test.go`: Covered committed marker lifecycle and first-commit rollback marker/retry. Negative: marker write/retry logic is sound for active DB writes; no durable confirm-delete coverage.
- `nodeid_lenient_test.go`: Covered lenient warning for node-id mismatch. Negative: no A4 issue.
- `persist_failure_test.go`: Covered persist-before-promote, failed commit-confirmed not arming timers, nested targets, SyncApply degraded retry, auto-rollback retry, stale callback no-op. Negative: active-config write failures are well covered; durable confirm-state write/delete failures are not injected.
- `plaintext_downgrade_warn_4579_test.go`: Covered warning on plaintext DB that declares master-password. Negative: detects plaintext active DB downgrade; does not cover cleartext text rollback/rescue/archive surfaces in F5.
- `ra_interval_4525_test.go`: Covered RA interval cross-check. Negative: no A4 persistence issue.
- `redaction_placeholder_4060_test.go`: Covered reject of redaction placeholder on strict commit/check and tolerant load of persisted placeholder. Negative: redacted-export ingest is guarded.
- `rescue_redaction_leak_4099_test.go`: Covered generic position-only parse errors for redacted rescue display. Negative: rescue display redaction is fail-closed.
- `rollback_corrupt_log_4690_test.go`: Covered position-only corrupt rollback log. Negative: corrupt rollback file does not leak token text in logs.
- `store.go`: Covered Store fields, size cap, strict/lenient compile, SyncApply. Negative: lock discipline around `s.mu` is coherent; SyncApply participates in F1 through `clearPendingConfirmLocked`.
- `store_command.go`: Covered candidate edit verbs, load override/merge/set, flat verb validation. Negative: size checks cover config payload; annotation delimiter validation prevents format-parse injection.
- `store_commit.go`: Covered commit, commit-confirmed, confirm/rollback timers, history/journal, rollback-file persistence. Findings F1, F2, F5, F6.
- `store_format.go`: Covered cleartext and redacted renderers for active/candidate/rollback/compare. Negative: redacted variants consistently clone through `RedactedClone`; cleartext variants are documented as internal/persistence surfaces.
- `store_lock.go`: Covered config lock, stale lease reclaim, read-only gates, session release. Negative: no storage/crypto issue.
- `store_lock_3979_test.go`: Covered exclusive/shared lock release. Negative: lock release tests match helper semantics.
- `store_lock_lease_4476_test.go`: Covered lease reclaim. Negative: stale lock DoS is bounded.
- `store_new_test.go`: Covered `New` fail-closed when DB unusable. Negative: no file-only fallback panic path.
- `store_persist.go`: Covered Load, pending confirm recovery, active write seams, degraded retry, archive/rescue persistence/redaction. Findings F1 and F5.
- `store_test.go`: Covered broad store behavior, commit/rollback basics, timer first-commit bootstrap behavior, retired dataplane regression, and CLI-ish flows. Negative: broad behavior passes; no extra A4 finding beyond focused modules.
- `system_action_journal_4108_test.go`: Covered system action journal entries and exclusion from commit history. Negative: destructive action metadata is journaled and not exposed as commit history.
- `test_seams.go`: Covered testing hooks. Negative: seams cover active writes and timer invocation, but there is no seam for confirm-state write/delete failure, contributing to F1/F2 test gap.
- `typed_leaf_lenient_test.go`: Covered lenient load/sync for stale typed-leaf violations and strict commit rejects. Negative: strict/lenient split is intentional and tested.

### A5-b1

- `pkg/cluster/manager.go`: observed the known `Manager.Start` lock/monitor stop pattern from F-038-001; suppressed as duplicate. `Stop` copies handles under lock and stops outside lock.
- `pkg/cluster/heartbeat*.go`: HMAC validation, liveness timeout, never-seen cold-boot grace, IPv4/IPv6 family handling, heartbeat restart keepalive, and duplicate-node-id warnings were checked. Prior heartbeat auth-after-unmarshal and RG-count items are either duplicate-suppressed or guarded by current config/tests.
- `pkg/cluster/election*.go`: duplicate node-id fail-closed, non-preempt cold-boot hold, readiness gate, transfer-out override, and dual-active loser behavior were checked. New issue is only the dual-active winner event-drop path above.
- `pkg/cluster/failover*.go`: single-RG and batch transfer commit state, local transfer-out hold, commit grace, abort/restore, and readiness hooks were checked. Invariant: committed transfer suppresses stale heartbeat ownership long enough for the peer view to catch up.
- `pkg/cluster/sync*.go`: auth handshake, per-frame HMAC/replay checks, disconnect waiter cleanup, bulk ack record-before-send, failover/batch waiters, generation guards, config generation, and DHCP lease full-set receive were checked. Known 16 MiB frame allocation and prior handshake concerns were suppressed as duplicates.
- `pkg/vrrp/*.go`: packet checksum, IPv6 hop-limit and ifindex filters, dual-stack equal-priority tie-break, preempt hold revalidation/watchdog, GARP/NA abdication gate, source-address watcher, ifindex drift rebuild, manager reuse, and VRID guard were checked. No new VRRP finding.
- `pkg/ra/*.go`: per-interface tombstones, graceful/hard shutdown arbitration, standalone goodbye, replacement make-before-break, source link-local handling, RA option pruning, and interval floor were checked. Prior RA goodbye/time.After concerns appear addressed; no new RA finding.
- `pkg/conntrack/gc.go`: secondary GC skip, adaptive delay, aggressive-aging lock discipline, userspace SkipSweep, and per-IP count path were checked. No new conntrack finding.
- Test files in the batch were used as regression context for the above invariants, especially election, heartbeat, sync auth/bulk/lease wire, RA sender, VRRP packet/instance/manager/addrwatch/track, and conntrack GC.

### A6-b1

1. `pkg/dataplane/appid_catalog_parity_test.go` - test-only app catalog parity; no control/dataplane boundary finding.
2. `pkg/dataplane/apply.go` - compile-result cloning and apply metadata; checked result map copying and snapshot boundaries; no finding.
3. `pkg/dataplane/apply_test.go` - test-only compile-result copy coverage; no finding.
4. `pkg/dataplane/bpf_session_value.go` - session value layout conversion helpers; checked wire/native conversion role; no finding.
5. `pkg/dataplane/bpf_session_value_test.go` - test-only layout/value conversion coverage; no finding.
6. `pkg/dataplane/compiler.go` - compiler orchestration and result state; checked generation/result maps and retained shim context; no finding.
7. `pkg/dataplane/compiler_filter.go` - filter compile path; checked rule expansion/indexing surface at batch level; no finding.
8. `pkg/dataplane/compiler_filter_expansion_test.go` - test-only filter expansion coverage; no finding.
9. `pkg/dataplane/compiler_filter_protocol_test.go` - test-only protocol expansion coverage; no finding.
10. `pkg/dataplane/compiler_iface.go` - interface/zone compile path; checked ifindex/VLAN mapping and stale cleanup surfaces; no finding.
11. `pkg/dataplane/compiler_nat.go` - legacy compile NAT counters/pool IDs and NAT64; checked pool ID overflow/capacity and counter stability; no finding for active userspace boundary.
12. `pkg/dataplane/compiler_nat_counter_collision_test.go` - test-only NAT counter collision coverage; no finding.
13. `pkg/dataplane/compiler_nat_counter_stability_test.go` - test-only NAT counter stability coverage; no finding.
14. `pkg/dataplane/compiler_test.go` - test-only broad compiler coverage; no finding.
15. `pkg/dataplane/constants.go` - constants; checked for obvious queue/pool capacity contracts; no finding.
16. `pkg/dataplane/constants_test.go` - test-only constants coverage; no finding.
17. `pkg/dataplane/cpumask.go` - CPU mask helper; checked index sizing behavior; no finding.
18. `pkg/dataplane/cpumask_test.go` - test-only CPU mask coverage; no finding.
19. `pkg/dataplane/current_sessions_test.go` - test-only session iteration/current-session behavior; no finding.
20. `pkg/dataplane/dataplane.go` - dataplane interface contracts; checked session/NAT/map method signatures; no finding.
21. `pkg/dataplane/default_test.go` - test-only default policy coverage; no finding.
22. `pkg/dataplane/legacy_bpf_manifest_canary_test.go` - test-only retirement canary; no finding.
23. `pkg/dataplane/loader.go` - retained shim manager and no-op userspace compile dataplane; checked no-op NAT pool map writes; no finding.
24. `pkg/dataplane/loader_userspace_shim.go` - retained userspace shim loader/map specs; checked 32-pool map cap against no-op compile writer; no finding.
25. `pkg/dataplane/maps_counters.go` - counter map access; checked delta/counter index style; no finding.
26. `pkg/dataplane/maps_fabric.go` - fabric map writes; checked key/value update wrappers; no finding.
27. `pkg/dataplane/maps_filter.go` - filter map writes; checked array index update wrappers; no finding.
28. `pkg/dataplane/maps_flow.go` - flow map/config writes; checked scalar config writes; no finding.
29. `pkg/dataplane/maps_helpers.go` - map helper wrappers; checked update/delete helpers; no finding.
30. `pkg/dataplane/maps_mirror.go` - mirror map writes; checked mirror config key handling; no finding.
31. `pkg/dataplane/maps_nat.go` - NAT map access; checked pool/IP map index math and clear loops; no active userspace finding.
32. `pkg/dataplane/maps_policy.go` - policy map writes; checked zone-pair/rule update surface; no finding.
33. `pkg/dataplane/maps_screen.go` - screen config map writes; checked reason/index style; no finding.
34. `pkg/dataplane/maps_session.go` - legacy session map operations; checked key/value map operations; no finding.
35. `pkg/dataplane/maps_stale.go` - stale map cleanup; checked delete/zero loops for partial-apply risk; no finding.
36. `pkg/dataplane/maps_stats.go` - statistics map reads; checked counter read paths; no finding.
37. `pkg/dataplane/maps_stats_test.go` - test-only stats coverage; no finding.
38. `pkg/dataplane/nptv6_test.go` - test-only NPTv6 coverage; no finding.
39. `pkg/dataplane/persistent_nat.go` - persistent NAT store; checked lock/map use and lease ownership at batch level; no finding.
40. `pkg/dataplane/persistent_nat_test.go` - test-only persistent NAT coverage; no finding.
41. `pkg/dataplane/protected_iface_test.go` - test-only protected interface behavior; no finding.
42. `pkg/dataplane/proxyarp.go` - proxy ARP helpers; checked host/IP parsing role; no finding.
43. `pkg/dataplane/proxyarp_test.go` - test-only proxy ARP coverage; no finding.
44. `pkg/dataplane/retirement_boundary_canary_test.go` - test-only legacy retirement boundary; no finding.
45. `pkg/dataplane/runtime/import_canary_test.go` - test-only runtime import canary; no finding.
46. `pkg/dataplane/runtime/session_delta.go` - runtime session delta structs; checked boundary role; no finding.
47. `pkg/dataplane/screen_reason_counters_3343_test.go` - test-only screen counter coverage; no finding.
48. `pkg/dataplane/session_store.go` - session store and rollback path; checked cluster-synced installer selection and rollback semantics; no finding.
49. `pkg/dataplane/session_store_test.go` - test-only session store coverage; no finding.
50. `pkg/dataplane/types.go` - dataplane struct/layout constants; checked NAT/session/control widths; no finding beyond Finding 1 in parser users.
51. `pkg/dataplane/userspace/address_book_collision_2514_test.go` - test-only address-book collision coverage; no finding.
52. `pkg/dataplane/userspace/address_book_test.go` - test-only address-book coverage; no finding.
53. `pkg/dataplane/userspace/addressbook_slash_name_4340_test.go` - test-only slash-name coverage; no finding.
54. `pkg/dataplane/userspace/app_catalog_test.go` - test-only app catalog coverage; no finding.
55. `pkg/dataplane/userspace/app_inactivity_timeout_3227_test.go` - test-only app timeout coverage; no finding.
56. `pkg/dataplane/userspace/app_inactivity_timeout_precedence_3298_test.go` - test-only timeout precedence coverage; no finding.
57. `pkg/dataplane/userspace/app_set_reject_3727_test.go` - test-only app-set reject coverage; no finding.
58. `pkg/dataplane/userspace/applied_nat_view.go` - applied NAT view/generation guard; checked status-generation coupling; no finding.
59. `pkg/dataplane/userspace/applied_nat_view_test.go` - test-only applied NAT view coverage; no finding.
60. `pkg/dataplane/userspace/binding_ready_gate_test.go` - test-only binding readiness coverage; no finding.
61. `pkg/dataplane/userspace/boot_probe.go` - boot probe helpers; checked helper capability/status boundary; no finding.
62. `pkg/dataplane/userspace/boot_probe_test.go` - test-only boot probe coverage; no finding.
63. `pkg/dataplane/userspace/builder.go` - snapshot builder entry points; checked generation and snapshot shaping at batch level; no finding.
64. `pkg/dataplane/userspace/capabilities.go` - capability derivation/gates; checked HA/persistent-NAT support gates; no finding.
65. `pkg/dataplane/userspace/cold_path_sample_mask_test.go` - test-only cold path sample coverage; no finding.
66. `pkg/dataplane/userspace/cold_path_status_test.go` - test-only cold path status coverage; no finding.
67. `pkg/dataplane/userspace/configstore_helper_test.go` - test-only configstore helper coverage; no finding.
68. `pkg/dataplane/userspace/control.go` - manual control parser; Finding 1.
69. `pkg/dataplane/userspace/control_request_cap_2744_test.go` - test-only request-size cap coverage; no finding.
70. `pkg/dataplane/userspace/control_socket_deadline_4036_test.go` - test-only control socket deadline coverage; no finding.
71. `pkg/dataplane/userspace/control_test.go` - parser tests; Finding 1 test gap for negative indices.
72. `pkg/dataplane/userspace/controllers.go` - controller interfaces; checked control-plane boundary shape; no finding.
73. `pkg/dataplane/userspace/cos.go` - CoS snapshot/control shaping; checked queue/class map sizing at batch level; no finding.
74. `pkg/dataplane/userspace/cos_iface_level_4021_test.go` - test-only CoS interface-level coverage; no finding.
75. `pkg/dataplane/userspace/default_policy_3065_test.go` - test-only default policy coverage; no finding.
76. `pkg/dataplane/userspace/default_policy_counter_3363_test.go` - test-only default policy counter coverage; no finding.
77. `pkg/dataplane/userspace/default_policy_log_3534_test.go` - test-only default policy log coverage; no finding.
78. `pkg/dataplane/userspace/eventstream.go` - eventstream framing/ACK/callback queue; checked length cap, session-sync gap handling, ACK withholding, and decoder guards; no finding.
79. `pkg/dataplane/userspace/eventstream_test.go` - test-only eventstream coverage; checked gap/full-resync tests; no finding.
80. `pkg/dataplane/userspace/fabric.go` - fabric snapshot shaping; checked field widths and generation role; no finding.
81. `pkg/dataplane/userspace/fabric_up_4082_test.go` - test-only fabric-up coverage; no finding.
82. `pkg/dataplane/userspace/fairness.go` - fairness config helper; checked capacity/math at batch level; no finding.
83. `pkg/dataplane/userspace/fairness_test.go` - test-only fairness coverage; no finding.
84. `pkg/dataplane/userspace/fairness_throughput.go` - throughput/fairness helper; checked arithmetic role; no finding.
85. `pkg/dataplane/userspace/fairness_throughput_test.go` - test-only fairness throughput coverage; no finding.
86. `pkg/dataplane/userspace/fbf_snapshot_test.go` - test-only FBF snapshot coverage; no finding.
87. `pkg/dataplane/userspace/feed_enforcement_test.go` - test-only feed enforcement coverage; no finding.
88. `pkg/dataplane/userspace/filtercounters.go` - filter counter status mapping; checked counter ID use; no finding.
89. `pkg/dataplane/userspace/filters.go` - userspace filter snapshot build; checked term/rule expansion and protocol/address handling at batch level; no finding.
90. `pkg/dataplane/userspace/filters_address_except_3359_test.go` - test-only address-except coverage; no finding.
91. `pkg/dataplane/userspace/filters_address_matchany_except_4338_test.go` - test-only match-any except coverage; no finding.
92. `pkg/dataplane/userspace/filters_flex_match_3077_test.go` - test-only flex-match coverage; no finding.
93. `pkg/dataplane/userspace/filters_multivalue_2545_test.go` - test-only multivalue coverage; no finding.
94. `pkg/dataplane/userspace/filters_next_term_2544_test.go` - test-only next-term coverage; no finding.
95. `pkg/dataplane/userspace/filters_per_packet_match_2362_test.go` - test-only per-packet match coverage; no finding.
96. `pkg/dataplane/userspace/filters_port_except_2622_test.go` - test-only port-except coverage; no finding.
97. `pkg/dataplane/userspace/filters_prefix_list_2506_test.go` - test-only prefix-list coverage; no finding.
98. `pkg/dataplane/userspace/filters_protocol_ipv6_3393_test.go` - test-only IPv6 protocol coverage; no finding.
99. `pkg/dataplane/userspace/filters_snapshot_integrity_3406_test.go` - test-only filter snapshot integrity coverage; no finding.
100. `pkg/dataplane/userspace/flow.go` - flow wire conversion/coercion; checked numeric coercion and test agreement; no finding.
101. `pkg/dataplane/userspace/flow_numwidth_agreement_test.go` - test-only flow width agreement coverage; no finding.
102. `pkg/dataplane/userspace/flow_wire_coerce_test.go` - test-only flow wire coercion coverage; no finding.
103. `pkg/dataplane/userspace/format/buffers.go` - status formatting only; no control/dataplane boundary finding.
104. `pkg/dataplane/userspace/format/buffers_golden_test.go` - test-only buffers golden coverage; no finding.
105. `pkg/dataplane/userspace/format/buffers_model.go` - formatting model only; no finding.
106. `pkg/dataplane/userspace/format/buffers_test.go` - test-only buffers coverage; no finding.
107. `pkg/dataplane/userspace/format/cos.go` - CoS formatting only; no finding.
108. `pkg/dataplane/userspace/format/cos_golden_test.go` - test-only CoS golden coverage; no finding.
109. `pkg/dataplane/userspace/format/cos_sections.go` - CoS formatting sections only; no finding.
110. `pkg/dataplane/userspace/format/cos_show.go` - CoS show formatting only; no finding.
111. `pkg/dataplane/userspace/format/cos_show_test.go` - test-only CoS show coverage; no finding.
112. `pkg/dataplane/userspace/format/cos_test.go` - test-only CoS formatting coverage; no finding.
113. `pkg/dataplane/userspace/format/math.go` - formatting math helpers; checked divide/percentage style; no finding.
114. `pkg/dataplane/userspace/format/status.go` - status formatting only; no finding.
115. `pkg/dataplane/userspace/format/status_golden_test.go` - test-only status golden coverage; no finding.
116. `pkg/dataplane/userspace/format/status_sections.go` - status section formatting only; no finding.
117. `pkg/dataplane/userspace/format/status_test.go` - test-only status formatting coverage; no finding.
118. `pkg/dataplane/userspace/format/wireguard.go` - WireGuard formatting only; no finding.
119. `pkg/dataplane/userspace/format/wireguard_test.go` - test-only WireGuard formatting coverage; no finding.
120. `pkg/dataplane/userspace/host_inbound_classify.go` - host-inbound classifier; reviewed only enough to avoid duplicate host-inbound findings; no new finding.
121. `pkg/dataplane/userspace/host_inbound_classify_3627_test.go` - test-only host-inbound classifier coverage; no finding.
122. `pkg/dataplane/userspace/host_inbound_per_iface_3362_test.go` - test-only host-inbound per-interface coverage; no new finding.
123. `pkg/dataplane/userspace/host_inbound_phys_unit_3720_test.go` - test-only physical/unit host-inbound coverage; no new finding.
124. `pkg/dataplane/userspace/host_inbound_protocols_all_4411_test.go` - test-only host-inbound protocols coverage; no new finding.
125. `pkg/dataplane/userspace/host_inbound_unzoned_4420_test.go` - test-only unzoned host-inbound coverage; no new finding.
126. `pkg/dataplane/userspace/host_inbound_view_grouping_3721_test.go` - test-only host-inbound view grouping coverage; no finding.
127. `pkg/dataplane/userspace/inject.go` - packet injection control path; checked boundary role; no finding.
128. `pkg/dataplane/userspace/inject_test.go` - test-only injection coverage; no finding.
129. `pkg/dataplane/userspace/interfaces.go` - interface snapshot/binding generation; checked ifindex, VLAN, binding slot shape; no finding.
130. `pkg/dataplane/userspace/interfaces_test.go` - test-only interface snapshot coverage; no finding.
131. `pkg/dataplane/userspace/junos_host_policy_3019_test.go` - test-only Junos host policy coverage; no new finding.
132. `pkg/dataplane/userspace/junos_ping_icmp_3020_test.go` - test-only Junos ping/ICMP coverage; no finding.
133. `pkg/dataplane/userspace/legacy_dataplane.go` - legacy adapter into userspace manager; checked session installer method routing; no finding.
134. `pkg/dataplane/userspace/legacy_dataplane_test.go` - test-only legacy adapter coverage; no finding.
135. `pkg/dataplane/userspace/lenient_keep_armed_3261_test.go` - test-only lenient keep-armed coverage; no finding.
136. `pkg/dataplane/userspace/link_cycle_test.go` - test-only link cycle coverage; no finding.
137. `pkg/dataplane/userspace/manager.go` - manager state fields and lifecycle; checked locks, generation fields, status fields; no finding.
138. `pkg/dataplane/userspace/manager_capabilities_test.go` - test-only capability coverage; no finding.
139. `pkg/dataplane/userspace/manager_compile.go` - manager compile/apply boundary; checked compile/apply sequencing, helper request ordering, generation publication, and unsupported-feature gates; no finding.
140. `pkg/dataplane/userspace/manager_cos_test.go` - test-only manager CoS coverage; no finding.
141. `pkg/dataplane/userspace/manager_counters_test.go` - test-only manager counter coverage; no finding.
142. `pkg/dataplane/userspace/manager_coupling_test.go` - test-only manager coupling coverage; no finding.
143. `pkg/dataplane/userspace/manager_fabric_test.go` - test-only manager fabric coverage; no finding.
144. `pkg/dataplane/userspace/manager_flow_test.go` - test-only manager flow coverage; no finding.
145. `pkg/dataplane/userspace/manager_generation.go` - generation helpers; checked monotonic generation use; no finding.
146. `pkg/dataplane/userspace/manager_ha.go` - HA state, forwarding gates, session sync, status counter mirroring; checked RG active sequencing, watchdog throttling, session mirror error handling, and egress lookup; no finding.
147. `pkg/dataplane/userspace/manager_ha_test.go` - test-only HA coverage; no finding.
148. `pkg/dataplane/userspace/manager_interfaces_test.go` - test-only manager interface/egress lookup coverage; no finding.
149. `pkg/dataplane/userspace/manager_mirrors_test.go` - test-only mirror coverage; no finding.
150. `pkg/dataplane/userspace/manager_misc_test.go` - test-only misc manager coverage; no finding.

### A6-b2

- pkg/dataplane/userspace/manager_nat_test.go: Negative. Checked manager NAT snapshot/counter integration through batch NAT builders; no new manager boundary finding beyond the nested feed residual below.
- pkg/dataplane/userspace/manager_neighbor.go: Negative. Publishable-only neighbor index, publish-success bookkeeping, monitored-ifindex rebuild, and neighbor replacement path preserve fail-closed publish semantics.
- pkg/dataplane/userspace/manager_overlay.go: Negative. Route/feed overlay snapshots are cloned under lock; route overlay cache commits after non-error returns, preserving dirty-retry behavior.
- pkg/dataplane/userspace/manager_policy_test.go: Negative. Policy address-book expansion and snapshot assertions align with policy builder invariants reviewed below.
- pkg/dataplane/userspace/manager_policycounters_test.go: Negative. Counter status-to-BPF mirror coverage exists; no ID boundary issue found in this batch.
- pkg/dataplane/userspace/manager_republish_3780_test.go: Negative. Republish path is covered for content-hash/duplicate skip behavior; no new partial-apply finding.
- pkg/dataplane/userspace/manager_routes_test.go: Negative. Route snapshot tests cover preference, ECMP retention, RI metadata, connected prefixes, and family normalization.
- pkg/dataplane/userspace/manager_screens_test.go: Negative. Screen snapshot builder is deterministic and missing-profile status is separately represented.
- pkg/dataplane/userspace/manager_sessionsync_test.go: Negative. Session sync adapter paths are small fixed IPC requests; no oversized request framing issue found.
- pkg/dataplane/userspace/manager_snapshot_test.go: Negative. Snapshot assembly threads feed/route/scheduler state and records zone collision diagnostics; no fresh partial apply issue found.
- pkg/dataplane/userspace/manager_status.go: Negative. Status and control mutators hold manager lock across request/update, apply returned status through `applyHelperStatusLocked`, and stamp manager-owned diagnostics.
- pkg/dataplane/userspace/manager_testhelpers_test.go: Negative. Test helper map injection supports binding/cap tests; gap is queue>=16, recorded in Finding 1.
- pkg/dataplane/userspace/manager_tunnels_test.go: Negative. Tunnel endpoint snapshot tests cover stable endpoint selection and WireGuard wire shape.
- pkg/dataplane/userspace/maps.go: Negative. Registry centralizes userspace map names and tests guard literal drift.
- pkg/dataplane/userspace/maps_decouple_test.go: Negative. AST canaries cover direct literals, const aliases, concat, and method alias bypasses.
- pkg/dataplane/userspace/maps_sync.go: Finding 1. Binding queue id is not bounded to the fixed 16-slot stride before flat-array writes and ctrl queue publication.
- pkg/dataplane/userspace/maps_sync_addrlist_prune_3924_test.go: Negative. Local address map refresh avoids pruning on incomplete enumeration; no partial-map fail-open found.
- pkg/dataplane/userspace/maps_sync_cap_test.go: Finding 1 test gap. It pins ifindex/cap overflow but not queue ids at or above `BindingQueuesPerIface`.
- pkg/dataplane/userspace/maps_sync_heartbeat_slots_4572_test.go: Negative. Heartbeat zeroing clamps worker-derived slots to map capacity.
- pkg/dataplane/userspace/mirrors.go: Negative. Mirroring builder handles duplicate ingress and negative rates as scope-drops, not whole-table loss or uint wrap.
- pkg/dataplane/userspace/named_port_caseinsensitive_3372_test.go: Negative. Named port normalization path is covered; no L4 widen issue found.
- pkg/dataplane/userspace/nat.go: Finding 2. Direct feed NAT resolution is fixed; recursive address-set feed member resolution remains a documented residual.
- pkg/dataplane/userspace/nat64.go: Negative. NAT64 pool arrays are non-null, deterministic v6 params are guarded, and global no-v6-frag option is carried per rule.
- pkg/dataplane/userspace/nat64_deterministic_4559_test.go: Negative. Deterministic NAT64 /32 and /64 support plus unsupported guards are covered.
- pkg/dataplane/userspace/nat64_frag_header_test.go: Negative. Fragment-header/DF option coverage present; no boundary mismatch found.
- pkg/dataplane/userspace/nat_address_name_failclosed_3425_test.go: Negative. Empty/unresolvable NAT address names fail closed for direct references.
- pkg/dataplane/userspace/nat_dest_address_name_3229_test.go: Negative. DNAT destination address-name direct/static expansion is covered.
- pkg/dataplane/userspace/nat_dest_prefix_3164_test.go: Negative. DNAT host-vs-prefix split is covered.
- pkg/dataplane/userspace/nat_destination.go: Negative except Finding 2 upstream resolver. DNAT pool host validation, off entries, source constraints, app/source-port/ICMP constraints, and invalid-port fail-closed behavior are explicit.
- pkg/dataplane/userspace/nat_dnat_app_dport_3857_test.go: Negative. Explicit DNAT destination-port plus application behavior is covered, including invalid fail-closed cases.
- pkg/dataplane/userspace/nat_dnat_app_empty_3434_test.go: Negative. Empty/unresolvable application behavior remains fail-closed.
- pkg/dataplane/userspace/nat_dnat_app_match_3437_test.go: Negative. DNAT app source-port and ICMP type/code constraints are covered.
- pkg/dataplane/userspace/nat_dnat_match_dport_3446_test.go: Negative. Rule destination-port match is carried and invalid ports fail closed.
- pkg/dataplane/userspace/nat_dnat_off_3844_test.go: Negative. DNAT off/exemption entries are emitted so later DNAT rules do not translate exempt traffic.
- pkg/dataplane/userspace/nat_dnat_pool_3450_test.go: Negative. DNAT pool non-host/out-of-range validation is covered.
- pkg/dataplane/userspace/nat_dnat_port_range_3449_test.go: Negative. DNAT destination-port range expansion is covered.
- pkg/dataplane/userspace/nat_feed_overlay_3303_test.go: Finding 2 test gap. Direct feed and static+feed union are pinned, but nested address-set feed membership is not covered.
- pkg/dataplane/userspace/nat_l4_match_3429_test.go: Negative. Source NAT L4/app matching is carried and malformed specs fail closed.
- pkg/dataplane/userspace/nat_match_multivalue_3431_test.go: Negative. Multi-value NAT application/protocol/name expansion is covered.
- pkg/dataplane/userspace/nat_nptv6.go: Negative. NPTv6 rules are separated from non-NPTv6 static NAT support decisions.
- pkg/dataplane/userspace/nat_per_uplink_test.go: Negative. Per-uplink/source-NAT scope behavior has coverage; no new boundary issue found.
- pkg/dataplane/userspace/nat_reversed_port_range_3726_test.go: Negative. Reversed port ranges are treated as never-match instead of widening.
- pkg/dataplane/userspace/nat_scope_3096_test.go: Negative. Interface/routing-instance scope fields are carried.
- pkg/dataplane/userspace/nat_scope_precedence_4161_test.go: Negative. Source NAT most-specific context sort is pinned.
- pkg/dataplane/userspace/nat_source.go: Negative except Finding 2 upstream resolver. Pool validation, deterministic IPv4, port range/no-translation, source/dest address names, L4 constraints, and rule-set precedence are guarded.
- pkg/dataplane/userspace/nat_source_address_name_2416_test.go: Negative. SNAT source-address-name direct/static expansion is covered.
- pkg/dataplane/userspace/nat_source_deterministic_4559_test.go: Negative. IPv4 deterministic fields and IPv6 deferral are covered.
- pkg/dataplane/userspace/nat_source_pool_port_3906_test.go: Negative. Pool range/no-translation fields are carried.
- pkg/dataplane/userspace/nat_static.go: Negative. Static NAT mapped port clamps and source-address constraints are handled.
- pkg/dataplane/userspace/natcounters.go: Negative. Clear path resets both Go-side offsets and helper cumulative store, with no-helper status zeroing.
- pkg/dataplane/userspace/neighbors.go: Negative. Publishable filtering mirrors helper acceptance and deterministic snapshot sorting is present.
- pkg/dataplane/userspace/nested_app_set_policy_test.go: Negative. Nested app set policy expansion behavior is covered.
- pkg/dataplane/userspace/policies.go: Negative. Sentinels for unsupported applications/addresses are unparseable by design and fail closed.
- pkg/dataplane/userspace/policies_addrbook.go: Negative. Address-book IDs are deterministic, collision errors return rather than panic, and policy nested feed expansion is feed-aware.
- pkg/dataplane/userspace/policies_ids.go: Negative. Runtime policy ID write/read namespace uses the same `walkPolicyRuleSlots` contract and caps expansion at MaxRulesPerPolicy.
- pkg/dataplane/userspace/policies_lower.go: Negative. Policy lowering is feed-aware, emits fail-closed sentinels for unrepresentable content, and records rejected tokens for status.
- pkg/dataplane/userspace/policies_reject.go: Negative. Rejection reasons are built from the actual snapshot/sentinel path and include app-catalog build failures.
- pkg/dataplane/userspace/policies_representable.go: Negative. Structural representability and concrete contribution are decoupled to match strict validator semantics.
- pkg/dataplane/userspace/policies_scheduler.go: Negative. Scheduler inactive predicate is a shared SSOT and fails closed on unavailable state.
- pkg/dataplane/userspace/policy_global_zone_3148_test.go: Negative. Global policy zone context is covered.
- pkg/dataplane/userspace/policy_match_excluded_test.go: Negative. Match inversion wire behavior is covered.
- pkg/dataplane/userspace/policy_namespace_3143_3145_test.go: Negative. Policy ID namespace overflow/expansion tests cover write/read contract.
- pkg/dataplane/userspace/policy_reject_reasons_3376_test.go: Negative. Rejection diagnostics name scope and offending tokens.
- pkg/dataplane/userspace/policy_runtime_ids_3063_test.go: Negative. Runtime ID display mapping uses the same walk contract.
- pkg/dataplane/userspace/policycounters.go: Negative. Clear path mirrors helper reset behavior; no counter resurrection issue found.
- pkg/dataplane/userspace/policycounters_bulk_test.go: Negative. Bulk counter population/clear coverage exists.
- pkg/dataplane/userspace/process.go: Negative. Eventstream starts before helper, is cleaned up on start failure, stale XSKMAP is cleared, stop disables ctrl before helper exit and resets applied snapshot/status state.
- pkg/dataplane/userspace/process_control.go: Negative. Control socket framing has a 64 MiB sender cap matching receiver contract, scaled deadlines, newline framing, and EOF diagnostics.
- pkg/dataplane/userspace/process_linkcycle.go: Negative. Link cycle disables ctrl before worker stop/rebind, resets XSK liveness, and applies rebind status before rebootstrap.
- pkg/dataplane/userspace/process_napi.go: Negative. NAPI bootstrap/proactive neighbor probes are throttled and guard nil process/snapshot state.
- pkg/dataplane/userspace/process_status.go: Negative. Status loop applies helper status before watchdog/auto-rebind, syncs same-plan snapshots, handles catch-up bookkeeping, and avoids HA transition contention.
- pkg/dataplane/userspace/protocol.go: Negative for general wire fields; BindingStatus carries unbounded `QueueID uint32`, which is part of Finding 1.
- pkg/dataplane/userspace/protocol_failopen_2124_test.go: Negative. Unsupported application sentinel fail-open guard is covered.
- pkg/dataplane/userspace/protocol_null_collections_2214_test.go: Negative. Null/empty collection wire handling is covered.
- pkg/dataplane/userspace/protocol_test.go: Negative. Wire key roundtrips are broad; no queue-cap invariant test found.
- pkg/dataplane/userspace/route_overlay_test.go: Negative. Overlay replaces whole route entries, moves content hash, skips duplicates, and preserves dirty-retry semantics.
- pkg/dataplane/userspace/routes.go: Negative. Route snapshots include discard/preference in dedupe, surface RuleList errors, skip PBR-band selector rules, normalize table family per route, and sort deterministically.
- pkg/dataplane/userspace/routes_dedupe_3770_test.go: Negative. Discard/preference dedupe and deterministic route order are covered.
- pkg/dataplane/userspace/routes_family_normalize_4423_test.go: Negative. VRF-preserving family normalization disproves cross-VRF rewrite concern.
- pkg/dataplane/userspace/routes_fib_metadata_test.go: Negative. Preference and ECMP metadata are carried.
- pkg/dataplane/userspace/routes_ipv6_nexttable_3768_test.go: Negative. IPv6 next-table leak family is covered.
- pkg/dataplane/userspace/routes_pbr_priority_4479_test.go: Negative. PBR-band rules are skipped while route-leak band rules are ingested.
- pkg/dataplane/userspace/routes_ribgroup_leak_3876_test.go: Negative. Per-prefix rib-group leak capture and dst-less skip are covered.
- pkg/dataplane/userspace/routes_rulelist_3772_test.go: Negative. RuleList failure and malformed overlay destination behavior are covered.
- pkg/dataplane/userspace/runtime_delta.go: Negative. Runtime delta adapter copies status/reasons, backend epoch, truncation, zone IDs, fabric and NAT metadata.
- pkg/dataplane/userspace/runtime_delta_test.go: Negative. Delta adapter and userspace HA controller behavior are covered.
- pkg/dataplane/userspace/screens.go: Negative. Screen snapshot ordering is deterministic, missing profiles are explicit, and SYN-cookie master key derives from cluster-shared secret material.
- pkg/dataplane/userspace/shim_loader_boundary_test.go: Negative. Userspace path uses retained shim loader and blocks legacy loader references.
- pkg/dataplane/userspace/snapshot_allowlist_test.go: Negative. Userspace-bound Linux interface allowlist uses binding-target SSOT, filters management/tunnels, and handles VLAN parent binding.
- pkg/dataplane/userspace/snapshot_neighbors_1197_test.go: Negative. Neighbor snapshot publish/regen behavior is covered.
- pkg/dataplane/userspace/static_nat_mapped_port_2491_test.go: Negative. Static NAT port clamp tests cover wrap avoidance.
- pkg/dataplane/userspace/static_nat_source_address_3435_test.go: Negative. Static NAT source-address constraint is covered.
- pkg/dataplane/userspace/three_color_default_4535_test.go: Negative. Three-color default behavior covered outside this review's primary dataplane boundary.
- pkg/dataplane/userspace/tunnels.go: Negative. Tunnel endpoint IDs are stable, collisions drop later endpoint deterministically, TTL defaults to 64, and WG peers sort by pubkey.
- pkg/dataplane/userspace/tunnels_test.go: Negative. Tunnel snapshot contract is covered.
- pkg/dataplane/userspace/userspace_boot_canary_test.go: Negative. Boot/registry return the legacy adapter plus runtime dataplane surface.
- pkg/dataplane/userspace/wg_status_test.go: Negative. WireGuard status surface covered; no control-boundary issue found.
- pkg/dataplane/userspace/wire_uint8list.go: Negative. Numeric JSON array marshaling avoids Go base64 `[]uint8` framing; range rejects >255.
- pkg/dataplane/userspace/wire_uint8list_test.go: Negative. Numeric DSCP/codepoint wire and raw `[]uint8` graph guard are covered.
- pkg/dataplane/userspace/xdp_shim_decouple_test.go: Negative for degraded/local-control behavior. Binding tests use queue 0/1 only; queue>=16 gap is Finding 1.
- pkg/dataplane/userspace/zone_counters_status_test.go: Negative. Helper zone counters populate sparse offsets and wire roundtrip.
- pkg/dataplane/userspace/zone_local_addressbook_3061_test.go: Negative. Zone-local address-book policy resolution is covered.
- pkg/dataplane/userspace/zonecounters.go: Negative. Clear resets helper zone counter store and cached status without helper.
- pkg/dataplane/userspace/zones.go: Negative. Interface-zone mapping and host-inbound lifeline wrappers share config SSOT.
- pkg/dataplane/userspace/zones_addressless_3698_test.go: Negative. Addressless enforcing zone observability is covered.
- pkg/dataplane/userspace/zones_addressless_iface_3710_test.go: Negative. Per-interface/family DHCP-pending observability is covered.
- pkg/dataplane/userspace/zones_ambiguous_3718_test.go: Negative. Ambiguous host-inbound address detection is covered.
- pkg/dataplane/userspace/zones_collision_3719_test.go: Negative. Zone ID collision quarantine drops zones, interfaces, zone-pair policies, and scoped global policies deterministically.
- pkg/dataplane/userspace/zones_host_inbound.go: Negative. Host-inbound kernel views include default-deny zones, dynamic/static/VRRP addresses, lifeline exclusions, and interface override grouping.
- pkg/dataplane/userspace/zones_host_inbound_test.go: Negative. Zone host-inbound wire/default-deny/lifeline behavior is covered.
- pkg/dataplane/userspace/zones_observability.go: Negative. Addressless/ambiguous observability reads the same builder output used for enforcement.
- pkg/dataplane/userspace/zones_override.go: Negative. Interface host-inbound override merge is additive and prevents physical override leakage to different-zone units.
- pkg/dataplane/userspace/zones_quarantine.go: Negative. StableZoneID collision quarantine is internally consistent and avoids publishing duplicate IDs.
- pkg/dataplane/userspace/zones_snapshot.go: Negative. Zone snapshots use stable IDs, unconditional host-inbound configured default-deny, and TCP RST flag.
- pkg/dataplane/userspace/zones_stable_id_3704_test.go: Negative. Stable zone ID contract is covered.
- pkg/dataplane/userspace/zones_tcp_rst_3071_test.go: Negative. TCP RST wire flag is covered.
- pkg/dataplane/userspace_shim_loader_test.go: Negative. Shim loader capacity, pin migration, and incompatible pinned-map refusal are covered.
- pkg/dataplane/userspace_xdp_rust.go: Negative. Embedded Rust XDP object load is a thin spec loader; verifier checks are in verify file.
- pkg/dataplane/verify_userspace_shim.go: Negative. Verify-only load validates full spec before shrink, shrinks only hash maps on a copy, avoids pins/attachments, and surfaces verifier rejects.
- pkg/dataplane/verify_userspace_shim_test.go: Negative. Root-gated verifier and shrink-equivalence tests cover the deploy/build gate.
- pkg/dataplane/watchdog_test.go: Negative. HA watchdog missing-map error surface is covered.
- pkg/dataplane/zone_flood_counters_hide_test.go: Negative. Sparse offset read hides stable-hash zone IDs instead of dense-array OOB failures.
- pkg/dataplane/zoneid_stable_test.go: Negative. Compiler StableZoneID assignment is pinned.

### A7-b1

| File | Review result |
| --- | --- |
| `pkg/daemon/apply_ctx_cancel_test.go` | Reviewed daemon start/stop, signal cancellation, apply semaphore serialization, and teardown ordering; tests cover apply cancellation wiring and serialization. No new finding. |
| `pkg/daemon/apply_serialize_test.go` | Reviewed daemon start/stop, signal cancellation, apply semaphore serialization, and teardown ordering; tests cover apply cancellation wiring and serialization. No new finding. |
| `pkg/daemon/archive_atomic_4621_test.go` | Reviewed config archival and SCP path; current code uses end-of-options and timeout. Prior SCP option injection is deduped/fixed. No new finding. |
| `pkg/daemon/archive_config_3867_test.go` | Reviewed config archival and SCP path; current code uses end-of-options and timeout. Prior SCP option injection is deduped/fixed. No new finding. |
| `pkg/daemon/archive_timer_4078_test.go` | Reviewed config archival and SCP path; current code uses end-of-options and timeout. Prior SCP option injection is deduped/fixed. No new finding. |
| `pkg/daemon/bootstrap.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/bootstrap_rollback_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/bootstrap_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/coalescence.go` | Reviewed forwarding status/self-recovery/coalescence support at batch level; no new finding. |
| `pkg/daemon/coalescence_test.go` | Reviewed forwarding status/self-recovery/coalescence support at batch level; no new finding. |
| `pkg/daemon/commit_confirm_demote_4378_test.go` | Reviewed config sync/commit-confirm surfaces; nonfatal apply errors still sync peer by design and fatal errors skip sync. No new finding. |
| `pkg/daemon/compile_error_policy_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/compile_health_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/config_arrival_naming_4179_test.go` | Reviewed startup/device-map/link rename ordering, protected lifeline handling, and retry-on-config-arrival naming; no new finding. |
| `pkg/daemon/config_sync_test.go` | Reviewed config sync/commit-confirm surfaces; nonfatal apply errors still sync peer by design and fatal errors skip sync. No new finding. |
| `pkg/daemon/configstore_helper_test.go` | Reviewed in batch sweep; no new A7 lifecycle/host-integration finding beyond findings/dedup noted. |
| `pkg/daemon/configsync_tail_error_test.go` | Reviewed config sync/commit-confirm surfaces; nonfatal apply errors still sync peer by design and fatal errors skip sync. No new finding. |
| `pkg/daemon/daemon.go` | Reviewed in batch sweep; no new A7 lifecycle/host-integration finding beyond findings/dedup noted. |
| `pkg/daemon/daemon_apply.go` | Reviewed apply lock, cancellation boundaries, tail error joins, networkd/nft/IPsec/DHCP ordering. Commit-path IPsec and nft tail errors are surfaced; FRR/route warn-and-continue issues are deduped. |
| `pkg/daemon/daemon_apply_runtime_test.go` | Reviewed in batch sweep; no new A7 lifecycle/host-integration finding beyond findings/dedup noted. |
| `pkg/daemon/daemon_archive_timer.go` | Reviewed config archival and SCP path; current code uses end-of-options and timeout. Prior SCP option injection is deduped/fixed. No new finding. |
| `pkg/daemon/daemon_cluster_bind.go` | Reviewed config sync/commit-confirm surfaces; nonfatal apply errors still sync peer by design and fatal errors skip sync. No new finding. |
| `pkg/daemon/daemon_ddns.go` | Reviewed DDNS/Surface A HA publication scope and DHCP nudge coupling; no new finding. |
| `pkg/daemon/daemon_ddns_scope_test.go` | Reviewed DDNS/Surface A HA publication scope and DHCP nudge coupling; no new finding. |
| `pkg/daemon/daemon_ddns_surface_a.go` | Reviewed DDNS/Surface A HA publication scope and DHCP nudge coupling; no new finding. |
| `pkg/daemon/daemon_ddns_surface_a_test.go` | Reviewed DDNS/Surface A HA publication scope and DHCP nudge coupling; no new finding. |
| `pkg/daemon/daemon_ddns_test.go` | Reviewed DDNS/Surface A HA publication scope and DHCP nudge coupling; no new finding. |
| `pkg/daemon/daemon_dhcp.go` | Finding F3: management-only DHCP lease IPsec rebind logs and drops Apply/reload errors. DHCP client reconciliation itself is scoped and tested. |
| `pkg/daemon/daemon_dhcp_filter_4647_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/daemon_dhcp_lease_sync.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/daemon_dhcp_lease_sync_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/daemon_dhcp_leasesync_4647_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/daemon_dhcp_relay_gate_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/daemon_dhcprelay_reconcile_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/daemon_dns.go` | Reviewed resolved disable/mask/reconcile timeout behavior through batch sweep and tests. No new finding. |
| `pkg/daemon/daemon_dns_test.go` | Reviewed resolved disable/mask/reconcile timeout behavior through batch sweep and tests. No new finding. |
| `pkg/daemon/daemon_eventoptions_reconcile_test.go` | Reviewed RPM/event-options reconcile and shutdown order; no new finding. |
| `pkg/daemon/daemon_fabric_monitor_4031_test.go` | Reviewed in batch sweep; no new A7 lifecycle/host-integration finding beyond findings/dedup noted. |
| `pkg/daemon/daemon_feeds.go` | Reviewed in batch sweep; no new A7 lifecycle/host-integration finding beyond findings/dedup noted. |
| `pkg/daemon/daemon_flow.go` | Reviewed config archival and SCP path; current code uses end-of-options and timeout. Prior SCP option injection is deduped/fixed. No new finding. |
| `pkg/daemon/daemon_flowexport.go` | Reviewed flow exporter/trace lifecycle and error surfacing tests; no new finding. |
| `pkg/daemon/daemon_flowexport_flowdir_test.go` | Reviewed flow exporter/trace lifecycle and error surfacing tests; no new finding. |
| `pkg/daemon/daemon_flowexport_reconcile_test.go` | Reviewed flow exporter/trace lifecycle and error surfacing tests; no new finding. |
| `pkg/daemon/daemon_flowexport_session_close_test.go` | Reviewed flow exporter/trace lifecycle and error surfacing tests; no new finding. |
| `pkg/daemon/daemon_flowtrace_3932_test.go` | Reviewed flow exporter/trace lifecycle and error surfacing tests; no new finding. |
| `pkg/daemon/daemon_forwarding_status.go` | Reviewed forwarding status/self-recovery/coalescence support at batch level; no new finding. |
| `pkg/daemon/daemon_forwarding_status_test.go` | Reviewed forwarding status/self-recovery/coalescence support at batch level; no new finding. |
| `pkg/daemon/daemon_gc.go` | Reviewed NAT pool alarm/GC lifecycle tests; no new finding. |
| `pkg/daemon/daemon_gc_test.go` | Reviewed NAT pool alarm/GC lifecycle tests; no new finding. |
| `pkg/daemon/daemon_ha.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_fabric.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_fabric_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_fence_3917_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_sync.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_sync_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_userspace.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_userspace_convert.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_userspace_export.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_userspace_readiness.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_userspace_stream.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_ha_vip.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/daemon_health.go` | Reviewed in batch sweep; no new A7 lifecycle/host-integration finding beyond findings/dedup noted. |
| `pkg/daemon/daemon_ipmon.go` | Reviewed route-overlay actuation: hard FRR errors abort publish, degraded reload is explicit, pending FIB bump retries, context cancel covered. No new finding. |
| `pkg/daemon/daemon_ipmon_test.go` | Reviewed route-overlay actuation: hard FRR errors abort publish, degraded reload is explicit, pending FIB bump retries, context cancel covered. No new finding. |
| `pkg/daemon/daemon_ipsec_apply_test.go` | Tests confirm commit-path IPsec failure propagation and DHCP config re-render, but not retry/health on lease-path reload failure; F3 reports that gap. |
| `pkg/daemon/daemon_linkstate_monitor_3950_test.go` | Reviewed SNMP/link-state monitor netlink resubscribe and teardown seams; no new finding. |
| `pkg/daemon/daemon_lldp_reconcile_test.go` | LLDP reconcile test coverage inspected; no new finding. |
| `pkg/daemon/daemon_natpoolalarm.go` | Reviewed NAT pool alarm/GC lifecycle tests; no new finding. |
| `pkg/daemon/daemon_natpoolalarm_race_test.go` | Reviewed NAT pool alarm/GC lifecycle tests; no new finding. |
| `pkg/daemon/daemon_neighbor.go` | Reviewed neighbor netlink/probe guard loops and listener tests; unsolicited neighbor poisoning class is deduped. No new finding. |
| `pkg/daemon/daemon_neighbor_listener.go` | Reviewed neighbor netlink/probe guard loops and listener tests; unsolicited neighbor poisoning class is deduped. No new finding. |
| `pkg/daemon/daemon_neighbor_listener_test.go` | Reviewed neighbor netlink/probe guard loops and listener tests; unsolicited neighbor poisoning class is deduped. No new finding. |
| `pkg/daemon/daemon_networkd_apply_test.go` | Reviewed networkd/RETH/interface address integration tests and route inference. Known route-leak classes are deduped. No new finding. |
| `pkg/daemon/daemon_nft.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/daemon_policy_default_4342_test.go` | Reviewed policy invalidation/default-policy tests for stale session handling; no new finding. |
| `pkg/daemon/daemon_policy_invalidate.go` | Reviewed policy invalidation/default-policy tests for stale session handling; no new finding. |
| `pkg/daemon/daemon_policy_invalidate_test.go` | Reviewed policy invalidation/default-policy tests for stale session handling; no new finding. |
| `pkg/daemon/daemon_policy_modified_4234_test.go` | Reviewed policy invalidation/default-policy tests for stale session handling; no new finding. |
| `pkg/daemon/daemon_policy_scheduler_4343_test.go` | Reviewed scheduler republish under apply semaphore, retry latch, and cancellation tests; UTC/date behavior is deduped. No new finding. |
| `pkg/daemon/daemon_proxyarp.go` | Reviewed proxy-ARP reconcile and tests; no new finding. |
| `pkg/daemon/daemon_proxyarp_test.go` | Reviewed proxy-ARP reconcile and tests; no new finding. |
| `pkg/daemon/daemon_ra.go` | Reviewed RA lifecycle in apply/shutdown context; no new finding. |
| `pkg/daemon/daemon_reth.go` | Reviewed networkd/RETH/interface address integration tests and route inference. Known route-leak classes are deduped. No new finding. |
| `pkg/daemon/daemon_reth_rename_up_test.go` | Reviewed networkd/RETH/interface address integration tests and route inference. Known route-leak classes are deduped. No new finding. |
| `pkg/daemon/daemon_rpm.go` | Reviewed RPM/event-options reconcile and shutdown order; no new finding. |
| `pkg/daemon/daemon_rpm_test.go` | Reviewed RPM/event-options reconcile and shutdown order; no new finding. |
| `pkg/daemon/daemon_run.go` | Reviewed daemon start/stop, signal cancellation, apply semaphore serialization, and teardown ordering; tests cover apply cancellation wiring and serialization. No new finding. |
| `pkg/daemon/daemon_run_test.go` | Reviewed daemon start/stop, signal cancellation, apply semaphore serialization, and teardown ordering; tests cover apply cancellation wiring and serialization. No new finding. |
| `pkg/daemon/daemon_scheduler.go` | Reviewed scheduler republish under apply semaphore, retry latch, and cancellation tests; UTC/date behavior is deduped. No new finding. |
| `pkg/daemon/daemon_scheduler_republish_3780_test.go` | Reviewed scheduler republish under apply semaphore, retry latch, and cancellation tests; UTC/date behavior is deduped. No new finding. |
| `pkg/daemon/daemon_scheduler_test.go` | Reviewed scheduler republish under apply semaphore, retry latch, and cancellation tests; UTC/date behavior is deduped. No new finding. |
| `pkg/daemon/daemon_snmp_reconcile.go` | Reviewed SNMP/link-state monitor netlink resubscribe and teardown seams; no new finding. |
| `pkg/daemon/daemon_snmp_reconcile_test.go` | Reviewed SNMP/link-state monitor netlink resubscribe and teardown seams; no new finding. |
| `pkg/daemon/daemon_ssh_test.go` | Regression tests cover happy-path/reload/revocation behavior but not control-character injection; gap reported in F1/F2. |
| `pkg/daemon/daemon_sudoers_reconcile_3889_test.go` | Regression tests cover happy-path/reload/revocation behavior but not control-character injection; gap reported in F1/F2. |
| `pkg/daemon/daemon_system.go` | Findings F1/F2: generated sudoers/chrony/sshd/rsyslog files render unvalidated config strings; other root-auth/password hash paths have apply-boundary validation. |
| `pkg/daemon/dataplane_boot_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/device_map.go` | Reviewed startup/device-map/link rename ordering, protected lifeline handling, and retry-on-config-arrival naming; no new finding. |
| `pkg/daemon/device_map_startup_test.go` | Reviewed startup/device-map/link rename ordering, protected lifeline handling, and retry-on-config-arrival naming; no new finding. |
| `pkg/daemon/device_map_test.go` | Reviewed startup/device-map/link rename ordering, protected lifeline handling, and retry-on-config-arrival naming; no new finding. |
| `pkg/daemon/dhcp_nexthop_resolver_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/dhcp_recompile_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/dhcp_reconcile_test.go` | Reviewed DHCP client/lease sync/relay reconciliation and tests; F3 is limited to IPsec reload handling after management-only lease change. |
| `pkg/daemon/direct_announce_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/direct_garp_gate_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/direct_garp_probe_target_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/direct_vip_ownership_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/exec_timeout.go` | Reviewed helper command timeout/WaitDelay contract for apply-path execs. No new finding. |
| `pkg/daemon/failover_commit_ready_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/frr_failclosed_boot_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/frr_fullconfig_guard_test.go` | Reviewed in batch sweep; no new A7 lifecycle/host-integration finding beyond findings/dedup noted. |
| `pkg/daemon/hb165_bootstrap_batch_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/heartbeat_retry_ctx_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/host_inbound_addressless_3698_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/host_inbound_ambiguous_3718_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/host_inbound_nft_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/host_inbound_parity_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/host_inbound_per_iface_3362_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/host_inbound_ssot_render_3627_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/host_inbound_unzoned_4420_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/host_tunables.go` | Reviewed host tunable claim/restore behavior and apply-semaphore shutdown tests; no new finding. |
| `pkg/daemon/host_tunables_daemon.go` | Reviewed host tunable claim/restore behavior and apply-semaphore shutdown tests; no new finding. |
| `pkg/daemon/host_tunables_restore_applysem_4691_test.go` | Reviewed host tunable claim/restore behavior and apply-semaphore shutdown tests; no new finding. |
| `pkg/daemon/host_tunables_restore_test.go` | Reviewed host tunable claim/restore behavior and apply-semaphore shutdown tests; no new finding. |
| `pkg/daemon/host_tunables_test.go` | Reviewed host tunable claim/restore behavior and apply-semaphore shutdown tests; no new finding. |
| `pkg/daemon/interface_addr_test.go` | Reviewed networkd/RETH/interface address integration tests and route inference. Known route-leak classes are deduped. No new finding. |
| `pkg/daemon/ipsec_lease_rebind_test.go` | Tests confirm commit-path IPsec failure propagation and DHCP config re-render, but not retry/health on lease-path reload failure; F3 reports that gap. |
| `pkg/daemon/ipsec_sa_sync_empty_4385_test.go` | Tests confirm commit-path IPsec failure propagation and DHCP config re-render, but not retry/health on lease-path reload failure; F3 reports that gap. |
| `pkg/daemon/ipv6_static_nexthop_test.go` | Reviewed networkd/RETH/interface address integration tests and route inference. Known route-leak classes are deduped. No new finding. |
| `pkg/daemon/kernel_selfrecover.go` | Reviewed forwarding status/self-recovery/coalescence support at batch level; no new finding. |
| `pkg/daemon/legacy_dataplane_canary_synthetic_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/legacy_dataplane_canary_test.go` | Reviewed bootstrap/lifeline/fail-closed boot and compile-health surfaces; rollback and degraded states are explicit and tested. No new finding. |
| `pkg/daemon/linksetup.go` | Reviewed startup/device-map/link rename ordering, protected lifeline handling, and retry-on-config-arrival naming; no new finding. |
| `pkg/daemon/linksetup_collision_4178_test.go` | Reviewed startup/device-map/link rename ordering, protected lifeline handling, and retry-on-config-arrival naming; no new finding. |
| `pkg/daemon/linksetup_rename_test.go` | Reviewed startup/device-map/link rename ordering, protected lifeline handling, and retry-on-config-arrival naming; no new finding. |
| `pkg/daemon/lo0_filter_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/login_password.go` | Reviewed login password lifecycle; hash validation and marker/UID locking are covered. Username validation gap is reported via F1 at the sudoers renderer. |
| `pkg/daemon/login_password_functional_test.go` | Reviewed login password lifecycle; hash validation and marker/UID locking are covered. Username validation gap is reported via F1 at the sudoers renderer. |
| `pkg/daemon/login_password_test.go` | Reviewed login password lifecycle; hash validation and marker/UID locking are covered. Username validation gap is reported via F1 at the sudoers renderer. |
| `pkg/daemon/neighbor_periodic_guard_test.go` | Reviewed neighbor netlink/probe guard loops and listener tests; unsolicited neighbor poisoning class is deduped. No new finding. |
| `pkg/daemon/nft_chain_priority_test.go` | Reviewed host-inbound/lo0 nft rendering and apply error propagation tests; IPsec/host-inbound and semantic gaps are deduped. No new finding. |
| `pkg/daemon/ntp_test.go` | Regression tests cover happy-path/reload/revocation behavior but not control-character injection; gap reported in F1/F2. |
| `pkg/daemon/per_rg_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/per_rg_zoneid_3704_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/persistent_snat_apply_test.go` | Reviewed NAT pool alarm/GC lifecycle tests; no new finding. |
| `pkg/daemon/policy_scheduler_apply_test.go` | Reviewed scheduler republish under apply semaphore, retry latch, and cancellation tests; UTC/date behavior is deduped. No new finding. |
| `pkg/daemon/ra_source_test.go` | Reviewed RA lifecycle in apply/shutdown context; no new finding. |
| `pkg/daemon/resolve_neighbor_test.go` | Reviewed neighbor netlink/probe guard loops and listener tests; unsolicited neighbor poisoning class is deduped. No new finding. |
| `pkg/daemon/rg_state.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |
| `pkg/daemon/rg_state_test.go` | Reviewed HA/fabric/RG/failover ownership surfaces at a targeted level; known fabric refresh/route-leak class issues are deduped. No new finding. |

### A7-b2

- `pkg/daemon/rollback_resync_test.go`: Checked commit-confirmed timeout rollback peer-resync ordering and nil-peer behavior. Negative result: the tests assert peer resync happens after `PromoteRollback` and no-panic when cluster/session sync is absent; no additional lifecycle ordering bug found in this file.
- `pkg/daemon/rollback_serialize_test.go`: Checked `applySem` serialization, blocking-not-skipping, timer executor, and store/dataplane consistency assertions. Negative result: rollback/commit interleaving is covered with body overlap and final-store-vs-applied checks; no new race found in the test slice.
- `pkg/daemon/rss_indirection.go`: Checked ethtool execution, mlx5 driver gating, allowlist scoping, stale-table restoration, parser bounds, idempotence, and timeout behavior. Negative result: ethtool is invoked through `exec.CommandContext` argument vectors via `runCommandTimeout`, no shell surface; empty allowlist and non-mlx5 guards are explicit; parser stops before RSS hash-key data.
- `pkg/daemon/rss_indirection_test.go`: Checked edge-case matrix for worker/queue counts, allowlist scoping, disabled restore, stale worker transitions, hash-key parse regression, and missing/generic ethtool errors. Negative result: coverage is broad for the RSS lifecycle surface; no duplicate command-injection or ordering finding.
- `pkg/daemon/runtime_probes.go`: Checked daemon-local interface surfaces for dataplane readiness, NAT seeding, FIB sync, API/gRPC/CLI runtime contracts. Negative result: method lists are package-private and compile-time assertions plus call-site assignment make drift a build failure; no runtime nil-deref path found.
- `pkg/daemon/runtime_probes_test.go`: Checked compile-time assertions for legacy and userspace dataplane adapters. Negative result: the assertions cover all declared probes for both in-tree backends.
- `pkg/daemon/session_sync_readiness_test.go`: Checked peer connect/disconnect readiness holds, timeout fallback, bulk-received release, progress detection, ack handling, and cold-start reset. Finding A7-b2-02 covers the warm-reconnect test gap.
- `pkg/daemon/syslog_close_3579_test.go`: Checked stream-client replacement and event-mode teardown. Negative result: tests observe old connection `Close` exactly once and verify event mode clears clients; no fd leak candidate in this file.
- `pkg/daemon/syslog_source_test.go`: Checked source-interface primary address selection and unit-0 default. Negative result: source resolution prefers configured `PrimaryAddress` and falls back empty on absent kernel links in tests; schema contract read confirmed non-numeric units are rejected before the resolver silently defaults to unit 0.
- `pkg/daemon/syslog_teardown_3351_test.go`: Checked zero-stream removal behavior. Negative result: stream mode with no streams clears installed clients and the no-client case stays zero; no lingering-client finding.
- `pkg/daemon/system/dns.go`: Checked pure renderers for systemd-resolved drop-in and managed `/etc/resolv.conf`. Finding A7-b2-03 covers raw domain/search rendering with untyped inputs.
- `pkg/daemon/system/dns_test.go`: Checked renderer tests for server ordering, combined domain/search, duplicate suppression, empty config, and empty-string search preservation. Finding A7-b2-03 covers missing hostile domain/search cases.
- `pkg/daemon/tunnel_anchor_test.go`: Checked GRE/WireGuard tunnel collection, userspace anchor-only mode, MTU propagation, and routing-instance member normalization. Negative result: tests pin userspace anchor behavior, sourceless WireGuard retention, sourceless GRE exclusion, unit MTU override, and unit>0 RI list mapping.
- `pkg/daemon/userspace_sync_test.go`: Checked userspace HA session delta conversion, byte order, NAT aliasing, owner RG filtering, local-delivery/missing-neighbor suppression, failover readiness classification, event-stream ack behavior, high RG IDs, and event-stream wiring. Negative result: no new integer truncation or HA transfer-order bug found in this test slice.
- `pkg/daemon/vip_readiness_test.go`: Checked netlink link state gating, carrier-vs-admin state, no-VIP behavior, RG filtering, no-reth sync gating, and userspace RG detection. Negative result: carrier-aware readiness is pinned, including `OperUnknown` VLAN fallback; no route-leak/takeover readiness finding found here.
- `pkg/daemon/web_management_clamp_4047_test.go`: Checked unauthenticated REST bind clamp tests. Finding A7-b2-01 covers the untested `:port` wildcard bind that is classified as safe.
- `pkg/daemon/zoneid_ha_symmetry_test.go`: Checked stable zone ID HA invariant. Negative result: tests compare daemon `buildZoneIDs` directly to `config.StableZoneID` and pin stability across earlier-sorting zone additions.

### A7-b3

- Reviewed all 66 assigned files across IPsec, networkd, FRR, and routing teardown/reconciliation. The seven retained roots cover IPsec clear/reload ordering, stale networkd files, BGP cluster-id and route-map origin validation, failed netlink-delete ownership, and RPM probe-pin cleanup. Known FRR injection, PBR widening, XFRM if_id, GRE keepalive, and IPsec selector findings were suppressed against the prior index. Focused package tests passed.

### A8-b1

- `pkg/api/api.go`: Reviewed route setup, `writeJSON`, `decodeJSONBody`, query parsing helpers, auth middleware attachment, and static route grouping. Body cap and overflow handling are present. `queryInt` lenient parsing participates in Finding A8-b1-003.
- `pkg/api/auth.go`: Reviewed API-key/basic auth, constant-time comparisons, loopback metrics bypass, and health bypass. No authz bypass found; relevant timing and metrics-gate tests are present.
- `pkg/api/auth_consttime_4157_test.go`: Reviewed coverage for constant-time auth path. No finding.
- `pkg/api/auth_test.go`: Reviewed auth success/failure and middleware behavior coverage. No finding.
- `pkg/api/config.go`: Reviewed config mutation body decoding, redaction paths, compare/rollback/commit-confirmed handling, search/show/export, and candidate locks. Mutation handlers use capped decoding. No direct finding.
- `pkg/api/config_activate_test.go`: Reviewed activation error coverage. No finding.
- `pkg/api/config_commit_test.go`: Reviewed commit/commit-confirmed validation coverage. No finding.
- `pkg/api/config_load_bodycap_hb164_test.go`: Reviewed load body-cap coverage. No finding.
- `pkg/api/config_raw_ast_redaction_test.go`: Reviewed raw AST redaction coverage. No finding.
- `pkg/api/config_rollback_compare_strict_3443_test.go`: Reviewed strict rollback compare behavior. No finding.
- `pkg/api/config_secret_redaction_test.go`: Reviewed secret redaction coverage for config output surfaces. No finding.
- `pkg/api/configstore_helper_test.go`: Reviewed configstore helper setup used by API tests. No finding.
- `pkg/api/dhcp.go`: Reviewed REST DHCP clear/list surfaces. Chunked-body handling on `clearDHCPIdentifiersHandler` is unsafe; see Finding A8-b1-001.
- `pkg/api/exec_timeout.go`: Reviewed timeout command runner. Uses context deadline, no shell. No finding.
- `pkg/api/exec_timeout_test.go`: Reviewed command timeout coverage. No finding.
- `pkg/api/filter_counters_metrics_test.go`: Reviewed metrics filter/counter coverage. No finding.
- `pkg/api/health.go`: Reviewed health/readiness handlers and dependency reporting. No finding.
- `pkg/api/health_test.go`: Reviewed health/readiness coverage. No finding.
- `pkg/api/http_dos_hardening_4150_test.go`: Reviewed body-cap/timeout coverage. It documents the intended REST mutation body-cap invariant but does not cover the DHCP chunked-body case in Finding A8-b1-001.
- `pkg/api/iface_name_test.go`: Reviewed interface-name helper coverage. No finding.
- `pkg/api/interface_counter_error_test.go`: Reviewed interface counter error coverage. No finding.
- `pkg/api/interfaces.go`: Reviewed read-only interface state and filter handling. No injection or unbounded mutation issue found.
- `pkg/api/ipsec.go`: Reviewed read-only IPsec API surface. No finding.
- `pkg/api/metrics.go`: Reviewed metrics handler, registry generation, request handling, and auth interaction. No finding.
- `pkg/api/metrics_auth_gate_4162_test.go`: Reviewed metrics auth-gate coverage. No finding.
- `pkg/api/metrics_cold_path_test.go`: Reviewed cold-path metrics behavior. No finding.
- `pkg/api/metrics_counters.go`: Reviewed counter collector helpers and error propagation. No finding.
- `pkg/api/metrics_descriptor_coverage_test.go`: Reviewed descriptor coverage. No finding.
- `pkg/api/metrics_descriptors.go`: Reviewed descriptors and label schemas for drift. No finding.
- `pkg/api/metrics_drops_scope_4508_test.go`: Reviewed drop-scope metrics coverage. No finding.
- `pkg/api/metrics_flowexport_test.go`: Reviewed flow export metrics coverage. No finding.
- `pkg/api/metrics_frr_degraded_test.go`: Reviewed FRR degraded metrics coverage. No finding.
- `pkg/api/metrics_host_inbound_addressless_3698_test.go`: Reviewed host-inbound addressless coverage. No finding.
- `pkg/api/metrics_host_inbound_ambiguous_3718_test.go`: Reviewed ambiguous host-inbound coverage. No finding.
- `pkg/api/metrics_host_inbound_kernel_test.go`: Reviewed host-inbound kernel coverage. No finding.
- `pkg/api/metrics_nat.go`: Reviewed NAT metrics collectors. No finding.
- `pkg/api/metrics_nat_det_ipv6_4692_test.go`: Reviewed deterministic IPv6 NAT metrics coverage. No finding.
- `pkg/api/metrics_neighbor_latency_test.go`: Reviewed neighbor latency metrics coverage. No finding.
- `pkg/api/metrics_persist_degraded_test.go`: Reviewed degraded persistence metrics coverage. No finding.
- `pkg/api/metrics_scoped_global_3286_test.go`: Reviewed scoped global metrics coverage. No finding.
- `pkg/api/metrics_sessions.go`: Reviewed session metrics collectors and cache behavior. No finding.
- `pkg/api/metrics_sessions_cache_test.go`: Reviewed session metrics cache coverage. No finding.
- `pkg/api/metrics_sessions_userspace_3929_test.go`: Reviewed userspace session metrics coverage. No finding.
- `pkg/api/metrics_surface_a_ddns_test.go`: Reviewed DDNS metrics surface coverage. No finding.
- `pkg/api/metrics_system.go`: Reviewed system metrics collectors. No finding.
- `pkg/api/metrics_test.go`: Reviewed general metrics coverage. No finding.
- `pkg/api/metrics_userspace.go`: Reviewed userspace metrics collectors. No finding.
- `pkg/api/metrics_wireguard_test.go`: Reviewed WireGuard metrics coverage. No finding.
- `pkg/api/nat.go`: Reviewed NAT read APIs, session iteration, and stats paths. Iteration errors fail the request; no finding.
- `pkg/api/nat_stats_test.go`: Reviewed NAT stats coverage. No finding.
- `pkg/api/policies_bulk_reader_test.go`: Reviewed policy bulk-reader coverage. No finding.
- `pkg/api/policy_counters_test.go`: Reviewed policy counter coverage. No finding.
- `pkg/api/rest_events_forensic_3337_test.go`: Reviewed forensic event coverage. Does not cover malformed `limit`; see Finding A8-b1-003.
- `pkg/api/rest_events_zone0_3338_test.go`: Reviewed zone-0 event filter coverage. No finding.
- `pkg/api/rest_filter_failclosed_test.go`: Reviewed fail-closed REST filter coverage. It covers malformed event zone filters, but not malformed event `limit`; see Finding A8-b1-003.
- `pkg/api/routing.go`: Reviewed routing read surfaces and type selectors. No API-side command injection or unbounded mutation issue found.
- `pkg/api/security.go`: Reviewed policy, screen, zone, address inventory, events, and match-policies surfaces. Match-policies input validation is strict; event `limit` is lenient; see Finding A8-b1-003.
- `pkg/api/security_default_policy_log_3670_test.go`: Reviewed default-policy logging coverage. No finding.
- `pkg/api/security_matchpolicies_action_3375_test.go`: Reviewed action filter coverage. No finding.
- `pkg/api/security_matchpolicies_desc_sched_3685_test.go`: Reviewed description/scheduler coverage. No finding.
- `pkg/api/security_matchpolicies_dup_3709_test.go`: Reviewed duplicate match-policies input coverage. No finding.
- `pkg/api/security_matchpolicies_exclusion_3668_test.go`: Reviewed exclusion coverage. No finding.
- `pkg/api/security_matchpolicies_hostinbound_3627_test.go`: Reviewed host-inbound coverage. No finding.
- `pkg/api/security_matchpolicies_queried_zones_3627_test.go`: Reviewed queried-zones coverage. No finding.
- `pkg/api/security_matchpolicies_scheduler_3414_test.go`: Reviewed scheduler validation coverage. No finding.
- `pkg/api/security_matchpolicies_scope_3331_test.go`: Reviewed match-policies scope coverage. No finding.
- `pkg/api/security_policy_addr_inventory_3336_test.go`: Reviewed policy address inventory coverage. No finding.
- `pkg/api/security_policy_counter_handle_3474_test.go`: Reviewed policy counter handle coverage. No finding.
- `pkg/api/security_policy_id_zero_3623_test.go`: Reviewed policy ID zero coverage. No finding.
- `pkg/api/security_policy_scheduler_inventory_3624_test.go`: Reviewed scheduler inventory coverage. No finding.
- `pkg/api/security_scoped_global_3286_test.go`: Reviewed scoped-global security coverage. No finding.
- `pkg/api/security_screen_inventory_3327_test.go`: Reviewed screen inventory coverage. No finding.
- `pkg/api/security_screen_nil_3476_test.go`: Reviewed nil screen coverage. No finding.
- `pkg/api/security_test.go`: Reviewed general security API coverage. No finding.
- `pkg/api/security_zone_hostinbound_3328_test.go`: Reviewed zone host-inbound coverage. No finding.
- `pkg/api/security_zone_local_3358_test.go`: Reviewed local zone coverage. No finding.
- `pkg/api/security_zone_nil_3493_test.go`: Reviewed nil zone coverage. No finding.
- `pkg/api/security_zone_policy_meta_3329_test.go`: Reviewed zone policy metadata coverage. No finding.
- `pkg/api/server.go`: Reviewed server construction, TLS setup, listener startup, and shutdown flow. Noted a low-grade shutdown robustness risk from shared shutdown budget and ignored HTTPS shutdown error, but did not elevate it to a finding because the HTTP shutdown result is still returned and there is no demonstrated security boundary failure in this batch.
- `pkg/api/sessions.go`: Reviewed REST session filters, cursor/offset pagination, clear-session guard, peer inclusion, and summary handling. Peer session request does not preserve cursor-mode page sizing; see Finding A8-b1-002.
- `pkg/api/sessions_ha_scope_3423_test.go`: Reviewed HA peer inclusion coverage. It checks first-page attachment and non-first-page omission but only with tiny peer responses; see Finding A8-b1-002.
- `pkg/api/sessions_iterator_error_test.go`: Reviewed iterator error coverage. No finding.
- `pkg/api/sessions_pagination_test.go`: Reviewed pagination validation and cursor coverage. No finding beyond peer page-size gap in Finding A8-b1-002.
- `pkg/api/sessions_parity_test.go`: Reviewed REST/gRPC parity coverage. No finding.
- `pkg/api/sessions_zonepair_peer_3592_test.go`: Reviewed zone-pair peer coverage. No finding.
- `pkg/api/show_text.go`: Reviewed text rendering helpers. No finding.
- `pkg/api/sse.go`: Reviewed SSE category/severity filters, bounded subscription, JSON event encoding, flush loop, and context exit. No finding.
- `pkg/api/sse_filter_failclosed_3383_test.go`: Reviewed SSE fail-closed filter coverage. No finding.
- `pkg/api/sse_test.go`: Reviewed SSE behavior coverage. No finding.
- `pkg/api/stats.go`: Reviewed global/interface stats, failure handling, and dataplane degraded reporting. No finding.
- `pkg/api/stats_counter_error_test.go`: Reviewed stats counter error coverage. No finding.
- `pkg/api/stats_global_host_inbound_3681_test.go`: Reviewed host-inbound global stats coverage. No finding.
- `pkg/api/stats_global_parity_3426_test.go`: Reviewed global stats parity coverage. No finding.
- `pkg/api/system.go`: Reviewed system action allowlist, action audit journaling, command execution, diagnostics, buffers, and system-info selectors. Diagnostics use argv arrays and timeout contexts. No finding.
- `pkg/api/system_action_audit_4484_test.go`: Reviewed action audit coverage. No finding.
- `pkg/api/system_argv_test.go`: Reviewed argv/option-confusion coverage for system diagnostics. No finding.
- `pkg/api/system_buffers_test.go`: Reviewed buffer API coverage. No finding.
- `pkg/api/tls_test.go`: Reviewed TLS server configuration coverage. No finding.
- `pkg/api/types.go`: Reviewed REST response/schema structs for obvious schema drift. No direct finding.
- `pkg/api/vrrp.go`: Reviewed VRRP read surface. No finding.
- `pkg/api/write_json_4541_test.go`: Reviewed JSON write error/status coverage. No finding.
- `pkg/api/zone_counter_doc_ref_test.go`: Reviewed zone counter documentation reference coverage. No finding.
- `pkg/api/zone_counters_hide_test.go`: Reviewed hidden zone counter coverage. No finding.
- `pkg/api/zones_policies_counter_error_test.go`: Reviewed zone/policy counter error coverage. No finding.

### A8-b2

| File | Review result |
| --- | --- |
| `pkg/grpcapi/apply_result.go` | Negative: helper only wraps dataplane apply result lookup; no API input/authz issue. |
| `pkg/grpcapi/clear_sessions_errors_test.go` | Negative: covers iterator/delete/peer partial-error behavior; no additional finding. |
| `pkg/grpcapi/clear_sessions_peer_nodeid_3423_test.go` | Negative: peer clear error messaging coverage reviewed; no additional finding. |
| `pkg/grpcapi/clear_sessions_reversekey_test.go` | Negative: reverse-key deletion regression coverage reviewed; no additional finding. |
| `pkg/grpcapi/completion_test.go` | Negative: completion behavior coverage reviewed; no additional finding. |
| `pkg/grpcapi/completion_typed_leaf_test.go` | Negative: typed leaf completion coverage reviewed; no additional finding. |
| `pkg/grpcapi/configstore_helper_test.go` | Negative: test helper only; no API issue. |
| `pkg/grpcapi/exec_timeout.go` | Negative: command helpers use context deadlines, `WaitDelay`, and bounded tail counts. |
| `pkg/grpcapi/exec_timeout_test.go` | Negative: timeout/clamp coverage reviewed. |
| `pkg/grpcapi/fabric_auth.go` | Negative: fabric HMAC token and dual-accept policy reviewed; no fresh auth bypass. |
| `pkg/grpcapi/flow_cluster_counter_error_test.go` | Negative: flow counter error coverage reviewed. |
| `pkg/grpcapi/global_stats_counter_error_test.go` | Negative: global counter failure coverage reviewed. |
| `pkg/grpcapi/global_stats_screen_keys_3343_test.go` | Negative: screen counter key coverage reviewed. |
| `pkg/grpcapi/iface_name_test.go` | Negative: interface name resolution regression coverage reviewed. |
| `pkg/grpcapi/interface_counter_error_test.go` | Negative: counter read error surfacing coverage reviewed. |
| `pkg/grpcapi/pagination_test.go` | Negative: session pagination coverage reviewed; no fresh pagination issue. |
| `pkg/grpcapi/policies_bulk_reader_test.go` | Negative: policy bulk reader coverage reviewed. |
| `pkg/grpcapi/runtime.go` | Negative: narrowed gRPC dataplane interface reviewed; supports Finding 2 contract only. |
| `pkg/grpcapi/runtime_canary_test.go` | Negative: runtime interface canary reviewed. |
| `pkg/grpcapi/server.go` | Finding F1: unbounded `GracefulStop` can hang shutdown with active streams. Fabric auth/allowlist otherwise negative. |
| `pkg/grpcapi/server_bgp_status_ip_guard_4588_test.go` | Negative: BGP neighbor IP guard coverage reviewed. |
| `pkg/grpcapi/server_cluster.go` | Negative: MatchPolicies and Complete validate malformed IPs, ports, protocol, ICMP values, and negative cursor position; no fresh issue. |
| `pkg/grpcapi/server_cluster_monitor_status_4480_test.go` | Negative: cluster monitor status coverage reviewed. |
| `pkg/grpcapi/server_cluster_test.go` | Negative: cluster API regression coverage reviewed. |
| `pkg/grpcapi/server_config.go` | Negative: config locks are bounded by store idle lease; rollback/show compare numeric validation reviewed. |
| `pkg/grpcapi/server_config_activate_test.go` | Negative: activate/deactivate coverage reviewed. |
| `pkg/grpcapi/server_config_redaction_test.go` | Negative: config redaction coverage reviewed. |
| `pkg/grpcapi/server_config_test.go` | Negative: config RPC validation coverage reviewed. |
| `pkg/grpcapi/server_dhcp.go` | Negative: DHCP lease/DUID APIs have no shell construction; interface string is delegated to DHCP manager. |
| `pkg/grpcapi/server_diag.go` | Negative: diag glue/proxy helpers reviewed with stream handlers. |
| `pkg/grpcapi/server_diag_argv_test.go` | Negative: ping/traceroute argv separator and VRF prefix coverage reviewed. |
| `pkg/grpcapi/server_diag_monitor.go` | Finding F1: long-lived `MonitorInterface` stream only observes stream context. Packet-drop validation otherwise negative. |
| `pkg/grpcapi/server_diag_monitor_test.go` | Negative: monitor dataplane projection coverage reviewed. |
| `pkg/grpcapi/server_diag_ping.go` | Negative: ping/traceroute clamp count and use bounded `streamDiagCmd`; no fresh injection issue. |
| `pkg/grpcapi/server_diag_stream_test.go` | Negative: streaming command kill/unblock coverage reviewed. |
| `pkg/grpcapi/server_diag_system_action.go` | Finding F4: userspace slot/queue IDs accept negative signed values before uint32 conversion. Destructive action journaling and fabric gating otherwise negative. |
| `pkg/grpcapi/server_diag_zeroize.go` | Negative: zeroize erases config/rendered/login artifacts with scoped paths and marker checks; no fresh source finding. |
| `pkg/grpcapi/server_fabric_allowlist_4122_test.go` | Negative: fabric allowlist denies destructive methods and gates SystemAction by nested action. |
| `pkg/grpcapi/server_fabric_auth_4107_test.go` | Negative: fabric auth interceptor coverage reviewed. |
| `pkg/grpcapi/server_helpers.go` | Negative: helper parsing/rendering reviewed; NAT session count full scans are read-only and not reported beyond Finding 2. |
| `pkg/grpcapi/server_input_validation_test.go` | Negative: Complete negative position coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_action_3375_test.go` | Negative: MatchPolicies default action coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_desc_sched_3685_test.go` | Negative: policy description/scheduler coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_exclusion_3668_test.go` | Negative: address exclusion coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_hostinbound_3627_test.go` | Negative: host-inbound MatchPolicies coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_queried_zones_3627_test.go` | Negative: queried zone echo coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_routedrop_4413_test.go` | Negative: route-drop advisory coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_scheduler_3414_test.go` | Negative: scheduler fail-closed coverage reviewed. |
| `pkg/grpcapi/server_matchpolicies_scope_3331_test.go` | Negative: scoped policy identity coverage reviewed. |
| `pkg/grpcapi/server_missing_zone_3355_test.go` | Negative: missing-zone rejection coverage reviewed. |
| `pkg/grpcapi/server_nat.go` | Negative: NAT stats clamp large port counts and do not build commands from request strings. |
| `pkg/grpcapi/server_nat_test.go` | Negative: NAT show panic coverage reviewed. |
| `pkg/grpcapi/server_packet_drop_validation_3382_test.go` | Negative: MonitorPacketDrop rejects invalid node/count/ports/protocol/zone/interface and caps count. |
| `pkg/grpcapi/server_policy_id_zero_3623_test.go` | Negative: policy id presence coverage reviewed. |
| `pkg/grpcapi/server_proto_validation_test.go` | Negative: proto validation coverage reviewed. |
| `pkg/grpcapi/server_recvsize_hb164_test.go` | Negative: receive-size coverage reviewed. |
| `pkg/grpcapi/server_rollback_negative_n_4589_test.go` | Negative: rollback negative input coverage reviewed. |
| `pkg/grpcapi/server_routing.go` | Negative: BGP neighbor route/detail selectors validate IPs before FRR wrappers. |
| `pkg/grpcapi/server_screen_inventory_3327_test.go` | Negative: screen inventory coverage reviewed. |
| `pkg/grpcapi/server_security_nil_3476_test.go` | Negative: nil tolerant security rendering coverage reviewed. |
| `pkg/grpcapi/server_sessions.go` | Finding F2: filtered ClearSessions accumulates all matching keys before deletion. Session filter/pagination validation otherwise negative. |
| `pkg/grpcapi/server_sessions_test.go` | Negative: session API regression coverage reviewed. |
| `pkg/grpcapi/server_show.go` | Negative: ShowText dispatch/log topic reviewed; log path uses `filepath.Base` and bounded tail count. |
| `pkg/grpcapi/server_show_appid.go` | Negative: app-id show wrapper reviewed. |
| `pkg/grpcapi/server_show_appid_test.go` | Negative: app-id show test reviewed. |
| `pkg/grpcapi/server_show_chassis.go` | Negative: chassis show text reviewed. |
| `pkg/grpcapi/server_show_chassis_forwarding_test.go` | Negative: peer forwarding recursion guard coverage reviewed. |
| `pkg/grpcapi/server_show_cluster_text.go` | Negative: cluster text renderers reviewed. |
| `pkg/grpcapi/server_show_compare_strict_3443_test.go` | Negative: compare rollback strictness coverage reviewed. |
| `pkg/grpcapi/server_show_cos_gap7_test.go` | Negative: CoS show coverage reviewed. |
| `pkg/grpcapi/server_show_device_map.go` | Negative: device-map show reviewed. |
| `pkg/grpcapi/server_show_dhcp_lldp_snmp.go` | Negative: DHCP/LLDP/SNMP show renderers reviewed; no command injection path. |
| `pkg/grpcapi/server_show_events.go` | Negative: GetEvents clamps limit to 10000 and validates zone range. |
| `pkg/grpcapi/server_show_events_forensic_3337_test.go` | Negative: forensic event field coverage reviewed. |
| `pkg/grpcapi/server_show_events_historical_zone_3335_test.go` | Negative: historical zone-name coverage reviewed. |
| `pkg/grpcapi/server_show_events_zone0_3338_test.go` | Negative: zone 0 event selector coverage reviewed. |
| `pkg/grpcapi/server_show_events_zone_3334_test.go` | Negative: event zone validation coverage reviewed. |
| `pkg/grpcapi/server_show_firewall.go` | Negative: test-policy parser has duplicate selector guard; used as invariant contrast for Finding F3. |
| `pkg/grpcapi/server_show_firewall_test.go` | Negative: firewall show/test-policy coverage reviewed. |
| `pkg/grpcapi/server_show_flow.go` | Negative: flow show renderers reviewed. |
| `pkg/grpcapi/server_show_forwarding.go` | Negative: forwarding show renderers reviewed. |
| `pkg/grpcapi/server_show_forwarding_adapter_test.go` | Negative: forwarding adapter coverage reviewed. |
| `pkg/grpcapi/server_show_golden_test.go` | Negative: golden text coverage reviewed. |
| `pkg/grpcapi/server_show_interfaces.go` | Negative: interface detail filter is prefix-only over config names; no shell/path issue. |
| `pkg/grpcapi/server_show_interfaces_reth_4328_test.go` | Negative: reth interface coverage reviewed. |
| `pkg/grpcapi/server_show_interfaces_text.go` | Negative: interface text renderers use config/sysfs reads; no request-built shell. |
| `pkg/grpcapi/server_show_nat.go` | Negative: delegates to shared NAT renderers; no fresh issue. |
| `pkg/grpcapi/server_show_nat_shared_test.go` | Negative: NAT shared renderer parity coverage reviewed. |
| `pkg/grpcapi/server_show_nat_test.go` | Negative: NAT detail panic coverage reviewed. |
| `pkg/grpcapi/server_show_policies_addr_inventory_3336_test.go` | Negative: policy address inventory coverage reviewed. |
| `pkg/grpcapi/server_show_policies_hitcount_gate_test.go` | Negative: hit-count gate coverage reviewed. |
| `pkg/grpcapi/server_show_policies_hitcount_globals_test.go` | Negative: global hit-count coverage reviewed. |
| `pkg/grpcapi/server_show_policies_scheduler_3062_test.go` | Negative: scheduler policy text coverage reviewed. |
| `pkg/grpcapi/server_show_policies_text.go` | Negative: policy text renderers reviewed; no new API input issue. |
| `pkg/grpcapi/server_show_policies_text_exclusion_3667_test.go` | Negative: policy exclusion text coverage reviewed. |
| `pkg/grpcapi/server_show_policies_text_scoped_global_3357_test.go` | Negative: scoped global policy text coverage reviewed. |
| `pkg/grpcapi/server_show_policies_thencount_3074_test.go` | Negative: then-count coverage reviewed. |
| `pkg/grpcapi/server_show_policies_zone_local_3358_test.go` | Negative: zone-local policy text coverage reviewed. |
| `pkg/grpcapi/server_show_rollback_zero_n_4556_test.go` | Negative: rollback zero coverage reviewed. |
| `pkg/grpcapi/server_show_routes_text.go` | Finding F3: `test-routing:` parser accepts duplicate selector keys with silent last-wins. |
| `pkg/grpcapi/server_show_rpm_test.go` | Negative: RPM show coverage reviewed. |
| `pkg/grpcapi/server_show_screen_inventory_text_3327_test.go` | Negative: screen inventory text coverage reviewed. |
| `pkg/grpcapi/server_show_security_log_zone_3547_test.go` | Negative: security-log zone filtering coverage reviewed. |
| `pkg/grpcapi/server_show_security_text.go` | Negative: security text renderers reviewed; no fresh issue. |
| `pkg/grpcapi/server_show_security_wireguard_test.go` | Negative: WireGuard show coverage reviewed. |
| `pkg/grpcapi/server_show_status.go` | Negative: system-info type switch uses fixed argv via timeout helper; unknown types rejected. |
| `pkg/grpcapi/server_show_status_3929_test.go` | Negative: status session count coverage reviewed. |
| `pkg/grpcapi/server_show_system.go` | Negative: system show renderers reviewed. |
| `pkg/grpcapi/server_show_system_buffers_test.go` | Negative: system buffers coverage reviewed. |
| `pkg/grpcapi/server_show_test_routing_unknownkey_4589_test.go` | Finding F3 test gap: covers unknown/malformed routing selectors but not duplicates. |
| `pkg/grpcapi/server_show_testpolicy_srcport_test.go` | Negative: test-policy source-port coverage reviewed. |
| `pkg/grpcapi/server_show_zones.go` | Negative: zones structured/text helpers reviewed. |
| `pkg/grpcapi/server_show_zones_default_policy_3363_test.go` | Negative: default policy coverage reviewed. |
| `pkg/grpcapi/server_show_zones_default_policy_log_3670_test.go` | Negative: default policy log coverage reviewed. |
| `pkg/grpcapi/server_show_zones_explicit_any_3680_test.go` | Negative: explicit any-zone policy coverage reviewed. |
| `pkg/grpcapi/server_show_zones_hostinbound_3328_test.go` | Negative: host-inbound zone coverage reviewed. |
| `pkg/grpcapi/server_show_zones_hostinbound_display_3654_test.go` | Negative: host-inbound display coverage reviewed. |
| `pkg/grpcapi/server_show_zones_lifeline_3682_test.go` | Negative: lifeline zone coverage reviewed. |
| `pkg/grpcapi/server_show_zones_metadata_3684_test.go` | Negative: zone metadata coverage reviewed. |
| `pkg/grpcapi/server_show_zones_policy_tiers_3658_test.go` | Negative: zone policy tiers coverage reviewed. |
| `pkg/grpcapi/server_show_zones_scheduler_inventory_3624_test.go` | Negative: scheduler inventory coverage reviewed. |
| `pkg/grpcapi/server_show_zones_scoped_global_3286_test.go` | Negative: scoped global zone coverage reviewed. |
| `pkg/grpcapi/server_show_zones_test.go` | Negative: zones show coverage reviewed. |
| `pkg/grpcapi/server_show_zones_text.go` | Negative: zones text rendering reviewed. |
| `pkg/grpcapi/server_testpolicy_dup_3709_test.go` | Negative: test-policy duplicate-key regression coverage reviewed; does not cover Finding F3 routing parser. |
| `pkg/grpcapi/server_testpolicy_strictness_3696_test.go` | Negative: test-policy strictness coverage reviewed. |
| `pkg/grpcapi/server_zone_nil_3493_test.go` | Negative: nil zone coverage reviewed. |
| `pkg/grpcapi/session_app_srcport_3428_test.go` | Negative: session app/source-port coverage reviewed. |
| `pkg/grpcapi/session_egress_drift_4650_test.go` | Negative: session egress drift coverage reviewed. |
| `pkg/grpcapi/session_filter_3439_test.go` | Negative: session filter validation coverage reviewed. |
| `pkg/grpcapi/session_filter_test.go` | Negative: session filter coverage reviewed. |
| `pkg/grpcapi/sessions_iterator_error_test.go` | Negative: iterator error surfacing coverage reviewed. |
| `pkg/grpcapi/system_action_failover_node_4693_test.go` | Negative: unsupported failover target coverage reviewed. |
| `pkg/grpcapi/system_action_journal_4108_test.go` | Negative: destructive SystemAction journal coverage reviewed. |
| `pkg/grpcapi/system_action_test.go` | Finding F4 test gap: positive userspace-inject covered, negative slot/queue/binding IDs not covered. |
| `pkg/grpcapi/test_commands_test.go` | Negative: ShowText test-policy/runtime parity coverage reviewed. |
| `pkg/grpcapi/text_filter_flood_counter_error_test.go` | Negative: text filter counter error coverage reviewed. |
| `pkg/grpcapi/xpfv1/xpf.pb.go` | Negative: generated request/response schema reviewed for relevant RPC field types; no generated-source finding. |
| `pkg/grpcapi/xpfv1/xpf_grpc.pb.go` | Negative: generated service registration reviewed for streaming/unary shape; no generated-source finding. |
| `pkg/grpcapi/zeroize_configdb_4576_test.go` | Negative: configdb zeroize coverage reviewed. |
| `pkg/grpcapi/zeroize_login_4598_test.go` | Negative: login-account zeroize coverage reviewed. |
| `pkg/grpcapi/zeroize_rendered_4585_test.go` | Negative: rendered-config zeroize coverage reviewed. |
| `pkg/grpcapi/zeroize_tls_4599_test.go` | Negative: TLS zeroize coverage reviewed. |
| `pkg/grpcapi/zone_flood_counters_hide_test.go` | Negative: zone flood counter coverage reviewed. |
| `pkg/grpcapi/zonepair_summary_3592_test.go` | Negative: zone-pair summary coverage reviewed. |
| `pkg/grpcapi/zones_policies_counter_error_test.go` | Negative: zones/policies counter error coverage reviewed. |

### A9-b1

**Event-options runtime (`engine.go`; `engine_4423_test.go`, `engine_edge_trigger_3756_test.go`, `engine_inclusive_until_3756_test.go`, `engine_integration_test.go`, `engine_stale_revalidate_3750_test.go`, `engine_test.go`, `engine_window_test.go`, `engine_within_failclosed_3751_test.go`).** Correctness/security/fail-open: traced apply-time indexing and regex compilation, semantic revisions, queued-action revalidation, transactional commit, cooldown, edge/inclusive thresholds, malformed temporal gates, and shutdown. Memory/concurrency/integer/resource: windows are pruned and shrink after bursts, the action queue is bounded, retries are cancellable, and lock ordering is exercised. vSRX/performance/modularity/tests: event-index routing avoids scanning unrelated policies and all assigned tests passed, including race execution. No new root cause was promoted: the broad engine lifecycle, matcher, queue, temporal-semantics, and modularity defects in `codex-review-159.md`/`codex-review-173.md` were explicitly suppressed as duplicates.

**Dynamic feeds (`feeds.go`; `feeds_bindings_test.go`, `feeds_sizecap_3934_test.go`, `feeds_test.go`).** Correctness/security/fail-open: checked endpoint resolution, startup match-none behavior, retain-last-good semantics, hold-interval expiry, canonicalization/dedup, binding unions, and update callback ordering. Memory/concurrency/integer/resource: the 32 MiB body cap, 1 MiB line cap, one-million-entry cap, client timeout, deep-copy snapshots, cancellation, and lock coverage were checked. Findings M02 and L02 remain. The existing plaintext-HTTP, SSRF, and tolerant undefined-feed findings were not repeated. Tests pass but do not cover globally colliding feed names or sample byte volume.

**Flow-export grouping, identity, transport, and batching (`exporterid.go`, `manager.go`, `transport.go`; `addr_format_test.go`, `collector_health_test.go`, `collector_stall_4423_test.go`, `exporter_id_3740_test.go`, `exporter_test.go`, `flowbatch_bounded_test.go`, `instance_isolation_test.go`, `per_collector_source_3745_test.go`, `template_group_test.go`, `transport_test.go`, `version_binding_test.go`).** Correctness/security/fail-open: traced version/template binding, instance/family attribution, source-bound collectors, stable exporter identity, health transitions, reconcile-facing stats, and sampling decisions. Safety/performance: collector writes have deadlines/backoff, partial dial construction closes prior sockets, and per-family batches are bounded and counted. Existing `codex-review-158.md` roots (group collisions, reconcile outage, collector stalls, queue bounds, metric identity, and sampling gaps) were suppressed. The remaining fallback-duration overflow is L03.

**NetFlow v9 encoder (`netflow.go`; shared wire tests `cos_fields_test.go`, `dropped_fields_test.go`, `flowdir_test.go`, `flowstart_test.go`, `ingress_interface_test.go`, `postnat_test.go`, `protocol_num_test.go`, `srcmask_dstmask_test.go`).** Correctness/record integrity: independently summed both templates, traced fixed-width field order and packet chunking, and checked post-NAT, masks, interfaces, CoS, direction, timestamps, sequence, and SourceID. The base templates are 61 bytes (v4) and 109 bytes (v6), but the encoder strides records at 64/112 bytes; this is H01. Safety/performance: packets remain under 1,400 bytes and encoding is cold telemetry work, not a forwarding hot path. Tests cover only one-record FlowSets and therefore codify rather than detect the framing error.

**IPFIX encoder (`ipfix.go`; `ipfix_biflow_test.go`, `ipfix_sampler_test.go`, `ipfix_seqnum_test.go`, plus the shared wire tests named above).** Correctness/record integrity: checked template/data length agreement, enterprise reverse IEs, sampler options records, sequence semantics, observation-domain IDs, conditional flowDirection, post-NAT values, and v4/v6 framing. IPFIX records use exact template sums and set-level padding; no sibling of H01 was found. Safety/performance: packet splitting and integer widths are bounded. Existing domain collision, family sequence-space, and sampler-metadata findings were deduplicated.

**Route-mask cache (`routemask.go`; `routemask_vrf_test.go`, `srcmask_dstmask_test.go`).** Correctness/fail-open: checked scoped lookup keys, async miss population, unresolved counters, nil resolver behavior, expiry, and bounded eviction. Safety/performance: session-close callbacks do not synchronously query netlink and cache work is bounded. No new finding; the prior table/source-interface limitations in `codex-review-158.md` were suppressed.

**Event records, aggregation, filtering, and buffering (`aggregator.go`, `event_filter_args.go`, `eventbuf.go`, `goid.go`, `ringbuf.go`; `aggregator_test.go`, `binary_test.go`, `default_policy_sentinel_3057_test.go`, `event_filter_args_test.go`, `event_severity_test.go`, `event_time_test.go`, `eventbuf_close_3384_test.go`, `eventbuf_negative_3342_test.go`, `eventbuf_subscriber_cap_4484_test.go`, `eventbuf_zone0_3338_test.go`, `host_inbound_deny_3610_test.go`, `per_policy_log_test.go`, `protocol_num_builder_3382_test.go`, `protoname_test.go`, `session_close_format_test.go`, `session_create_format_test.go`).** Correctness/security/fail-open: traced both raw decoders, wire offsets, timestamps, policy sentinels, per-policy log gates, callback ordering, event categories/severity, aggregation, filters, circular-buffer subscriptions, and create/close renderers. Concurrency/resource: callback/name maps and fanout snapshots are locked, subscribers are bounded on the untrusted entrypoint, and close/send ordering is tested. Findings M05 and M06 remain. Reverse-volume aggregation and identifier transport-safety issues were suppressed as indexed roots.

**Log destinations (`locallog.go`, `slog_handler.go`, `syslog.go`; `locallog_format_3409_test.go`, `locallog_test.go`, `syslog_lazy_connect_3351_test.go`, `syslog_partial_frame_3874_test.go`, `syslog_reentrancy_test.go`, `syslog_replace_close_3579_test.go`, `syslog_resilience_test.go`, `syslog_test.go`).** Correctness/security/fail-open: checked facility/severity filters, four formats, TLS/source binding, octet-count framing, reconnect/cooldown, partial-frame teardown, writer rotation, replacement, and error observability. Concurrency/resource: write deadlines and reentrancy guards are present, but terminal-close ownership is not; M04 results. The indexed persistent-write-timeout and rotation-failure findings were not repeated. Tests prove old connections are closed, but never send through an old snapshot after closure or update a derived slog handler.

**Trace output (`trace.go`; `trace_filter_3422_test.go`, `trace_size_3424_test.go`, `trace_test.go`).** Correctness/security/fail-open: checked filter parse failures, protocol/prefix conjunction, flag defaults, path traversal, symlink/non-regular rejection, and rotation. Safety/performance: files are mode-hardened, size/file counts are clamped, errors counted, and work is off packet forwarding. No new finding; the prior permanent-loss-on-rotation root was suppressed.

**RPM (`rpm.go`, `icmp.go`, `display.go`; `event_buffer_3755_test.go`, `http_scheme_2495_test.go`, `icmp_ctx_2647_test.go`, `icmp_linklocal_2494_test.go`, `icmp_test.go`, `pin_hold_test.go`, `probe_dialer_2492_test.go`, `scoped_hostname_2493_test.go`, `transition_cycle_test.go`).** Correctness/security/fail-open: checked setup-error hold behavior, pin-install gating, per-cycle transitions, event buffering/replay, URL schemes, scoped DNS, link-local zones, source binds, ICMP matching, and display defaults. Concurrency/resource: apply cancels and waits for probe loops, ICMP/TCP sockets close, and contexts reach DNS/dials. HTTP constructs an unowned keep-alive transport per attempt, yielding M01. Existing boot callback and wrong-RG/default-status findings were deduplicated.

**SNMP agent, MIB/BER, traps, and USM (`agent.go`, `traps.go`, `v3.go`; `agent_clients_4289_test.go`, `agent_secret_log_4302_test.go`, `agent_set_test.go`, `agent_test.go`, `getbulk_size_test.go`, `traps_async_2991_test.go`, `traps_community_2989_test.go`, `traps_test.go`, `traps_version_3948_test.go`, `v3_auth_test.go`, `v3_context_test.go`, `v3_priv_iv_test.go`, `v3_seclevel_test.go`, `v3_set_test.go`, `v3_timeliness_test.go`).** Correctness/security/fail-open: traced v2c source/community gates, read-only SET behavior, MIB walks, response sizing, trap versions/community, v3 discovery/context, HMAC field location, timeliness/boots persistence, privacy IVs, and live config swaps. Memory/concurrency/integer/resource: request serving is serial, interface data is once per PDU, but response construction, trap lifecycle, TimeTicks sign encoding, and EngineID bounds leave H02, H03, M03, M07, and L01. The ignored `crypto/rand.Read` error is the indexed `ps-review-040` root and was suppressed.

## 5. Coverage and verification summary

| Metric | Count |
|---|---:|
| Source files reviewed | 2247 |
| Isolated batches | 23 |
| Raw findings | 150 |
| Final unique findings | 146 |
| Critical | 1 |
| High | 28 |
| Medium | 79 |
| Low | 38 |
| High-confidence | 133 |
| Medium-confidence | 13 |
| Low-confidence | 0 |

All 29 surviving Critical/High findings were independently re-opened and source-traced by the coordinator. Of 31 provisional Critical/High reports, 29 retained top-tier severity, one was downgraded, and one was dropped.

Coordinator dispositions:

| Finding | Raw | Final | Reason |
|---|---|---|---|
| Lease synchronization hardcodes an x86_64 Kea hook path and prevents DHCP startup on shipped arm64 systems. | High | Dropped | Refuted: scripts/dist/install.sh rejects non-x86_64, debian/control declares Architecture amd64, and release documentation ships amd64 only. The claimed shipped-arm64 failure is outside the supported product contract. |
| All AF_XDP reproducers recycle frames without preserving received UMEM addresses | High | Medium | Confirmed root cause; downgraded because impact is confined to lab evidence tooling. |

Coordinator validation commands:

- `go test ./pkg/config ./pkg/appid`
- `go test ./pkg/configstore ./pkg/configstore/journal`
- `go test ./pkg/ipsec ./pkg/daemon`
- Manifest set comparison against `git ls-files` (2,247 exact, no duplicate/missing/extra assignment).
- Direct source re-read for every provisional Critical/High, including called validators, persistence boundaries, wire contracts, and HA state transitions.

Subagent validation summary:

- Focused Go tests passed across config/appid/cmdtree, cluster/VRRP/RA/conntrack, dataplane/userspace, daemon/system, IPsec/networkd/FRR/routing, API/gRPC, CLI, DHCP/DDNS/service packages, upgrade, and observability packages.
- Go vet passed for the A9 observability and A10 service/tooling package sets; focused race runs passed except the full SNMP run, whose surviving worker directly corroborates the reported lifecycle finding.
- A10-b4 ran 388 Python tests and warning-enabled C syntax checks. Two pytest suites were unavailable because `pytest` was not installed.
- A1-b2 and A2-b1 were review-only batches; no full Rust workspace or live AF_XDP/cluster smoke run was performed in this audit.

Focus-line results:

- Zone/global/default/host-inbound policy enforcement was traced in Rust policy/filter/poll modules and Go policy simulator/show surfaces. No new packet-verdict bypass survived; malformed snapshots and undefined zones fail closed. One zone-detail wildcard display/order divergence remains Medium.
- HA/VRRP/cold-boot review found no new VRRP wire-safety root in A5, but kernel promotion, deploy reboot inference, DHCP standby lifetime, and DDNS family ownership produced concrete HA findings.
- Integer-width review found queue-slot aliasing at `queue_id >= 16` and a cross-surface signed-to-uint32 wrap root.
- DDNS review found durable quarantine, dual-family ownership, endpoint transport, pagination, state semantics, and destructive lease-parser issues; these are represented individually below.

## 6. High-confidence findings

### C175-HC-001

Title: Unchecked `fork()` failure turns cleanup into root-wide `SIGKILL`

Severity: Critical

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/libbpf_xsk_test.c:232`
```c
    /* Start background traffic: ping own IP */
    pid_t child = fork();
    if (child == 0) {
        /* Child: send pings to self */
        char ifarg[64];
        snprintf(ifarg, sizeof(ifarg), "-I%s", iface);
        char *ip = "10.0.61.1"; /* adjust if needed */
        execlp("ping", "ping", ifarg, "-i", "0.1", "-c", "50", "-q", ip, NULL);
        _exit(1);
    }
```

The same file later performs unconditional process-group-like cleanup at `test/xsk-repro/libbpf_xsk_test.c:273`:

```c
cleanup:
    kill(child, 9);
    waitpid(child, NULL, 0);
    bpf_xdp_attach(ifindex, -1, 0, NULL);
    printf("  XDP detached\n");

    printf("\n");
    if (rx1 > 0 && rx2 > 0)
```

Trace:

These reproducers require root. On `fork()` failure, POSIX returns `-1`; execution follows the parent path, eventually calls `kill(-1, SIGKILL)`, and asks Linux to signal every process the caller may signal. `libbpf_xsk_shared_test.c:268-284` repeats the same unchecked-fork/unconditional-kill pattern.

Refutation attempt:

A successful child cannot have its PID reused before `waitpid` because it remains a zombie, so ordinary early child exit is not the trigger. The trigger is specifically `fork()` returning `-1`, which is reachable under PID-cgroup exhaustion, `RLIMIT_NPROC`, or memory pressure; neither file tests that return value.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Test-only control flow; no dataplane hot-path cost. Invariant checked: cleanup may signal only a positively identified child created by this process.

Why it matters:

A diagnostic run under resource pressure can terminate the firewall daemon, management services, unrelated test processes, and potentially most of the host instead of reporting that traffic generation could not start.

Fix direction:

Handle `child < 0` immediately and unwind without signaling; guard both `kill` and `waitpid` with `child > 0`; use a scoped child helper that records ownership and tolerates `ESRCH`.

Labels:

security, operational-safety, process-lifecycle, xsk-repro

Dedup note:

No matching `fork`/`kill(-1)` finding appears in `dedup-index.md`.
### A10-b4-02

### C175-HC-002

Title: Address-set bracket-list members after the first are silently dropped.

Severity: High

Confidence: High

Source batch: A3-b3

Evidence:

`pkg/config/schema_security.go:181-185` (contract read)

```go
			"address-book": {desc: "Zone-local address book", children: map[string]*schemaNode{
				"address": {desc: "Named address (name and prefix)", args: 2, multi: true, placeholder: "<address-name>", children: nil},
				"address-set": {desc: "Address set name", args: 1, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: map[string]*schemaNode{
					"address":     {desc: "Address to include in this set", args: 1, multi: true, placeholder: "<address-name>", children: nil},
					"address-set": {desc: "Nested address set to include", args: 1, multi: true, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: nil},
```

Trace:

1. An operator writes a canonical list form such as `set security address-book global address-set blocked address [ a1 a2 ]`, or hierarchical `address [ a1 a2 ];`.
2. The lexer strips `[` and `]`. The schema marks the address-set member leaf `multi:true`, so `SetPath`/hierarchical parsing can represent the list as one leaf with keys like `["address","a1","a2"]`.
3. `parseAddressBookEntries` compiles each member by reading only `member.Keys[1]`.
4. `a2` and every later member in `Keys[2:]` are silently discarded.
5. Strict policy address-set validation walks only the compiled `AddressBook`. It sees the narrowed set containing `a1`, not the dropped `a2`, so there is no error.
6. A deny policy matching `blocked` no longer covers dropped members. If a later rule or default action permits them, traffic from those members bypasses the intended deny.

Refutation attempt:

I searched the assigned tests for `address-set ... address [` and found bracket-list coverage for firewall/policy fields, static next-hop, SNAT, and WireGuard, but not address-set member lists. Existing nested address-set tests use repeated single-member statements, which do compile. I also checked the strict address-set validator; it validates the compiled book and cannot see discarded `Keys[2:]` tokens.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Cold config compiler path only. Fixing the compiler to append all `member.Keys[1:]` for `address`/`address-set` member leaves, or adding an arity/list-aware validator, does not touch packet-path allocation, byte order, or Rust map layout.

Why it matters:

Address sets are commonly used as a policy indirection for deny/permit lists. Silently narrowing a configured set is a direct policy enforcement error and can fail open under a permit fallback.

Fix direction:

Teach `parseAddressBookEntries` to consume all list members for address-set member leaves, preserving repeated-line and hierarchical shapes. Add differential tests for flat-set and hierarchical `address [ a1 a2 ]` and `address-set [ s1 s2 ]` under both global and zone-local books.

Labels:

`config-compiler`, `address-book`, `bracket-list`, `dual-ast`, `fail-open`, `tests`

Dedup note:

Distinct from the prior address-book `address <name> <prefix> <extra>` trailing-token finding and the policy match multi-value fixes. This root cause is address-set membership list compilation, not address prefix parsing or policy match parsing.

### A3-b3-03

### C175-HC-003

Title: Nil user application values panic AppID catalog build and tuple fallback

Severity: High

Confidence: High

Source batch: A3-b1

Evidence:

`pkg/appid/catalog.go:88` dereferences the application returned by `ResolveApplication` without checking for nil:

```go
for _, name := range names {
	if nextID > maxCatalogAppID {
		return cat, fmt.Errorf("application catalog exceeds %d entries: assigning app_id to %q would overflow the uint16 app_id space (0 is the reserved unknown sentinel); reduce the number of referenced applications", maxCatalogAppID, name)
	}
	appID := uint16(nextID)
	app, found := config.ResolveApplication(name, userApps)
	if !found {
		continue
	}

	proto := catalogProtocolNumber(app.Protocol)
```

`pkg/appid/runtime.go:210` has the same nil dereference in the AppID-disabled tuple fallback:

```go
for name, app := range cfg.Applications.Applications {
	if icmpTypeConstrained(app) {
		continue
	}
	if !matchTuple(proto, srcPort, dstPort, app.Protocol, app.SourcePort, app.DestinationPort) {
		continue
	}
	portBased := app.DestinationPort != "" || app.SourcePort != ""
```

`pkg/config/compiler_validate_warn_nil_3494_test.go:70` documents that the tolerant/HA-sync shape can contain a nil application value:

```go
cfg.Applications.Applications = map[string]*Application{
	"app1":       {Name: "app1", Protocol: "not-a-proto"}, // invalid proto -> warning
	"zz-nil-app": nil,                                     // #3494: nil application value
}
cfg.Security.AddressBook = &AddressBook{
	Addresses: map[string]*Address{
```

Trace:

1. A tolerant load or HA-sync decoded config carries `cfg.Applications.Applications["zz-nil-app"] = nil`; this shape is explicitly covered by the warning-path nil test.
2. If `services application-identification` is enabled, `CatalogNames(cfg, true)` adds every user application map key to the catalog candidate set. If disabled, a policy/NAT reference to the nil-valued name also adds it.
3. `BuildCatalog` calls `config.ResolveApplication(name, userApps)`. `ResolveApplication` returns `(nil, true)` for a present user map key whose value is nil, so `found` does not protect the dereference.
4. `BuildCatalog` immediately evaluates `app.Protocol` and panics instead of returning an error to the snapshot/apply path.
5. Independently, with AppID disabled, `ResolveSessionName` falls into `resolveTupleFallback`, ranges the same application map, `icmpTypeConstrained(nil)` returns false, and the subsequent `app.Protocol` dereference panics during session-name rendering.

Refutation attempt:

I checked the candidate guards rather than assuming the map cannot contain nil. `ValidateConfig`/warning coverage explicitly includes a nil application value. `validateApplicationSpecsStrict` skips nil application pointers instead of rejecting them, so it is not a hard barrier. `CatalogNames` has nil guards for zone-pair and policy entries but include-all mode adds application names from the map without validating values. `config.ResolveApplication` treats a present nil user value as found and returns nil. Existing appid tests cover nil zone-policy/policy entries, malformed ports, and overflow, but not nil application values. The finding survived.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Not a packet hot path. The relevant invariant is malformed-config fail-closed behavior: tolerated nil config slots must be skipped, warned, or rejected as data, not converted to process panics.

Why it matters:

A single malformed persisted or HA-synced nil application can turn AppID catalog construction or show/session rendering into a panic. That is fail-open/fail-stop behavior at the control-plane boundary rather than the intended "warn/skip and keep running" tolerant-load posture.

Fix direction:

Add nil checks at AppID ingestion boundaries: `BuildCatalog` should treat `(nil, true)` from `ResolveApplication` as unemittable and skip it without consuming an id, or return a structured catalog error if referenced. `resolveTupleFallback` should skip nil map values before ICMP/type and matchTuple processing. Add tests for `BuildCatalog` with AppID enabled plus nil app, referenced nil app, and `ResolveSessionName` with AppID disabled plus nil app.

Labels:

appid, malformed-config, fail-closed, panic, tolerant-load

Dedup note:

Prior dedup has AppID catalog panics for nil zone-policy and nil policy entries, but this is a different root cause: nil values inside `cfg.Applications.Applications`, plus the disabled tuple fallback. It is not a restatement of H05/H06 in the dedup index.

### F2

### C175-HC-004

Title: Top-level unmatched `}` stops parsing with zero errors and drops all trailing config.

Severity: High

Confidence: High

Source batch: A3-b3

Evidence:

`pkg/config/parser.go:39-44`

```go
// Parse parses the input and returns the configuration tree.
func (p *Parser) Parse() (*ConfigTree, []ParseError) {
	children := p.parseStatements()
	tree := &ConfigTree{Children: children}
	return tree, p.errors
}
```

Trace:

1. A hierarchical `load override` or commit-check input contains an extra unmatched `}` at top level before a later security stanza, for example before a default-policy or deny policy.
2. `Parse()` calls `parseStatements()` once for the top level.
3. `parseStatements()` treats `TokenRBrace` exactly like EOF and breaks out, even though there is no enclosing block at depth 1.
4. `Parse()` returns the nodes accumulated before the extra brace and returns no `ParseError`; it does not check that the lexer is at EOF.
5. `LoadOverride`/`CheckText` only checks `len(errs)` and then compiles/applies the returned tree.
6. Everything after the unmatched `}` is ignored. If the skipped tail contained deny/default-policy/address objects, the committed config is silently weaker than the authored file.

Refutation attempt:

I checked the parser tests and found coverage for unterminated block comments and recursion depth, but not for a top-level unmatched `}` followed by valid trailing statements. I also checked hierarchical callers in `configstore`; they rely only on `len(errs)` and do not perform a post-parse EOF/trailing-token check. Later validators cannot catch this because the skipped tail never enters the `ConfigTree`.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Parser/load path only. A fix can be a top-level EOF assertion after `parseStatements()` or a depth-aware `TokenRBrace` error, with no packet-path impact, no per-packet allocation, and no change to Rust dataplane layout.

Why it matters:

This is a fail-open config acceptance path. A single stray brace in an imported Junos config can make the commit/load path accept a prefix of the file while silently dropping the security policy tail.

Fix direction:

Make top-level `TokenRBrace` a parse error, or have `Parse()` consume/check the next token after `parseStatements()` and reject anything other than EOF. Add tests for `system { ... } } security { ... }` proving parse failure and no tail drop.

Labels:

`parser`, `config-load`, `fail-open`, `silent-drop`, `tests`

Dedup note:

Not a duplicate of the deduped unterminated `/* */` truncation finding. That root cause is lexer comment handling; this one is unmatched top-level right-brace handling after successful lexing.

### A3-b3-02

### C175-HC-005

Title: `CommitConfirmed` returns success even when the durable crash-recovery record fails to persist

Severity: High

Confidence: High

Source batch: A4-b1

Evidence:

`pkg/configstore/store_commit.go:274-285` writes `confirm.json` only after active promotion and explicitly notes a residual crash window:

```go
// #4577: persist the pending-confirm state so the auto-rollback deadline
// survives a daemon crash/reboot inside the window. The in-memory timer
// above is lost on restart; without confirm.json the just-promoted (and
// still UNCONFIRMED) config would become permanent. Written AFTER the
// successful writeActive+promote so a FAILED commit-confirmed never leaves
// a confirm.json (persist-before-promote already returned above on
// failure). PrevTree is confirmPrevTree — the ORIGINAL last-confirmed tree
// for a nested re-arm; firstCommit mirrors the confirmPrevCfg==nil #1922
// Item 1b path. A residual crash window remains between the writeActive
// syscall and this write (microseconds vs. the whole multi-minute window
```

`pkg/configstore/store_commit.go:291-304` then logs any `WriteConfirm` failure and still lets `CommitConfirmed` return success:

```go
// writeConfirmState persists the pending commit-confirmed state (#4577) so the
// auto-rollback deadline + rollback target survive a daemon crash/reboot.
// Best-effort: a failure is logged, not fatal — the in-memory timer still
// covers the no-crash case (the #1799 degrade-not-fail doctrine). Caller holds
// s.mu.
func (s *Store) writeConfirmState(prevTree *config.ConfigTree, deadline time.Time, firstCommit bool) {
	if s.db == nil {
		return
```

Trace:

1. Operator commits a potentially management-stranding candidate with `CommitConfirmed`.
2. `CommitConfirmed` durably writes the candidate to `active.json`, promotes it in memory, writes journal/rollback history, arms the in-memory timer, and then calls `writeConfirmState`.
3. If `db.WriteConfirm` fails because `.configdb` is full, permission-broken, or otherwise unavailable, `writeConfirmState` only logs a warning.
4. `CommitConfirmed` returns the compiled config as success, so the caller and operator believe the commit-confirmed safety hatch is armed.
5. If the daemon crashes before the in-memory timer fires, there is no durable `confirm.json` for `Store.Load` to recover.
6. The unconfirmed config becomes permanent after restart, which is exactly the management-stranding scenario commit-confirmed is meant to avoid.

Refutation attempt:

I checked `persist_failure_test.go`: it verifies active-config write failures prevent arming a confirmed commit, but the only injected failure seam is `SetWriteActiveForTesting`; there is no confirm-state write seam. I checked `db.WriteConfirm`, and it does use `fsatomic.WriteFileDurable`, so the write itself is strong when it succeeds. The unsafe part is that failure is swallowed after the operator-visible commit-confirmed success path. The finding survives.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Storage transaction invariant: the active config and its rollback deadline are promoted as separate durable objects without an all-or-visible-failure rule. No per-packet/HPC concern.

Why it matters:

A successful `commit confirmed` must mean "this will roll back even if the daemon restarts inside the window." Here it can mean only "the current process has a timer," which is weaker than the operator contract and unsafe during crashes, watchdog restarts, and power loss.

Fix direction:

(concrete - the report is a remediation work-list)
Treat `confirm.json` persistence as part of the commit-confirmed transaction. Add a confirm-state write failure seam and tests. On `WriteConfirm` failure, either durably revert `active.json` to the previous tree and return an error, or surface a hard degraded state that makes health/CLI show the commit-confirmed window is not crash-safe. Do not report normal success while the durable rollback record is absent.

Labels:

(include vsrx-parity for parity issues)
storage-durability, commit-confirmed, rollback, crash-recovery

Dedup note:

(why this is not a restatement of any entry in the dedup index)
Prior entries cover active-config persist-before-promote, nested rollback target preservation, and persisted confirm recovery. This finding is specifically about post-promotion `confirm.json` write failure being warning-only.

### F3

### C175-HC-006

Title: Confirmed `commit confirmed` windows can be resurrected because `confirm.json` deletion is warning-only and not directory-fsynced

Severity: High

Confidence: High

Source batch: A4-b1

Evidence:

`pkg/configstore/db.go:232-238` deletes the recovery record with a plain unlink and no `fsatomic.SyncDir`:

```go
// DeleteConfirm removes the pending commit-confirmed state file (#4577).
// Absent is not an error.
func (db *DB) DeleteConfirm() error {
	if err := os.Remove(db.confirmPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete confirm state: %w", err)
	}
	return nil
}
```

`pkg/configstore/store_commit.go:348-355` treats that removal as best-effort after the in-memory timer has already been cleared:

```go
// #4577: the pending confirm is now confirmed (plain commit / HA sync /
// explicit confirm / demotion) — drop the persisted crash-recovery state
// so a later restart does not resurrect a stale rollback window. A nested
// confirmed re-arm does NOT pass through here (it re-writes confirm.json
// with the extended deadline in CommitConfirmed), so this only fires on a
// genuine confirmation.
s.removeConfirmState()
return true
```

`pkg/configstore/store_persist.go:151-158` will honor any stale record found after restart and roll back if the deadline is expired:

```go
if time.Now().After(rec.Deadline) {
	// Expired during downtime: the operator never confirmed, so the
	// unconfirmed config on disk must NOT stand. Revert to the prev tree
	// with the same persistence semantics as PromoteRollback.
	s.active = prevTree
	var perr error
	if rec.FirstCommit {
		// #1922 Item 1b: the rollback target is the empty bootstrap tree;
```

Trace:

1. Operator runs `commit confirmed`, which durably writes `confirm.json` with the previous tree and a deadline.
2. Operator later confirms the window via `ConfirmCommit`, a plain `Commit`, HA `SyncApply`, or demotion. All routes call `clearPendingConfirmLocked`.
3. `clearPendingConfirmLocked` stops the timer, bumps `confirmGen`, drops in-memory rollback state, and calls `removeConfirmState`.
4. `removeConfirmState` calls `DB.DeleteConfirm`; `DeleteConfirm` only calls `os.Remove`.
5. If `os.Remove` fails, the caller only logs. If `os.Remove` succeeds but the directory is not fsynced, a crash/power loss can replay the old directory entry.
6. On restart, `Store.Load` calls `recoverPendingConfirmLocked`, reads the stale `confirm.json`, and either re-arms a rollback timer or rolls back immediately if the deadline passed.
7. The config the operator already confirmed can therefore be reverted after reboot. On HA demotion this can re-diverge a standby that was explicitly confirmed to match the new primary.

Refutation attempt:

I checked `commit_confirmed_persist_4577_test.go`: it asserts `ReadConfirm()` returns nil after explicit confirm, bare commit, and recovered rollback, but it does not inject `DeleteConfirm` failure and does not assert a directory fsync. I also checked the `fsatomic.SyncDir` contract: it explicitly makes previously completed unlinks durable. No caller adds that sync after `DeleteConfirm`, and `removeConfirmState` logs instead of returning the failure. The finding survives.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Storage invariant violation, not a hot-path/HPC issue: a state transition from "pending confirm" to "confirmed/resolved" depends on a namespace unlink that is neither made durable nor surfaced to callers.

Why it matters:

`commit confirmed` is a management safety hatch. A stale `confirm.json` can undo a config after it has been explicitly confirmed, including after RG0 demotion where rollback causes cluster divergence.

Fix direction:

(concrete - the report is a remediation work-list)
Make confirm-state removal a durable state transition: unlink plus `fsatomic.SyncDir(filepath.Dir(confirmPath))`, with tests using a seam that proves the sync route. Consider changing `ConfirmCommit` to return an error if the persisted state cannot be cleared, and add a record guard such as the unconfirmed active config hash/generation so restart recovery can ignore stale confirm records that no longer match the current active config.

Labels:

(include vsrx-parity for parity issues)
storage-durability, commit-confirmed, rollback, fsync

Dedup note:

(why this is not a restatement of any entry in the dedup index)
The dedup index mentions prior commit-confirmed timer fixes, stale callback generation, demotion confirmation, and persisted confirm recovery, but not the root cause here: unresolved or crash-undurable deletion of `confirm.json` after confirmation.

### F2

### C175-HC-007

Title: Binding queue IDs >= 16 alias adjacent userspace_bindings slots

Severity: High

Confidence: High

Source batch: A6-b2

Evidence:

The Go-side stride is fixed at 16, but the control-plane applies helper queue IDs directly:

```
pkg/dataplane/userspace/maps_sync.go:48-51
    48 // tunnel is configured. The shim gates its per-packet WG steering branch
    49 // on this single bit so non-WG traffic never even loads wg_listen_port.
    50 const userspaceCtrlFlagWgRx = 16
    51 const bindingQueuesPerIface = 16 // must match BINDING_QUEUES_PER_IFACE in BPF
```

```
pkg/dataplane/userspace/maps_sync.go:369-375
   369 zero := uint32(0)
   370 ctrl := userspaceCtrlValue{
   371     Enabled:            0,
   372     MetadataVersion:    userspaceMetadataVersion,
   373     Workers:            uint32(maxInt(status.Workers, 1)),
   374     QueueCount:         uint32(queueCountFromBindings(status.Bindings)),
   375     Flags:              ctrlFlags,
```

```
pkg/dataplane/userspace/maps_sync.go:696-707
   696 idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
   697 // Call-site cap guard (#814): the aya Array is sized to
   698 // dataplane.BindingArrayMaxEntries = MaxInterfaces *
   699 // BindingQueuesPerIface. An ifindex above MaxInterfaces would
   700 // overflow the flat index; fail with a legible error instead
   701 // of relying on the kernel's "argument list too long" E2BIG.
   702 if idx >= dataplane.BindingArrayMaxEntries {
   703     return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
   704         "update userspace_bindings: idx=%d exceeds cap=%d (ifindex=%d queue=%d; raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
   705         idx, dataplane.BindingArrayMaxEntries, binding.Ifindex, binding.QueueID,
   706     ))
   707 }
```

The VLAN-alias and watchdog paths repeat the same formula without bounding the queue dimension:

```
pkg/dataplane/userspace/maps_sync.go:720-734
   720 for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
   721     for _, binding := range status.Bindings {
   722         if binding.Ifindex != int(parentIfindex) {
   723             continue
   724         }
   725         flags := uint32(0)
   726         if bindingForwardingLive(binding, deadWorkers) {
   727             // #1666: unify the VLAN-alias child with the primary gate.
   728             flags = userspaceBindingReady
   729         }
   730         idx := childIfindex*bindingQueuesPerIface + binding.QueueID
   731         // Call-site cap guard (#814): see primary apply above.
   732         // VLAN-alias children use their own ifindex here, so the
   733         // child (not the parent) is the overflow risk.
   734         if idx >= dataplane.BindingArrayMaxEntries {
```

```
pkg/dataplane/userspace/maps_sync.go:1749-1763
  1749 func queueCountFromBindings(bindings []BindingStatus) int {
  1750     maxQueueID := -1
  1751     for _, binding := range bindings {
  1752         if !binding.Registered || binding.Ifindex <= 0 {
  1753             continue
  1754         }
  1755         if int(binding.QueueID) > maxQueueID {
  1756             maxQueueID = int(binding.QueueID)
  1757         }
  1758     }
  1759     if maxQueueID < 0 {
  1760         return 1
  1761     }
  1762     return maxQueueID + 1
  1763 }
```

The batch tests cover ifindex/cap overflow, but only queue IDs 0/1 and constant equality:

```
pkg/dataplane/userspace/maps_sync_cap_test.go:657-683
   657 overCapIfindex := int(dataplane.MaxInterfaces) + 42
   658 m.lastStatus.Bindings = []BindingStatus{
   659     {Slot: 1, QueueID: 0, Ifindex: overCapIfindex, Registered: true, Armed: true, Bound: true},
   660     {Slot: 2, QueueID: 1, Ifindex: 7, Registered: true, Armed: true, Bound: true},
   661 }
   ...
   675 func TestBindingArrayMaxEntriesMirrorsRustSide(t *testing.T) {
   676     if dataplane.BindingQueuesPerIface != bindingQueuesPerIface {
   677         t.Fatalf("bindingQueuesPerIface in maps_sync.go (%d) differs from dataplane.BindingQueuesPerIface (%d); one side of the mirror drifted",
   678             bindingQueuesPerIface, dataplane.BindingQueuesPerIface)
   679     }
   680     if dataplane.BindingArrayMaxEntries != dataplane.MaxInterfaces*dataplane.BindingQueuesPerIface {
   681         t.Fatalf("BindingArrayMaxEntries (%d) != MaxInterfaces * BindingQueuesPerIface (%d * %d)",
   682             dataplane.BindingArrayMaxEntries, dataplane.MaxInterfaces, dataplane.BindingQueuesPerIface)
   683     }
```

The Rust helper emits one binding per hardware RX queue without a 16-queue cap:

```
userspace-dp/src/server/helpers.rs:1154-1172
  1154 let queue_count = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
  1155 let interfaces = candidates
  1156     .iter()
  1157     .map(|(name, _)| name.clone())
  1158     .collect::<Vec<_>>();
  1159 let mut out = Vec::with_capacity(queue_count * interfaces.len());
  1160 let mut slot = 0u32;
  1161 for queue_id in 0..queue_count {
  1162     for iface in &interfaces {
  1163         let mut binding = existing_by_slot.remove(&slot).unwrap_or_default();
  ...
  1170         binding.slot = slot;
  1171         binding.queue_id = queue_id as u32;
  1172         binding.worker_id = (queue_id % workers.max(1)) as u32;
```

The XDP shim uses the same fixed 16 stride and selects queues from `ctrl.queue_count`, which Go derives from max reported queue id:

```
userspace-xdp/src/lib.rs:74-85
    74 const USERSPACE_CTRL_FLAG_WG_RX: u32 = 16;
    75 const BINDING_QUEUES_PER_IFACE: u32 = 16;
    ...
    85 const BINDING_ARRAY_MAX_ENTRIES: u32 = MAX_INTERFACES * BINDING_QUEUES_PER_IFACE;
```

```
userspace-xdp/src/lib.rs:443-450
   443     &parsed,
   444 );
   445 let binding_idx = ingress_ifindex * BINDING_QUEUES_PER_IFACE + selected_queue;
   446 let mut binding = USERSPACE_BINDINGS.get(binding_idx);
   447 // Treat zero-flags (unpopulated Array entry) as missing.
   448 if binding.map_or(true, |b| b.flags == 0) && selected_queue != rx_queue_index {
   449     let fallback_idx = ingress_ifindex * BINDING_QUEUES_PER_IFACE + rx_queue_index;
   450     binding = USERSPACE_BINDINGS.get(fallback_idx);
```

```
userspace-xdp/src/lib.rs:1465-1481
  1465 let queue_count = if ctrl.queue_count == 0 {
  1466     ctrl.workers
  1467 } else {
  1468     ctrl.queue_count
  1469 };
  ...
  1481 rx_queue_index % queue_count
```

Trace:

1. A physical or fabric parent has 32 RX queues, so the helper's candidate `rx_queues` minimum is 32.
2. `replan_bindings_from_candidates` emits queue IDs 0..31 for each interface.
3. Go computes `idx = ifindex*16 + queue_id` and only checks the total `idx < BindingArrayMaxEntries`, not `queue_id < 16`.
4. For ifindex N, queue 16 writes index `N*16+16`, which is exactly `(N+1)*16+0`.
5. The same alias occurs for VLAN alias writes and watchdog repairs.
6. Go also publishes `ctrl.QueueCount = maxQueueID+1`, so the XDP selector can use queue IDs above 15.
7. XDP then reads `ingress_ifindex*16 + selected_queue` or fallback `ingress_ifindex*16 + rx_queue_index`, so packets for one interface/queue can read a slot overwritten by another interface/queue binding.

Refutation attempt:

- Checked the batch cap tests. They reject over-cap ifindex and pin constant equality, but no test uses `QueueID >= bindingQueuesPerIface`.
- Checked Rust helper planning; it uses effective RX queues from snapshot/sysfs/fabric parent and does not cap at 16.
- Checked XDP selector; it uses `ctrl.queue_count` and the same 16-slot stride.
- Checked dedup index for binding/queue/BINDING_QUEUES_PER_IFACE/rx queue aliases. No matching root-cause finding found.
- Considered whether map max entries catches this. It does not; queue 16 on ifindex N is a valid in-range slot for adjacent ifindex N+1.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

The hot-path invariant is a fixed dense array indexed as `(ifindex, queue) -> ifindex*16+queue`. The control-plane producer must ensure `queue < 16`, or the mapping is not injective. Per-entry map writes are atomic, but atomicity cannot preserve correctness when two logical bindings share one physical array slot.

Why it matters:

NICs with more than 16 RX queues are common on throughput boxes. On those hosts, enabling userspace forwarding can alias binding slots across adjacent ifindexes or VLAN child aliases. The result is wrong XSK slot selection, binding-missing/binding-not-ready drops, or redirecting traffic for one ingress interface to another interface's socket. This is a dataplane availability and isolation boundary failure, and it can also mask HA readiness because helper status says the bindings are ready while the BPF map cannot represent them uniquely.

Fix direction:

- Enforce `QueueID < dataplane.BindingQueuesPerIface` in `applyHelperStatusLocked` before primary and alias writes. Treat violation as fail-closed with a clear error and ctrl disabled.
- Apply the same queue bound in `verifyBindingsMapLocked` and alias repair, logging/skipping rather than repairing an aliased slot.
- Either cap/reject helper planner queue counts above `BINDING_QUEUES_PER_IFACE` or raise the BPF/Go/Rust stride consistently. If raising the stride, update map capacity validation and XDP constants together.
- Add Go tests for `QueueID == bindingQueuesPerIface` on primary apply and alias/watchdog repair, proving it cannot overwrite adjacent ifindex queue 0.
- Add Rust planner/contract tests for a 32-queue candidate so the chosen behavior is explicit.

Labels:

- a6-b2
- dataplane-boundary
- map-write-atomicity
- binding-index-math
- capacity-limit
- ha-readiness
- test-gap

Dedup note:

Not a duplicate of the existing ifindex/max-entry guard (#814 style) because the failing dimension is queue ID within an otherwise in-range flat index. No matching queue-stride alias entry was found in the dedup index.

### Finding 2

### C175-HC-008

Title: `system login user <name>` can inject arbitrary sudoers directives through the generated `/etc/sudoers.d/xpf-*` drop-in

Severity: High

Confidence: High

Source batch: A7-b1

Evidence:

`system login user` is an untyped keyed instance, so quoted strings are accepted as the username; the compiler preserves the key as `LoginUser.Name`; the apply tail calls `reconcileSudoers` unconditionally after `applySystemLogin`; and `writeSudoersGrant` formats the username directly into sudoers syntax before validating the whole file with `visudo`.
`pkg/config/lexer.go:243-266` decodes `\n` inside a quoted string into a literal newline and returns `TokenString`; `pkg/config/parser.go:99-105` appends string tokens to the path; `pkg/config/schema_system.go:218-229` has `"user": {args: 1}` with no username validator; `pkg/config/compiler_system.go:117-142` copies `userInst.name` into `LoginUser.Name`.

Snippet read from `pkg/daemon/daemon_apply.go:1515-1523`:

```go
	// 11. Apply system login users (create OS accounts, SSH keys)
	d.applySystemLogin(cfg)

	// 11b. Reconcile super-user sudo grants against the CURRENT config so a
	// class downgrade or user removal REVOKES the stale NOPASSWD grant
	// (#3889). Runs unconditionally — applySystemLogin returns early when
	// there are no users, which is exactly the "all users removed" case
	// that must still sweep stale grants.
	d.reconcileSudoers(cfg)
```

Snippet read from `pkg/daemon/daemon_system.go:943-955`:

```go
func writeSudoersGrant(user string) error {
	path := filepath.Join(sudoersDir, sudoersPrefix+user)
	line := fmt.Sprintf("%s ALL=(ALL) NOPASSWD: ALL\n", user)
	if current, _ := os.ReadFile(path); string(current) == line {
		return nil // idempotent: already correct
	}
	// DurableState: a torn or lost sudoers file is a management-access
	// (sudo) hazard, so it must survive a power cut.
	if err := fsatomic.WriteFileDurable(path, []byte(line), 0440); err != nil {
```

Trace:

1. A flat-set/load/HA-sync config can supply a quoted username carrying spaces and a newline, for example a single `system login user` key whose decoded value begins with a syntactically valid sudoers grant, then `\nALL ALL=(ALL) NOPASSWD: ALL\n#`.
2. The lexer materializes `\n` as a newline and `ParseSetVerb` accepts `TokenString` path components; the schema validates the class leaf but does not validate the keyed username.
3. `compileSystem` stores the raw key in `LoginUser.Name`.
4. Even if `useradd` rejects the impossible OS username, `applyTailReconciles` still calls `reconcileSudoers` for the current config.
5. `writeSudoersGrant` formats `user` directly into `%s ALL=(ALL) NOPASSWD: ALL\n`. The injected newline creates an additional sudoers directive, and a trailing `#` can comment out the renderer's appended suffix.
6. `validateSudoersFile` runs `visudo -cf` on the generated drop-in; a syntactically valid injected directive passes validation and is durably installed under `/etc/sudoers.d`.

Refutation attempt:

I checked the password path because it uses `chpasswd` stdin, but `ValidateCryptHash` protects only the password hash value, not `user.Name`. I also checked whether OS account creation would gate the sudoers write; it does not, because `reconcileSudoers` runs independently after `applySystemLogin`. `visudo` is a syntax validator, not a containment validator, so it accepts the injected directive if the final file is valid sudoers syntax. Existing sudoers tests cover revocation of stale grants, not control characters or whitespace in usernames.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

A structured `system login user <name> class super-user` stanza must produce exactly one sudoers grant for one valid OS account name. Generated root-owned host config files must not allow AST key bytes to create additional lines/directives. The current renderer violates that by treating a raw config key as sudoers source code.

Why it matters:

A malformed or synced config can escape the modeled login-user privilege boundary and install arbitrary sudoers grants, including broad `ALL` grants, while passing the existing validation gate. That is a root host-integration privilege boundary, not just a cosmetic parse issue.

Fix direction:

Add a schema and apply-boundary `ValidateLoginUsername` for `system login user` keys, using a strict POSIX/Linux account-name regex and rejecting whitespace, control characters, `/`, `:`, leading `-`, and empty names. Make `reconcileSudoers` refuse unsafe names defensively before writing. Add regression tests that quoted usernames containing `\n`, spaces, `/`, and leading `-` are rejected and never passed to `writeSudoersGrant`.

Labels:

`area:A7-b1`, `daemon`, `host-integration`, `sudoers`, `config-injection`, `privilege-boundary`, `CWE-74`

Dedup note:

Distinct from dedup F-055, which was stale sudoers revocation on class downgrade/removal. This finding is directive injection into the generated sudoers file through the username key.
### F2

### C175-HC-009

Title: IPsec empty clear suppresses `swanctl --load-all` failures and can report stale tunnels removed

Severity: High

Confidence: High

Source batch: A7-b3

Evidence:

`pkg/ipsec/manager.go:162`

```go
   162	// clearConfig removes the xpf snippet and reloads strongSwan.
   163	func (m *Manager) clearConfig() error {
   164		if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
   165			return fmt.Errorf("remove config: %w", err)
   166		}
   167		_ = m.reload()
   168		return nil
```

`pkg/ipsec/reload_error_4433_test.go:9`

```go
     9	// TestApplyReloadErrorPropagates documents the Manager-side half of the #4433
    10	// contract: when `swanctl --load-all` fails, strongSwan leaves the previously
    11	// loaded config in place (the OLD tunnels stay active), so Manager.Apply MUST
    12	// return that reload error to its caller. The daemon then joins it into the
    13	// commit result (see pkg/daemon TestApplyConfigLocked_IPsecApplyErrorFailsCommit)
    14	// so the operator is not told the new IPsec policy is enforced when it is not.
```

Trace:

1. Device has one active IPsec VPN and `m.prevConnNames` records its swanctl connection name.
2. Operator deletes the last VPN, so `Apply(nil)` takes `clearConfig()`.
3. `clearConfig()` removes `xpf.conf` and calls `m.reload()`, but discards any `swanctl --load-all` error.
4. The comment in the reload-error test states the operational contract: when load-all fails, strongSwan leaves the previously loaded config in place.
5. `Apply(nil)` returns nil after best-effort SA termination, so the commit path can tell the operator the empty IPsec config is enforced even though charon may still carry the old loaded connection and can re-initiate it.

Refutation attempt:

I checked whether `Clear()` or `Apply(nil)` had another reload-error path; both call the same `clearConfig()` branch. I also checked whether SA termination makes this harmless. It only targets currently listed SAs and is explicitly separate from unloading the connection config; if load-all failed, the old connection definition remains in strongSwan and can re-establish after termination or keep trap/start behavior. The existing #4433 test proves the non-empty path must propagate load-all failure but does not cover the empty-clear branch.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Fail-closed lifecycle invariant violated: a config commit that removes IPsec policy must not report success until the host daemon accepted the removal. The clear branch breaks commit-after-success by converting reload failure to nil.

Why it matters:

Deleting the last VPN is a security-sensitive operation. A compromised/decommissioned peer can remain authorized in strongSwan while the daemon reports the tunnel removed.

Fix direction:

Make `clearConfig()` return `m.reload()` errors just like `applyConfig()` does. Keep the best-effort terminate call, but do not let it mask unload failure. Add a regression test for `Apply(nil)`/`Clear()` where `--load-all` fails.

Labels:

`A7-b3`, `ipsec`, `lifecycle`, `strongSwan`, `fail-closed`, `reload-error`

Dedup note:

Related consequence to dedup `C172-H01`, but not the same root: that item covers daemon-level apply failure handling for IPsec apply errors; this is the manager's empty-clear branch swallowing the reload error before any caller can fail the commit.

### C175-HC-010

Title: NetFlow v9 inserts padding between records, corrupting every multi-record FlowSet after the first record

Severity: High

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/flowexport/netflow.go:229`
```go
229	// recordSize computes the data record size from template fields, padded to 4 bytes.
230	func recordSize(fields []templateField) int {
231		size := 0
232		for _, f := range fields {
233			size += int(f.fieldLen)
234		}
235		// Pad to 4-byte boundary
236		pad := (4 - size%4) % 4
237		return size + pad
238	}
```

Trace:

`Exporter.ExportSessionClose` appends fixed-family records to `flowBatch`; the 100 ms flush calls `sendRecords`, which commonly chunks multiple records into one packet. The templates advertise sums of 61/109 bytes without flowDirection (62/110 with it), while `recordSize` returns 64/112 and each `encodeRecordV4/V6` returns `startOff + recSize`. A collector advances by the template's fixed record width, so record two begins two or three bytes before the encoder placed it; all subsequent tuple, counter, and timestamp fields are shifted. FlowSet padding is permitted only once at the end of the set.

Refutation attempt:

Independently summed every template field and compared the IPFIX sibling, which correctly uses exact template lengths. `TestV9DataRecordSizeConsistency` encodes exactly one record and explicitly expects a padded per-record size, so it cannot distinguish valid trailing FlowSet padding from invalid inter-record padding. No assigned test decodes two v9 records using the advertised template.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

This is a cold export-goroutine path, not the packet forwarding path. The violated invariant is wire layout: records must be contiguous at the template-advertised width and only the enclosing FlowSet may receive up to three terminal padding octets. The fix adds no per-packet allocation.

Why it matters:

Normal close bursts produce multi-record packets. Collectors retain the first record but misdecode or discard every later record, corrupting addresses, ports, policy analytics, counters, and timestamps precisely when flow telemetry volume is highest.

Fix direction:

Split `recordLen` (sum of template fields) from `flowSetLen` (header plus contiguous records, rounded once). Make record encoders return the actual field end, append records at that offset, and clear only terminal set padding. Add two- and maximum-record v4/v6 golden decoders for both flowDirection modes and assert every boundary against the template sum.

Labels:

`telemetry`, `netflow-v9`, `wire-format`, `record-correctness`, `vsrx-parity`

Dedup note:

No per-record padding or multi-record NetFlow framing root appears in the supplied dedup index. The indexed NetFlow findings concern exporter identity, sequence domains, masks, lifecycle, and missing fields.
### A9-b1-H02

### C175-HC-011

Title: SNMP response sizing permits quadratic GETBULK work and oversized GET/GETNEXT amplification

Severity: High

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/snmp/agent.go:782`
```go
782		// Process repeaters.
783		for i := nonRepeaters; i < len(oids); i++ {
784			currentOID := oids[i]
785			for j := 0; j < maxRepetitions; j++ {
786				nextOID := a.findNextOIDSnap(currentOID, snap)
787				if nextOID == nil {
788					varbinds = append(varbinds, varbind{oid: currentOID, tag: tagEndOfMibView, value: nil})
789					break
790				}
```

Trace:

A 4,096-byte request can carry hundreds of short varbinds. GETBULK multiplies each repeater by the cap of 100 and materializes the entire result before sizing. `trimToFit` then rebuilds complete prefixes one varbind at a time until only roughly one datagram remains, yielding quadratic encoding/allocation; v3 repeats USM framing, HMAC, and optional encryption on each rebuild. `Start` handles requests serially, so one request blocks every poll. Plain GET/GETNEXT bypass `trimToFit` entirely and can emit responses larger than `maxPacketSize`, especially when a repeated OID has a long configured string value.

Refutation attempt:

Checked the 100-repetition cap, 4,096-byte receive buffer, one-netlink-snapshot optimization, and output tests. Those bounds limit input and netlink calls but not `len(oids)*100` intermediate records or the number/size of rebuilds. Existing size tests use one repeater OID and assert only final datagram size; they do not bound allocations/build calls or exercise large GET/GETNEXT lists.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Management-plane, but it monopolizes the single SNMP serving goroutine and drives heap/GC work. The invariant is budget-before-work: response byte/varbind limits must constrain generation and encoding before attacker-controlled multiplicative loops execute.

Why it matters:

A party with a v2c community, or only a username via H02, can consume substantial CPU and memory with one datagram, starve legitimate monitoring, and use oversized replies for reflection/amplification.

Fix direction:

Apply one shared response budget to GET, GETNEXT, and GETBULK. Generate varbinds incrementally while tracking encoded size and stop near the effective maximum; cap total generated varbinds independently of repetition count. If a final fit pass remains, use exact length accounting or binary search rather than decrement-and-rebuild. Add adversarial many-OID tests that assert build count, allocation/work bounds, response size, and continued service latency.

Labels:

`security`, `snmp`, `denial-of-service`, `amplification`, `resource-bounds`, `performance`

Dedup note:

No SNMP response-generation or GETBULK complexity finding appears in the supplied dedup index. The indexed control-plane performance issues concern other protocols.
### A9-b1-M01

### C175-HC-012

Title: SNMPv3 users configured with authentication and privacy can be queried without either credential

Severity: High

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/snmp/v3.go:255`
```go
255		// Verify authentication if required.
256		if msgFlags&msgFlagAuth != 0 {
257			if user.authKey == nil {
258				slog.Debug("SNMPv3: user has no auth key", "user", userName)
259				return nil
260			}
261			if !a.verifyAuth(user, authParams) {
262				slog.Debug("SNMPv3: authentication failed", "user", userName)
263				return nil
264			}
```

Trace:

UDP/161 `Start` calls `handlePacketFrom`, which dispatches v3 to `handleV3Packet`. After username lookup, HMAC/timeliness checks run only when the request itself sets `msgFlagAuth`; decryption runs only when it sets `msgFlagPriv`. A request naming an authPriv-configured username with flags zero therefore reaches plaintext GET/GETNEXT/GETBULK and receives a plaintext response. An authPriv user can similarly request authNoPriv and remove confidentiality.

Refutation attempt:

Checked the invalid noAuthPriv guard, USM key derivation, configuration type, and tests. The guard rejects only privacy-without-authentication. There is no VACM/minimum-security-level gate elsewhere, and the regression test explicitly asserts a key-bearing user must be served at noAuthNoPriv. The config model describes the user as having authentication/privacy credentials and exposes no separate access rule authorizing downgrade.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

SNMP management-plane only. The violated invariant is that configured credentials establish a minimum security level; request flags cannot opt out of the operator's authentication or confidentiality policy.

Why it matters:

Anyone who can guess or learn a username can read system identity, uptime, and interface inventory/counters without the configured password. This also exposes the unauthenticated GETBULK CPU path in H03 and makes privacy configuration misleading.

Fix direction:

Derive a minimum security level per user. Require auth whenever `authKey` exists and require auth+priv whenever a privacy key/protocol is configured; reject lower request levels before decoding the scoped PDU. If intentional multi-level access is needed, add explicit VACM-style configuration rather than inferring permission from request flags. Replace the current downgrade test with an authPriv/authNoPriv/noAuth matrix.

Labels:

`security`, `snmpv3`, `authentication-bypass`, `confidentiality`, `telemetry`, `vsrx-parity`

Dedup note:

No SNMPv3 security-level downgrade appears in the supplied index. The indexed SNMPv3 crypto finding is the distinct ignored `crypto/rand.Read` error.
### A9-b1-H03

### C175-HC-013

Title: `--skip-validate` still creates a fully signed, publishable image set

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`scripts/image/bake.py:470`
```python
    Aborts the bake (via die(), exit non-zero) if the gate FAILS, so a
    validation failure stops BEFORE signing (#4017). --skip-validate
    downgrades to a loud warning and skips the gate — the resulting
    artifacts are marked non-publishable.
    """
    if skip_validate:
        print("WARNING: --skip-validate — artifacts have NOT passed the in-guest "
              "verify-dataplane gate; do not publish them.", file=sys.stderr)
        return
```

Finalization treats that return as success at `scripts/image/bake.py:526`:

```python
    one, per the #1864 secure-boot chain) is produced ONLY after the gate
    returns success. If validate_step aborts — die()/SystemExit or any
    exception — sign_step is never reached, so a bake that fails validation
    leaves NO signed artifact behind. Extracted as a standalone,
    dependency-free function so the ordering is unit-testable with injected
    steps (scripts/image/test_bake_sign_ordering.py).
    """
    validate_step()
    sign_step()
```

Trace:

`main` passes `a.skip_validate` to `validation_gate_step` and then `sign_manifest_step` through `finalize_artifacts` at lines 723-727. With a signing key set, skip returns normally, signing executes, and `publish.py` sees the same valid manifest/signature shape as a validated bake. The assigned test explicitly documents that skip can proceed to sign at `test_bake_sign_ordering.py:126-132`.

Refutation attempt:

The warning is only stderr text; no durable non-publishable marker is written and no signature is suppressed. The publish gate has no source of validation provenance other than the signature, so it cannot enforce the warning.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Build-time only. Invariant checked: a trust-bearing signature must imply the required in-guest validation gate actually passed.

Why it matters:

A development or emergency bake made with `--skip-validate` can be indistinguishable from a release artifact and pass the fail-closed publication gate despite never booting or verifying the dataplane.

Fix direction:

Make skip and signing mutually exclusive, or emit signed provenance that records validation state and have publication require `validated=true` bound into the signed manifest. Remove any stale signature before a skipped/failed bake completes.

Labels:

image, supply-chain, validation, signing, fail-open

Dedup note:

No matching skip-validation/signing finding appears in the index; `fable-review-165` H-9 concerns missing validation scenarios, not bypass provenance.
### A10-b4-05

### C175-HC-014

Title: `operator` can disarm forwarding and dataplane queues through request verbs omitted from the maintenance gate

Severity: High

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/permissions.go:147`:

```go
	if action == "request" && requestSubcommandIsMaintenance(parts[1:]) {
		return config.PermMaint
	}

	switch action {
	case "show", "ping", "traceroute", "monitor":
		return config.PermView
	case "clear":
		return config.PermClear
	case "request", "test":
```

`pkg/cli/cli_request_chassis.go:180`:

```go
	case len(args) > 0 && args[0] == "forwarding":
		armed, err := dpuserspace.ParseForwardingCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetForwardingArmed(armed)
		if err != nil {
```

Called parser contract, `pkg/dataplane/userspace/control.go:15`:

```go
func ParseForwardingCommand(args []string) (bool, error) {
	if len(args) != 2 || args[0] != "forwarding" {
		return false, fmt.Errorf("usage: %s", ForwardingUsage)
	}
	switch strings.ToLower(args[1]) {
	case "arm":
		return true, nil
	case "disarm":
		return false, nil
```

Built-in class contract, `pkg/config/types_system.go:605`:

```go
// PermMaint (destructive maintenance) is deliberately absent from every
// non-super class: only `super-user` (via PermAll) may reboot/halt/power-off/
// zeroize the box or trigger a chassis-cluster failover, matching Junos where
// the predefined `operator` class has no `maintenance` permission (#4108 F21).
var LoginClassPermissions = map[string][]LoginClassPermission{
	"super-user": {PermAll},
	"operator":   {PermView, PermClear, PermControl},
	"read-only":  {PermView},
```

Trace:

`checkPermission` maps a resolved `request chassis cluster data-plane userspace forwarding disarm` to ordinary `PermControl` because `requestSubcommandIsMaintenance` recognizes only system power/wipe verbs and chassis `failover`. The predefined `operator` has `PermControl`, so dispatch reaches `ParseForwardingCommand`, obtains `false`, and invokes `SetForwardingArmed(false)`. The same permission path reaches queue/binding `unregister|disarm` and `in-service-upgrade`, which can force all RGs secondary.

Refutation attempt:

I checked abbreviation resolution, built-in/custom class mapping, handler-side confirmation, and parser semantics. The maintenance helper resolves abbreviations but never classifies `data-plane` or `software in-service-upgrade`; the forwarding/queue/binding handlers have no confirmation or second permission check. Existing RBAC tests intentionally cover the non-destructive `forwarding arm` form and call ISSU benign, but never exercise `disarm`/`unregister`; that does not refute the destructive forms.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Control-plane only, but it directly changes the packet-path liveness gate. RBAC invariant: a class without `PermMaint` must not be able to take forwarding out of service, detach queues/bindings, or force ownership away from the node.

Why it matters:

Compromise or misuse of an operator-level account can stop forwarding on the active firewall, producing a network outage across security zones despite the repository's explicit super-user-only maintenance boundary.

Fix direction:

Classify request verbs by resolved leaf and operation, not just the first three tokens. Require `PermMaint` for forwarding/queue/binding `disarm|unregister`, packet injection if retained in production, and ISSU ownership drain; keep read/status and restorative `arm|register` operations at the intended lower level. Add positive and negative tests for every leaf and abbreviation.

Labels:

security, authorization, availability, command-dispatch, vsrx-parity

Dedup note:

Distinct residual of indexed F21. F21's reboot/halt/power-off/zeroize/failover verbs are now gated; these separate destructive userspace-control and ISSU leaves were not included in that fix.

### C175-HC-015

Title: `xpfd upgrade` ignores positional arguments, so `xpfd upgrade rolling` performs an uncoordinated standalone cut

Severity: High

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/xpfd/upgrade.go:39`
```go
39	journalPath := fs.String("journal", upgrade.DefaultJournalPath, "crash-safe state journal path")
40	unit := fs.String("unit", upgrade.DefaultUnit, "systemd unit name")
41	healthDeadline := fs.Duration("health-deadline", 30*time.Second,
42		"post-start helper-health deadline before auto-rollback (standalone)")
43	if err := fs.Parse(args); err != nil {
44		os.Exit(1)
45	}
```

Trace:

Go's `flag.FlagSet.Parse` accepts `rolling` as a positional argument, leaves `*rolling == false`, and exposes it via `fs.Args`; this wrapper never checks `NArg`. It therefore reaches `Runner.Run`, whose called contract explicitly implements the standalone STOP->FLIP->START flow and has no cluster-state guard. Only `RunRolling` performs peer health, sync, takeover-readiness, force-secondary, and strong-drain checks.

Refutation attempt:

Read the called `Runner.Run` and `RunRolling` contracts. The former only acquires the host upgrade lock and starts the standalone cut; it does not infer cluster membership or require prior drain. The post-install script's policy of calling plain upgrade only on standalone nodes does not protect an operator invocation or typo.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Cold upgrade path. The violated HA invariant is "never stop/cut a clustered node until the peer owns the RGs and sync/drain predicates are proven"; packet hot-path constraints are unaffected by the fix.

Why it matters:

Omitting the two dashes from a plausible maintenance command changes a guarded rolling upgrade into a direct daemon stop and binary flip. That can drop sessions, strand VIPs during an unhealthy-peer condition, and defeat the repository's explicit HA smoke-gate assumptions.

Fix direction:

Reject `fs.NArg() != 0` before constructing/running the runner, and do the same for other mutating subcommands/verbs. Add a second defense in the plain runner or wrapper that detects configured cluster mode and requires either `--rolling` or an explicit, verified drained override. Add parser tests proving `rolling`, unknown positionals, and positionals before flags perform no mutation.

Labels:

`upgrade`, `ha`, `availability`, `input-validation`

Dedup note:

No positional-argument or rolling-to-standalone root cause appears in the supplied dedup index.
### A10-b1-M01

### C175-HC-016

Title: A failed `systemctl is-active` query is treated as inactive, so DHCP policy apply can silently skip restart or stop.

Severity: High

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcpserver/dhcpserver.go:60` discards the command error and maps every empty or unknown result to false:
```go
60 func unitIsActive(unit string) bool {
61     ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
62     defer cancel()
63     cmd := exec.CommandContext(ctx, "systemctl", "is-active", unit)
64     cmd.WaitDelay = 5 * time.Second
65     out, _ := cmd.Output()
66     switch strings.TrimSpace(string(out)) {
67     case "active", "activating", "reloading", "deactivating":
```

`pkg/dhcpserver/dhcpserver.go:278` uses false as permission to skip a cluster-commit restart and still returns success:

```go
278     if want4 {
279         if err := m.generateKea4Config(cfg); err != nil {
280             errs = append(errs, fmt.Errorf("generate kea4 config: %w", err))
281         } else if restartInactive || m.unitActive(kea4Svc) {
282             if err := m.runSystemctl("restart", kea4Svc); err != nil {
283                 errs = append(errs, fmt.Errorf("restart %s: %w", kea4Svc, err))
284             }
285         }
```

`pkg/dhcpserver/dhcpserver.go:388` also ignores config-removal errors after a false activity result:

```go
388             slog.Warn("failed to stop Kea unit", "service", svc, "err", e)
389         } else {
390             slog.Info("stopped Kea unit not in current config", "service", svc)
391         }
392     }
393     os.Remove(confPath)
394     return err
```

Trace:

On an active cluster node, a config commit changes a subnet while `systemctl is-active` times out, cannot execute, or returns malformed/empty output. Generation succeeds, the boolean is false, restart is skipped, `lastAppliedGen` advances, and the commit returns nil while the old Kea process continues serving stale policy. For a removed family, the same query failure skips the stop, ignores config unlink failure, and returns nil while the old process can keep serving the removed subnet from memory.

Refutation attempt:

I checked the synchronous `ApplyClusterCommit`, normal `Apply`, `Clear`, and async paths. There is no secondary service-state check, no unconditional stop for an absent desired family, and the `bool` seam cannot distinguish a known inactive state from query failure. A nonzero `systemctl is-active` exit with a recognized `inactive`/`failed` stdout can safely map to false; execution and timeout failures cannot.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

This is cold lifecycle work. The violated invariant is "skip a policy-enforcement action only after positively establishing that the service is inactive." Query uncertainty currently fails open.

Why it matters:

The control plane can report a successful commit while DHCP continues advertising old gateways, DNS, pools, reservations, or a family that was explicitly removed. That is policy drift and can allocate addresses on the wrong network.

Fix direction:

Change the seam to `(active bool, err error)` or a tri-state. Parse recognized systemd state output separately from command execution/timeout errors and propagate uncertainty to the caller. For removal, make stop authoritative and surface unlink errors. Do not advance the applied generation as successful after an enforcement failure; add timeout/exec-error tests for active-change and removed-family cases.

Labels:

`fail-open`, `dhcp-server`, `systemd`, `policy-enforcement`, `vsrx-parity`

Dedup note:

No matching systemd-query/false-inactive root cause was present in `dedup-index.md`.
### H03

### C175-HC-017

Title: A transient status-command failure is mistaken for proof that an HA node rebooted

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`scripts/deploy/xpf-deploy.py:1256`
```python
            while _time.time() < deadline:
                _time.sleep(10)
                st = _kernel_status(runner, backend, node)
                running = _running_kernel(runner, backend, node)
                if not running:
                    rebooted = True   # transport dropped -> the box is rebooting
                    continue          # node still rebooting / unreachable
                if running == version:
                    rebooted = True   # booted the candidate kernel
```

The command wrapper discards return status at `scripts/deploy/xpf-deploy.py:1086`:

```python
    if runner.dry:
        print("   " + " ".join(shlex.quote(a) for a in full))
        return ""
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"{node}: command failed ({' '.join(argv)}): "
            f"{r.stdout.strip()} {r.stderr.strip()}")
    return r.stdout
```

Trace:

The node is confirmed drained; `arm` is deliberately run with `check=False`; a preflight failure leaves it running and ForceSecondary; one transient SSH/Incus or `uname` command failure returns empty stdout and sets `rebooted=True`; the next successful poll reports the known-good kernel and `armed=none`; lines 1282-1289 classify that as a completed revert; `finally` rejoins only when `not rebooted` at lines 1328-1334, so the still-running node remains drained.

Refutation attempt:

An empty `uname` string does not prove transport loss or a reboot; it also represents command-not-found, permission, timeout, backend, and remote-shell failures because return code/stderr are thrown away. A later boot ID or confirmed kernel transition is never required. Existing deploy tests do not exercise the kernel-roll state machine.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Orchestration path only. Invariant checked: suppressing HA rejoin requires affirmative evidence that reboot cleared the in-memory drain state.

Why it matters:

A single observability failure can strand one member ForceSecondary with both leases released. Redundancy is silently lost, and subsequent maintenance or failure of the peer can create a no-primary outage.

Fix direction:

Return a structured command result including transport/exit status; treat unknown observations as unknown, not reboot; record pre-arm `/proc/sys/kernel/random/boot_id` and require a changed boot ID or another affirmative reboot signal; decide rejoin from confirmed drain state, not an inferred boolean.

Labels:

deploy, ha, kernel-roll, fail-open, observability

Dedup note:

Distinct from `fable-review-165` H-32 (lease release) and H-33 (node-ID order); this is false reboot classification and skipped rejoin.
### A10-b4-04

### C175-HC-018

Title: An unreadable `BootCurrent` prunes a possibly running candidate kernel

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`pkg/upgrade/kernel_run.go:359`
```go
	cur, err := sys.BootCurrent()
	if err != nil {
		// Can't tell which slot we booted. Do NOT reboot (that risks a loop on
		// a flaky efibootmgr — r1 AGY): clean up to known-good in place.
		return r.cleanupAlreadyOnKnownGood(j, fmt.Errorf("read BootCurrent: %w", err))
	}
	if cur != candID {
		// Firmware ignored BootNext / fell back — this boot is ALREADY on a
		// non-candidate (known-good) slot. This is NOT a revert-needing reboot:
```

That cleanup removes the candidate at `pkg/upgrade/kernel_run.go:498`:

```go
	if err := sys.DisarmWatchdog(); err != nil {
		r.logf("kernel-upgrade: WARNING disarm watchdog: %v", err)
	}
	if err := sys.PruneInactiveSlot(j.InactiveSlot, j.KnownGoodVersion, j.CandidateVersion); err != nil {
		r.logf("kernel-upgrade: WARNING prune inactive slot: %v", err)
	}
	// Clear the durable promotion marker (r2 AGY #6: a reverted node must not
	// retain a "promoted" marker from a prior same-version roll) and the local
```

Trace:

A candidate boot reaches `Promote`; `BootEntries` succeeds but a transient `efibootmgr`/NVRAM read makes `BootCurrent` fail; the code assumes the machine is already known-good before calling `RunningKernel` (which is only reached at lines 376-382); `cleanupAlreadyOnKnownGood` calls `PruneInactiveSlot`; the real implementation purges candidate packages and removes `/lib/modules/<candidate>` and `/boot/*-<candidate>` at `kernel_linux.go:497-533`; the journal and lease are then cleared and promotion returns success.

Refutation attempt:

Preflight does not guarantee that a later post-boot NVRAM read succeeds, and `BootEntries` success does not identify the entry actually booted. The fake system has no injectable `BootCurrent` error, so current tests cover a confirmed known-good ID but not this ambiguous branch. `uname -r` is an available independent discriminator but is consulted too late.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Boot-time control path only. Invariant checked: destructive candidate cleanup requires affirmative proof that the candidate is not the running kernel.

Why it matters:

The node can continue on a running kernel whose package, modules, boot files, promotion journal, and recovery lease were just removed. A later module load or reboot can fail, while orchestration sees a successful known-good cleanup.

Fix direction:

Read and validate `RunningKernel` before any prune. If it equals the candidate, preserve the journal and run the normal verification gate or enter an explicit ambiguous/recovery state; if neither boot identity nor running version proves known-good, fail without destructive mutation.

Labels:

upgrade, kernel, fail-open, destructive-cleanup, ha

Dedup note:

Distinct from `fable-review-165` M-2/M-3/M-4/M-10; none covers a `BootCurrent` read error deleting the running candidate.
### A10-b4-03

### C175-HC-019

Title: DDNS corrupt-state quarantine fails closed for only one process lifetime, then silently reopens on restart.

Severity: High

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/ddns/manager.go:320` classifies corruption and moves the only canonical state file aside:
```go
320 func loadStateOrDegrade(path string, now func() time.Time) (st *ddnsState, degraded bool, reason string) {
321     st, err := loadDDNSState(path)
322     if err == nil {
323         return st, false, ""
324     }
325     classified := errors.Is(err, errDDNSStateCorrupt) || errors.Is(err, errDDNSStateUnsupportedVersion)
326     reason = err.Error()
327     if classified {
328         nowFn := now
```

`pkg/ddns/state.go:366` implements quarantine as a rename with no durable degraded marker:

```go
366 func quarantineBadState(path string, now time.Time) (string, error) {
367     // Colons are filesystem-hostile; use a compact, sortable stamp.
368     stamp := now.UTC().Format("20060102T150405Z")
369     dst := fmt.Sprintf("%s.corrupt-%s", path, stamp)
370     if err := os.Rename(path, dst); err != nil {
371         return "", fmt.Errorf("quarantine ddns state %s -> %s: %w", path, dst, err)
372     }
373     return dst, nil
```

`pkg/ddns/state.go:326` treats that now-missing canonical path as a fresh, trusted empty store on the next boot:

```go
326 func loadDDNSState(path string) (*ddnsState, error) {
327     s := &ddnsState{path: path, records: map[string]ownedRecord{}}
328     data, err := os.ReadFile(path)
329     if err != nil {
330         if errors.Is(err, os.ErrNotExist) {
331             return s, nil
332         }
333         return s, fmt.Errorf("read ddns state %s: %w", path, err)
```

Trace:

Boot N sees corrupt or unsupported ownership JSON, renames it to `.corrupt-<timestamp>`, and keeps only an in-memory `degraded` flag. A crash, watchdog restart, upgrade, or ordinary reboot starts Boot N+1. The canonical path is absent, so `loadDDNSState` returns an empty store with no error and the new manager resumes publication and deletion with all prior ownership forgotten.

Refutation attempt:

I searched manager construction, state loading, quarantine tests, and restart tests. No persistent marker is created, startup does not scan quarantine siblings, and degraded state is not reconstructed from disk. Existing tests assert only the first manager instance becomes degraded and that the bad file was renamed.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Cold boot path. The documented fail-closed invariant says record operations remain suspended "until the operator resolves" ownership state. A process restart is not operator resolution, so the invariant is not durable.

Why it matters:

Previously published A/AAAA/PTR records become permanently uncleanable, and lost DHCID/backend ownership can allow the node to reclaim or overwrite a name whose safe ownership can no longer be proven.

Fix direction:

Persist degraded status atomically and durably before removing the canonical file. Options include retaining the corrupt canonical file while copying a forensic artifact, or creating and fsyncing a separate `.degraded` marker that startup honors until an explicit repair/import operation clears it. Add a two-constructor restart test and crash-injection around marker/quarantine ordering.

Labels:

`ddns`, `fail-open`, `durability`, `ownership`, `restart`

Dedup note:

Prior DDNS reports covered corrupt-state fail-closed intent but not the quarantine-across-restart hole; no same root cause appears in the dedup index.
### H04

### C175-HC-020

Title: DHCP DUID clearing lets a control-plane caller unlink an arbitrary root-owned file.

Severity: High

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcp/dhcp.go:527` accepts the interface string without validation and passes the derived path directly to `os.Remove`:
```go
527 func (m *Manager) ClearDUID(ifaceName string) error {
528     m.mu.Lock()
529     delete(m.duids, ifaceName)
530     m.mu.Unlock()
531 
532     path := m.duidPath(ifaceName)
533     if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
534         return err
535     }
```

`pkg/dhcp/dhcp.go:613` constructs the filename with attacker-controlled separators intact:

```go
613 func (m *Manager) duidPath(ifaceName string) string {
614     return filepath.Join(m.stateDir, "dhcpv6-duid-"+ifaceName)
615 }
616 
617 func (m *Manager) loadDUID(ifaceName string) (dhcpv6.DUID, error) {
```

The necessary REST caller contract at `pkg/api/dhcp.go:75` forwards the request field directly:

```go
75     if req.Interface != "" {
76         if err := s.dhcp.ClearDUID(req.Interface); err != nil {
77             writeError(w, http.StatusBadRequest, err.Error())
78             return
79         }
80         writeOK(w, map[string]string{"message": fmt.Sprintf("DHCPv6 DUID cleared for %s", req.Interface)})
81         return
```

Trace:

A REST or gRPC request sets `interface` to `../../../../../etc/passwd`. The joined path is `/var/lib/xpf/dhcpv6-duid-../../../../../etc/passwd`, whose normalized target is `/etc/passwd` (confirmed with `realpath -m`). `xpfd` then executes `os.Remove` with daemon privileges. Any unlinkable regular file reachable by a sufficiently deep traversal can be removed.

Refutation attempt:

I traced both REST and gRPC callers in the detached worktree; neither validates membership, Linux interface syntax, separators, or path containment before calling `ClearDUID`. The fixed `dhcpv6-duid-` prefix only changes the first `..` component and does not neutralize subsequent traversal components. `os.Remove` does not perform a containment check.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

This is a cold administrative path. The violated invariant is that a state-file operation derived from an interface identifier must remain beneath `stateDir`; lexical normalization demonstrated that it does not.

Why it matters:

A user authorized only to invoke the DHCP identifier operation can delete service configuration, authentication databases, state, or other root-owned files, producing denial of service or weakening subsequent boot behavior.

Fix direction:

Reject anything that is not a canonical Linux interface name before all DUID path operations, explicitly reject `/`, `\\`, `.`/`..` components and NUL, and verify the cleaned result remains under the cleaned state directory. Prefer a reversible filename encoding or a keyed state map over embedding raw identifiers. Add REST and gRPC traversal tests plus direct unit tests for containment.

Labels:

`security`, `path-traversal`, `arbitrary-unlink`, `dhcp`, `control-plane`

Dedup note:

No DUID/path-containment finding matched in `dedup-index.md`.
### H02

### C175-HC-021

Title: HA DHCP lease lifetimes stop aging on the standby and are re-extended or resurrected at takeover.

Severity: High

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcpserver/lease_sync.go:68` defines `Remaining` only at sender observation time:
```go
68 // Remaining is the SECONDS of valid lifetime left at the moment the SENDER read
69 // the lease (Expire - now_sender). The receiver re-anchors it to fresh absolute
70 // time at seed (now_local + Remaining) — see the clock invariant above.
71 type SyncLease struct {
72     Family int // 4 or 6
73 
74     Address  string // v4 dotted / v6 colon address (or PD prefix base for IA_PD)
75     SubnetID int    // Kea subnet-id the lease belongs to
76 
```

`pkg/dhcpserver/lease_sync.go:253` computes the value once and carries no observation timestamp:

```go
253     // Remaining = (cltt + valid-lft) - now, computed on the sender's clock.
254     expire := kl.Expire
255     if expire == 0 {
256         expire = kl.CLTT + int64(kl.ValidLft)
257     }
258     rem := expire - now.Unix()
259     if rem < 0 {
260         rem = 0
261     }
262     l.Remaining = int(rem)
```

`pkg/dhcpserver/lease_sync.go:520` re-anchors the unchanged value at takeover and even revives zero as one second:

```go
520 // syncLeaseToKea re-anchors a SyncLease to fresh absolute time at seed (the
521 // clock-skew-immunity step: expire = now_local + Remaining) and renders the Kea
522 // lease{4,6}-add argument record. valid-lft is set to Remaining so a renewing
523 // client sees the correct remaining time, and the absolute expire matches.
524 func syncLeaseToKea(l SyncLease, now time.Time) keaLeaseJSON {
525     rem := l.Remaining
526     if rem < 1 {
527         rem = 1 // Kea rejects a zero/negative lifetime; floor to 1s
528     }
```

The necessary receiver contract at `pkg/cluster/sync.go:935` stores only a value copy, with no receipt time to age against:

```go
935 // PeerDHCPLeases4 returns a copy of the v4 lease set held from the peer (#2239).
936 // The standby seeds these into Kea on takeover.
937 func (s *SessionSync) PeerDHCPLeases4() []dhcpserver.SyncLease {
938     s.peerDHCPLeasesMu.Lock()
939     defer s.peerDHCPLeasesMu.Unlock()
940     cp := make([]dhcpserver.SyncLease, len(s.peerDHCPLeases4))
941     copy(cp, s.peerDHCPLeases4)
942     return cp
```

Trace:

The master reads a lease with 60 seconds remaining and sends it. The standby holds that value for ten minutes while the sync channel is partitioned or the peer is otherwise stale. On promotion, both pre-seed and control-socket seed compute `expire = now_local + 60`, resurrecting a lease that expired nine minutes earlier. Even healthy operation extends leases by transport/heartbeat age (up to roughly the 30-second full-set cadence). The original server or another allocator may already have reassigned the address/prefix.

Refutation attempt:

I traced the cluster wire encoding, receive store, peer getters, daemon pre-seed, post-start seed, and memfile fallback in the detached worktree. The wire carries `Remaining` but no sample epoch; the receiver stores no monotonic receipt time; neither seed path subtracts standby residence; and zero is floored to one instead of dropped. Periodic pushes bound the healthy case only and do not solve the stale-partition condition under which failover matters most.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

HA control path, not packet hot path. The violated invariant is monotonic lease lifetime: remaining validity may only decrease after the sender observes it. Here it remains constant and then restarts from that constant.

Why it matters:

A promoted node can create overlapping DHCPv4 addresses, DHCPv6 addresses, or delegated prefixes. Duplicate ownership can blackhole traffic, route a customer's delegated prefix to the wrong client, or enable interception on the shared segment.

Fix direction:

Record receiver receipt time per full-set family and subtract monotonic residence before either seed; drop leases at or below zero. Include a bounded transport-age treatment (for example, a sender sample timestamp with an established clock-offset bound, or conservative receipt-time anchoring) without trusting raw peer wall clocks. Persist or invalidate held sets across long disconnects and add partition-duration/takeover tests.

Labels:

`ha`, `dhcp-server`, `lease-sync`, `duplicate-allocation`, `vsrx-parity`

Dedup note:

No HA DHCP lifetime-aging finding matched in the dedup index.
### H06

### C175-HC-022

Title: Local `zeroize` leaves the authoritative config database and reports a completed wipe

Severity: High

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_request_system.go:68`:

```go
		// Remove active and candidate configs, rollback history
		configDir := "/etc/xpf"
		files, _ := os.ReadDir(configDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".conf") || strings.HasPrefix(f.Name(), "rollback") {
				os.Remove(configDir + "/" + f.Name())
			}
		}
```

Called persistence contract, `pkg/configstore/store.go:195`:

```go
func New(filePath string) (*Store, error) {
	dbDir := filepath.Join(filepath.Dir(filePath), ".configdb")
	db, err := NewDB(dbDir)
	if err != nil {
		return nil, fmt.Errorf("config db %s unusable: %w (no file-only fallback exists; refusing to run without config persistence)", dbDir, err)
	}

	journalPath := filepath.Join(filepath.Dir(filePath), ".config.journal")
```

Called startup contract, `pkg/configstore/store_persist.go:18`:

```go
// Load builds the configuration from disk.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, committed, err := s.db.ReadActiveMeta()
	if err != nil {
		// A read/parse/decrypt/envelope failure on a PRESENT active.json is
```

Trace:

A super-user confirms `request system zeroize`; the loop removes only names ending in `.conf` or beginning with `rollback`, so `/etc/xpf/.configdb/{active,candidate,rollback.N}.json`, `master.key`, and `.config.journal` survive. The command ignores removal errors, prints `Configuration erased`, and asks for a reboot. On that reboot `configstore.New` reopens `.configdb` and `Store.Load` reads its active tree before any legacy file bootstrap, restoring the supposedly erased configuration and secrets.

Refutation attempt:

I checked whether the legacy `.conf` deletion was authoritative, whether startup preferred the removed file, and whether hidden entries matched either predicate. The persistence constructor explicitly has no file-only fallback and points at `.configdb`; `Store.Load` reads that DB. I also checked for error propagation in the wipe loop: all `ReadDir`, `Remove`, `RemoveAll`, and `systemctl stop` errors are discarded, so no later guard refutes the false-success path.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Control-plane only. Factory reset invariant: success may be reported only after all authoritative configuration, rollback/candidate state, encryption keys, rescue/archive state, and audit artifacts intended for tenant wipe are durably removed; failure must be explicit.

Why it matters:

A maintainer can hand off or repurpose a firewall after a reported zeroize while the prior tenant's policy, credentials, and keys remain recoverable and become active again after reboot.

Fix direction:

Move zeroize into one shared, tested factory-reset primitive used by local CLI and RPC paths. Stop mutators, remove the complete configstore directory and explicitly enumerated sibling artifacts with checked errors, fsync parent directories, and report success only after verification. Add a temp-directory test that commits a secret, runs the wipe primitive, reconstructs a `Store`, and proves startup is empty.

Labels:

security, data-remanence, fail-open, persistence, vsrx-parity

Dedup note:

Distinct from indexed F-038-031 (in-memory/key-buffer zeroization) and F8 (system-action journaling). This finding is that the local factory-reset path does not delete the authoritative on-disk database at all.

### C175-HC-023

Title: Publication verifies a mutable tree and later uploads whatever bytes replaced it

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`scripts/dist/publish.py:760`
```python
    # ── fail-closed gate ──
    if not a.no_image:
        versions, pub = gate_images(dist, require_installer=not a.no_installer)
        gate_latest(dist, a.channel, versions, pub)
    if not a.no_apt:
        gate_apt(dist, a.channel)

    pubcmd = os.environ.get("XPF_PUBLISH_CMD")
    if not pubcmd:
```

Dispatch later hands the original live directory to an arbitrary backend at `scripts/dist/publish.py:695`:

```python
def dispatch(cmd, local_dir, base_url, dry):
    info(f"publish: {cmd} {local_dir} {base_url}")
    if dry:
        print(f"  (dry-run) {cmd} {local_dir} {base_url}")
        return
    r = subprocess.run([cmd, local_dir, base_url])
    if r.returncode != 0:
        die(f"XPF_PUBLISH_CMD failed (rc={r.returncode}) for {base_url}")
```

Trace:

`gate_images` hashes artifacts and verifies `install.sh` at lines 397-417 and 517-525; the function returns; no file descriptors, snapshot, lock, or content-addressed staging tree is retained; `dispatch` gives the mutable `dist` pathname to the backend, which reopens files recursively. A concurrent bake, cleanup, or process with write access can replace an artifact, sidecar, or installer after the gate. `sign.verify_image_artifact` likewise returns only `True` after hashing the path, so callers cannot use the verified bytes atomically.

Refutation attempt:

Most signed image artifacts will later fail client-side hash verification if only the artifact changes, but the published tree can still be internally inconsistent and unavailable. More seriously, the Tier-A `install.sh` is fetched and executed directly; its signature was checked only by this gate and the upload backend is not required to reverify or snapshot it. Same-user/concurrent-writer risk is realistic in CI artifact directories.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Release tooling only. Invariant checked: uploaded bytes must be the exact bytes accepted by the signing/publication gate.

Why it matters:

A gate-pass log can accompany different uploaded content, including an unsigned replacement installer, defeating the stated fail-closed release boundary and enabling release compromise or widespread install failure.

Fix direction:

Copy allowed regular files into a private, immutable staging directory while hashing; verify signatures/hashes against that snapshot; fsync it; and dispatch only the snapshot. Prefer content-addressed backend uploads and atomically publish the index last.

Labels:

distribution, supply-chain, toctou, publication

Dedup note:

`fable-review-165` H-5/H-13 cover ungated file classes/channels, not gate-to-dispatch mutation of bytes that were gated.
### A10-b4-07

### C175-HC-024

Title: Remote `commit` grammar turns an unknown modifier into a permanent commit and silently rewrites invalid confirmed deadlines

Severity: High

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/cli/main.go:245`
```go
245	if len(args) > 0 && args[0] == "confirmed" {
246		minutes := int32(10)
247		if len(args) >= 2 {
248			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
249				minutes = int32(v)
250			}
251		}
252		resp, err := c.client.CommitConfirmed(c.ctx(), &pb.CommitConfirmedRequest{Minutes: minutes})
253		if err != nil {
```

Trace:

`dispatchConfig` passes every token after `commit` to `handleCommit`. Only exact `check`, `comment`, and `confirmed` prefixes return before line 262. Thus `commit confimed 10` skips all three branches and invokes the permanent `Commit` RPC. `commit confirmed junk`, `0`, or a negative value silently keeps the 10-minute default. On this 64-bit target, `commit confirmed 4294967297` parses successfully and narrows to `int32(1)`, arming one minute rather than rejecting the value.

Refutation attempt:

Checked the canonical command tree and the gRPC contracts. The tree supplies completion/help only and does not validate dispatch. `Commit` and `CommitConfirmed` are separate server mutations; there is no server signal that an unknown client-side modifier was present. No assigned test exercises `handleCommit` grammar or timer bounds.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Cold control path only. The violated invariant is that an unrecognized or malformed safety-critical configuration command must fail before any mutation; no packet-path allocation or latency change is implicated.

Why it matters:

`commit confirmed` is the operator's rollback guard when changing reachability. A one-character typo can permanently apply a management-stranding configuration with no timer, while malformed/overflowed deadlines can roll back much earlier than requested.

Fix direction:

Parse the full command with an exact switch: zero args means plain commit; every recognized modifier must enforce exact arity; every unknown token must error. Parse confirmed minutes directly into a bounded width (`ParseInt(..., 10, 32)`) and enforce the product/Junos range. Add no-RPC tests for unknown modifiers, missing/extra arguments, zero/negative values, `MaxInt32+1`, and `2^32+1`.

Labels:

`cli`, `config-safety`, `fail-open`, `integer-truncation`, `vsrx-parity`

Dedup note:

No matching commit-command root cause appears in the supplied dedup index. The indexed commit-confirmed HA timer finding concerns demotion after a valid commit, not client grammar.
### A10-b1-H02

### C175-HC-025

Title: Root XSK tooling writes and loads a predictable attacker-owned `/tmp` BPF object

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/main.rs:250`
```rust
fn load_xdp_prog() -> (i32, i32) {
    // Write XDP object to temp file
    let obj_path = "/tmp/xdp_pass_redirect.o";
    std::fs::write(obj_path, XDP_OBJ).expect("write XDP obj");

    // Use libbpf to load
    let cpath = CString::new(obj_path).unwrap();

    // Open object
    let obj = unsafe { libbpf_sys::bpf_object__open(cpath.as_ptr()) };
```

The C path independently trusts the same name at `test/xsk-repro/libbpf_xsk_test.c:48`:

```c
static int load_xdp_prog(const char *iface, int ifindex, int *map_fd_out)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, err;

    obj = bpf_object__open("/tmp/xdp_pass_redirect.o");
    if (!obj) {
```

Trace:

The documented tool requires root. An unprivileged user pre-creates `/tmp/xdp_pass_redirect.o` as a symlink; Rust `std::fs::write` follows it and truncates/overwrites the target as root. There is also a write-to-open race, and both C binaries load a world-writable-namespace pathname without ownership/mode/inode verification.

Refutation attempt:

`fs.protected_symlinks`/`fs.protected_regular` can reject some pre-created objects on hardened hosts, converting the Rust case into a denial of service, but the code does not require those sysctls and the C binaries still directly trust the fixed object. The sticky bit alone does not prevent pre-creation. BPF verification limits kernel memory-safety exploits but does not prevent arbitrary file clobber where following is allowed or malicious packet-path behavior from replaced bytes.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Setup path only. Invariant checked: privileged tooling must not follow or trust attacker-controlled filesystem names between materialization and load.

Why it matters:

Running the diagnostic can corrupt an arbitrary root-writable file, or load/attach BPF bytes that were not the embedded reviewed object.

Fix direction:

Load from a sealed `memfd` if supported, or create a private `mkstemp`/`O_CREAT|O_EXCL|O_NOFOLLOW` file in a 0700 directory, keep the descriptor open, load through `/proc/self/fd/<n>`, verify inode/type/mode, and unlink after open.

Labels:

security, xsk-repro, toctou, symlink, privileged-tooling

Dedup note:

No predictable-`/tmp` BPF-object finding appears in the index.
### A10-b4-11

### C175-HC-026

Title: Scheduler off-CPU intervals end at wakeup instead of schedule-in, making involuntary waits unmeasurable

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/step2-sched-switch-reduce.py:417`
```python
        if event == "sched:sched_switch":
            prev_pid = fields.get("prev_pid")
            prev_state = fields.get("prev_state", "")
            if prev_pid in worker_tids:
                off_start_ns[prev_pid] = t_event_wall_ns
                off_state[prev_pid] = prev_state
        elif event == "sched:sched_wakeup":
            pid = fields.get("pid")
            if pid in worker_tids and pid in off_start_ns:
```

The parser deliberately discards the schedule-in identity at `test/incus/step2-sched-switch-reduce.py:198`:

```python
            if event == "sched:sched_switch":
                pm = SWITCH_PREV_PID_RE.search(rest)
                sm = SWITCH_PREV_STATE_RE.search(rest)
                if pm:
                    fields["prev_pid"] = int(pm.group(1))
                if sm:
                    fields["prev_state"] = sm.group(1)
```

Trace:

A worker switched out with `prev_state=R` remains runnable and normally receives no `sched_wakeup`; its interval is therefore never closed on the later `sched_switch next_pid=<worker>`. For sleeping workers, wakeup marks transition to runnable, not actual CPU resumption, so run-queue latency is excluded. Tests at `step2-sched-switch-reduce_test.py:190-217` synthesize a wakeup after `prev_state=R`, an event sequence the scheduler does not emit for ordinary preemption.

Refutation attempt:

`sched_wakeup` is appropriate for blocked duration but cannot measure total off-CPU duration or involuntary preemption. No `next_pid` regex/state exists anywhere in the reducer, so another branch cannot close these intervals.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Offline reducer only. Invariant checked: off-CPU time is `schedule-in timestamp - schedule-out timestamp`, with wakeup retained only as an optional runnable-state marker.

Why it matters:

The principal involuntary scheduler-pressure channel is systematically zero, stale, or misattributed, and voluntary values omit queueing delay. Root-cause classification built from these blocks can confidently point away from scheduler contention when it is present.

Fix direction:

Parse `next_pid`; start on switch-out and close on switch-in; preserve `prev_state` for voluntary/involuntary classification; optionally split blocked and runnable-queue components using wakeup; replace impossible synthetic traces with kernel-realistic sequences.

Labels:

packet-tooling, scheduler, evidence-integrity, false-negative

Dedup note:

No matching `sched_switch` interval-semantic finding appears in the index.
### A10-b4-09

### C175-HC-027

Title: Surface B keeps one representative DDNS updater for two independent families and can withdraw IPv6 through the IPv4 provider.

Severity: High

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/ddns/manager.go:607` correctly resolves one live updater per family initially:
```go
607     // Resolve each family's live backend from THIS cycle's policy (plan §6
608     // fork 1: resolve-per-Reconcile, now PER FAMILY — #2663). A nil factory
609     // keeps the static updater (tests inject a fixed fakeUpdater). A factory
610     // error (bad TSIG / unusable policy) for one family falls back to that
611     // family's no-op WITHOUT affecting the other family — independence (#2663).
612     if m.newUpdater != nil {
613         env.updater[0] = m.resolveFamilyUpdater(pol4, ddns4)
614         env.updater[1] = m.resolveFamilyUpdater(pol6, ddns6)
```

`pkg/ddns/manager.go:620` then substitutes the same prior updater for either family that needs withdrawal:

```go
620         if isNopUpdater(env.updater[0]) && !isNopUpdater(m.updater) && m.familyOwnsRecords(4) {
621             env.updater[0] = m.updater
622             slog.Debug("ddns: keeping live v4 updater this cycle to withdraw owned records")
623         }
624         if isNopUpdater(env.updater[1]) && !isNopUpdater(m.updater) && m.familyOwnsRecords(6) {
625             env.updater[1] = m.updater
626             slog.Debug("ddns: keeping live v6 updater this cycle to withdraw owned records")
627         }
```

`pkg/ddns/manager.go:628` always remembers IPv4 first, even when IPv6 has a different backend:

```go
628         // Track a single representative live updater for the next-cycle
629         // withdraw guard (m.updater is the "last live backend seen" anchor).
630         if !isNopUpdater(env.updater[0]) {
631             m.updater = env.updater[0]
632         } else if !isNopUpdater(env.updater[1]) {
633             m.updater = env.updater[1]
634         }
```

Trace:

Configure DHCPv4 DDNS through provider A and DHCPv6 DDNS through provider B, and publish records in both families. The representative becomes A. Disable both DDNS families, remove the DDNS configuration, or make the v6 backend temporarily unresolvable. Both family updaters resolve to no-op, both see owned records, and both are replaced with A. The AAAA/PTR delete is sent to A rather than B; B's record remains, while a permissive/wrong endpoint can also cause local ownership to be dropped after deleting the wrong namespace.

Refutation attempt:

I checked family policy inheritance, updater resolution, owned-record fields, and delete dispatch. Independent family providers are supported, but `Manager` has only one historical updater anchor and Surface B owned records do not retain a usable per-family updater. Existing dual-family tests inject the same fake updater for both families, so they cannot expose endpoint cross-routing.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Reconcile is cold path. The violated invariant is that an owned record must be withdrawn through the same family/backend authority that published it; family independence is lost only in the fallback path.

Why it matters:

Turning DDNS off or recovering from a provider error can leave stale public DNS indefinitely, delete in the wrong account/zone, or discard the only cleanup authority while claiming success.

Fix direction:

Maintain independent previous-live updater state per family at minimum. More robustly, persist a non-secret backend identity/fingerprint and enough controlled catalog identity to refuse wrong-endpoint deletion, matching Surface A's ownership safeguards. Add a test with distinct v4/v6 fake updaters, publish both, disable both in one cycle, and assert family-correct deletes and retained ownership on mismatch.

Labels:

`ddns`, `ownership`, `cross-family`, `wrong-backend`, `vsrx-parity`

Dedup note:

Distinct from `codex-review-157` H01-H03, which cover Surface A provider catalog/binding transitions. This is Surface B's single historical updater shared across independently configured families.
### H05

### C175-HC-028

Title: The bake authenticates an Ubuntu image with an unsigned checksum from the same endpoint

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`scripts/image/bake.py:208`
```python
    info(f"fetching Ubuntu {rel} server cloud image base ({base_url})")
    cached = os.path.join(cache_dir, img)
    if not os.path.isfile(cached):
        run(["curl", "-fsSL", "-o", cached + ".tmp", f"{base_url}/{img}"])
        os.replace(cached + ".tmp", cached)
    # Re-verify the cache against the upstream checksum (cache not trusted).
    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
    expected = None
```

The only trust decision is the downloaded digest at `scripts/image/bake.py:217`:

```python
    with open(sums) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == img:
                expected = parts[0]
                break
    if not expected:
        die(f"no SHA256 for {img} in upstream SHA256SUMS")
    actual = sha256(cached)
```

Trace:

The image and `SHA256SUMS` come from the same configurable `base_url`; no `SHA256SUMS.gpg`, Ubuntu signing-key fingerprint, or repository-pinned digest is fetched or checked; a compromised mirror/TLS endpoint supplies matching malicious bytes and hash; customization and runtime validation do not establish provenance; XPF then signs the resulting artifact with its release key.

Refutation attempt:

HTTPS protects against passive network corruption but does not protect against a compromised/custom mirror, DNS/CA compromise, or endpoint compromise controlling both files. A hash from the same unauthenticated source proves integrity only, not publisher identity.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Build-time only. Invariant checked: the release signing key may bless only a base image authenticated to a pinned upstream trust root.

Why it matters:

Compromise of the base-image endpoint becomes a trusted XPF appliance release, including arbitrary root-level image contents that ordinary functional validation may not detect.

Fix direction:

Verify Canonical's signed checksum file against a pinned Ubuntu image-signing key/fingerprint, or pin the expected image digest in reviewed repository metadata; bind the authenticated base digest and source into the signed XPF manifest.

Labels:

image, supply-chain, provenance, signing

Dedup note:

Distinct from `fable-review-165` H-37 (an unverified operator import path); this is the release bake's upstream root of trust.
### A10-b4-06

### C175-HC-029

Title: The mouse-latency matrix exits zero when its aggregate verdict is `FAIL`

Severity: High

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/mouse_latency_aggregate.py:378`
```python
    with open(args.out, "w") as f:
        json.dump(
            {
                "summaries": {f"N{n}_M{m}": s for (n, m), s in summaries.items()},
                "verdict": verdict,
            },
            f,
            indent=2,
        )
```

The status mapping at `test/incus/mouse_latency_aggregate.py:388` explicitly treats both outcomes as success:

```python
    print(render_markdown(summaries, verdict))
    return 0 if verdict["verdict"] in ("PASS", "FAIL") else 2


if __name__ == "__main__":
    sys.exit(main())
```

Trace:

`decide` produces `FAIL` when the loaded/idle percentile ratio exceeds threshold; `main` persists and prints that failure but returns 0; the matrix shell invokes the aggregator as its final command under `set -euo pipefail` and does not parse `summary.json` (`test-mouse-latency-matrix.sh:215-222`, inspected only as this caller contract); CI therefore observes a successful matrix process.

Refutation attempt:

Tests extensively cover `decide` and artifact contents but no assigned test asserts CLI status for a `FAIL`. The caller has no independent verdict check, so the JSON cannot rescue automation.

Coordinator verification: independently re-opened the cited source and relevant caller/guard at the immutable base 385f940b7c3208734775d48763e60d66ee8274e0; the runtime trace and failed refutation both hold.

HPC/invariant check:

Evidence-control path only. Invariant checked: a gate's process status must distinguish PASS, measured FAIL, and insufficient evidence.

Why it matters:

A regression that violates the mouse-latency acceptance ratio is green in shell/CI even though the human-readable output says `FAIL`.

Fix direction:

Return 0 for PASS, 1 for FAIL, and 2 for insufficient/error; add subprocess-level tests for all three outcomes and pin the shell contract.

Labels:

test-gate, mouse-latency, false-pass, ci

Dedup note:

No matching aggregate-exit-status finding appears in `dedup-index.md`.
### A10-b4-08

### C175-HC-030

Title: Debug BPF session dump performs an aligned `ptr::read` from a `Vec<u8>` key buffer

Severity: Medium

Confidence: High

Source batch: A1-b2

Evidence:

`userspace-dp/src/afxdp/bpf_map/metrics.rs:151-158` reads a typed key from a byte vector returned by `bpf_map_get_next_key`:

```rust
151     loop {
152         // Read the key as UserspaceSessionMapKey
153         let map_key: UserspaceSessionMapKey =
154             unsafe { core::ptr::read(next_key_bytes.as_ptr().cast()) };
155         let _ = unsafe {
156             libbpf_sys::bpf_map_lookup_elem(
157                 map_fd,
158                 next_key_bytes.as_ptr().cast::<c_void>(),
```

`userspace-dp/src/afxdp/bpf_map/mod.rs:16-23` defines the key as a `repr(C)` struct containing `u16` fields, so the type alignment is greater than 1:

```rust
16 pub(super) struct UserspaceSessionMapKey {
17     addr_family: u8,
18     protocol: u8,
19     pad: u16,
20     src_port: u16,
21     dst_port: u16,
22     src_addr: [u8; 16],
23     dst_addr: [u8; 16],
```

`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3387-3394` shows the reachable call site when the `debug-log` feature is enabled:

```rust
3387                                                     count_bpf_session_entries(
3388                                                         binding.bpf_maps.session_map_fd
3389                                                     ),
3390                                                 );
3391                                                 dump_bpf_session_entries(
3392                                                     binding.bpf_maps.session_map_fd,
3393                                                     20,
3394                                                 );
```

Trace:

1. Build with the `debug-log` feature enabled.
2. A packet creates/publishes a session in `poll_descriptor`.
3. The debug-only verification block calls `dump_bpf_session_entries`.
4. `bpf_map_get_next_key` writes raw key bytes into `next_key_bytes: Vec<u8>`.
5. The code casts `next_key_bytes.as_ptr()` to `*const UserspaceSessionMapKey` and calls `core::ptr::read`.
6. `Vec<u8>` guarantees byte alignment only; `UserspaceSessionMapKey` has `u16` fields under `repr(C)`, so `ptr::read` has an alignment precondition the buffer need not satisfy.
7. If the allocation address is not suitably aligned for the struct, the debug dump executes undefined behavior before or while logging the key.

Refutation attempt:

I checked the only observed call site in `poll_descriptor/mod.rs`; it is gated by `if cfg!(feature = "debug-log")`, so this is not reachable in the default hot path. I also checked the map value side: the userspace session map stores a `u8` value, so the adjacent `value = 0u8` lookup is not a size bug. The finding survived because the feature gate only narrows reachability; it does not satisfy `ptr::read` alignment requirements. The same codebase already uses `std::ptr::read_unaligned` for unaligned metadata in `userspace-dp/src/afxdp/frame/inspect.rs:1797-1801`, which confirms this alignment class is recognized elsewhere.

HPC/invariant check:

The affected path is debug-only and syscall-heavy, so replacing this with `read_unaligned` or a `MaybeUninit<UserspaceSessionMapKey>` buffer does not affect packet-path performance. The hot publish path continues to pass aligned typed keys by reference.

Why it matters:

Debug builds are used for packet-path diagnosis exactly when session creation is under scrutiny. Undefined behavior in the diagnostic dump can crash, mislog, or mask the bug being investigated.

Fix direction:

Use `core::ptr::read_unaligned(next_key_bytes.as_ptr().cast())`, or allocate an aligned `MaybeUninit<UserspaceSessionMapKey>` and pass its bytes to `bpf_map_get_next_key`. Add a regression test or Miri-targeted unit that exercises decoding from an intentionally unaligned byte slice.

Labels:

`memory-safety`, `unsafe`, `bpf-map`, `debug-log`, `test-gap`

Dedup note:

The dedup index contains several BPF/session and telemetry items, but I did not find a prior entry for this specific unaligned `ptr::read` in `bpf_map/metrics.rs`.

### Finding 2

### C175-HC-031

Title: Several hot-path benchmark "gates" are observational and do not fail on regression

Severity: Medium

Confidence: High

Source batch: A1-b1

Evidence:

`userspace-dp/benches/tx_kick_latency.rs:24-32` documents a concrete p99 gate:

```rust
// Gate: p99 per-call overhead ≤ 60 ns on the userspace cluster VM
// (VDSO-confirmed monotonic_nanos path). Plan §3.10 R1 correction
// — the earlier 25 ns gate only covered the atomic fast-path; 45 ns
// derivation + 15 ns jitter headroom ≈ 60 ns.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
```

`userspace-dp/benches/session_table.rs:32-38` documents pass criteria, but the file only registers Criterion benchmarks:

```rust
// Pass criterion: slab shape must NOT regress on the dominant
// slow-path lookups (reverse_nat, alias). Small regressions on
// `lookup_forward` (<10ns, due to slab indirection) and
// `owner_rg_export` (~2×, on a rare HA-failover path) are
// accepted in exchange for the secondary-index payload
// reduction (50-byte Key → 4-byte u32).
```

`userspace-dp/benches/snat_allocator.rs:684-699` prints speedup and failure percentages without enforcing a threshold:

```rust
println!(
    "{:>2}  {:>13.0} {:>13.0} {:>6.2}x  | {:>7} {:>7} {:>8}            | {:>7} {:>7} {:>8}           | {:.1}/{:.1}",
    m,
    cur.allocs_per_sec,
    new.allocs_per_sec,
    speedup,
    cur.p50,
    cur.p99,
    cur.p999,
    new.p50,
    new.p99,
    new.p999,
```

Trace:

1. `tx_kick_latency.rs` and `session_table.rs` run under Criterion.
2. Criterion reports measurements, but this code does not compare observed p99/speedup/regression values against the documented thresholds.
3. `snat_allocator.rs` uses a custom `main`, but its loop prints metrics and never calls `std::process::exit(1)` or panics when speedup/failure/latency is outside an acceptance band.
4. A CI job that treats a zero exit status as success will pass even when the documented hot-path gate fails numerically.

Refutation attempt:

I compared this with `prefix_set_lookup.rs`, which does enforce its threshold by exiting nonzero when p95 exceeds the limit. I also searched the assigned bench files for `exit`, `panic`, and assertion-style gates; the non-prefix benches have comments and printouts, not machine-enforced acceptance logic.

HPC/invariant check:

The affected invariants are p99 TX-kick instrumentation overhead, session-table lookup/churn regression bounds, and SNAT allocation contention scaling. These are exactly the kinds of hot-path regressions that need deterministic pass/fail gates because small per-packet overheads amplify at line rate.

Why it matters:

Performance gates that only print results are easy to miss in automated review, especially in a campaign built around no per-packet allocation and bounded hot-path work. A regression can ship with a green benchmark job unless a human manually interprets every number.

Fix direction:

Convert each documented gate into a machine-enforced check. For Criterion benches, either add a custom harness that computes the relevant statistic and exits nonzero, or add a CI parser with explicit thresholds checked into the repo. For `snat_allocator.rs`, define per-profile/M minimum speedup or maximum latency/failure envelopes and fail the process when violated.

Labels:

performance, test-coverage, hpc

Dedup note:

The prior reports mention missing tests for host-inbound, reject logging, and screen rate limiting, but not non-enforced A1 benchmark gates.

### C175-HC-032

Title: SNAT allocator contention bench is stale against the production allocator it is supposed to gate

Severity: Medium

Confidence: High

Source batch: A1-b1

Evidence:

`userspace-dp/benches/snat_allocator.rs:23-31` still frames the bench as a current-vs-proposed merge gate:

```rust
// This bench is the REQUIRED merge gate: it answers the PLAN-KILL
// question "is the global mutex a measurable bottleneck at the loss
// cluster's 6-worker scale?" by re-implementing BOTH shapes side by
// side (the production allocator is `pub(crate)` in a bin crate, so we
// re-implement the hot-path shapes here — same pattern as
// benches/session_table.rs / benches/tx_kick_latency.rs) and driving
// them under M = {1,2,4,6,8} threads across the four AGY-5 stress
// profiles: (a) uniform low occupancy, (b) 85-98% occupancy, (c) 80/20
```

`userspace-dp/benches/snat_allocator.rs:314-329` models the proposed allocator with an atomic cap reservation and a map insert that does not perform the production reuse/exact-cap sequence:

```rust
fn allocate(&self, flow: FlowKey) -> Option<Translated> {
    // Global cap: reserve, roll back on any failure (plan F4).
    if self.live_count.fetch_add(1, Ordering::Relaxed) >= self.max_tracked {
        self.live_count.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    let addr = addr_for(flow.src_ip, self.num_addrs);
    let Some(off) = self.bitmaps[addr].claim() else {
        self.live_count.fetch_sub(1, Ordering::Relaxed);
        return None;
    };
    // TINY critical section: just the map insert.
    {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(flow, (addr, off));
```

Contract read, `userspace-dp/src/nat/allocator.rs:3-15`, shows production at the reviewed base is already the Phase-1 lock-free design:

```rust
// #2852 Phase 1 (lock-free port claim): the port-ownership state is no
// longer serialized behind the single `Mutex<PortAllocatorLiveState>`.
// Per-pool-address occupancy is an atomic bitmap (`AddressOccupancy`,
// `Vec<AtomicU64>` + an atomic fresh-port cursor); a CAS on the bit IS the
// port-ownership token (a set bit cannot be re-claimed), replacing the
// pre-#2852 `owner_by_translated` / `addr_index_by_translated` maps and the
// per-address `next_port_offset_by_addr` cursor. The port CLAIM (the
// contended hot path in `allocate_translation`) is therefore lock-free: a
// non-persistent new flow claims its port with zero global-mutex contention
```

Contract read, `userspace-dp/src/nat/allocator.rs:24-31`, explicitly says the microbench's atomic cap model is not the production invariant:

```rust
// F4 (global tracked-flow cap): kept EXACT with no overshoot. The cap is
// `live_by_flow.len()` re-checked under the tiny insert mutex, where the map
// length is authoritative — so it never overshoots and a tiny pool near
// capacity is NOT falsely exhausted. This is strictly better than the
// microbench's atomic `fetch_add`-reserve model (which surfaced an M-in-
// flight overshoot on tiny pools): that overshoot only exists when the cap
// is checked OUTSIDE any lock (the Phase-2 sharded world); Phase 1 keeps the
// maps under one mutex, so the exact `len()` check is available and used.
```

Trace:

1. A reviewer or CI runner executes `snat_allocator.rs` to assess the required #2852 contention gate.
2. The benchmark labels `CurrentAllocator` as the current single-global-mutex shape and `ProposedAllocator` as the Phase-1 bitmap shape.
3. At this base SHA, production `PortAllocator::allocate_translation` has already moved to lock-free port claim and retained the map mutex for reuse/exact-cap insertion.
4. The bench therefore measures a retired historical implementation against a simplified proposal, not the current production allocator.
5. A future regression in the actual exact-cap, reuse, GC, or per-address recycle behavior can escape this gate because those production invariants are absent or explicitly different in the bench model.

Refutation attempt:

I checked the production allocator contract instead of relying on the bench comments. The production file references this bench as historical proof and then states that the microbench's atomic `fetch_add` cap overshoot is not the Phase-1 production design. That confirms the stale-model issue rather than refuting it.

HPC/invariant check:

The relevant hot-path invariant is "atomic bitmap claim is the ownership token, but flow reuse and exact global cap are serialized under the retained map mutex." The bench's `ProposedAllocator` keeps the bitmap-token part but changes the cap/reuse invariant, so its contention numbers are no longer a faithful proxy for the production packet path.

Why it matters:

This file is described as a required merge gate for a high-rate SNAT allocation path. A stale performance gate can drive the wrong engineering decision or miss a regression in the allocator that actually ships.

Fix direction:

Update the bench to model the current production Phase-1 allocator: bitmap claim, map-mutex reuse check, exact `live_by_flow.len()` cap check, rollback/free on duplicate or cap pressure, and the current recycle behavior. If direct bench access to `PortAllocator` remains blocked by crate shape, add an internal bench module or a narrow test-only adapter instead of maintaining a divergent copy. Move the historical pre-Phase-1 comparison to a research-only benchmark.

Labels:

performance, test-coverage, nat, hpc

Dedup note:

The dedup index has NAT findings for static NAT shadowing and config/application validation, but not stale SNAT allocator benchmark drift.

### F2

### C175-HC-033

Title: Deterministic NAPT64 accepts IPv6 subscribers outside the configured subscriber prefix

Severity: Medium

Confidence: High

Source batch: A2-b1

Evidence:

The wire contract carries both the IPv6 deterministic prefix length and the subscriber-CIDR base:

```rust
userspace-dp/src/protocol/nat.rs:351
    #[serde(rename = "deterministic_host_prefix_len", default)]
    pub deterministic_host_prefix_len: u8,
    /// #4559: IPv6 subscriber-CIDR network base (canonical string). Empty => not
    /// a deterministic NAPT64 pool. Parsed to the 16-octet base the allocator
    /// derives the subscriber word from and reverses against.
    #[serde(rename = "deterministic_host_base_v6", default)]
    pub deterministic_host_base_v6: String,
```

The allocator derives the subscriber index from only the selected 32-bit word. It reads no prefix bytes before `off` from `src`:

```rust
userspace-dp/src/nat/allocator.rs:297
    let off = deterministic_v6_word_offset(params.host_prefix_len);
    let src_octets = src.octets();
    let src_word = u32::from_be_bytes([
        src_octets[off],
        src_octets[off + 1],
        src_octets[off + 2],
        src_octets[off + 3],
    ]);
```

The only membership checks are `src_word >= base_word` and `sub_idx < host_count`, so a different /32 or /64 with the same subscriber word is accepted:

```rust
userspace-dp/src/nat/allocator.rs:311
    if src_word < base_word {
        return None;
    }
    let sub_idx = src_word - base_word;
    if sub_idx >= params.host_count {
        return None;
    }
    let ip_idx = (sub_idx / bpi) as usize;
```

The NAT64 permit path immediately uses this deterministic allocator when present; there is no earlier source-prefix guard in the batch code:

```rust
userspace-dp/src/nat64.rs:966
        if let Some(det) = prefix.deterministic_v6 {
            return allocate_nat64_pool_port_deterministic_v6(
                &prefix.port_allocator,
                flow,
                &prefix.pool_v4,
                det,
                src_v6,
            );
```

Trace:

1. Configure deterministic NAPT64 with `deterministic_host_base_v6 = 2001:db8::`, `deterministic_host_prefix_len = 32`, block size 512, blocks-per-IP 126, and four pool addresses. This matches the existing tests' setup.
2. A permitted source outside that prefix, for example `2001:db9:0:5::`, sends to a NAT64 synthetic destination under the configured /96 prefix.
3. `classify_ipv6_dest` matches only the destination NAT64 prefix and returns `MatchReady`.
4. `allocate_source` enters the deterministic branch and passes `src_v6 = 2001:db9:0:5::` to `allocate_nat64_pool_port_deterministic_v6`.
5. `deterministic_indices_v6` uses offset 4 for /32. Both `2001:db8:0:5::` and `2001:db9:0:5::` have `src_octets[4..8] == 0x00000005`, while `params.host_base[4..8] == 0x00000000`.
6. The computed `sub_idx` is 5, within `host_count`, so the packet receives the deterministic block for subscriber index 5.
7. `reverse_deterministic_v6` reconstructs the subscriber from `params.host_base` plus word 5, producing `2001:db8:0:5::`, not the actual outside-prefix source. The audit/reverse mapping now lies about the subscriber prefix.

Refutation attempt:

- Checked `build_deterministic_v6` in `userspace-dp/src/nat64.rs:633-654`; it validates supported prefix lengths and parses the base, but does not install a predicate that source addresses must match the configured base prefix bytes.
- Checked `Nat64State::allocate_source` in `userspace-dp/src/nat64.rs:940-975` and `allocate_nat64_pool_port_deterministic_v6` in `userspace-dp/src/nat/source.rs:888-899`; neither checks `src_v6` prefix membership before invoking the allocator.
- Checked `reverse_deterministic_v6` in `userspace-dp/src/nat/allocator.rs:323-368`; it explicitly reconstructs from `params.host_base`, confirming that accepted wrong-prefix sources are later attributed to the configured base prefix.
- Checked tests in `userspace-dp/src/nat64_tests.rs:70-177` and `userspace-dp/src/nat/tests_pool.rs:3534-3651`; coverage asserts in-prefix allocation, unsupported prefix-length fallback, and word-out-of-range fail-closed behavior, but not wrong-prefix/same-word fail-closed behavior.
- Dedup checked: this is not F-038-013 deterministic NAT `/0` host-count arithmetic, not the NAT64 /96 destination-prefix validation issue, not NAT64 missing port/ICMP BIB translation, and not the non-first fragment key collision. This root cause is runtime source-prefix membership for deterministic IPv6 subscriber selection.

HPC/invariant check:

The fix is O(1) on the hot path: compare the prefix bytes before the subscriber word (`src_octets[..off] == params.host_base[..off]`) before deriving `src_word`, where `off` is 4 for /32 and 8 for /64. It adds no allocation, no lock, and no allocator contention. The existing `sub_idx < host_count` invariant should remain, and fail-closed should return `DeterministicSubscriberOutOfRange`.

Why it matters:

Deterministic CGN/NAPT64 is used specifically because `(external IPv4, port)` must map back to the correct subscriber prefix without per-flow logs. With the current logic, a host from another IPv6 prefix can consume the fixed block assigned to an in-prefix subscriber that shares the same 32-bit subscriber word. Reverse audit then reports the configured base prefix subscriber, not the actual source, and port-block exhaustion or attribution can be shifted across tenants or VRFs when policy permits traffic to the NAT64 prefix.

Fix direction:

In `deterministic_indices_v6`, reject sources whose prefix bytes before the subscriber word differ from `params.host_base`. Add red tests for both supported prefix lengths:

- `/32`: base `2001:db8::`, in-range word 5, source `2001:db9:0:5::` must fail closed and must not claim a port.
- `/64`: base `2001:db8::`, in-range word 7, source with different first 64 bits but the same word at octets 8..12 must fail closed.

Also consider validating that the configured base is canonical for its advertised subscriber prefix when building `DeterministicV6`, so reverse mapping and forward membership use the same normalized base.

Labels:

nat64, deterministic-napt64, cgnat, allocator, audit, correctness

Dedup note:

Distinct from the deduped deterministic NAT `/0` Go host-count bug (F-038-013), NAT64 destination-prefix `/96` validation, NAT64 BIB port/ICMP translation gaps, and NAT64 fragment cache collision. This is a Rust dataplane deterministic-NAPT64 source-prefix membership bug.
### 2. Static NAT block local-address registration publishes only the network base

### C175-HC-034

Title: `ValidatePercent` accepts `NaN`, letting CoS `guarantee-rate` poison userspace snapshot publish

Severity: Medium

Confidence: High

Source batch: A3-b4

Evidence:

`pkg/config/schema_validators.go:132-141` accepts any successfully parsed float and never rejects `NaN` or infinity:

```go
func ValidatePercent(min, max float64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected percent %.0f..%.0f)", min, max)
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("not a number: %q", raw)
		}
		if v < min || v > max {
```

`pkg/config/schema_cos.go:336-344` wires that validator to the CoS oversubscription guarantee fraction:

```go
			"guarantee-rate": {
				desc:          "Fraction of the shaping-rate guaranteed to each exact class before proportional sharing (0..1)",
				args:          1,
				placeholder:   "<fraction>",
				valueType:     ValuePercent,
				valueDesc:     "Guaranteed fraction of the shaping-rate in the range 0..1 (e.g. 0.7)",
				valueExamples: []string{"0.5", "0.7", "1"},
				validator:     ValidatePercent(0, 1),
			},
```

`pkg/config/compiler_class_of_service.go:565-574` parses the same value and clamps only with comparisons, which `NaN` bypasses:

```go
		if len(oversubNode.Keys) >= 2 && oversubNode.Keys[1] == "guarantee-rate" {
			unit.OversubscriptionPolicy = "guarantee-rate"
			if len(oversubNode.Keys) >= 3 {
				if f, err := strconv.ParseFloat(oversubNode.Keys[2], 64); err == nil {
					if f < 0 {
						f = 0
					} else if f > 1 {
						f = 1
					}
					unit.OversubscriptionGuaranteeFraction = f
```

`pkg/dataplane/userspace/process_control.go:84-92` preflights control requests with standard JSON marshaling, which rejects non-finite floats:

```go
	// Pre-flight size check (#2744). Serialize the request once and reject
	// it here if it would exceed the receiver's cap, so the operator sees
	// an actionable config error at apply time rather than a silent
	// control-socket EOF after the config is already committed. The most
	// common offender is a feed-heavy apply_snapshot whose inline feed
	// prefixes push the body past MaxControlRequestBytes.
	body, err := json.Marshal(&req)
	if err != nil {
		return ControlResponse{}, err
```

Trace:

`set class-of-service interfaces ge-0/0/0 unit 0 oversubscription-policy guarantee-rate NaN` reaches `ValidatePercent(0, 1)`. `strconv.ParseFloat("NaN", 64)` succeeds; comparisons against `NaN` are false, so the schema returns nil. The compiler stores `NaN` into `CoSInterfaceUnit.OversubscriptionGuaranteeFraction`; `pkg/dataplane/userspace/interfaces.go:296-297` copies it to the snapshot field `CoSOversubscriptionGuaranteeFraction`, declared as `float64` in `pkg/dataplane/userspace/protocol.go:287-291`. Applying the userspace snapshot then hits `json.Marshal(&req)` and fails with `json: unsupported value: NaN`.

Refutation attempt:

I checked `pkg/config/schema_validators_cos.go:121-126` and `pkg/config/schema_validators_cos.go:239-244`; the CoS-specific validators already reject `math.IsNaN`/`math.IsInf`, so this is localized to the generic `ValidatePercent` path. The existing `TestValidatePercent` in `pkg/config/schema_validate_test.go:715-725` covers in-range and out-of-range finite values but not `NaN`/`Inf`. The dedup index only had `G-5`, about missing `oversubscription-policy` schema coverage before this leaf existed; it did not cover non-finite numeric acceptance.

HPC/invariant check:

Not a per-packet hot-path issue in Go, but it can block snapshot publication. The data-plane contract should never carry non-finite floats across the Go/Rust JSON control boundary.

Why it matters:

A single schema-accepted CoS value can make commit/apply fail at userspace snapshot publish time instead of being rejected at commit-check with a precise leaf error. If a future transport or sanitizer allows the value through, the Rust selector currently tests `oversubscription_guarantee_fraction > 0.0`, which is false for `NaN`, silently disabling the requested guarantee-rate policy.

Fix direction:

Update `ValidatePercent` to reject `math.IsNaN(v)` and `math.IsInf(v, 0)` after parsing. Add tests for `NaN`, `+Inf`, and `-Inf`. Consider a defense-in-depth finite check before snapshot publication for any float fields exported over the userspace control protocol.

Labels:

`config-validation`, `cos`, `numeric-edge`, `userspace-publish`, `test-gap`

Dedup note:

Distinct from dedup `G-5`; this leaf is present in the current schema, but its generic percent validator has a non-finite value hole.
### Finding 3

### C175-HC-035

Title: DPD interval/threshold are closed-world keywords but still accept arbitrary strings and overflowing integers

Severity: Medium

Confidence: High

Source batch: A3-b4

Evidence:

`pkg/config/schema_security.go:978-984` models the DPD keywords as closed-world, but leaves the numeric arguments untyped and unvalidated:

```go
			"dead-peer-detection": {desc: "Dead peer detection", closedWorld: true, children: map[string]*schemaNode{
				"always-send":       {desc: "Send DPD probes regardless of traffic", children: nil},
				"optimized":         {desc: "Optimized DPD probing", children: nil},
				"probe-idle-tunnel": {desc: "Probe idle tunnels", children: nil},
				"interval":          {desc: "DPD probe interval in seconds (default 10)", args: 1, placeholder: "<seconds>", children: nil},
				"threshold":         {desc: "Failed-probe count before peer is dead (default 5)", args: 1, placeholder: "<count>", children: nil},
			}},
```

`pkg/config/compiler_ipsec.go:241-250` then parses the values with `Atoi` and silently ignores parse errors:

```go
		case "interval":
			if i+1 < len(keys) {
				if n, err := strconv.Atoi(keys[i+1]); err == nil {
					gw.DPDInterval = n
				}
				i++
			}
		case "threshold":
			if i+1 < len(keys) {
				if n, err := strconv.Atoi(keys[i+1]); err == nil {
```

`pkg/ipsec/ike.go:246-253` treats non-positive values as defaults, not as config errors:

```go
	delay := gw.DPDInterval
	if delay <= 0 {
		delay = 10
	}
	threshold := gw.DPDThreshold
	if threshold <= 0 {
		threshold = 5
	}
```

`pkg/ipsec/policy.go:147-151` renders only positive values, so an overflowed timeout can disappear:

```go
		if dpd.Delay > 0 {
			fmt.Fprintf(&b, "    dpd_delay = %ds\n", dpd.Delay)
		}
		if dpd.Timeout > 0 {
			fmt.Fprintf(&b, "    dpd_timeout = %ds\n", dpd.Timeout)
```

Trace:

An operator can commit `set security ike gateway gw1 dead-peer-detection interval banana` or an oversized value such as `interval 9223372036854775807 threshold 9223372036854775807`. The DPD subtree rejects unknown keywords but accepts any token after `interval`/`threshold` because those leaves only have `args: 1`. The compiler ignores `Atoi` errors, so a string falls back to the strongSwan defaults. A huge valid integer survives into `deriveDPD`, where `delay * threshold` is computed in Go `int`; overflow can produce a negative timeout, which the renderer then omits.

Refutation attempt:

I checked the closed-world DPD tests in `pkg/config/schema_closedworld_ipsec_4313_test.go:174-186`; they cover valid `interval 10` and `threshold 5`, plus unknown keyword rejection, but no invalid string, negative, zero, or overflow case. I also checked the dedup index: `F-038` covers the prior bare/interval-only DPD mode bug, not numeric validation or timeout overflow.

HPC/invariant check:

This is a config-apply and render-time invariant, not a packet hot-path issue. The invariant should be: DPD tuning that reaches strongSwan must be a finite, positive, bounded integer pair whose product cannot overflow the rendered timeout.

Why it matters:

DPD is the liveness mechanism that decides when an IPsec peer is dead. Accepting invalid values while rendering defaults or dropping `dpd_timeout` makes commit success diverge from the operator's HA/liveness intent.

Fix direction:

Add `valueType: ValueInteger` and bounded validators to both IKE-gateway and IPsec-gateway DPD `interval`/`threshold` leaves. Use lower bound `1` and an upper bound that also prevents `interval * threshold` overflow, or add a strict cross-field validator for the product. Add schema tests for bad strings, negative/zero, and overflow-sized values in both flat-set and hierarchical forms.

Labels:

`config-validation`, `ipsec`, `numeric-edge`, `fail-closed`, `test-gap`

Dedup note:

Distinct from dedup `F-038`, which is about DPD enable/mode semantics. This report is about untyped numeric leaves and arithmetic/rendering overflow after the closed-world fix.
### Finding 2

### C175-HC-036

Title: Dynamic-address `update-interval` and `hold-interval` accept non-numeric strings and silently fall back to runtime defaults.

Severity: Medium

Confidence: High

Source batch: A3-b3

Evidence:

`pkg/config/schema_security.go:1195-1200` (contract read)

```go
	"dynamic-address": {desc: "Dynamic address feeds", children: map[string]*schemaNode{
		"feed-server": {desc: "Feed server name", args: 1, placeholder: "<server-name>", children: map[string]*schemaNode{
			"url":             {desc: "Feed URL (takes precedence over hostname)", args: 1, placeholder: "<url>", children: nil},
			"hostname":        {desc: "Server hostname for building per-feed URLs", args: 1, scalar: true, placeholder: "<hostname>", children: nil},
			"update-interval": {desc: "Feed refresh interval in seconds (default 3600)", args: 1, placeholder: "<seconds>", children: nil},
			"hold-interval":   {desc: "Drop a feed's last-good snapshot to empty after N seconds of fetch failure; omit to retain last-good forever (default)", args: 1, placeholder: "<seconds>", children: nil},
```

Trace:

1. An operator configures `security dynamic-address feed-server threat hold-interval 2h` or `update-interval fast`, intending an explicit refresh/staleness policy.
2. The schema declares these leaves as untyped string arguments, not integer/range validators.
3. The compiler calls `strconv.Atoi` but ignores parse errors, leaving the struct field at zero.
4. Runtime feed application maps `UpdateInterval <= 0` to one hour and `HoldInterval <= 0` to retain forever.
5. The configured interval is silently ignored. For a feed used as an allowlist or scoped permit source, retaining stale data forever can leave outdated sources permitted longer than the operator configured; for any feed, refresh timing is not what commit accepted.

Refutation attempt:

I checked dynamic-address strict validators in `compiler_validate_strict_observability.go`; they validate endpoint emptiness and feed-name references, not interval syntax. Assigned tests exercise valid numeric interval values but do not test invalid strings or non-positive interval semantics.

HPC/invariant check:

Config validation only. Adding typed schema validators or compile-time `Atoi` errors does not affect feed fetch hot loops beyond rejecting invalid config before runtime.

Why it matters:

Dynamic-address feeds are security inputs. Accepting an invalid interval while silently substituting runtime defaults undermines operator intent and makes stale-feed behavior hard to audit.

Fix direction:

Add integer validators to the dynamic-address interval schema, with `update-interval > 0` and `hold-interval > 0` if present. Alternatively return compile errors on `Atoi` failure and non-positive explicit values. Add strict tests for invalid strings and zero/negative explicit intervals.

Labels:

`config-compiler`, `dynamic-address`, `numeric-validation`, `silent-default`, `tests`

Dedup note:

Distinct from prior dynamic-address empty/slash-only endpoint, undefined feed-name, and plaintext HTTP URL findings. This root cause is interval numeric parsing and silent runtime defaulting.

### C175-HC-037

Title: Inverted NAT destination-port ranges silently degrade to a single low port before strict validation

Severity: Medium

Confidence: High

Source batch: A3-b2

Evidence:

`pkg/config/compiler_nat.go:2147-2155` only expands a range when `high >= low`; otherwise it appends only `low` and leaves no invalid marker:

```go
2147				if i+2 < len(vals) && vals[i+1] == "to" {
2148					if high, err2 := parseCanonicalPort(vals[i+2]); err2 == nil && high >= low {
2149						ports = appendDNATPortRange(ports, low, high)
2150						i += 2
2151						continue
2152					}
2153				}
2154				ports = append(ports, low)
2155			}
```

The child/hierarchical shapes have the same fallback at `pkg/config/compiler_nat.go:2184-2199`:

```go
2184				// Hierarchical range: "20000 to 30000" → leaf Keys=["20000", "to", "30000"]
2185				if len(child.Keys) >= 3 && child.Keys[1] == "to" {
2186					if high, err2 := parseCanonicalPort(child.Keys[2]); err2 == nil && high >= low {
2187						ports = appendDNATPortRange(ports, low, high)
2188						continue
2189					}
2190				}
2191				// Sibling-node range: child[i]="20000", child[i+1]="to", child[i+2]="30000"
2192				if i+2 < len(m.Children) && m.Children[i+1].Name() == "to" {
2193					if high, err2 := parseCanonicalPort(m.Children[i+2].Name()); err2 == nil && high >= low {
2194						ports = appendDNATPortRange(ports, low, high)
2195						i += 2
2196						continue
2197					}
2198				}
2199				ports = append(ports, low)
```

The strict validator can only reject values that remain in `DestinationPorts` or `InvalidDestinationPorts`:

```go
378					for _, p := range rule.Match.DestinationPorts {
379						if p < 1 || p > 65535 {
380							return fmt.Errorf(
381								"%s-nat rule-set %q rule %q: match destination-port %d is out "+
382									"of range (1-65535); the rule would commit but the dataplane "+
383									"cannot install it as an L4 port match (the value wraps on a "+
384									"uint16 cast or collapses to the wildcard port, translating "+
385									"the wrong port or every port)",
386								kind, rs.Name, rule.Name, p)
```

Existing invalid-port tests cover zero, over-range, negative, nonnumeric, endpoint-over, and bracket-bad cases, but not reversed in-range ranges (`pkg/config/compiler_nat_match_dport_3446_test.go:63-68`).

Trace:

1. An operator sets `match destination-port 6000 to 5000` under source or destination NAT.
2. The flat-set shape reaches `parseDNATPortList` as `Keys=["destination-port","6000","to","5000"]`; the hierarchical child/sibling shapes follow the analogous paths.
3. `low=6000` parses, `high=5000` parses, but `high >= low` is false. The parser does not append the high endpoint, does not append an invalid token, and falls through to `ports = append(ports, low)`.
4. The strict validator later sees only `DestinationPorts=[6000]`, which is in range, and `InvalidDestinationPorts=[]`; commit succeeds.
5. The compiled NAT rule matches port 6000 instead of rejecting malformed `6000 to 5000` syntax. The same parser is used for source-NAT `match destination-port`, so both source and destination NAT are affected.

Refutation attempt:

I checked `validateNATMatchDestinationPortStrict` to see whether it reconstructs range order or preserves original tokens; it does not. It only scans numeric ports and invalid nonnumeric tokens already emitted by `parseDNATPortList`. I also checked the #3446/#3449 tests; they prove out-of-range endpoints survive validation and large ranges are bounded, but they do not cover an in-range reversed pair where both values are valid and the high endpoint is dropped before validation.

HPC/invariant check:

No hot-path atomic/cache invariant is involved. The relevant invariant is fail-closed grammar projection: invalid range ordering must survive into strict validation rather than being normalized into a different valid singleton.

Why it matters:

Malformed NAT port ranges become a different, commit-clean NAT match. For translation rules this can translate one port the operator did not mean as a singleton; for no-translate/off rules it can exempt only the low port instead of rejecting the invalid policy. Either way the candidate config no longer means what the operator wrote, and Junos-style `low to high` grammar should fail closed on reversed bounds.

Fix direction:

(concrete - the report is a remediation work-list)
Teach `parseDNATPortList` to preserve reversed ranges as invalid. Minimal change: when the `to` keyword is present and both endpoints parse but `high < low`, append a dedicated invalid token/string or append both endpoints plus a new `InvalidDestinationPortRanges` field that `validateNATMatchDestinationPortStrict` rejects. Add strict/lenient tests for DNAT and SNAT flat, child, and sibling AST shapes: `6000 to 5000` should reject at strict commit and warn on lenient load without installing a widened wildcard.

Labels:

(include vsrx-parity for parity issues)
`config-compiler`, `nat`, `fail-closed`, `numeric-edge-case`, `vsrx-parity`, `tests`

Dedup note:

(why this is not a restatement of any entry in the dedup index)
Prior #3446/#3449 findings cover nonnumeric/out-of-range ports and OOM from huge ranges. This finding is specific to an in-range but inverted range whose ordering information is lost before the strict validator runs.

### C175-HC-038

Title: Mixed NAT rule-set scope kinds are compiled as multiple OR-style rule-sets instead of being rejected or ANDed

Severity: Medium

Confidence: High

Source batch: A3-b2

Evidence:

`pkg/config/compiler_nat.go:1037-1045` says Junos allows one kind and claims mixed-kind input is captured so it is ANDed fail-closed:

```go
1037	//   - Child-leaf / hierarchical: one child per scope kind, each
1038	//     Keys=["interface","ge-0/0/1.0"] (with bracket lists collapsed onto the
1039	//     child's Keys, plus defensive orphan grandchildren — mirroring
1040	//     parseZoneList / firewallMatchValues).
1041	//
1042	// Junos restricts a single from/to clause to ONE kind; xpf accumulates
1043	// whatever is present so a hostile mixed-kind clause is captured (and AND-ed
1044	// fail-closed at match time) rather than silently dropped.
1045	func parseNATMatchScopes(node *Node) []natMatchScope {
```

`pkg/config/compiler_nat.go:1837-1846` actually turns each parsed scope into a separate source NAT rule-set:

```go
1837			// Expand Cartesian product of from-scopes × to-scopes (#3096).
1838			for _, fs := range fromScopes {
1839				for _, ts := range toScopes {
1840					rs := &NATRuleSet{
1841						Name:  rsInst.name,
1842						Rules: rules,
1843					}
1844					applyNATFromScope(rs, fs)
1845					applyNATToScope(rs, ts)
1846					sec.NAT.Source = append(sec.NAT.Source, rs)
```

The same expansion exists for DNAT and static NAT: `pkg/config/compiler_nat.go:2068-2075` and `pkg/config/compiler_nat.go:2518-2525`. Contract read: `pkg/config/schema_security.go:437-445`, `486-489`, and `550-553` declare `zone`, `interface`, and `routing-instance` as independent `multi: true` children, with no mutual-exclusion validator.

Trace:

1. An operator or loader provides:
   `set security nat source rule-set RS from zone trust`
   and
   `set security nat source rule-set RS from interface ge-0/0/1.0`.
2. The schema accepts both children because `from` declares separate `multi: true` leaves for `zone` and `interface`.
3. `collectNATScopes` appends both parsed scopes into `fromScopes`.
4. `compileNATSource` iterates `fromScopes x toScopes` and creates two typed `NATRuleSet` values with the same rules: one scoped by `FromZone=trust`, the other by `FromInterface=ge-0/0/1.0`.
5. The dataplane receives two alternative rule-sets, so traffic matching either scope can translate. This is OR expansion, not the comment's fail-closed conjunction, and it also does not match Junos' one-kind-per-clause reject.

Refutation attempt:

I checked the schema and prewalk contracts for a hidden mutual-exclusion gate. `schema_security.go` exposes all three scope kinds independently; `compiler_prewalk.go:238-248` explicitly says the old `validateNATRuleSetScopeAST` gate was removed; `README.md:532-542` documents Cartesian expansion and "exactly one" typed scope per expanded rule-set. The only DNAT-specific AST gate is `validateDNATRuleSetToScopeAST`, which rejects DNAT `to`, not mixed `from` scope kinds. Existing `compiler_nat_scope_3079_test.go` proves individual interface/RI scopes commit and are captured but has no mixed-kind reject or AND semantics test.

HPC/invariant check:

No per-packet/HPC primitive is involved in the Go compiler. The violated invariant is config-shape fail-closedness: a NAT rule-set side should be one scoped dimension, or the compiler/runtime must model a true conjunction. The current projection widens it into multiple alternatives.

Why it matters:

NAT scope controls where source NAT, destination NAT, and static NAT apply. Silently widening a mixed `zone + interface` or `zone + routing-instance` clause can translate traffic outside the operator's intended ingress/egress boundary. For DNAT/static NAT that can expose translations on an unintended ingress context; for source NAT it can NAT flows from the zone on every interface or from the interface in every zone/RI.

Fix direction:

(concrete - the report is a remediation work-list)
Add a strict AST validator for NAT rule-set `from` / source `to` / static `from` clauses that rejects more than one scope kind per clause, with lenient warning behavior for persisted configs. Alternatively, introduce a typed conjunctive scope model and wire it through snapshot/runtime, but that is a larger feature. Add tests for mixed `zone+interface`, `zone+routing-instance`, and `interface+routing-instance` across source, destination, static, and source `to`.

Labels:

(include vsrx-parity for parity issues)
`config-compiler`, `nat`, `fail-closed`, `vsrx-parity`, `tests`

Dedup note:

(why this is not a restatement of any entry in the dedup index)
Prior #3096/#3079 entries cover interface/RI scopes being silently dropped or later accepted/captured, and prior NAT precedence findings cover ordering among separate rule-sets. This finding is a different root cause: mixed scope kinds in a single Junos clause are accepted and OR-expanded into multiple typed rule-sets despite a local comment claiming fail-closed AND semantics.

### Finding 2

### C175-HC-039

Title: Operational completions still panic on nil routing-instance and redundancy-group entries

Severity: Medium

Confidence: High

Source batch: A3-b1

Evidence:

`pkg/cmdtree/tree.go:249` dereferences every routing-instance pointer while completing `show route table`:

```go
"table": {Desc: "Show routes in named routing table", DynamicFn: func(cfg *config.Config) []string {
	if cfg == nil {
		return []string{"inet.0", "inet6.0"}
	}
	// Include main tables plus per-instance tables.
	names := []string{"inet.0", "inet6.0"}
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name+".inet.0", ri.Name+".inet6.0")
```

`pkg/cmdtree/tree.go:820` does the same for redundancy groups:

```go
"redundancy-group": {Desc: "Failover a specific redundancy group", DynamicFn: func(cfg *config.Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Chassis.Cluster.RedundancyGroups))
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		names = append(names, fmt.Sprintf("%d", rg.ID))
	}
```

`pkg/config/compiler_validate_warn_nil_3494_test.go:90` documents both nil shapes as tolerated:

```go
// derefs routing-instances, interface configs + units, redundancy-groups,
// and flow-monitoring template maps -- all nil-tolerant pointer
// slices/maps. Inject a nil element into each so reverting any added guard
// panics.
cfg.RoutingInstances = []*RoutingInstanceConfig{
	{Name: "ri1", Interfaces: []string{"ge-0/0/9.0"}}, // unknown iface -> warning
	nil, // #3494: nil routing-instance
```

Trace:

1. Tolerant load or HA-sync can produce `cfg.RoutingInstances` or `cfg.Chassis.Cluster.RedundancyGroups` slices containing nil entries; config validation warning tests explicitly treat these as nil-tolerant shapes.
2. The operational tree is the SSOT for local CLI, remote CLI, and gRPC completion/help.
3. A user requests completions for any affected path, for example `show route table <TAB>`, `show route instance <TAB>`, `test routing instance <TAB>`, `ping routing-instance <TAB>`, `traceroute routing-instance <TAB>`, `request chassis cluster failover redundancy-group <TAB>`, or `request chassis cluster failover reset redundancy-group <TAB>`.
4. `CompleteFromTree` or `CompleteFromTreeWithDesc` invokes the node's DynamicFn through `DynamicValues`.
5. The DynamicFn dereferences `ri.Name` or `rg.ID` without a nil guard and panics. This makes malformed but tolerated config able to take down completion/help handling instead of skipping the bad slot.

Refutation attempt:

I checked whether this was already covered by the existing cmdtree nil tests. `completion_nil_3476_test.go` only covers nil zone-pair/policy entries under `show security policies`; `completion_nil_3493_test.go` only covers nil security zone map values under `monitor security packet-drop`. I checked neighboring config code: strict/warning validators and the userspace route builder skip nil routing instances/redundancy groups, confirming the intended contract is nil-tolerant. The cmdtree dynamic functions above do not share those guards. The finding survived.

HPC/invariant check:

Not a packet hot path. The invariant is operational-surface robustness under tolerated malformed config: completion must perform bounded iteration and skip nil slots.

Why it matters:

Completion and help are reachable from operator surfaces. A malformed synced or persisted config can turn a non-mutating completion request into a process panic, breaking troubleshooting during exactly the kind of recovery scenario tolerant load is meant to support.

Fix direction:

Add small helper functions for routing-instance names/table names and redundancy-group ids that skip nil entries, then use them across all dynamic completion nodes. Add tests mirroring #3494 for `show route table`, `ping routing-instance`, `traceroute routing-instance`, and both redundancy-group completion paths.

Labels:

cmdtree, malformed-config, completion, panic, tolerant-load

Dedup note:

The dedup index and current batch tests already cover nil policy and nil zone completion panics. This is not the same root cause: it is the still-unguarded routing-instance and redundancy-group pointer slices.

### C175-HC-040

Title: Packed hierarchical `node 0 priority <v>;` bypasses the chassis priority range gate but is still compiled into HA/VRRP state

Severity: Medium

Confidence: High

Source batch: A3-b4

Evidence:

`pkg/config/schema_chassis.go:190-197` correctly intends to reject node priorities outside `1..254`:

```go
				"priority": {
					desc:          "Node priority for primary election (1..254; higher wins)",
					args:          1,
					valueType:     ValueInteger,
					valueDesc:     "Node priority for primary election (1..254; higher wins)",
					valueExamples: []string{"100", "200", "254"},
					validator:     ValidateInteger(1, 254),
					children:      nil,
```

`pkg/config/schema_validate_chassis_test.go:217-226` documents the bypass for the common compact hierarchical shape:

```go
// Documented contract pin (NOT an endorsement): the hierarchical packed
// one-liner `node 0 priority <v>;` carries the priority INSIDE the
// instance node's own Keys. The PR-1 walker's compiler-faithful rule
// consumes only the identity tokens of a named-instance container and
// ignores the rest, so this shape bypasses the typed-leaf gate even
// though compileChassis happens to read the inline tokens. Rejecting it
// would require a new walker feature (out of PR-2 scope; see
// docs/config-schema.md). The flat-set form of the same statement IS
```

`pkg/config/compiler_system.go:1713-1722` proves the compiler reads that inline `priority` tail:

```go
				// Look for "priority" in inline keys or children
				for i := 2; i < len(child.Keys)-1; i++ {
					if child.Keys[i] == "priority" {
						if n, err := strconv.Atoi(child.Keys[i+1]); err == nil {
							rg.NodePriorities[nodeID] = n
						}
					}
				}
				if priNode := child.FindChild("priority"); priNode != nil {
					if v := nodeVal(priNode); v != "" {
```

`pkg/vrrp/instance.go:1932-1938` later narrows the configured priority onto the VRRP wire:

```go
	// Send IPv4 advertisement if we have any IPv4 VIPs.
	if len(v4Addrs) > 0 {
		maxAdvert := uint16(vi.cfg.AdvertiseInterval / 10) // milliseconds → centiseconds
		pkt := &VRRPPacket{
			VRID:         uint8(vi.cfg.GroupID),
			Priority:     uint8(priority),
			MaxAdvertInt: maxAdvert,
```

Trace:

In hierarchical Junos-style config, `node 0 priority 999;` is represented as the `node` instance's own key tail. The schema walker consumes only the identity tokens and intentionally ignores remaining key tokens, so `SchemaValidate` accepts the batch test's `priority 999` case. The compiler then scans `child.Keys` and stores `999` into `RedundancyGroup.NodePriorities`. `pkg/cluster/group_state.go:25-28` copies that into `LocalPriority`; the control-link election compares that integer directly via `EffectivePriority`, while VRRP advert generation casts it to `uint8`. That means the same committed priority can be treated as `999` by the private election and `231` on the VRRP wire.

Refutation attempt:

I checked the strict post-compile chassis gate in `pkg/config/compiler_validate_strict_chassis.go:47-80`; it validates redundancy-group count and ID width only, not per-node priority. The targeted test run confirms `TestSchemaValidate_ChassisCluster_PackedOneLinerBypassesGate` still passes. Dedup searches for `PackedOneLiner`, `node 0 priority`, `priority 999`, and chassis priority did not find a prior campaign finding.

HPC/invariant check:

This is a commit-time invariant with a runtime HA impact. VRRP advertisement generation is hot enough that it should not be asked to clamp or diagnose schema mistakes; commit/schema validation should ensure `1..254` before state reaches HA and VRRP.

Why it matters:

The flat-set form is range-checked, but the compact hierarchical form is accepted and compiled. That creates a dual-shape behavior split and can make HA control-link election disagree with the VRRP wire priority.

Fix direction:

Add a walker path for named-instance key tails that can validate recognized leaf/value pairs after identity consumption, or special-case chassis `redundancy-group node` until the generic walker supports it. Add strict post-compile validation that every `RedundancyGroup.NodePriorities` entry is `1..254`, so both flat-set and hierarchical shapes fail closed. Flip the current contract-pin test into a rejection test once the walker/strict gate is fixed.

Labels:

`config-validation`, `schema-walk`, `chassis-ha`, `dual-shape`, `numeric-edge`, `test-gap`

Dedup note:

No matching dedup entry found. This is related to the in-tree documented limitation, but it is not listed as a prior campaign finding.

### C175-HC-041

Title: Repeated hierarchical `address-set <name> { ... }` blocks replace instead of merge.

Severity: Medium

Confidence: High

Source batch: A3-b3

Evidence:

`pkg/config/compiler_security_addressbook.go:231-239`

```go
func parseAddressBookEntries(node *Node, ab *AddressBook) {
	for _, child := range node.Children {
		switch child.Name() {
		case "address":
			// A single Junos `address <name>` may render as MULTIPLE sibling
			// AST nodes (flat-set: one leaf per sub-stanza) or as a single
			// hierarchical block, and the sub-stanzas (prefix, description,
			// ...) arrive in arbitrary order. Merge by name so a described
```

Trace:

1. A hierarchical loaded config contains two same-name address-set blocks, for example one generated fragment with `address a1;` and another with `address a2;`.
2. The parser appends both blocks as sibling `address-set` nodes.
3. `parseAddressBookEntries` explicitly merges same-name `address` nodes by looking up an existing `Address`.
4. The adjacent `address-set` path does not look up an existing set. It creates a fresh `AddressSet` for each sibling block.
5. The final assignment `ab.AddressSets[as.Name] = as` overwrites the earlier block, leaving only the last block's members.
6. Strict validators see a defined, resolving set and cannot tell that earlier members were overwritten.

Refutation attempt:

The nearby `address` path shows the compiler already had to handle repeated sibling nodes for dual AST shapes. I found nested address-set tests for a single block with multiple child statements and flat-set tests with repeated single-member set commands, but not repeated same-name hierarchical blocks. No later validator can reconstruct overwritten members from the compiled map.

HPC/invariant check:

Cold compiler map merge only. Fixing this by merging into an existing `AddressSet` is bounded by config size and does not affect packet-path invariants.

Why it matters:

Hierarchical imports and generated snippets can split one logical address set across repeated blocks. Dropping earlier members silently narrows the set and can make deny policies miss intended sources/destinations.

Fix direction:

Mirror the `address` merge pattern for `address-set`: look up/create `ab.AddressSets[name]`, then append/merge members from each child. Add tests for repeated same-name global and zone-local address-set blocks, including nested set members.

Labels:

`config-compiler`, `address-book`, `dual-ast`, `silent-drop`, `tests`

Dedup note:

Distinct from prior duplicate policy/match/then and host-inbound duplicate block findings. This is an address-book address-set overwrite in `parseAddressBookEntries`.

### A3-b3-04

### C175-HC-042

Title: `master-password` encryption does not cover rollback, rescue, or archive text copies of full configs

Severity: Medium

Confidence: High

Source batch: A4-b1

Evidence:

`pkg/configstore/store_commit.go:715-728` writes rollback text slots from `entry.Config.Format()` with no encryption branch:

```go
for i, entry := range entries {
	path := s.rollbackPath(i + 1)
	data := entry.Config.Format()
	var err error
	// Owner-only 0600 (#4056): the rollback slots (xpf.conf.N) hold the
	// full committed config TEXT, which always includes cleartext secret
	// leaves (IKE PSK, auth keys, SNMP community) — Format() does not
	// redact or encrypt. World-readable 0644 exposed every firewall
```

`pkg/configstore/store_persist.go:516-530` writes `rescue.conf` from cleartext `Format()`:

```go
// SaveRescueConfig saves the active config as rescue configuration.
func (s *Store) SaveRescueConfig() error {
	s.mu.RLock()
	data := s.active.Format()
	s.mu.RUnlock()

	path := s.rescuePath()
	// DurableState (#1894): the rescue config is the operator's
```

Trace:

1. Operator configures a master-password PRF, so DB `active.json` bodies route through `maybeEncryptTreeJSON`.
2. The same active or prior config is copied to rollback text slots during commit via `entry.Config.Format()`.
3. `ArchiveConfig` and auto-archive write `s.active.Format()` through `writeArchive`; `SaveRescueConfig` writes `s.active.Format()` through `fsatomic.WriteFileDurable`.
4. These files are 0600/0700, but their contents are full cleartext config text including secret leaves.
5. A disk backup, root-equivalent local reader, or post-incident collection that includes `xpf.conf.N`, archive files, or `rescue.conf` still receives cleartext secrets even though the primary DB body is encrypted.

Refutation attempt:

Not required for Medium. I checked `file_perms_4056_test.go`: it intentionally proves these files contain cleartext secrets and are owner-only. That confirms the current mitigation is Unix permissions, not master-password encryption. I also checked the redacted display methods; they protect view/export surfaces but are not used for persistence because rollback/rescue need restorable secrets.

HPC/invariant check:

Crypto-at-rest coverage invariant: enabling encryption for the active DB does not cover all durable full-config replicas. No per-packet/HPC issue.

Why it matters:

Operators enabling `system master-password` can reasonably expect full config-at-rest copies to be encrypted or explicitly excluded. Instead, several durable safety/history surfaces preserve cleartext secrets indefinitely under owner-only permissions.

Fix direction:

(concrete - the report is a remediation work-list)
Define the product contract. If master-password means config-at-rest encryption, add encrypted formats for rollback text history, rescue config, and archives, with restore/load support and migration. If those surfaces must remain plaintext for operational compatibility, expose that clearly in CLI/docs and add an operator setting to disable plaintext archive/rescue/rollback copies when master-password is set.

Labels:

(include vsrx-parity for parity issues)
crypto-at-rest, secrets, rollback, rescue, archive

Dedup note:

(why this is not a restatement of any entry in the dedup index)
Prior #4056-style findings were about world-readable file modes. This is a different root cause: cleartext full-config replicas remain outside the AES-GCM master-password envelope even after file modes are fixed.

### F6

### C175-HC-043

Title: Malformed AES-GCM nonce length can panic the config DB read path instead of returning an unreadable-DB error

Severity: Medium

Confidence: High

Source batch: A4-b1

Evidence:

`pkg/configstore/crypto.go:136-153` decodes the nonce and passes it directly to `gcm.Open` without checking `len(nonce) == gcm.NonceSize()`:

```go
nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
if err != nil {
	return nil, false, fmt.Errorf("decode nonce: %w", err)
}
ciphertext, err := base64.StdEncoding.DecodeString(env.Data)
if err != nil {
	return nil, false, fmt.Errorf("decode ciphertext: %w", err)
}

block, err := aes.NewCipher(key)
```

`pkg/configstore/crypto.go:149-156` then calls `Open`:

```go
gcm, err := cipher.NewGCM(block)
if err != nil {
	return nil, false, fmt.Errorf("create GCM: %w", err)
}
plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
if err != nil {
	return nil, false, fmt.Errorf("decrypt config tree: %w", err)
}
```

Trace:

1. `.configdb/active.json`, `confirm.json`, or another encrypted tree body contains an AES-GCM envelope with `nonce` base64-decoding successfully but to the wrong byte length.
2. `maybeDecryptTreeJSON` accepts the decoded nonce and constructs an AES-GCM AEAD.
3. Go's `cipher.AEAD` contract requires the nonce passed to `Open` to be exactly `NonceSize()` bytes.
4. The configstore code does not convert that malformed envelope into an error before calling `Open`.
5. A malformed on-disk DB can crash the daemon during `Store.Load`/`ReadConfirm` instead of returning an error tagged by the unreadable-DB path.

Refutation attempt:

Not required for Medium. I still checked `db_test.go` and `plaintext_downgrade_warn_4579_test.go`: they cover happy-path encryption/decryption and plaintext downgrade warnings, but no malformed nonce-length case.

HPC/invariant check:

Crypto input-validation invariant: serialized envelope fields must be length-checked before AEAD operations. No hot-path/HPC issue.

Why it matters:

An at-rest corruption or local tamper of a 0600 DB file should fail closed as an unreadable config DB. A panic turns a recoverable/configurable boot failure into a daemon crash loop and bypasses the existing `ErrConfigDBUnreadable` control flow.

Fix direction:

(concrete - the report is a remediation work-list)
After `cipher.NewGCM`, check `len(nonce) == gcm.NonceSize()` and return a normal error if not. Add malformed-envelope tests for wrong nonce length, malformed salt, and short ciphertext on active DB and confirm-state reads. If desired, wrap `maybeDecryptTreeJSON` with panic-proof tests to make sure no serialized envelope can panic load.

Labels:

(include vsrx-parity for parity issues)
crypto, AES-GCM, input-validation, crash-recovery

Dedup note:

(why this is not a restatement of any entry in the dedup index)
No dedup entry covers malformed AES-GCM envelope field length causing a panic in configstore.

### F4

### C175-HC-044

Title: Dual-active winner reaffirm event silently drops without the reconcile fallback

Severity: Medium

Confidence: High

Source batch: A5-b1

Evidence:

`pkg/cluster/election.go:331`

```go
			// Dual-active winner: state unchanged but emit ownership
			// reaffirm event so daemon can send GARPs to refresh
			// upstream ARP/NDP caches.
			if reason == "Dual-active: winner stays" {
				select {
				case m.eventCh <- ClusterEvent{
					GroupID:       rg.GroupID,
					OldState:      StatePrimary,
					NewState:      StatePrimary,
					DualActiveWin: true,
```

`pkg/cluster/election.go:339`

```go
					NewState:      StatePrimary,
					DualActiveWin: true,
				}:
				default:
				}
				m.history.Record(EventRG, rg.GroupID, "dual-active resolved: winner reaffirm")
			}
			continue
```

`pkg/cluster/manager.go:356`

```go
func (m *Manager) sendEvent(groupID int, oldState, newState NodeState, reason string) {
	select {
	case m.eventCh <- ClusterEvent{GroupID: groupID, OldState: oldState, NewState: newState}:
	default:
		slog.Warn("cluster: event channel full, dropping event",
			"rg", groupID, "old", oldState, "new", newState)
		if m.onEventDrop != nil {
			m.onEventDrop()
```

Minimal contract read: `pkg/daemon/daemon_ha.go:185`

```go
			// Dual-active winner reaffirm: no state change but send
			// GARPs to refresh upstream ARP/NDP caches after split-brain.
			if ev.DualActiveWin && noRethVRRP {
				d.scheduleDirectAnnounce(ev.GroupID, "dual-active-win")
				continue
			}
```

Trace:

1. In direct VIP mode (`noRethVRRP`), both nodes can transiently be primary after a partition or stale peer view.
2. Election resolves the local node as the dual-active winner with no state change, so the normal `oldState != rg.State` path and `sendEvent` are not used.
3. The special `DualActiveWin` event is sent with a local non-blocking `select`.
4. If `eventCh` is full, the default arm silently discards the only event that tells the daemon to call `scheduleDirectAnnounce`.
5. This path also bypasses `m.onEventDrop`, so the daemon's immediate reconcile fallback wired in `daemon_run.go` is not invoked.
6. The loser can demote while upstream ARP/NDP caches still point at the losing MAC; without the reaffirm GARP/NA, recovery can wait for cache aging or another unrelated event.

Refutation attempt:

I checked the normal cluster event path and the daemon wiring. `sendEvent` logs and calls `onEventDrop`, and the daemon wires that callback to `triggerReconcile`, but the dual-active reaffirm path does not call `sendEvent` or the callback. I also checked the dedup index for prior dual-active items; the matching prior issue is duplicate node-id/no-progress, not this event-loss path. The risk is conditional on a full 256-entry event channel, so this is not a steady-state correctness failure, but it is exactly the backpressure condition the normal path already treats as requiring immediate reconciliation.

HPC/invariant check:

HA convergence events that repair data-plane ownership after split-brain must be either delivered or converted into an immediate reconcile signal. The `DualActiveWin` no-state-change event currently violates the same event-drop invariant enforced by `sendEvent`.

Why it matters:

This is the event that refreshes upstream neighbor caches after dual-active resolution in direct VIP mode. Losing it can leave traffic blackholed even though cluster election has selected the correct owner.

Fix direction:

Route the `DualActiveWin` emission through a helper that shares `sendEvent`'s drop handling, or add the same warning and `m.onEventDrop()` call in the inline dual-active path. A focused test should fill `eventCh`, run the "winner stays" election case, and assert the drop callback fires.

Labels:

area:A5, batch:1, cluster, election, split-brain, direct-vip, event-loss, failover-convergence

Dedup note:

Not a duplicate of the prior duplicate-node-id dual-active no-progress finding. This is a distinct lossy notification path after the winner has already been selected.

### Finding 2

### C175-HC-045

Title: DHCP lease-change IPsec rebind path drops `swanctl` reload failures with no retry or health signal

Severity: Medium

Confidence: High

Source batch: A7-b1

Evidence:

The management-only DHCP lease callback skips the full apply path and calls `reapplyIPsecForLeaseChange`. That function serializes on `applySem` but only logs `d.ipsec.Apply` errors. The IPsec manager contract returns reload failures, and the DHCP-bound gateway contract says stale `local_addrs` prevents tunnel re-establishment.
Snippet read from `pkg/daemon/daemon_dhcp.go:130-138`:

```go
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		slog.Warn("IPsec: failed to acquire apply lock for DHCP lease re-render", "err", err)
		return
	}
	defer d.applySem.Release(1)
	slog.Info("DHCP address changed on IPsec-bound interface, re-rendering swanctl local_addrs")
	if err := d.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
		slog.Warn("failed to re-apply IPsec config after DHCP address change", "err", err)
```

Snippet read from `pkg/ipsec/policy.go:627-635`:

```go
// HasDHCPBoundGateway reports whether any IPsec gateway resolves its
// local bind address DYNAMICALLY from a DHCP-managed interface — i.e.
// the gateway sets external-interface, carries no explicit
// local-address (so PrepareConfig resolves local_addrs at apply time),
// and the referenced interface unit is DHCP/DHCPv6-managed. Such a
// gateway's swanctl local_addrs tracks the lease, so a runtime lease
// change (DHCP renew to a new address) must trigger a swanctl
// re-render; otherwise strongSwan keeps binding to the stale IP and the
```

`pkg/ipsec/manager.go:154-157` returns `m.reload()` errors. `pkg/daemon/ipsec_lease_rebind_test.go:64-66` explicitly treats a missing `swanctl` reload as harmless because the test only asserts the rendered file changed. `pkg/daemon/daemon_ipsec_apply_test.go:15-22` covers the commit path and proves normal `applyConfigLocked` now fails closed on IPsec apply errors, but that path is not used here.

Trace:

1. A DHCP renewal changes the address on a management-only interface, so `onDHCPAddressChange` takes the branch that refreshes management routes/DNS and skips full `applyConfig`.
2. The active config has an IPsec gateway whose `external-interface` is DHCP-bound and has no explicit `local-address`, so `HasDHCPBoundGateway` returns true.
3. `reapplyIPsecForLeaseChange` acquires `applySem` and calls `d.ipsec.Apply(ipsec.PrepareConfig(cfg))` directly.
4. `ipsec.Manager.Apply` writes the updated swanctl snippet and returns an error if `swanctl --load-all`/reload fails.
5. The lease-change path logs that error and returns; it does not mark a dirty/retry state, return an apply error, or surface health/metrics.
6. strongSwan may continue enforcing the old loaded `local_addrs`, so the tunnel can remain bound to the stale lease address until another lease event, config apply, or daemon restart happens to reload successfully.

Refutation attempt:

I verified the normal commit path is not affected: `daemon_apply.go:1333-1351` records an IPsec apply error and `daemon_ipsec_apply_test.go` asserts the commit fails. That does not refute this finding because the management-only DHCP callback deliberately bypasses full apply. I searched for retry/health latches around `reapplyIPsecForLeaseChange` and found none; the only test for this path asserts file re-render and documents that reload failure is ignored.

HPC/invariant check:

Runtime lease-driven rebind is an enforcement update, not just a config-file refresh. If the service reload fails, the daemon must keep a convergent retry/health signal until strongSwan has actually loaded the new `local_addrs`.

Why it matters:

A WAN or management uplink DHCP address change can leave IPsec down or bound to a stale source while the daemon reports only a log warning. Operators get no commit failure and no durable degraded signal for a tunnel that cannot re-establish.

Fix direction:

Make the DHCP rebind path converge like other runtime actuators: add an IPsec lease-rebind dirty flag and retry loop, or route this through a bounded apply/retry mechanism that records a health metric until `ipsec.Apply` succeeds. Add a seam test that injects an IPsec reload error on the lease path and asserts a retry/health/dirty state remains set instead of treating the failure as harmless.

Labels:

`area:A7-b1`, `daemon`, `dhcp`, `ipsec`, `lifecycle`, `strongswan`, `runtime-reconcile`, `stale-enforcement`

Dedup note:

Related to but distinct from the deduped IPsec commit-path stale-tunnel/reload failures (#4433/C172-H01). This is the runtime DHCP lease callback path added for #2884, where the commit fail-closed contract is bypassed.

### C175-HC-046

Title: IPsec connection tracking is advanced before reload success and deleted SAs are terminated on failed applies

Severity: Medium

Confidence: High

Source batch: A7-b3

Evidence:

`pkg/ipsec/manager.go:104`

```go
   104	func (m *Manager) Apply(ipsecCfg *config.IPsecConfig) error {
   105		newNames := vpnConnNameSet(ipsecCfg)
   106		removed := m.swapConnNames(newNames)
   107	
   108		var applyErr error
   109		if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
   110			applyErr = m.clearConfig()
   111		} else {
   112			applyErr = m.applyConfig(ipsecCfg)
```

`pkg/ipsec/manager.go:115`

```go
   115		// Terminate the live SAs of deleted connections AFTER the reload has
   116		// unloaded their config, so a straggler SA cannot be re-initiated from a
   117		// still-loaded connection while we tear it down. Terminate is idempotent:
   118		// a removed VPN with no active SA is a clean no-op (no --terminate is
   119		// issued because it never shows up in --list-sas).
   120		m.terminateRemovedConns(removed)
   121	
   122		return applyErr
```

`pkg/ipsec/manager.go:200`

```go
   200	func (m *Manager) swapConnNames(newNames map[string]bool) []string {
   201		m.mu.Lock()
   202		defer m.mu.Unlock()
   203		var removed []string
   204		for name := range m.prevConnNames {
   205			if !newNames[name] {
   206				removed = append(removed, name)
   207			}
   208		}
   209		m.prevConnNames = newNames
```

Trace:

1. Running config has connection `site-a`, and strongSwan has it loaded.
2. New config removes `site-a` or replaces it with `site-b`; `swapConnNames` immediately records the new set and returns `site-a` as removed.
3. `applyConfig` or `clearConfig` fails to reload strongSwan, so the old strongSwan config is still the effective config.
4. `terminateRemovedConns(removed)` still runs, even though the comment says termination is safe because reload has already unloaded the removed config.
5. The manager has now forgotten that `site-a` is the effective loaded connection. A later `Clear()` diffs against the prematurely promoted set, so missed termination/cleanup for `site-a` is not retried from state.

Refutation attempt:

Not required at this severity. During merge, the coordinator checked the cited caller/guard path and found no condition that invalidated the reported behavior.

HPC/invariant check:

Commit-after-success/state-promotion invariant violated: internal "applied" state is updated before the external host daemon has accepted the new config. Teardown side effects also run before their prerequisite ("config unloaded") is true.

Why it matters:

Failed IPsec commits can disrupt still-effective tunnels by terminating their live SAs, while also losing the bookkeeping needed to clean up stale loaded connections on a future apply. This is both an availability problem and a stale-policy cleanup problem.

Fix direction:

Make the diff two-phase: compute `removed` without mutating `prevConnNames`, reload/unload, and only on successful reload promote `prevConnNames` and terminate removed SAs. On reload failure, preserve the old set and skip removed-SA termination because the removed config was not actually unloaded.

Labels:

`A7-b3`, `ipsec`, `state-machine`, `apply-ordering`, `strongSwan`

Dedup note:

Related to the same stale-strongSwan failure class as dedup `C172-H01`, but this is a distinct manager-internal ordering bug: state is promoted and SAs are terminated before reload success.

### C175-HC-047

Title: networkd stale-file delete failures are warn-only, so removed host interface config can survive a successful commit

Severity: Medium

Confidence: High

Source batch: A7-b3

Evidence:

`pkg/networkd/networkd.go:172`

```go
   172		matches, _ := filepath.Glob(filepath.Join(m.networkDir, filePrefix+"*"))
   173		for _, path := range matches {
   174			base := filepath.Base(path)
   175			if !expected[base] {
   176				if err := os.Remove(path); err != nil {
   177					slog.Warn("failed to remove stale networkd file", "path", path, "err", err)
   178				} else {
   179					slog.Info("removed stale networkd file", "path", path)
   180					changed = true
   181				}
```

`pkg/networkd/networkd.go:337`

```go
   337		for _, path := range matches {
   338			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
   339				slog.Warn("failed to remove networkd file", "path", path, "err", err)
   340			}
   341		}
   342	
   343		if err := runNetworkctl("reload"); err != nil {
   344			return fmt.Errorf("networkctl reload: %w", err)
   345		}
```

`pkg/networkd/networkd.go:225`

```go
   225		if len(writeErrs) > 0 {
   226			// Fail the commit (#2987). Still reload if some files changed so the
   227			// kernel reflects whatever did get written, but surface the error.
   228			if changed {
   229				if err := runNetworkctl("reload"); err != nil {
   230					writeErrs = append(writeErrs, fmt.Errorf("networkctl reload: %w", err))
```

Trace:

1. Operator removes the last address/interface/bond/bridge/rename that previously generated `10-xpf-old.network` or `.netdev`.
2. `Apply(nil)` or a reduced interface set enters the stale sweep.
3. `os.Remove` fails due EACCES, read-only filesystem, immutable file, or another host-integrity fault.
4. The failure is only logged. If no generated file changes, `changed` remains false and Apply returns nil without a reload; if Clear is called, it reloads and still returns nil.
5. The stale networkd unit survives and can continue applying old addresses, VRF membership, bonds, bridges, or renames on reload/boot.

Refutation attempt:

Not required at this severity. During merge, the coordinator checked the cited caller/guard path and found no condition that invalidated the reported behavior.

HPC/invariant check:

Host config reconciliation invariant violated: stale generated files are part of the desired-state diff. Delete failures must be observable like write failures, otherwise the host can keep a previous desired state while commit reports success.

Why it matters:

systemd-networkd snippets are authoritative host integration state. A stale `.network` or `.netdev` can resurrect addresses, bridge/bond membership, or VRF binding that the operator removed, creating route leaks or management-plane surprises.

Fix direction:

Aggregate stale `os.Remove` errors alongside write errors for both `Apply` and `Clear`. Still best-effort every delete and optionally reload if any change succeeded, but return a joined error when any managed file could not be removed. Add remove-failure tests mirroring the existing write-failure test.

Labels:

`A7-b3`, `networkd`, `host-config`, `teardown`, `route-leak`

Dedup note:

Distinct from the prior #2987 write-failure and #2988 empty-set sweep fixes; those tests prove stale files are removed when remove succeeds, but do not cover remove failure.

### C175-HC-048

Title: Routing teardown paths forget failed netlink deletes and return success

Severity: Medium

Confidence: High

Source batch: A7-b3

Evidence:

`pkg/routing/xfrm.go:222`

```go
   222		if err != nil {
   223			delete(x.xfrmis, name)
   224			return // already gone
   225		}
   226		if err := x.ops.LinkDel(link); err != nil {
   227			slog.Warn("failed to delete xfrmi", "name", name, "err", err)
   228		} else {
   229			slog.Info("xfrmi removed", "name", name)
   230		}
   231		delete(x.xfrmis, name)
```

`pkg/routing/bond.go:121`

```go
   121			if err := b.ops.LinkDel(link); err != nil {
   122				slog.Warn("failed to delete bond", "name", name, "err", err)
   123			} else {
   124				slog.Info("bond removed", "name", name)
   125			}
   126		}
   127		b.bonds = nil
   128		return nil
```

`pkg/routing/tunnel.go:1775`

```go
  1775		for name := range names {
  1776			link, err := t.ops.LinkByName(name)
  1777			if err != nil {
  1778				continue // already gone
  1779			}
  1780			if err := t.ops.LinkDel(link); err != nil {
  1781				slog.Warn("failed to delete tunnel", "name", name, "err", err)
  1782			} else {
  1783				slog.Info("tunnel removed", "name", name)
  1784			}
```

Trace:

1. A VPN bind-interface is removed, a fabric bond is removed, or an explicit `Clear*` runs while netlink `LinkDel` returns EBUSY/EPERM/transient netlink error.
2. The failed delete leaves the link in the kernel.
3. XFRM deletes the tracking entry regardless; bond clears the whole tracked list; tunnel full-clear resets ownership maps after logging.
4. The method returns nil, so callers observe successful teardown.
5. A later apply has no remembered ownership for removed objects, so the surviving link can become an orphaned xfrmi/bond/tunnel with stale addresses, enslaved members, or XFRM if_id state.

Refutation attempt:

Not required at this severity. During merge, the coordinator checked the cited caller/guard path and found no condition that invalidated the reported behavior.

HPC/invariant check:

Ownership-retention invariant violated. The VRF and tunnel Apply paths explicitly retain ownership on delete failure so the next reconcile retries; these teardown paths drop ownership after failed deletion.

Why it matters:

Host interfaces are routing objects. A stale xfrmi can keep IPsec-facing interface state around after VPN removal; a stale bond can keep members enslaved; a stale tunnel can preserve addresses/routes after clear. Returning success hides the divergence from the daemon and operator.

Fix direction:

Return joined delete errors from `Clear`/teardown paths and retain tracking for objects whose `LinkDel` failed. For XFRM removed-VPN Apply, keep the failed name in `x.xfrmis` so the next apply retries. Add failure-injection tests mirroring the existing VRF and tunnel Apply retention tests.

Labels:

`A7-b3`, `routing`, `netlink`, `teardown`, `xfrm`, `bond`, `tunnel`

Dedup note:

Distinct from the deduped XFRM if_id collision fix and GRE keepalive fixes. This is delete-failure state retention/observability.

### C175-HC-049

Title: Several system service renderers write unvalidated string leaves into chrony/sshd/rsyslog config files as directives

Severity: Medium

Confidence: High

Source batch: A7-b1

Evidence:

The same parser/schema pattern appears on non-identity system service leaves: `system ntp server`, `system services ssh key-exchange/ciphers/macs`, and `system syslog file/user` are untyped string leaves or keyed instances, and their values are written verbatim into service config files that are reloaded.
Snippet read from `pkg/daemon/daemon_system.go:291-300`:

```go
func renderChronySources(servers []string) string {
	var b strings.Builder
	for _, server := range servers {
		// Use "pool" for hostnames and "server" for literal IPs.
		directive := "pool"
		if net.ParseIP(server) != nil {
			directive = "server"
		}
		fmt.Fprintf(&b, "%s %s iburst\n", directive, server)
```

Snippet read from `pkg/daemon/daemon_system.go:1223-1234`:

```go
	if len(ssh.KeyExchange) > 0 {
		lines = append(lines, "KexAlgorithms "+strings.Join(ssh.KeyExchange, ","))
	}
	// #4305 S-4: sshd hardening knobs. sshd validates the algorithm
	// spellings and numeric ranges at reload, so xpf renders them verbatim
	// (a bad value fails the reload, which applySSHConfig reverts).
	if len(ssh.Ciphers) > 0 {
		lines = append(lines, "Ciphers "+strings.Join(ssh.Ciphers, ","))
	}
```

Snippet read from `pkg/daemon/daemon_system.go:669-695`:

```go
				selector := fmt.Sprintf("%s.%s", facility, severity)
				logPath := fmt.Sprintf("/var/log/%s", f.Name)

				content := fmt.Sprintf("# Managed by xpf — do not edit\n%s\t%s\n", selector, logPath)
				confFile := prefix + f.Name + ".conf"
				desired[confFile] = content
			}
			// Syslog user destinations: forward to logged-in users via rsyslog omusrmsg
```

Trace:

1. A config can carry quoted strings with embedded newlines because `lexer.readString` decodes `\n` and `parser.ParseSetVerb` accepts `TokenString` path values.
2. `system ntp server` is `args: 1, multi: true` with no hostname/IP validator; `compiler_system.go:64-68` appends `ntpChild.Keys[1]` verbatim to `NTPServers`.
3. `renderChronySources` writes `%s %s iburst\n`; a value like `pool.example.net\nlocal stratum 10\n#` produces a second chrony directive and comments out the renderer's trailing `iburst` fragment before `applySystemNTP` reloads chrony.
4. `system services ssh ciphers`, `macs`, and `key-exchange` are free-form strings; `buildSSHDConfig` joins them directly into `Ciphers`, `MACs`, and `KexAlgorithms` lines. An embedded newline can add any syntactically valid sshd directive that `sshd -t` accepts, because the validation gate only checks sshd syntax.
5. `system syslog file` and `user` keyed values flow to rsyslog drop-in content and filenames; newline-bearing values can add rsyslog directives such as `stop`, or make reload fail, because `applySyslogFiles` restarts rsyslog after writing.

Refutation attempt:

Existing tests verify happy-path rendering and sshd validation rollback for invalid algorithm names, but not control characters or directive boundaries. The previous deduped items cover inert SSH knobs and syslog substatement misparse, not code/directive injection in generated host config files. `sshd -t` and `visudo -cf`-style validation do not solve containment when the injected line is valid service syntax.

HPC/invariant check:

Generated service config files must be a pure serialization of structured xpf fields. Values that are supposed to be hostnames, OpenSSH algorithm names, rsyslog filenames, or user targets must remain one token/operand and must not be able to open a second directive line.

Why it matters:

These are root-owned host-service configs under `/etc`. A malicious or malformed imported/synced config can alter chrony/sshd/rsyslog behavior outside xpf's modeled schema or cause persistent service reload failures that look like ordinary apply degradation.

Fix direction:

Add typed validators for each rendered token: hostname/IP for NTP servers, OpenSSH algorithm-token syntax for KEX/cipher/MAC leaves, safe syslog file/user destination names, and a common `rejectControlOrWhitespace` helper for any single-token service value. Keep defensive checks in the renderers so lenient load/sync paths cannot bypass strict commit validation. Add negative tests that embedded newline/space/control characters are rejected and are never rendered.

Labels:

`area:A7-b1`, `daemon`, `host-integration`, `chrony`, `sshd`, `rsyslog`, `config-injection`, `CWE-74`

Dedup note:

Distinct from prior syslog parsing, NTP/SSH inert knob, and SCP argv-injection findings. This is generated service-file directive injection from unvalidated string leaves.
### F3

### C175-HC-050

Title: Unauthenticated REST `--api-addr :port` wildcard bind bypasses the runtime loopback clamp

Severity: Medium

Confidence: High

Source batch: A7-b2

Evidence:

`pkg/daemon/web_management_clamp_4047_test.go:17-25` currently marks empty hosts as loopback/safe and only tests explicit `0.0.0.0` as wildcard:

```go
		{"127.0.0.5", true},    // anywhere in 127.0.0.0/8 is loopback
		{"::1", true},          // IPv6 loopback
		{"10.0.0.5", false},    // routable IPv4 (RFC1918, but network-reachable)
		{"192.168.1.1", false}, // routable IPv4
		{"2001:db8::1", false}, // routable IPv6
		{"0.0.0.0", false},     // wildcard bind — reachable on every interface
		{"", true},             // empty host: treated as safe (do not clamp)
		{"not-an-ip", true},    // unparseable: treated as safe (do not clamp)
```

`pkg/daemon/daemon_cluster_bind.go:60-88` uses that classification directly after `net.SplitHostPort`:

```go
func hostIsLoopback(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return ip.IsLoopback()
}
```

```go
	host, port, err := net.SplitHostPort(addr)
	if err != nil || hostIsLoopback(host) {
		return addr, false
	}
	loopback := "127.0.0.1"
```

`cmd/xpfd/main.go:242-245` and `pkg/daemon/daemon_run.go:1152-1154,1396-1400` show the command-line API address flows into the same clamp:

```go
	configFile := flag.String("config", "/etc/xpf/xpf.conf", "configuration file path")
	noDataplane := flag.Bool("no-dataplane", false, "run without a dataplane (config-only mode)")
	apiAddr := flag.String("api-addr", "127.0.0.1:8080", "HTTP API listen address (empty to disable)")
	grpcAddr := flag.String("grpc-addr", "127.0.0.1:50051", "gRPC API listen address")
```

```go
	apiCfg := api.Config{
		Addr:     d.opts.APIAddr,
		Store:    d.store,
		DP:       apiDP,
```

```go
	hasAuth := apiCfg.Auth != nil
	if clamped, ok := clampBindToLoopback(apiCfg.Addr, hasAuth); ok {
		slog.Warn("web-management HTTP bind is non-loopback without api-auth; clamping to loopback (add `set system services web-management api-auth` to bind off-loopback) — #4047",
			"requested", apiCfg.Addr, "clamped", clamped)
		apiCfg.Addr = clamped
```

Trace:

1. Operator or service unit starts `xpfd --api-addr :8080` with no `system services web-management api-auth`.
2. `cmd/xpfd/main.go` passes `APIAddr=":8080"` into `daemon.Options`.
3. `daemon_run.go` seeds `apiCfg.Addr` from `d.opts.APIAddr`.
4. `clampBindToLoopback(":8080", false)` calls `net.SplitHostPort`, which yields `host == ""`, `port == "8080"`, `err == nil`.
5. `hostIsLoopback("")` returns `true`, so the clamp returns `":8080", false`.
6. The REST API server listens on the Go wildcard address instead of loopback, while `apiCfg.Auth` remains nil.

Refutation attempt:

Not required for Medium severity, but checked the likely guards. The strict `web-management` config gate only covers persisted config and interface-resolved addresses, not the command-line `--api-addr` value. The runtime clamp explicitly covers `apiCfg.Addr` regardless of source, but the empty-host rule classifies `:port` as safe. Prior API-side loopback checks are conservative for wildcard binds, but this daemon clamp is a separate helper.

HPC/invariant check:

No hot-path dataplane invariant. Lifecycle invariant affected: the fail-safe runtime clamp must treat all network-reachable unauthenticated REST binds as unsafe, including Go's empty-host wildcard form.

Why it matters:

The #4047 runtime clamp exists to prevent unauthenticated mutating REST endpoints from becoming network-reachable after lenient load or operator error. `:8080` is a common listen-address spelling for "all interfaces"; this spelling currently bypasses the clamp even though it is equivalent in exposure to `0.0.0.0:8080`.

Fix direction:

Make `hostIsLoopback("")` return false for bind-address classification, or have `clampBindToLoopback` special-case empty host as wildcard and clamp to `127.0.0.1:<port>`. Add table cases for `":8080"` and, if supported, `"[::]:8080"` / `"*:8080"` style inputs. Keep unparseable no-port strings unchanged if that compatibility is required, but do not treat an empty host from a successful `SplitHostPort` as loopback.

Labels:

`daemon-lifecycle`, `web-management`, `auth`, `host-integration`, `test-gap`

Dedup note:

Not a restatement of prior broad `web-management` off-loopback/no-auth reports (#4047/F-155). Those covered missing policy for literal interface/non-loopback binds before the runtime clamp. This finding is a distinct empty-host wildcard form that the new clamp itself misclassifies as loopback; prior A7 notes even recorded the clamp as correct without testing `:port`.

### A7-b2-02

### C175-HC-051

Title: Active gRPC streams can block daemon shutdown forever

Severity: Medium

Confidence: High

Source batch: A8-b2

Evidence:

`pkg/grpcapi/server.go:251`
```go
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	srv.GracefulStop()
	return nil
```

`pkg/grpcapi/server.go:302`
```go
	go func() {
		slog.Info("gRPC fabric listener started", "addr", addr, "vrf", vrfDevice)
		if err := srv.Serve(lis); err != nil {
			slog.Warn("gRPC fabric listener error", "err", err)
		}
	}()

	<-ctx.Done()
	srv.GracefulStop()
```

`pkg/grpcapi/server_diag_monitor.go:416`
```go
	startTime := time.Now()
	ctx := stream.Context()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	summaryMode := monitorSummaryModeFromProto(req.GetSummaryMode())

	// Previous snapshots for rate calculation.
	var prevSingle *monitoriface.Snapshot
	var baselineSingle *monitoriface.Snapshot
```

`pkg/grpcapi/server_diag_monitor.go:465`
```go
		if err := stream.Send(&pb.MonitorInterfaceResponse{Frame: buf.String()}); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
```

Trace:

During daemon shutdown, the parent context passed to `Run` or `RunFabricListener` is cancelled. Both listeners call `srv.GracefulStop()` without a timeout or fallback `Stop()`. `MonitorInterface` is an unbounded server-streaming RPC and only watches `stream.Context()`, which remains live while the client keeps the stream open. Since `GracefulStop` waits for active RPCs to finish, one held monitor stream can keep the gRPC server shutdown path from returning indefinitely.

Refutation attempt:

I looked for a server-lifetime context being threaded into streaming handlers or a timeout wrapper around `GracefulStop`; none exists in the batch. Ping/traceroute and packet-drop have their own budgets/limits, but `MonitorInterface` intentionally streams forever. The fabric stream proxy also uses the caller stream context.

HPC/invariant check:

Shutdown should be bounded even when a client holds an allowed streaming RPC open. Either active streams must observe the server shutdown context or `GracefulStop` must be time-bounded with a hard `Stop()` fallback.

Why it matters:

A local client on the loopback API, or an authenticated fabric peer/client on the fabric listener, can prevent a clean daemon stop/failover/restart by holding `MonitorInterface` open. That turns an observability stream into an availability and operations risk.

Fix direction:

Add a bounded graceful-shutdown helper, for example start `GracefulStop` in a goroutine and call `Stop()` after a short timeout. For streaming handlers, also consider storing a server shutdown context on `Server` and deriving stream work from both `stream.Context()` and server lifetime. Add a regression test that opens `MonitorInterface`, cancels the server context, and asserts `Run` returns within the timeout.

Labels:

`api`, `grpc`, `streaming`, `graceful-shutdown`, `availability`

Dedup note:

Searched the dedup index for `GracefulStop`, `MonitorInterface`, `ClearSessions`, `shutdown`, and related stream terms. Existing shutdown findings are in other subsystems; no exact duplicate for these gRPC listener shutdown paths.
### F2: Filtered ClearSessions accumulates every matching key before deleting

### C175-HC-052

Title: Chunked DHCP identifier clear requests skip JSON decoding and clear every DUID

Severity: Medium

Confidence: High

Source batch: A8-b1

Evidence:

`pkg/api/dhcp.go:68`

```go
	var req ClearDHCPIdentifierRequest
	if r.ContentLength > 0 {
		if !decodeJSONBody(w, r, &req) {
			return
		}
	}

	if req.Interface != "" {
		if err := s.dhcp.ClearDUID(req.Interface); err != nil {
```

`pkg/api/dhcp.go:80`

```go
		writeOK(w, map[string]string{"message": fmt.Sprintf("DHCPv6 DUID cleared for %s", req.Interface)})
		return
	}

	s.dhcp.ClearAllDUIDs()
	writeOK(w, map[string]string{"message": "All DHCPv6 DUIDs cleared"})
}
```

Minimal contract read, `pkg/dhcp/dhcp.go:540`:

```go
// ClearAllDUIDs removes all persisted DUIDs.
func (m *Manager) ClearAllDUIDs() {
	m.mu.Lock()
	ifaces := make([]string, 0, len(m.duids))
	for k := range m.duids {
		ifaces = append(ifaces, k)
	}
```

Trace:

A REST client sends `POST /api/v1/dhcp/identifiers/clear` with `Transfer-Encoding: chunked` and body `{"interface":"wan0"}`. Go sets `r.ContentLength` to `-1`, so the `ContentLength > 0` guard is false. The JSON body is not decoded, `req.Interface` remains empty, and the handler falls through to `s.dhcp.ClearAllDUIDs()`. The caller intended to clear one interface DUID, but the API clears all persisted DHCPv6 DUIDs.

Refutation attempt:

I checked the nearby session-clear body guard, which explicitly treats any non-zero `ContentLength`, including chunked `-1`, as body-present and rejects it. I also checked the API README contract, which lists `dhcp/identifiers/clear` among REST mutations expected to decode through `decodeJSONBody`, and checked the DHCP manager contract to confirm `ClearAllDUIDs` really removes all known persisted DUIDs. I did not find a REST test covering the DHCP clear handler with a chunked body.

HPC/invariant check:

REST mutation invariant is that body-bearing mutations go through `decodeJSONBody` and do not silently reinterpret a narrow operation as a broad destructive operation. This handler violates that invariant for chunked requests because `ContentLength == -1` bypasses decoding.

Why it matters:

Clearing all DUIDs can disrupt DHCPv6 identity stability across interfaces. An authenticated operator or automation path that sends chunked JSON can cause a full DUID reset while attempting a scoped reset.

Fix direction:

Decode the body whenever `r.ContentLength != 0`, mirroring the session clear guard, or always call `decodeJSONBody` for this mutation and handle an empty body explicitly if clear-all is still intended. Add tests for chunked `{"interface":...}` and empty-body clear-all behavior.

Labels:

`api`, `rest`, `dhcp`, `chunked-body`, `mutation`, `data-loss`

Dedup note:

Reviewed `/tmp/review-work-codex-175/dedup-index.md`; no duplicate DHCP identifier chunked-body clear-all issue found.
### A8-b1-002

### C175-HC-053

Title: Filtered local and gRPC session clears snapshot unbounded copies of every matching key

Severity: Medium

Confidence: High

Source batch: A8-b2 + A10-b2

Evidence:

**A8-b2 component**

`pkg/grpcapi/server_sessions.go:975`
```go
	// Clear matching IPv4 sessions
	v4Deleted := 0
	var v4Keys []dataplane.SessionKey
	var v4RevKeys []dataplane.SessionKey
	var snatDNATKeys []dataplane.DNATKey
	// Enumeration failure must be surfaced: a partial scan means the
	// clear silently misses sessions the operator asked to remove.
	agg.add("v4 iterate", s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if !filter.matchV4(key, val) {
```

`pkg/grpcapi/server_sessions.go:986`
```go
		v4Keys = append(v4Keys, key)
		// The reverse companion is installed keyed on val.ReverseKey
		// (the TRANSLATED tuple for NAT'd sessions — session_store.go
		// PutClusterSyncedV4 / manager_ha.go), NOT a naive src/dst swap
		// of the forward key. For a non-NAT session the two coincide;
		// for a NAT'd session a naive swap would leave the real reverse
		// entry behind (#2733). A zero ReverseKey (Protocol==0) means no
		// reverse companion was installed (the needsReverse gate).
```

`pkg/grpcapi/server_sessions.go:1020`
```go
	// Clear matching IPv6 sessions
	v6Deleted := 0
	var v6Keys []dataplane.SessionKeyV6
	var v6RevKeys []dataplane.SessionKeyV6
	var snatDNATKeysV6 []dataplane.DNATKeyV6
	agg.add("v6 iterate", s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if !filter.matchV6(key, val) {
			return true
```

`pkg/dataplane/loader_userspace_shim.go:312`
```go
		hashMapSpec("sessions", sizeOf[SessionKey](), ConntrackSessionValueSize, userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("sessions_v6", sizeOf[SessionKeyV6](), ConntrackSessionValueSizeV6, userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("dnat_table", sizeOf[DNATKey](), sizeOf[DNATValue](), userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("dnat_table_v6", sizeOf[DNATKeyV6](), sizeOf[DNATValueV6](), userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		arrayMapSpec("fib_gen_map", sizeOf[uint32](), 1),
```

`pkg/dataplane/loader_userspace_shim.go:332`
```go
const (
	userspaceShimMaxSessions uint32 = 10000000
	userspaceShimMaxPolicies uint32 = 4096
	userspaceShimMaxNATPools uint32 = 32
)
```

**A10-b2 component**

`pkg/cli/cli_clear.go:191`:

```go
	var v4Keys []dataplane.SessionKey
	var v4RevKeys []dataplane.SessionKey
	var snatDNATKeys []dataplane.DNATKey
	// Enumeration failure must be surfaced: a partial scan silently
	// skips sessions the operator asked to clear (#2468).
	agg.add("v4 iterate", c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !f.matchesV4(key, val) {
```

`pkg/cli/cli_clear.go:203`:

```go
		v4Keys = append(v4Keys, key)
		// The reverse companion is installed keyed on val.ReverseKey
		// (the TRANSLATED tuple for NAT'd sessions — session_store.go
		// PutClusterSyncedV4 / manager_ha.go), NOT a naive src/dst swap
		// of the forward key. For a non-NAT session the two coincide;
		// for a NAT'd session a naive swap would leave the real reverse
		// entry behind (#2733). A zero ReverseKey (Protocol==0) means no
		// reverse companion was installed (the needsReverse gate), so
		// skip it.
		if val.ReverseKey.Protocol != 0 {
```

`pkg/cli/cli_clear.go:238`:

```go
	var v6Keys []dataplane.SessionKeyV6
	var v6RevKeys []dataplane.SessionKeyV6
	var snatDNATKeysV6 []dataplane.DNATKeyV6
	agg.add("v6 iterate", c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !f.matchesV6(key, val) {
			return true
		}
```

Trace:

**A8-b2 component**

An API caller sends a filtered clear that is broad but not empty, such as `protocol=tcp` or a valid zone name. That misses the clear-all fast path and enters the filtered path. The handler iterates v4 and v6 tables and appends every matching forward key, reverse key, and SNAT/DNAT companion key to slices before doing any deletion. On a large userspace deployment, the compatibility maps are sized up to 10,000,000 entries, so the management process can allocate memory proportional to the number of matched sessions, plus slice growth overhead, before it can make progress.

**A10-b2 component**

A broad but syntactically filtered clear such as `protocol tcp` cannot use `ClearAllSessions`. It appends every matching forward key, reverse key, and NAT companion key to separate growing slices for v4, then repeats for v6, before deleting anything. With a large table this consumes hundreds of megabytes or more in the control daemon and can trigger OOM before the clear starts.

Refutation attempt:

**A8-b2 component**

The no-filter clear-all branch uses `ClearAllSessions()` and avoids the slices, so this is limited to filtered clears. I did not find a cap, batching/chunk flush, context check during iteration, or backend delete-by-filter contract in the filtered path. Existing tests cover iterator and delete errors but not memory growth or request cancellation.

**A10-b2 component**

N/A (required only for Critical/High). Existing tests seed one entry and do not impose a cap. Neither the filter nor iterator supplies a maximum, chunk size, or early-stop condition.

HPC/invariant check:

**A8-b2 component**

API-triggered maintenance operations should be bounded by a configured batch size, not by the full dataplane table capacity. Filtered clear should either stream deletes in chunks or fail closed when a broad filter exceeds a safe budget.

**A10-b2 component**

Not packet hot path, but violates the bounded-control-work invariant. Clear memory should be O(chunk size), independent of total session-table cardinality, while preserving iterator safety and companion deletion correctness.

Why it matters:

**A8-b2 component**

A legitimate operator or compromised local/fabric-authorized management client can turn a broad filtered clear into a memory pressure event in `xpfd`. The request is privileged but sits on an API surface used during incidents, where predictability and cancellation matter.

**A10-b2 component**

A legitimate cleanup command during a session storm can kill the same daemon needed to recover or fail over the firewall.

Fix direction:

**A8-b2 component**

Delete in bounded batches during iteration, or add a dataplane-level delete-by-filter primitive that does not materialize all keys in userspace. Check `ctx.Err()` during long scans and expose a clear error on cancellation. Add a regression test with a fake iterator that proves the handler flushes before collecting an unbounded number of keys.

**A10-b2 component**

Introduce a bounded batch iterator/cursor, delete one chunk after releasing iteration state, then resume. If the backend cannot safely mutate while iterating, expose a paged key snapshot API. Keep failure aggregation bounded by operation class/count rather than one string per error.

Labels:

`api`, `grpc`, `resource-exhaustion`, `sessions`, `clear-sessions`, availability, resource-safety, session-table, control-plane

Dedup note:

Merged the gRPC and local CLI reports because both materialize an unbounded filtered key set before deletion. This is distinct from prior unbounded session display/top-talker findings: it is the destructive clear implementation and its extra snapshots.

### C175-HC-054

Title: Closing a stream syslog client is non-terminal, so removed destinations can reconnect and receive later logs

Severity: Medium

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/logging/syslog.go:761`
```go
761	// Close closes the underlying connection.
762	func (s *SyslogClient) Close() error {
763		s.mu.Lock()
764		defer s.mu.Unlock()
765		if s.conn != nil {
766			return s.conn.Close()
767		}
768		return nil
```

Trace:

EventReader and slog handlers snapshot client pointers outside their registry lock. Replacement installs the new set and calls `Close` on the old set. A sender holding an old snapshot then writes the closed TCP/TLS connection, enters the normal reconnect path, dials the deleted remote, and retries the message. `Close` neither marks the client closed nor clears a terminal state. Moreover, `WithAttrs`/`WithGroup` copy the client slice into independent handlers, so a derived logger can retain old clients indefinitely and never observe later `SetClients` updates.

Refutation attempt:

Replacement tests assert that the old connection's `Close` is called once, but never call `Send` through an already captured pointer. UDP does not reconnect, but TCP/TLS explicitly do. No production guard distinguishes construction-time disconnection from administrative closure, and no derived-handler update test exists.

HPC/invariant check:

Logging path, not forwarding. The ownership invariant is linearizable removal: once replacement/Close returns, all stale references must fail terminally and must never create new sockets or transmit.

Why it matters:

Logs can continue reaching a receiver whose access was revoked, leaking security events after a credential/destination change. Reconnected orphan clients also consume descriptors and make the configured stream set differ from actual outbound traffic.

Fix direction:

Add a mutex-guarded terminal `closed` flag; `Close` must set it, nil/close the connection, and make `Send`, `SendBinary`, and `reconnect` return a stable closed error without dialing. Store a shared client-registry pointer in all slog handler derivatives rather than copying slices. Add coordinated snapshot-replace-send tests for TCP/TLS and `slog.With` derivatives.

Labels:

`logging`, `syslog`, `lifecycle`, `confidentiality`, `resource-leak`

Dedup note:

No post-close reconnect or derived-handler stale-registry finding appears in the index. The indexed syslog finding is bounded-write latency, a different root.
### A9-b1-M05

### C175-HC-055

Title: Every HTTP RPM attempt can strand a keep-alive transport for bodyless responses

Severity: Medium

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/rpm/rpm.go:747`
```go
747		dialer, err := probeDialer(10*time.Second, test.SourceAddress, opts)
748		if err != nil {
749			return 0, err
750		}
751		transport := &http.Transport{
752			DialContext: dialer.DialContext,
753		}
754		client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
755
```

Trace:

Each scheduled probe and each probe within a cycle calls `probeHTTP`, allocates a new `http.Transport`, performs one GET, and loses the transport reference. For a 204 or `Content-Length: 0` HTTP/1.1 response, closing the body returns the connection to that transport's idle pool. The zero-value custom transport has keep-alives enabled and `IdleConnTimeout == 0` (no limit), and neither `CloseIdleConnections` nor `DisableKeepAlives` is used. The transport/persistent-connection read loop retain each other and the socket indefinitely.

Refutation attempt:

Confirmed that the client timeout bounds only the request, not idle-connection lifetime, and that closing an already-complete/bodyless response permits reuse rather than closing the socket. Responses with unread bodies often close their connection, but a valid bodyless health endpoint deterministically reaches the idle path. No HTTP RPM test exercises repeated probes or file-descriptor/goroutine counts.

HPC/invariant check:

Probe goroutines only, no forwarding hot path. The lifecycle invariant is one owned transport per reusable client or one closed connection per one-shot probe; every successful cycle must have a terminal owner.

Why it matters:

A common empty health endpoint leaks one TCP fd plus transport goroutines per attempt. Frequent probes eventually exhaust descriptors and memory, disrupting unrelated routing and management services.

Fix direction:

Prefer a long-lived client/transport per test and close idle connections when the test is removed. For strictly one-shot probes, set `DisableKeepAlives: true` or defer `transport.CloseIdleConnections()` immediately after construction. Add a repeated 204-response test that tracks accepted/closed connections and goroutine/fd stability across cancellation.

Labels:

`rpm`, `http`, `resource-leak`, `file-descriptor`, `goroutine`, `vsrx-parity`

Dedup note:

No RPM HTTP transport-ownership finding appears in the supplied index.
### A9-b1-M02

### C175-HC-056

Title: Globally duplicate feed names choose a provider nondeterministically and strand refresh loops until daemon shutdown

Severity: Medium

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/feeds/feeds.go:172`
```go
172		m.mu.Lock()
173		for _, fsCfg := range daCfg.FeedServers {
174			baseURL := resolveBaseURL(fsCfg)
175			if baseURL == "" {
176				continue
177			}
178
179			interval := time.Duration(fsCfg.UpdateInterval) * time.Second
180			if interval <= 0 {
```

Trace:

`FeedServers` is a Go map, so server iteration order changes. Two servers may each declare `FeedEntry.Name == "threats"`; compilation/reference validation treats that as one declared global key. `Apply` starts both loops but the later map assignment wins. `StopAll` can see and cancel only the winner, so the overwritten loop survives every later apply until the daemon's parent context ends. Its private snapshots still fetch, log, and invoke `onUpdate`, while enforcement reads whichever provider happened to win the latest map iteration.

Refutation attempt:

Checked the dynamic-address compiler/reference validator contract. It builds a set of declared names but does not reject cross-server collisions; repeated set syntax within one server may merge, but two different servers remain reachable. Assigned tests cover prefix deduplication, not identity collisions, goroutine ownership, or deterministic provider selection.

HPC/invariant check:

Cold configuration/refresh path. The invariants are global identity uniqueness and exact lifecycle ownership: one configured feed key must resolve to one deterministic state, and every started loop must remain cancellable by the manager.

Why it matters:

A typo can silently switch a denylist to the wrong provider after any commit and leave old outbound fetchers running forever. Repeated applies accumulate network activity and spurious policy rebuild callbacks; the active security set is not predictable from configuration.

Fix direction:

Reject duplicate effective feed names globally at strict validation, including collisions between nested entries and single-feed fallback keys. Defensively build a complete unique plan before starting any goroutine. Track all workers with a generation context and `WaitGroup`, and wait on stop so no old generation can publish callbacks.

Labels:

`feeds`, `configuration`, `lifecycle`, `goroutine-leak`, `policy-correctness`, `vsrx-parity`

Dedup note:

No duplicate-feed identity or orphan-loop root appears in the supplied index. Undefined references, empty endpoints, plaintext URLs, and SSRF are distinct indexed findings.
### A9-b1-M03

### C175-HC-057

Title: Live SESSION_CLOSE sinks emit policy ID zero and a fabricated deny action

Severity: Medium

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/logging/ringbuf.go:548`
```go
548			// #3056: the admitting policy ID rides the trailing [136:140] slot on a
549			// SESSION_CLOSE (because #2853 took [44:48]). Resolve PolicyID from there
550			// so the RT_FLOW_SESSION_CLOSE record and the NetFlow/IPFIX close
551			// exporters name the admitting policy instead of policy 0. A short
552			// (legacy 136-byte) frame leaves it 0. The policy-name resolution below
553			// reads rec.PolicyID, so it follows this value.
554			rec.PolicyID = 0
555			evt.PolicyID = 0
556			if len(data) >= rawEventWireSize {
557				rec.PolicyID = binary.LittleEndian.Uint32(data[rawEventPolicyCloseOffset : rawEventPolicyCloseOffset+4])
```

Trace:

On close, raw `[44:48]` is creation nanoseconds, so `logEvent` correctly moves the admitting policy from `[136:140]` into `rec.PolicyID` and zeroes `evt.PolicyID`. The generic slog close branch and binary encoder later read the zeroed raw event instead of the enriched record. The close wire action is intentionally zero (no forwarding decision), but `actionName(0)` is `deny` and the generic slog branch emits it. Standard and structured formatters were fixed to omit close action; these live sinks were missed.

Refutation attempt:

Direct formatter tests construct `rawEvent` and `EventRecord` with matching hand-set policy IDs, bypassing live close decoding. Session close format tests cover only standard/structured text, not generic slog attributes or a binary record produced by `ProcessRawEvent`. `rec.PolicyName` and callback export use the correct value, confirming this is sink-specific rather than absent wire data.

HPC/invariant check:

Event telemetry path. The invariant is that all sinks consume the enriched close record after overloaded raw slots are normalized; a close must not be represented as a deny decision.

Why it matters:

Binary forensic consumers cannot attribute closes to the admitting policy, and system logs classify every normal termination as a deny. That breaks incident correlation and can trigger false drop alerts while hiding the actual rule.

Fix direction:

Encode `rec.PolicyID` in binary and generic slog. Give SESSION_CLOSE a dedicated slog field set that omits action and includes close reason/reverse counters as appropriate. Add one live extended-close fixture through `ProcessRawEvent` and assert parity across buffer, callback, slog, standard, structured, and binary sinks.

Labels:

`telemetry`, `logging`, `rt-flow`, `record-correctness`, `binary-wire`, `vsrx-parity`

Dedup note:

No close-sink raw/enriched field mix-up appears in the supplied index. The indexed duplicate policy-ID configuration finding is unrelated.
### A9-b1-M06

### C175-HC-058

Title: RT_FLOW session IDs are per-event sequence numbers, so create and close records cannot correlate

Severity: Medium

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/logging/eventbuf.go:57`
```go
57		TOS            uint8
58		TCPControlBits uint8
59		EgressIfindex  uint32
60		CloseReason    string // "idle Timeout", "TCP FIN", "TCP RST", etc.
61		SessionID      uint64 // unique session identifier
62	}
```

Trace:

The 144/152-byte raw event schema contains no session identity. Every call to `logEvent`, including unrelated denies/screens, increments `sessionSeq` and assigns that event's ordinal. A session create and its later close necessarily receive different numbers, and restart resets the namespace. The structured vSRX-compatible renderer, binary log, EventBuffer, REST/SSE, and callbacks expose this ordinal as `SessionID`.

Refutation attempt:

Formatter tests inject the same literal ID into independently constructed create and close records, so they prove rendering only. `DecodeRawEventRecord` leaves SessionID zero, confirming no hidden decoder source. Tuple matching cannot reliably recover identity under concurrent/reused 5-tuples, NAT, and HA.

HPC/invariant check:

The preferred fix is an additive event-wire field copied from existing session state, preserving O(1) work and no packet-path allocation. The violated invariant is identity stability: one dataplane session must carry the same ID across create, close, HA, and every telemetry surface.

Why it matters:

Operators and SIEMs cannot join a session's open and close, distinguish reused tuples, or correlate RT_FLOW with session/HA views. The field looks authoritative while conveying only log arrival order.

Fix direction:

Extend the userspace RT_FLOW producer/wire contract to carry the dataplane's stable uint64 SessionID on create and close, with explicit old/new length handling for rolling upgrades. Decode it directly; use an event-sequence field with a different name only if separately useful. Add end-to-end create/close and HA-failover correlation tests.

Labels:

`telemetry`, `rt-flow`, `session-identity`, `correlation`, `ha`, `vsrx-parity`

Dedup note:

No synthetic RT_FLOW session-ID correlation finding appears in the supplied index.
### A9-b1-M07

### C175-HC-059

Title: SNMP Agent.Stop leaves trap and context goroutines alive and allows queued traps after removal

Severity: Medium

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/snmp/agent.go:465`
```go
465		a.mu.Lock()
466		a.conn = conn
467		a.mu.Unlock()
468
469		slog.Info("SNMP agent listening", "addr", ":161")
470
471		go func() {
472			<-ctx.Done()
473			a.Stop()
474		}()
```

Trace:

The day-2 daemon reconcile calls `Agent.Stop` while the daemon-wide context remains live. The UDP read loop exits, but its context watcher remains blocked. If any trap was ever enqueued, `trapWorker` ranges an unclosed channel forever. Jobs contain prebuilt packets, targets, and old community values, so the worker can continue sending removed configuration for up to the queued backlog. Re-enable creates another agent and another pair of goroutines.

Refutation attempt:

The queue is bounded, but bounded is not terminal: there is no queue close, stop channel, stopped check, generation validation, or worker wait. The full race suite exposed this directly when a worker outlived its test and read `trapSender` after cleanup; production does not mutate that seam, but the same worker lifetime and stale job drain are real.

HPC/invariant check:

Management/link-event path. The invariant is that `Stop` is a lifecycle barrier: after it returns, no owned goroutine or outbound telemetry operation may survive and no removed credential/destination may be used.

Why it matters:

Repeated SNMP enable/disable cycles leak goroutines, and trap removal or community rotation does not stop already queued disclosures to an old receiver. A blocked target can prolong the stale-send window substantially.

Fix direction:

Give Agent one lifecycle context/done channel and `WaitGroup`; have both watcher and trap worker select it. On Stop, atomically reject new jobs, cancel sends, drop or generation-check queued jobs, close/drain safely, close the socket, and wait. Add disable/re-enable tests with a blocked sender proving no post-Stop delivery and zero surviving workers.

Labels:

`snmp`, `traps`, `lifecycle`, `goroutine-leak`, `stale-telemetry`, `vsrx-parity`

Dedup note:

No SNMP trap worker/Stop lifecycle finding appears in the supplied index. The prior day-2 SNMP finding concerned missing reconciliation and is fixed at this base.
### A9-b1-M04

### C175-HC-060

Title: Valid hostnames longer than 26 bytes generate an invalid oversized SNMPv3 EngineID

Severity: Medium

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/snmp/agent.go:295`
```go
295	// initEngine generates a deterministic engine ID from the hostname.
296	func (a *Agent) initEngine() {
297		hostname, _ := os.Hostname()
298		if hostname == "" {
299			hostname = "xpf"
300		}
301		// RFC 3411 format: enterprise(4) + text(3) = 0x80 | len, enterprise OID, format byte, text.
302		// Simplified: use 0x80 0x00 0x00 0x00 0x01 (enterprise=1) + 0x04 (text) + hostname bytes.
303		a.engineID = append([]byte{0x80, 0x00, 0x01, 0x86, 0xa3, 0x04}, []byte(hostname)...)
304		a.engineBoots = a.loadAndIncrementEngineBoots()
```

Trace:

`initEngine` prepends six bytes and appends the OS hostname without a maximum. SNMP-FRAMEWORK-MIB constrains SnmpEngineID to 5..32 octets, so any hostname over 26 bytes creates an invalid authoritative identity. The config/compiler contract imposes no corresponding 26-byte host-name limit, and ordinary Linux hostnames can exceed it. Every v3 discovery, key localization, auth check, and response uses the oversized value.

Refutation attempt:

The test checks only a minimum length and format byte. BER itself accepts the long OCTET STRING, but standards-compliant managers may reject it before USM. Hashing/localization does not reduce the transmitted EngineID. No validator or runtime truncation was found.

HPC/invariant check:

Startup/management only. The identity invariant is stable, globally unique, protocol-valid authoritative engine identity; any migration must preserve existing short-host IDs or explicitly manage rediscovery.

Why it matters:

A valid appliance hostname can make all SNMPv3 monitoring fail while v2c continues, with no startup error explaining the incompatibility.

Fix direction:

Construct a standards-compliant fixed/bounded EngineID, preferably enterprise-specific format plus a stable machine/cluster identity hash. Define migration behavior because changing EngineID invalidates localized keys and manager caches. At minimum reject or deterministically hash long hostnames and test 26/27/64-byte boundaries and uniqueness.

Labels:

`snmpv3`, `identity`, `wire-format`, `configuration`, `vsrx-parity`

Dedup note:

No SNMP EngineID length/identity finding appears in the supplied index.
### A9-b1-L01

### C175-HC-061

Title: `monitor traffic` silently broadens unknown or value-less `matching` clauses to an unfiltered capture

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/monitor_traffic.go:62`:

```go
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "interface":
			// The value after `interface` must be a real interface name,
			// not a missing value or another grammar keyword. Without this
			// guard `interface matching tcp port 80` consumed `matching` as
			// the interface name → tcpdump "no such device" or an
			// unfiltered capture; a trailing bare `interface` consumed
			// nothing and fell through to the usage message (#4540).
```

`pkg/cli/monitor_traffic.go:76`:

```go
		case "matching":
			rest := make([]string, 0, len(args)-i-1)
			for j := i + 1; j < len(args); j++ {
				if monitorTrafficKeywords[args[j]] {
					break
				}
				rest = append(rest, args[j])
			}
			i += len(rest)
			filter = stripSurroundingQuotes(strings.Join(rest, " "))
```

`pkg/cli/monitor_traffic.go:108`:

```go
			if n < 0 || n > 8192 {
				return "", "", "", fmt.Errorf("monitor traffic: 'count' must be 0 (unlimited) or 1..8192, got %q", count)
			}
		}
	}
	return iface, filter, count, nil
}
```

Trace:

`monitor traffic interface ge-0-0-0 matching` collects an empty `rest`, returns `filter=""`, and launches tcpdump without a BPF expression. A typo such as `matchng tcp port 443` hits no switch arm because there is no default rejection; all three tokens are discarded and the same unfiltered capture starts. The strict interface/count checks do not protect the filter predicate.

Refutation attempt:

N/A (required only for Critical/High). `validateMonitorFilter("")` intentionally accepts no filter, so it cannot distinguish an omitted clause from a malformed explicit clause. Existing tests cover missing interface/count values but not missing matching value or unknown top-level tokens.

HPC/invariant check:

External diagnostic path, not packet hot path. Input invariant: once the operator supplies a scoping keyword, every token must be consumed exactly once and an empty/unknown predicate must fail closed before capture.

Why it matters:

A typo in a privileged packet-capture command can expose all traffic on an interface instead of the narrowly intended flow, creating confidentiality and load risk.

Fix direction:

Use a strict parser with a default error, duplicate detection, and an explicit `matchingSeen` flag requiring at least one filter token. Preserve the deliberate no-`matching` capture-all form. Add fail-on-revert cases for trailing `matching`, `matching count`, unknown tokens, and duplicates.

Labels:

security, input-validation, packet-capture, fail-open, vsrx-parity

Dedup note:

Distinct from indexed F-022 (multi-token filter truncation) and the tcpdump option-injection fixes. This path drops an explicit filter entirely.

### C175-HC-062

Title: `publish-generation` runs destructive GC even when it cannot read the journal protection set

Severity: Medium

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/xpfd/publish_generation.go:77`
```go
77	// recoverable cut). Best-effort: a journal read error does not block the
78	// publish (the cut's own GC also protects its source).
79	protected := map[string]bool{}
80	if pinned, jerr := upgrade.ReadJournalSourceGeneration(*journalPath); jerr != nil {
81		fmt.Fprintf(os.Stderr, "publish-generation: WARN read journal for GC protection: %v\n", jerr)
82	} else if pinned != "" {
83		protected[pinned] = true
84	}
85	if gcErr := cfg.GC(protected); gcErr != nil {
86		fmt.Fprintf(os.Stderr, "publish-generation: WARN gc: %v\n", gcErr)
```

Trace:

Suppose a crashed/resumable cut pins generation A. An I/O/permission error leaves `protected` empty but GC still runs and the command exits success. The called GC contract retains only the two newest generations plus current and explicit protections. Publishing B retains A as the one prior generation; publishing C while the journal remains unreadable retains C/B and deletes A. The runner then reads the recovered journal but hard-fails because its pinned source generation no longer exists. A malformed journal is even quieter because the called reader returns no protection without an error.

Refutation attempt:

Confirmed `RetainGenerations == 2`, current-gen is protected, and only caller-provided IDs receive additive protection. That delays deletion for one publish but does not preserve an older resumable source. The claim that the cut's own GC protects it applies only while a cut is running with an authoritative in-memory journal, not after a crash.

HPC/invariant check:

Cold upgrade path. The violated durability invariant is that uncertainty about a live journal must disable destructive reclamation; retaining extra disk state is preferable to deleting the only resumable source.

Why it matters:

A transient journal read problem plus repeated package publishes can turn a recoverable interrupted upgrade, including crash-after-STOP, into an irreversible daemon-down state.

Fix direction:

Publish may proceed, but skip GC whenever journal state cannot be authoritatively read/parsed. Surface malformed journals as protection errors, and run GC only after successful journal classification. Test three generations with an old pinned source under read error and malformed JSON; the pinned directory must remain.

Labels:

`upgrade`, `durability`, `resource-safety`, `fail-open`

Dedup note:

No journal-protection/GC root cause appears in the supplied dedup index.
### A10-b1-L01

### C175-HC-063

Title: `show security alarms` labels cumulative historical screen drops as currently active alarms

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_show_security_log.go:180`:

```go
	// Screen drop alarms — any non-zero screen counter indicates detected attacks
	if c.dp != nil && c.dp.IsLoaded() {
		// #3345: track a counter-read failure so a degraded counter bridge
		// is reported as a warning rather than masquerading as "no alarms".
		var readErr error
		readCtr := func(idx uint32) uint64 {
			v, err := c.dp.ReadGlobalCounter(idx)
			if err != nil && readErr == nil {
				readErr = err
```

`pkg/cli/cli_show_security_log.go:196`:

```go
		for i := range dataplane.ScreenReasonCounters {
			rc := &dataplane.ScreenReasonCounters[i]
			val := readCtr(rc.Index)
			if val > 0 {
				alarmCount++
				if detail {
					fmt.Printf("Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, rc.Label, val)
				}
			}
```

Trace:

Screen reason counters are cumulative drop totals. After one historical drop, `val > 0` remains true until counters are explicitly cleared or the process resets. Every later invocation increments `alarmCount` and prints `currently active`, even when no attack is occurring; a growing total is never compared with a prior sample or time window.

Refutation attempt:

N/A (required only for Critical/High). No timestamp, baseline, rate, alarm latch/clear state, or event-buffer recency check participates in this function. Counter-read warnings only address unavailable data.

HPC/invariant check:

Read-only control path. Alarm invariant: `active` requires current state or a latched alarm with explicit acknowledge/clear semantics; a lifetime counter alone is historical evidence, not state.

Why it matters:

Persistent false Major alarms train operators to ignore the surface and prevent them from distinguishing a current scan/flood from an event that occurred weeks earlier.

Fix direction:

Render cumulative values under statistics, and source alarms from a daemon-maintained state machine with last-seen time, quiet/clear interval, and acknowledge status. At minimum rename the output to historical detections and remove `currently active` until real state exists.

Labels:

correctness, alarms, observability, screen, vsrx-parity

Dedup note:

No matching root in the dedup index. Entries for `alarm-without-drop` concern dataplane detection mode, not CLI interpretation of cumulative counters.

### C175-HC-064

Title: A flow-trace writer failure leaves the monitor permanently reported Active

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/monitor.go:634`:

```go
	go func() {
		defer writer.close()
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case rec := <-sub.C:
				// Check if any filter matches.
```

`pkg/cli/monitor.go:653`:

```go
				line := formatFlowEvent(rec)
				if !traceLineMatches(line, matchRe) {
					continue
				}
				if err := writer.writeLine(line); err != nil {
					// Rotation or write failed; stop tracing rather than grow
					// the active file without bound.
					return
				}
```

`pkg/cli/monitor.go:693`:

```go
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	status := "Inactive"
	if c.monitorFlow.active {
		status = "Active"
	}

	fmt.Printf("  Monitor security flow session status: %s\n", status)
```

Trace:

Disk-full, permission, rename, or rotation failure makes `writeLine` return and the goroutine closes the file/subscription. It never reacquires `monitorFlow.mu`, clears `active/cancel/sub`, or stores the error. `show monitor security flow` continues to say Active, and another `start` is rejected as already active until an operator happens to issue `stop`.

Refutation attempt:

N/A (required only for Critical/High). The only state-clearing code is `handleMonitorSecurityFlowStop`; the goroutine defers close operations only. No health watcher reconciles the boolean.

HPC/invariant check:

Background control-plane writer. Lifecycle invariant: `active` must mean the subscription and writer goroutine are alive; every exit path must transition state exactly once and expose the terminal error. Cleanup must avoid deadlock with stop/restart.

Why it matters:

Audit telemetry can stop silently while the firewall reports collection healthy, causing incident evidence loss and blocking restart at the moment disk/rotation faults need operator attention.

Fix direction:

Give each run a generation/state object and a completion channel. In one deferred finalizer, close resources, clear active state only for the same generation, store the last error, and signal waiters. Make stop wait for completion before restart. Add injected write/rotation failure tests.

Labels:

observability, concurrency, lifecycle, logging, vsrx-parity

Dedup note:

Distinct from indexed flow-trace file privilege and rotation-cap findings; those concern authorization/bounds, while this is stale health after an enforced writer stop.

### C175-HC-065

Title: A missing `node` value turns a targeted HA failover command into an untargeted manual failover

Severity: Medium

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/cli/request.go:211`
```go
211	if len(args) >= 2 && args[0] == "redundancy-group" {
212		actionSuffix := args[1]
213		if len(args) >= 4 && args[2] == "node" {
214			actionSuffix += ":node" + args[3]
215		}
216		action := "cluster-failover:" + actionSuffix
217		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
218			Action: action,
219		})
220		if err != nil {
```

Trace:

`request chassis cluster failover redundancy-group 1 node` produces `args=[redundancy-group,1,node]`. The optional-node condition is false because the fourth token is absent, but the outer branch still sends `cluster-failover:1`. The server contract treats that form as `ManualFailover(1)`; it cannot know the operator supplied an incomplete target selector.

Refutation attempt:

Confirmed that the command tree can suggest the missing value but does not validate execution, and that the server's target-less action is intentionally valid. No downstream range/arity check can recover the discarded `node` token.

HPC/invariant check:

Cold control path. HA action parsing must be exact and fail closed before changing RG ownership; no per-packet cost is involved.

Why it matters:

A truncated automation variable or interactive omission can trigger a real RG failover instead of returning usage. On a degraded cluster this can interrupt forwarding or move ownership in the wrong direction.

Fix direction:

Accept exactly `redundancy-group <N>` or exactly `redundancy-group <N> node <0|1>` and reject every other arity/token. Validate both numbers before constructing the string action, ideally replace the string mini-protocol with typed protobuf fields, and test that malformed forms make zero RPC calls.

Labels:

`cli`, `ha`, `fail-open`, `input-validation`, `vsrx-parity`

Dedup note:

No equivalent missing-node/untargeted-failover finding appears in the supplied dedup index.
### A10-b1-M02

### C175-HC-066

Title: A missing Kea memfile is trusted as an authoritative empty lease set and can trigger mass DNS withdrawal.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcpserver/ddns_leases.go:126` maps `ENOENT` to successful empty input:
```go
126 func parseActiveLeases(path string, family int, now time.Time) ([]ddnsLease, error) {
127     f, err := os.Open(path)
128     if err != nil {
129         if os.IsNotExist(err) {
130             return nil, nil
131         }
132         return nil, err
133     }
134     defer f.Close()
```

`pkg/dhcpserver/ddns_leases.go:149` treats a present zero-byte file as less trustworthy than absence:

```go
149     //   1. An existing-but-0-record file (no header at all) is anomalous —
150     //      Kea always writes a header line when it creates the memfile, so a
151     //      headerless existing file is a mid-write / truncated / corrupt read.
152     //      We cannot validate columns, so fail SAFE (error → untrusted →
153     //      Reconcile SKIPS the destructive diff), not trusted-empty. (A
154     //      genuinely MISSING file already returned nil,nil above via
155     //      os.IsNotExist — "no leases yet" is a legitimate trusted-empty.)
```

The test explicitly pins this behavior at `pkg/dhcpserver/ddns_leases_test.go:663`:

```go
663     t.Run("missing file stays trusted-empty", func(t *testing.T) {
664         dir := t.TempDir()
665         path := filepath.Join(dir, "does-not-exist.csv")
666         leases, err := parseActiveLeases4(path, now)
667         if err != nil {
668             t.Fatalf("a genuinely missing file must be trusted-empty, got error: %v", err)
669         }
670         if leases != nil {
671             t.Fatalf("missing file should yield nil leases, got %+v", leases)
672         }
```

Trace:

DDNS owns records from the prior healthy cycle. During startup ordering, mount/path loss, Kea lease-file cleanup/rotation, or accidental unlink, `os.Open` returns ENOENT. The parser reports a trusted zero-lease family; Surface B's destructive pass interprets every owned record as no longer wanted and deletes all of them from DNS.

Refutation attempt:

A missing file can mean first run, but prior owned state makes that assumption unsafe. The parser already has a trusted-empty proof: a valid header with zero active rows. No generation, Kea-active check, or prior-ownership condition distinguishes first-run absence from transient disappearance.

HPC/invariant check:

Destructive reconciliation may act only on positively validated authoritative input. Absence is lack of evidence, not evidence of an empty lease database.

Why it matters:

A transient local file condition can remove every dynamically managed customer hostname even while leases and clients remain active.

Fix direction:

Treat ENOENT as untrusted whenever DDNS is enabled and especially when ownership exists. Permit destructive empty only from a successfully parsed, valid header (or an explicit Kea control-socket response proving zero leases). Add startup/missing-after-owned and file-rotation tests.

Labels:

`ddns`, `kea`, `fail-open`, `mass-delete`, `lease-parser`

Dedup note:

No missing-memfile authoritative-empty finding matched in the dedup index.
### M06

### C175-HC-067

Title: A rollback index that fits `int` but not `int32` can wrap to zero and discard the candidate

Severity: Medium

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/cli/shared.go:438`
```go
438			v, err := strconv.Atoi(parts[1])
439			if err != nil {
440				return fmt.Errorf("rollback: invalid rollback number %q", parts[1])
441			}
442			if v < 0 {
443				return fmt.Errorf("rollback: rollback number must be >= 0, got %d", v)
444			}
445			n = int32(v)
446		}
447		_, err := c.client.Rollback(c.ctx(), &pb.RollbackRequest{N: n})
```

Trace:

On the deployed 64-bit architecture, `4294967296` is a valid `int`, passes both checks, and converts to `int32(0)`. The server explicitly treats rollback zero as valid and resets the candidate to the active configuration. Similar unbounded `int -> int32` conversions remain in session `limit` and show rollback/compare paths, although those are diagnostic rather than candidate-destructive.

Refutation attempt:

The assigned #3447 tests reject malformed, negative, and one value too large for `int`, but do not test values in `(MaxInt32, MaxInt]`. The server only sees the already-narrowed nonnegative protobuf value; its negative guard cannot detect wrap-to-zero or wrap-to-positive.

HPC/invariant check:

Cold config path. Every value crossing a narrower wire type must be range-checked before conversion, especially where zero has a destructive sentinel meaning.

Why it matters:

A generated command or wrong unit can report success while silently erasing all uncommitted changes. Wrap-to-positive values can also select an unintended historical slot or produce misleading show/session limits.

Fix direction:

Parse directly with `strconv.ParseInt(token, 10, 32)`, reject extra rollback tokens, and centralize bounded protobuf integer parsing for every remote CLI path. Add `MaxInt32`, `MaxInt32+1`, `2^32`, and `2^32+1` no-RPC tests.

Labels:

`cli`, `config-safety`, `integer-truncation`, `input-validation`

Dedup note:

This is a materially new residual of the source-documented #3447 malformed-token fix: the token parses successfully, then the newly added `int32` assignment recreates the same rollback-zero outcome. No supplied dedup entry identifies this narrowing bypass.
### A10-b1-M04

### C175-HC-068

Title: A syntactically valid empty lease is treated as an expired node-0 roll lease

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`pkg/upgrade/kernel_selfrecover.go:151`
```go
	var l KernelRollLease
	if err := json.Unmarshal(data, &l); err != nil {
		// A transient partial read during the orchestrator's atomic write — treat
		// as "no decision this tick" (none); the grace timer + next tick re-read
		// absorb it (r2 AGY non-atomic-write transient).
		s.cfg.Logf("kernel self-recovery: ignoring unparsable lease %s: %v", s.cfg.LeasePath, err)
		return leaseNone
	}
	if l.NodeID != s.cfg.NodeID {
```

Zero values then satisfy expiry at `pkg/upgrade/kernel_selfrecover.go:159`:

```go
	if l.NodeID != s.cfg.NodeID {
		return leaseOther
	}
	if s.cfg.Now().Before(l.ExpiresAt) {
		return leaseActiveOurs
	}
	s.cfg.Logf("kernel self-recovery: EXPIRED lease for node %d (orchestrator crashed mid-roll?)", l.NodeID)
	return leaseExpiredOurs
```

Trace:

JSON `{}` decodes without error to `NodeID=0` and zero `ExpiresAt`; on cluster node 0 it becomes `leaseExpiredOurs`; if the node is drained, not armed, and the peer is healthy for the grace period, `Tick` invokes `ResetFailover` at lines 230-248. Tests cover absent, valid active/expired, and other-node leases but not missing required fields.

Refutation attempt:

The orchestrator currently writes atomically, reducing partial-file exposure, but semantic corruption, manual recovery, downgrade/schema mismatch, or an empty valid JSON object survives syntax checks. The comment calls this lease an "unambiguous fingerprint," which `{}` is not.

HPC/invariant check:

Low-frequency HA timer. Invariant checked: automatic rejoin requires a schema-valid lease with explicitly present node ID and nonzero, sane expiration.

Why it matters:

A malformed/stale file can break a deliberate maintenance drain on node 0 by authorizing automatic rejoin, creating an unexpected election participant.

Fix direction:

Decode required fields through pointer/optional fields or a versioned schema, reject unknown/missing fields, require `node_id` in the supported set and a nonzero bounded expiration, and reset the grace timer on semantic rejection.

Labels:

upgrade, ha, self-recovery, schema-validation, fail-open

Dedup note:

No semantic-empty kernel lease finding appears in `dedup-index.md`.
### A10-b4-13

### C175-HC-069

Title: All AF_XDP reproducers recycle frames without preserving received UMEM addresses

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/libbpf_xsk_test.c:177`
```c
        unsigned int rcvd = xsk_ring_cons__peek(&info->rx, BATCH_SIZE, &idx_rx);
        if (rcvd > 0) {
            total += rcvd;
            xsk_ring_cons__release(&info->rx, rcvd);
            /* Return frames to fill ring */
            __u32 idx_fq;
            if (xsk_ring_prod__reserve(&info->fq, rcvd, &idx_fq) == rcvd) {
                for (unsigned int i = 0; i < rcvd; i++) {
                    *xsk_ring_prod__fill_addr(&info->fq, idx_fq + i) =
                        *xsk_ring_cons__comp_addr(&info->rx, idx_rx + i);
```

The Rust variant discards descriptors and inserts the same prefix repeatedly at `test/xsk-repro/main.rs:180`:

```rust
        let available = rx.available();
        if available > 0 {
            let mut recv = rx.receive(available);
            while recv.read().is_some() {
                total_rx += 1;
            }
            let needed = available.min(offsets.len() as u32);
            let mut fill = device.fill(needed);
            fill.insert(offsets.iter().take(needed as usize).copied());
            fill.commit();
```

Trace:

The C code releases RX descriptors before reading them and calls the completion-ring accessor on an RX ring. The inspected libxdp contract (`/usr/include/xdp/xsk.h:63-84`) shows `comp_addr` interprets entries as packed `u64`, while RX entries are `struct xdp_desc`; the correct address is `xsk_ring_cons__rx_desc(...)->addr` captured before release. The shared C test repeats this at lines 187-198. Rust primes every address once, then repeatedly returns `offsets[0..needed]` regardless of which descriptors were consumed, duplicating kernel-owned addresses and leaking actual received frames.

Refutation attempt:

Initial FIFO order can make the first Rust batch coincidentally match the prefix, but after it is appended once, the next consumed range advances while the code submits the prefix again. No deduplication or descriptor-address capture occurs. The C accessor layouts are definitively different in the called header contract.

Coordinator severity disposition: the descriptor-ownership bug is source-confirmed, but it corrupts standalone lab reproducer evidence rather than the production dataplane. It was therefore downgraded from High to Medium.

HPC/invariant check:

Hot test loop, not production dataplane. Invariant checked: each UMEM frame has exactly one owner and only the address returned in an RX descriptor may be resubmitted after that descriptor is consumed. The correct fix is O(1) per packet and does not add allocation.

Why it matters:

Fill-ring starvation, duplicate ownership, corrupted frame contents, and misleading RX counts can make rebind/shared-UMEM tests pass or fail for allocator corruption rather than the behavior under investigation.

Fix direction:

Capture every RX descriptor address before release, mask unaligned-chunk addresses as required by libxdp, release only after capture, and submit exactly that address list. In Rust, retain the returned frame/descriptor offsets and return those, with ownership assertions in tests.

Labels:

xsk-repro, memory-safety, umem, evidence-integrity

Dedup note:

No AF_XDP frame-recycling finding appears in `dedup-index.md`.
### A10-b4-10

### C175-HC-070

Title: An empty or truncated perf capture is classified as definitive scheduler `OUT`

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/step2-sched-switch-reduce.py:492`
```python
        if rel_err <= STAT_RUNTIME_REL_TOLERANCE:
            stat_runtime_check = "PASS"
        else:
            stat_runtime_check = "WARN"

        obj = {
            "b": b,
            "buckets": buckets,
            "off_cpu_time_3to6": off_3to6,
            "voluntary_3to6": vol,
```

The classifier turns zero signal into `OUT` before checking degeneracy at `test/incus/step2-sched-switch-classify.py:128`:

```python
    if duty_cycle_pct < DUTY_OUT_PCT:
        return "OUT", (
            f"duty_cycle_pct={duty_cycle_pct:.3f} < {DUTY_OUT_PCT}"
        )
    if rho is None:
        return "INCONCLUSIVE", (
            "Spearman rho undefined (degenerate input: constant on one side "
            "or too few blocks)."
```

Trace:

With no parsed perf events, reducer still emits 12 zero blocks, marks all `stat_runtime_check=WARN`, and returns 0 at lines 608-617. Classifier only collects WARN block numbers at lines 298-302; it does not make them suspect. Duty is zero, so `verdict_from(None, 0, None)` returns `OUT` and classifier exits 0. The reducer test explicitly pins "empty events still emit 12 blocks."

Refutation attempt:

Drift sentinels can force SUSPECT, but an empty/truncated capture with acceptable clock metadata has no sentinel. Twelve correctly shaped JSON objects prove formatting, not event coverage; `stat_runtime_check` already provides the missing-evidence signal and is ignored for verdict validity.

HPC/invariant check:

Offline analysis only. Invariant checked: absence of required telemetry is unknown/suspect, never affirmative evidence that scheduler contention is absent.

Why it matters:

Perf permission, tracepoint, collection, or truncation failures produce a confident negative diagnosis, steering engineering work away from a cause that was never measured.

Fix direction:

Count parsed switch/wakeup/runtime events and coverage by worker/block; return nonzero or stamp `suspect_reason` below minimum coverage; make any accounting WARN invalidate the definitive IN/OUT verdict unless explicitly overridden for forensics.

Labels:

packet-tooling, scheduler, fail-open, evidence-integrity

Dedup note:

No empty-perf definitive-verdict finding appears in the index.
### A10-b4-17

### C175-HC-071

Title: Async DHCP server apply drops transient failures permanently and has no convergence retry.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcpserver/dhcpserver.go:365` removes the desired request from the only pending slot before attempting it:
```go
365 func (m *Manager) applyAsyncWorker() {
366     for range m.asyncNotify {
367         m.asyncMu.Lock()
368         req := m.pendingAsync
369         m.pendingAsync = nil
370         m.asyncMu.Unlock()
371         if req == nil {
372             continue
373         }
```

`pkg/dhcpserver/dhcpserver.go:374` only logs an error:

```go
374         if err := m.apply(req.gen, req.cfg, true); err != nil {
375             slog.Warn("async DHCP server apply failed",
376                 "reason", req.reason, "gen", req.gen, "err", err)
377         }
378     }
```

`pkg/dhcpserver/dhcpserver.go:296` advances the generation even when errors were accumulated:

```go
296             }
297         }
298     } else if err := m.clearFamilyLocked(kea6Svc, m.confPath6); err != nil {
299         errs = append(errs, err)
300     }
301 
302     m.lastAppliedGen = gen
303     return errors.Join(errs...)
```

Trace:

A VRRP promotion enqueues the desired active DHCP configuration. The singleton worker reaches a transient systemd timeout or Kea restart failure. The request has already been removed, the generation is recorded as attempted, and the error is only logged. If no later transition or commit occurs, Kea remains stopped or stale indefinitely despite the node remaining master.

Refutation attempt:

Coalescing and generation ordering correctly prevent stale async requests from overwriting new state, but they provide no retry of the newest failed state. Systemd restart behavior cannot be assumed to self-heal an explicit failed restart, and no supervisor callback re-enqueues the request.

HPC/invariant check:

Cold HA lifecycle. A nonblocking event handler still needs eventual convergence to the latest desired state; coalescing must not turn one transient error into permanent drift.

Why it matters:

A brief service-manager failure during takeover can leave clients without DHCP for the entire master tenure, while control-plane state says the transition completed.

Fix direction:

Retain/requeue the latest desired request on failure with bounded exponential backoff and cancellation when superseded. Track desired versus successfully applied generations separately and expose failure state/metrics. Add a fail-once-then-succeed async test and a superseding-request retry test.

Labels:

`dhcp-server`, `async`, `retry`, `ha`, `vsrx-parity`

Dedup note:

No async DHCP apply convergence finding matched in the dedup index.
### M08

### C175-HC-072

Title: Bounded cold-path mode rapidly reuses tuples while claiming every packet installs a new session

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/cold-path-flooder/src/main.rs:9`
```rust
// Two regimes:
//   * `--cohort=unbounded` (DEFAULT, AGY r3 axis 1): sweeps /16
//     src-IP × full 16-bit src-port = ~4.3 B unique 5-tuples.
//     Session table fills in ~26 ms; remaining ~99.9% measures
//     the pure policy-eval cold path
//     (cache_miss → policy_eval → install_rejected_fast_return),
//     cross-worker replicate bypassed.
//   * `--cohort=bounded` (DIAGNOSTIC opt-in): fits the session
//     table (DEFAULT_MAX_SESSIONS = 131_072). Every cold-path
//     sample measures real session miss → install → replicate.
```

Generation is random with replacement at `test/incus/cold-path-flooder/src/main.rs:1101`:

```rust
        for slot in ctx.ring.slots.iter_mut() {
            let s = prng.next();
            let src_ip_off = (s as u32) % args.src_ip_span;
            let src_port_v = (((s >> 16) as u32) % args.src_port_span) as u16;
            let src_port = args.src_port_base.wrapping_add(src_port_v);
            let dst_port_v = (((s >> 32) as u32) % args.dst_port_span) as u16;
            let dst_port = args.dst_port_base.wrapping_add(dst_port_v);
            let src_ip = args.src_ip_base.wrapping_add(src_ip_off);
            let ip_id = (s >> 48) as u16;
            slot.fill_packet(src_ip, ip_id, src_port, dst_port);
```

Trace:

Bounded defaults define exactly 131,072 possible tuples, but random sampling collides before the table is full (after N draws, only about 63% are unique) and a default 30-second multi-Mpps run sends orders of magnitude more than N. Once installed, repeats are session hits, not miss/install/replicate samples. Tests check only cardinality and unbounded first-window seed overlap.

Refutation attempt:

Session aging/eviction may eventually re-cold some tuples, but that is uncontrolled and contradicts "every sample." Merely fitting the table does not make draws unique or remove entries between repetitions.

HPC/invariant check:

Generator hot path. Invariant checked: bounded mode must have a known cold-sample denominator. A counter-based permutation/enumeration can be allocation-free and cheaper than modulo-heavy RNG.

Why it matters:

The diagnostic's measured latency/rate is dominated by warm session hits while being interpreted as real install/replication cost, invalidating comparisons and capacity conclusions.

Fix direction:

Enumerate a no-replacement permutation of the bounded tuple index space, partition disjoint ranges by worker, stop measurement after one cohort pass, or explicitly expire/flush and verify session absence before another pass; report unique/collision counts.

Labels:

packet-tooling, performance, sessions, evidence-integrity

Dedup note:

No bounded-cohort reuse finding appears in `dedup-index.md`.
### A10-b4-19

### C175-HC-073

Title: Cluster session views discard filters in summary mode and print sentinel totals in filtered detail mode

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_show_flow.go:505`:

```go
	err = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV6(key, val) {
			return true
		}
		count++

		if f.summary {
```

`pkg/cli/session_filter.go:415`:

```go
	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := client.GetSessionSummary(ctx, &pb.GetSessionSummaryRequest{})
	if err != nil {
		slog.Warn("failed to fetch peer session summary", "err", err)
		return nil
	}
	return resp
```

`pkg/cli/session_filter.go:365`:

```go
	req := &pb.GetSessionsRequest{Limit: 10000}
	if f.zoneID != 0 {
		// Zone IDs are config-compile-derived and config is synced
		// across the cluster, so the peer resolves the same ID.
		req.Zone = uint32(f.zoneID)
	}
	if f.proto != 0 {
		req.Protocol = strings.ToUpper(protoNameFromNum(f.proto))
	}
```

Called response contract, `pkg/grpcapi/xpfv1/xpf.pb.go:2783`:

```go
type GetSessionsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Total         int32                  `protobuf:"varint,1,opt,name=total,proto3" json:"total,omitempty"` // exact count when unfiltered; -1 when filters active (avoids full scan)
	Sessions      []*SessionEntry        `protobuf:"bytes,2,rep,name=sessions,proto3" json:"sessions,omitempty"`
	NodeId        int32                  `protobuf:"varint,3,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
	NextPageToken string                 `protobuf:"bytes,4,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
```

`pkg/cli/cli_show_flow.go:719`:

```go
					fmt.Println()
				}
			}
			fmt.Printf("Total sessions: %d\n", peerResp.Total)
		}
```

Trace:

Local `show security flow session zone trust summary` applies `f.matches*` and counts only trust sessions. The peer branch calls an empty `GetSessionSummaryRequest`, then renders the peer's all-session count under the same filtered command. In non-summary mode, filters are forwarded but the peer request is capped at 10,000; the RPC contract returns `Total=-1` whenever a filter is active, and the CLI prints `Total sessions: -1` while ignoring `NextPageToken`.

Refutation attempt:

N/A (required only for Critical/High). The response comments and output path directly confirm the sentinel behavior; no caller post-processes the peer summary or follows pagination.

HPC/invariant check:

Control-plane aggregation. Invariant: both node sections produced by one command must apply the identical predicate and clearly distinguish exact, lower-bound, and truncated counts. A fix should remain bounded and use paged/summary-side aggregation rather than materializing every peer session.

Why it matters:

During failover diagnosis, the two nodes appear to have materially different scoped session populations when the CLI is actually comparing filtered local state with unfiltered or truncated peer state.

Fix direction:

Add filter fields to the summary RPC or use a bounded count RPC that evaluates the shared session predicate. For detail, follow page tokens for a user-requested bounded page or print an explicit truncation marker and displayed-row count; never render the `-1` sentinel as a session count.

Labels:

correctness, HA, observability, pagination, vsrx-parity

Dedup note:

No matching root in the dedup index. This is separate from indexed top-talkers memory growth and NAT counter attribution.

### C175-HC-074

Title: Credentialed HTTP DDNS backends allow plaintext endpoints and redirect downgrades.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/ddns/backend_dyndns2.go:109` explicitly accepts both HTTP and HTTPS for a backend that uses Basic authentication:
```go
109 func resolveDyndns2Endpoint(p *config.DDNSProvider) (string, error) {
110     if s := strings.TrimSpace(p.Server); s != "" {
111         if strings.Contains(s, "://") {
112             u, err := url.Parse(s)
113             if err != nil {
114                 return "", fmt.Errorf("ddns dyndns2: provider %q server %q is not a valid URL: %w", p.Name, s, err)
115             }
116             if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
117                 return "", fmt.Errorf("ddns dyndns2: provider %q server %q must be an http(s) URL", p.Name, s)
```

`pkg/ddns/backend_dyndns2.go:209` puts the configured credentials in the request header:

```go
209     req, err := http.NewRequest(http.MethodGet, u.String(), nil)
210     if err != nil {
211         return fmt.Errorf("ddns dyndns2: build request: %w", err)
212     }
213     // Basic auth via the header (set explicitly, NOT in the URL userinfo, so the
214     // password never lands in a logged URL string).
215     if b.username != "" || b.password != "" {
216         req.SetBasicAuth(b.username, b.password)
```

`pkg/ddns/backend_cloudflare.go:54` likewise accepts an arbitrary `server` while carrying a bearer token:

```go
54     token := p.APIToken.Reveal()
55     if token == "" {
56         return nil, fmt.Errorf("ddns cloudflare: provider %q has no api-token", p.Name)
57     }
58     if strings.TrimSpace(p.Zone) == "" {
59         return nil, fmt.Errorf("ddns cloudflare: provider %q has no zone", p.Name)
60     }
61     base := cloudflareAPIBase
62     if s := strings.TrimSpace(p.Server); s != "" {
63         base = strings.TrimRight(s, "/")
```

`pkg/ddns/backend_http.go:98` installs no redirect policy on the shared client:

```go
98     if d := b.dialer(httpDialTimeout); d != nil {
99         tr.DialContext = d.DialContext
100     }
101     return &http.Client{
102         Timeout:   httpClientTimeout,
103         Transport: tr,
104     }
105 }
```

Trace:

Configure `server http://...` for dyndns2, DuckDNS, Cloudflare, or Route53. Basic credentials, a query-string token, a bearer token, or SigV4 authorization is transmitted without TLS. An HTTPS endpoint can also redirect to HTTP under the default client policy; same-host sensitive headers/query credentials can then reach the downgraded request.

Refutation attempt:

Built-in endpoints are HTTPS and the transport validates TLS when TLS is used, but provider overrides are accepted at runtime and the compiler checks credentials/zones rather than requiring HTTPS for these authenticated backends. Generic/checkip HTTP support is not the issue; the finding is limited to credential-bearing providers.

HPC/invariant check:

Cold network control path. Credentials and signed updates must only traverse authenticated transport unless an explicit, narrowly scoped insecure test mode is selected.

Why it matters:

An on-path attacker can recover provider credentials, alter the advertised firewall address, or replay updates. Route53 and Cloudflare credentials can have authority beyond a single hostname.

Fix direction:

Parse endpoints centrally and require `https` plus a nonempty host for every credentialed backend. Add `CheckRedirect` to reject HTTPS-to-HTTP and unexpected cross-origin redirects. If lab HTTP is essential, require an explicit insecure flag unavailable in normal committed configuration and redact it in status. Add constructor/compiler and redirect tests for all credentialed providers.

Labels:

`ddns`, `credentials`, `plaintext`, `tls`, `scheme-enforcement`

Dedup note:

Distinct from `codex-review-157` M05, which reported malformed dyndns2 host/scheme validation and is fixed. This finding is acceptance of valid-but-plaintext authenticated endpoints across multiple backends.
### M04

### C175-HC-075

Title: Ctrl-C or any terminal read error can apply a partial `load ... terminal` configuration

Severity: Medium

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/cli/main.go:391`
```go
391	if source == "terminal" {
392		fmt.Println("[Type or paste configuration, then press Ctrl-D on an empty line]")
393		var lines []string
394		for {
395			line, err := c.rl.Readline()
396			if err != nil {
397				break
398			}
399			lines = append(lines, line)
400		}
```

Trace:

Ctrl-D produces `io.EOF` and is the intended terminator, but readline Ctrl-C (`readline.ErrInterrupt`) and all other read errors enter the same `break`. If at least one valid line was collected, the code joins it and invokes `Load`, then can print `load <mode> complete`; no abort marker reaches the server.

Refutation attempt:

The outer interactive loop distinguishes `readline.ErrInterrupt` from `io.EOF`, proving the library exposes the required distinction. The load loop does not. Server parse/compile can reject syntactically incomplete text, but a partial set-format load or completed prefix is valid and will mutate the candidate.

HPC/invariant check:

Cold config path. User cancellation must be transactional: no candidate mutation after an interrupt or terminal failure.

Why it matters:

An operator trying to abort a paste can unknowingly load a valid subset and later commit it, omitting policies, services, or interfaces that were meant to follow.

Fix direction:

Continue only on successful reads; treat `io.EOF` as completion, `readline.ErrInterrupt`/context cancellation as an explicit abort with no RPC, and other errors as command failures. Add a reader seam and tests for EOF success, interrupt no-RPC, generic error no-RPC, and partial valid set input.

Labels:

`cli`, `config-safety`, `cancellation`, `input-validation`, `vsrx-parity`

Dedup note:

No terminal-load interruption root cause appears in the supplied dedup index.
### A10-b1-M05

### C175-HC-076

Title: DDNS write-ahead state can disappear after first-directory creation because its parent hierarchy is not durably created.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/ddns/state.go:395` uses ordinary `MkdirAll` before the otherwise durable write:
```go
395     if err := os.MkdirAll(dirOf(s.path), 0o755); err != nil {
396         return fmt.Errorf("create ddns state dir: %w", err)
397     }
398     if s.writeFile != nil {
399         return s.writeFile(s.path, data, 0o600)
400     }
401     return fsatomic.WriteFileDurable(s.path, data, 0o600)
```

The assigned helper contract at `pkg/fsatomic/fsatomic.go:150` explains why file-parent fsync alone is insufficient:

```go
150 // MkdirAllDurable is os.MkdirAll plus an fsync of every directory whose
151 // entry set the call may have changed: each newly-created level and the
152 // deepest pre-existing ancestor (which gained the topmost new entry).
153 // Without this, a DurableState file written into a just-created
154 // directory can survive a power cut while the directory itself does not
155 // — fsyncing a file's parent (WriteFileDurable) persists the file's
156 // entry in that directory, not the directory's own entry in ITS parent
157 // (Codex code-r1 High on PR #1900). When the full path already exists
158 // this degrades to plain MkdirAll with zero fsyncs.
```

Trace:

On a first installation or recovered state volume, `/var/lib/xpf` does not exist. DDNS creates it with plain `MkdirAll`, durably writes ownership intent inside it, then publishes DNS. A power loss can preserve the file's entry inside the new directory while losing the new directory entry from `/var/lib`. Next boot sees no state file and treats ownership as empty, leaving the live DNS record orphaned.

Refutation attempt:

`WriteFileDurable` fsyncs the target's immediate parent after rename, but cannot persist that parent's entry in its own parent. The package already provides and tests `MkdirAllDurable`, and this caller does not use it.

HPC/invariant check:

Cold durable-state path. The write-ahead invariant requires state namespace and content to survive before a DNS add is considered owned.

Why it matters:

The precise crash window that write-ahead ownership is intended to close remains open on first directory creation, leading to stale authoritative records and lost cleanup authority.

Fix direction:

Replace the directory creation with `fsatomic.MkdirAllDurable`, propagate its error, and include the quarantine/marker directory operations in the same durability model. Add an injected sync-order test for an initially absent parent hierarchy.

Labels:

`ddns`, `durability`, `fsync`, `write-ahead`, `crash-consistency`

Dedup note:

No DDNS caller-level durable-directory finding matched in the dedup index.
### M05

### C175-HC-077

Title: Destination NAT summary joins rule hits by translated IP instead of pool name, making named-pool hits display as zero

Severity: Medium

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/cli/show_nat.go:207`
```go
207	statsResp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
208		NatType: "destination",
209	})
210	poolHits := make(map[string]uint64)
211	if err == nil {
212		for _, r := range statsResp.Rules {
213			poolHits[r.Action] += r.HitPackets
214		}
215	}
```

Trace:

The called `GetNATRuleStats` contract sets `Action` to `"pool " + rule.Then.PoolName`, so the aggregation keys are names such as `pool web-servers`. The called `GetNATDestination` contract omits pool identity and returns only `TranslateIp`; this client keys rows by that address and reads `poolHits["pool "+addr]`, such as `pool 10.0.0.10`. Those key domains match only when the configured pool name literally equals its address. A transport error is also silently converted to an empty map and zero hits.

Refutation attempt:

Read both RPC builders and the protobuf projection. No hidden normalization changes pool names to addresses, and `NATDestInfo` has no pool-name field. No assigned NAT renderer test exists.

HPC/invariant check:

Cold observability path; O(rules + pools), no packet-path impact. The invariant is that a zero operational counter must mean measured zero, not failed/mismatched attribution.

Why it matters:

Operators can conclude a DNAT rule/pool is unused and remove or troubleshoot it incorrectly even while it carries traffic. The same projection labels the translated address as the pool, hiding vSRX-style named-pool identity.

Fix direction:

Add pool name to the structured destination NAT response (or return pool-keyed summary rows), aggregate and render using that same stable identity, and propagate the stats RPC error instead of printing zeros. Add a test with pool name `web-servers`, address `10.0.0.10`, and nonzero rule hits.

Labels:

`cli`, `nat`, `observability`, `counter-attribution`, `vsrx-parity`

Dedup note:

Indexed F-071 concerns local natshow attributing zone-pair session totals to individual rules. This is a distinct remote-summary key-domain mismatch that makes named-pool rule-hit counters zero.
### A10-b1-M06

### C175-HC-078

Title: DHCP clients leave expired addresses and delegated prefixes installed after T2 failure while reacquisition retries indefinitely.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcp/dhcp.go:825` explicitly falls from failed rebind to fresh acquisition without deconfiguring the expired v4 lease:
```go
825             // A DHCPNAK in REBINDING is also a revocation (RFC 2131
826             // §4.4.5): deconfigure now and re-DISCOVER from INIT with no
827             // prior lease. A rebind TIMEOUT is left to the existing
828             // lease-expiry fallback, which retains the address until the
829             // re-acquire replaces it (#1844 last-known-gateway note in
830             // README) — only an explicit NAK forces immediate abandon.
831             if errors.Is(rerr, errDHCPNAK) {
832                 slog.Warn("DHCPv4: REBINDING NAK — lease revoked, deconfiguring and restarting DISCOVER",
833                     "interface", ifaceName)
```

`pkg/dhcp/dhcp.go:834` breaks to acquisition with the `committed` lease still applied:

```go
834                 m.abandonLeaseAfterNAK(key, committed)
835                 committed = nil
836                 break // outer loop → fresh DORA from INIT
837             }
838             slog.Warn("DHCPv4: T2 rebind failed, lease will expire, re-acquiring",
839                 "interface", ifaceName, "err", rerr)
840             break // fall back to a fresh DORA
```

The v6 path has the same behavior at `pkg/dhcp/dhcp.go:1246`:

```go
1246                 slog.Info("DHCPv6: lease rebound",
1247                     "interface", ifaceName,
1248                     "address", committed.Address,
1249                     "delegated_prefixes", len(renewed.prefixes),
1250                     "lease_time", committed.LeaseTime)
1251                 continue
1252             }
1253             slog.Warn("DHCPv6: T2 rebind failed, lease will expire, re-acquiring",
1254                 "interface", ifaceName, "err", rerr)
1255             break // fall back to a fresh solicit
```

Trace:

A client reaches T2, receives no reply, and reaches actual lease expiry. The run loop immediately starts DORA/Solicit but never removes the old netlink address/default route, lease map entry, or delegated-prefix map first. Repeated acquisition failures retain and expose the expired binding indefinitely; a configured finite v4 retry count can return from the goroutine with it still installed.

Refutation attempt:

Cancellation and explicit DHCPNAK paths do deconfigure, but no timer/reaper or expiry check removes a timed-out binding. The acquisition failure branches do not inspect `Obtained + LeaseTime`, and delegated-prefix readers do not filter by their own expiration.

HPC/invariant check:

Control-plane state machine. The invariant is that an address/prefix must not remain usable after its server-granted valid lifetime, regardless of acquisition availability.

Why it matters:

The server is free to reallocate an expired address or prefix. Continuing to source/route it can create duplicate addresses, stale default routes, incorrect RA, and traffic interception or blackholing.

Fix direction:

Track absolute T2/expiry deadlines independently of exchange duration. At expiry, atomically remove the address, route, lease, and expired PDs, notify consumers, then continue acquisition from INIT. Preserve a last-known gateway only as non-authoritative diagnostic state, not an installed expired lease. Add post-T2 timeout tests that advance through expiry and assert kernel/store cleanup.

Labels:

`dhcp`, `lease-expiry`, `stale-state`, `routing`, `vsrx-parity`

Dedup note:

Distinct from prior classless-route and DHCPv6 IA selection reports; no expired-client-binding retention finding matched.
### M02

### C175-HC-079

Title: DHCPv6 accepts zero-lifetime delegated prefixes and continues exposing them for router advertisement.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcp/dhcp.go:1606` accepts every syntactically valid IA_PD prefix without checking preferred or valid lifetime:
```go
1606         for _, prefix := range iapdOpt.Options.Prefixes() {
1607             if prefix.Prefix == nil {
1608                 continue
1609             }
1610             ones, _ := prefix.Prefix.Mask.Size()
1611             ip, ok := netip.AddrFromSlice(prefix.Prefix.IP)
1612             if !ok {
1613                 continue
1614             }
```

`pkg/dhcp/dhcp.go:1615` stores zero values as ordinary delegated-prefix lifetimes:

```go
1615             result = append(result, DelegatedPrefix{
1616                 Interface:         ifaceName,
1617                 Prefix:            netip.PrefixFrom(ip, ones),
1618                 PreferredLifetime: prefix.PreferredLifetime,
1619                 ValidLifetime:     prefix.ValidLifetime,
1620                 Obtained:          now,
1621             })
1622         }
```

`pkg/dhcp/dhcp.go:278` returns every stored prefix to RA consumers without an expiry/lifetime filter:

```go
278     var result []PDRAMapping
279     for ifName, pds := range m.delegatedPDs {
280         opts := m.v6opts[ifName]
281         if opts == nil || opts.RAIface == "" {
282             continue
283         }
284         for _, dp := range pds {
285             result = append(result, PDRAMapping{
```

The necessary RA merge contract at `pkg/daemon/daemon_ra.go:38` turns zero into an unset configuration lifetime:

```go
38             pfx := &config.RAPrefix{
39                 Prefix:     subPrefix.String(),
40                 OnLink:     true,
41                 Autonomous: true,
42             }
43             if mapping.ValidLifetime > 0 {
44                 pfx.ValidLifetime = int(mapping.ValidLifetime.Seconds())
45             }
46             if mapping.PreferredLifetime > 0 {
47                 pfx.PreferredLife = int(mapping.PreferredLifetime.Seconds())
```

`pkg/ra/sender.go:747` then replaces that unset zero with long SLAAC defaults:

```go
747         validLife := pfx.ValidLifetime
748         if validLife <= 0 {
749             validLife = defaultValidLifetime
750         }
751         prefLife := pfx.PreferredLife
752         if prefLife <= 0 {
753             prefLife = defaultPreferredLifetime
754         }
```

Trace:

A DHCPv6 server revokes an IA_PD by returning the prefix with valid lifetime zero while also renewing an IA_NA address. The parser stores the zero-lifetime prefix, `commitLease` replaces the prior PD slice because it is nonempty, and `DelegatedPrefixesForRA` continues returning it. The daemon omits both zero lifetime fields, and the RA sender interprets omission as its 30-day valid / 7-day preferred defaults. Renewal scheduling follows the unrelated IA_NA lifetime, so the revoked prefix can be repeatedly advertised with newly refreshed long lifetimes.

Refutation attempt:

IA_NA selection explicitly skips zero-valid-lifetime addresses, but IA_PD has no equivalent guard. Neither `commitLease` nor the RA projection filters `Obtained + ValidLifetime`, and existing tests cover extraction/lifetime preservation rather than withdrawal.

HPC/invariant check:

Control-plane projection. A zero valid lifetime is an immediate withdrawal and must never enter the active delegated-prefix set.

Why it matters:

Downstream hosts can receive a fresh 30-day validity for a prefix the provider explicitly reclaimed, causing loss, overlap with another customer, source-address policy failures, and prolonged routing toward the wrong subscriber.

Fix direction:

Treat zero-valid-lifetime IA_PD entries as deletions, age each prefix independently, and remove/notify on expiry even when IA_NA remains valid. Preserve an explicit zero-versus-unset lifetime distinction at the DHCP-to-RA boundary so withdrawal can never receive defaults. Add mixed IA_NA-renew plus IA_PD-zero tests through emitted Prefix Information options.

Labels:

`dhcpv6`, `prefix-delegation`, `withdrawal`, `router-advertisement`, `vsrx-parity`

Dedup note:

Distinct from the older PD-only/IA_NA-empty parsing finding; current code handles PD-only acquisition, but not explicit zero-lifetime withdrawal.
### M03

### C175-HC-080

Title: DHCPv6 lease output labels the hardware-address column as DUID

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/show_services_dhcp.go:265`:

```go
	if len(leases6) > 0 {
		fmt.Printf("DHCPv6 Leases (%d active):\n", len(leases6))
		if detail {
			fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n", "Address", "DUID", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		} else {
```

Called lease contract, `pkg/dhcpserver/dhcpserver.go:419`:

```go
// Lease represents a DHCP lease from Kea's lease database.
type Lease struct {
	Address    string
	HWAddress  string
	Hostname   string
	ValidLife  string
	ExpireTime string
	SubnetID   string
}
```

Called parser contract, `pkg/dhcpserver/dhcpserver.go:572`:

```go
		latest[addr] = Lease{
			Address:    addr,
			HWAddress:  field(fields, "hwaddr"),
			Hostname:   field(fields, "hostname"),
			ValidLife:  field(fields, "valid_lifetime"),
			ExpireTime: expireStr,
			SubnetID:   field(fields, "subnet_id"),
		}
```

Trace:

`GetLeases6` uses the common `Lease` type and parser, which never reads Kea's `duid` or `iaid` columns. The CLI prints `l.HWAddress` under a `DUID` header in both detail and brief forms. A client without a link-layer address yields blank DUID; one with a MAC shows a MAC while claiming it is the DHCPv6 identity.

Refutation attempt:

N/A (required only for Critical/High). The separate HA/DDNS lease-sync model does carry DUID/IAID, but `showDHCPServer` constructs a fresh manager and calls this display parser; no enrichment joins those identities later.

HPC/invariant check:

Bounded file/display path. Identity invariant: a column named DUID must originate from the lease's DUID field and preserve IAID/type where needed to disambiguate DHCPv6 associations.

Why it matters:

Operators cannot correlate displayed leases with DHCPv6 clients, reservations, HA ownership, or packet captures, and may take action against the wrong identity.

Fix direction:

Define family-aware display leases carrying DUID, IAID, lease type/prefix length, and optional hardware address. Parse the v6 header explicitly and render DUID/IAID separately. Add fixture tests where DUID and MAC intentionally differ and where no MAC exists.

Labels:

correctness, DHCPv6, identity, observability, vsrx-parity

Dedup note:

No matching root in the dedup index. The indexed delegated-prefix omission is a separate early-return problem.

### C175-HC-081

Title: Early XSK setup failures read uninitialized phase counters and can return `PASS`

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/libbpf_xsk_test.c:243`
```c
    struct xsk_info info = {};

    printf("\n=== Phase 1: Initial bind (%s) on %s queue %d ===\n", mode, iface, queue);
    if (create_xsk(iface, queue, map_fd, use_copy, &info) < 0) {
        printf("RESULT: FAIL (cannot create XSK)\n");
        goto cleanup;
    }
    unsigned long rx1 = receive_loop(&info, 3);
```

Cleanup consumes skipped initializers at `test/xsk-repro/libbpf_xsk_test.c:273`:

```c
cleanup:
    kill(child, 9);
    waitpid(child, NULL, 0);
    bpf_xdp_attach(ifindex, -1, 0, NULL);
    printf("  XDP detached\n");

    printf("\n");
    if (rx1 > 0 && rx2 > 0)
        printf("RESULT: PASS  phase1_rx=%lu phase2_rx=%lu\n", rx1, rx2);
```

Trace:

Phase-1 failure jumps over initialization of both `rx1` and `rx2`; phase-2 failure jumps over `rx2`; cleanup compares and returns based on indeterminate values at lines 280-289. Warning-enabled compilation reports both `-Wjump-misses-init` and `-Wmaybe-uninitialized` at these sites.

Refutation attempt:

Printing an earlier FAIL line does not constrain the final status or return code. Reading an uninitialized automatic object is undefined behavior, so neither compiler behavior nor typical stack contents provide a reliable fail-closed outcome.

HPC/invariant check:

Test control path only. Invariant checked: every result counter is initialized before any cleanup edge can observe it.

Why it matters:

The reproducer can print contradictory results or exit 0 after it failed to create/rebind the socket, invalidating automated diagnosis.

Fix direction:

Declare and zero `rx1`/`rx2` before any `goto`, maintain an explicit phase/error state, and make any setup error force nonzero independent of counts; compile tests with warnings-as-errors.

Labels:

xsk-repro, undefined-behavior, false-pass, c

Dedup note:

No uninitialized XSK result finding appears in the index.
### A10-b4-22

### C175-HC-082

Title: Every local session is labeled Active or Backup from RG0 rather than its owning redundancy group

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_show_flow.go:213`:

```go
	// Determine HA state string for session display.
	haState := ""
	if clusterMode {
		if c.cluster.IsLocalPrimary(0) {
			haState = "Active"
		} else {
			haState = "Backup"
		}
	}
```

Called session contract, `pkg/dataplane/types.go:25`:

```go
	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   uint32
```

Trace:

In an active/active chassis where node0 is primary for RG0 but secondary for data RG2, sessions whose ingress zone maps to RG2 still use `IsLocalPrimary(0)` and print `HA State: Active`. The inverse mislabel occurs when RG0 is secondary but another data RG is locally primary. Both v4 and v6 rows reuse the single precomputed string.

Refutation attempt:

N/A (required only for Critical/High). I checked the peer/session contracts: session entries carry ingress-zone identity and the cluster subsystem maintains zone-to-RG ownership for session sync, so per-RG state exists; the CLI simply does not use it. The gRPC session renderer currently repeats the RG0 shortcut, which confirms rather than corrects the local output.

HPC/invariant check:

Display-only control path. Invariant: a per-session HA state must be derived from that session's owning data RG, with an explicit unknown state if ownership cannot be resolved.

Why it matters:

Operators can mistake a peer-owned synced copy for the forwarding owner, corrupting failover diagnosis and decisions about which node is safe to drain or restart.

Fix direction:

Build the stable zone-ID-to-RG map once per command, derive the owner RG from `IngressZone`, and call `IsLocalPrimary(rgID)` per row. Share that helper with the gRPC session presenter and test split ownership across at least two data RGs.

Labels:

correctness, HA, session-table, observability, vsrx-parity

Dedup note:

No matching root in the dedup index. The indexed RG0 role-transition issue concerns configuration mutability, not session ownership display.

### C175-HC-083

Title: Failed RG polls disappear, so a failover/failback inside the gap passes as stable

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/mouse_latency_orchestrate.py:630`
```python
    by_ts: "dict[str, set]" = {}
    with open(args.poll_file) as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) != 4:
                continue
            ts, rg_part, node_part, state_part = parts
            triple = (rg_part, node_part, state_part)
            by_ts.setdefault(ts, set()).add(triple)
```

Any nonempty sparse sequence can pass at `test/incus/mouse_latency_orchestrate.py:642`:

```python
    samples = sorted(by_ts.items())
    initial = samples[0][1]
    if not initial:
        # First sample collected an empty triple set (cli succeeded
        # but parser found nothing). Treat as undetermined.
        print("first RG sample is empty", file=sys.stderr)
        return 2
    for ts, triples in samples[1:]:
        if triples != initial:
```

Trace:

The live 1 Hz caller pipes each status poll through the parser with `|| true`, appending nothing for command/parser failure (`test-mouse-latency.sh:286-297`, inspected as caller contract). This function knows neither expected cadence nor run interval. If polls fail while RGs fail over and fail back, successful samples before/after are identical and return stable. Initial/final one-shots also match after failback.

Refutation attempt:

Empty-all data correctly returns 2 and endpoint comparison catches a persistent change, but neither detects a transient state transition wholly inside a missing interval. The comments claim endpoint samples catch gaps, which is false for failover/failback.

HPC/invariant check:

One-Hz observability path only. Invariant checked: a "stable for the run" verdict requires bounded observation gaps over the entire run, not merely equal successful samples.

Why it matters:

A latency repetition contaminated by HA movement can be admitted as valid, distorting the very tail-latency result the RG monitor is intended to protect.

Fix direction:

Record every poll attempt with timestamp/status, pass expected start/end/cadence, invalidate on gaps above tolerance or failed samples, and retain state-transition events from both nodes if available.

Labels:

mouse-latency, ha, observability, evidence-integrity

Dedup note:

No RG-poll cadence-gap finding appears in `dedup-index.md`.
### A10-b4-21

### C175-HC-084

Title: Fairness aggregation accepts a failing harness exit paired with a `PASS` JSON verdict

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/fairness_multi_sample.py:353`
```python
        if exit_code not in (0, 1):
            raise MultiSampleError(
                f"sample {index} harness exited {exit_code}; see {sample_dir}"
            )

        objects = extract_verdict_objects(stdout_text)
        if len(objects) != 1:
            raise MultiSampleError(
```

Only the JSON field controls aggregate failure at `test/incus/fairness_multi_sample.py:180`:

```python
    failure_reasons: list[str] = []
    failing_samples = [s["sample"] for s in samples if s.get("verdict") != "PASS"]
    if failing_samples:
        failure_reasons.append(f"sample verdicts failed: {failing_samples}")
    if mean_gap > max_mean_gap:
        failure_reasons.append(
            f"mean gap {mean_gap:.6f} exceeds threshold {max_mean_gap:.6f}"
        )
```

Trace:

A harness prints its final `PASS` object, then a cleanup/trap/postcondition fails and exits 1; wrapper accepts rc 1 as an ordinary measured result; `sample_record` stores but does not validate `exit_code`; `summarize` checks only JSON verdict and metrics; all samples can aggregate to PASS and main exits 0.

Refutation attempt:

Exit 1 must remain valid for a legitimate JSON `FAIL`, but that calls for an explicit consistency matrix (`0/PASS`, `1/FAIL`). Accepting both codes independent of verdict masks post-verdict failures. Assigned tests cover ordinary rc 0 and hard codes, not rc1/PASS mismatch.

HPC/invariant check:

Offline wrapper only. Invariant checked: process status and machine verdict must agree before a sample is admitted.

Why it matters:

Failed cleanup, capture finalization, or late shell checks can be silently converted into valid passing samples, contaminating a multi-run fairness gate.

Fix direction:

Require rc 0 iff verdict PASS and rc 1 iff verdict FAIL (or define an explicit richer status contract); reject all mismatches and add subprocess tests for both directions.

Labels:

fairness, test-gate, exit-status, evidence-integrity

Dedup note:

No fairness exit/verdict consistency finding appears in the index.
### A10-b4-20

### C175-HC-085

Title: Image validation deletes fixed Incus aliases and instances without ownership or locking

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`scripts/image/validate.py:193`
```python
    def import_image(self):
        self.verify_signatures()
        incus("image", "delete", ALIAS, check=False, capture=True)
        info(f"importing image into local incus as {ALIAS}")
        incus("image", "import", self.metadata, self.qcow2, "--alias", ALIAS)

    def launch(self, name, iso=None, root_size=None, extra_nics=0):
        incus("delete", "-f", name, check=False, capture=True)
        incus("init", ALIAS, name, "--vm", "--network", self.net,
```

Cleanup again deletes the shared names at `scripts/image/validate.py:229`:

```python
    def cleanup(self):
        if self.keep:
            print(f"keeping instances {self.instances}, alias {ALIAS}, network {self.net}")
        else:
            for i in self.instances:
                incus("delete", "-f", i, check=False, capture=True)
            incus("image", "delete", ALIAS, check=False, capture=True)
            if self.created_net:
                incus("network", "delete", self.net, check=False, capture=True)
```

Trace:

`ALIAS` is the constant `xpf-image-validate`; scenario names are fixed `xpf-image-a` through `-e`. A second validation, a stale first run, or an operator object with the same name is forcibly deleted at import/launch/cleanup. There is no lock, run ID, project isolation, or ownership tag.

Refutation attempt:

The names look reserved, but nothing prevents parallel CI jobs or proves an existing object belongs to this run. `--keep` makes collisions more likely on the next invocation.

HPC/invariant check:

Validation orchestration only. Invariant checked: cleanup may delete only resources created and owned by the current validation run.

Why it matters:

Concurrent bakes invalidate each other's tests and artifacts; a validation command can destroy an unrelated VM/image, causing false failures or operational data loss.

Fix direction:

Use a per-run Incus project or UUID-suffixed alias/instance/network names, tag resources with run ownership, refuse foreign collisions, and use a lock only where truly global resources remain.

Labels:

image, incus, concurrency, operational-safety, cleanup

Dedup note:

Distinct from `fable-review-165` H-9 (scenario coverage); no fixed-resource ownership finding is indexed.
### A10-b4-27

### C175-HC-086

Title: Interface session filters treat every ingress session as arriving on the zone's first interface

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/session_filter.go:317`:

```go
func (f *sessionFilter) populateIfaceMaps(c *CLI) {
	zoneIfaces := make(map[uint16]string)
	if cr := c.applyResult(); cr != nil && f.cfg != nil {
		for zoneName, zone := range f.cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
				zoneIfaces[zid] = zone.Interfaces[0]
			}
```

`pkg/cli/session_filter.go:200`:

```go
func (f *sessionFilter) matchesV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.iface != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := f.resolveEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatches(inIf) && !f.ifaceMatches(outIf) {
			return false
		}
```

`pkg/cli/cli_clear.go:179`:

```go
	if err := f.validate(); err != nil {
		return err
	}
	// Interface matching needs the zone/egress interface maps; the
	// show path builds them inline, the clear path must do it too —
	// without this an interface-filtered clear matches nothing.
	f.populateIfaceMaps(c)
```

Trace:

For a zone configured with `[ge-0/0/0.0, ge-0/0/1.0]`, `populateIfaceMaps` stores only `ge-0/0/0.0`. A session that actually entered on `ge-0/0/1.0` carries only `IngressZone`, so `matchesV4/V6` labels it as `ge-0/0/0.0`. `clear security flow session interface ge-0/0/0` therefore deletes that session, while the intended `... interface ge-0/0/1` filter misses it unless its egress happens to match.

Refutation attempt:

N/A (required only for Critical/High). I nevertheless checked `dataplane.SessionValue`/`SessionValueV6`: they carry ingress/egress zone and egress FIB ifindex/VLAN, but no ingress ifindex, so no later field corrects the first-interface guess.

HPC/invariant check:

Matching stays O(1), but correctness invariant fails: a destructive interface-scoped clear must never match sessions whose recorded ingress/egress interface differs from the requested interface. No packet hot-path change is implicated.

Why it matters:

In multi-interface zones, an operator can clear unrelated production sessions and fail to clear the intended interface's sessions. The same mapping makes ordinary `show ... interface` output misleading.

Fix direction:

Persist ingress ifindex/VLAN in the session ABI and sync protocol, or explicitly reject ingress-interface filtering when identity is unavailable. Do not infer an exact interface from a zone. Add v4/v6 tests with two interfaces in one zone and prove show/clear selection on each.

Labels:

correctness, destructive-command, session-table, HA, vsrx-parity

Dedup note:

No matching root in the dedup index. This is distinct from the earlier missing-map clear bug: the map is now populated, but its one-interface data model is wrong.

### C175-HC-087

Title: Interface show paths mix authored, logical, and kernel names, hiding live devices and fabricating VLAN addresses

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_show_interfaces_detail.go:34`:

```go
		for _, z := range cfg.Security.Zones {
			if z == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			for _, ifName := range z.Interfaces {
				ifZoneMap[ifName] = z.Name
			}
		}
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Description != "" {
```

`pkg/cli/cli_show_interfaces_detail.go:49`:

```go
	found := false
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		if filterName != "" && attrs.Name != filterName {
			continue
```

`pkg/cli/cli_show_interfaces.go:318`:

```go
		// Show each logical unit
		for _, li := range group {
			lookupName := physName
			if li.vlanID > 0 {
				lookupName = fmt.Sprintf("%s.%d", physName, li.vlanID)
			}

			fmt.Printf("\n  Logical interface %s.%d", physName, li.unitNum)
```

`pkg/cli/cli_show_interfaces.go:410`:

```go
			} else {
				liface, err := net.InterfaceByName(lookupName)
				if err != nil && iface != nil {
					liface = iface
				}
				if liface != nil {
					if addrs, err := liface.Addrs(); err == nil {
						for _, addr := range addrs {
```

`pkg/cli/cli_show_interfaces_stats.go:69`:

```go
	var entries []vlanEntry
	for _, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.VlanID > 0 || ifc.VlanTagging {
				zone := ifZone[ifc.Name]
				entries = append(entries, vlanEntry{
					iface:  ifc.Name,
					unit:   unitNum,
					vlanID: unit.VlanID,
```

Trace:

A normal configuration keys the physical interface as `ge-0/0/0`, the zone as `ge-0/0/0.50`, and Linux as `ge-0-0-0.50`. Detail/extensive maps remain keyed by the authored logical reference and compare a canonical CLI filter directly to `attrs.Name`, so `show interfaces ge-0/0/0 detail` reports not found and unfiltered output loses configured description/zone joins. Summary constructs `ge-0/0/0.50`, fails kernel lookup, falls back to the parent, and prints parent addresses under unit 50. `show vlans` looks up `ifZone[ge-0/0/0]` although the map key is `ge-0/0/0.50`, leaving the zone blank. The main summary is also built only from zone references, so configured but unzoned interfaces are omitted.

Refutation attempt:

N/A (required only for Critical/High). The shared `cfg.ResolveKernelIfName` contract handles these mappings, and the summary already uses it for the parent, but the cited logical/detail/extensive/VLAN paths bypass it. RETH tests do not refute the normal-interface path because RETH has custom synthesis.

HPC/invariant check:

Control-plane netlink/config joins. Invariant: each row needs explicit authored physical name, authored logical ref, and resolved kernel name; no failed logical lookup may silently substitute parent state.

Why it matters:

Operators can see a live interface as absent, miss its zone/description, or believe a VLAN owns an address that is actually on the parent. Those errors directly undermine outage and security-zone diagnosis.

Fix direction:

Build one interface view model keyed by canonical authored ref with a resolved kernel ref from `ResolveKernelIfName`. Reuse it in summary/detail/extensive/VLAN/zone views, require an exact filter match, and show configured-vs-runtime absence explicitly. Add normal slash-name, tagged unit with distinct VLAN ID, unzoned interface, and per-unit zone tests.

Labels:

correctness, interface-identity, VLAN, observability, vsrx-parity

Dedup note:

Distinct from the indexed monitor-status fallback that marks an unavailable interface Up and from prior RETH resolution fixes. This affects normal authored/logical/kernel joins.

### C175-HC-088

Title: Live device-map enumeration drops every non-PCI NIC even though MAC-only mappings are supported.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/devicemap/devicemap.go:20` defines present NICs as valid without a PCI address:
```go
20 // PresentNIC is one live host NIC as seen at resolve time. Captured as plain
21 // data so the resolver core is unit-testable without sysfs/netlink.
22 type PresentNIC struct {
23     Name       string // current kernel name (post-udev, pre-xpf-rename)
24     PCIAddr    string // PCI bus address ("" if none)
25     PermMAC    string // permanent/factory MAC ("" if unavailable)
26     RunningMAC string // current running MAC (diagnostic only)
27     LinkUp     bool   // operational/admin state (diagnostic; for `candidates`)
```

`pkg/devicemap/devicemap.go:270` discards such interfaces before querying their MAC:

```go
270         devReal, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", name, "device"))
271         if err != nil {
272             continue // not a PCI device
273         }
274         pci := ExtractPCIAddr(devReal)
275         if pci == "" {
276             continue
277         }
278         nic := PresentNIC{Name: name, PCIAddr: pci}
```

The necessary configuration contract at `pkg/config/types_chassis.go:41` explicitly supports MAC as the only key:

```go
41 // DeviceMapKey* are the per-entry identity key-order values (V-5). The
42 // default (empty) is treated as pci-then-mac.
43 const (
44     DeviceMapKeyPCIThenMAC = "pci-then-mac"
45     DeviceMapKeyMACThenPCI = "mac-then-pci"
46     DeviceMapKeyPCI        = "pci"
47     DeviceMapKeyMAC        = "mac"
48 )
```

Trace:

Configure a USB, platform, SoC, virtual, or other non-PCI interface using `key mac`. `/sys/class/net/<name>/device` is absent or resolves to a non-PCI path, so enumeration continues before `netlink.LinkByName` can collect permanent/running MAC. The resolver never sees the NIC and marks a valid mapping unbound.

Refutation attempt:

Resolver unit tests can represent empty-PCI NICs and index them by permanent MAC, confirming the core supports this case. The production enumerator is the narrowing point; no alternate inventory merges non-PCI links later.

HPC/invariant check:

Cold hardware-discovery path. Inventory must include every usable non-loopback link, with PCI as optional metadata rather than an admission criterion.

Why it matters:

Supported appliances or virtual deployments can strand management/data interfaces, skip intended renaming, and diverge from vSRX-style stable interface identity despite a valid committed MAC mapping.

Fix direction:

Enumerate all non-loopback netlink links first, populate MAC/link state for each, and add PCI metadata only when sysfs resolution succeeds. Sort by a composite stable key and distinguish sysfs errors diagnostically. Add a production-enumerator seam/test for a MAC-only non-PCI NIC.

Labels:

`device-map`, `hardware`, `mac`, `inventory`, `vsrx-parity`

Dedup note:

No non-PCI inventory exclusion finding matched in the dedup index.
### L01

### C175-HC-089

Title: Malformed interface-scoped DHCP identifier clears fall through to clearing every DUID

Severity: Medium

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/cli/clear.go:239`
```go
239
240	req := &pb.ClearDHCPClientIdentifierRequest{}
241	if len(args) >= 3 && args[1] == "interface" {
242		req.Interface = args[2]
243	}
244
245	resp, err := c.client.ClearDHCPClientIdentifier(c.ctx(), req)
```

Trace:

Bare `clear dhcp client-identifier` intentionally sends an empty request for clear-all. The same empty request is also sent for malformed nonempty forms such as `... interface` (missing name) or `... interfce ge-0/0/0` (unknown selector). The called server contract branches on `req.Interface != ""`; empty invokes `ClearAllDUIDs`, deleting all cached/persisted DHCPv6 client identities so subsequent requests generate new DUIDs.

Refutation attempt:

Checked the server and DHCP manager contracts. Neither receives the discarded CLI tokens, so they cannot distinguish intentional clear-all from malformed interface scope. The command tree currently does not advertise the handler's hidden `interface` form, and there is no assigned clear-DHCP parser test.

HPC/invariant check:

Cold control path. The ownership/identity invariant is that a malformed scoped destructive command must never broaden into an all-interface mutation.

Why it matters:

DUID changes can make DHCPv6 servers treat clients as new identities, perturb leases/delegated prefixes, and indirectly change routes or DDNS state on every WAN interface rather than the requested one.

Fix direction:

Enforce exact forms: no trailing args for intentional clear-all, or exactly `interface <nonempty-name>` for a scoped clear; reject all other input before RPC. Add the interface child to the canonical command tree and no-RPC tests for missing/unknown/extra tokens.

Labels:

`cli`, `dhcp`, `identity`, `destructive-action`, `input-validation`, `vsrx-parity`

Dedup note:

No DHCP DUID clear-all parser finding appears in the supplied dedup index.
### A10-b1-M03

### C175-HC-090

Title: Rebind tests ignore whether the requested link down/up cycle happened

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/libbpf_xsk_test.c:254`
```c
    printf("\n=== Link DOWN/UP on %s ===\n", iface);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s down", iface);
    system(cmd);
    usleep(200000);
    snprintf(cmd, sizeof(cmd), "ip link set %s up", iface);
    system(cmd);
```

Rust also discards status at `test/xsk-repro/main.rs:63`:

```rust
    eprintln!("\n=== Link DOWN/UP on {} ===", iface);
    eprintln!("  ip link set {} down", iface);
    std::process::Command::new("ip").args(["link", "set", iface, "down"]).status().ok();
    std::thread::sleep(Duration::from_millis(200));
    eprintln!("  ip link set {} up", iface);
    std::process::Command::new("ip").args(["link", "set", iface, "up"]).status().ok();
    eprintln!("  waiting 500ms for NIC reinit...");
```

Trace:

Missing `ip`, insufficient capability, backend/netdev refusal, or command failure leaves the link unchanged; both programs proceed to phase 2 and can report PASS based on an ordinary socket recreate. C additionally invokes a shell with an interpolated interface name.

Refutation attempt:

`if_nametoindex` proves the interface existed at startup but not that either state transition succeeded. Sleep duration and phase-2 traffic are not proof of a carrier/admin-state cycle.

HPC/invariant check:

Setup path only. Invariant checked: a link-cycle rebind result is valid only after confirmed down and up transitions.

Why it matters:

The test can green-light a driver/kernel rebind behavior it never exercised, or leave the interface down while reporting only RX failure.

Fix direction:

Use rtnetlink directly or check `Command::status.success()`/decoded `system` status; verify `IFF_UP` transitions with bounded waits; abort and restore state on either failure; eliminate the C shell command.

Labels:

xsk-repro, false-pass, link-state, operational-safety

Dedup note:

No ignored XSK link-cycle status finding appears in the index.
### A10-b4-23

### C175-HC-091

Title: Rust unmaps the UMEM packet area while socket/UMEM owners are still alive

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/main.rs:195`
```rust
        }
    }
    eprintln!("  rx={} empty_polls={}", total_rx, poll_count);

    // Cleanup
    xskmap_delete(xsk_map_fd, queue);
    unsafe { libc::munmap(area_ptr, area_size) };
    total_rx
}
```

Those live owners were built from the mapping at `test/xsk-repro/main.rs:122`:

```rust
    let umem = unsafe { Umem::new(cfg, area_slice) }.expect("create umem");

    let mut info = IfInfo::invalid();
    info.from_ifindex(if_nametoindex(iface)).expect("ifindex lookup");
    info.set_queue(queue);

    let sock = Socket::with_shared(&info, &umem).expect("create socket");
    let mut device = umem.fq_cq(&sock).expect("create fq/cq");
```

Trace:

`area_slice` is an unsafe lifetime promise to `Umem`; `umem`, `sock`, `device`, `user`, and `rx` remain in scope when `munmap` runs and are dropped only during function return. Deleting the XSK-map entry stops redirect lookup but does not close the AF_XDP socket or revoke outstanding kernel/ring ownership before the backing mapping disappears.

Refutation attempt:

Kernel page pins may delay physical reuse, but they do not satisfy the Rust API's requirement that the user mapping remain valid for all objects borrowing it, and drop implementations are free to access associated state. No explicit close/drop synchronization precedes unmap.

HPC/invariant check:

Phase teardown only. Invariant checked: UMEM backing memory outlives every socket/ring/kernel owner and is unmapped last.

Why it matters:

Teardown can fault, race kernel access, or hide lifetime bugs behind platform-specific pinning behavior, making repeated rebind results unstable.

Fix direction:

Scope/drop `rx`, `user`, `device`, `sock`, and `umem` explicitly before `munmap`; use an RAII owner whose `Drop` closes sockets then unmaps; drain outstanding descriptors if required by the library.

Labels:

xsk-repro, memory-lifetime, rust, umem

Dedup note:

No UMEM teardown-lifetime finding appears in the index.
### A10-b4-24

### C175-HC-092

Title: Scheduler duty cycle divides by 60 seconds even when measured boundaries span another duration

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/step2-sched-switch-classify.py:39`
```python
RHO_IN = 0.8
RHO_OUT = 0.3
DUTY_IN_PCT = 1.0
DUTY_OUT_PCT = 1.0
NOMINAL_WINDOW_NS = 60_000_000_000  # 60 s
D1_LO, D1_HI = 3, 6  # inclusive
```

The fixed value is used at `test/incus/step2-sched-switch-classify.py:285`:

```python
    T_D1 = compute_T_D1(hist_blocks)
    off_times = [int(b.get("off_cpu_time_3to6", 0)) for b in off_cpu_blocks]

    rho, pvalue = spearman_rho(T_D1, [float(x) for x in off_times])

    duty_cycle_pct = 100.0 * sum(off_times) / NOMINAL_WINDOW_NS

    verdict, reason = verdict_from(rho, duty_cycle_pct, suspect_reason)
```

Trace:

Reducer block boundaries come from observed snapshot timestamps and accept each interval in `[1,30]` seconds, merely warning outside `[3,7]` (`step2-sched-switch-reduce.py:302-314`). Twelve accepted 7-second blocks span 84 seconds, while classification still divides by 60; 3-second blocks span 36 seconds. The 1% IN/OUT boundary can therefore flip solely due to collection cadence.

Refutation attempt:

"Nominal" is not an enforced capture duration. Warning-only 3-7 second jitter still permits 36-84 seconds, and neither emitted blocks nor classifier metadata carries/uses the actual total duration.

HPC/invariant check:

Offline arithmetic only. Invariant checked: a duty fraction uses the same measured time window as its numerator.

Why it matters:

Identical scheduler behavior receives different classification depending on snapshot delay, with errors up to large factors inside accepted input bounds.

Fix direction:

Emit `block_duration_ns` or start/end boundaries in each reduced block, validate continuity, sum actual durations in the classifier, and make severe cadence warnings suspect rather than silently normalized.

Labels:

packet-tooling, scheduler, measurement, integer-time

Dedup note:

No nominal-versus-observed scheduler-window finding appears in the index.
### A10-b4-18

### C175-HC-093

Title: Show paging and pipe filters buffer complete output and nest an invisible pager

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_dispatch.go:53`:

```go
func (c *CLI) dispatchWithPipe(cmd, pipeType, pipeArg string) error {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	os.Stdout = w

	outputCh := make(chan []byte, 1)
```

`pkg/cli/cli_dispatch.go:62`:

```go
	go func() {
		output, _ := io.ReadAll(r)
		r.Close()
		outputCh <- output
	}()

	cmdErr := c.dispatch(cmd)
	w.Close()
	os.Stdout = origStdout
```

`pkg/cli/cli_dispatch.go:127`:

```go
func (c *CLI) dispatchWithPager(line string) error {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return c.dispatchOperational(line)
	}
	os.Stdout = w

	outputCh := make(chan []byte, 1)
```

`pkg/cli/cli_dispatch.go:135`:

```go
	outputCh := make(chan []byte, 1)
	go func() {
		output, _ := io.ReadAll(r)
		r.Close()
		outputCh <- output
	}()

	cmdErr := c.dispatchOperational(line)
	w.Close()
```

Trace:

Every literal `show` redirects process-global `os.Stdout` and `io.ReadAll`s the entire result before pagination, then converts it to a string and a second slice of lines. An all-session show can therefore allocate proportional to millions of rendered rows. With `show ... | match`, the outer pipe calls `c.dispatch(cmd)`, which invokes the inner pager; for output over one page, the `--More--` prompt is written into the outer hidden pipe while the inner pager blocks on stdin, so the command appears hung until the operator types blind pager keys.

Refutation attempt:

N/A (required only for Critical/High). The session view has no output cap, and `| no-more` takes the same recursive path. The reader goroutine avoids pipe-buffer deadlock but does not bound memory or bypass the inner pager. Global stdout also permits unrelated goroutine output to be captured during the command.

HPC/invariant check:

Control-plane I/O. Invariant: presentation memory must be bounded by a page/filter buffer, and a pipe-filtered command must execute the producer exactly once with paging disabled. Process-global output descriptors must not be mutated by one session.

Why it matters:

A view-only user can exhaust daemon memory with a large show. Pipe filters on long output can stall with no visible prompt and can absorb unrelated daemon output, making routine troubleshooting unreliable.

Fix direction:

Thread an `io.Writer` through renderers or use a per-command output context. Stream lines through filter and pager stages with fixed-size buffers; have `no-more` explicitly bypass pagination and never recurse through `dispatch`. Add large synthetic output and concurrent-writer tests.

Labels:

availability, resource-safety, concurrency, CLI

Dedup note:

No matching root in the dedup index. This is independent of the indexed top-talkers collection inside the renderer; even streaming renderers are fully re-buffered here.

### C175-HC-094

Title: The destructive DDNS lease parser materializes the entire append-only Kea history on every reconcile.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcpserver/ddns_leases.go:136` calls `ReadAll` before filtering or deduplication:
```go
136     r := csv.NewReader(f)
137     r.FieldsPerRecord = -1 // memfile rows vary across Kea versions
138     r.Comment = '#'
139     records, err := r.ReadAll()
140     if err != nil {
141         return nil, fmt.Errorf("parse %s: %w", path, err)
142     }
```

The sibling parser documents the source's growth model at `pkg/dhcpserver/dhcpserver.go:439`:

```go
439 // parseLeaseCSV parses Kea's append-only memfile CSV and returns the
440 // CURRENT, ACTIVE leases for display (`show dhcp server leases`).
441 //
442 // Kea never rewrites the memfile in place between lease-file-cleanup
443 // (LFC) compactions: every renewal, re-allocation, release, decline,
444 // and expiry-reclaim is APPENDED as a new row, so the same address
445 // appears multiple times and superseded/stale rows linger until the
446 // next LFC. A naive "emit every row with a non-empty address" therefore
447 // shows duplicate and stale leases (#2085). This parser collapses the
```

Trace:

DHCP churn appends many historical rows between LFC compactions. Every DDNS reconcile allocates strings/slices for all rows with `ReadAll`, then allocates header/index/latest/order structures while retaining the first copy. A client population able to drive lease churn can create repeated O(history) latency and transient memory, potentially stalling or OOM-killing the Go control plane.

Refutation attempt:

LFC normally reduces growth, but there is no parser-side byte/row cap or streaming bound and the fallback lease-sync reader reuses this parser. The non-destructive display parser already streams records, proving a local pattern exists, though destructive semantics must remain all-or-nothing on any malformed row.

HPC/invariant check:

Cold path, but work must be bounded by active leases or an explicit file limit, not unbounded historical events. No per-packet constraint applies.

Why it matters:

Remote DHCP activity can amplify a local append log into recurring allocator pressure and DDNS/HA latency; a control-plane OOM affects configuration, monitoring, and failover orchestration.

Fix direction:

Stream `csv.Reader.Read` and retain only the latest row per address, while recording any syntax/ragged-row error and rejecting the entire resulting set before destructive reconciliation. Enforce a configured byte/row ceiling, export size/reject metrics, and test a large duplicate-heavy log plus a malformed tail.

Labels:

`resource-exhaustion`, `ddns`, `kea`, `memory`, `latency`

Dedup note:

No destructive-parser `ReadAll` resource finding matched in the dedup index.
### M07

### C175-HC-095

Title: The shared-UMEM test can pass without routing or reading one packet on the secondary socket

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/libbpf_xsk_shared_test.c:143`
```c
    }

    /* Register in xskmap */
    __u32 key = queue, val = xsk_fd;
    bpf_map_update_elem(map_fd, &key, &val, 0);
    printf("  xskmap[%u] = fd %d\n", key, xsk_fd);

    /* Prime the per-socket fill ring */
```

The receive loop uses only owner rings at `test/xsk-repro/libbpf_xsk_shared_test.c:187`:

```c
        __u32 idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&rx, BATCH_SIZE, &idx_rx);
        if (rcvd > 0) {
            total += rcvd;
            xsk_ring_cons__release(&rx, rcvd);
            /* Return to per-socket fill ring */
            __u32 idx_fq;
            if (xsk_ring_prod__reserve(&fill, rcvd, &idx_fq) == rcvd) {
                for (unsigned int i = 0; i < rcvd; i++)
```

Trace:

Optional secondary creation checks bind/zerocopy flags at lines 109-142, but XDP is attached only to the owner ifindex, only the owner queue/fd is inserted in the map, traffic targets the owner, and neither `secondary_rx` nor `secondary_fill` is polled. Final PASS depends solely on owner `rx1 > 0` at lines 291-297.

Refutation attempt:

If the intended contract is API-bind-only, owner traffic does not validate secondary shared-UMEM data-plane behavior and the generic PASS output overstates scope. The CLI accepts a secondary interface/queue, strongly implying that path is meant to be exercised.

HPC/invariant check:

Diagnostic path. Invariant checked: a shared-secondary success verdict requires data movement and frame recycling through that secondary socket, not only successful construction.

Why it matters:

Cross-interface/queue shared-UMEM regressions can pass while only the already-working owner socket receives traffic.

Fix direction:

Attach/register on the secondary interface and queue, generate distinguishable traffic to both, poll and recycle both RX rings, require nonzero counts per socket, and report bind-only as a separate non-data-path result.

Labels:

xsk-repro, test-completeness, shared-umem, false-pass

Dedup note:

No secondary shared-UMEM coverage finding appears in the index.
### A10-b4-26

### C175-HC-096

Title: The standalone config-drive builder leaves secret-bearing ISOs world-readable

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`scripts/image/make_config_drive.py:68`
```python
    tool = _iso_tool()
    stage = tempfile.mkdtemp(prefix="xpf-day0-")
    try:
        shutil.copyfile(config, os.path.join(stage, "xpf.conf"))
        os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
        if node_id is not None:
            with open(os.path.join(stage, "node-id"), "w") as f:
                f.write(f"{node_id}\n")
        print(f"==> building {out} (volume label xpf-config)")
```

No owner-only postcondition follows ISO creation at `scripts/image/make_config_drive.py:77`:

```python
        if tool == "xorriso":
            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
                    "-J", "-r", "-o", out, stage]
        else:
            argv = [tool, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", out, stage]
        subprocess.run(argv, check=True)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return out
```

Trace:

Day-0 configuration may contain password hashes, IKE PSKs, SNMP communities, and tokens. mkisofs-family tools create output under the process umask, commonly 0644; the helper neither sets a restrictive umask nor chmods the ISO. The duplicate deploy implementation explicitly documents this exposure and applies 0600 at `xpf-deploy.py:320-340`.

Refutation attempt:

The staging directory is 0700, but confidentiality is lost in the persistent output ISO, which is the artifact users attach/share. Rock Ridge `-r` also makes embedded files readable within the ISO; host-file mode therefore must protect the container.

HPC/invariant check:

Image tooling only. Invariant checked: every artifact embedding full appliance configuration remains owner-readable only by default.

Why it matters:

Any co-located account can extract day-0 credentials from a default-created ISO that may linger in a build/work directory.

Fix direction:

Create output in a private temp file with mode 0600, atomically rename, and enforce `chmod(0600)` afterward; keep staged config 0600; consolidate both builders behind one implementation and add a mode test.

Labels:

image, secrets, permissions, day0, vsrx-parity

Dedup note:

`fable-review-165` H-34 cataloged duplicated builders and drift. This is the concrete confidentiality defect still present in the assigned standalone helper; coordinator may merge it under H-34 if that issue already records modes.
### A10-b4-16

### C175-HC-097

Title: Unvalidated appliance/image identifiers escape managed deployment directories

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`scripts/deploy/xpf-deploy.py:213`
```python
def validate_appliance(ap, where):
    if not ap.get("name"):
        die(f"{where}: name is required")
    if ap["mode"] not in ("standalone", "cluster"):
        die(f"{where}: mode must be standalone|cluster")
    if ap["mode"] == "cluster" and ap.get("node_id") not in (0, 1):
        die(f"{where}: cluster needs node_id 0|1")
    if not ap["interfaces"]:
        die(f"{where}: at least one interface (position 1 = fxp0)")
```

Paths are built by raw joining at `scripts/deploy/xpf-deploy.py:559`:

```python
def libvirt_golden_path(image):
    """The libvirt golden qcow2 path — the SINGLE source of truth shared by
    `deploy --hypervisor libvirt` (reads it as the read-only overlay backing)
    AND `fetch --install-libvirt` (writes the verified image here). One helper
    so the two halves can't drift (fable-165 H-30)."""
    return os.path.join(LIBVIRT_IMAGES, f"{image}.qcow2")
```

Trace:

`name` and `image` accept separators and `..`; overlay, golden, and day-0 paths are formed at lines 296, 564, and 603/651/760/775 without `realpath/commonpath` containment; deploy/fetch writes them and destroy/cleanup removes them, often via sudo. Targeted execution showed `../../../../tmp/owned` and `../../../../tmp/golden` resolve to `/tmp/owned.qcow2` and `/tmp/golden.qcow2` after validation.

Refutation attempt:

Configuration is operator-supplied, but it is also an automation boundary and the script performs privileged destructive operations. Requiring a basename is consistent with hypervisor naming constraints and does not remove a supported legitimate form.

HPC/invariant check:

Deployment control path only. Invariant checked: every generated/removed artifact remains beneath its designated managed root, and identifiers cannot become option-like/path arguments.

Why it matters:

A typo or crafted YAML can overwrite/remove arbitrary suffixed files outside libvirt storage or the working directory, and can make fetch install a golden image to an unintended privileged path.

Fix direction:

Define strict appliance/image identifier syntax, reject separators, dot components, control characters, and leading `-`; resolve destinations and enforce `os.path.commonpath([root, destination]) == root` immediately before every write/delete.

Labels:

deploy, path-traversal, operational-safety, input-validation

Dedup note:

Related to `fable-review-165` L-4 (non-strict YAML) but distinct: this is a reproduced filesystem containment failure with privileged write/delete sinks.
### A10-b4-14

### C175-HC-098

Title: Userspace forwarding health reports Online with no worker heartbeat, and future timestamps also count as fresh.

Severity: Medium

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/fwdstatus/builder.go:213` reaches Online unless `allHeartbeatsFresh` returns false:
```go
213     // --- State ---------------------------------------------------
214     switch {
215     case dp == nil || !dp.IsLoaded():
216         fs.State = StateUnknown
217     case !hasProcStat || !hasStatm:
218         fs.State = StateUnknown
219     case isUserspace && usErr != nil:
220         fs.State = StateUnknown
221     case isUserspace && !allHeartbeatsFresh(usStatus.WorkerHeartbeats, time.Now(), 2*time.Second):
```

`pkg/fwdstatus/builder.go:234` makes empty input vacuously true and accepts arbitrarily future timestamps because the age is negative:

```go
234 // allHeartbeatsFresh returns true iff every heartbeat is within
235 // maxAge of now.  Empty slice returns true (no workers → trivially
236 // fresh; caller distinguishes the empty vs populated case when
237 // interpreting Degraded).
238 func allHeartbeatsFresh(hbs []time.Time, now time.Time, maxAge time.Duration) bool {
239     for _, hb := range hbs {
240         if now.Sub(hb) > maxAge {
241             return false
242         }
```

Trace:

The userspace helper is considered loaded and status retrieval succeeds before workers publish heartbeats, after a wire-version mismatch omits the field, or after a malformed/future clock conversion. An empty slice performs no loop iteration; a future heartbeat has negative age. Both return true, so the default branch reports Online without positive evidence that any packet-processing worker is alive.

Refutation attempt:

The helper comment says the caller distinguishes empty from populated, but the state switch has no such branch. Fresh-heartbeat and stale-heartbeat tests exist; no empty/future health-state test does.

HPC/invariant check:

Observability path. Online must require positive, bounded liveness evidence from the expected worker population, not merely absence of a stale sample.

Why it matters:

Operators and automation receive a false-green forwarding state during worker startup/failure or status-contract drift, delaying failover and incident response.

Fix direction:

Require a nonempty heartbeat set and, preferably, the expected worker count from status/bindings. Reject timestamps after `now + smallSkew`, classify missing evidence as Unknown or Degraded, and add empty/future/partial-worker tests using one captured `now` value.

Labels:

`observability`, `false-green`, `userspace-dataplane`, `heartbeat`, `vsrx-parity`

Dedup note:

Distinct from `codex-review-161` F-070 (redundant status polling); no missing-heartbeat false-Online finding matched.
### M09

### C175-HC-099

Title: View-level `show log` can read any root-readable file directly under `/var/log`

Severity: Medium

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_show_system.go:770`:

```go
func (c *CLI) showDaemonLog(args []string) error {
	// If first arg is not a number, treat it as a syslog file name
	if len(args) > 0 {
		if _, err := strconv.Atoi(args[0]); err != nil {
			// Argument is a filename like "messages"
			filename := args[0]
			n := 50
			if len(args) > 1 {
				if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
```

`pkg/cli/cli_show_system.go:779`:

```go
				n = v
			}
		}
		logPath := filepath.Join("/var/log", filepath.Base(filename))
		out, err := exec.Command("tail", "-n", strconv.Itoa(n), logPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("read %s: %w", logPath, err)
		}
		fmt.Print(string(out))
```

`pkg/cli/permissions.go:151`:

```go
	switch action {
	case "show", "ping", "traceroute", "monitor":
		return config.PermView
	case "clear":
		return config.PermClear
	case "request", "test":
		return config.PermControl
```

Trace:

Any class with only `PermView` can run `show log auth.log`, `show log audit.log`, or another guessed basename. The root daemon executes `tail` against that direct child and returns content that the CLI account could not read from the filesystem. `filepath.Base` blocks traversal but supplies no configured-syslog allowlist.

Refutation attempt:

N/A (required only for Critical/High). I checked dispatch and permission classification: `show log` has no narrower gate, configured-file lookup, ownership check, or redaction stage.

HPC/invariant check:

Control-plane only. Confidentiality invariant: a show surface may expose only logs deliberately registered for that surface, regardless of the daemon's filesystem privilege.

Why it matters:

Read-only and config-viewer accounts can retrieve authentication, audit, package, or service logs containing usernames, source addresses, tokens, and operational details outside their intended firewall-view role.

Fix direction:

Resolve the requested name against active `system syslog file` configuration plus an explicit safe built-in set, open with `O_NOFOLLOW`, and reject everything else. Consider a separate permission for security/audit logs and bound `n`.

Labels:

security, information-disclosure, authorization, logging, vsrx-parity

Dedup note:

No matching root in the dedup index. Secret configuration redaction findings do not cover arbitrary host log files.

### C175-HC-100

Title: Watchdog control failures are hidden, including under `StrictWatchdog`

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`pkg/upgrade/kernel_linux.go:314`
```go
	timeout := watchdogTimeoutSecs()
	// WDIOC_SETTIMEOUT failure (driver doesn't support it) is non-fatal — fall
	// through to a keepalive write to at least pet whatever default timeout the
	// driver has; the keepalive is the minimal arm signal.
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.WDIOC_SETTIMEOUT), uintptr(unsafe.Pointer(&timeout)))
	return writeWatchdogKeepalive(fd)
```

Disarm reports every device error as success at `pkg/upgrade/kernel_linux.go:484`:

```go
func (s *realKernelSystem) DisarmWatchdog() error {
	if _, err := os.Stat("/dev/watchdog"); err != nil {
		return nil
	}
	fd, err := unix.Open("/dev/watchdog", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	_, _ = unix.Write(fd, []byte{'V'})
	_ = unix.Close(fd)
```

Trace:

Strict mode checks only a prior present/persistent status at `kernel_run.go:188-192`. Actual `ArmWatchdog` errors are always logged and ignored at lines 299-301, even in strict mode; ioctl timeout failure is discarded; promotion/revert calls `DisarmWatchdog`, whose implementation turns stat/open/write/close failure into nil, so callers cannot react or alert.

Refutation attempt:

BootNext still prevents an infinite candidate boot loop after an eventual reset, but it does not turn an unknown short watchdog timeout into the requested 600 seconds or prove disarm. `StrictWatchdog` is documented as fail-closed policy, making actual arm failure materially different from optional D2 behavior.

HPC/invariant check:

Boot transition path only. Invariant checked: strict recovery policy requires affirmative successful arm/configuration, and promotion must not claim disarm when the magic-close operation failed.

Why it matters:

A strict deployment can reboot into a candidate without a functioning watchdog, reset during firmware boot on an unchanged short timeout, or suffer repeated post-promotion resets while logs report successful cleanup.

Fix direction:

Check ioctl errno and returned timeout, propagate open/write/close errors, verify disarm where the driver supports status ioctls, and make `KernelRunner.Arm` abort actual arm failure when `StrictWatchdog` is true.

Labels:

upgrade, kernel, watchdog, fail-open, operational-safety

Dedup note:

Distinct from `fable-review-165` M-4, which concerns an OnFailure reboot unit; no indexed finding covers hidden watchdog I/O failures.
### A10-b4-12

### C175-HC-101

Title: XSK reproducers replace an existing XDP program and detach it instead of restoring it

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`test/xsk-repro/main.rs:285`
```rust
fn attach_xdp(ifindex: u32, prog_fd: i32) {
    let rc = unsafe { libbpf_sys::bpf_xdp_attach(ifindex as i32, prog_fd, 0, std::ptr::null()) };
    assert_eq!(rc, 0, "bpf_xdp_attach failed: {}", io::Error::last_os_error());
}

fn detach_xdp(ifindex: u32) {
    unsafe { libbpf_sys::bpf_xdp_attach(ifindex as i32, -1, 0, std::ptr::null()) };
}
```

Cleanup is only on the normal path at `test/xsk-repro/main.rs:77`:

```rust
    // Stop traffic
    traffic_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = traffic_handle.join();

    // Detach XDP
    detach_xdp(ifindex);
    eprintln!("  XDP detached");
```

Trace:

Attach flags are zero, so there is no `XDP_FLAGS_UPDATE_IF_NOEXIST` guard and no query/save of the prior attachment. Normal completion detaches to `-1`; any `expect`/assert panic after attach skips cleanup entirely. Both C reproducers use the same zero-flag attach/detach pattern.

Refutation attempt:

These tools are intended for isolated testing, but they neither enforce an isolated namespace nor refuse an occupied interface, and their usage only says "run as root." Accidental invocation on a live firewall interface is therefore an unguarded destructive action.

HPC/invariant check:

Setup/teardown only. Invariant checked: a diagnostic must not mutate pre-existing dataplane attachment state outside its owned test object.

Why it matters:

The test can immediately replace the firewall's redirect program and then leave the interface with no XDP program, causing traffic loss beyond the test window.

Fix direction:

Query current attachment, refuse unless empty by default, attach with update-if-noexist and expected-old-fd semantics, use a libbpf link/RAII guard, and restore the exact prior program/mode on every exit and signal.

Labels:

xsk-repro, operational-safety, xdp, cleanup

Dedup note:

No existing-XDP preservation finding appears in `dedup-index.md`.
### A10-b4-25

### C175-HC-102

Title: Zone detail omits and misorders wildcard zone-pair policies that affect the zone

Severity: Medium

Confidence: High

Source batch: A10-b4

Evidence:

`pkg/policymatch/zone_detail_summary.go:107`
```go
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, rather than dereferencing zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		if zpp.FromZone == zone || zpp.ToZone == zone {
			for i, pol := range zpp.Policies {
```

Runtime instead has a separate wildcard tier at `pkg/policymatch/policymatch.go:883`:

```go
	for setIdx, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		fromAny := zpp.FromZone == "any"
		toAny := zpp.ToZone == "any"
		if fromAny == toAny {
			continue // both-any (Tier 3) or neither (Tier 1) — not single-wildcard
		}
		applies := (fromAny && zpp.ToZone == q.ToZone) || (toAny && zpp.FromZone == q.FromZone)
```

Trace:

For zone `trust`, runtime applies `from any to untrust` to a `trust -> untrust` flow, but neither endpoint equals `trust`, so zone detail omits it. `any -> any` is omitted from every zone. Conversely, included exact and wildcard sets are printed in raw config order, while runtime always evaluates exact, then single-wildcard merged order, then both-any, regardless of set placement. Assigned summary tests contain exact pairs and globals only.

Refutation attempt:

The function contract says it lists policies "affecting this zone" in runtime evaluation tiers, not merely policies whose literal endpoint names the zone. The matcher comments and loops make wildcard applicability/order explicit; no caller post-processes the summary.

HPC/invariant check:

Display path only; no dataplane cost. Invariant checked: operational policy summaries enumerate every rule that can affect traffic involving the selected zone in actual first-match order.

Why it matters:

Operators can miss an effective permit/deny or infer the wrong winner while diagnosing firewall behavior, diverging from vSRX/Junos wildcard-policy expectations.

Fix direction:

Build summary entries using the same exact/single-any/both-any tier predicates as `Match`, parameterized for all concrete peers of the selected zone; deduplicate rules that affect multiple peers and label wildcard scope/order explicitly. Add wildcard-only and precedence tests.

Labels:

policy, cli, observability, vsrx-parity, wildcard

Dedup note:

Prior `codex-review-127` H01/H02 covered explicit-`any` **global** policies. That path is fixed; this finding is the still-distinct wildcard **zone-pair** filter and sub-tier ordering.
### A10-b4-15

### C175-HC-103

Title: Native GRE encap/decap performs heap allocations on the packet path

Severity: Low

Confidence: High

Source batch: A1-b2

Evidence:

`userspace-dp/src/afxdp/gre.rs:690-698` allocates a synthetic Ethernet frame for each decapped inner packet:

```rust
690         key,
691         key_present,
692     )?;
693     let (protocol, rel_l4_offset, payload_offset) =
694         parse_inner_protocol_and_offsets(inner_packet, inner_family)?;
695 
696     let mut synthetic = vec![0u8; 14 + inner_packet.len()];
697     synthetic[12..14].copy_from_slice(&inner_eth_proto.to_be_bytes());
698     synthetic[14..].copy_from_slice(inner_packet);
```

`userspace-dp/src/afxdp/gre.rs:833-838` allocates and copies the inner L3 slice before trimming:

```rust
833     let inner_l3 = match frame_l3_offset(inner_frame) {
834         Some(offset) => offset,
835         None => inner_meta.l3_offset as usize,
836     };
837     let inner_packet = inner_frame.get(inner_l3..)?.to_vec();
838     let inner_len = packet_trimmed_len(&inner_packet, inner_meta.addr_family)?;
```

`userspace-dp/src/afxdp/gre.rs:866-875` then allocates the GRE output frame:

```rust
866     let outer_l3_len = gre_encapped_outer_len(outer_ip_len, gre_len, inner_packet.len());
867     let outer_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
868     if outer_l3_len > outer_mtu {
869         GRE_ENCAP_DF_OVERSIZE_DROPS.fetch_add(1, Ordering::Relaxed);
870         return None;
871     }
872 
873     let frame_len = outer_eth_len + outer_ip_len + gre_len + inner_packet.len();
874     let mut out = vec![0u8; frame_len];
875     write_eth_header_slice(
```

Trace:

1. A native GRE decap packet reaches `try_native_gre_decap_from_frame`.
2. After parsing the outer and inner protocol offsets, the function allocates `synthetic` and copies the inner packet into it before parsing/session handling.
3. A native GRE encap packet reaches `encapsulate_native_gre_frame`.
4. The function copies the inner L3 slice into `inner_packet` with `to_vec`, trims it, then allocates `out` for the outer Ethernet/IP/GRE frame.
5. These allocations happen per GRE packet, not just during control-plane setup or tunnel state changes.

Refutation attempt:

Not required for Low. I checked the dedup index entry `AGY-171-21`, which is a low-confidence file-decomposition note for `gre.rs`; it does not call out these specific per-packet allocations. I also checked the orientation invariant that hot-path changes must preserve no per-packet allocation. The finding is therefore reported as a concrete performance debt, not as a correctness or memory-safety bug.

HPC/invariant check:

The packet path invariant says no per-packet allocation. This GRE path violates that invariant with one allocation on decap and two allocations/copies on encap. At tunnel rates, allocator contention and cache churn can add latency and jitter.

Why it matters:

GRE tunnels are data-plane features, not rare diagnostics. A workload carrying sustained GRE traffic pays allocator overhead per packet, while adjacent code such as WG uses explicit scratch/staging patterns for bounded packet buffers.

Fix direction:

Refactor GRE decap to parse the inner packet from borrowed slices or a reusable worker scratch buffer instead of materializing a synthetic `Vec`. Refactor GRE encap to trim using borrowed slices, then write directly into a reusable output frame/scratch area or UMEM frame. Add an allocation-count regression or microbenchmark for GRE encap/decap.

Labels:

`performance`, `hot-path`, `gre`, `allocation`, `test-gap`

Dedup note:

This is not a restatement of `AGY-171-21` because that entry is about whether `gre.rs` should be split. This finding is the concrete per-packet `Vec` allocation behavior at the listed lines.

### C175-HC-104

Title: Prefix-set benchmark name and production comment imply lookup coverage, but the gate only covers IPv4 trie build cost

Severity: Low

Confidence: High

Source batch: A1-b1

Evidence:

`userspace-dp/benches/prefix_set_lookup.rs:10-16` explicitly says the bench reimplements only allocation/build shape:

```rust
// Like `tx_kick_latency`, the daemon code lives in a bin crate
// (`xpf-userspace-dp` is a binary target with `pub(crate)`-only
// items), so this bench re-implements the bit-equivalent shape — a
// `TrieNode { covers: bool, children: [Option<Box<TrieNode>>; 2] }`
// inserted into via MSB→LSB walk. The test suite in
// `prefix_set.rs::tests` exercises the real types for correctness;
// this bench only gates the allocation cost.
```

Contract read, `userspace-dp/src/prefix_set.rs:27-32`, documents the same limitation and leaves threshold/lookup sweeps as follow-up:

```rust
/// `benches/prefix_set_lookup.rs` gates the worst-case build cost
/// (`Box<TrieNode>` allocation footprint for 256 random /32
/// prefixes) at p95 ≤ 2 ms — it does NOT sweep thresholds yet.
/// A threshold-sweep + lookup-cost microbench is a follow-up if
/// the constant turns out to be poorly tuned in production traces.
pub(crate) const PREFIX_SET_LINEAR_MAX: usize = 16;
```

Trace:

Not required for Low severity. The practical path is: a change regresses `PrefixSetV4::contains`, `PrefixSetV6::contains`, or the linear-vs-trie threshold; this bench still passes because it only times construction of 256 random IPv4 /32 prefixes.

Refutation attempt:

I checked the production trie insertion code and confirmed the bench mirrors the V4 build shape. That refutes a build-model bug, but it does not cover lookup latency, IPv6's 128-bit path, or threshold selection.

HPC/invariant check:

The packet-path invariant is bounded, allocation-free prefix membership lookup. This bench protects commit/build allocation cost only; it does not measure per-packet lookup work.

Why it matters:

Prefix sets back policy/address matching. A lookup regression can add packet-path latency even while this benchmark remains green.

Fix direction:

Either rename the bench to make the scoped build-cost gate explicit, or add lookup microbenches for V4 and V6 covering linear size 0..=16, just-over-threshold trie sizes, dense shared-prefix sets, and worst-case misses. Keep the existing p95 build gate as a separate acceptance check.

Labels:

performance, test-coverage, packet-path

Dedup note:

The dedup index has policy and host-inbound behavior findings, but not prefix-set benchmark coverage drift.

### C175-HC-105

Title: WireGuard data and cookie-reply parsers accept non-canonical reserved bytes

Severity: Low

Confidence: High

Source batch: A1-b3

Evidence:

userspace-dp/src/afxdp/wg/framing.rs:79

```rust
79	pub(crate) fn parse_data_header(buf: &[u8]) -> Option<ParsedDataHeader<'_>> {
80	    if buf.len() < WG_DATA_HEADER_LEN {
81	        return None;
82	    }
83	    if buf[0] != WG_TYPE_DATA {
84	        return None;
85	    }
86	    // Bytes 1..4 are reserved and transmitted as zero by
87	    // `encode_data_header`. We accept non-zero values here for
88	    // interoperability robustness.
```

userspace-dp/src/afxdp/wg/cookie.rs:645

```rust
645	    pub(crate) fn decrypt_cookie_reply(
646	        reply: &[u8],
647	        responder_static_pub: &[u8; WG_KEY_LEN],
648	        aad_mac1: &[u8],
649	    ) -> Option<[u8; WG_COOKIE_LEN]> {
650	        if reply.len() != WG_MSG_COOKIE_LEN || reply[0] != WG_TYPE_COOKIE {
651	            return None;
652	        }
```

userspace-dp/src/afxdp/wg/handshake.rs:216

```rust
216	    // WG's message_type is a 32-bit little-endian word: a canonical
217	    // initiation is exactly 0x00000001, i.e. type byte = 1 AND the three
218	    // reserved bytes = 0. wireguard-go / kernel WG read the full u32 and
219	    // reject a non-canonical high byte, so we do too (strict parse). This is
220	    // also belt-and-suspenders: mac1 already covers bytes [0..116] including
221	    // the reserved bytes, so a forged non-zero-reserved datagram would fail
222	    // mac1 regardless — but rejecting it up front keeps us byte-strict.
223	    if !is_canonical_type(msg, WG_TYPE_INITIATION) {
224	        return Err(FramingError::BadType);
```

Trace:

1. A peer has a valid transport session or has sent a valid cookie reply.
2. An on-path device or a noncanonical peer changes only bytes 1..3 in a type-4 transport data datagram while leaving the type byte, receiver index, counter, ciphertext, and tag unchanged.
3. `WgEngine::try_decap` calls `parse_data_header`; the parser checks length and `buf[0]` only, then derives receiver index and counter starting at byte 4.
4. WireGuard transport AEAD does not authenticate those reserved header bytes as associated data, so the altered reserved bytes do not prevent payload decryption. The packet can be accepted and delivered if the receiver index, counter, replay window, tag, and AllowedIPs checks pass.
5. The same canonicality gap exists on type-3 cookie replies: `decrypt_cookie_reply` checks length and `reply[0]` only, while the reserved bytes are outside the AEAD AAD/ciphertext. A noncanonical but otherwise valid cookie reply is accepted and can refresh the cookie state.
6. The handshake parser is stricter and explicitly documents that kernel WG/wireguard-go read the full 32-bit type word and reject nonzero high bytes.

Refutation attempt:

This does not allow unauthenticated payload forgery: changing receiver index, counter, ciphertext, nonce, or tag still fails lookup, replay, or AEAD checks. The code also documents the data-header leniency as an interoperability choice. That keeps severity low. The concern is still credible because the implementation already requires canonical message types on handshake packets for kernel/wireguard-go parity, and accepting unauthenticated reserved-bit mutations in transport/cookie packets is a fail-open parser behavior rather than a necessary fast-path optimization.

HPC/invariant check:

The fail-closed fix is three fixed byte comparisons in the hot transport header parse and the same constant-time shape in the cookie reply path. It adds no allocation, no variable loop, no cache-unfriendly data dependency, and can share the existing malformed-header/cookie-ignore counters.

Why it matters:

The userspace dataplane is the only runtime dataplane, and strict packet parsing is part of vSRX parity and fail-closed behavior. Accepting noncanonical reserved bytes creates a protocol-compliance gap, permits undetected header mutation by an on-path device, and makes data/cookie handling inconsistent with the strict handshake parser.

Fix direction:

Require bytes 1..3 to be zero in `parse_data_header` and in cookie-reply parsing before decrypting/storing the cookie. Add regression tests that nonzero reserved bytes are rejected for type-4 data and type-3 cookie replies. If leniency is intentionally required, put it behind an explicit compatibility flag and counter rather than making the default dataplane accept noncanonical packets.

Labels:

wireguard, packet-parsing, fail-closed, vsrx-parity

Dedup note:

Searched the provided dedup index for WireGuard reserved/canonical/framing/cookie-reply/data-header coverage. Existing WireGuard dedup items cover AllowedIPs overlap/misconfiguration, TAI64N high-water reset, static key carriers, responder rekey/session issues, cookie DoS, and endpoint parsing, but I did not find this reserved-byte canonicality issue.

### C175-HC-106

Title: NAT address-set members backed by dynamic feeds are still not resolved

Severity: Low

Confidence: High

Source batch: A6-b2

Evidence:

The resolver explicitly handles direct feed-backed NAT address names and explicitly leaves nested feed members unresolved:

```
pkg/dataplane/userspace/nat.go:50-68
    50 // The recursive case — an address-SET whose member is feed-backed — is NOT
    51 // resolved here (the static resolveUserspaceAddressBookEntry expander poisons
    52 // the whole set on an unresolvable feed member and never consults the overlay).
    53 // #3294 closed this for the SECURITY-POLICY path (the feed-aware
    54 // expandBookNameRecursive now merges nested feed members into the policy
    55 // address-book row), but the NAT path was deliberately left out of #3294 scope
    56 // (the converged plan, constraint 5 / open-question 4) and remains a tracked
    57 // residual. A DIRECT `match ...-address-name <feed-name>` reference is fully
    58 // resolved here, which was the #3303 NAT-side gap.
    59 func resolveNATAddressNamePrefixes(cfg *config.Config, feedOverlay map[string][]string, name string) []string {
    60     var out []string
    61     if values, ok := resolveUserspaceAddressBookEntry(cfg, name); ok {
    62         out = append(out, values...)
    63     }
    64     if feeds := feedOverlay[name]; len(feeds) > 0 {
    65         out = append(out, feeds...)
    66     }
    67     return out
    68 }
```

The current test file proves direct feed references and direct static+feed unions only:

```
pkg/dataplane/userspace/nat_feed_overlay_3303_test.go:9-26
     9 // #3303: NAT `match {source,destination}-address-name` references must resolve
    10 // the dynamic-address feed overlay (#2049), exactly as the policy/address-book
    11 // path does. Before the fix the snapshot builder threaded feedOverlay into the
    12 // policy and address-book builders but called the NAT builders with NO overlay,
    13 // so a NAT rule scoped to a feed-backed address-name resolved STATIC-ONLY and
    14 // matched nothing on live feed content — contradicting docs/feature-gaps.md's
    15 // claim that feeds are enforced via "policy/NAT address-name bindings".
    ...
    21 // nat.go + builder.go to the pre-#3303 state makes every assertion below RED:
    22 //   - SNAT source-address-name falls back to the raw "bad-feed" token
    23 //     (fail-closed, no feed prefix),
    24 //   - SNAT destination-address-name likewise,
    25 //   - DNAT destination-address-name resolves nothing -> the rule installs no
    26 //     table row at all.
```

```
pkg/dataplane/userspace/nat_feed_overlay_3303_test.go:194-224
   194 // TestNATAddressNameUnionsStaticBookAndFeedOverlay: a name that exists BOTH as a
   195 // static book entry and as a feed binding resolves to the union, mirroring the
   196 // policy address-book bucket merge. This guards against a revert that resolves
   197 // only one source.
   198 func TestNATAddressNameUnionsStaticBookAndFeedOverlay(t *testing.T) {
   ...
   214     overlay := map[string][]string{"mixed": {"198.51.100.0/24"}}
   215
   216     snap := natFeedSnapHelper(t, cfg, overlay)
   217     got := snatSourceAddrs(snap, "union")
   218     if !contains(got, "10.10.0.0/16") {
   219         t.Fatalf("union must keep the static book prefix, got %v", got)
   220     }
   221     if !contains(got, "198.51.100.0/24") {
   222         t.Fatalf("union must add the feed prefix, got %v #3303", got)
   223     }
   224 }
```

Trace:

1. Operator configures an address-set `bad-set` containing a dynamic-address feed-backed member `bad-feed`.
2. A NAT rule uses `match source-address-name bad-set` or `match destination-address-name bad-set`.
3. `resolveNATAddressNamePrefixes` first calls the static `resolveUserspaceAddressBookEntry(cfg, "bad-set")`; that path cannot consult `feedOverlay` for nested feed members and returns no concrete feed prefixes.
4. It then checks `feedOverlay["bad-set"]`, but the overlay is keyed by the direct dynamic address name (`bad-feed`), not by the containing static address-set.
5. The NAT builder therefore emits no feed prefixes for the nested set. For SNAT this falls back to an unparseable raw token and matches nothing; for DNAT the destination entry is skipped. This is fail-closed, but it is a vSRX/policy parity gap: equivalent security-policy address-set usage is feed-aware.

Refutation attempt:

- Confirmed direct feed references are covered and work in `nat_feed_overlay_3303_test.go`.
- Confirmed policy address-book table uses `expandBookNameRecursive` with feed overlay, so this gap is NAT-specific rather than a global address-book limitation.
- Searched dedup index for nested feed/address-set NAT wording; no matching finding was present. This is documented in source comments as a tracked residual, not a newly hidden code path.

HPC/invariant check:

The relevant invariant is cross-feature address-name parity: a named address-set should expand the same member prefixes for policy and NAT consumers unless NAT deliberately documents a narrower support contract. Current NAT direct-name and policy recursive paths disagree, so a single operator-authored address object has different dataplane meaning across subsystems.

Why it matters:

This does not widen traffic; the current failure is fail-closed/no-match. It still breaks documented "policy/NAT address-name bindings" behavior for operators who group feed-backed objects through address-sets, and it can silently disable intended NAT rules after HA sync or lenient reload when the direct feed tests remain green.

Fix direction:

- Replace NAT's static `resolveUserspaceAddressBookEntry` call with a feed-aware recursive expander shared with policy address-book expansion, or add a NAT-specific recursive resolver that merges `feedOverlay` for nested members.
- Preserve existing fail-closed behavior for unrepresentable non-feed address-set members.
- Add SNAT and DNAT tests where `match {source,destination}-address-name` references an address-set containing a feed-backed member, including mixed static+feed and feed-only cases.

Labels:

- a6-b2
- nat
- dataplane-boundary
- vsrx-parity
- dynamic-address
- address-book
- test-gap

Dedup note:

Direct NAT feed overlay #3303 is already tested and not re-reported. This finding is specifically the recursive address-set feed member case, which the source comments call a residual and which was not present in the dedup index.

### C175-HC-107

Title: Negative userspace queue, binding, and injection IDs wrap to uint32 before helper control

Severity: Low

Confidence: High

Source batch: A6-b1 + A8-b2

Evidence:

**A6-b1 component**

`pkg/dataplane/userspace/control.go:29`

```go
func ParseQueueCommand(args []string) (queueID uint32, registered, armed bool, err error) {
	if len(args) != 3 || args[0] != "queue" {
		return 0, false, false, fmt.Errorf("usage: %s", QueueUsage)
	}
	queueNum, err := strconv.Atoi(args[1])
	if err != nil {
		return 0, false, false, fmt.Errorf("invalid queue: %s", args[1])
	}
	registered, armed, err = ParseRegistrationOperation(args[2])
```

`pkg/dataplane/userspace/control.go:37`

```go
	registered, armed, err = ParseRegistrationOperation(args[2])
	if err != nil {
		return 0, false, false, fmt.Errorf("usage: %s", QueueUsage)
	}
	return uint32(queueNum), registered, armed, nil
}
```

`pkg/dataplane/userspace/control.go:44`

```go
func ParseBindingCommand(args []string) (slot uint32, registered, armed bool, err error) {
	if len(args) != 4 || args[0] != "binding" || args[1] != "slot" {
		return 0, false, false, fmt.Errorf("usage: %s", BindingUsage)
	}
	slotNum, err := strconv.Atoi(args[2])
	if err != nil {
		return 0, false, false, fmt.Errorf("invalid slot: %s", args[2])
	}
```

`pkg/dataplane/userspace/control.go:52`

```go
	registered, armed, err = ParseRegistrationOperation(args[3])
	if err != nil {
		return 0, false, false, fmt.Errorf("usage: %s", BindingUsage)
	}
	return uint32(slotNum), registered, armed, nil
}
```

`pkg/dataplane/userspace/control_test.go:55`

```go
func TestParseQueueAndBindingCommands(t *testing.T) {
	queueID, registered, armed, err := ParseQueueCommand([]string{"queue", "3", "arm"})
	if err != nil {
		t.Fatalf("ParseQueueCommand error = %v", err)
	}
	if queueID != 3 || !registered || !armed {
		t.Fatalf("ParseQueueCommand = (%d,%t,%t), want (3,true,true)", queueID, registered, armed)
	}
```

Minimal contract read, parallel gRPC action path:

`pkg/grpcapi/server_diag_system_action.go:444`

```go
queueID, err := strconv.Atoi(parts[0])
if err != nil {
	return nil, status.Errorf(codes.InvalidArgument, "invalid userspace queue: %s", parts[0])
}
registered, armed, err := dpuserspace.ParseRegistrationOperation(parts[1])
if err != nil {
	return nil, status.Error(codes.InvalidArgument, err.Error())
}
statusAfter, err := provider.SetQueueState(uint32(queueID), registered, armed)
```

`pkg/grpcapi/server_diag_system_action.go:469`

```go
slot, err := strconv.Atoi(parts[0])
if err != nil {
	return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
}
registered, armed, err := dpuserspace.ParseRegistrationOperation(parts[1])
if err != nil {
	return nil, status.Error(codes.InvalidArgument, err.Error())
}
statusAfter, err := provider.SetBindingState(uint32(slot), registered, armed)
```

**A8-b2 component**

`pkg/grpcapi/server_diag_system_action.go:394`
```go
			slot, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
			}
			mode := parts[1]
			statusNow, err := provider.Status()
			if err != nil {
```

`pkg/grpcapi/server_diag_system_action.go:403`
```go
			extra, err := dpuserspace.DecodeInjectPacketTarget(req.Target)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			injectReq, err := dpuserspace.BuildInjectPacketRequest(uint32(slot), mode, extra, statusNow)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
```

`pkg/grpcapi/server_diag_system_action.go:444`
```go
			queueID, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid userspace queue: %s", parts[0])
			}
			registered, armed, err := dpuserspace.ParseRegistrationOperation(parts[1])
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			statusAfter, err := provider.SetQueueState(uint32(queueID), registered, armed)
```

`pkg/grpcapi/server_diag_system_action.go:469`
```go
			slot, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
			}
			registered, armed, err := dpuserspace.ParseRegistrationOperation(parts[1])
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			statusAfter, err := provider.SetBindingState(uint32(slot), registered, armed)
```

`userspace-dp/src/server/handlers/queue.rs:21`
```rust
    let mut found = false;
    let mut registration_changed = false;
    for binding in guard
        .status
        .bindings
        .iter_mut()
        .filter(|b| b.queue_id == queue_req.queue_id)
```

`userspace-dp/src/server/handlers/queue.rs:48`
```rust
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown queue {}", queue_req.queue_id);
    }
}
```

Trace:

**A6-b1 component**

1. Operator or automation submits a manual userspace control command with a negative index, e.g. `request chassis cluster data-plane userspace queue -1 arm` or a gRPC action `userspace-binding:-1:arm`.
2. `strconv.Atoi` accepts `-1`.
3. The Go boundary converts the signed value to `uint32`, producing `4294967295`.
4. The control request is sent to the userspace helper as an apparently valid unsigned JSON ID.
5. The helper currently rejects the unknown queue/binding, so this does not appear to become memory corruption or direct forwarding failure, but the control-plane boundary still accepts an impossible signed input and turns an input-validation failure into a helper-side failed precondition.

**A8-b2 component**

A caller sends `userspace-queue:-1:arm`, `userspace-binding:-1:arm`, or `userspace-inject:-1:valid`. `strconv.Atoi` accepts `-1`; the handler then casts to `uint32`, producing `4294967295`, and sends that value to the userspace control provider. The current helper searches known queues/bindings and rejects unknown values, so the operation fails closed today, but the bad input crosses the API boundary and returns as a backend/precondition failure rather than an immediate `InvalidArgument`.

Refutation attempt:

**A6-b1 component**

- Checked the immediate CLI parser tests: `TestParseQueueAndBindingCommands` only covers positive queue `3` and binding slot `7`.
- Checked the gRPC action parser because it does not call `ParseQueueCommand` / `ParseBindingCommand`; it repeats the same signed `Atoi` plus `uint32(...)` pattern.
- Checked userspace helper handlers: the Rust side looks up queues/bindings by `u32` and returns an unknown-ID error rather than indexing directly into an array. That downgrades impact to Low, but it does not refute the Go boundary bug.

**A8-b2 component**

I followed the call into the userspace helper. The current Rust queue/binding/inject handlers reject unknown IDs, so I do not see a present state mutation for `-1`; that is why this is Low severity. The Go parser is still accepting a value that cannot be a valid slot/queue ID and relies on downstream rejection.

HPC/invariant check:

**A6-b1 component**

- Human: manual CLI and gRPC action inputs should reject negative queue IDs and binding slots at the Go control-plane boundary.
- Protocol: queue and binding IDs are unsigned helper control fields, so signed parse results must not be narrowed without a range check.
- Code: both Go parsers accept negative values and convert directly to `uint32`.

**A8-b2 component**

Numeric identifiers accepted at the gRPC/SystemAction boundary should be range-checked before unsigned conversion. Signed-to-unsigned wrap should not be part of the helper contract.

Why it matters:

**A6-b1 component**

This is a control-plane/dataplane boundary hygiene issue. Manual HA and userspace recovery commands are often used during degraded conditions; impossible queue/binding identifiers should fail fast with `InvalidArgument` / usage errors before they become helper requests with wrapped IDs. The current behavior also leaves a regression gap if future helper code changes from lookup-based rejection to index math.

**A8-b2 component**

This creates schema drift and brittle trust-boundary behavior. Future helper changes, sentinel IDs, or wider queue spaces could accidentally give wrapped values meaning, and current clients receive the wrong error class for malformed input.

Fix direction:

**A6-b1 component**

Parse queue IDs and binding slots with `strconv.ParseUint(..., 10, 32)` or add explicit `>= 0` and `<= math.MaxUint32` checks before narrowing. Apply the same rule to `pkg/grpcapi/server_diag_system_action.go`. Add negative-value tests to `pkg/dataplane/userspace/control_test.go` and the gRPC system-action tests.

**A8-b2 component**

Parse with `strconv.ParseUint(..., 10, 32)` or explicitly reject `slot < 0` and `queueID < 0` before casting. Mirror the same fix in `pkg/dataplane/userspace/control.go` for CLI parity, and add negative ID tests for `userspace-inject`, `userspace-queue`, and `userspace-binding`.

Labels:

control-plane-boundary, userspace-control, integer-wrap, queue-binding-index, test-gap, `api`, `system-action`, `input-validation`, `integer-conversion`, `test-gap`

Dedup note:

Merged the A6 Go-manager and A8 gRPC entrypoint reports because both have the same root cause: signed identifiers are narrowed to uint32 before the userspace helper boundary. Neither root appears in the prior-campaign index.

### C175-HC-108

Title: Daemon warm-reconnect session-sync readiness path is named as tested but only exercises cold-start/no-panic behavior

Severity: Low

Confidence: High

Source batch: A7-b2

Evidence:

`pkg/daemon/session_sync_readiness_test.go:148-190` claims to verify warm reconnect preservation, then documents that it cannot set `BulkEverCompleted` and only verifies the cold-start/no-panic path:

```go
// TestReconnectAfterBulkPreservesPrimedState verifies that a reconnect
// after a completed bulk exchange does not reset bulk-primed state or
// drop sync readiness (#466).
func TestReconnectAfterBulkPreservesPrimedState(t *testing.T) {
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	d := &Daemon{
		cluster:          newClusterManager(false),
		sessionSync:      ss,
```

```go
	// Without BulkEverCompleted set, reconnect is still a "cold start" from
	// the daemon's perspective. The daemon relies on the SessionSync's
	// bulkEverCompleted flag which is set in the receiveLoop.
	// For this unit test, just verify the cold-start vs warm-start paths.

	// Simulate disconnect then reconnect. Since we can't set the cluster
	// package's bulkEverCompleted flag from daemon-layer tests, this is
	// treated as a cold start. The warm-reconnect path (where primed state
	// is preserved) is covered by cluster-level tests in sync_test.go:
```

`pkg/daemon/daemon_ha_sync.go:54-64,106-114` shows the daemon behavior depends on `BulkEverCompleted()` at both connect and disconnect:

```go
	// Determine whether this is a true cold start or a routine reconnect.
	// A cold start means no bulk sync has ever completed during this
	// daemon's lifetime — the peer (or we) genuinely started from scratch.
	// On a routine reconnect after a brief network blip, the sessions are
	// already synced; preserve the primed state and sync readiness (#466).
	coldStart := d.sessionSync == nil || !d.sessionSync.BulkEverCompleted()

	if coldStart {
```

```go
	// On disconnect after a completed bulk exchange, preserve primed state
	// and sync readiness. The sessions are still in the BPF maps — a
	// subsequent reconnect will resume incremental sync without needing a
	// full bulk transfer (#466).
	wasEverPrimed := d.sessionSync != nil && d.sessionSync.BulkEverCompleted()
	if !wasEverPrimed {
		d.syncBulkPrimed.Store(false)
```

The cited cluster-level test only proves the flag survives disconnect inside `pkg/cluster`, not that daemon callbacks preserve readiness when the flag is true:

```go
// TestBulkEverCompletedSurvivesDisconnect verifies that bulkEverCompleted
// persists across disconnect/reconnect cycles.
func TestBulkEverCompletedSurvivesDisconnect(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.bulkEverCompleted.Store(true)

	// Simulate a disconnect.
```

Trace:

1. Warm reconnect correctness requires `d.sessionSync.BulkEverCompleted()` to return true.
2. On disconnect, daemon should preserve `syncBulkPrimed`, `syncPeerBulkPrimed`, and cluster sync readiness instead of clearing readiness.
3. On reconnect, daemon should not re-arm the sync-ready timeout or restart bulk priming as a cold start.
4. The daemon-package test leaves `BulkEverCompleted()` false, then calls disconnect/connect and does not assert final readiness or primed state after reconnect.
5. A future regression in `onSessionSyncPeerConnected` or `onSessionSyncPeerDisconnected` could reset readiness on warm reconnect while this test still passes.

Refutation attempt:

Not required for Low severity. I checked the referenced cluster tests: they cover `SessionSync.BulkEverCompleted()` persistence, but not the daemon callback side effects that depend on that value. The gap survives as daemon-layer coverage, not as a production defect claim.

HPC/invariant check:

No dataplane hot-path invariant. HA lifecycle invariant affected: a routine session-sync reconnect after a completed bulk exchange must not transiently mark the node unready or trigger avoidable takeover hold/retry behavior.

Why it matters:

This is a failover-readiness regression trap. The test name and comment say the warm path is pinned, but the assertions do not exercise the warm branch. That can hide a regression that turns harmless sync reconnects into readiness drops or timeout-based release behavior.

Fix direction:

Add a daemon-package test seam or cluster test hook to create a `SessionSync` with `bulkEverCompleted=true`, then assert disconnect and reconnect preserve `syncBulkPrimed`, `syncPeerBulkPrimed`, and `cluster.IsSyncReady()`, and do not arm/release readiness via timeout. Rename the current test if it remains a no-panic cold-start cycle.

Labels:

`ha`, `session-sync`, `readiness`, `test-gap`

Dedup note:

Not a duplicate of prior HA session-sync data-plane findings. This is specifically a daemon-layer test gap around the `BulkEverCompleted` warm-reconnect branch; the dedup index entries on session sync focus event ordering, frame limits, and transfer correctness.

### A7-b2-03

### C175-HC-109

Title: RPM probe-pin band clear drops list/delete errors and always returns nil

Severity: Low

Confidence: High

Source batch: A7-b3

Evidence:

`pkg/routing/probe_pin.go:245`

```go
   245	func (p *probePinManager) clear() error {
   246		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
   247			rules, err := p.ops.RuleList(family)
   248			if err != nil {
   249				continue
   250			}
   251			for _, r := range rules {
   252				if r.Priority >= config.ProbeRulePriorityBase &&
   253					r.Priority < config.ProbeRulePriorityBase+config.ProbeTableCount {
   254					if err := p.ops.RuleDel(&r); err != nil {
```

`pkg/routing/probe_pin.go:266`

```go
   266				for i := range routes {
   267					if err := p.ops.RouteDel(&routes[i]); err != nil {
   268						slog.Debug("failed to delete stale probe pin route",
   269							"table", table, "err", err)
   270					}
   271				}
   272			}
   273		}
   274		return nil
```

`pkg/routing/routing.go:197`

```go
   197	// ClearProbePins removes all probe pin rules and flushes the reserved
   198	// probe tables. Run at daemon startup so a crashed daemon never leaks
   199	// stale pins.
   200	func (m *Manager) ClearProbePins() error { return m.probePin.clear() }
```

Trace:

Not required for a Low-severity finding. The direct control-path consequence is described in Evidence and Why it matters.

Refutation attempt:

Not required at this severity. During merge, the coordinator checked the cited caller/guard path and found no condition that invalidated the reported behavior.

HPC/invariant check:

Probe-pin cleanup invariant partially violated: startup/reapply cleanup is documented as the backstop for stale pinned rules/routes, but clear failures are neither returned to `ClearProbePins` nor represented in the per-pin failure map.

Why it matters:

RPM next-hop pins feed HA/ip-monitoring decisions. A stale fwmark rule or reserved-table host route that cannot be listed/deleted can survive startup or reprogramming with no operator-visible error from this layer. Existing per-pin install failures catch many collision cases, but pure cleanup failures outside the current desired pin set are silent.

Fix direction:

Aggregate `RuleList`, `RuleDel`, `RouteListFiltered`, and `RouteDel` failures from `clear()` and return them, while preserving best-effort cleanup of other families/tables. Add tests equivalent to `TestRulesClearListErrorSurfaced` and `TestPBRApplyClearDelFailureSurfaced` for probe pins.

Labels:

`A7-b3`, `routing`, `rpm`, `probe-pin`, `cleanup`, `observability`

Dedup note:

Distinct from the #1895 probe-pin install/ErrProbeSetup work in the dedup log. That work reports per-pin install failures; this is the cleanup band returning nil after failed stale-state removal.

### C175-HC-110

Title: ShowText test-routing accepts duplicate selectors with silent last-wins

Severity: Low

Confidence: High

Source batch: A8-b2

Evidence:

`pkg/grpcapi/server_show_routes_text.go:197`
```go
				}
				continue
			}
			switch parts[0] {
			case "dest":
				dest = parts[1]
			case "instance":
				instance = parts[1]
			default:
```

`pkg/grpcapi/server_show_firewall.go:226`
```go
	// #3709: reject a DUPLICATE selector key (e.g. `from=trust,from=dmz`). The
	// switch below re-assigns fromZone/dstPort/... on a repeated key, silently
	// LAST-WINning, so the gRPC-text simulator answered for a DIFFERENT packet
	// than the operator typed — and it disagreed with REST (first-win) on WHICH
	// value survived. There is no correct silent pick, so a repeat is a reported
	// error, matching the strict CLI parser (policymatch.ParseSelectorArgs).
	seen := make(map[string]bool)
```

`pkg/grpcapi/server_show_test_routing_unknownkey_4589_test.go:31`
```go
		{
			name:       "typo'd instance key",
			topic:      "test-routing:dest=10.0.0.0/24,instnace=dmz",
			wantSubstr: `unknown selector "instnace"`,
		},
		{
			name:       "malformed segment",
```

Trace:

A caller sends `ShowText{Topic: "test-routing:dest=192.0.2.1,instance=blue,instance=prod"}` or repeats `dest`. The parser validates malformed and unknown keys, but for known keys it assigns directly into `dest` or `instance` every time. The last value silently wins, so the diagnostic route lookup can run against a different destination or VRF than the operator intended.

Refutation attempt:

The routing parser has the #4589 malformed/unknown selector guard, but unlike the adjacent `test-policy` parser it does not allocate a `seen` map or reject repeated known keys. The current routing test covers unknown and malformed selectors plus a valid selector, not duplicates.

HPC/invariant check:

The selector grammar invariant established for `test-policy` is that malformed, unknown, empty, and duplicate selectors are reported rather than silently changing the query. `test-routing` comments say it mirrors that hardening, but duplicate-key parity is missing.

Why it matters:

This is a diagnostic integrity issue. It can mislead an API or remote-CLI user during routing/firewall investigation by answering for the last repeated selector instead of rejecting ambiguous input.

Fix direction:

Add `seen := map[string]bool{}` in `showTestRouting`, reject repeated known keys with the same error shape used by `showTestPolicy`, and add tests for duplicate `dest` and duplicate `instance`.

Labels:

`api`, `grpc-text`, `input-validation`, `diagnostic`, `test-gap`

Dedup note:

The dedup index includes prior `test-policy` duplicate-key work (#3709), but no exact duplicate for `test-routing`. This finding is the analogous gap in a different ShowText parser.
### F4: Userspace SystemAction IDs parse negative values before uint32 conversion

### C175-HC-111

Title: Count-bounded invalid feed samples still retain and log about 5 MiB per feed

Severity: Low

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/feeds/feeds.go:33`
```go
33	const maxLineBytes = 1 << 20 // 1 MiB
34
35	// maxInvalidSample bounds how many distinct malformed lines are retained for
36	// operator display (#2993). A degraded feed records the total invalid-line
37	// count plus a small verbatim sample so an operator can identify the bad lines
38	// without the sample growing unbounded for a wholesale-garbage body.
39	const maxInvalidSample = 5
40
41	// maxFeedBodyBytes caps the total HTTP response body a single feed fetch will
```

Trace:

Scanner accepts malformed lines up to roughly 1 MiB and `parseFeed` retains the first five verbatim. `installSnapshot` keeps them for the snapshot, `AllFeeds` copies them, and a changed degraded feed sends the full slice to `slog.Warn`. The test named `TestInvalidSampleIsBounded` checks only element count using tiny strings.

Refutation attempt:

The 32 MiB body cap bounds one fetch, so this is not unbounded OOM from one feed. It does not make the claimed sample small: multiple feeds can retain several MiB each, API reads copy it, and changing bodies can repeatedly submit multi-megabyte journal records.

HPC/invariant check:

Feed refresh/status path. The invariant is that diagnostic samples are bounded in bytes as well as count and cannot dominate logs or status allocations.

Why it matters:

A broken or controlled provider can create persistent memory pressure and expensive/truncated log records while staying inside all advertised feed limits.

Fix direction:

Cap each sample to a small escaped prefix (for example 256 bytes), cap aggregate sample bytes, and include original byte length/hash for diagnosis. Test multi-byte/near-1-MiB malformed lines, AllFeeds copy size, and log field size.

Labels:

`feeds`, `resource-bounds`, `logging`, `telemetry`

Dedup note:

No invalid-sample byte-bound finding appears in the supplied index.
### A9-b1-L03

### C175-HC-112

Title: Packet-count fallback duration overflows and can place flow start after flow end

Severity: Low

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/flowexport/manager.go:820`
```go
820			created := time.Unix(int64(rec.Created), int64(rec.CreatedNanos))
821			// Guard against a created stamp at or after the close time (clock skew
822			// across the monotonic→wall conversion): clamp to the EndTime so the
823			// flow never reports a negative duration.
824			if created.After(rec.Time) {
825				return rec.Time, false
826			}
827			return created, false
828		}
829		return rec.Time.Add(-estimateSessionDuration(rec.SessionPkts, proto)), true
```

Trace:

Old/synthesized close frames with `Created == 0` use the packet heuristic. Multiplication overflows signed `time.Duration` above about 92.2 billion TCP packets (184.5 billion non-TCP), values reachable by long/high-rate sessions or imported HA/clear records. A negative wrapped duration is subtracted, moving StartTime after EndTime. The real-created branch has a future clamp; fallback does not. NetFlow then emits first-switched after last-switched, while IPFIX emits contradictory absolute milliseconds.

Refutation attempt:

Current tests use at most nine packets. Packet counters are uint64 end to end and no producer-side bound was found. The estimated-duration counter provides observability but does not validate the result.

HPC/invariant check:

Cold session-close export. The invariant is saturating monotonic time arithmetic: `StartTime <= EndTime` for every record, with no unchecked uint64-to-Duration multiplication.

Why it matters:

Rare high-volume fallback records poison duration and ordering analytics and may be rejected by collectors, exactly on legacy/HA recovery paths where telemetry is already important.

Fix direction:

Compute with checked/saturating arithmetic, cap the heuristic to a defensible maximum age, and clamp the resulting start to `[deviceBootOrEpoch, EndTime]`. Count overflow/cap separately. Add boundary tests around `MaxInt64/(100ms)` and `MaxInt64/(50ms)` for both exporters.

Labels:

`flow-export`, `integer-overflow`, `timestamps`, `record-correctness`, `vsrx-parity`

Dedup note:

No packet-count duration overflow appears in the index. Prior flow-start findings concern real-created clock skew and daemon boot anchoring.

### C175-HC-113

Title: TimeTicks values become non-canonical signed BER after 248.55 days of uptime

Severity: Low

Confidence: High

Source batch: A9-b1

Evidence:

`pkg/snmp/agent.go:1057`
```go
1057		// Strip leading zeros but keep at least one byte.
1058		// If high bit set, prepend zero for unsigned.
1059		for len(buf) > 1 && buf[0] == 0 {
1060			buf = buf[1:]
1061		}
1062		if buf[0]&0x80 != 0 {
1063			buf = append([]byte{0}, buf...)
1064		}
1065		return buf
```

Trace:

`sysUpTime` and v1/v2 link traps convert uptime to hundredths and pass it here. At `0x80000000` ticks (248.55 days), the first content octet has its sign bit set. Counter32/64 correctly prepend `0x00`; TimeTicks does not, so its INTEGER-derived application value is encoded as negative/non-canonical until wrap at roughly 497 days.

Refutation attempt:

Existing tests exercise 100 ticks and one hour, both below the sign boundary. The sibling unsigned encoders demonstrate the required leading-zero rule; no downstream wrapper alters the value bytes.

HPC/invariant check:

Cold SNMP encoding. Wire invariant: every unsigned application integer whose high bit is set needs a leading zero content octet.

Why it matters:

Long-running routers can report invalid uptime or emit traps rejected/misdecoded by strict managers, creating an outage that appears only after months.

Fix direction:

Reuse `berEncodeCounter32(uint32(hundredths))` for TimeTicks or share one unsigned BER helper. Add exact tests at `0x7fffffff`, `0x80000000`, and `0xffffffff`, including full varbind decode.

Labels:

`snmp`, `ber`, `record-correctness`, `long-uptime`, `vsrx-parity`

Dedup note:

No TimeTicks sign-encoding finding appears in the supplied index.
### A9-b1-L02

### C175-HC-114

Title: `ClearAllDUIDs` clears only identifiers loaded in the current process and silently ignores deletion failures.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcp/dhcp.go:540` derives "all" exclusively from the in-memory cache:
```go
540 // ClearAllDUIDs removes all persisted DUIDs.
541 func (m *Manager) ClearAllDUIDs() {
542     m.mu.Lock()
543     ifaces := make([]string, 0, len(m.duids))
544     for k := range m.duids {
545         ifaces = append(ifaces, k)
546     }
547     m.mu.Unlock()
```

`pkg/dhcp/dhcp.go:548` discards each `ClearDUID` error:

```go
548 
549     for _, ifName := range ifaces {
550         m.ClearDUID(ifName)
551     }
552 }
```

Trace:

Restart the daemon before a configured DHCPv6 client has called `getDUID`; its persisted file exists but `m.duids` is empty. The REST/gRPC "clear all" request returns success without touching that file. Even for loaded entries, permission/I/O errors are ignored and the API still reports all identifiers cleared.

Refutation attempt:

Configured interface option maps and the state directory could provide authoritative candidates, but this method consults neither and returns no error. Existing API contracts cannot distinguish partial failure.

HPC/invariant check:

Cold administrative operation. "All" must cover durable state, not only a lazy cache, and destructive failures must be observable.

Why it matters:

Operators troubleshooting DHCP identity can believe a reset succeeded while the same DUID is reused after renewal/restart.

Fix direction:

Return an error/result set, safely enumerate exact DUID state filenames or union configured interfaces with cache entries, and aggregate per-file failures. Reuse strict filename validation from H01. Add restart-with-unloaded-file and partial-error tests.

Labels:

`dhcpv6`, `duid`, `administration`, `error-handling`

Dedup note:

No incomplete clear-all DUID finding matched in the dedup index.
### L04

### C175-HC-115

Title: `commit confirmed` silently defaults malformed durations and accepts timer-overflowing values

Severity: Low

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_config.go:213`:

```go
	if len(args) > 0 && args[0] == "confirmed" {
		minutes := 10
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				minutes = v
			}
		}

		compiled, err := c.runCommitConfirmed(minutes)
```

Called timer contract, `pkg/configstore/store_commit.go:264`:

```go
	// Start auto-rollback timer. The closure captures the generation
	// at arm time; a stale callback from a superseded timer no-ops in
	// performAutoRollback.
	s.confirmGen++
	gen := s.confirmGen
	deadline := time.Now().Add(time.Duration(minutes) * time.Minute)
	s.confirmTimer = time.AfterFunc(time.Duration(minutes)*time.Minute, func() {
		s.fireConfirmTimer(gen)
```

Trace:

N/A (Low). `commit confirmed banana`, `0`, or `-1` commits successfully with an unannounced 10-minute window instead of rejecting the typo. Any positive `int` is accepted without an upper bound; sufficiently large minutes overflow `time.Duration(minutes)*time.Minute`, potentially producing an immediate or otherwise wrong rollback deadline after the candidate has already been promoted.

Refutation attempt:

N/A (required only for Critical/High). `Store.CommitConfirmed` only defaults non-positive values and applies the same unbounded duration conversion; it does not validate the CLI's positive input.

HPC/invariant check:

One timer, no hot-path impact. Transaction invariant: a commit-confirmed window must be strictly parsed and bounded before persistence/promotion, and the persisted deadline must equal the displayed interval.

Why it matters:

A typo can commit configuration under a different rollback window than intended, while an extreme value can immediately undo a valid change or persist a nonsensical deadline.

Fix direction:

Parse exactly one optional integer, reject malformed/extra tokens, enforce a documented range before `runCommitConfirmed`, and perform checked duration conversion. Repeat validation in `Store` for non-CLI callers and add boundary/overflow tests.

Labels:

input-validation, configuration, timer, correctness, vsrx-parity

Dedup note:

No matching root in the dedup index. Existing commit-confirmed entries concern candidate loss, timer generation, and persistence, not duration parsing/overflow.

### C175-HC-116

Title: Chassis cluster status drops VRRP rows for normal logical zone references

Severity: Low

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_show_cluster.go:223`:

```go
		for _, zone := range cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			for _, iface := range zone.Interfaces {
				ifCfg, ok := cfg.Interfaces.Interfaces[iface]
				if !ok {
					continue
				}
```

Trace:

N/A (Low). Zone references are normally logical (`ge-0/0/0.0`, `reth0.50`), while `cfg.Interfaces.Interfaces` is keyed by the physical base (`ge-0/0/0`, `reth0`). The exact lookup fails and skips every unit, so cluster status omits configured VRRP state on those interfaces.

Refutation attempt:

N/A (required only for Critical/High). No base-name split, RETH resolution, or alternate VRRP inventory is used in this status function.

HPC/invariant check:

Small config walk. Invariant: logical interface references must be resolved to the physical config object and selected unit before joining VRRP state.

Why it matters:

The default cluster status can hide the first-hop redundancy state operators need during a failover, even though VRRP is configured and active.

Fix direction:

Parse each zone ref into base/unit, resolve RETH/local member as appropriate, and inspect only that unit. Prefer a shared canonical interface inventory rather than another map join. Add physical-unit and RETH-unit cluster status tests.

Labels:

correctness, HA, VRRP, interface-identity, vsrx-parity

Dedup note:

No matching root in the dedup index. This is separate from dataplane VRRP election/checksum findings.

### C175-HC-117

Title: Cloudflare record lookup claims to return all matching rows but performs only one unpaginated request.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/ddns/backend_cloudflare.go:177` makes full-set semantics part of ownership safety:
```go
177 // listRecords returns ALL A/AAAA records Cloudflare holds for the FQDN+type.
178 // Returning the full set (rather than recs[0]) is the basis for both the
179 // upsert content-match and — critically — the ownership-scoped delete: a name
180 // can carry several records of one type, and recs[0] is an API-ordering
181 // artifact, not a statement of which row xpf owns (#2770).
182 func (b *cloudflareBackend) listRecords(ctx context.Context, zoneID, rtype, fqdn string) ([]cfRecord, error) {
183     q := url.Values{}
184     q.Set("type", rtype)
185     q.Set("name", strings.TrimSuffix(fqdn, "."))
186     env, err := b.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil)
```

`pkg/ddns/backend_cloudflare.go:186` decodes only that response and ignores pagination metadata:

```go
186     env, err := b.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil)
187     if err != nil {
188         return nil, err
189     }
190     var recs []cfRecord
191     if err := json.Unmarshal(env.Result, &recs); err != nil {
192         return nil, fmt.Errorf("ddns cloudflare: %s: decode records: %w", b.name, err)
193     }
194     return recs, nil
```

Trace:

A name/type has more matching rows than one API page. The xpf-owned content is on a later page, so upsert cannot see it and can create a duplicate; delete cannot find it and reports the record already absent or leaves ownership retrying depending on the surrounding path.

Refutation attempt:

Name/type filters usually keep result sets small, but the code explicitly supports several same-name values and has no `per_page`, `page`, cursor, or `result_info` loop. Tests use a single response page.

HPC/invariant check:

Cold provider API path. Ownership-safe selection requires complete enumeration or a server-side exact-content query with equivalent guarantees; work should also have a bounded page cap.

Why it matters:

An unusual but valid shared-name RR set defeats exact-content ownership logic, causing duplicate or stale public records.

Fix direction:

Implement bounded pagination using the provider response metadata, request the maximum supported page size, deduplicate IDs, and fail closed if the page bound is exceeded. Add a two-page owned-row test.

Labels:

`ddns`, `cloudflare`, `pagination`, `ownership`

Dedup note:

Distinct from `codex-review-157` H11 (foreign-row clobber) and L08 (repeated zone-ID lookup); this is incomplete same-name row enumeration.
### L09

### C175-HC-118

Title: Cluster CLI peer dialing constructs invalid endpoints for IPv6 fabric addresses

Severity: Low

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/peer.go:49`:

```go
	for _, ip := range peerIPs {
		peerAddr := fmt.Sprintf("%s:50051", ip)
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			continue
		}
		// Quick TCP probe to verify the address is reachable.
		d := &net.Dialer{Timeout: 2 * time.Second}
		if c.fabricVRFDevice != "" {
```

Trace:

N/A (Low). A peer address such as `2001:db8::2` becomes `2001:db8::2:50051`, which lacks the brackets required by `host:port` parsing. Both the gRPC target and TCP reachability probe use that malformed string and fall through to `peer not reachable` behavior.

Refutation attempt:

N/A (required only for Critical/High). The provider returns bare address strings, including `net.IP.String()` output; no earlier bracketing is guaranteed.

HPC/invariant check:

One bounded control-plane dial per fabric address. Address invariant: endpoint construction must be family-neutral and zone-aware for IPv6 link-local addresses.

Why it matters:

Cluster-wide show and peer-directed maintenance commands fail on an IPv6 fabric even when transport is otherwise reachable.

Fix direction:

Use `net.JoinHostPort(ip, "50051")`; preserve/validate any IPv6 zone identifier and reject inputs already containing an unexpected port. Add IPv4, global IPv6, and link-local scoped endpoint tests.

Labels:

correctness, IPv6, HA, protocol-tooling, vsrx-parity

Dedup note:

No matching root in the dedup index.

### C175-HC-119

Title: Concurrent `natpoolalarm.Stop` calls can both close the same channel and panic.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/natpoolalarm/natpoolalarm.go:171` reads lifecycle state under a mutex but performs the close after releasing it:
```go
171 func (m *Monitor) Stop() {
172     if m == nil {
173         return
174     }
175     m.mu.Lock()
176     started := m.started
177     m.mu.Unlock()
178     select {
```

`pkg/natpoolalarm/natpoolalarm.go:178` uses a check-then-close sequence that is not atomic across callers:

```go
178     select {
179     case <-m.stop:
180         // already stopped
181     default:
182         close(m.stop)
183     }
184     if started {
185         <-m.done // join the run() goroutine
```

Trace:

Two goroutines enter `Stop`, both execute the select before either close becomes visible, and both choose `default`. The first closes `m.stop`; the second then closes the already closed channel and panics. Sequential double-stop tests cannot force this interleaving.

Refutation attempt:

A receive from a closed channel makes later sequential calls safe, but select plus close is not an atomic test-and-set. The existing mutex does not cover it and there is no `sync.Once`.

HPC/invariant check:

Cold lifecycle path. An API documented as idempotent should be concurrency-safe when daemon shutdown paths can converge.

Why it matters:

Duplicate shutdown/cleanup paths can crash the control plane during teardown or test cleanup.

Fix direction:

Guard channel close with `sync.Once` or a stopped flag under `m.mu`; keep the join outside the lock. Add a barrier-based concurrent multi-Stop race test, including Stop-before-Start.

Labels:

`concurrency`, `panic`, `lifecycle`, `nat-alarm`

Dedup note:

No concurrent natpool alarm Stop finding matched in the dedup index.
### L08

### C175-HC-120

Title: DDNS state loading validates JSON/version but not record semantics, then drops malformed ownership without a wire delete.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/ddns/state.go:350` inserts every decoded record without validating address, family, FQDN, scope, or duplicate semantic consistency:
```go
350     if f.Version != 0 && f.Version != ddnsStateVersion {
351         return s, fmt.Errorf("ddns state %s has version %d (want %d): %w",
352             path, f.Version, ddnsStateVersion, errDDNSStateUnsupportedVersion)
353     }
354     for _, r := range f.Records {
355         s.records[ownedRecordKey(r.scopeOf(), r.Identity, r.Address)] = r
356     }
357     return s, nil
```

`pkg/ddns/manager.go:1166` treats an invalid stored address by deleting local authority without saving or issuing DNS cleanup:

```go
1166 func (m *Manager) deleteOwnedLocked(ctx context.Context, updater DNSUpdater, owned ownedRecord) error {
1167     rec, err := buildLeaseRecord(owned.FQDN, owned.Address, owned.TTL)
1168     if err != nil {
1169         // The stored address no longer parses (should not happen): drop
1170         // the entry to avoid wedging, but do NOT issue a delete with a
1171         // guessed name.
1172         slog.Warn("ddns: owned record has unparseable address; dropping entry",
1173             "address", owned.Address, "err", err)
1174         m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
1175         return nil
```

Trace:

Disk corruption, manual recovery, or an incompatible writer produces syntactically valid version-1 JSON with a malformed address or inconsistent record fields. Startup considers the store trusted. On cleanup, the manager silently removes the in-memory ownership entry, returns success, and leaves any real authoritative DNS record uncleanable; the deletion is not persisted immediately either, so behavior can oscillate across restart.

Refutation attempt:

JSON syntax and top-level version are fail-closed, but no per-record validator runs. Avoiding a guessed wire delete is correct; dropping the only ownership proof is not. Current tests cover corrupt JSON and unsupported versions, not semantically invalid records.

HPC/invariant check:

Cold durable-state path. Every loaded ownership tuple must be semantically valid before the store is trusted; an invalid tuple should degrade the whole destructive source or quarantine the individual record without losing it.

Why it matters:

Valid-JSON corruption bypasses the package's fail-closed posture and turns a recoverable forensic record into a permanent stale-DNS leak.

Fix direction:

Validate all required fields, family/address consistency, normalized FQDN/PTR/type, TTL bounds, scope bounds, and duplicate keys during load. On any unsafe record, enter durable degraded/quarantine state rather than deleting authority. Add semantic-corruption fixtures and restart tests.

Labels:

`ddns`, `state-validation`, `ownership`, `fail-open`

Dedup note:

No semantic DDNS state-validation finding matched in the dedup index.

### C175-HC-121

Title: DHCP lease read failures are rendered as a clean empty lease table

Severity: Low

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/show_services_dhcp.go:235`:

```go
	// Read Kea lease files directly.
	server := dhcpserver.New()
	leases4, _ := server.GetLeases4()
	leases6, _ := server.GetLeases6()

	if len(leases4) == 0 && len(leases6) == 0 {
		if !detail {
			fmt.Println("No active leases")
		} else {
```

Trace:

N/A (Low). If a configured Kea lease file is unreadable, missing unexpectedly, or fails CSV parsing before a header is obtained, its error is discarded. Empty slices then produce `No active leases`, which is indistinguishable from a healthy server with no clients.

Refutation attempt:

N/A (required only for Critical/High). The called methods return errors expressly; no runtime-health check or warning follows these reads.

HPC/invariant check:

Bounded control-plane file read. Invariant: an unavailable source must never be represented as authoritative empty state.

Why it matters:

Operators can conclude clients have no leases during storage/permission corruption and make incorrect DHCP recovery or failover decisions.

Fix direction:

Read only configured families, retain each error, render successful-family leases, and emit a family-specific warning/error for failed sources. Add unreadable, missing-configured-file, malformed-header, and one-family-only tests.

Labels:

correctness, error-handling, DHCP, observability

Dedup note:

No matching root in the dedup index.

### C175-HC-122

Title: DHCP relay counts a request as relayed even when every server send fails.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcprelay/relay.go:1161` increments the success-style counter unconditionally after the send loop:
```go
1161             // Unicast the modified packet to each server in the active group.
1162             relayData := pkt.ToBytes()
1163             for _, srv := range servers {
1164                 if _, err := serverConn.WriteTo(relayData, srv); err != nil {
1165                     slog.Warn("dhcp-relay: send to server failed",
1166                         "interface", ifaceName,
1167                         "server", srv, "err", err)
1168                 }
1169             }
1170             ir.requestsRelayed.Add(1)
```

Trace:

The server socket is broken or routing to every configured server fails. Every `WriteTo` returns an error, yet `RequestsRelayed` increases by one and no failure counter records the lost request.

Refutation attempt:

Warnings carry per-server detail in logs, but the exported statistics cannot distinguish successful fanout, partial fanout, and total failure. Existing delivery tests focus client reply delivery rather than server-send accounting.

HPC/invariant check:

Per-request control/data-adjacent path. Counter work remains O(number of configured servers); the semantic invariant is that a success counter requires at least one successful send.

Why it matters:

Monitoring reports healthy relay throughput while clients receive no lease offers, obscuring the failure and weakening SLO/alert accuracy.

Fix direction:

Count `RequestsRelayed` only after at least one full successful send; add total and per-server send-failure counters plus partial-fanout status. Test all-fail, partial, and all-success cases, including short writes if the interface permits them.

Labels:

`dhcp-relay`, `observability`, `counter`, `error-handling`

Dedup note:

No relay server-send counter finding matched in the dedup index.
### L07

### C175-HC-123

Title: DUID-LLT generation continues after persistence failure, making the DHCPv6 identity silently ephemeral.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/dhcp/dhcp.go:598` logs a failed durable write but caches and returns the newly generated DUID as success:
```go
598     // Persist
599     if err := m.saveDUID(ifaceName, duid); err != nil {
600         slog.Warn("DHCPv6: failed to persist DUID",
601             "interface", ifaceName, "err", err)
602     }
603 
604     m.mu.Lock()
605     m.duids[ifaceName] = duid
606     m.mu.Unlock()
```

Trace:

Configure `duid-llt` and make the state directory read-only/full. The client uses the generated time-based DUID for the process lifetime despite the failed save. On restart it generates a different timestamped DUID, so the server sees a new client while the old lease remains until expiry.

Refutation attempt:

Default DUID-LL is usually stable from the MAC, reducing impact there, but DUID-LLT is explicitly offered and relies on persistence. The function's error return remains nil after save failure.

HPC/invariant check:

Cold identity creation. A time-based stable identifier must not be activated unless its durable copy is committed.

Why it matters:

Repeated restart under storage failure can leak leases, churn addresses/prefixes, exhaust a constrained pool, and make reservations keyed by DUID unreliable.

Fix direction:

Fail DUID acquisition closed for persistence-dependent types, or retain a clearly degraded non-running client state until durable storage recovers. Surface a metric/status and test save failure followed by simulated restart.

Labels:

`dhcpv6`, `duid`, `durability`, `identity`

Dedup note:

No DUID persistence-failure finding matched in the dedup index.
### L05

### C175-HC-124

Title: Forwarding-status CPU tick conversion overflows before division on high-core long-lived daemons.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/fwdstatus/builder.go:230` multiplies the cumulative tick count by one billion in `uint64` before reducing it by `userHZ`:
```go
230 func ticksToNanos(ticks uint64) uint64 {
231     return ticks * 1_000_000_000 / userHZ
232 }
233 
234 // allHeartbeatsFresh returns true iff every heartbeat is within
235 // maxAge of now.  Empty slice returns true (no workers → trivially
236 // fresh; caller distinguishes the empty vs populated case when
237 // interpreting Degraded).
238 func allHeartbeatsFresh(hbs []time.Time, now time.Time, maxAge time.Duration) bool {
```

`pkg/fwdstatus/sampler.go:212` responds to the resulting decrease by invalidating CPU windows:

```go
212         // Guard against non-monotonic counters.  A userspace-dp
213         // restart or a brief Status() miscarriage can reset the
214         // cumulative series; an unchecked subtract on uint64 would
215         // underflow to a huge value and pass the clamp-on-display
216         // path, reporting a bogus 9e20%.  Mark the window invalid
217         // in that case so the operator sees `-` until fresh samples
218         // accumulate.
219         wallNs := uint64(wallDelta.Nanoseconds())
```

Trace:

The intermediate wraps at about 18.45 billion ticks, or 5.85 aggregate CPU-years at 100 Hz. A process averaging 64 busy cores reaches that in about 33 days. The converted cumulative counter jumps backward, making 5-second, 1-minute, and 5-minute daemon CPU windows invalid until all pre-wrap samples age out.

Refutation attempt:

The downstream monotonicity guard prevents a huge underflow percentage, but does not prevent the telemetry outage. Tests cover manually decreasing counters, not conversion near the multiplication boundary.

HPC/invariant check:

Observability-only arithmetic. A monotonic cumulative source must remain monotonic under unit conversion for every representable result.

Why it matters:

Busy appliances can periodically lose the very CPU windows used to diagnose saturation, despite no daemon restart or `/proc` failure.

Fix direction:

Convert with quotient/remainder (`ticks/userHZ` and `ticks%userHZ`) or checked wide multiplication, and define saturation once the nanosecond result itself is unrepresentable. Add boundary/property tests around `MaxUint64/1e9` and realistic multicore accumulation.

Labels:

`integer-overflow`, `observability`, `cpu`, `long-uptime`

Dedup note:

No tick-conversion overflow finding matched in the dedup index.
### L03

### C175-HC-125

Title: LLDP shutdown frames are learned as neighbors and remain visible until the 10-second expiry sweep.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/lldp/lldp.go:512` inserts a parsed TTL-zero frame just like an advertisement:
```go
512         neighbor := ParseTLVs(buf[ethHdrLen:n])
513         if neighbor == nil {
514             continue
515         }
516         neighbor.Interface = iface.Name
517         neighbor.LastSeen = time.Now()
518         neighbor.ExpiresAt = time.Now().Add(time.Duration(neighbor.TTL) * time.Second)
519 
520         key := fmt.Sprintf("%s/%s/%s", iface.Name, neighbor.ChassisID, neighbor.PortID)
521         m.learnNeighbor(key, neighbor)
```

`pkg/lldp/lldp.go:593` removes it only on a periodic ticker:

```go
593 // expiryLoop periodically removes expired neighbors.
594 func (m *Manager) expiryLoop(ctx context.Context) {
595     ticker := time.NewTicker(10 * time.Second)
596     defer ticker.Stop()
597 
598     for {
599         select {
600         case <-ctx.Done():
601             return
```

Trace:

A peer sends the standard TTL=0 shutdown PDU. The parser intentionally accepts it, the receive loop sets expiration to the current instant and calls `learnNeighbor`, and `show lldp neighbors` can continue to show it until the next 10-second sweep. A previously unknown shutdown tuple can also be inserted transiently.

Refutation attempt:

The expiry loop eventually removes the row, and the parser is correct to recognize a syntactically valid shutdown frame. The missing behavior is an immediate keyed delete in the receive path; tests assert parsing only.

HPC/invariant check:

Low-rate L2 control path. TTL zero is a withdrawal event, not a lease with a short positive hold time.

Why it matters:

Topology automation and operators can act on a neighbor the peer explicitly withdrew, delaying convergence and producing transient false adjacency.

Fix direction:

After deriving the key, delete an existing neighbor immediately when TTL is zero and do not admit a new one. Add receive-path tests for existing and unknown shutdown tuples.

Labels:

`lldp`, `withdrawal`, `stale-state`, `vsrx-parity`

Dedup note:

No TTL-zero LLDP lifecycle finding matched in the dedup index.
### L06

### C175-HC-126

Title: Local and remote policy inventory parsers silently ignore malformed zone selectors

Severity: Low

Confidence: High

Source batch: A10-b1 + A10-b2

Evidence:

**A10-b1 component**

`cmd/cli/show_security.go:28`
```go
28		if len(args) >= 2 && args[1] == "detail" {
29			var filterParts []string
30			for i := 2; i+1 < len(args); i++ {
31				if args[i] == "from-zone" || args[i] == "to-zone" {
32					filterParts = append(filterParts, args[i], args[i+1])
33					i++
34				}
35			}
36			return c.showTextFiltered("policies-detail", strings.Join(filterParts, " "))
```

**A10-b2 component**

`pkg/cli/cli_show_security_dispatch.go:80`:

```go
// parsePolicyZoneFilter extracts from-zone/to-zone filters from args.
func parsePolicyZoneFilter(args []string) (fromZone, toZone string) {
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "from-zone":
			fromZone = args[i+1]
		case "to-zone":
			toZone = args[i+1]
		}
	}
```

Trace:

**A10-b1 component**

Both loops stop before a trailing selector and have no unknown-token error. `show security policies detail from-zone trust to-zone` forwards only `from-zone trust`; `... form-zone trust` forwards no scope and renders all policies. Hit-count uses the same pattern. The strict shared parser used by match-policy diagnostics is not used here.

**A10-b2 component**

N/A (Low). `show security policies hit-count from-zone trust to-zone` silently drops the missing `to-zone` predicate and returns all trust-originating rows. A misspelled selector is ignored, and duplicates silently last-win. These inventory/detail commands therefore retain the loose parser behavior already removed from the policy simulator.

Refutation attempt:

**A10-b1 component**

These are read-only commands, and broader output can sometimes make the mistake visually apparent, which limits severity. However, the command returns success and server receives a valid broadened query, so neither layer can warn that the requested scope was discarded.

**A10-b2 component**

N/A (required only for Critical/High). `showMatchPolicies`/`testPolicy` use the strict shared parser, but this separate helper does not call it or validate consumed tokens.

HPC/invariant check:

**A10-b1 component**

Cold diagnostic path. Firewall audit selectors should be exact and fail closed; strict parsing adds negligible work and no packet-path cost.

**A10-b2 component**

Tiny control-plane token vector. Invariant: selector-bearing diagnostic commands must reject any unconsumed, duplicate, or value-less token so audit scope cannot widen silently.

Why it matters:

**A10-b1 component**

Operators and automation can believe they inspected one zone pair while actually receiving a broader or one-sided inventory, undermining policy-change verification.

**A10-b2 component**

A policy audit can show a broader rule set than requested without warning, obscuring whether the intended zone pair is actually covered.

Fix direction:

**A10-b1 component**

Add one strict parser for policy inventory scope (`from-zone` and `to-zone`, no duplicates, exact values, no unknown/extra tokens) and use it for normal/detail/hit-count modes. Add no-RPC tests for trailing, unknown, duplicate, and extra selectors.

**A10-b2 component**

Replace this tuple-return helper with a strict parser returning an error and consumed-selector state. Validate duplicates and both values; add negative tests parallel to `query_strictness_3696_test.go`.

Labels:

`cli`, `policy`, `diagnostics`, `input-validation`, `vsrx-parity`, input-validation, policy, observability, fail-open, vsrx-parity

Dedup note:

Merged the local and remote CLI parser reports because both silently discard malformed inventory scope tokens instead of rejecting the request. No matching root appears in the prior-campaign index.

### C175-HC-127

Title: Persistent-NAT show rendering races with live binding refresh because `All` returns mutable pointers rather than a snapshot.

Severity: Low

Confidence: High

Source batch: A10-b3

Evidence:

`pkg/natshow/persistent.go:15` obtains a purported collection and reads each pointed-to binding after the table lock is gone:
```go
15 func RenderPersistent(w io.Writer, dp Reader) {
16     if dp == nil || dp.GetPersistentNAT() == nil {
17         io.WriteString(w, "Persistent NAT table not available\n")
18         return
19     }
20     bindings := dp.GetPersistentNAT().All()
21     if len(bindings) == 0 {
22         io.WriteString(w, "No persistent NAT bindings\n")
23         return
```

The necessary table contract at `pkg/dataplane/persistent_nat.go:125` mutates those same objects under its lock:

```go
125 // Save stores a persistent NAT binding. If a binding with the same source
126 // IP, port, and pool already exists, LastSeen is updated to the current time.
127 func (t *PersistentNATTable) Save(b *PersistentNATBinding) {
128     t.mu.Lock()
129     defer t.mu.Unlock()
130 
131     key := persistentNATKey{SrcIP: b.SrcIP, SrcPort: b.SrcPort, Pool: b.PoolName}
132     if existing, ok := t.bindings[key]; ok {
133         existing.LastSeen = time.Now()
```

`pkg/dataplane/persistent_nat.go:171` copies only pointers under the read lock:

```go
171 // All returns a snapshot of all current bindings.
172 func (t *PersistentNATTable) All() []*PersistentNATBinding {
173     t.mu.RLock()
174     defer t.mu.RUnlock()
175 
176     result := make([]*PersistentNATBinding, 0, len(t.bindings))
177     for _, b := range t.bindings {
178         result = append(result, b)
179     }
180     return result
```

Trace:

A session refresh calls `Save` and writes `LastSeen` while a concurrent show request calls `All`, releases the lock, then evaluates `b.LastSeen.Add(...)`. Both access the same `time.Time` object without synchronization, producing a Go data race and potentially inconsistent timeout output.

Refutation attempt:

The slice and map iteration are protected, but pointees are not copied. Existing renderer tests use static tables; the selected race suite therefore remains green.

HPC/invariant check:

Diagnostic path, not packet hot path. A method named snapshot must return immutable values or keep the lock through all reads.

Why it matters:

The daemon has a real data race in a routine operational command and can print torn/incorrect timeout state. The raw-pointer API also permits future callers to mutate table state outside its lock.

Fix direction:

Make `All` return deep-copied values (`[]PersistentNATBinding`) and sort a stable snapshot before rendering. Add a race test that continuously refreshes a binding while both persistent views render.

Labels:

`concurrency`, `data-race`, `nat`, `observability`

Dedup note:

Distinct from `codex-review-161` F-071, which concerns per-rule session counts rather than pointer snapshot safety.
### L02

### C175-HC-128

Title: Rate-spread thresholds are derived from partial cells and partial stream sets

Severity: Low

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/step1-rate-spread-analysis.py:54`
```python
    streams = data.get("end", {}).get("streams", [])
    rates: List[float] = []
    for s in streams:
        sender = s.get("sender") or {}
        bps = sender.get("bits_per_second")
        if bps and bps > 0:
            rates.append(float(bps))
    return rates
```

Missing cells and any reduced stream count are accepted at `test/incus/step1-rate-spread-analysis.py:131`:

```python
    for name in args.cells:
        path = args.evidence_dir / f"{name}.json"
        if not path.is_file():
            print(f"# WARN: missing {path}", file=sys.stderr)
            continue
        rates = load_per_flow_rates(path)
        ratio, mx, mn, n = cell_spread(rates)
        print(f"{name:<12}  {n:>3}  {mx/1e9:>10.4f}  {mn/1e9:>10.4f}  {ratio:>7.4f}")
        ratios.append(ratio)
```

Trace:

The stated input contract is 16 streams in each of four forward cells. Zero/missing/malformed sender values are dropped; no exact-16 check exists; missing cells are skipped; any two surviving ratios are enough to compute and print the threshold at lines 141-153.

Refutation attempt:

The table displays `n` and warnings, so a careful human may notice, but the script still emits an authoritative rounded "Y" with exit 0. Missing/zero flows are precisely evidence that can widen spread and must not be trimmed as slow-start noise without accounting.

HPC/invariant check:

Offline statistics only. Invariant checked: a published threshold uses the complete, predeclared cohort and every expected stream, or is explicitly marked non-authoritative.

Why it matters:

Lost worst-case flows or cells bias the derived acceptance threshold and bootstrap interval while preserving a successful machine status.

Fix direction:

Require the expected cell set and exactly 16 finite positive sender summaries per cell by default; offer an explicit exploratory partial mode that cannot emit the canonical threshold; report dropped stream identities.

Labels:

packet-tooling, statistics, evidence-integrity, step1

Dedup note:

No partial rate-spread evidence finding appears in the index.
### A10-b4-30

### C175-HC-129

Title: Routing-instance detail counts `next-table` static routes but omits their rows

Severity: Low

Confidence: High

Source batch: A10-b2

Evidence:

`pkg/cli/cli_show_routing.go:1029`:

```go
		if len(ri.StaticRoutes) > 0 {
			fmt.Printf("  Static routes: %d\n", len(ri.StaticRoutes))
			for _, sr := range ri.StaticRoutes {
				if sr.Discard {
					fmt.Printf("    %s -> discard\n", sr.Destination)
					continue
				}
				for _, nh := range sr.NextHops {
					nhStr := nh.Address
```

Trace:

N/A (Low). A static route with `NextTable` has no `NextHops`; it contributes to the printed count, skips the discard branch, and emits no row. The global routing-options renderer has an explicit `NextTable` branch, so the same route appears there but vanishes from routing-instance detail.

Refutation attempt:

N/A (required only for Critical/High). No later block prints `sr.NextTable` in this function.

HPC/invariant check:

O(number of configured routes), unchanged. Invariant: every item included in a displayed count must have a row or an explicit unsupported marker.

Why it matters:

Route-leaking configuration is hidden on the instance-focused command used to verify it, while the count misleadingly says the route exists.

Fix direction:

Reuse the shared static-route formatter from the global view, including discard, next-table, qualified next-hops, preferences, and tags. Add an instance fixture with next-table only.

Labels:

correctness, routing, observability, vsrx-parity

Dedup note:

No matching root in the dedup index.

### C175-HC-130

Title: RSS Monte Carlo retains every trial despite needing only aggregate counters

Severity: Low

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/step1-rss-multinomial.py:71`
```python
        for _f in range(n_flows):
            if cum is None:
                w = rng.randrange(n_workers)
            else:
                u = rng.random()
                w = 0
                while w < n_workers - 1 and u > cum[w]:
                    w += 1
            counts[w] += 1
        out.append((max(counts), min(counts)))
```

Trace:

`simulate` allocates a Python tuple and list slot for every trial, then `tail_probabilities` immediately reduces the list to counters. Default is one million trials, and the documented ten-million-trial invocation can consume hundreds of MiB to over a GiB depending on interpreter overhead, despite O(1) sufficient statistics.

Refutation attempt:

One million may fit a developer workstation, but the script advertises larger runs and has no cap or streaming mode. Deterministic output does not require retaining samples because RNG order and online counters are identical.

HPC/invariant check:

Analysis performance path. Invariant checked: Monte Carlo memory remains O(number of outcome bins/workers), not O(trials); streaming also improves cache behavior without changing arithmetic.

Why it matters:

Higher-confidence runs can swap, stall, or be OOM-killed, wasting long computations and making the documented reproducibility command impractical in CI.

Fix direction:

Accumulate max/min and union counters online, return counts/probabilities directly, validate positive trial/flow/worker values, and optionally batch/vectorize while preserving the seeded sequence contract.

Labels:

packet-tooling, performance, memory, monte-carlo

Dedup note:

No RSS Monte Carlo memory finding appears in `dedup-index.md`.

### C175-HC-131

Title: Self-recovery errors do not break the claimed continuous grace observation

Severity: Low

Confidence: High

Source batch: A10-b4

Evidence:

`pkg/upgrade/kernel_selfrecover.go:194`
```go
	if s.cfg.Armed != nil {
		armed, err := s.cfg.Armed()
		if err != nil {
			return false, fmt.Errorf("kernel self-recovery: armed check: %w", err)
		}
		if armed {
			s.drainedSince = time.Time{}
			s.cfg.Logf("kernel self-recovery: lease expired but a candidate is STILL ARMED; " +
				"a trial is in flight (promote/revert owns it) -> NOT recovering")
```

Trace:

After one valid drained/healthy observation starts `drainedSince`, errors from `Armed`, `LocalDrained`, or `PeerHealthyPrimary` return without resetting it (lines 194-219). Enough wall time can pass with no observations; the next successful positive tick sees `now.Sub(drainedSince) >= Grace` and immediately rejoins.

Refutation attempt:

The final tick still verifies all predicates, limiting impact, but the function comment explicitly requires the condition to hold continuously. Unknown periods cannot establish continuity and may include a real armed/peer transition.

HPC/invariant check:

Low-rate timer only. Invariant checked: safety grace is accumulated only across consecutive affirmative observations, with unknown/error breaking or explicitly pausing the interval.

Why it matters:

A transient management outage can consume the entire safety delay and turn the first recovered observation into an immediate HA state change.

Fix direction:

Reset `drainedSince` on every predicate error, or track monotonic accumulated affirmative duration with a maximum allowed sample gap; add error-between-positive-ticks tests for each dependency.

Labels:

upgrade, ha, timing, robustness

Dedup note:

No continuous-grace error-gap finding appears in the index.
### A10-b4-28

### C175-HC-132

Title: Step-1 histogram classification skips failed/missing cells and still exits success

Severity: Low

Confidence: High

Source batch: A10-b4

Evidence:

`test/incus/step1-histogram-classify.py:484`
```python
        cell_dir = args.evidence_root / rel_dir
        if not cell_dir.is_dir():
            print(f"WARN: cell dir missing {cell_dir}", file=sys.stderr)
            continue
        try:
            snaps = load_snapshots(cell_dir)
            blocks = compute_blocks(snaps)
        except Exception as e:
            print(f"ERROR: cell {rel_dir} failed: {e}", file=sys.stderr)
            continue
```

Even an empty result remains successful at `test/incus/step1-histogram-classify.py:535`:

```python
    if args.only_cell is not None:
        # #821 §3.6: --only-cell skips summary-table.csv.
        return 0

    if summary_rows:
        summary_path = args.output_summary or (
            args.evidence_root / "summary-table.csv"
        )
        with summary_path.open("w", newline="") as f:
```

Trace:

Missing/corrupt target cells only warn and continue; `--only-cell` returns 0 even if its sole cell failed and no `hist-blocks.jsonl` was written; full mode can print `k_D1 = 0 of 0` and return 0 at line 556. Baseline quorum does fail closed, but target-cell completeness does not.

Refutation attempt:

A downstream consumer may notice a missing artifact, but this command claims successful classification and can be used independently. The explicit `--only-cell` contract is especially unambiguous: one requested cell either produced its output or failed.

HPC/invariant check:

Offline analysis only. Invariant checked: requested evidence cells are complete, and command success means every required output was generated.

Why it matters:

Automation can treat an incomplete investigation as a valid zero-fire result or continue with stale output from a previous run.

Fix direction:

Track expected, successful, missing, and failed cells; return nonzero on any required-cell failure; remove/stage outputs atomically; require exactly one success in `--only-cell`; add missing/corrupt-cell CLI tests.

Labels:

packet-tooling, evidence-integrity, exit-status, step1

Dedup note:

No missing-cell success finding appears in `dedup-index.md`.
### A10-b4-29

### C175-HC-133

Title: The supposedly local WireGuard key generator cannot run when xpfd is unavailable

Severity: Low

Confidence: High

Source batch: A10-b1

Evidence:

`cmd/cli/main.go:40`
```go
40	client := pb.NewBpfrxServiceClient(conn)
41
42	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
43	resp, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
44	cancel()
45	if err != nil {
46		fmt.Fprintf(os.Stderr, "cli: cannot reach xpfd at %s: %v\n", *addr, err)
47		os.Exit(1)
```

Trace:

`main` performs `GetStatus` and exits before either `-c` dispatch or interactive readline initialization. The handler itself makes no RPC, but it is unreachable through the binary when the daemon is stopped or unhealthy.

Refutation attempt:

The assigned test calls `handleRequest` directly with a fake client, so it proves only handler locality and bypasses startup. No early local-command dispatch exists before `GetStatus`.

HPC/invariant check:

Cold utility path, no dataplane effect. The violated modularity invariant is that a documented local-only utility must not require unrelated daemon liveness.

Why it matters:

Key generation is useful during recovery/bootstrap precisely when xpfd may not be running; the shipped command fails despite its explicit contract.

Fix direction:

Recognize and execute this pure local `-c` command before dialing/status, or split local request utilities into a daemon-independent command path. Add a subprocess/entrypoint test with an unreachable address that still emits a valid key pair.

Labels:

`cli`, `wireguard`, `feature-completeness`, `test-gap`

Dedup note:

No offline WireGuard key-generation entrypoint finding appears in the supplied dedup index.
### A10-b1-L02

## 7. Medium-confidence findings

### C175-MC-001

Title: Scan/sweep source-cap eviction can skip a fresh scanner when the fixed global sample misses the saturated zone

Severity: Medium

Confidence: Medium

Source batch: A1-b4

Evidence:

`userspace-dp/src/screen/scan.rs:299-305` skips a brand-new source when the per-zone cap is reached and the bounded eviction helper returns false:

```rust
if !exists && self.zone_count(zone_id) >= MAX_SOURCES_PER_ZONE {
    if !self.evict_stalest_in_zone(zone_id, now_micros, window_micros) {
        // No same-zone victim within the bounded sample (pathological
        // many-zone interleave). Preserve the fail-safe: skip, never
        // fail-open. Cost is still O(EVICT_SCAN_LIMIT).
        self.skipped_pressure += 1;
        return false;
    }
}
```

`userspace-dp/src/screen/scan.rs:378-386` shows the helper samples only the first `EVICT_SCAN_LIMIT` entries of the global `per_src` iterator; non-target-zone entries consume the entire sample budget:

```rust
// Hard total-iteration bound: take a fixed prefix of the iterator.
for (k, (start, set)) in self.per_src.iter().take(EVICT_SCAN_LIMIT) {
    if k.0 != zone_id {
        continue; // not a candidate, but still counts against the bound
    }
    // An expired-or-empty window is dead weight - evict it first.
    if now_micros.saturating_sub(*start) >= window_micros || set.is_empty() {
        expired_victim = Some(*k);
```

The comments recognize this many-zone sparse-interleave fallback but call it "never fail-open" at `userspace-dp/src/screen/scan.rs:54-56`; the same file says the goal is that "a fresh real scanner is still always admissible" at `userspace-dp/src/screen/scan.rs:95-96`. The existing regression tests cover the single-zone dense case only: `userspace-dp/src/screen/scan.rs:785-822` and `userspace-dp/src/screen/tests.rs:4626-4665` saturate one zone, then prove the scanner is admitted.

Trace:

1. A zone `Z` already has `MAX_SOURCES_PER_ZONE` tracked `(zone_id, src_ip)` entries in `ScanCore::per_src`.
2. Other zones' source keys occupy the first `EVICT_SCAN_LIMIT` positions of the `FxHashMap` iteration order. This is plausible in a many-zone deployment because the sample is a fixed global iterator prefix, not a per-zone sample.
3. A new scanner source appears in zone `Z` and sends its first scan/sweep packet within a configured scan window.
4. `check()` sees `exists == false` and `zone_count(Z) >= MAX_SOURCES_PER_ZONE`, so it calls `evict_stalest_in_zone(Z, ...)`.
5. `evict_stalest_in_zone()` iterates only `.take(EVICT_SCAN_LIMIT)` global entries. If none has `k.0 == Z`, no victim is selected and it returns `false`.
6. `check()` increments `skipped_pressure` and returns `false` before inserting the new source. Later packets from that scanner remain untracked as long as this source-cap/sample condition persists, so the distinct-destination count never reaches `SCAN_DETECT_COUNT` and port-scan/ip-sweep never fires.

Refutation attempt:

I tried to refute this by reading the surrounding invariants and tests. The code maintains `per_zone_count`, so the target zone really can be known saturated. The helper does least-suspicious eviction when it sees same-zone candidates, and the tests prove that dense single-zone saturation admits a later scanner. I did not find any per-zone victim list, randomized start offset, retry-until-same-zone budget, or test that constructs a many-zone interleaving where the first global sample contains no target-zone entry. The refutation failed because non-target-zone entries explicitly count against the fixed sample budget.

HPC/invariant check:

cost invariant is preserved, but the security invariant is weaker than documented. A fixed global prefix gives bounded work, but it is not a bounded per-zone sample. The detector can therefore preserve memory/cache bounds while becoming fail-open for detection in the saturated zone. There is no atomic or endianness issue here; the problem is sample selection versus the per-zone tracking invariant.

Why it matters:

This is a detection-DoS against the advanced screen port-scan/ip-sweep feature. The packet is forwarded rather than dropped, and the screen state never learns the new source, so an attacker can hide the real scanner behind source-cap pressure in a many-zone/sparse-interleaved table. That contradicts the comment's stated post-#2234/#4418 objective that a fresh real scanner stays admissible under source-axis saturation.

Fix direction:

(concrete - the report is a remediation work-list): Keep the bounded cost, but make victim search per-zone. Options: maintain a small per-zone ring/list of source keys for victim sampling; keep per-zone maps so `.take(EVICT_SCAN_LIMIT)` samples within the zone; or iterate from a per-zone index until `EVICT_SCAN_LIMIT` same-zone candidates have been examined while preserving an absolute cap. Add a regression test that fills enough other-zone entries to ensure the first global iterator prefix has no entries for saturated zone `Z`, then verifies a new scanner in `Z` is still admitted and detected.

Labels:

(include vsrx-parity for parity issues): `security-screen`, `detection-dos`, `fail-open-detection`, `test-gap`, `rust-dataplane`

Dedup note:

(why this is not a restatement of any entry in the dedup index): Not a duplicate of N-11/N-12/M-1/F11, which cover scan threshold/window semantics and cleanup timing. Not a duplicate of N-13/#4418, which covers least-suspicious victim choice once a same-zone victim is in the bounded sample. This finding is about the residual global-prefix sample-selection hole where no same-zone victim is sampled at all.

### C175-MC-002

Title: Lenient bad application protocol is emitted as protocol 0 in the AppID catalog

Severity: Medium

Confidence: Medium

Source batch: A3-b1

Evidence:

`pkg/appid/catalog.go:386` deliberately collapses unrepresentable protocols to byte 0 and discards the ok bit:

```go
// returning 0 for an unrepresentable token (the catalog's historical
// "unknown -> 0" behavior). Delegates to ProtocolNumber (#2124) so the catalog
// and the capability gate share one table.
func catalogProtocolNumber(name string) uint8 {
	n, _ := ProtocolNumber(name)
	return n
}
```

`pkg/appid/catalog.go:198` then emits that byte as a real catalog row whenever the raw protocol string is non-empty:

```go
protos := []uint8{proto}
if strings.TrimSpace(app.Protocol) == "" {
	protos = []uint8{6, 17}
}
for _, p := range protos {
	cat.Entries = append(cat.Entries, CatalogEntry{
		Name:        name,
		AppID:       appID,
		Protocol:    p,
```

`pkg/config/compiler_application_specs_test.go:454` confirms the tolerant path keeps a bad referenced protocol as a warning:

```go
tree := flatTreeFromSets(t, referencedProtoApp("junos-foobar")...)
cfg, err := CompileConfigLenient(tree)
if err != nil {
	t.Fatalf("lenient load of a referenced bad-protocol app must not fail: %v", err)
}
var warned bool
```

Trace:

1. Strict commit rejects an application protocol such as `junos-foobar`, but `CompileConfigLenient` intentionally returns a config plus warning for no-brick tolerant load.
2. With AppID enabled, all user applications are selected for catalog validation/compilation; otherwise, policy/NAT references select the bad application.
3. `BuildCatalog` calls `catalogProtocolNumber(app.Protocol)`. For `junos-foobar`, `ProtocolNumber` would return `(0, false)`, but `catalogProtocolNumber` returns only `0`.
4. Because the raw protocol string is non-empty, the fan-out branch does not treat it as an omitted protocol; it emits one catalog row with `Protocol: 0`.
5. Rust `AppCatalog::from_snapshot` indexes nonzero app_ids by the protocol byte, and `lookup_directional` can return that app_id for protocol-0 sessions. The result is a false AppID label for an application whose protocol was known malformed on the tolerant path.

Refutation attempt:

I checked whether strict validation fully removes the case: it does for normal commit, but the lenient test proves the bad config continues as a warning. I also checked whether ProtocolNumber confuses explicit `protocol 0`; it does not, because it preserves `(0,true)` vs `(0,false)`. The collapse happens in `catalogProtocolNumber`. I checked Rust catalog indexing: it skips app_id 0, not protocol 0, so a nonzero app_id with protocol byte 0 is a live row. Policy enforcement impact is narrower because referenced bad applications may trigger userspace content rejection elsewhere; the remaining issue is AppID catalog/log integrity, especially with AppID enabled compiling all apps.

HPC/invariant check:

No per-packet allocation or atomic invariant. The relevant wire invariant is that protocol byte 0 is a legitimate HOPOPT protocol, not an "unknown protocol" sentinel; only app_id 0 is reserved as unknown. Discarding `ok` violates that distinction.

Why it matters:

The catalog has recently been hardened to avoid false labels from malformed ports and ICMP type constraints. This keeps a similar malformed-config path open: an unrepresentable explicit protocol becomes a valid protocol-0 catalog row instead of being inert.

Fix direction:

Have `BuildCatalog` call `ProtocolNumber` directly and keep the ok bit. If `ok == false`, treat the application as unemittable: do not ship a CatalogEntry and do not add an AppNames row for a stampable id. Preserve explicit `protocol 0` by allowing `(0, true)`. Add a tolerant-load regression test for `protocol junos-foobar` with AppID enabled and no ports.

Labels:

appid, malformed-config, tolerant-load, log-integrity

Dedup note:

The dedup index covers AppID malformed port, ICMP type/code, protocol-0 fan-out, and generic AppID parity issues. This is a distinct root cause: `ProtocolNumber`'s false ok bit is discarded and an unrepresentable explicit protocol is emitted as a real protocol-0 row.

### F3

### C175-MC-003

Title: Unknown encrypted-envelope formats fall through as plaintext and can empty-load instead of failing closed

Severity: Medium

Confidence: Medium

Source batch: A4-b1

Evidence:

`pkg/configstore/crypto.go:165-177` treats any JSON object whose `format` is not the current encrypted format as "not an envelope":

```go
func unmarshalEnvelope(data []byte) (encryptedTreeEnvelope, bool, error) {
	type alias encryptedTreeEnvelope
	var env alias
	if err := json.Unmarshal(data, &env); err != nil {
		return encryptedTreeEnvelope{}, false, nil
	}
	if env.Format != encryptedTreeFormat {
		return encryptedTreeEnvelope{}, false, nil
	}
```

`pkg/configstore/db.go:270-278` then parses the same bytes as a config tree:

```go
data, decrypted, err := db.maybeDecryptTreeJSON(data)
if err != nil {
	return nil, true, fmt.Errorf("decrypt %s: %w", path, err)
}

tree := &config.ConfigTree{}
if err := json.Unmarshal(data, tree); err != nil {
	return nil, true, fmt.Errorf("parse %s: %w", path, err)
}
```

Trace:

1. The body after the outer config envelope is JSON shaped like an encrypted-tree envelope, but `format` is altered or from a future inner format such as `xpf-master-password-v2`.
2. `unmarshalEnvelope` successfully unmarshals that JSON into `encryptedTreeEnvelope`, sees `env.Format != encryptedTreeFormat`, and returns `ok=false, err=nil`.
3. `maybeDecryptTreeJSON` returns the original JSON bytes as "plaintext".
4. `readTreeMeta` unmarshals those bytes into `config.ConfigTree`. Go JSON decoding ignores unknown fields such as `format`, `prf`, `salt`, `nonce`, and `data`, so this can produce an empty tree rather than an error.
5. `Store.Load` can then boot a committed empty config instead of failing closed on an unreadable or too-new encrypted DB.

Refutation attempt:

Not required for Medium. I checked `envelope.go`/`envelope_test.go`: the outer `#xpf-config-envelope` min-reader gate is strong for DB format upgrades when it is bumped correctly. This finding survives as an inner encrypted-envelope parser issue because the inner `format` field itself is treated as plaintext fallback instead of fail-closed.

HPC/invariant check:

Compatibility-envelope invariant: recognizable envelope-shaped data with an unsupported discriminator should be rejected, not passed to a permissive JSON target. No HPC concern.

Why it matters:

The outer envelope was added specifically to prevent unknown JSON objects from empty-loading on old readers. The inner encryption envelope reintroduces that class inside the stripped body: a corrupted or too-new encrypted body can be accepted as an empty config.

Fix direction:

(concrete - the report is a remediation work-list)
In `unmarshalEnvelope`, distinguish "not JSON / normal ConfigTree JSON" from "JSON object with encrypted-envelope fields but unsupported format." If `format` is non-empty and not `encryptedTreeFormat`, return an error. Also reject objects carrying `salt`, `nonce`, or `data` with a missing/unknown `format`. Add a test that wraps an inner `xpf-master-password-v2` body in the outer config envelope and asserts `Store.Load` returns `ErrConfigDBUnreadable`, not an empty active tree.

Labels:

(include vsrx-parity for parity issues)
crypto, envelope-compatibility, fail-closed, rollback

Dedup note:

(why this is not a restatement of any entry in the dedup index)
The dedup index includes outer-envelope compatibility issues and empty-load prevention, but not this inner encrypted-envelope fallthrough after the outer envelope has already been stripped.

### F5

### C175-MC-004

Title: FRR BGP `cluster-id` is accepted and rendered without router-id style validation

Severity: Medium

Confidence: Medium

Source batch: A7-b3

Evidence:

`pkg/frr/policy_render.go:676`

```go
   676		if bgp != nil && bgp.LocalAS > 0 {
   677			fmt.Fprintf(&b, "router bgp %d%s\n", bgp.LocalAS, vrfSuffix)
   678			if validRouterID(bgp.RouterID) {
   679				fmt.Fprintf(&b, " bgp router-id %s\n", bgp.RouterID)
   680			}
   681			if bgp.ClusterID != "" {
   682				fmt.Fprintf(&b, " bgp cluster-id %s\n", bgp.ClusterID)
   683			}
```

`pkg/config/schema_routing.go:335`

```go
   335		"bgp": {desc: "BGP configuration", children: map[string]*schemaNode{
   336			"local-as":         {desc: "Local AS number", args: 1, valueType: ValueInteger, placeholder: "<as-number>", validator: ValidateInteger(1, 4294967295), children: nil},
   337			"router-id":        {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
   338			"cluster-id":       {desc: "Cluster ID", args: 1, placeholder: "<id>", children: nil},
   339			"graceful-restart": {desc: "Graceful restart", children: nil},
```

`pkg/config/compiler_protocols.go:217`

```go
   217				case "router-id":
   218					if len(child.Keys) >= 2 {
   219						proto.BGP.RouterID = child.Keys[1]
   220					}
   221				case "cluster-id":
   222					if len(child.Keys) >= 2 {
   223						proto.BGP.ClusterID = child.Keys[1]
   224					}
```

Trace:

1. Operator or lenient load supplies `set protocols bgp cluster-id not.an.ip`.
2. Schema accepts the value as an untyped token, and the compiler copies it unchanged.
3. FRR render emits `bgp cluster-id not.an.ip`.
4. FRR expects a valid route-reflector cluster identifier; invalid tokens can fail `frr-reload.py`/`vtysh -f`, putting FRR reload into degraded or failed state for an otherwise unrelated routing change.

Refutation attempt:

Not required at this severity. During merge, the coordinator checked the cited caller/guard path and found no condition that invalidated the reported behavior.

HPC/invariant check:

FRR reload safety invariant violated: raw BGP identifiers with strict FRR grammar should either be commit-validated or render-skipped on lenient load, matching the adjacent router-id guard.

Why it matters:

A typo in a route-reflector-only knob can poison the whole FRR reload and leave routing config stale. The adjacent `router-id` path already documents this exact reload-failure class and has a guard; `cluster-id` lacks the same protection.

Fix direction:

Add strict validation for `cluster-id` using FRR's accepted grammar, likely dotted IPv4/32-bit cluster ID, and add a render-side belt that skips invalid values on lenient load. Add a regression test parallel to `router_id_2980_test.go`.

Labels:

`A7-b3`, `frr`, `bgp`, `reload-poison`, `validation`

Dedup note:

Distinct from prior FRR command-injection and local-preference/metric validation items. This is not control-character injection; it is an invalid single-token FRR grammar value.

### C175-MC-005

Title: FRR policy `then origin` accepts arbitrary tokens and can render invalid `set origin`

Severity: Medium

Confidence: Medium

Source batch: A7-b3

Evidence:

`pkg/frr/policy_render.go:1829`

```go
  1829				if term.Origin != "" {
  1830					// #4498: sanitize the origin token — parity with the #4482
  1831					// set-clause belt so a tolerant-load / peer-synced /
  1832					// rolled-back value with an embedded newline cannot inject an
  1833					// extra frr.conf line.
  1834					fmt.Fprintf(&b, " set origin %s\n", sanitizeFRRValue(term.Origin))
  1835				}
```

`pkg/config/schema_routing.go:231`

```go
   231					"community": {desc: "Community (add | delete | set | none | <value>)", args: 1, multi: true, groupReplace: true, placeholder: "<add|delete|set|none|community>", children: nil},
   232					// `then as-path-prepend "<asn> <asn> ..."` prepends the listed
   233					// ASNs to the advertised AS_PATH (FRR `set as-path prepend`).
   234					// multi:true so a quoted "65001 65001" or bracketed
   235					// [ 65001 65001 ] list keeps EVERY ASN (order + repetition
   236					// matter — repeating the ASN is the whole mechanism); a
   237					// single-value leaf would drop all but the first (#2892).
   238					"as-path-prepend": {desc: "AS path prepend", args: 1, multi: true, groupReplace: true, placeholder: "<asn>", children: nil},
   239					"origin":          {desc: "Origin", args: 1, placeholder: "<origin>", children: nil},
```

`pkg/config/compiler_routing.go:896`

```go
   896					case "as-path-prepend":
   897						// `then as-path-prepend` is a multi-value leaf: a quoted
   898						// "65001 65001" or bracketed [ 65001 65001 ] list flattens
   899						// onto ac.Keys[1:] and/or ac.Children. Read EVERY ASN via
   900						// the firewallMatchValues SSOT (reading only Keys[1] would
   901						// drop all but the first prepend, the #2419/#2892 trap) and
   902						// accumulate so repeated set lines also keep every ASN.
   903						term.ASPathPrepend = append(term.ASPathPrepend, firewallMatchValues(ac)...)
   904					case "origin":
   905						term.Origin = nodeVal(ac)
```

Trace:

1. Operator configures `then origin igpp` or a lenient peer-sync carries a bad origin token.
2. Schema has no enum validator; compiler stores the token unchanged.
3. Renderer sanitizes only control characters, then emits `set origin igpp`.
4. FRR route-map grammar only accepts the supported origin values, so an invalid token can fail the route-map load and stall the managed FRR section.

Refutation attempt:

Not required at this severity. During merge, the coordinator checked the cited caller/guard path and found no condition that invalidated the reported behavior.

HPC/invariant check:

Route-policy reload invariant violated: BGP set clauses that have finite FRR enums should be schema-validated and lenient-load guarded, not merely control-character sanitized.

Why it matters:

One mistyped policy action can prevent an entire FRR reload, leaving stale routing policy active while the daemon reports a degraded routing apply.

Fix direction:

Add `ValidateEnum([]string{"igp","egp","incomplete"})` or equivalent strict validation for `then origin`, and add a render-side skip/error belt for lenient-loaded bad values. Add tests for valid values and a malformed value not reaching rendered config.

Labels:

`A7-b3`, `frr`, `route-map`, `reload-poison`, `validation`

Dedup note:

Distinct from the deduped #4482/#4498 newline/set-clause injection fix. The injection belt is present; the remaining issue is accepting invalid non-control tokens.

### C175-MC-006

Title: REST `include_peer=true` session lists undercount peer sessions in cursor-mode requests

Severity: Medium

Confidence: Medium

Source batch: A8-b1

Evidence:

`pkg/api/sessions.go:307`

```go
func (s *Server) writeSessionList(w http.ResponseWriter, r *http.Request, resp SessionListResponse) {
	resp.NodeID = s.nodeID()
	if includePeer, _ := sessionIncludePeer(r); includePeer && sessionFirstPage(r) {
		if svc := s.clusterSession(); svc != nil {
			if pr, err := svc.GetSessions(r.Context(), peerSessionsRequest(r)); err == nil {
				if peer := pr.GetPeer(); peer != nil {
					resp.Peer = sessionListFromPB(peer)
				}
```

`pkg/api/sessions.go:344`

```go
func peerSessionsRequest(r *http.Request) *pb.GetSessionsRequest {
	q := r.URL.Query()
	req := &pb.GetSessionsRequest{
		IncludePeer:       true,
		Protocol:          q.Get("protocol"),
		SourcePrefix:      q.Get("source_prefix"),
		DestinationPrefix: q.Get("destination_prefix"),
		Application:       q.Get("application"),
		InterfaceFilter:   q.Get("interface"),
```

`pkg/api/sessions.go:364`

```go
	if b, err := strconv.ParseBool(q.Get("nat_only")); err == nil {
		req.NatOnly = b
	}
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		req.Limit = int32(l)
	}
	return req
```

Minimal contract read, `pkg/grpcapi/server_sessions.go:588`:

```go
// getSessionsLegacy is the original limit/offset iteration path.
func (s *Server) getSessionsLegacy(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
```

Trace:

A dashboard requests the first cursor-mode page with `GET /api/v1/sessions?page_size=1000&include_peer=true`. The local REST session path uses cursor pagination for the local response, then `writeSessionList` asks the cluster session service for the peer with `peerSessionsRequest`. That peer request forwards filters and `limit`, but not `page_size`/`PageSize`; if the REST caller used cursor-mode `page_size`, the peer request reaches gRPC with `Limit == 0` and `PageSize == 0`. The gRPC legacy path defaults the peer list to 100 sessions, so REST attaches at most 100 peer sessions even though the first local page is sized for 1000 and the API contract says the first page carries the peer's full table.

Refutation attempt:

I checked the HA scope test and it verifies peer attachment on first page and omission on non-first pages, but only with a tiny peer response that cannot expose the 100-row default. I also checked the gRPC peer fan-out implementation; it forwards `PageSize` when the original gRPC caller used it, which confirms cursor-mode page size is part of the intended peer request contract. The REST adapter is the part that drops it.

HPC/invariant check:

HA observability invariant is that `include_peer=true` first-page REST responses do not understate peer state. The adapter violates that invariant for cursor-mode requests by translating only offset-mode `limit` into the peer request.

Why it matters:

HA dashboards and automation can undercount peer sessions by an arbitrary amount whenever the peer has more than 100 sessions and the client uses cursor pagination. This is a schema/translation drift between REST and gRPC surfaces and can hide peer load or failover state.

Fix direction:

In `peerSessionsRequest`, parse and forward validated `page_size` as `PageSize` for cursor-mode callers, or normalize REST cursor pagination to the equivalent peer request size before calling `GetSessions`. Add HA tests with peer cardinality above 100 and `page_size` set without `limit`.

Labels:

`api`, `rest`, `grpc`, `ha`, `sessions`, `pagination`, `schema-drift`

Dedup note:

Reviewed `/tmp/review-work-codex-175/dedup-index.md`; no duplicate REST `include_peer` page-size undercount issue found.
### A8-b1-003

### C175-MC-007

Title: RX source-MAC learning accepts non-unicast source IPs from ordinary IP traffic

Severity: Low

Confidence: Medium

Source batch: A1-b2

Evidence:

`userspace-dp/src/afxdp/poll_stages.rs:278-287` learns from the parsed flow source IP on live frames:

```rust
278     if learn_from_live_frame && let Some(flow) = flow.as_ref() {
279         learn_dynamic_neighbor_from_packet(
280             area,
281             desc,
282             meta,
283             flow.src_ip,
284             last_learned_neighbor,
285             worker_ctx.forwarding,
286             worker_ctx.dynamic_neighbors,
287         );
```

`userspace-dp/src/afxdp/neighbor_dispatch.rs:439-443` filters only the Ethernet source MAC class before constructing the learn:

```rust
439     let mut src_mac = [0u8; 6];
440     src_mac.copy_from_slice(&frame[6..12]);
441     if src_mac == [0; 6] || (src_mac[0] & 1) != 0 {
442         return;
443     }
```

`userspace-dp/src/afxdp/neighbor_dispatch.rs:493-501` rejects own IPs but does not reject loopback, multicast, or limited broadcast source IPs before creating the keys:

```rust
493     // non-own neighbors are unaffected.
494     if forwarding.owns_configured_ip(src_ip) {
495         return;
496     }
497     // #1787: stack array, no per-packet heap alloc. At most 2 keys:
498     // the physical ingress ifindex plus the resolved logical (VLAN
499     // sub-) ifindex when it differs. keys[1] stays an unused
500     // placeholder when n == 1.
501     let mut keys: [(i32, IpAddr); 2] = [(ingress_ifindex, src_ip), (0, src_ip)];
```

`userspace-dp/src/afxdp/frame/inspect.rs:1571-1576` shows metadata flow construction rejects only unspecified addresses:

```rust
1571         _ => return None,
1572     };
1573     if src_ip.is_unspecified() || dst_ip.is_unspecified() {
1574         return None;
1575     }
1576     Some(SessionFlow {
```

Trace:

1. A live ingress TCP/UDP packet has a unicast Ethernet source MAC but spoofs an IP source such as `127.0.0.1`, `224.0.0.1`, or `255.255.255.255`.
2. `parse_session_flow_from_bytes` can produce a `SessionFlow`; the metadata path shown above rejects unspecified addresses but not loopback, multicast, or limited broadcast.
3. `stage_parse_flow_and_learn` passes `flow.src_ip` into `learn_dynamic_neighbor_from_packet`.
4. `learn_dynamic_neighbor_from_packet` rejects zero and multicast source MACs, but does not validate the source IP class.
5. `learn_dynamic_neighbor` rejects only router-owned IPs, then inserts `(physical_ifindex, src_ip)` and possibly `(logical_ifindex, src_ip)` into `dynamic_neighbors` via `learn_pair_if_changed`.

Refutation attempt:

Not required for Low, but I checked the obvious guards. ARP and NDP learning in `poll_stages.rs` explicitly call `neighbor_ip_is_learnable`, which rejects unspecified, loopback, multicast, and IPv4 limited broadcast addresses. The RX source-MAC path has a #3182 own-IP regression test, but that test only proves router-owned source IPs are rejected. The candidate is narrowed because this path updates the userspace `dynamic_neighbors` cache rather than calling `add_kernel_neighbor`; I did not find direct kernel-neighbor poisoning from this path.

HPC/invariant check:

The intended fix is a scalar predicate before the existing pre-check and bulk insert. It preserves the no-allocation RX learn path and avoids new locks. It also keeps the neighbor-write invariant consistent with the ARP/NDP learn sites.

Why it matters:

The code comments around `neighbor_ip_is_learnable` state that illegitimate address classes should not be cached as neighbors. This path is a fifth neighbor write path, and it can cache impossible next-hop identities in the fast userspace dynamic-neighbor table. Even if normal routing rarely resolves such addresses, spoofed traffic can pollute state and misses the documented invariant/test posture.

Fix direction:

Add `if !neighbor_ip_is_learnable(src_ip) { return; }` near the top of `learn_dynamic_neighbor`, before the own-IP gate and before `last_learned_neighbor` is updated. Add tests mirroring `arp_invalid_sender_ip_not_learned_2790` for the RX learn path: valid non-own unicast still learns, while loopback, multicast, and limited broadcast sources do not.

Labels:

`neighbor-learning`, `hardening`, `packet-path`, `test-gap`

Dedup note:

The dedup index includes prior ARP/NDP poisoning and invalid host-inbound multicast/broadcast findings. This is distinct: it is ordinary IP RX source-MAC learning into `dynamic_neighbors`, with kernel neighbor installation absent and a different missing predicate.

### Finding 3

### C175-MC-008

Title: Static NAT block local-address registration publishes only the network base

Severity: Low

Confidence: Medium

Source batch: A2-b1

Evidence:

Static NAT block external IP publication chains only the block's external base:

```rust
userspace-dp/src/nat/static_nat.rs:765
    pub(crate) fn external_ips(&self) -> impl Iterator<Item = &IpAddr> {
        self.dnat
            .keys()
            .map(|(ip, _)| ip)
            .chain(self.blocks.iter().map(|b| &b.external.base))
    }
```

The scoped view used by forwarding state does the same:

```rust
userspace-dp/src/nat/static_nat.rs:781
    pub(crate) fn external_ips_scoped(&self) -> Vec<(IpAddr, &str)> {
        let mut out = Vec::new();
        for ((ip, _port), entries) in &self.dnat {
            for entry in entries {
                out.push((*ip, entry.from_routing_instance.as_str()));
            }
        }
        for block in &self.blocks {
            out.push((block.external.base, block.from_routing_instance.as_str()));
```

Forwarding build treats these as local-delivery NAT targets:

```rust
userspace-dp/src/afxdp/forwarding_build/mod.rs:449
    // Add static NAT external IPs and DNAT destination IPs as local-delivery
    // targets so inbound traffic destined to those IPs is recognized by the
    // firewall. #3769: each IP carries its owning rule's `from
    // routing-instance` scope. A NAMED instance records the specific canonical
    // route table (via `connected_route_tables`) in `local_tables_v*` so the
```

DNAT's equivalent prefix publication has a bounded host expansion for small blocks:

```rust
userspace-dp/src/nat/destination.rs:1031
                match (slot.v4, slot.v6) {
                    (Some(p), _) => {
                        let hosts = host_count_v4(p.prefix_len());
                        if hosts <= Self::MAX_LOCAL_PREFIX_HOSTS {
                            if let Ok(net) =
                                Ipv4Net::new(p.addr(), p.prefix_len())
                            {
                                for host in net.hosts() {
                                    out.push((IpAddr::V4(host), instance));
```

Trace:

1. Configure a static block rule `198.51.100.0/24 -> 192.168.1.0/24` from `untrust`.
2. The packet translation path works: `match_dnat(198.51.100.7, "untrust")` rewrites to `192.168.1.7` (covered in `userspace-dp/src/nat/tests_static.rs:154-170`).
3. During forwarding-state build, `state.static_nat.external_ips_scoped()` contributes only `198.51.100.0` for that block.
4. `forwarding_build` inserts only that base into `state.local_v4` / local NAT table attribution. A peer on a directly connected public segment resolving `198.51.100.7` will not see `.7` registered through this local-address/proxy path.
5. DNAT small-prefix rules do expand bounded blocks host-by-host, so `/24` DNAT and `/24` static block NAT have different local-address/proxy behavior even though both translate any host in the block.

Refutation attempt:

- The static NAT comment at `userspace-dp/src/nat/static_nat.rs:759-764` says block DNAT matching is not gated on local membership and that base-only publication avoids unbounded blow-up. That refutes a packet-translation fail-open claim: routed traffic to `.7` can still translate.
- The residual issue is narrower: directly connected local-address/proxy registration and vSRX parity for small static NAT blocks. DNAT already handles the same blow-up concern with `MAX_LOCAL_PREFIX_HOSTS`; static NAT block registration does not.
- Tests cover block offset translation (`userspace-dp/src/nat/tests_static.rs:154-205`) and host-rule `external_ips()` (`userspace-dp/src/nat/tests_static.rs:594-630`), but I did not find a static-block local-address registration test analogous to `dnat_prefix_destination_ips_registers_small_block_base_only_for_large` in `userspace-dp/src/nat/tests_destination.rs:1211-1233`.
- Dedup checked for static NAT block/proxy/local registration roots; no exact duplicate found. Existing static NAT shadowing and `prefix-name` compiler findings are different roots.

HPC/invariant check:

Any fix must keep the cold-path expansion bounded. Reuse the DNAT cap (`MAX_LOCAL_PREFIX_HOSTS`) or move the helper to a shared NAT-local-target utility. Large blocks should continue to publish only the network base and require routing to the firewall. For IPv6, expand only host-scale prefixes under the same cap. This is forwarding-state build work, not per-packet work.

Why it matters:

Static block NAT is often deployed on an external segment where the firewall is expected to own or proxy the public block. Publishing only the network base means the translated addresses inside a small block are not represented in the same local-target set used for static host NAT and DNAT small-prefix parity. Operators can see the block translate in unit tests or routed deployments, but directly connected traffic to non-base public addresses may never reach the NAT path unless they add routing/proxy configuration outside this helper.

Fix direction:

Mirror DNAT's bounded prefix expansion in `StaticNatTable::external_ips_scoped()` and keep `external_ips()` derived from that behavior, or make the base-only routed-block requirement explicit through config/status and tests. Add tests for:

- Static NAT `/24` block publishes representative usable hosts such as `.1` and `.254` when under the cap.
- Large static NAT blocks still publish only the base.
- Scoped block publication preserves `from_routing_instance` per expanded address.

Labels:

static-nat, block-nat, local-delivery, proxy-arp, vsrx-parity, test-gap

Dedup note:

No exact duplicate found in `/tmp/review-work-codex-175/dedup-index.md`. This is distinct from static NAT rule shadowing/overwrite and the Go compiler `static-nat prefix-name` drop.

### C175-MC-009

Title: Unbounded commit descriptions can create oversized journal records that are later dropped by the bounded tail scanner

Severity: Low

Confidence: Medium

Source batch: A4-b1

Evidence:

`pkg/configstore/store_commit.go:93-128` stores the caller-supplied description in history and journal without a length cap:

```go
// Push current active to history with description
s.history.Push(&HistoryEntry{
	Config:    s.active.Clone(),
	Timestamp: time.Now(),
	Comment:   description,
})

// Promote candidate to active
s.active = s.candidate
```

`pkg/configstore/journal/journal.go:87-92` sets a hard tail-scan line cap:

```go
// maxTailLineBytes caps reverse-scan line assembly (AGY plan-r1
// F4): a corrupt newline-free segment would otherwise buffer the
// whole file. 16 MiB is far above any real legacy fat entry; a
// fragment past the cap is discarded and the scanner resyncs at
// the previous newline, dropping only the poisoned line.
maxTailLineBytes = 16 << 20
```

`pkg/configstore/journal/journal.go:168-178` marshals the whole entry before any size check and rotates based on the old segment size:

```go
data, err := json.Marshal(entry)
if err != nil {
	return fmt.Errorf("marshal journal entry: %w", err)
}

rotated, err := j.maybeRotateLocked()
if err != nil {
	return err
}
```

Trace:

1. A caller passes an extremely large commit description to `CommitWithDescription`.
2. Config payload size gates do not apply, because the description is not part of the parsed config text.
3. `journal.Log` JSON-marshals the full `Detail`, allocating proportional memory and writing one huge JSONL line.
4. Rotation happens before the append and only considers the current segment size, not the new entry length.
5. Later `Tail(limit)` sees a line larger than `maxTailLineBytes`, treats it like a poisoned line, discards it, and the audit record can disappear from bounded history views.

Refutation attempt:

Not required for Low. I checked `config_size_ceiling_hb164_test.go`; the 16 MiB ceiling is applied to config payload entry points, not commit descriptions. `journal/journal_test.go` proves over-cap corrupt lines are skipped, but there is no test proving legitimate commit comments are bounded below that cap.

HPC/invariant check:

Resource invariant: operator-paced path, not packet hot path. The issue is bounded memory/disk/audit retention for an unbounded string.

Why it matters:

The journal is the durable audit trail for commits and destructive actions. An oversized but syntactically valid commit comment can cause excessive allocation/disk usage and then be hidden by the tail reader's corrupt-line defense.

Fix direction:

(concrete - the report is a remediation work-list)
Add a maximum length for `JournalEntry.Detail`/commit descriptions at the configstore boundary, for example a few KiB. Reject or truncate with an explicit marker before journaling. Add tests for over-limit descriptions and for entries near the tail cap. Consider rotating based on `current size + len(data) + 1`, not only current size.

Labels:

(include vsrx-parity for parity issues)
journal, resource-bounds, audit

Dedup note:

(why this is not a restatement of any entry in the dedup index)
The dedup index covers journal compactness, fat legacy handling, and corrupt-line caps, but not unbounded legitimate `Detail` input creating records that the cap later drops.

### C175-MC-010

Title: DHCP lease sync string lengths wrap at uint16 and can corrupt a lease record

Severity: Low

Confidence: Medium

Source batch: A5-b1

Evidence:

`pkg/cluster/sync_protocol.go:659`

```go
// putLeaseString appends a uint16-length-prefixed string.
func putLeaseString(b []byte, s string) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}
```

`pkg/cluster/sync_protocol.go:683`

```go
func encodeOneLease(l dhcpserver.SyncLease) []byte {
	b := make([]byte, 0, 96)
	b = append(b, byte(l.Family))
	b = putLeaseString(b, l.Address)
	b = binary.LittleEndian.AppendUint32(b, uint32(l.SubnetID))
	b = binary.LittleEndian.AppendUint32(b, uint32(l.ValidLife))
	b = binary.LittleEndian.AppendUint32(b, uint32(l.Remaining))
	b = append(b, byte(l.State))
```

`pkg/cluster/sync_protocol.go:694`

```go
	b = putLeaseString(b, l.HWAddress)
	b = putLeaseString(b, l.ClientID)
	b = putLeaseString(b, l.DUID)
	b = binary.LittleEndian.AppendUint32(b, l.IAID)
	b = putLeaseString(b, l.LeaseType)
	b = binary.LittleEndian.AppendUint32(b, uint32(l.PrefixLen))
	b = putLeaseString(b, l.Hostname)
```

`pkg/cluster/sync_protocol.go:725`

```go
	if l.Address, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off+4 > len(buf) {
		return l
	}
	l.SubnetID = int(binary.LittleEndian.Uint32(buf[off:]))
```

Minimal contract read: `pkg/dhcpserver/lease_sync.go:71`

```go
type SyncLease struct {
	Family int // 4 or 6

	Address  string // v4 dotted / v6 colon address (or PD prefix base for IA_PD)
	SubnetID int    // Kea subnet-id the lease belongs to

	// v4 identity. At least one of HWAddress / ClientID is set.
	HWAddress string // "aa:bb:cc:dd:ee:ff"
```

Trace:

Low severity, but the failure chain is concrete: `QueueDHCPLeases` serializes unbounded `SyncLease` string fields; `putLeaseString` stores only `uint16(len(s))` while appending the full string; the peer decodes only the wrapped low-16-bit prefix; then it interprets remaining bytes from that same string as later fields in the record. The outer record length lets the next lease stay aligned, but the affected lease can be seeded with corrupted identity, lease type, prefix length, hostname, or FQDN flags.

Refutation attempt:

Normal DHCP client identifiers, DUIDs, hostnames, and IP address strings should be far smaller than 65535 bytes, so this is unlikely from well-formed DHCP traffic. I could not find a code-level bound on `SyncLease` fields or an encoder guard in the batch path; the struct uses plain strings sourced from Kea socket/memfile conversion, and the sync frame cap is much larger than 64 KiB. Existing lease sync tests cover round-trip, trailing-field compatibility, and hostile count preallocation, but not oversized variable fields.

HPC/invariant check:

Wire codecs must either encode the true byte length or reject/truncate explicitly before emitting a frame. Silent integer narrowing breaks the lease-record self-describing invariant and gives the standby a different lease identity than the primary sent.

Why it matters:

On takeover, the standby may seed Kea from the held peer lease set. A malformed or unexpectedly large field should not silently turn one lease into a different identity/type; fail-closed is preferable to seeding corrupted DHCP state.

Fix direction:

Make lease-string encoding return an error when any field exceeds `math.MaxUint16`, and have `encodeDHCPLeasePayload` skip that lease with a warning or fail the send for the family. Add a regression test with a 65536-byte hostname/client-id to assert the encoder does not emit a misframed record.

Labels:

area:A5, batch:1, cluster, session-sync, dhcp-lease-sync, wire-format, defensive-hardening

Dedup note:

No matching prior finding in the dedup index. Prior lease-sync coverage focused on count preallocation and DHCP identity/type fidelity, not uint16 string-length narrowing.

### C175-MC-011

Title: DNS domain/search renderers write untyped domain values verbatim, including quoted newline payloads

Severity: Low

Confidence: Medium

Source batch: A7-b2

Evidence:

`pkg/daemon/system/dns.go:56-61,118-123` writes DNS servers and domains into resolver files by joining raw strings:

```go
	if len(in.NameServers) > 0 {
		fmt.Fprintf(&b, "DNS=%s\n", strings.Join(in.NameServers, " "))
	}
	if domains := combinedDomains(in.DomainName, in.DomainSearch); len(domains) > 0 {
		fmt.Fprintf(&b, "Domains=%s\n", strings.Join(domains, " "))
	}
```

```go
	for _, ns := range in.NameServers {
		fmt.Fprintf(&b, "nameserver %s\n", ns)
	}
	if domains := combinedDomains(in.DomainName, in.DomainSearch); len(domains) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(domains, " "))
```

`pkg/config/schema_system.go:59-77` validates `name-server` as an IP but leaves `domain-name` and `domain-search` as untyped string leaves:

```go
var schemaSystem = &schemaNode{desc: "System configuration", children: map[string]*schemaNode{
	"host-name":     {desc: "System hostname", args: 1, scalar: true, placeholder: "<hostname>", children: nil},
	"domain-name":   {desc: "Domain name", args: 1, placeholder: "<domain>", children: nil},
	"domain-search": {desc: "Domain search list", args: 1, multi: true, placeholder: "<domain>", children: nil},
	"time-zone":     {desc: "System time zone", args: 1, placeholder: "<timezone>", children: nil},
```

```go
		placeholder:   "<address>",
		valueType:     ValueIPAddress,
		valueDesc:     "DNS server IP address (IPv4 or IPv6)",
		valueExamples: []string{"8.8.8.8", "2001:4860:4860::8888"},
		validator:     ValidateIPAddress,
		children:      nil,
```

`pkg/config/lexer.go:243-267` preserves quoted `\n` as an actual newline inside a single token:

```go
func (l *Lexer) readString(line, col int) Token {
	l.advance() // opening quote
	var b strings.Builder
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '\\' && l.pos+1 < len(l.input) {
			l.advance()
```

```go
		case 'n':
			b.WriteByte('\n')
		default:
			b.WriteByte('\\')
			b.WriteByte(l.input[l.pos])
		}
		l.advance()
```

The assigned DNS tests intentionally preserve an empty search element and do not include whitespace/newline hostile values:

```go
		// De-dup: a search entry equal to the (non-empty)
		// domain-name is dropped so the primary domain is not
		// repeated; distinct suffixes keep their order.
		name: "domain-name duplicated in search is de-duplicated",
		in: ResolvedDropinInput{
			DomainName:   "example.com",
			DomainSearch: []string{"corp.example.com", "example.com", "lab.example.com"},
```

Trace:

1. Config can carry `system domain-name` or `system domain-search` as a quoted string token.
2. The lexer turns `\n` in a quoted token into a literal newline.
3. The schema has no validator for those leaves, unlike `system name-server`.
4. `mergeDNSInput` copies `cfg.System.DomainName` and `cfg.System.DomainSearch` into `ResolvedDropinInput`.
5. `RenderResolvConf` and `RenderResolvedDropin` write those values with `fmt.Fprintf` and `strings.Join`, without escaping or rejecting whitespace/control characters.
6. A malformed or hostile config can inject extra resolver-file lines or at least render an invalid resolver/search directive despite a clean commit path.

Refutation attempt:

Not required for Low severity. I checked the immediate validation contract: `name-server` is explicitly typed as `ValueIPAddress` with `ValidateIPAddress`; `domain-name` and `domain-search` are not. The exposure is limited by configuration-author privilege and may not be remotely exploitable by itself, which is why this is Low severity.

HPC/invariant check:

No dataplane hot-path invariant. Host-integration invariant affected: root-owned resolver files should be rendered from sanitized directive values, with the renderer and schema agreeing on permitted characters.

Why it matters:

The DNS renderer owns `/etc/resolv.conf` and legacy systemd-resolved drop-ins. Even if only an authenticated config path can set these values, accepting newline/space/control characters makes the committed configuration's resolver effect differ from the visible domain/search intent and creates a future footgun for non-interactive load/sync paths.

Fix direction:

Add schema validators for `system domain-name` and every `domain-search` entry: reject empty values, whitespace, control characters, and newline escapes; enforce a conservative DNS label/FQDN/search-suffix grammar. Add renderer tests for quoted newline, embedded spaces, empty search members, and values starting with resolver directive keywords. Consider making the renderer defensively reject or skip invalid domains even if schema validation is expected to catch them.

Labels:

`dns`, `host-integration`, `input-validation`, `test-gap`

Dedup note:

Not a duplicate of prior `name-server` validation issues or the fixed multi-value `to` range-separator bug. This finding is about the still-untyped `domain-name` / `domain-search` values flowing into daemon-owned resolver-file renderers.

### C175-MC-012

Title: Malformed event `limit` values silently widen forensic event queries to the default window

Severity: Low

Confidence: Medium

Source batch: A8-b1

Evidence:

`pkg/api/security.go:419`

```go
func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeOK(w, []EventEntry{})
		return
	}

	limit := queryInt(r, "limit", 50)
	if limit > 10000 {
```

`pkg/api/api.go:146`

```go
func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
```

Trace:

A caller requests `/api/v1/security/events?limit=-1` or `limit=abc`. The event handler delegates to `queryInt`, which converts malformed or negative input into the default `50`. The endpoint then returns up to 50 latest or filtered forensic events instead of rejecting the malformed query. Other event filter fields, such as malformed `zone`, fail closed with HTTP 400.

Refutation attempt:

I checked the event-zone tests and shared REST filter fail-closed tests; they assert malformed security filters are rejected, but they do not cover malformed `limit`. I did not find an explicit documented contract that malformed event limits should default open, and the behavior can widen a caller's requested result set.

HPC/invariant check:

API input-validation invariant for security event filters is fail-closed parsing of malformed query parameters. `limit` is not an authz predicate, so this remains Low severity, but it controls response scope and currently fails open to the default window.

Why it matters:

Forensic/event APIs should make malformed scoping input visible to clients. Silent defaulting can mask client bugs and return more event records than a caller intended.

Fix direction:

Replace `queryInt` use here with strict event-limit parsing that rejects malformed or negative values with HTTP 400 while keeping the existing upper cap of 10000. Add tests for `limit=-1`, `limit=abc`, and `limit=10001`.

Labels:

`api`, `rest`, `security-events`, `input-validation`, `schema-drift`

Dedup note:

Reviewed `/tmp/review-work-codex-175/dedup-index.md`; no duplicate malformed event-limit default-open issue found.

### C175-MC-013

Title: `check-config` allocates through an unbounded TOCTOU window despite its 4 MiB hard-cap claim

Severity: Low

Confidence: Medium

Source batch: A10-b1

Evidence:

`cmd/xpfd/main.go:172`
```go
172		// The day-0 config drive is untrusted input: hard-cap the size
173		// before reading so a garbage volume cannot balloon memory.
174		const maxCheckConfigBytes = 4 << 20 // 4 MiB
175		fi, err := os.Stat(path)
176		if err != nil {
177			fmt.Fprintf(os.Stderr, "check-config: %v\n", err)
178			os.Exit(1)
179		}
180		if !fi.Mode().IsRegular() {
181			fmt.Fprintf(os.Stderr, "check-config: %s: not a regular file\n", path)
```

Trace:

`Stat` and `ReadFile` resolve/open the path separately. A file can grow or be replaced after the size/type check; `os.ReadFile` reads to EOF and allocates before the later `len(data)` check can reject it. A mutable/FUSE-like untrusted source can also return more data than its advisory size.

Refutation attempt:

The primary config-drive deployment is normally read-only, which materially lowers exploitability and supports Low severity. The subcommand nevertheless accepts arbitrary paths, and the source comment explicitly tries to cover non-read-only growth; the post-read check limits parsing, not memory consumed while reading.

HPC/invariant check:

Cold startup utility. Resource caps must be enforced during I/O, not after allocation; no packet-path effect.

Why it matters:

A root-invoked validation helper can hang or consume excessive memory on a raced or adversarial file even though callers rely on the documented 4 MiB bound.

Fix direction:

Open once, `f.Stat()` the opened descriptor, require regular mode there, and read through `io.LimitReader(max+1)` (or an exact bounded helper). Reject as soon as the extra byte is observed and add a growing/adversarial-reader test seam.

Labels:

`xpfd`, `resource-safety`, `input-validation`, `toctou`

Dedup note:

No `check-config` bounded-read root cause appears in the supplied dedup index. The indexed day-0 preflight issue concerns device-map validation, not I/O allocation.
### A10-b1-L03

## 8. Low-confidence findings

No low-confidence candidates survived evidence and duplicate triage. Low *severity* findings are present in the High- and Medium-confidence sections above.

## 9. Suggested issue split

Create one standalone issue for each Critical/High root; do not combine unrelated state machines merely because they share an area. Immediate queue:

- `C175-HC-001` Unchecked `fork()` failure turns cleanup into root-wide `SIGKILL`
- `C175-HC-002` Address-set bracket-list members after the first are silently dropped.
- `C175-HC-003` Nil user application values panic AppID catalog build and tuple fallback
- `C175-HC-004` Top-level unmatched `}` stops parsing with zero errors and drops all trailing config.
- `C175-HC-005` `CommitConfirmed` returns success even when the durable crash-recovery record fails to persist
- `C175-HC-006` Confirmed `commit confirmed` windows can be resurrected because `confirm.json` deletion is warning-only and not directory-fsynced
- `C175-HC-007` Binding queue IDs >= 16 alias adjacent userspace_bindings slots
- `C175-HC-008` `system login user <name>` can inject arbitrary sudoers directives through the generated `/etc/sudoers.d/xpf-*` drop-in
- `C175-HC-009` IPsec empty clear suppresses `swanctl --load-all` failures and can report stale tunnels removed
- `C175-HC-010` NetFlow v9 inserts padding between records, corrupting every multi-record FlowSet after the first record
- `C175-HC-011` SNMP response sizing permits quadratic GETBULK work and oversized GET/GETNEXT amplification
- `C175-HC-012` SNMPv3 users configured with authentication and privacy can be queried without either credential
- `C175-HC-013` `--skip-validate` still creates a fully signed, publishable image set
- `C175-HC-014` `operator` can disarm forwarding and dataplane queues through request verbs omitted from the maintenance gate
- `C175-HC-015` `xpfd upgrade` ignores positional arguments, so `xpfd upgrade rolling` performs an uncoordinated standalone cut
- `C175-HC-016` A failed `systemctl is-active` query is treated as inactive, so DHCP policy apply can silently skip restart or stop.
- `C175-HC-017` A transient status-command failure is mistaken for proof that an HA node rebooted
- `C175-HC-018` An unreadable `BootCurrent` prunes a possibly running candidate kernel
- `C175-HC-019` DDNS corrupt-state quarantine fails closed for only one process lifetime, then silently reopens on restart.
- `C175-HC-020` DHCP DUID clearing lets a control-plane caller unlink an arbitrary root-owned file.
- `C175-HC-021` HA DHCP lease lifetimes stop aging on the standby and are re-extended or resurrected at takeover.
- `C175-HC-022` Local `zeroize` leaves the authoritative config database and reports a completed wipe
- `C175-HC-023` Publication verifies a mutable tree and later uploads whatever bytes replaced it
- `C175-HC-024` Remote `commit` grammar turns an unknown modifier into a permanent commit and silently rewrites invalid confirmed deadlines
- `C175-HC-025` Root XSK tooling writes and loads a predictable attacker-owned `/tmp` BPF object
- `C175-HC-026` Scheduler off-CPU intervals end at wakeup instead of schedule-in, making involuntary waits unmeasurable
- `C175-HC-027` Surface B keeps one representative DDNS updater for two independent families and can withdraw IPv6 through the IPv4 provider.
- `C175-HC-028` The bake authenticates an Ubuntu image with an unsigned checksum from the same endpoint
- `C175-HC-029` The mouse-latency matrix exits zero when its aggregate verdict is `FAIL`

Then triage Medium/Low roots as area-scoped workstreams:

| Workstream | Unique findings | Recommended split |
|---|---:|---|
| A1 - Rust dataplane packet path & memory safety | 8 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A2 - Rust NAT/NAT64/translation | 2 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A3 - Go config compiler, schema & CLI grammar | 9 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A4 - Go configstore, persistence & crypto-at-rest | 4 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A5 - HA cluster, VRRP, RA, conntrack sync | 2 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A6 - Dataplane Go manager/control-plane to dataplane compilation | 2 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A7 - Daemon lifecycle & host integration | 11 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A8 - APIs (gRPC/REST) & surfaces | 6 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A9 - Observability & telemetry | 10 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |
| A10 - Services, policy simulator, CLI/show, build/deploy tooling | 63 | One issue per root cause; group only shared parser/state-machine fixes with a common regression matrix. |

Cross-area issue ownership:

- A6 owns the signed-ID narrowing fix with A8 gRPC regression coverage.
- A8 owns bounded filtered session-clear execution with A10 local CLI coverage.
- A10 owns the shared strict policy-inventory selector parser for local and remote CLI.
- Apply `vsrx-parity` to every finding whose Labels field includes it; retain security/HA/supply-chain labels separately rather than substituting the parity label.
